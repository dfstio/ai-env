// The relay (S13, plans/s13-contracts.md §I-infra.4.3): a t4g.nano `ai-env-relay` in the proxy subnet at a fixed
// private address, with an Elastic IP for the workers, its role (relayRolePolicy beside the AWS managed SSM agent
// policy) and instance profile, its log group, its binary in the artifacts bucket and the `artifact` parameter that pins
// it. Its other four parameters (workers, grants, token-signers, tls) are `ai-env relay`'s, written as the deployer at
// their first use: Pulumi never holds them (LD-I5: the grants name private sources; a SecureString in Pulumi's state
// would hold the key).
//
// Why this shape: administration through SSM only (no key pair, no port 22), IMDSv2 with hop limit 1, the AMI pinned
// by ignoreChanges as the proxy's; the user data (relay-spec.ts renderRelayFiles) carries no secret, and a change to
// it replaces the instance (the Elastic IP moves to the new one). The scratch:relay-imds, scratch:relay-policy and
// scratch:relay-eip markers are edited by `make preview-scratch NEGATIVE=relay-imds|relay-role-widen|relay-eip-elsewhere`.
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { Egress, EgressGuard, EgressProviders } from "./egress";
import { AMI_PARAMETER, EgressSpec, NET } from "./egress-spec";
import { Artifacts, uploadCopy } from "./image";
import { Names, REGION, RELAY_INSTANCE_PROFILE_NAME, RELAY_KEY_PREFIX, RELAY_ROLE_NAME, SSM_INSTANCE_POLICY_ARN, relayRolePolicy, relayTrustPolicy } from "./policies";
import { relayArtifactValue, renderRelayFiles } from "./relay-spec";

/** What `make relay-artifact` wrote; `binaryPath` resolved, `uploadPath` the verified copy the upload reads. */
export interface RelayJson {
    binary: string;
    binaryPath: string;
    uploadPath: string;
    sha256: string;
    key: string;
    version: string;
}

/**
 * relay.json from $RELAY_JSON (default target/relay/relay.json), relative to $AI_ENV_REPO_ROOT (default the parent of
 * infra/), as loadImageJson reads image.json: the key must be the sha256's, and the binary is read once and hashed again
 * (a stale relay.json must not upload another binary under its key); the upload then reads a content-addressed,
 * read-only copy (image.ts uploadCopy).
 */
export function loadRelayJson(): RelayJson {
    const root = path.resolve(process.env.AI_ENV_REPO_ROOT || path.join(__dirname, ".."));
    const file = path.resolve(root, process.env.RELAY_JSON || path.join("target", "relay", "relay.json"));
    if (!fs.existsSync(file)) throw new Error(`${file} not found: run make relay-artifact (it cross-builds the relay and writes relay.json)`);
    const fail = (what: string): never => { throw new Error(`${file}: ${what}`); };
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    const str = (v: unknown, field: string): string => (typeof v === "string" && v.length > 0 ? v : fail(`${field} must be a non-empty string`));
    const sha256 = str(raw.sha256, "sha256");
    if (!/^[0-9a-f]{64}$/.test(sha256)) fail("sha256 must be 64 lowercase hex digits");
    const key = str(raw.key, "key");
    const want = `${RELAY_KEY_PREFIX}${sha256.slice(0, 16)}`;
    if (key !== want) fail(`key ${key} does not match the sha256 (expected ${want}): run make relay-artifact`);
    const version = str(raw.version, "version");
    if (!/^[0-9A-Za-z.+-]{1,32}$/.test(version)) fail("version must be 1 to 32 of 0-9 A-Z a-z . + -");
    const binary = str(raw.binary, "binary");
    const binaryPath = path.resolve(root, binary);
    if (!fs.existsSync(binaryPath)) fail(`${binaryPath} not found: run make relay-artifact`);
    // Read once: the bytes hashed here are the bytes copied for the upload.
    const bytes = fs.readFileSync(binaryPath);
    const actual = crypto.createHash("sha256").update(bytes).digest("hex");
    if (actual !== sha256) fail(`${binaryPath} has sha256 ${actual}, not the recorded one: relay.json is stale, run make relay-artifact`);
    const uploadPath = uploadCopy(file, bytes, sha256, path.join(path.dirname(file), "upload"), "");
    return { binary, binaryPath, uploadPath, sha256, key, version };
}

export interface Relay {
    instance: aws.ec2.Instance;
    eip: aws.ec2.Eip;
    eipAssociation: aws.ec2.EipAssociation;
    role: aws.iam.Role;
    rolePolicy: aws.iam.RolePolicy;
    profile: aws.iam.InstanceProfile;
    logGroup: aws.cloudwatch.LogGroup;
    artifact: aws.s3.BucketObjectv2;
    artifactParameter: aws.ssm.Parameter;
}

/** The relay's resources, every one with the Pulumi name the inventory lists, and nothing else. */
export function createRelay(
    spec: EgressSpec, guard: EgressGuard, names: pulumi.Output<Names>, net: Egress, artifacts: Artifacts, relayJson: RelayJson, tags: Record<string, string>,
    providers: EgressProviders,
): Relay {
    const cfg = spec.cfg;
    const opts = { provider: providers.aws };
    const named = (name: string) => ({ ...tags, Name: name });
    const files = renderRelayFiles(cfg, REGION);

    const logGroup = new aws.cloudwatch.LogGroup(NET.relayLogGroup, { name: cfg.relayLogGroup, retentionInDays: cfg.relayLogRetentionDays, tags }, opts);
    // A new binary is a new key, hence a replacement: the new object exists before the parameter names it.
    const artifact = new aws.s3.BucketObjectv2(NET.relayArtifact, {
        bucket: artifacts.bucket.id, key: relayJson.key, source: new pulumi.asset.FileAsset(relayJson.uploadPath), contentType: "application/octet-stream", tags,
    }, { ...opts, dependsOn: [artifacts.publicAccess] });
    // Never ignoreChanges: every deploy pins the binary it uploaded (the reload unit installs it within a minute).
    const artifactParameter = new aws.ssm.Parameter(NET.relayArtifactParameter, {
        name: `${cfg.relayParameterPrefix}/artifact`, type: "String", tier: "Standard", dataType: "text",
        insecureValue: pulumi.all([artifacts.bucket.bucket, artifact.key]).apply(([bucket, key]) => relayArtifactValue({ bucket, key, sha256: relayJson.sha256, version: relayJson.version })),
        description: "ai-env relay: the hash-pinned binary its reload unit installs (make relay-artifact)", tags,
    }, opts);

    const role = new aws.iam.Role(RELAY_ROLE_NAME, {
        name: RELAY_ROLE_NAME, description: "ai-env relay: SSM agent, its own parameters and binary, its log group (root units only)", assumeRolePolicy: JSON.stringify(relayTrustPolicy()), tags,
    }, opts);
    const ssmAttachment = new aws.iam.RolePolicyAttachment(`${RELAY_ROLE_NAME}-ssm`, { role: role.name, policyArn: SSM_INSTANCE_POLICY_ARN }, opts);
    const rolePolicy = new aws.iam.RolePolicy(RELAY_ROLE_NAME, { name: RELAY_ROLE_NAME, role: role.id, policy: names.apply((n) => JSON.stringify(relayRolePolicy(n))) }, opts); // scratch:relay-policy
    const profile = new aws.iam.InstanceProfile(RELAY_INSTANCE_PROFILE_NAME, { name: RELAY_INSTANCE_PROFILE_NAME, role: role.name, tags }, opts);

    const ami = aws.ssm.getParameterOutput({ name: AMI_PARAMETER }, opts).insecureValue;
    const instance = new aws.ec2.Instance(NET.relayInstance, {
        ami,
        instanceType: cfg.relayInstanceType,
        subnetId: net.proxySubnet.id,
        privateIp: cfg.relayIp,
        // LD-I7: read back as "the primary interface has a public address", which the Elastic IP gives; it boots with
        // internet before the association, and AWS releases the automatic address when the Elastic IP attaches.
        associatePublicIpAddress: true,
        vpcSecurityGroupIds: [net.relaySecurityGroup.id],
        iamInstanceProfile: profile.name,
        metadataOptions: { httpEndpoint: "enabled", httpTokens: "required", httpPutResponseHopLimit: 1, instanceMetadataTags: "disabled" }, // scratch:relay-imds
        rootBlockDevice: { volumeType: "gp3", volumeSize: 8, encrypted: true, deleteOnTermination: true },
        creditSpecification: { cpuCredits: "standard" },
        userData: files.userData,
        userDataReplaceOnChange: true,
        tags: named(NET.relayInstance),
        volumeTags: named(NET.relayInstance),
    }, {
        ...opts,
        // A newer AMI comes with a deliberate replacement (its weekly patch keeps this one current), never a routine deploy.
        ignoreChanges: ["ami"],
        // The fixed private IP cannot be held by two instances.
        deleteBeforeReplace: true,
        // Its boot fetches packages (the route, DHCP, the S3 endpoint), its parameters and binary, and ships logs.
        dependsOn: [net.proxyRouteAssociation, net.dhcpAssociation, net.s3Endpoint, ...net.relayRules, logGroup, artifact, artifactParameter, rolePolicy, ssmAttachment],
    });
    guard.track("relay-instance", instance.id);
    const eip = new aws.ec2.Eip(NET.relayEip, { domain: "vpc", tags: named(NET.relayEip) }, opts);
    guard.track("relay-eip", eip.id);
    const eipAssociation = new aws.ec2.EipAssociation(NET.relayEip, { allocationId: eip.allocationId, instanceId: instance.id }, opts); // scratch:relay-eip
    return { instance, eip, eipAssociation, role, rolePolicy, profile, logGroup, artifact, artifactParameter };
}
