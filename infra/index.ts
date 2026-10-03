// ai-env S3 infrastructure (plans/s3-plan.md §8, §9): the artifacts bucket with the hash-keyed image zip, the log
// group, the build and execution roles, the runtime user ai-env-runtime, the unattached ai-env-deploy policy, the
// monthly budget and the aws-native MicrovmImage ai-env-agent. S5 (plans/s5-plan.md) adds the egress side
// (egress.ts): a VPC without Amazon DNS, the squid proxy and the network connector `ai-env-egress`.
//
// Why it looks like this: the MicroVM API exists in one region only, so both providers are explicit objects with
// the region from a constant and the program refuses a stack whose aws:region or aws-native:region says otherwise
// (a default provider would follow the CLI's default region). No secret exists in config, outputs or state (D17,
// D23); per-stack settings come from config/<stack>.env as in DFST/monitoring. Outputs feed `ai-env infra status`
// (bridge.toml [aws] and state/infra.toml).
import * as fs from "fs";
import * as path from "path";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsnative from "@pulumi/aws-native";
import { budgetSettings, createBudget } from "./budget";
import { createEgress, guardEgress } from "./egress";
import { assertEgressSpec, egressNames, egressSpec, loadEgressConfig } from "./egress-spec";
import { createIam } from "./iam";
import { createArtifacts, createImage, loadImageConfig, loadImageJson } from "./image";
import { Names, PROJECT, REGION } from "./policies";

const stack = pulumi.getStack();

// The region pin: throw before any resource is registered.
for (const pkg of ["aws", "aws-native"]) {
    const configured = new pulumi.Config(pkg).get("region");
    if (configured !== undefined && configured !== REGION) {
        throw new Error(`${pkg}:region is ${configured} in stack ${stack}, but ai-env is pinned to ${REGION} (the MicroVM API answers 403 elsewhere): pulumi config rm ${pkg}:region --stack ${stack}`);
    }
}

// config/<stack>.env: KEY=VALUE lines, # comments (the DFST/monitoring loadEnvConfig pattern). Settings only, never secrets.
function loadEnvConfig(file: string): Record<string, string> {
    if (!fs.existsSync(file)) throw new Error(`${file} not found: copy config/dev.env.example to it and set BUDGET_EMAIL`);
    const env: Record<string, string> = {};
    for (const raw of fs.readFileSync(file, "utf-8").split("\n")) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
        if (!m) throw new Error(`${file}: not a KEY=VALUE line: ${line}`);
        env[m[1]] = m[2].replace(/^(["'])(.*)\1$/, "$2");
    }
    return env;
}

// The egress spec (S5): refused before any resource is registered, then guarded: the transform checks every resource
// registered after this line against the stack inventory, wherever in the program it comes from, and later
// transform registrations throw. `make preview-scratch NEGATIVE=...` disables the assert through its scratch:assert
// marker (and the guard through egress.ts's scratch:guard), so the next layer alone must refuse.
const egressConfig = loadEgressConfig();
const egress = egressSpec(egressConfig);
assertEgressSpec(egress); // scratch:assert
const imageConfig = loadImageConfig();
const guard = guardEgress(egress, imageConfig);

const envFile = path.join(__dirname, "config", `${stack}.env`);
const budget = budgetSettings(loadEnvConfig(envFile), envFile);
const imageJson = loadImageJson();

const tags: Record<string, string> = { Project: PROJECT, Stack: stack };
const awsProvider = new aws.Provider(`aws-${REGION}`, { region: REGION });
const nativeProvider = new awsnative.Provider(`aws-native-${REGION}`, { region: REGION });

const accountId = aws.getCallerIdentityOutput({}, { provider: awsProvider }).accountId;
const artifacts = createArtifacts(imageConfig, imageJson, tags, awsProvider);
const names: pulumi.Output<Names> = pulumi.all([accountId, artifacts.bucket.bucket]).apply(([acct, bucket]) => ({
    accountId: acct, region: REGION, bucket, imageName: imageConfig.imageName, logGroup: imageConfig.logGroup, egress: egressNames(egressConfig),
}));
const net = createEgress(egress, guard, names, tags, { aws: awsProvider, native: nativeProvider });
// The (unattached) deploy policy waits for the VM subnet and security group (its CreateNetworkConnector condition), as does
// the operator role's Deny in egress.ts (its NotResource).
const deployNames: pulumi.Output<Names> = pulumi.all([names, net.vmSubnet.id, net.vmSecurityGroup.id]).apply(([n, vmSubnetId, vmSecurityGroupId]) => ({
    ...n, egress: { ...n.egress, vmSubnetId, vmSecurityGroupId },
}));
const iam = createIam(names, deployNames, tags, awsProvider);
const image = createImage(imageConfig, REGION, tags, { buildRole: iam.buildRole, buildPolicy: iam.buildPolicy, artifacts }, nativeProvider);
const monthly = createBudget(budget, REGION, tags, awsProvider);

// Consumed by `ai-env infra status` (camelCase; none of them is secret).
export const region = REGION;
export { accountId };
export const imageName = image.name;
export const imageArn = image.imageArn;
export const imageState = image.state;
export const latestActiveImageVersion = image.latestActiveImageVersion;
export const latestFailedImageVersion = image.latestFailedImageVersion;
export const executionRoleArn = iam.executionRole.arn;
export const buildRoleArn = iam.buildRole.arn;
export const runtimeUserName = iam.runtimeUser.name;
export const runtimeUserArn = iam.runtimeUser.arn;
export const deployPolicyArn = iam.deployPolicy.arn;
export const budgetName = monthly.name;
export const bucket = artifacts.bucket.bucket;
export const zipKey = artifacts.zip.key;
export const zipSha256 = imageJson.sha256;
export const logGroup = artifacts.logGroup.name;
export const claudeVersion = imageJson.claudeVersion;
export const shimVersion = imageJson.shimVersion;
// S5 egress (contract 5; `ai-env infra status` maps connectorArn and proxyPrivateIp into bridge.toml [aws]).
export const connectorArn = net.connector.arn;
export const connectorName = net.connector.name;
export const proxyPrivateIp = net.instance.privateIp;
export const proxyInstanceId = net.instance.id;
export const egressVpcId = net.vpc.id;
export const vmSubnetId = net.vmSubnet.id;
export const vmEgressSecurityGroupId = net.vmSecurityGroup.id;
export const proxySecurityGroupId = net.proxySecurityGroup.id;
export const operatorRoleArn = net.operatorRole.arn;
export const egressLogGroup = net.logGroup.name;
export const dnsMode = egressConfig.dnsMode;
export const parameterPrefix = egressConfig.parameterPrefix;
// SHA-256 (lowercase hex) of the exact squid.conf and allow parameter values written above: `ai-env egress status`
// compares the live parameters with them (state/infra.toml).
export const squidConfSha256 = net.squidConfSha256;
export const allowSha256 = net.allowSha256;
