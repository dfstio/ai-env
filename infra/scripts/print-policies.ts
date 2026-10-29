// Prints the stack's IAM documents for `make check-policies` (compiled by tsc into target/infra-policies and run
// with plain node, so it and policies.ts import nothing from Pulumi).
//
//   node print-policies.js --account-id <12 digits> --image-config infra/image-config.json --egress-config infra/egress-config.json
//                          [--bucket NAME] [--vm-subnet-id ID] [--vm-security-group-id ID] [--connector-arn ARN] [--proxy-instance-id ID]
//                          [--s3-endpoint-id ID] [--relay-instance-id ID]
//       one line per document: <name> TAB <IDENTITY_POLICY|RESOURCE_POLICY> TAB <resource type or ->
//   ... --name <name>
//       that document as compact JSON (what validate-policy / simulate-custom-policy take)
//   ... --arn image|execution-role|build-role|egress|connector|connector-by-name|other-connector|proxy-parameter|squid-log-group|image-log-group|
//             dns-log-group|runtime-user|ops-user|deployer-user|proxy-role|operator-role|ssm-instance-policy|operator-policy|deploy-policy|
//             deploy-egress-policy|deploy-dns-policy|deployer-policy|ops-policy|transcripts-bucket|transcripts-vm-object|transcripts-mac-object|
//             transcripts-egress-check|transcripts-outside-prefix|transcripts-claude-object|other-bucket-object|al2023-object|s3-endpoint|
//             relay-role|relay-instance-profile|relay-parameter|relay-tls|relay-artifact-parameter|relay-log-group|relay-artifact-object
//       an ARN the checks simulate against (or fetch: the two AWS managed policies the egress roles attach); `s3-endpoint`
//       prints the endpoint id the bucket policy names (an id, the simulations' aws:SourceVpce)
//
// The egress documents (S5) are the proxy role's trust and inline policy and the operator role's trust and inline
// Deny (`operator`); the deploy policy's CreateNetworkConnector condition and the operator role's Deny name the VM
// subnet and security group, whose ids exist only in a stack, so the printer uses well-formed placeholders unless
// they are given (check-policies passes other ids for its operator simulations, since it uses the placeholders' ARNs
// as "another subnet" and "another group"). Deliberately no --arn kind for the VM subnet or group: the simulations
// build those ARNs themselves, so a wrong ARN shape in policies.ts fails them.
//
// S8 operators: the operator identities' documents, `deployer` (ai-env-deployer's supplement) and `ops` (held by
// ai-env-ops and ai-env-deployer), are listed too, so Access Analyzer and the size check cover them. The ops policy
// names the proxy instance, whose id exists only in a stack: --proxy-instance-id, else a placeholder of the real shape
// that differs from check-policies' "another instance" (all zeros). Deliberately no --arn kind for the proxy instance
// or the documents either: check-policies builds them from egress-config.json's names. The users' and the stack's
// policies' ARNs are printed (--arn), as the targets of section 6 and 7's simulations.
//
// S9: the two resource policies of the transcript store, `s3-endpoint` (the S3 gateway endpoint's: RESOURCE_POLICY with
// no resource type, which Access Analyzer has none for) and `transcripts-bucket` (the bucket's: AWS::S3::Bucket). The
// bucket policy names the endpoint's id, which exists only in a stack: --s3-endpoint-id, else a placeholder of the real
// shape (the contracts' example), which `--arn s3-endpoint` prints so the simulations' aws:SourceVpce is the one the
// document names. The transcripts bucket's name is the account's (transcriptsBucketName); the object ARNs the
// simulations ask are printed (--arn transcripts-*), so a wrong key shape in policies.ts fails them.
//
// S13: the relay's role (`relay-trust`, `relay`); the ops policy names the relay instance, whose id exists only in a
// stack: --relay-instance-id, else a placeholder of the real shape (not the proxy's). The relay's ARNs the simulations
// ask are printed (--arn relay-*): its role and profile, a list parameter (`workers`), the TLS pair, the artifact
// parameter, its log group and an artifact object.
//
// The account id is passed in by the caller (from `aws sts get-caller-identity`) and only ever printed to stdout.
import * as fs from "fs";
import { egressNames, loadEgressConfig } from "../egress-spec";
import {
    AL2023_REPO_BUCKET, BUCKET_PREFIX, BUILD_ROLE_NAME, CONNECTOR_OPERATOR_POLICY_ARN, DEPLOYER_POLICY_NAME, DEPLOYER_USER_NAME, DEPLOY_DNS_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME,
    DEPLOY_POLICY_NAME, EGRESS_CHECK_PREFIX, EXECUTION_ROLE_NAME, Names, OPS_POLICY_NAME, OPS_USER_NAME, REGION, RELAY_INSTANCE_PROFILE_NAME, RELAY_KEY_PREFIX, RELAY_ROLE_NAME,
    RELAY_TLS, RUNTIME_USER_NAME, SSM_INSTANCE_POLICY_ARN, TRANSCRIPTS_KEY_PREFIX, allPolicies, dnsQueryLogGroupArns, egressLogGroupArns, imageArn, instanceProfileArn,
    internetEgressConnectorArn, logGroupArns, policyArn, proxyParameterArn, relayLogGroupArns, relayParameterArn, roleArn, transcriptsBucketName, userArn,
} from "../policies";

function usage(msg: string): never {
    process.stderr.write(`print-policies: ${msg}\nusage: print-policies --account-id <12 digits> --image-config <file> --egress-config <file> [--bucket NAME] [--vm-subnet-id ID] [--vm-security-group-id ID] [--connector-arn ARN] [--proxy-instance-id ID] [--s3-endpoint-id ID] [--relay-instance-id ID] [--name NAME | --arn KIND]\n`);
    process.exit(2);
}

const args = new Map<string, string>();
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (!k.startsWith("--") || v === undefined) usage(`bad argument ${k}`);
    args.set(k.slice(2), v);
}
const accountId = args.get("account-id") ?? usage("--account-id is required");
if (!/^[0-9]{12}$/.test(accountId)) usage("--account-id must be 12 digits");
const configFile = args.get("image-config") ?? usage("--image-config is required");
const config = JSON.parse(fs.readFileSync(configFile, "utf-8"));
const egressConfig = loadEgressConfig(args.get("egress-config") ?? usage("--egress-config is required"));
const names: Names = {
    accountId,
    region: REGION,
    // The real name is auto-generated at create time; any name under the prefix exercises the same documents.
    bucket: args.get("bucket") ?? `${BUCKET_PREFIX}-0000000`,
    imageName: config.imageName,
    logGroup: config.logGroup,
    egress: {
        ...egressNames(egressConfig),
        // Placeholders of the real shape: the ids exist only once a stack created the subnet and the group.
        vmSubnetId: args.get("vm-subnet-id") ?? "subnet-00000000000000000",
        vmSecurityGroupId: args.get("vm-security-group-id") ?? "sg-00000000000000000",
        // Likewise the connector's ARN (S7 D5: runtimePolicy grants GetNetworkConnector on exactly it). The
        // placeholder is in the service's own id form, so `--arn connector` and the document always name the same
        // ARN and the simulations mean what they say.
        connectorArn: args.get("connector-arn") ?? `arn:aws:lambda:${REGION}:${accountId}:network-connector:nc-00000000000000000`,
        // And the proxy instance's id (S8 operators: opsPolicy scopes start, stop and SendCommand to exactly it).
        proxyInstanceId: args.get("proxy-instance-id") ?? "i-0123456789abcdef0",
        // S13: and the relay instance's (opsPolicy's RelayInstance), another placeholder of the real shape.
        relayInstanceId: args.get("relay-instance-id") ?? "i-0123456789abcdef1",
    },
    // S9: the transcripts bucket (the account's) and the S3 gateway endpoint's id (a placeholder of the real shape).
    transcriptsBucket: transcriptsBucketName(accountId),
    s3EndpointId: args.get("s3-endpoint-id") ?? "vpce-0123456789abcdef0",
};
const policies = allPolicies(names);

const name = args.get("name");
const arn = args.get("arn");
if (name !== undefined) {
    const p = policies.find((x) => x.name === name) ?? usage(`no policy named ${name}`);
    process.stdout.write(`${JSON.stringify(p.document)}\n`);
} else if (arn !== undefined) {
    // A Map, never an object literal: a kind like `constructor` must not find Object.prototype's.
    const arns = new Map<string, string>([
        ["image", imageArn(names)],
        ["execution-role", roleArn(names, EXECUTION_ROLE_NAME)],
        ["build-role", roleArn(names, BUILD_ROLE_NAME)],
        ["egress", internetEgressConnectorArn(REGION)],
        // Exactly what runtimePolicy's ReadTheEgressConnector names, so the simulations prove that grant (S7 D5): the
        // id form the service reports, and the name form the IAM service reference documents.
        ["connector", names.egress.connectorArn as string],
        ["connector-by-name", `arn:aws:lambda:${REGION}:${accountId}:network-connector:${egressConfig.connectorName}`],
        // Another connector of the same account: the Get grant must not reach it.
        ["other-connector", `arn:aws:lambda:${REGION}:${accountId}:network-connector:nc-11111111111111111`],
        ["proxy-parameter", proxyParameterArn(names, "allow")],
        ["squid-log-group", egressLogGroupArns(names)[0]],
        ["image-log-group", logGroupArns(names)[0]],
        ["dns-log-group", dnsQueryLogGroupArns(names)[0]],
        ["runtime-user", userArn(names, RUNTIME_USER_NAME)],
        ["ops-user", userArn(names, OPS_USER_NAME)],
        ["deployer-user", userArn(names, DEPLOYER_USER_NAME)],
        ["proxy-role", roleArn(names, egressConfig.proxyRoleName)],
        ["operator-role", roleArn(names, egressConfig.operatorRoleName)],
        ["ssm-instance-policy", SSM_INSTANCE_POLICY_ARN],
        ["operator-policy", CONNECTOR_OPERATOR_POLICY_ARN],
        ["deploy-policy", policyArn(names, DEPLOY_POLICY_NAME)],
        ["deploy-egress-policy", policyArn(names, DEPLOY_EGRESS_POLICY_NAME)],
        ["deploy-dns-policy", policyArn(names, DEPLOY_DNS_POLICY_NAME)],
        ["deployer-policy", policyArn(names, DEPLOYER_POLICY_NAME)],
        ["ops-policy", policyArn(names, OPS_POLICY_NAME)],
        // S9: the transcripts bucket and objects of each kind of key (a VM's segment, a Mac-begun chat's object, the
        // egress check's, one outside `v1/`), another bucket's object, an AL2023 repository object, the endpoint's id.
        ["transcripts-bucket", `arn:aws:s3:::${names.transcriptsBucket}`],
        ["transcripts-vm-object", `arn:aws:s3:::${names.transcriptsBucket}/${TRANSCRIPTS_KEY_PREFIX}0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/vm/g1/s/000000000000bc55`],
        ["transcripts-mac-object", `arn:aws:s3:::${names.transcriptsBucket}/${TRANSCRIPTS_KEY_PREFIX}0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/mac/${"0".repeat(64)}`],
        ["transcripts-egress-check", `arn:aws:s3:::${names.transcriptsBucket}/${EGRESS_CHECK_PREFIX}0123abcd`],
        ["transcripts-outside-prefix", `arn:aws:s3:::${names.transcriptsBucket}/x/_egress-check/0123abcd`],
        // S11 (part A): a claude object, v1/_claude/mac/<version>/<sha256> (wire::s3::CLAUDE_PREFIX).
        ["transcripts-claude-object", `arn:aws:s3:::${names.transcriptsBucket}/${TRANSCRIPTS_KEY_PREFIX}_claude/mac/2.1.308/${"0".repeat(64)}`],
        ["other-bucket-object", "arn:aws:s3:::not-ai-env-transcripts/v1/x"],
        ["al2023-object", `arn:aws:s3:::${AL2023_REPO_BUCKET}/core/mirrors/latest/aarch64/mirror.list`],
        ["s3-endpoint", names.s3EndpointId as string],
        // S13: the relay's role, instance profile, a list parameter, the TLS pair, the artifact parameter, its log group
        // and an artifact object of the bucket.
        ["relay-role", roleArn(names, RELAY_ROLE_NAME)],
        ["relay-instance-profile", instanceProfileArn(names, RELAY_INSTANCE_PROFILE_NAME)],
        ["relay-parameter", relayParameterArn(names, "workers")],
        ["relay-tls", relayParameterArn(names, RELAY_TLS)],
        ["relay-artifact-parameter", relayParameterArn(names, "artifact")],
        ["relay-log-group", relayLogGroupArns(names)[0]],
        ["relay-artifact-object", `arn:aws:s3:::${names.bucket}/${RELAY_KEY_PREFIX}0123456789abcdef`],
    ]);
    process.stdout.write(`${arns.get(arn) ?? usage(`no ARN kind ${arn}`)}\n`);
} else {
    for (const p of policies) {
        // S9's resource policies: the bucket's is validated as an S3 bucket policy; the endpoint's has no resource type.
        const [type, resource] = p.kind === "trust" ? ["RESOURCE_POLICY", "AWS::IAM::AssumeRolePolicyDocument"]
            : p.kind === "resource" ? ["RESOURCE_POLICY", p.name === "transcripts-bucket" ? "AWS::S3::Bucket" : "-"]
            : ["IDENTITY_POLICY", "-"];
        process.stdout.write(`${p.name}\t${type}\t${resource}\n`);
    }
}
