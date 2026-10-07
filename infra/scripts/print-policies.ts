// Prints the stack's IAM documents for `make check-policies` (compiled by tsc into target/infra-policies and run
// with plain node, so it and policies.ts import nothing from Pulumi).
//
//   node print-policies.js --account-id <12 digits> --image-config infra/image-config.json --egress-config infra/egress-config.json
//                          [--bucket NAME] [--vm-subnet-id ID] [--vm-security-group-id ID] [--connector-arn ARN]
//       one line per document: <name> TAB <IDENTITY_POLICY|RESOURCE_POLICY> TAB <resource type or ->
//   ... --name <name>
//       that document as compact JSON (what validate-policy / simulate-custom-policy take)
//   ... --arn image|execution-role|build-role|egress|connector|connector-by-name|other-connector|proxy-parameter|squid-log-group|image-log-group|runtime-user|proxy-role|operator-role|
//             ssm-instance-policy|operator-policy
//       an ARN the checks simulate against (or fetch: the two AWS managed policies the egress roles attach)
//
// The egress documents (S5) are the proxy role's trust and inline policy and the operator role's trust and inline
// Deny (`operator`); the deploy policy's CreateNetworkConnector condition and the operator role's Deny name the VM
// subnet and security group, whose ids exist only in a stack, so the printer uses well-formed placeholders unless
// they are given (check-policies passes other ids for its operator simulations, since it uses the placeholders' ARNs
// as "another subnet" and "another group"). Deliberately no --arn kind for the VM subnet or group: the simulations
// build those ARNs themselves, so a wrong ARN shape in policies.ts fails them.
//
// The account id is passed in by the caller (from `aws sts get-caller-identity`) and only ever printed to stdout.
import * as fs from "fs";
import { egressNames, loadEgressConfig } from "../egress-spec";
import {
    BUCKET_PREFIX, BUILD_ROLE_NAME, CONNECTOR_OPERATOR_POLICY_ARN, EXECUTION_ROLE_NAME, Names, REGION, RUNTIME_USER_NAME, SSM_INSTANCE_POLICY_ARN, allPolicies,
    egressLogGroupArns, imageArn, internetEgressConnectorArn, logGroupArns, proxyParameterArn, roleArn,
} from "../policies";

function usage(msg: string): never {
    process.stderr.write(`print-policies: ${msg}\nusage: print-policies --account-id <12 digits> --image-config <file> --egress-config <file> [--bucket NAME] [--vm-subnet-id ID] [--vm-security-group-id ID] [--connector-arn ARN] [--name NAME | --arn KIND]\n`);
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
    },
};
const policies = allPolicies(names);

const name = args.get("name");
const arn = args.get("arn");
if (name !== undefined) {
    const p = policies.find((x) => x.name === name) ?? usage(`no policy named ${name}`);
    process.stdout.write(`${JSON.stringify(p.document)}\n`);
} else if (arn !== undefined) {
    const arns: Record<string, string> = {
        image: imageArn(names),
        "execution-role": roleArn(names, EXECUTION_ROLE_NAME),
        "build-role": roleArn(names, BUILD_ROLE_NAME),
        egress: internetEgressConnectorArn(REGION),
        // Exactly what runtimePolicy's ReadTheEgressConnector names, so the simulations prove that grant (S7 D5): the
        // id form the service reports, and the name form the IAM service reference documents.
        connector: names.egress.connectorArn as string,
        "connector-by-name": `arn:aws:lambda:${REGION}:${accountId}:network-connector:${egressConfig.connectorName}`,
        // Another connector of the same account: the Get grant must not reach it.
        "other-connector": `arn:aws:lambda:${REGION}:${accountId}:network-connector:nc-11111111111111111`,
        "proxy-parameter": proxyParameterArn(names, "allow"),
        "squid-log-group": egressLogGroupArns(names)[0],
        "image-log-group": logGroupArns(names)[0],
        "runtime-user": `arn:aws:iam::${accountId}:user/${RUNTIME_USER_NAME}`,
        "proxy-role": roleArn(names, egressConfig.proxyRoleName),
        "operator-role": roleArn(names, egressConfig.operatorRoleName),
        "ssm-instance-policy": SSM_INSTANCE_POLICY_ARN,
        "operator-policy": CONNECTOR_OPERATOR_POLICY_ARN,
    };
    process.stdout.write(`${arns[arn] ?? usage(`no ARN kind ${arn}`)}\n`);
} else {
    for (const p of policies) {
        const [type, resource] = p.kind === "trust" ? ["RESOURCE_POLICY", "AWS::IAM::AssumeRolePolicyDocument"] : ["IDENTITY_POLICY", "-"];
        process.stdout.write(`${p.name}\t${type}\t${resource}\n`);
    }
}
