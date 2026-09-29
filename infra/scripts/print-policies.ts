// Prints the stack's IAM documents for `make check-policies` (compiled by tsc into target/infra-policies and run
// with plain node, so it and policies.ts import nothing from Pulumi).
//
//   node print-policies.js --account-id <12 digits> --image-config infra/image-config.json [--bucket NAME]
//       one line per document: <name> TAB <IDENTITY_POLICY|RESOURCE_POLICY> TAB <resource type or ->
//   ... --name <name>
//       that document as compact JSON (what validate-policy / simulate-custom-policy take)
//   ... --arn image|execution-role|build-role|egress
//       an ARN the checks simulate against
//
// The account id is passed in by the caller (from `aws sts get-caller-identity`) and only ever printed to stdout.
import * as fs from "fs";
import {
    BUCKET_PREFIX, BUILD_ROLE_NAME, EXECUTION_ROLE_NAME, Names, REGION, allPolicies, imageArn, internetEgressConnectorArn, roleArn,
} from "../policies";

function usage(msg: string): never {
    process.stderr.write(`print-policies: ${msg}\nusage: print-policies --account-id <12 digits> --image-config <file> [--bucket NAME] [--name NAME | --arn KIND]\n`);
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
const names: Names = {
    accountId,
    region: REGION,
    // The real name is auto-generated at create time; any name under the prefix exercises the same documents.
    bucket: args.get("bucket") ?? `${BUCKET_PREFIX}-0000000`,
    imageName: config.imageName,
    logGroup: config.logGroup,
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
    };
    process.stdout.write(`${arns[arn] ?? usage(`no ARN kind ${arn}`)}\n`);
} else {
    for (const p of policies) {
        const [type, resource] = p.kind === "trust" ? ["RESOURCE_POLICY", "AWS::IAM::AssumeRolePolicyDocument"] : ["IDENTITY_POLICY", "-"];
        process.stdout.write(`${p.name}\t${type}\t${resource}\n`);
    }
}
