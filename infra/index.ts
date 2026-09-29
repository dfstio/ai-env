// ai-env S3 infrastructure (plans/s3-plan.md §8, §9): the artifacts bucket with the hash-keyed image zip, the log
// group, the build and execution roles, the runtime user ai-env-runtime, the unattached ai-env-deploy policy, the
// monthly budget and the aws-native MicrovmImage ai-env-agent.
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

const envFile = path.join(__dirname, "config", `${stack}.env`);
const budget = budgetSettings(loadEnvConfig(envFile), envFile);
const imageConfig = loadImageConfig();
const imageJson = loadImageJson();

const tags: Record<string, string> = { Project: PROJECT, Stack: stack };
const awsProvider = new aws.Provider(`aws-${REGION}`, { region: REGION });
const nativeProvider = new awsnative.Provider(`aws-native-${REGION}`, { region: REGION });

const accountId = aws.getCallerIdentityOutput({}, { provider: awsProvider }).accountId;
const artifacts = createArtifacts(imageConfig, imageJson, tags, awsProvider);
const names: pulumi.Output<Names> = pulumi.all([accountId, artifacts.bucket.bucket]).apply(([acct, bucket]) => ({
    accountId: acct, region: REGION, bucket, imageName: imageConfig.imageName, logGroup: imageConfig.logGroup,
}));
const iam = createIam(names, tags, awsProvider);
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
