// Every IAM document of the ai-env stack, as pure functions of (account id, region, names).
//
// Why pure: the same documents are created by Pulumi (iam.ts) and checked before any deploy by
// `make check-policies` (scripts/print-policies.ts → Access Analyzer validate-policy + simulate-custom-policy),
// so this module imports nothing from Pulumi and runs under plain node.
//
// Action names are only those verified for S3 (plans/s3-plan.md §3, §9): the CloudFormation handler lists of
// AWS::Lambda::MicrovmImage name two actions that do not exist (lambda:TagResource20170331v2,
// lambda:UntagResource20170331v2) and the budgets service has no CreateBudget / DescribeBudget / DeleteBudget
// (ModifyBudget and ViewBudget are the real ones). simulate-* accepts invented names, so names are proven with
// Access Analyzer, which reports an unknown action as an ERROR (INVALID_ACTION). Resource scopes follow the IAM
// service reference: the MicroVM calls authorize on the microvm-image ARN (GetMicrovm and the token calls too),
// while CreateMicrovmImage, PassNetworkConnector and the List* calls have no resource type and need "*".

/** The one region: the MicroVM API answers 403 elsewhere. Never taken from config or the environment. */
export const REGION = "eu-central-1";
export const PROJECT = "ai-env";

export const BUILD_ROLE_NAME = "ai-env-image-build";
export const EXECUTION_ROLE_NAME = "ai-env-vm-exec";
export const RUNTIME_USER_NAME = "ai-env-runtime";
export const RUNTIME_POLICY_NAME = "MacRuntimePolicy";
export const DEPLOY_POLICY_NAME = "ai-env-deploy";
export const BUDGET_NAME = "ai-env-monthly";
/** Pulumi auto-names the bucket `<prefix>-<7 random>`; the deploy policy scopes S3 to this prefix. */
export const BUCKET_PREFIX = "ai-env-artifacts";
/** Key prefix of the hash-keyed image zips (`ai-env/image-<sha256[:16]>.zip`, written by `make image-zip`). */
export const ZIP_KEY_PREFIX = "ai-env/image-";
/** The service that assumes the build and execution roles. */
export const LAMBDA_SERVICE = "lambda.amazonaws.com";

/** The managed INTERNET_EGRESS network connector (the image build downloads packages and claude). */
export function internetEgressConnectorArn(region: string): string {
    return `arn:aws:lambda:${region}:aws:network-connector:aws-network-connector:INTERNET_EGRESS`;
}

export interface Names {
    accountId: string;
    region: string;
    /** The artifacts bucket (its real, auto-generated name). */
    bucket: string;
    imageName: string;
    logGroup: string;
}

export interface Statement {
    Sid: string;
    Effect: "Allow";
    Principal?: { Service: string };
    Action: string[];
    Resource?: string[];
    Condition?: Record<string, Record<string, string | string[]>>;
}

export interface PolicyDocument {
    Version: "2012-10-17";
    Statement: Statement[];
}

export function imageArn(n: Names): string {
    return `arn:aws:lambda:${n.region}:${n.accountId}:microvm-image:${n.imageName}`;
}

export function roleArn(n: Names, role: string): string {
    return `arn:aws:iam::${n.accountId}:role/${role}`;
}

export function logGroupArns(n: Names): string[] {
    const group = `arn:aws:logs:${n.region}:${n.accountId}:log-group:${n.logGroup}`;
    return [group, `${group}:*`];
}

function doc(...statements: Statement[]): PolicyDocument {
    return { Version: "2012-10-17", Statement: statements };
}

const passedToLambda = { StringEquals: { "iam:PassedToService": LAMBDA_SERVICE } };

/** The three calls that write runtime and build logs, on the one log group (§9). */
function writeLogs(n: Names, sid: string): Statement {
    return { Sid: sid, Effect: "Allow", Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource: logGroupArns(n) };
}

/** Trust of the build and the execution role: Lambda MicroVMs assume them and tag the session. */
export function lambdaTrustPolicy(): PolicyDocument {
    return doc({ Sid: "LambdaMicrovms", Effect: "Allow", Principal: { Service: LAMBDA_SERVICE }, Action: ["sts:AssumeRole", "sts:TagSession"] });
}

/** Build role: read the hash-keyed zips, write the build log. Nothing else. */
export function buildRolePolicy(n: Names): PolicyDocument {
    return doc(
        { Sid: "ReadImageZip", Effect: "Allow", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${n.bucket}/${ZIP_KEY_PREFIX}*`] },
        writeLogs(n, "WriteBuildLogs"),
    );
}

/** Execution role (passed at run-microvm): runtime logs only, so in-VM code can at most write events to one group. */
export function executionRolePolicy(n: Names): PolicyDocument {
    return doc(writeLogs(n, "WriteRuntimeLogs"));
}

/** The runtime actions on the image, allowed to ai-env-runtime (§9); tested by `make check-policies`. */
export const RUNTIME_IMAGE_ACTIONS = [
    "lambda:RunMicrovm", "lambda:GetMicrovm", "lambda:SuspendMicrovm", "lambda:ResumeMicrovm", "lambda:TerminateMicrovm",
    "lambda:CreateMicrovmAuthToken", "lambda:CreateMicrovmShellAuthToken",
    "lambda:GetMicrovmImage", "lambda:GetMicrovmImageVersion", "lambda:ListMicrovmImageVersions",
];
export const RUNTIME_LIST_ACTIONS = ["lambda:ListMicrovms", "lambda:ListManagedMicrovmImages", "lambda:ListManagedMicrovmImageVersions"];
/**
 * Tentative (D22): S4 confirms or removes them. PassNetworkConnector has no resource type in the IAM service
 * reference (like CreateMicrovmImage and the List* calls), so it can only be granted on "*".
 */
export const PASS_CONNECTOR_ACTION = "lambda:PassNetworkConnector";
export const GET_CONNECTOR_ACTION = "lambda:GetNetworkConnector";

/** Network connectors: the AWS-managed ones (INTERNET_EGRESS, SHELL_INGRESS) and this account's (S5). */
export function connectorArns(n: Names): string[] {
    return [`arn:aws:lambda:${n.region}:aws:network-connector:*`, `arn:aws:lambda:${n.region}:${n.accountId}:network-connector:*`];
}

/**
 * MacRuntimePolicy on the user ai-env-runtime (the key the bridge holds). Everything else is implicitly denied:
 * creating, updating or deleting images and versions, every cloudformation:, budgets:, s3:, logs: action and every
 * other iam: action.
 */
export function runtimePolicy(n: Names): PolicyDocument {
    return doc(
        { Sid: "MicrovmsOfTheImage", Effect: "Allow", Action: RUNTIME_IMAGE_ACTIONS, Resource: [imageArn(n)] },
        { Sid: "ListMicrovms", Effect: "Allow", Action: RUNTIME_LIST_ACTIONS, Resource: ["*"] },
        { Sid: "GetNetworkConnectorsTentative", Effect: "Allow", Action: [GET_CONNECTOR_ACTION], Resource: connectorArns(n) },
        { Sid: "PassNetworkConnectorTentative", Effect: "Allow", Action: [PASS_CONNECTOR_ACTION], Resource: ["*"] },
        { Sid: "PassExecutionRoleTentative", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, EXECUTION_ROLE_NAME)], Condition: passedToLambda },
    );
}

/**
 * ai-env-deploy: what a non-administrator would need to run `make deploy` / `make destroy`, except creating,
 * changing or deleting ai-env-deploy itself, which needs an administrator (the stack creates it; it is attached to
 * nothing: `rust` is an administrator). Validated for names by Access Analyzer, not for sufficiency. It is not a
 * privilege boundary (it can write the runtime user's policy and pass the build role); it only reads itself, so a
 * principal holding it cannot rewrite it.
 */
export function deployPolicy(n: Names): PolicyDocument {
    const acct = n.accountId;
    const bucket = `arn:aws:s3:::${BUCKET_PREFIX}-*`;
    return doc(
        {
            Sid: "CloudControl", Effect: "Allow", Resource: ["*"],
            Action: ["cloudformation:CreateResource", "cloudformation:GetResource", "cloudformation:UpdateResource", "cloudformation:DeleteResource",
                "cloudformation:ListResources", "cloudformation:GetResourceRequestStatus", "cloudformation:ListResourceRequests", "cloudformation:CancelResourceRequest"],
        },
        {
            Sid: "MicrovmImageHandlers", Effect: "Allow", Resource: [imageArn(n)],
            Action: ["lambda:GetMicrovmImage", "lambda:UpdateMicrovmImage", "lambda:DeleteMicrovmImage",
                "lambda:GetMicrovmImageVersion", "lambda:ListMicrovmImageVersions", "lambda:UpdateMicrovmImageVersion", "lambda:DeleteMicrovmImageVersion",
                "lambda:ListMicrovmImageBuilds", "lambda:GetMicrovmImageBuild", "lambda:TagResource", "lambda:UntagResource", "lambda:ListTags"],
        },
        // No resource type in the IAM service reference: "*" is the only possible scope.
        {
            Sid: "MicrovmUnscoped", Effect: "Allow", Resource: ["*"],
            Action: ["lambda:CreateMicrovmImage", "lambda:ListMicrovmImages", "lambda:ListMicrovms", "lambda:ListManagedMicrovmImages",
                "lambda:ListManagedMicrovmImageVersions", PASS_CONNECTOR_ACTION],
        },
        { Sid: "EgressConnector", Effect: "Allow", Resource: connectorArns(n), Action: [GET_CONNECTOR_ACTION] },
        { Sid: "PassBuildAndExecutionRoles", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, BUILD_ROLE_NAME), roleArn(n, EXECUTION_ROLE_NAME)], Condition: passedToLambda },
        {
            Sid: "Roles", Effect: "Allow", Resource: [`arn:aws:iam::${acct}:role/${PROJECT}-*`],
            Action: ["iam:CreateRole", "iam:GetRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy",
                "iam:TagRole", "iam:UntagRole", "iam:ListRoleTags", "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy",
                "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole"],
        },
        {
            Sid: "RuntimeUser", Effect: "Allow", Resource: [`arn:aws:iam::${acct}:user/${RUNTIME_USER_NAME}`],
            Action: ["iam:CreateUser", "iam:GetUser", "iam:DeleteUser", "iam:TagUser", "iam:UntagUser", "iam:ListUserTags",
                "iam:PutUserPolicy", "iam:GetUserPolicy", "iam:DeleteUserPolicy", "iam:ListUserPolicies", "iam:ListAttachedUserPolicies", "iam:ListGroupsForUser",
                "iam:ListAccessKeys", "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListSigningCertificates", "iam:DeleteSigningCertificate",
                "iam:ListSSHPublicKeys", "iam:DeleteSSHPublicKey", "iam:ListServiceSpecificCredentials", "iam:DeleteServiceSpecificCredential",
                "iam:ListMFADevices", "iam:DeactivateMFADevice", "iam:GetLoginProfile", "iam:DeleteLoginProfile"],
        },
        {
            Sid: "ReadDeployPolicy", Effect: "Allow", Resource: [`arn:aws:iam::${acct}:policy/${DEPLOY_POLICY_NAME}`],
            Action: ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:ListPolicyTags", "iam:ListEntitiesForPolicy"],
        },
        {
            Sid: "ArtifactsBucket", Effect: "Allow", Resource: [bucket],
            Action: ["s3:CreateBucket", "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucket*", "s3:PutBucket*", "s3:DeleteBucket*",
                "s3:GetAccelerateConfiguration", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:GetEncryptionConfiguration"],
        },
        {
            Sid: "ArtifactsObjects", Effect: "Allow", Resource: [`${bucket}/*`],
            Action: ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectTagging", "s3:GetObjectTagging", "s3:DeleteObjectTagging"],
        },
        {
            Sid: "LogGroup", Effect: "Allow", Resource: logGroupArns(n),
            Action: ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource",
                "logs:ListTagsForResource", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartLiveTail"],
        },
        { Sid: "DescribeLogGroups", Effect: "Allow", Resource: ["*"], Action: ["logs:DescribeLogGroups"] },
        {
            Sid: "Budget", Effect: "Allow", Resource: [`arn:aws:budgets::${acct}:budget/${BUDGET_NAME}`],
            Action: ["budgets:ModifyBudget", "budgets:ViewBudget", "budgets:TagResource", "budgets:UntagResource", "budgets:ListTagsForResource"],
        },
    );
}

export type PolicyKind = "identity" | "trust";

export interface NamedPolicy {
    name: string;
    kind: PolicyKind;
    document: PolicyDocument;
}

/** Every document of the stack, in a stable order (the check-policies loop and the Pulumi program share it). */
export function allPolicies(n: Names): NamedPolicy[] {
    return [
        { name: "build-trust", kind: "trust", document: lambdaTrustPolicy() },
        { name: "execution-trust", kind: "trust", document: lambdaTrustPolicy() },
        { name: "build", kind: "identity", document: buildRolePolicy(n) },
        { name: "execution", kind: "identity", document: executionRolePolicy(n) },
        { name: "runtime", kind: "identity", document: runtimePolicy(n) },
        { name: "deploy", kind: "identity", document: deployPolicy(n) },
    ];
}
