// Every IAM document of the ai-env stack, as pure functions of (account id, region, names). The scratch:* markers are
// edited by `make preview-scratch NEGATIVE=iam-widen` in a scratch copy.
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
//
// S5 (plans/s5-plan.md) adds the egress proxy's role (its own SSM parameters and its squid log group, plus the
// AWS managed SSM agent policy), the network connector's operator role (the AWS managed operator policy, confined
// to the VM subnet and the VM security group by the inline Deny of operatorRolePolicy) and the egress statements of
// the deploy policy. CreateNetworkConnector is the only connector call with the lambda:SubnetIds /
// lambda:SecurityGroupIds keys (IAM service reference, 1 Oct 2026); the network-connector resource type is the
// account's `network-connector:*`.

/** The one region: the MicroVM API answers 403 elsewhere. Never taken from config or the environment. */
export const REGION = "eu-central-1";
export const PROJECT = "ai-env";

export const BUILD_ROLE_NAME = "ai-env-image-build";
export const EXECUTION_ROLE_NAME = "ai-env-vm-exec";
export const RUNTIME_USER_NAME = "ai-env-runtime";
export const RUNTIME_POLICY_NAME = "MacRuntimePolicy";
export const DEPLOY_POLICY_NAME = "ai-env-deploy";
/** S5: the egress statements of the deploy policy, in two more documents (one managed policy holds at most 6144 characters). */
export const DEPLOY_EGRESS_POLICY_NAME = "ai-env-deploy-egress";
export const DEPLOY_DNS_POLICY_NAME = "ai-env-deploy-dns";
/** IAM's limit on a managed policy (characters without whitespace); `make check-policies` asserts every document against it. */
export const MANAGED_POLICY_MAX_CHARS = 6144;
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

/** The services that assume the egress roles (S5). */
export const EC2_SERVICE = "ec2.amazonaws.com";
/**
 * Not trusted: the other candidate principal of the connector's operator role, never seen assuming it (T5.1's CloudTrail
 * AssumeRole events, 1 and 2 Oct 2026, both connector creations: lambda.amazonaws.com only). The deploy policy's
 * PassOperatorRole still accepts it as iam:PassedToService, that value being unmeasured (the root deploy identity
 * bypasses the deploy policy).
 */
export const NETWORK_CONNECTORS_SERVICE = "network-connectors.lambda.amazonaws.com";
/** The SSM agent's actions (without ssm:GetParameter on "*"), for the proxy instance. */
export const SSM_INSTANCE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy";
/**
 * ec2:CreateNetworkInterface in any subnet with any security group (operatorRolePolicy confines it) + the ENI tags;
 * ENI deletion is the service-linked role AWSServiceRoleForLambda's. `make check-policies` pins its action set.
 */
export const CONNECTOR_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy";
/** The managed policies the stack attaches: the deploy policy's iam:AttachRolePolicy is limited to them. */
export const MANAGED_POLICY_ARNS = [SSM_INSTANCE_POLICY_ARN, CONNECTOR_OPERATOR_POLICY_ARN];

/** The egress names (infra/egress-config.json via egress-spec.ts egressNames). */
export interface EgressNames {
    parameterPrefix: string;
    /** The squid access log group. */
    logGroup: string;
    proxyRoleName: string;
    operatorRoleName: string;
    proxyInstanceProfileName: string;
    connectorName: string;
    /**
     * The connector's subnet and security group, ids that exist only once the stack created them: the deploy policy's
     * CreateNetworkConnector condition and the operator role's Deny (operatorRolePolicy) need them.
     */
    vmSubnetId?: string;
    vmSecurityGroupId?: string;
}

export interface Names {
    accountId: string;
    region: string;
    /** The artifacts bucket (its real, auto-generated name). */
    bucket: string;
    imageName: string;
    logGroup: string;
    egress: EgressNames;
}

export interface Statement {
    Sid: string;
    Effect: "Allow" | "Deny";
    Principal?: { Service: string | string[] };
    Action: string[];
    Resource?: string[];
    NotResource?: string[];
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
    return groupArns(n, n.logGroup);
}

function groupArns(n: Names, logGroup: string): string[] {
    const group = `arn:aws:logs:${n.region}:${n.accountId}:log-group:${logGroup}`;
    return [group, `${group}:*`];
}

/** The squid access log group of the egress proxy (S5). */
export function egressLogGroupArns(n: Names): string[] {
    return groupArns(n, n.egress.logGroup);
}

/** The proxy's SSM parameters `<prefix>/*` (a name starting with `/` follows `parameter` directly). */
export function proxyParameterArn(n: Names, name = "*"): string {
    return `arn:aws:ssm:${n.region}:${n.accountId}:parameter${n.egress.parameterPrefix}/${name}`;
}

/** This account's network connectors (the resource type's ARN carries an id or a name; both are under `:*`). */
export function accountConnectorArns(n: Names): string[] {
    return [`arn:aws:lambda:${n.region}:${n.accountId}:network-connector:*`];
}

export function instanceProfileArn(n: Names, profile: string): string {
    return `arn:aws:iam::${n.accountId}:instance-profile/${profile}`;
}

/** Route 53 Resolver query logs (dnsMode firewall + enableDnsQueryLog): `dns` next to the squid group. */
export function dnsQueryLogGroupName(squidLogGroup: string): string {
    return squidLogGroup.replace(/\/[^/]*$/, "/dns");
}

function dnsQueryLogGroupArns(n: Names): string[] {
    return groupArns(n, dnsQueryLogGroupName(n.egress.logGroup));
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

/** Trust of the egress proxy's role ai-env-egress-proxy (S5): EC2 only, through the instance profile. */
export function proxyTrustPolicy(): PolicyDocument {
    return doc({ Sid: "Ec2Proxy", Effect: "Allow", Principal: { Service: EC2_SERVICE }, Action: ["sts:AssumeRole"] });
}

/**
 * The proxy role's inline policy (next to SSM_INSTANCE_POLICY_ARN): read its own parameters (the reload script's
 * get-parameters) and ship squid's access log to its one group (the CloudWatch agent). Nothing else: the proxy
 * cannot read another parameter, write another group or change its own configuration.
 */
export function proxyRolePolicy(n: Names): PolicyDocument {
    return doc(
        { Sid: "ReadProxyParameters", Effect: "Allow", Action: ["ssm:GetParameter", "ssm:GetParameters"], Resource: [proxyParameterArn(n)] }, // scratch:proxy-policy
        {
            Sid: "WriteSquidLogs", Effect: "Allow", Resource: egressLogGroupArns(n),
            Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        },
    );
}

/**
 * Trust of the connector's operator role ai-env-egress-operator (S5): lambda.amazonaws.com, the principal T5.1's
 * CloudTrail AssumeRole events show (every one of them, at both connector creations; network-connectors.lambda was
 * never seen). An aws:SourceAccount condition (confused deputy) still waits for a measurement that the service sends
 * the key: added blind, it could refuse every AssumeRole and leave the connector without ENIs.
 */
export function operatorTrustPolicy(): PolicyDocument {
    return doc({
        Sid: "LambdaNetworkConnectors", Effect: "Allow", Principal: { Service: LAMBDA_SERVICE }, Action: ["sts:AssumeRole", "sts:TagSession"],
    });
}

/**
 * The operator role's inline policy (next to CONNECTOR_OPERATOR_POLICY_ARN): one Deny, no grant. The managed policy
 * lets the connector's service create an ENI in any subnet with any security group (its subnet/* and
 * security-group/* statements have no condition). CreateNetworkInterface authorizes on each resource of the call
 * separately (the subnet, every security group, the new ENI), so an ENI naming any other subnet or group, in any
 * VPC, account or region, is denied whatever the managed policy grants. NotResource rather than condition keys: a
 * negated condition on a key the request lacks would also deny the security-group check, and the IfExists forms can
 * let a request through. `make check-policies` simulates both sides; `make connector-probe` proves ENIs still come up.
 */
export function operatorRolePolicy(n: Names): PolicyDocument {
    const { vmSubnetId, vmSecurityGroupId } = n.egress;
    if (vmSubnetId === undefined || vmSecurityGroupId === undefined) throw new Error("operatorRolePolicy: the VM subnet and security group ids are required (EnisOnlyInTheVmSubnet)");
    const ec2 = `arn:aws:ec2:${n.region}:${n.accountId}`;
    return doc({
        Sid: "EnisOnlyInTheVmSubnet", Effect: "Deny", Action: ["ec2:CreateNetworkInterface"],
        NotResource: [`${ec2}:subnet/${vmSubnetId}`, `${ec2}:security-group/${vmSecurityGroupId}`, `${ec2}:network-interface/*`],
    });
}

/** The runtime actions on the image, allowed to ai-env-runtime (§9); tested by `make check-policies`. */
export const RUNTIME_IMAGE_ACTIONS = [
    "lambda:RunMicrovm", "lambda:GetMicrovm", "lambda:SuspendMicrovm", "lambda:ResumeMicrovm", "lambda:TerminateMicrovm",
    "lambda:CreateMicrovmAuthToken", "lambda:CreateMicrovmShellAuthToken",
    "lambda:GetMicrovmImage", "lambda:GetMicrovmImageVersion", "lambda:ListMicrovmImageVersions",
];
export const RUNTIME_LIST_ACTIONS = ["lambda:ListMicrovms", "lambda:ListManagedMicrovmImages", "lambda:ListManagedMicrovmImageVersions"];
/**
 * PassNetworkConnector is confirmed (S5): RunMicrovm passes the egress connector. It has no resource type in the
 * IAM service reference (like CreateMicrovmImage and the List* calls), so it can only be granted on "*". The
 * tentative GetNetworkConnector grant is gone (S5): nothing that uses the runtime key reads a connector (`ai-env
 * egress` and `infra status` call it as the operator). If T5.1's first vpc run is denied naming it, restore it.
 *
 * iam:PassRole on the execution role is measured necessary (S4 T4.1, 30 Sep 2026): RunMicrovm with
 * --execution-role-arn was denied iam:PassRole under `StringEquals iam:PassedToService = lambda.amazonaws.com`
 * (the value the IAM service reference lists for RunMicrovm) while simulate-principal-policy with that context
 * allowed it, so the service sends another value or none. The grant therefore has no condition; it stays scoped to
 * the one role, whose trust admits only lambda.amazonaws.com and whose policy writes one log group, and the runtime
 * user has no other call that takes a role.
 */
export const PASS_CONNECTOR_ACTION = "lambda:PassNetworkConnector";
export const GET_CONNECTOR_ACTION = "lambda:GetNetworkConnector";

/** Network connectors: the AWS-managed ones (INTERNET_EGRESS, SHELL_INGRESS) and this account's (S5). */
export function connectorArns(n: Names): string[] {
    return [`arn:aws:lambda:${n.region}:aws:network-connector:*`, `arn:aws:lambda:${n.region}:${n.accountId}:network-connector:*`];
}

/**
 * MacRuntimePolicy on the user ai-env-runtime (the key the bridge holds). Everything else is implicitly denied:
 * creating, updating or deleting images and versions, every cloudformation:, budgets:, s3:, logs: action, every
 * other iam: action, every network connector call but PassNetworkConnector, and every ssm: and ec2: action (the
 * proxy and its parameters are the operator's).
 */
export function runtimePolicy(n: Names): PolicyDocument {
    return doc(
        { Sid: "MicrovmsOfTheImage", Effect: "Allow", Action: RUNTIME_IMAGE_ACTIONS, Resource: [imageArn(n)] },
        { Sid: "ListMicrovms", Effect: "Allow", Action: RUNTIME_LIST_ACTIONS, Resource: ["*"] },
        { Sid: "PassNetworkConnector", Effect: "Allow", Action: [PASS_CONNECTOR_ACTION], Resource: ["*"] },
        { Sid: "PassExecutionRole", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, EXECUTION_ROLE_NAME)] }, // scratch:runtime
    );
}

/**
 * ai-env-deploy: what a non-administrator would need to run `make deploy` / `make destroy`, except creating,
 * changing or deleting ai-env-deploy itself, which needs an administrator (the stack creates it; it is attached to
 * nothing: `rust` is an administrator). Validated for names by Access Analyzer, not for sufficiency. It is not a
 * privilege boundary (it can write the runtime user's policy and pass the build role); it only reads itself, so a
 * principal holding it cannot rewrite it. S5 adds the network connector here and the rest of the egress side in
 * ai-env-deploy-egress and ai-env-deploy-dns (deployEgressPolicy, deployDnsPolicy): a deployer holds all three.
 */
export function deployPolicy(n: Names): PolicyDocument {
    const acct = n.accountId;
    const bucket = `arn:aws:s3:::${BUCKET_PREFIX}-*`;
    const { vmSubnetId, vmSecurityGroupId } = n.egress;
    if (vmSubnetId === undefined || vmSecurityGroupId === undefined) throw new Error("deployPolicy: the VM subnet and security group ids are required (CreateEgressConnector)");
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
                "lambda:ListManagedMicrovmImageVersions", PASS_CONNECTOR_ACTION, "lambda:ListNetworkConnectors"],
        },
        { Sid: "ReadNetworkConnectors", Effect: "Allow", Resource: connectorArns(n), Action: [GET_CONNECTOR_ACTION] },
        // S5: the egress connector may only be created on the VM subnet and its security group (the two keys exist
        // for CreateNetworkConnector only; Null makes a request without them fail instead of passing ForAllValues).
        // Cosmetic as a boundary: UpdateNetworkConnector takes Configuration and OperatorRole and has no condition
        // keys. The operator role's Deny (operatorRolePolicy) refuses the connector's ENIs in any other subnet or
        // security group, but the Roles statement below can rewrite or delete that Deny (iam:PutRolePolicy,
        // iam:DeleteRolePolicy on role/ai-env-*). Like the whole deploy policy, it documents.
        {
            Sid: "CreateEgressConnector", Effect: "Allow", Resource: accountConnectorArns(n), Action: ["lambda:CreateNetworkConnector"],
            Condition: {
                "ForAllValues:StringEquals": { "lambda:SubnetIds": [vmSubnetId], "lambda:SecurityGroupIds": [vmSecurityGroupId] },
                Null: { "lambda:SubnetIds": "false", "lambda:SecurityGroupIds": "false" },
            },
        },
        {
            Sid: "ChangeEgressConnector", Effect: "Allow", Resource: accountConnectorArns(n),
            Action: ["lambda:UpdateNetworkConnector", "lambda:DeleteNetworkConnector", "lambda:TagResource", "lambda:UntagResource", "lambda:ListTags"],
        },
        // Unproven condition: RunMicrovm did not match it (runtimePolicy); Create/UpdateMicrovmImage may not either.
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
            Sid: "ReadDeployPolicy", Effect: "Allow", Resource: [DEPLOY_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME, DEPLOY_DNS_POLICY_NAME].map((p) => `arn:aws:iam::${acct}:policy/${p}`),
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

/**
 * ai-env-deploy-egress (S5): the VPC, subnets, route tables, security groups, the proxy instance with its role,
 * profile, parameters and log group, and the operator role. Like ai-env-deploy: attached to nothing, names proven by
 * Access Analyzer, not sufficiency.
 */
export function deployEgressPolicy(n: Names): PolicyDocument {
    const acct = n.accountId;
    return doc(
        // Describe* and DescribeParameters have no resource type: "*" is the only possible scope.
        {
            Sid: "EgressUnscoped", Effect: "Allow", Resource: ["*"],
            Action: ["ssm:DescribeParameters", "ec2:DescribeVpcs", "ec2:DescribeVpcAttribute", "ec2:DescribeDhcpOptions", "ec2:DescribeInternetGateways", "ec2:DescribeSubnets",
                "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:DescribeNetworkAcls", "ec2:DescribeInstances",
                "ec2:DescribeInstanceAttribute", "ec2:DescribeInstanceStatus", "ec2:DescribeInstanceTypes", "ec2:DescribeInstanceCreditSpecifications",
                "ec2:DescribeVolumes", "ec2:DescribeNetworkInterfaces", "ec2:DescribeImages", "ec2:DescribeTags", "ec2:DescribeAvailabilityZones",
                "ec2:DescribeAccountAttributes", "ec2:DescribePrefixLists"],
        },
        {
            Sid: "Ec2EgressNetwork", Effect: "Allow", Resource: [`arn:aws:ec2:${n.region}:${acct}:*`, `arn:aws:ec2:${n.region}::image/*`],
            Action: ["ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute", "ec2:CreateDhcpOptions", "ec2:DeleteDhcpOptions", "ec2:AssociateDhcpOptions",
                "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway", "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
                "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute", "ec2:CreateRouteTable", "ec2:DeleteRouteTable",
                "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:ReplaceRoute", "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
                "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress", "ec2:ModifySecurityGroupRules",
                "ec2:UpdateSecurityGroupRuleDescriptionsIngress", "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
                "ec2:RunInstances", "ec2:TerminateInstances", "ec2:StopInstances", "ec2:StartInstances", "ec2:ModifyInstanceAttribute",
                "ec2:ModifyInstanceMetadataOptions", "ec2:ModifyInstanceCreditSpecification", "ec2:CreateTags", "ec2:DeleteTags"],
        },
        {
            Sid: "ProxyParameters", Effect: "Allow", Resource: [proxyParameterArn(n)],
            Action: ["ssm:PutParameter", "ssm:GetParameter", "ssm:GetParameters", "ssm:DeleteParameter", "ssm:AddTagsToResource",
                "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource"],
        },
        // The AL2023 AMI id (an AWS public parameter, no account in its ARN).
        { Sid: "AmiParameter", Effect: "Allow", Resource: [`arn:aws:ssm:${n.region}::parameter/aws/service/ami-amazon-linux-latest/*`], Action: ["ssm:GetParameter", "ssm:GetParameters"] },
        {
            Sid: "EgressLogGroup", Effect: "Allow", Resource: egressLogGroupArns(n),
            Action: ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource",
                "logs:ListTagsForResource", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartLiveTail"],
        },
        {
            Sid: "ProxyInstanceProfile", Effect: "Allow", Resource: [instanceProfileArn(n, n.egress.proxyInstanceProfileName)],
            Action: ["iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:AddRoleToInstanceProfile",
                "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile", "iam:ListInstanceProfileTags"],
        },
        {
            Sid: "AttachManagedPolicies", Effect: "Allow", Resource: [roleArn(n, n.egress.proxyRoleName), roleArn(n, n.egress.operatorRoleName)],
            Action: ["iam:AttachRolePolicy", "iam:DetachRolePolicy"], Condition: { ArnEquals: { "iam:PolicyARN": MANAGED_POLICY_ARNS } },
        },
        { Sid: "ReadManagedPolicies", Effect: "Allow", Resource: MANAGED_POLICY_ARNS, Action: ["iam:GetPolicy", "iam:GetPolicyVersion"] },
        { Sid: "PassProxyRole", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, n.egress.proxyRoleName)], Condition: { StringEquals: { "iam:PassedToService": EC2_SERVICE } } },
        // The connector's PassRole service value is unmeasured (like RunMicrovm's, S4 T4.1): either candidate principal.
        {
            Sid: "PassOperatorRole", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, n.egress.operatorRoleName)],
            Condition: { StringEquals: { "iam:PassedToService": [NETWORK_CONNECTORS_SERVICE, LAMBDA_SERVICE] } },
        },
        // AWSServiceRoleForLambda deletes the connector's ENIs; the first connector of an account creates it.
        {
            Sid: "LambdaServiceLinkedRole", Effect: "Allow", Resource: [`arn:aws:iam::${acct}:role/aws-service-role/*`], Action: ["iam:CreateServiceLinkedRole"],
            Condition: { StringEquals: { "iam:AWSServiceName": LAMBDA_SERVICE } },
        },
    );
}

/** ai-env-deploy-dns (S5, dnsMode "firewall" only): the block-all DNS Firewall rule group and, with enableDnsQueryLog, query logging. */
export function deployDnsPolicy(n: Names): PolicyDocument {
    const acct = n.accountId;
    return doc(
        {
            Sid: "DnsFirewall", Effect: "Allow", Resource: [`arn:aws:route53resolver:${n.region}:${acct}:*`],
            Action: ["route53resolver:CreateFirewallDomainList", "route53resolver:DeleteFirewallDomainList", "route53resolver:GetFirewallDomainList",
                "route53resolver:UpdateFirewallDomains", "route53resolver:ListFirewallDomains", "route53resolver:CreateFirewallRuleGroup",
                "route53resolver:DeleteFirewallRuleGroup", "route53resolver:GetFirewallRuleGroup", "route53resolver:CreateFirewallRule",
                "route53resolver:DeleteFirewallRule", "route53resolver:UpdateFirewallRule", "route53resolver:ListFirewallRules",
                "route53resolver:AssociateFirewallRuleGroup", "route53resolver:DisassociateFirewallRuleGroup", "route53resolver:GetFirewallRuleGroupAssociation",
                "route53resolver:UpdateFirewallRuleGroupAssociation", "route53resolver:GetFirewallConfig", "route53resolver:UpdateFirewallConfig",
                "route53resolver:CreateResolverQueryLogConfig", "route53resolver:DeleteResolverQueryLogConfig", "route53resolver:GetResolverQueryLogConfig",
                "route53resolver:AssociateResolverQueryLogConfig", "route53resolver:DisassociateResolverQueryLogConfig",
                "route53resolver:TagResource", "route53resolver:UntagResource", "route53resolver:ListTagsForResource"],
        },
        {
            Sid: "DnsFirewallUnscoped", Effect: "Allow", Resource: ["*"],
            Action: ["route53resolver:ListFirewallConfigs", "route53resolver:ListFirewallDomainLists", "route53resolver:ListFirewallRuleGroups",
                "route53resolver:ListFirewallRuleGroupAssociations", "route53resolver:ListResolverQueryLogConfigs",
                "route53resolver:ListResolverQueryLogConfigAssociations", "route53resolver:GetResolverQueryLogConfigAssociation",
                "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:ListLogDeliveries",
                "logs:PutResourcePolicy", "logs:DescribeResourcePolicies"],
        },
        {
            Sid: "DnsQueryLogGroup", Effect: "Allow", Resource: dnsQueryLogGroupArns(n),
            Action: ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:TagResource", "logs:UntagResource", "logs:ListTagsForResource"],
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
        { name: "deploy-egress", kind: "identity", document: deployEgressPolicy(n) },
        { name: "deploy-dns", kind: "identity", document: deployDnsPolicy(n) },
        { name: "proxy-trust", kind: "trust", document: proxyTrustPolicy() },
        { name: "proxy", kind: "identity", document: proxyRolePolicy(n) },
        { name: "operator-trust", kind: "trust", document: operatorTrustPolicy() },
        { name: "operator", kind: "identity", document: operatorRolePolicy(n) },
    ];
}
