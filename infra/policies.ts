// Every IAM document of the ai-env stack, as pure functions of (account id, region, names). The scratch:* markers are
// edited by `make preview-scratch NEGATIVE=iam-widen|identity-widen` in a scratch copy.
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
//
// S8 operators (plans/s8-operators-plan.md §1) adds the operator identities: the users ai-env-deployer (its key in
// Strongbox only, pasted per command) and ai-env-ops (its key sealed in credentials/ops.env, opened by Touch ID), the
// deployer's supplement ai-env-deployer and ai-env-ops' own policy. The deployer holds the three deploy policies, its
// supplement and ai-env-ops; ops holds ai-env-ops alone. Every key is issued out of band (D17, D23): no document here
// is ever a key's, and the stack holds no access key.
//
// S9 (plans/s9-plan.md §5, plans/s9-contracts.md §7.3 to §7.5) adds the transcript store: the runtime user's objects
// under `v1/` of the bucket ai-env-transcripts-<acct> (TranscriptObjects, ListTranscripts, both bound to the account by
// s3:ResourceAccount), the deployer's bucket and endpoint actions, ai-env-ops' bucket reads, and two resource policies:
// the S3 gateway endpoint's (s3EndpointPolicy: our `v1/*` for the runtime user only, plus the AL2023 repository bucket
// the proxy's dnf reads) and the bucket's own, Deny only (transcriptsBucketPolicy). Their canonical hashes
// (canonicalPolicySha256) are stack outputs, which `ai-env egress status` compares with the live documents.
//
// S13 (plans/s13-contracts.md §I-infra.4.6) adds the relay: its role ai-env-relay (relayTrustPolicy, EC2 only;
// relayRolePolicy: its five parameters by name, the decryption of its TLS pair alone, its binary in the artifacts
// bucket, its log group; the AWS managed SSM agent policy beside it), a third statement of the S3 gateway endpoint's
// policy (the relay role's binary through the endpoint), the deployer's rights to build it (the Elastic IP, the VM
// subnet's NACL entries, its parameters, log group, instance profile and role) and ai-env-ops' (start, stop, its
// non-secret parameters and its log group: never the TLS pair, never a command or a session). Its root units read
// the parameters and ship the logs; the internet-facing relay process holds no credential at all (LD-I2).

import * as crypto from "crypto";

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
/** S8 operators: the deploy identity, whose long-term key lives in Strongbox only (`ai-env as deployer`). */
export const DEPLOYER_USER_NAME = "ai-env-deployer";
/** S8 operators: the daily operator, whose key is sealed in credentials/ops.env (`ai-env as ops`, one Touch ID). */
export const OPS_USER_NAME = "ai-env-ops";
/** The deployer's supplement: the ops user and its key, the deployer's own keys and policy attachments. */
export const DEPLOYER_POLICY_NAME = "ai-env-deployer";
/** The operator's policy, held by ai-env-ops and by ai-env-deployer (the deployer covers ops). */
export const OPS_POLICY_NAME = "ai-env-ops";
/** The managed policies ai-env-deployer holds: five of the ten a user may hold. */
export const DEPLOYER_POLICIES = [DEPLOY_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME, DEPLOY_DNS_POLICY_NAME, DEPLOYER_POLICY_NAME, OPS_POLICY_NAME] as const;
/** The stack's managed policies: exactly the deployer's five (it manages their versions, never creates or deletes one). */
export const STACK_POLICIES: readonly string[] = DEPLOYER_POLICIES;
/** The stack's IAM users. None has an access key in the stack, ever (D17, D23): keys are issued out of band. */
export const STACK_USERS = [RUNTIME_USER_NAME, OPS_USER_NAME, DEPLOYER_USER_NAME] as const;
/** Which user holds which managed policy: the deployer its five, ops its one; nothing else is ever attached. */
export const USER_POLICY_ATTACHMENTS: readonly (readonly [string, string])[] = [
    ...DEPLOYER_POLICIES.map((p) => [DEPLOYER_USER_NAME, p] as const),
    [OPS_USER_NAME, OPS_POLICY_NAME],
];
/** The Pulumi (and plan) name of a user's policy attachment: `<user>--<policy>`. */
export function attachmentName(user: string, policy: string): string {
    return `${user}--${policy}`;
}
/**
 * The managed policies' descriptions, frozen at the bootstrap: IAM cannot update a description in place, so a change
 * replaces the policy, which check-plan refuses once the stack has its deployer (an attached policy cannot be
 * deleted mid-deploy). ASCII only. A Map, never an object literal: a name like `constructor` finds nothing.
 */
export const POLICY_DESCRIPTIONS: ReadonlyMap<string, string> = new Map([
    [DEPLOY_POLICY_NAME, "ai-env deploy/destroy (held by ai-env-deployer): Cloud Control, the image, bucket, logs, budget, roles, the runtime user and the stack's managed policies"],
    [DEPLOY_EGRESS_POLICY_NAME, "ai-env deploy/destroy, egress side (held by ai-env-deployer): VPC, security groups, proxy instance, parameters, SSM documents, roles"],
    [DEPLOY_DNS_POLICY_NAME, "ai-env deploy/destroy, egress dnsMode firewall (held by ai-env-deployer): DNS Firewall and query logging"],
    [DEPLOYER_POLICY_NAME, "ai-env deployer identity (held by ai-env-deployer): the ai-env-ops user and its key, the deployer's own keys and policy attachments"],
    [OPS_POLICY_NAME, "ai-env operator (held by ai-env-ops and ai-env-deployer): proxy start/stop, the fixed proxy SSM documents, the suspended list, read-only status"],
]);
/** The frozen description of one of the stack's managed policies (throws for any other name). */
export function policyDescription(name: string): string {
    const d = POLICY_DESCRIPTIONS.get(name);
    if (d === undefined) throw new Error(`policyDescription: ${name} is not one of the stack's managed policies (${STACK_POLICIES.join(", ")})`);
    return d;
}
/** The two service quotas ai-env reads (doctor's MicroVM memory row, preflight P15's VPC count). */
export const MICROVM_MEMORY_QUOTA = "lambda/L-CD1C0CC4";
export const VPC_QUOTA = "vpc/L-F678F1CE";
/** IAM's limit on a managed policy (characters without whitespace); `make check-policies` asserts every document against it. */
export const MANAGED_POLICY_MAX_CHARS = 6144;
export const BUDGET_NAME = "ai-env-monthly";
/** Pulumi auto-names the bucket `<prefix>-<7 random>`; the deploy policy scopes S3 to this prefix. */
export const BUCKET_PREFIX = "ai-env-artifacts";
/** Key prefix of the hash-keyed image zips (`ai-env/image-<sha256[:16]>.zip`, written by `make image-zip`). */
export const ZIP_KEY_PREFIX = "ai-env/image-";
/** The service that assumes the build and execution roles. */
export const LAMBDA_SERVICE = "lambda.amazonaws.com";

/** S9: the transcripts bucket is `ai-env-transcripts-<accountId>` (`wire::s3::BUCKET_PREFIX`): a fixed name, so the
 * allowlist line and the policies are exact strings at preview time. */
export const TRANSCRIPTS_BUCKET_PREFIX = "ai-env-transcripts-";
/** S9: the Pulumi name of the transcripts bucket and of each of its settings (contracts §7.1). */
export const TRANSCRIPTS_RESOURCE = "ai-env-transcripts";
/** S9: every transcript object is under this prefix (`wire::s3::KEY_PREFIX`). */
export const TRANSCRIPTS_KEY_PREFIX = "v1/";
/** S9: the egress check's own objects (`wire::s3::EGRESS_CHECK_PREFIX`), expired after a day. */
export const EGRESS_CHECK_PREFIX = "v1/_egress-check/";
/**
 * S9: the Amazon Linux 2023 repository bucket of the region. The proxy reaches S3 through the gateway endpoint from
 * now on (it sits on the proxy's route table), so its `dnf` (and `make proxy-patch`) reads these objects through the
 * endpoint's policy. Read off the proxy's repository configuration before the deploy (plan risk): a wrong name breaks
 * the proxy's package updates. What else the proxy fetches over S3 (an SSM agent update) is refused at the endpoint.
 */
export const AL2023_REPO_BUCKET = "al2023-repos-eu-central-1-de612dc2";
/** S9: the S3 gateway endpoint's service in the region. */
export const S3_ENDPOINT_SERVICE = "com.amazonaws.eu-central-1.s3";

/** S13: the relay's role and instance profile, named by the stack (LD-I1). */
export const RELAY_ROLE_NAME = "ai-env-relay";
export const RELAY_INSTANCE_PROFILE_NAME = "ai-env-relay";
/** S13: the relay's binary in the artifacts bucket, `relay/ai-env-relay-<sha256[:16]>` (`make relay-artifact`). */
export const RELAY_KEY_PREFIX = "relay/ai-env-relay-";
/** S13: what the relay's reload unit fetches (infra/relay/reload.py PARAMETERS, same order); `tls` alone is a SecureString. */
export const RELAY_PARAMETERS = ["artifact", "workers", "grants", "token-signers", "tls"] as const;
export type RelayParameter = (typeof RELAY_PARAMETERS)[number];
export const RELAY_TLS: RelayParameter = "tls";

/** S9: the transcripts bucket of `accountId`. */
export function transcriptsBucketName(accountId: string): string {
    return `${TRANSCRIPTS_BUCKET_PREFIX}${accountId}`;
}

/** S9: the bucket's virtual-hosted name (`wire::s3::bucket_host`), the one AWS host squid serves. */
export function transcriptsBucketHost(bucket: string): string {
    return `${bucket}.s3.${REGION}.amazonaws.com`;
}

/** The managed INTERNET_EGRESS network connector (the image build downloads packages and claude). */
export function internetEgressConnectorArn(region: string): string {
    return `arn:aws:lambda:${region}:aws:network-connector:aws-network-connector:INTERNET_EGRESS`;
}

/** The services that assume the egress roles (S5). */
export const EC2_SERVICE = "ec2.amazonaws.com";
/**
 * Not trusted: the other candidate principal of the connector's operator role, never seen assuming it (T5.1's CloudTrail
 * AssumeRole events, 1 and 2 Oct 2026, both connector creations: lambda.amazonaws.com only). The deploy policy's
 * PassOperatorRole still accepts it as iam:PassedToService, that value being unmeasured until ai-env-deployer's first
 * connector creation (every earlier one ran as the account root, which no policy binds).
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
    /**
     * The egress connector's own ARN, which likewise exists only once the stack created it: runtimePolicy grants
     * GetNetworkConnector on exactly this one (S7 D5). Pulumi passes the connector's `arn` output, whatever form the
     * service gives it; `print-policies` a placeholder of the same shape, so `make check-policies` simulates against
     * the very ARN the document names.
     */
    connectorArn?: string;
    /** S8 operators: the proxy's three SSM Command documents (egress-config.json), the only ones ops may send. */
    reloadDocumentName: string;
    statusDocumentName: string;
    patchDocumentName: string;
    /**
     * The proxy instance's id, which exists only once the stack created it: opsPolicy scopes start, stop and
     * SendCommand to exactly this instance's ARN (never a tag: the deploy policy's ec2:CreateTags could tag any
     * instance into ops' reach), so the ops policy gets a new version whenever the proxy is replaced.
     */
    proxyInstanceId?: string;
    /** S13: the relay's SSM prefix and log group (egress-config.json). */
    relayParameterPrefix: string;
    relayLogGroup: string;
    /**
     * S13: the relay instance's id, which exists only once the stack created it: opsPolicy's RelayInstance scopes
     * start and stop to exactly this instance's ARN, as ProxyInstance does the proxy's.
     */
    relayInstanceId?: string;
}

export interface Names {
    accountId: string;
    region: string;
    /** The artifacts bucket (its real, auto-generated name). */
    bucket: string;
    imageName: string;
    logGroup: string;
    egress: EgressNames;
    /** S9: the transcripts bucket, `ai-env-transcripts-<accountId>` (transcriptsBucketName). */
    transcriptsBucket: string;
    /**
     * S9: the S3 gateway endpoint's id, which exists only once the stack created it: the bucket policy's
     * `aws:SourceVpce` conditions name it. `print-policies` passes a placeholder of the same shape.
     */
    s3EndpointId?: string;
}

export interface Statement {
    Sid: string;
    Effect: "Allow" | "Deny";
    /** A trust policy's service, or `*` in a resource policy (S9: the endpoint's and the bucket's, narrowed by conditions). */
    Principal?: "*" | { Service: string | string[] };
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

/** The four proxy parameters `<prefix>/<name>` (contract 2); extras and suspended are owned by `ai-env egress` after creation. */
export const PROXY_PARAMETERS = ["squid.conf", "allow", "extras", "suspended"] as const;
export type ProxyParameter = (typeof PROXY_PARAMETERS)[number];

/** The proxy's SSM parameters `<prefix>/*` (a name starting with `/` follows `parameter` directly). */
export function proxyParameterArn(n: Names, name = "*"): string {
    return `arn:aws:ssm:${n.region}:${n.accountId}:parameter${n.egress.parameterPrefix}/${name}`;
}

/** The proxy's three SSM documents (account-owned: the account is in the ARN, unlike AWS-RunShellScript's). */
export function proxyDocumentArns(n: Names): string[] {
    const { reloadDocumentName, statusDocumentName, patchDocumentName } = n.egress;
    return [reloadDocumentName, statusDocumentName, patchDocumentName].map((d) => `arn:aws:ssm:${n.region}:${n.accountId}:document/${d}`);
}

/** The proxy instance's ARN (opsPolicy's ProxyInstance and ProxyCommands); throws without the instance id. */
export function proxyInstanceArn(n: Names): string {
    const id = n.egress.proxyInstanceId;
    if (id === undefined) throw new Error("opsPolicy: the proxy instance id is required (ProxyInstance, ProxyCommands)");
    return `arn:aws:ec2:${n.region}:${n.accountId}:instance/${id}`;
}

/** S13: a relay parameter, `arn:aws:ssm:<region>:<acct>:parameter<relayParameterPrefix>/<name>` (`*` for all of them). */
export function relayParameterArn(n: Names, name: string): string {
    return `arn:aws:ssm:${n.region}:${n.accountId}:parameter${n.egress.relayParameterPrefix}/${name}`;
}

/** S13: the relay's log group and its `:*`. */
export function relayLogGroupArns(n: Names): string[] {
    return groupArns(n, n.egress.relayLogGroup);
}

/** S13: the relay instance's ARN (opsPolicy's RelayInstance); throws without the instance id. */
export function relayInstanceArn(n: Names): string {
    const id = n.egress.relayInstanceId;
    if (id === undefined) throw new Error("opsPolicy: the relay instance id is required (RelayInstance)");
    return `arn:aws:ec2:${n.region}:${n.accountId}:instance/${id}`;
}

/** An IAM user of this account. */
export function userArn(n: Names, user: string): string {
    return `arn:aws:iam::${n.accountId}:user/${user}`;
}

/** A customer-managed policy of this account. */
export function policyArn(n: Names, policy: string): string {
    return `arn:aws:iam::${n.accountId}:policy/${policy}`;
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

export function dnsQueryLogGroupArns(n: Names): string[] {
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

/** S13: trust of the relay's role ai-env-relay: EC2 only, through the instance profile. */
export function relayTrustPolicy(): PolicyDocument {
    return doc({ Sid: "Ec2Relay", Effect: "Allow", Principal: { Service: EC2_SERVICE }, Action: ["sts:AssumeRole"] });
}

/**
 * S13: the relay role's inline policy (next to SSM_INSTANCE_POLICY_ARN), for its root units only: the reload unit's one
 * get-parameters of its five parameters by name (never by path: a later /ai-env/relay/* stays out of reach), the
 * decryption of the TLS pair through SSM, its binary in the artifacts bucket, and its log group (the CloudWatch agent).
 * The Deny is what restricts the decryption: aws/ssm's key policy admits every principal of the account through SSM,
 * so an Allow alone would add nothing; the Allow keeps the role working if the key ever becomes a customer managed one.
 * No MicroVM, connector, iam:, ec2:, ssm:PutParameter, ssm:SendCommand or S3 write right (plan §A4: none in Track A).
 */
export function relayRolePolicy(n: Names): PolicyDocument {
    const key = relayParameterArn(n, RELAY_TLS);
    return doc(
        { Sid: "ReadRelayParameters", Effect: "Allow", Action: ["ssm:GetParameters"], Resource: RELAY_PARAMETERS.map((p) => relayParameterArn(n, p)) },
        {
            Sid: "DecryptTheTlsKey", Effect: "Allow", Action: ["kms:Decrypt"], Resource: [`arn:aws:kms:${n.region}:${n.accountId}:key/*`],
            Condition: { StringEquals: { "kms:EncryptionContext:PARAMETER_ARN": key, "kms:ViaService": `ssm.${n.region}.amazonaws.com` } },
        },
        { Sid: "NoOtherDecrypt", Effect: "Deny", Action: ["kms:Decrypt"], Resource: ["*"], Condition: { StringNotEquals: { "kms:EncryptionContext:PARAMETER_ARN": key } } },
        {
            Sid: "ReadRelayArtifact", Effect: "Allow", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${n.bucket}/${RELAY_KEY_PREFIX}*`],
            Condition: { StringEquals: { "s3:ResourceAccount": n.accountId } },
        },
        {
            Sid: "WriteRelayLogs", Effect: "Allow", Resource: relayLogGroupArns(n),
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
 * IAM service reference (like CreateMicrovmImage and the List* calls), so it can only be granted on "*".
 *
 * GetNetworkConnector is back in S7 (D5), on exactly the egress connector and nothing else: the credential gate
 * compares the connector's live configuration with the one the recorded `ai-env egress check` verified, and it must
 * do so with the runtime key, so delivering a credential never depends on an operator identity (ai-env-ops'
 * credentials/ops.env) or the Python aws CLI. It reads non-secret configuration only; creating, updating and deleting
 * a connector, and every call on INTERNET_EGRESS or any other connector, stay implicitly denied (`make check-policies`
 * simulates each).
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
 * proxy and its parameters are ai-env-ops' and ai-env-deployer's).
 */
/**
 * The egress connector's two ARNs: the one the service reports (Pulumi's `arn` output, in the `nc-…` id form, as
 * measured in S5) and the one the IAM service reference documents for the networkConnector resource type
 * (`network-connector:${NetworkConnectorName}`). Both name this one connector — names are unique per account and Region —
 * so granting on both keeps the grant exact while not depending on which form IAM matches a request against (part B
 * shows which). Deduplicated when they coincide.
 */
export function egressConnectorArns(n: Names): string[] {
    const { connectorArn, connectorName } = n.egress;
    if (connectorArn === undefined) throw new Error("runtimePolicy: the egress connector's ARN is required (ReadTheEgressConnector, S7 D5)");
    const byName = `arn:aws:lambda:${n.region}:${n.accountId}:network-connector:${connectorName}`;
    return byName === connectorArn ? [connectorArn] : [connectorArn, byName];
}

/**
 * S9: the transcript objects the runtime key works with: presigned GETs and PUTs for the VM, the Mac's own multipart
 * upload, deletes (gc, a compaction, `forget --purge`), ListObjectsV2 of `v1/`. S3 ARNs carry no account, so without
 * `s3:ResourceAccount` both statements would allow a bucket of that name in any account (a name freed by a destroy and
 * taken elsewhere); the signed `x-amz-expected-bucket-owner` refuses it as well.
 */
export const RUNTIME_TRANSCRIPT_ACTIONS = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"];

export function runtimePolicy(n: Names): PolicyDocument {
    const bucket = `arn:aws:s3:::${n.transcriptsBucket}`;
    return doc(
        { Sid: "MicrovmsOfTheImage", Effect: "Allow", Action: RUNTIME_IMAGE_ACTIONS, Resource: [imageArn(n)] },
        { Sid: "ListMicrovms", Effect: "Allow", Action: RUNTIME_LIST_ACTIONS, Resource: ["*"] },
        { Sid: "PassNetworkConnector", Effect: "Allow", Action: [PASS_CONNECTOR_ACTION], Resource: ["*"] },
        { Sid: "ReadTheEgressConnector", Effect: "Allow", Action: [GET_CONNECTOR_ACTION], Resource: egressConnectorArns(n) },
        { Sid: "PassExecutionRole", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, EXECUTION_ROLE_NAME)] },
        {
            Sid: "TranscriptObjects", Effect: "Allow", Action: RUNTIME_TRANSCRIPT_ACTIONS, Resource: [`${bucket}/${TRANSCRIPTS_KEY_PREFIX}*`],
            Condition: { StringEquals: { "s3:ResourceAccount": n.accountId } },
        },
        {
            Sid: "ListTranscripts", Effect: "Allow", Action: ["s3:ListBucket"], Resource: [bucket],
            Condition: { StringLike: { "s3:prefix": [TRANSCRIPTS_KEY_PREFIX, `${TRANSCRIPTS_KEY_PREFIX}*`] }, StringEquals: { "s3:ResourceAccount": n.accountId } },
        },
    );
}

/**
 * S9: the S3 gateway endpoint's policy (contracts §7.3): through the endpoint, only the runtime user, only our
 * account's bucket, only `v1/*` (reads by version and writes), plus anonymous reads of the AL2023 repository bucket
 * the proxy's dnf needs. Everything else through the endpoint — another bucket by its virtual-hosted name or path
 * style (fronting), our bucket outside `v1/`, the VM's own IMDS role credentials — is denied by the endpoint itself.
 * S13: and the relay role's reads of its binary, `relay/ai-env-relay-*` of the artifacts bucket (the relay shares the
 * proxy's subnet and route table, so its S3 reads go through the endpoint too); nobody else reads `relay/`, and nobody
 * writes there, through it.
 */
export function s3EndpointPolicy(n: Pick<Names, "accountId" | "transcriptsBucket">): PolicyDocument {
    return doc(
        {
            Sid: "TranscriptsOfTheRuntimeUser", Effect: "Allow", Principal: "*", Action: ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
            Resource: [`arn:aws:s3:::${n.transcriptsBucket}/${TRANSCRIPTS_KEY_PREFIX}*`],
            Condition: { ArnEquals: { "aws:PrincipalArn": `arn:aws:iam::${n.accountId}:user/${RUNTIME_USER_NAME}` }, StringEquals: { "s3:ResourceAccount": n.accountId } },
        },
        { Sid: "Al2023Repos", Effect: "Allow", Principal: "*", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${AL2023_REPO_BUCKET}/*`] },
        {
            Sid: "RelayArtifactOfTheRelayRole", Effect: "Allow", Principal: "*", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${BUCKET_PREFIX}-*/${RELAY_KEY_PREFIX}*`],
            Condition: { ArnEquals: { "aws:PrincipalArn": `arn:aws:iam::${n.accountId}:role/${RELAY_ROLE_NAME}` }, StringEquals: { "s3:ResourceAccount": n.accountId } },
        },
    );
}

/**
 * S9: the transcripts bucket's policy (contracts §7.4), Deny only: any request without TLS; reads of `v1/*` unless
 * through our endpoint (the Mac never reads an object); the VM's writes (`v1/<sid>/vm/…`) unless through it; the Mac's
 * writes (`v1/<sid>/mac/…`) through it; object reads and writes by any principal but the runtime user. Deletes are
 * never denied (the Mac's gc and compaction; forceDestroy). Throws without the endpoint's id.
 */
export function transcriptsBucketPolicy(n: Pick<Names, "accountId" | "transcriptsBucket" | "s3EndpointId">): PolicyDocument {
    const vpce = n.s3EndpointId;
    if (vpce === undefined) throw new Error("transcriptsBucketPolicy: the S3 gateway endpoint's id is required (aws:SourceVpce)");
    const bucket = `arn:aws:s3:::${n.transcriptsBucket}`;
    const objects = `${bucket}/${TRANSCRIPTS_KEY_PREFIX}*`;
    return doc(
        { Sid: "DenyWithoutTls", Effect: "Deny", Principal: "*", Action: ["s3:*"], Resource: [bucket, `${bucket}/*`], Condition: { Bool: { "aws:SecureTransport": "false" } } },
        {
            Sid: "DenyReadsOutsideTheEndpoint", Effect: "Deny", Principal: "*", Action: ["s3:GetObject", "s3:GetObjectVersion"], Resource: [objects],
            Condition: { StringNotEquals: { "aws:SourceVpce": vpce } },
        },
        {
            Sid: "DenyVmWritesOutsideTheEndpoint", Effect: "Deny", Principal: "*", Action: ["s3:PutObject"], Resource: [`${bucket}/${TRANSCRIPTS_KEY_PREFIX}*/vm/*`],
            Condition: { StringNotEquals: { "aws:SourceVpce": vpce } },
        },
        {
            Sid: "DenyMacWritesThroughTheEndpoint", Effect: "Deny", Principal: "*", Action: ["s3:PutObject"], Resource: [`${bucket}/${TRANSCRIPTS_KEY_PREFIX}*/mac/*`],
            Condition: { StringEquals: { "aws:SourceVpce": vpce } },
        },
        {
            Sid: "DenyOtherPrincipals", Effect: "Deny", Principal: "*", Action: ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], Resource: [`${bucket}/*`],
            Condition: { ArnNotEquals: { "aws:PrincipalArn": `arn:aws:iam::${n.accountId}:user/${RUNTIME_USER_NAME}` } },
        },
    );
}

/**
 * S9: a policy document's text in its canonical form (contracts §7.6; `bridge::infra::canonical_policy_sha256` in
 * Rust is the same): every object's keys sorted, an array of exactly one string written as that string, no
 * whitespace. AWS's normalised text of a document (keys reordered, `["x"]` turned into `"x"`) has the same form.
 */
export function canonicalPolicyText(document: unknown): string {
    const canon = (v: unknown): unknown => {
        if (Array.isArray(v)) return v.length === 1 && typeof v[0] === "string" ? v[0] : v.map(canon);
        if (v !== null && typeof v === "object") return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])]));
        return v;
    };
    return JSON.stringify(canon(typeof document === "string" ? JSON.parse(document) : document));
}

/** S9: the canonical hash of a policy document (text or object): sha256 of [canonicalPolicyText], lowercase hex. */
export function canonicalPolicySha256(document: unknown): string {
    return crypto.createHash("sha256").update(canonicalPolicyText(document), "utf-8").digest("hex");
}

/**
 * ai-env-deploy, held by ai-env-deployer (S8 operators): what `make deploy` needs as that user, the stack's five
 * managed policies included, which it manages through StackPolicies (their reads, versions and tags: the
 * five-version limit, a rollback) but never creates or deletes (no iam:CreatePolicy or DeletePolicy: they all exist
 * from the bootstrap, which the account root runs once). Validated for names by Access Analyzer, not yet for
 * sufficiency: part B's first deployer preview and deploy prove it, and `make deploy-policies` adds a right it lacks.
 * It is not a privilege boundary: with the deployer's other policies it is admin-equivalent inside the account (it
 * writes the runtime user's policy, passes the build role and versions its own documents); the protection is the
 * offline key. `make destroy` runs as the account root (it deletes the operator users themselves). S5 adds the
 * network connector here and the rest of the egress side in ai-env-deploy-egress and ai-env-deploy-dns
 * (deployEgressPolicy, deployDnsPolicy).
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
        // S8 operators: the stack's five managed policies, the deployer's own included. A policy update is a new default
        // version (CreatePolicyVersion, after DeletePolicyVersion of the oldest at IAM's five), SetDefaultPolicyVersion
        // rolls one back; no CreatePolicy or DeletePolicy (check-plan refuses replacing or deleting them).
        {
            Sid: "StackPolicies", Effect: "Allow", Resource: STACK_POLICIES.map((p) => policyArn(n, p)),
            Action: ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:ListPolicyTags", "iam:ListEntitiesForPolicy",
                "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:TagPolicy", "iam:UntagPolicy"],
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
        // S9: the transcripts bucket and its settings (versioning, encryption, ownership, public access block,
        // lifecycle, policy), and its objects' deletion for forceDestroy only: the deployer never reads or writes one.
        {
            Sid: "TranscriptsBucket", Effect: "Allow", Resource: [`arn:aws:s3:::${n.transcriptsBucket}`],
            Action: ["s3:CreateBucket", "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucket*", "s3:PutBucket*", "s3:DeleteBucket*",
                "s3:GetAccelerateConfiguration", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:GetEncryptionConfiguration",
                "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration"],
        },
        { Sid: "TranscriptsObjectsDestroy", Effect: "Allow", Resource: [`arn:aws:s3:::${n.transcriptsBucket}/*`], Action: ["s3:DeleteObject", "s3:DeleteObjectVersion"] },
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
 * profile, parameters and log group, and the operator role; S9 the S3 gateway endpoint; S8 operators adds the proxy's three SSM documents
 * (ProxyDocuments: their whole lifecycle, never ssm:ModifyDocumentPermission, so a document can never be shared).
 * Held by ai-env-deployer like ai-env-deploy; names proven by Access Analyzer, not sufficiency. Sending the documents
 * is ai-env-ops' (opsPolicy's ProxyCommands), which the deployer holds too: one source of truth. S13: the relay (its
 * Elastic IP, the VM subnet's NACL entries to it, its parameters, log group, instance profile and role; Sids unchanged:
 * preview-scratch's tampers find statements by Sid), and AttachRelayManagedPolicy, which lets the relay role hold the
 * SSM agent's managed policy and nothing else (Q-I12: AttachManagedPolicies also admits the connector's operator
 * policy). The relay role's own lifecycle, its inline policy and its artifact object are deployPolicy's (Roles,
 * ArtifactsObjects).
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
                "ec2:DescribeAccountAttributes", "ec2:DescribePrefixLists", "ec2:DescribeVpcEndpoints", "ec2:DescribeAddresses", "ec2:DescribeAddressesAttribute"],
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
                "ec2:ModifyInstanceMetadataOptions", "ec2:ModifyInstanceCreditSpecification", "ec2:CreateTags", "ec2:DeleteTags",
                // S9: the S3 gateway endpoint on the proxy's route table.
                "ec2:CreateVpcEndpoint", "ec2:ModifyVpcEndpoint", "ec2:DeleteVpcEndpoints",
                // S13: the relay's Elastic IP, and the VM subnet's NACL entries to the relay
                "ec2:AllocateAddress", "ec2:ReleaseAddress", "ec2:AssociateAddress", "ec2:DisassociateAddress", "ec2:CreateNetworkAclEntry",
                "ec2:DeleteNetworkAclEntry", "ec2:ReplaceNetworkAclEntry"],
        },
        // S13: also the relay's parameters (Pulumi's `artifact`, and every write of `ai-env relay` as the deployer).
        {
            Sid: "ProxyParameters", Effect: "Allow", Resource: [proxyParameterArn(n), relayParameterArn(n, "*")],
            Action: ["ssm:PutParameter", "ssm:GetParameter", "ssm:GetParameters", "ssm:DeleteParameter", "ssm:AddTagsToResource",
                "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource"],
        },
        // The AL2023 AMI id (an AWS public parameter, no account in its ARN).
        { Sid: "AmiParameter", Effect: "Allow", Resource: [`arn:aws:ssm:${n.region}::parameter/aws/service/ami-amazon-linux-latest/*`], Action: ["ssm:GetParameter", "ssm:GetParameters"] },
        // S8 operators: the proxy's documents (create with tags, read until active, update then make it the default,
        // delete).
        {
            Sid: "ProxyDocuments", Effect: "Allow", Resource: proxyDocumentArns(n),
            Action: ["ssm:CreateDocument", "ssm:UpdateDocument", "ssm:UpdateDocumentDefaultVersion", "ssm:DeleteDocument", "ssm:DescribeDocument", "ssm:GetDocument",
                "ssm:DescribeDocumentPermission", "ssm:ListDocumentVersions", "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource"],
        },
        {
            Sid: "EgressLogGroup", Effect: "Allow", Resource: [...egressLogGroupArns(n), ...relayLogGroupArns(n)],
            Action: ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource",
                "logs:ListTagsForResource", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartLiveTail"],
        },
        {
            Sid: "ProxyInstanceProfile", Effect: "Allow", Resource: [instanceProfileArn(n, n.egress.proxyInstanceProfileName), instanceProfileArn(n, RELAY_INSTANCE_PROFILE_NAME)],
            Action: ["iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:AddRoleToInstanceProfile",
                "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile", "iam:ListInstanceProfileTags"],
        },
        {
            Sid: "AttachManagedPolicies", Effect: "Allow", Resource: [roleArn(n, n.egress.proxyRoleName), roleArn(n, n.egress.operatorRoleName)],
            Action: ["iam:AttachRolePolicy", "iam:DetachRolePolicy"], Condition: { ArnEquals: { "iam:PolicyARN": MANAGED_POLICY_ARNS } },
        },
        // S13 (Q-I12): the relay role holds the SSM agent's managed policy alone, never the connector's operator policy.
        {
            Sid: "AttachRelayManagedPolicy", Effect: "Allow", Resource: [roleArn(n, RELAY_ROLE_NAME)],
            Action: ["iam:AttachRolePolicy", "iam:DetachRolePolicy"], Condition: { ArnEquals: { "iam:PolicyARN": [SSM_INSTANCE_POLICY_ARN] } },
        },
        { Sid: "ReadManagedPolicies", Effect: "Allow", Resource: MANAGED_POLICY_ARNS, Action: ["iam:GetPolicy", "iam:GetPolicyVersion"] },
        {
            Sid: "PassProxyRole", Effect: "Allow", Action: ["iam:PassRole"], Resource: [roleArn(n, n.egress.proxyRoleName), roleArn(n, RELAY_ROLE_NAME)],
            Condition: { StringEquals: { "iam:PassedToService": EC2_SERVICE } },
        },
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

/**
 * ai-env-deployer (S8 operators): the deployer's supplement next to the three deploy policies and ai-env-ops. The ops
 * user's whole lifecycle and keys (`make ops-key`, and the cleanup its forceDestroy does, as RuntimeUser in
 * deployPolicy); attaching or detaching exactly ai-env-ops on it; and on the deployer itself its reads, tags and key
 * rotation (`make deployer-key ROTATE=1`) and attaching one of its own five policies, nothing else: no DeleteUser,
 * PutUserPolicy, login profile, group membership or DetachUserPolicy on itself (check-plan refuses any replace or
 * delete of the deployer's user, attachments and policies once it exists, so Pulumi never needs them; the account
 * root deletes them, `make destroy BREAKGLASS=1`). ListVirtualMFADevices (forceDestroy's MFA lookup) and
 * ListAllMyBuckets (the destroy checklist) have no resource type. CloudTrailLogs serves the `aws logs
 * filter-log-events … --unmask` command `ai-env lab run cloudtrail-payload` prints per CloudTrail log group: reading the
 * account's API record unmasked is the deployer's, never the daily ops key's (S8 fix round, contracts §13). Admin-
 * equivalent with the deploy policies, not a boundary.
 */
export function deployerPolicy(n: Names): PolicyDocument {
    return doc(
        {
            Sid: "OpsUser", Effect: "Allow", Resource: [userArn(n, OPS_USER_NAME)],
            Action: ["iam:CreateUser", "iam:GetUser", "iam:DeleteUser", "iam:TagUser", "iam:UntagUser", "iam:ListUserTags", "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies", "iam:ListGroupsForUser", "iam:ListAccessKeys", "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
                "iam:GetAccessKeyLastUsed", "iam:ListSigningCertificates", "iam:DeleteSigningCertificate", "iam:ListSSHPublicKeys", "iam:DeleteSSHPublicKey",
                "iam:ListServiceSpecificCredentials", "iam:DeleteServiceSpecificCredential", "iam:ListMFADevices", "iam:DeactivateMFADevice",
                "iam:GetLoginProfile", "iam:DeleteLoginProfile"],
        },
        {
            Sid: "OpsPolicyAttachment", Effect: "Allow", Resource: [userArn(n, OPS_USER_NAME)], Action: ["iam:AttachUserPolicy", "iam:DetachUserPolicy"],
            Condition: { ArnEquals: { "iam:PolicyARN": [policyArn(n, OPS_POLICY_NAME)] } },
        },
        {
            Sid: "DeployerUser", Effect: "Allow", Resource: [userArn(n, DEPLOYER_USER_NAME)],
            Action: ["iam:GetUser", "iam:TagUser", "iam:UntagUser", "iam:ListUserTags", "iam:ListUserPolicies", "iam:ListAttachedUserPolicies", "iam:ListGroupsForUser",
                "iam:ListAccessKeys", "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey", "iam:GetAccessKeyLastUsed"],
        },
        {
            Sid: "DeployerPolicyAttachments", Effect: "Allow", Resource: [userArn(n, DEPLOYER_USER_NAME)], Action: ["iam:AttachUserPolicy"],
            Condition: { ArnEquals: { "iam:PolicyARN": DEPLOYER_POLICIES.map((p) => policyArn(n, p)) } }, // scratch:deployer-attach
        },
        // The log groups are found at run time (a trail's own group, CloudWatch's CloudTrail ingestion), so no narrower name
        // exists. The trailing * also matches a group's `:*` form (Access Analyzer reports a second ARN for it as redundant).
        { Sid: "CloudTrailLogs", Effect: "Allow", Resource: [`arn:aws:logs:${n.region}:${n.accountId}:log-group:*cloudtrail*`], Action: ["logs:FilterLogEvents", "logs:Unmask"] },
        { Sid: "DeployerUnscoped", Effect: "Allow", Resource: ["*"], Action: ["iam:ListVirtualMFADevices", "s3:ListAllMyBuckets"] },
    );
}

/**
 * ai-env-ops (S8 operators), held by ai-env-ops and by ai-env-deployer: the daily operator commands and the reads of
 * every status, nothing that deploys or widens egress (O3, O4). Each action is traced to its caller in
 * plans/s8-operators-design.md B5, plus one the ops-tier targets call: lambda:ListMicrovms (`make image-prune`'s dry
 * run). lambda:GetMicrovmImageVersion stays with the image's other reads below: its caller, `make claude-update`'s
 * active-version check, was retired in S11 (VMs follow Cursor's Claude Code with no deploy), and a read of the stack's
 * own image changes nothing.
 *   - Reads on "*" (no resource type): the SSM command and agent reads, the ec2 Describe* calls of egress status and
 *     preflight P14 and P15, the DNS Firewall association list, the lambda connector, image and MicroVM lists, the log
 *     group list, the four CloudTrail reads of `ai-env lab run cloudtrail-payload`, the account summary (doctor's root
 *     key row) and the two policy checks of `make check-policies`.
 *   - ec2:StartInstances and StopInstances on the proxy instance's ARN only (an ARN, never a tag: the deploy policy's
 *     ec2:CreateTags could tag any instance into reach); no ModifyInstanceAttribute (user data runs as root at the next
 *     start), CreateTags or any other write.
 *   - S13: the relay instance's start and stop on its ARN only (`ai-env relay start|stop`), its four non-secret
 *     parameters read (`ai-env relay status`; never `tls`), its log group read, and ec2:DescribeAddresses. No SSM
 *     document and no ssm:SendCommand ever reaches the relay instance, and no statement grants ssm:StartSession.
 *   - ssm:SendCommand on exactly the three proxy documents plus that instance (SendCommand authorizes the document
 *     and every target separately): never AWS-RunShellScript, another document or instance, nor StartSession.
 *   - The four proxy parameters read; only `suspended` written (O3: widening egress, `extras`, is the deployer's).
 *   - Reads of the stack's own resources: the DNS Firewall rules, domains and config, the account's connectors, the
 *     image with its versions and builds, the stack's three log groups (never a CloudTrail group: the command
 *     cloudtrail-payload prints for one is the deployer's, deployerPolicy's CloudTrailLogs), two service quotas, the
 *     three users (G7's simulation, doctor's key rows, `creds aws-set --check`), the ai-env-* and the two AWS managed
 *     policies, the Lambda service-linked role (P16), S9's transcripts bucket's settings and policy (never an object),
 *     and (S11, L8) the stack's one budget, budgets:ViewBudget on its ARN only (doctor's budget row: describe-budget).
 * No IAM write (its own keys included), no iam:PassRole, no image, connector, Cloud Control, S3, budget or logs write.
 * `make check-policies` simulates both sides (its section 6).
 */
export function opsPolicy(n: Names): PolicyDocument {
    const acct = n.accountId;
    const instance = proxyInstanceArn(n);
    const relay = relayInstanceArn(n);
    return doc(
        {
            Sid: "OpsUnscoped", Effect: "Allow", Resource: ["*"],
            Action: ["ssm:GetCommandInvocation", "ssm:DescribeInstanceInformation",
                "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables", "ec2:DescribeNetworkAcls", "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs", "ec2:DescribeVpcAttribute", "ec2:DescribeDhcpOptions", "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeNatGateways", "ec2:DescribeVpcBlockPublicAccessOptions", "ec2:DescribeVpcBlockPublicAccessExclusions",
                "route53resolver:ListFirewallRuleGroupAssociations",
                "lambda:ListNetworkConnectors", "lambda:ListMicrovmImages", "lambda:ListManagedMicrovmImages", "lambda:ListManagedMicrovmImageVersions", "lambda:ListMicrovms",
                "logs:DescribeLogGroups", "cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors", "cloudtrail:ListChannels", "cloudtrail:GetChannel",
                "iam:GetAccountSummary", "access-analyzer:ValidatePolicy", "iam:SimulateCustomPolicy", "ec2:DescribeAddresses"],
        },
        { Sid: "ProxyInstance", Effect: "Allow", Resource: [instance], Action: ["ec2:StartInstances", "ec2:StopInstances"] },
        // S13: `ai-env relay start|stop`, and `ai-env relay status`'s reads (never the TLS pair).
        { Sid: "RelayInstance", Effect: "Allow", Resource: [relay], Action: ["ec2:StartInstances", "ec2:StopInstances"] },
        { Sid: "ReadRelayParameters", Effect: "Allow", Resource: RELAY_PARAMETERS.filter((p) => p !== RELAY_TLS).map((p) => relayParameterArn(n, p)), Action: ["ssm:GetParameters"] },
        { Sid: "ProxyCommands", Effect: "Allow", Resource: [...proxyDocumentArns(n), instance], Action: ["ssm:SendCommand"] },
        { Sid: "ReadProxyParameters", Effect: "Allow", Resource: PROXY_PARAMETERS.map((p) => proxyParameterArn(n, p)), Action: ["ssm:GetParameters", "ssm:GetParameterHistory"] },
        { Sid: "WriteSuspendedParameter", Effect: "Allow", Resource: [proxyParameterArn(n, "suspended")], Action: ["ssm:PutParameter"] },
        {
            Sid: "DnsFirewallReads", Effect: "Allow", Resource: [`arn:aws:route53resolver:${n.region}:${acct}:*`],
            Action: ["route53resolver:ListFirewallRules", "route53resolver:ListFirewallDomains", "route53resolver:GetFirewallConfig"],
        },
        { Sid: "ReadConnectors", Effect: "Allow", Resource: accountConnectorArns(n), Action: [GET_CONNECTOR_ACTION] },
        {
            Sid: "ReadImage", Effect: "Allow", Resource: [imageArn(n)],
            Action: ["lambda:GetMicrovmImage", "lambda:GetMicrovmImageVersion", "lambda:ListMicrovmImageVersions", "lambda:ListMicrovmImageBuilds"],
        },
        { Sid: "ReadLogs", Effect: "Allow", Resource: [...logGroupArns(n), ...egressLogGroupArns(n), ...dnsQueryLogGroupArns(n), ...relayLogGroupArns(n)], Action: ["logs:FilterLogEvents", "logs:StartLiveTail"] },
        { Sid: "ReadQuotas", Effect: "Allow", Resource: [MICROVM_MEMORY_QUOTA, VPC_QUOTA].map((q) => `arn:aws:servicequotas:${n.region}:${acct}:${q}`), Action: ["servicequotas:GetServiceQuota"] },
        // S11 (L8): doctor's budget row reads the stack's one budget (describe-budget), never another, never a write.
        { Sid: "ViewBudget", Effect: "Allow", Resource: [`arn:aws:budgets::${acct}:budget/${BUDGET_NAME}`], Action: ["budgets:ViewBudget"] },
        {
            Sid: "StackUsers", Effect: "Allow", Resource: STACK_USERS.map((u) => userArn(n, u)),
            Action: ["iam:SimulatePrincipalPolicy", "iam:ListAccessKeys", "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:ListGroupsForUser"],
        },
        { Sid: "ReadPolicies", Effect: "Allow", Resource: [...MANAGED_POLICY_ARNS, policyArn(n, `${PROJECT}-*`)], Action: ["iam:GetPolicy", "iam:GetPolicyVersion"] },
        // S9: `ai-env egress status`'s transcripts-bucket row: the bucket's settings and policy, never an object.
        {
            Sid: "ReadTranscriptsBucket", Effect: "Allow", Resource: [`arn:aws:s3:::${n.transcriptsBucket}`],
            Action: ["s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration"],
        },
        {
            Sid: "ReadLambdaServiceLinkedRole", Effect: "Allow", Resource: [`arn:aws:iam::${acct}:role/aws-service-role/${LAMBDA_SERVICE}/AWSServiceRoleForLambda`],
            Action: ["iam:GetRole"],
        },
    );
}

/** S9 adds `resource`: the S3 gateway endpoint's policy and the transcripts bucket's (Principal `*`, narrowed by conditions). */
export type PolicyKind = "identity" | "trust" | "resource";

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
        { name: "deployer", kind: "identity", document: deployerPolicy(n) },
        { name: "ops", kind: "identity", document: opsPolicy(n) },
        { name: "proxy-trust", kind: "trust", document: proxyTrustPolicy() },
        { name: "proxy", kind: "identity", document: proxyRolePolicy(n) },
        { name: "operator-trust", kind: "trust", document: operatorTrustPolicy() },
        { name: "operator", kind: "identity", document: operatorRolePolicy(n) },
        // S13: the relay's role.
        { name: "relay-trust", kind: "trust", document: relayTrustPolicy() },
        { name: "relay", kind: "identity", document: relayRolePolicy(n) },
        { name: "s3-endpoint", kind: "resource", document: s3EndpointPolicy(n) },
        { name: "transcripts-bucket", kind: "resource", document: transcriptsBucketPolicy(n) },
    ];
}
