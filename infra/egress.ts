// The S5 egress side of the stack (plans/s5-plan.md "Design → Infra", "W1 review, design changes"): a dedicated
// VPC without Amazon DNS, the proxy subnet (0.0.0.0/0 → IGW) and the VM subnet (no route at all, its own NACL), the
// two security groups, the squid proxy instance with its role, profile, SSM parameters and log group, the
// connector's operator role (with an inline Deny confining its ENIs to the VM subnet and the VM security group) and
// the aws-native NetworkConnector `ai-env-egress` whose ENIs sit in the VM subnet. S8 operators adds the proxy's three
// SSM Command documents (infra/proxy/documents, egress-config.json's names): the only commands ai-env-ops and
// ai-env-deployer may send, and only to the proxy instance (AWS-RunShellScript is never sent).
//
// Why this shape: MicroVMs on the connector can only reach TCP 3128 on the proxy's address, which CONNECTs to an
// allowlist. Every network resource is built from the spec in egress-spec.ts after assertEgressSpec accepted it.
// guardEgress registers a resource transform before any resource exists: an allowlist of the stack inventory that
// checks every resource the program registers, anywhere, and the network resources input by input, then seals
// transform registration. The final word is scripts/check-plan.ts over `pulumi preview --json` (the engine does
// not order stack transforms, and a preview cannot compare unknown ids). No Pulumi `protect` (it would make `make
// destroy` refuse), no `retainOnDelete` and no `deletedWith` anywhere (destroy, the account root's alone, removes the
// operator identities too): the guard refuses all three; `make deploy`'s replacement guard covers the VPC, subnets, SGs and
// connector, and check-plan refuses replacing or deleting the deployer's identity. The proxy configuration lives in
// SSM Parameter Store, never in user-data (a user-data change replaces the instance).
//
// S9 (plans/s9-contracts.md §7.1, §7.7): the S3 gateway endpoint ai-env-s3 on the proxy's route table only (never the
// VM table: squid stays the only way out of the VMs), its policy policies.ts s3EndpointPolicy; the `allow` parameter
// carries the transcripts bucket's virtual-hosted name after allow.txt (egress-spec.ts allowValue). The guard checks the
// endpoint and the transcripts bucket's resources (transcripts.ts) input by input, their policies against policies.ts
// for the stack's account. The scratch:endpoint-table and scratch:endpoint-policy markers are edited by `make
// preview-scratch NEGATIVE=endpoint-on-vm-table|endpoint-policy-widen` in a scratch copy.
//
// S13 (plans/s13-contracts.md §I-infra.4.2): the relay's security group `ai-env-relay` and its seven rules join the SG
// loop (SG_KEYS), the VM group gets its second rule (to the relay's private port), and the guard checks the relay's
// resources (relay.ts): its instance by name, its Elastic IP and association, its artifact object, parameter, log group
// and SSM attachment. The template renderer is egress-spec.ts's renderTemplate (LD-I14): the proxy's files render byte
// for byte as before.
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsnative from "@pulumi/aws-native";
import {
    AMI_PARAMETER, DOCUMENT_ROLES, DocumentRole, EgressConfig, EgressSpec, FIREWALL_ASSOCIATION_PRIORITY, FIREWALL_BLOCK_RESPONSE, FIREWALL_REDIRECTION, FIREWALL_RULE_PRIORITY,
    ImageNames, NET, NaclRuleSpec, PARAMETER_MAX_BYTES, PROVIDER_INPUTS, PROXY_PARAMETERS, PROXY_SG_DESCRIPTION, ProxyDocuments, ProxyParameter, RELAY_SG_DESCRIPTION, RouteSpec,
    RuleSpec, SG_KEYS, SgKey, VM_SG_DESCRIPTION, allowValue, checkNacl, checkProxyDocument, checkRoutes, checkRule, checkVpcDns, dnsQueryLogGroup, documentFile, documentNames,
    embedded, inInventory, renderTemplate, ruleName, ruleOwner, stackInventory,
} from "./egress-spec";
import {
    CONNECTOR_OPERATOR_POLICY_ARN, Names, POLICY_DESCRIPTIONS, PolicyDocument, REGION, RELAY_INSTANCE_PROFILE_NAME, RELAY_ROLE_NAME, RUNTIME_USER_NAME, S3_ENDPOINT_SERVICE,
    SSM_INSTANCE_POLICY_ARN, TRANSCRIPTS_RESOURCE, USER_POLICY_ATTACHMENTS, attachmentName, canonicalPolicyText, operatorRolePolicy, operatorTrustPolicy, proxyRolePolicy,
    proxyTrustPolicy, s3EndpointPolicy, transcriptsBucketName, transcriptsBucketPolicy,
} from "./policies";
import { RELAY_KEY_RE } from "./relay-spec";
import { TRANSCRIPTS_LIFECYCLE } from "./transcripts";

/** The operator role must be assumable before CreateNetworkConnector (IAM is eventually consistent; image.ts waits 15 s). */
const CONNECTOR_IAM_PROPAGATION_MS = 30_000;
/** EC2's limit on raw user data. */
const USER_DATA_MAX_BYTES = 16 * 1024;
/** Filled by the proxy's reload script at run time (contract 3), the only token allowed to survive rendering. */
const RUNTIME_TOKEN = "@DIR@";

// ---- the proxy files (infra/proxy/*, contract 3) ----

export interface ProxyFiles {
    /** Rendered squid.conf (the `squid.conf` parameter; @DIR@ is left for the reload script). */
    squidConf: string;
    /** The base allowlist (the `allow` parameter). */
    allow: string;
    userData: string;
}

/** Every token each template must carry: a missing one means a config value never reaches the proxy. */
const TOKENS: Record<string, string[]> = {
    "squid.conf": ["PROXY_IP", "PORT", "VMS", "RESOLVERS"],
    "cloudwatch-agent.json": ["LOG_GROUP"],
    "user-data.sh": ["PARAM_PREFIX", "REGION", "LOG_GROUP", "RELOAD_SH", "CW_AGENT_JSON"],
};

/** One pass of token replacement (egress-spec.ts renderTemplate): a value is never scanned again (the embedded reload script carries @DIR@). */
function render(dir: string, file: string, values: Record<string, string>): string {
    return renderTemplate(dir, file, TOKENS[file], values, [RUNTIME_TOKEN]);
}

/**
 * squid.conf, allow.txt and user-data.sh rendered from infra/proxy and the config; throws on a leftover placeholder
 * (other than @DIR@), a squid.conf or allowlist over a standard parameter (4096 bytes), user data over 16 KB, or a
 * heredoc delimiter of user-data.sh occurring in a file it embeds (the heredoc would end early).
 */
export function renderProxyFiles(cfg: EgressConfig, region: string, dir = path.join(__dirname, "proxy")): ProxyFiles {
    const squidConf = render(dir, "squid.conf", { PROXY_IP: cfg.proxyIp, PORT: String(cfg.proxyPort), VMS: cfg.vmSubnetCidr, RESOLVERS: cfg.resolvers.join(" ") });
    const cwAgent = render(dir, "cloudwatch-agent.json", { LOG_GROUP: cfg.logGroup });
    try {
        JSON.parse(cwAgent);
    } catch (e) {
        throw new Error(`${path.join(dir, "cloudwatch-agent.json")}: not JSON after rendering: ${(e as Error).message}`);
    }
    const reload = fs.readFileSync(path.join(dir, "reload.sh"), "utf-8");
    const template = fs.readFileSync(path.join(dir, "user-data.sh"), "utf-8");
    const delimiters = [...template.matchAll(/<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/g)].map((m) => m[2]);
    for (const [file, body] of [["reload.sh", reload], ["cloudwatch-agent.json", cwAgent]]) {
        const hit = delimiters.find((d) => body.includes(d));
        if (hit !== undefined) throw new Error(`${path.join(dir, file)} contains ${hit}, a heredoc delimiter of user-data.sh: the embedded copy would end early`);
    }
    const userData = render(dir, "user-data.sh", {
        PARAM_PREFIX: cfg.parameterPrefix, REGION: region, LOG_GROUP: cfg.logGroup, RELOAD_SH: embedded(reload), CW_AGENT_JSON: embedded(cwAgent),
    });
    const allow = fs.readFileSync(path.join(dir, "allow.txt"), "utf-8");
    const bytes = (s: string) => Buffer.byteLength(s, "utf-8");
    if (bytes(squidConf) > PARAMETER_MAX_BYTES) throw new Error(`${path.join(dir, "squid.conf")}: rendered ${bytes(squidConf)} bytes, over the ${PARAMETER_MAX_BYTES}-byte standard parameter`);
    if (bytes(allow) > PARAMETER_MAX_BYTES) throw new Error(`${path.join(dir, "allow.txt")}: ${bytes(allow)} bytes, over the ${PARAMETER_MAX_BYTES}-byte standard parameter`);
    if (allow.trim().length === 0) throw new Error(`${path.join(dir, "allow.txt")} is empty (an SSM parameter cannot be)`);
    if (bytes(userData) > USER_DATA_MAX_BYTES) throw new Error(`${path.join(dir, "user-data.sh")}: rendered ${bytes(userData)} bytes, over EC2's ${USER_DATA_MAX_BYTES}-byte user data limit`);
    return { squidConf, allow, userData };
}

// ---- the guard: a stack transform over every resource ----

const T = {
    providerAws: "pulumi:providers:aws",
    providerNative: "pulumi:providers:aws-native",
    vpc: "aws:ec2/vpc:Vpc",
    dhcp: "aws:ec2/vpcDhcpOptions:VpcDhcpOptions",
    dhcpAssociation: "aws:ec2/vpcDhcpOptionsAssociation:VpcDhcpOptionsAssociation",
    igw: "aws:ec2/internetGateway:InternetGateway",
    subnet: "aws:ec2/subnet:Subnet",
    routeTable: "aws:ec2/routeTable:RouteTable",
    routeTableAssociation: "aws:ec2/routeTableAssociation:RouteTableAssociation",
    nacl: "aws:ec2/networkAcl:NetworkAcl",
    naclAssociation: "aws:ec2/networkAclAssociation:NetworkAclAssociation",
    defaultSg: "aws:ec2/defaultSecurityGroup:DefaultSecurityGroup",
    sg: "aws:ec2/securityGroup:SecurityGroup",
    ingress: "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule",
    egress: "aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule",
    instance: "aws:ec2/instance:Instance",
    connector: "aws-native:lambda:NetworkConnector",
    parameter: "aws:ssm/parameter:Parameter",
    logGroup: "aws:cloudwatch/logGroup:LogGroup",
    role: "aws:iam/role:Role",
    rolePolicy: "aws:iam/rolePolicy:RolePolicy",
    attachment: "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
    instanceProfile: "aws:iam/instanceProfile:InstanceProfile",
    user: "aws:iam/user:User",
    userPolicy: "aws:iam/userPolicy:UserPolicy",
    policy: "aws:iam/policy:Policy",
    userAttachment: "aws:iam/userPolicyAttachment:UserPolicyAttachment",
    document: "aws:ssm/document:Document",
    budget: "aws:budgets/budget:Budget",
    image: "aws-native:lambda:MicrovmImage",
    fwDomainList: "aws:route53/resolverFirewallDomainList:ResolverFirewallDomainList",
    fwRuleGroup: "aws:route53/resolverFirewallRuleGroup:ResolverFirewallRuleGroup",
    fwRule: "aws:route53/resolverFirewallRule:ResolverFirewallRule",
    fwAssociation: "aws:route53/resolverFirewallRuleGroupAssociation:ResolverFirewallRuleGroupAssociation",
    fwConfig: "aws:route53/resolverFirewallConfig:ResolverFirewallConfig",
    queryLog: "aws:route53/resolverQueryLogConfig:ResolverQueryLogConfig",
    queryLogAssociation: "aws:route53/resolverQueryLogConfigAssociation:ResolverQueryLogConfigAssociation",
    // S13: the relay's Elastic IP, its association and its artifact (relay.ts).
    eip: "aws:ec2/eip:Eip",
    eipAssociation: "aws:ec2/eipAssociation:EipAssociation",
    bucketObject: "aws:s3/bucketObjectv2:BucketObjectv2",
    // S9: the S3 gateway endpoint and the transcripts bucket's resources (transcripts.ts).
    endpoint: "aws:ec2/vpcEndpoint:VpcEndpoint",
    bucket: "aws:s3/bucket:Bucket",
    versioning: "aws:s3/bucketVersioning:BucketVersioning",
    encryption: "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
    ownership: "aws:s3/bucketOwnershipControls:BucketOwnershipControls",
    publicAccess: "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
    lifecycle: "aws:s3/bucketLifecycleConfiguration:BucketLifecycleConfiguration",
    bucketPolicy: "aws:s3/bucketPolicy:BucketPolicy",
} as const;

/**
 * Ids the guard compares references against (tracked right after each resource is created). S9 adds the stack's
 * account (the policies the guard compares are built for it), the S3 gateway endpoint and the transcripts bucket; S13
 * the relay instance and its Elastic IP (a VPC address's id is its allocation id), and `sg:relay` through SgKey.
 */
type IdKey = "vpc" | "dhcp" | "igw" | "nacl" | "fw-list" | "fw-group" | "query-log" | `subnet:${"proxy" | "vms"}` | `rt:${"proxy" | "vms"}` | `sg:${SgKey}`
    | "account" | "s3-endpoint" | "transcripts" | "relay-instance" | "relay-eip";

export interface EgressGuard {
    /** Records a resource's id for the guard's reference checks (call right after creating the resource). */
    track(key: IdKey, id: pulumi.Output<string>): void;
}

type Props = Record<string, unknown>;

/**
 * A computed input the transform cannot see yet. The engine hands the transform every input that came from another
 * resource as an Output without dependencies: unknown in a preview of a new resource, known during an update.
 */
const UNKNOWN = Symbol("unknown");

/** Props as plain values: an Output becomes its value, or UNKNOWN (Output's isKnown/promise are not in its typings). */
async function settle(v: unknown): Promise<unknown> {
    if (pulumi.Output.isInstance(v)) {
        const o = v as unknown as { isKnown: Promise<boolean>; promise(): Promise<unknown> };
        return (await o.isKnown) ? settle(await o.promise()) : UNKNOWN;
    }
    if (pulumi.isUnknown(v)) return UNKNOWN;
    if (Array.isArray(v)) return Promise.all(v.map(settle));
    if (v !== null && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
        const out: Props = {};
        for (const [k, x] of Object.entries(v)) out[k] = await settle(x);
        return out;
    }
    return v;
}

function show(v: unknown): string {
    return v === UNKNOWN ? "(unknown)" : JSON.stringify(v);
}

/** `p`, or undefined once `ms` passed (a tracked id that never resolves: unknown in a preview). */
function within<T>(p: Promise<T> | undefined, ms: number): Promise<T | undefined> {
    if (p === undefined) return Promise.resolve(undefined);
    return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(undefined), ms);
        timer.unref();
        p.then((v) => { clearTimeout(timer); resolve(v); }, () => { clearTimeout(timer); resolve(undefined); });
    });
}

function isSet(v: unknown): boolean {
    return v !== undefined && v !== null && v !== "";
}

function sameList(a: unknown, b: readonly unknown[]): boolean {
    return Array.isArray(a) && a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Transform registrations the SDK exposes: on `pulumi.runtime` and its stack module, and on the callback server. */
const TRANSFORM_ENTRY_POINTS = ["registerResourceTransform", "registerStackTransform", "registerStackTransformation", "registerInvokeTransform"];
const CALLBACK_ENTRY_POINTS = ["registerStackTransform", "registerStackInvokeTransform"];

/**
 * After the guard: every later transform registration throws. The engine does not run stack transforms in
 * registration order, so a later transform could rewrite inputs the guard approved (a transform registered before
 * the guard can too: scripts/check-plan.ts, over the planned inputs, is the final word).
 */
function sealTransforms(): void {
    const refuse = (what: string) => () => {
        throw new Error(`egress guard (infra/egress.ts): ${what} after the guard is refused: a later transform could rewrite inputs the guard approved`);
    };
    const modules: Record<string, unknown>[] = [pulumi.runtime as unknown as Record<string, unknown>, require("@pulumi/pulumi/runtime/stack"), require("@pulumi/pulumi/runtime")];
    for (const m of modules) for (const k of TRANSFORM_ENTRY_POINTS) if (typeof m[k] === "function") m[k] = refuse(k);
    const callbacks: Record<string, unknown> | undefined = require("@pulumi/pulumi/runtime/settings").getCallbacks();
    if (callbacks !== undefined) for (const k of CALLBACK_ENTRY_POINTS) if (typeof callbacks[k] === "function") callbacks[k] = refuse(`callbacks.${k}`);
}

/**
 * Registers the stack transform (call it before any resource is registered: it applies to the resources registered
 * after it), then seals transform registration. The transform is an allowlist: a resource outside the stack
 * inventory (egress-spec.ts stackInventory: CloudFormation stacks, Cloud Control and other generic resources, SSM
 * associations, extra providers, components...) is refused, and every resource of the inventory has its inputs
 * checked; the network resources against the spec's predicates, input by input. It throws, failing the preview or
 * update. In a preview of new resources the references (vpcId, subnet and SG ids) are unknown: check-plan.ts checks
 * them by URN; during an update the guard compares them with the ids the egress resources got. `documents` are the
 * proxy's SSM documents as index.ts read them (readProxyDocuments): each Document resource must carry exactly its file.
 */
export function guardEgress(spec: EgressSpec, image: ImageNames, documents: ProxyDocuments): EgressGuard {
    const cfg = spec.cfg;
    const inventory = stackInventory(cfg, image);
    const ids = new Map<IdKey, Promise<string>>();
    const counts = new Map<string, number>();
    // Maps, never object literals: a name like `constructor` must not find Object.prototype's.
    const tables = new Map<string, "proxy" | "vms">([[NET.proxy, "proxy"], [NET.vms, "vms"]]);
    const sgKeys = new Map<string, SgKey>([[cfg.vmSecurityGroupName, "vm"], [cfg.proxySecurityGroupName, "proxy"], [cfg.relaySecurityGroupName, "relay"]]);
    const sgDescriptions = new Map<SgKey, string>([["vm", VM_SG_DESCRIPTION], ["proxy", PROXY_SG_DESCRIPTION], ["relay", RELAY_SG_DESCRIPTION]]);
    const parameterNames = new Map<string, string>([
        ...PROXY_PARAMETERS.map((p) => [`ai-env-proxy-${p}`, `${cfg.parameterPrefix}/${p}`] as [string, string]),
        [NET.relayArtifactParameter, `${cfg.relayParameterPrefix}/artifact`],
    ]);
    const logGroups = new Map<string, string>([
        ["image-log-group", image.logGroup], [NET.logGroup, cfg.logGroup], [NET.dnsLogGroup, dnsQueryLogGroup(cfg)], [NET.relayLogGroup, cfg.relayLogGroup],
    ]);
    const attachments = new Map<string, string>([
        [`${cfg.proxyRoleName}-ssm`, SSM_INSTANCE_POLICY_ARN], [cfg.operatorRoleName, CONNECTOR_OPERATOR_POLICY_ARN], [`${RELAY_ROLE_NAME}-ssm`, SSM_INSTANCE_POLICY_ARN],
    ]);
    // S8 operators: which user and policy each user policy attachment binds, and which document each name is.
    const userAttachments = new Map<string, readonly [string, string]>(USER_POLICY_ATTACHMENTS.map(([u, p]) => [attachmentName(u, p), [u, p] as const]));
    const documentRoles = new Map<string, DocumentRole>(DOCUMENT_ROLES.map((r) => [documentNames(cfg)[r], r]));

    async function check(type: string, name: string, custom: boolean, props: Props, opts: pulumi.ResourceOptions): Promise<string[]> {
        const problems: string[] = [];
        const waits: Promise<void>[] = [];
        const bad = (msg: string) => problems.push(msg);
        if (!custom) return [`component resources are refused (the stack has none): ${type} ${name}`];
        if (!inInventory(inventory, type, name)) return [`not in the stack inventory (infra/egress-spec.ts stackInventory): ${type} ${name}`];
        // No resource keeps itself out of `make destroy`, or out of its own deletion (contracts §1.1). deletedWith does
        // the same: when the named resource goes in the same run, Pulumi never calls this one's Delete (it would leave
        // ai-env-deployer, its key and its policies behind a `make destroy` that reports success).
        if (opts.protect === true) bad("protect is refused (make destroy must work)");
        if (opts.retainOnDelete === true) bad("retainOnDelete is refused (make destroy removes every resource of the stack, the operator identities included)");
        if (opts.deletedWith !== undefined && opts.deletedWith !== null) bad("deletedWith is refused (make destroy deletes every resource of the stack itself, the operator identities included)");
        // Only these inputs may be set; any other is outside the spec.
        const only = (...keys: string[]) => {
            for (const [k, v] of Object.entries(props)) if (isSet(v) && !keys.includes(k)) bad(`input ${k} is outside the stack spec`);
            if (isSet(props.region) && props.region !== REGION) bad(`region ${show(props.region)} is not ${REGION}`);
        };
        const eq = (k: string, want: unknown) => {
            if (props[k] !== want) bad(`${k} must be ${JSON.stringify(want)}, got ${show(props[k])}`);
        };
        // A reference to another egress resource: unknown (a preview of a new resource), or exactly the id the
        // resource got. A literal id or another resource's id is refused. During an update the id is known by the time
        // a dependent registers; a preview of an existing stack knows it too, else (replaced) the reference is unknown.
        const ref = (field: string, key: IdKey, actual: unknown) => {
            if (actual === UNKNOWN) return;
            if (typeof actual !== "string" || actual === "") { bad(`${field} must reference the egress ${key}`); return; }
            waits.push(within(ids.get(key), pulumi.runtime.isDryRun() ? 5_000 : 600_000).then((want) => {
                if (actual !== want) bad(`${field} ${actual} is not the egress ${key}${want === undefined ? " (unknown or not created by egress.ts)" : ` (${want})`}`);
            }));
        };
        const once = (key: string, max: number) => {
            const n = (counts.get(key) ?? 0) + 1;
            counts.set(key, n);
            if (n > max) bad(`${key}: more than ${max} (the spec has exactly ${max})`);
        };
        // S9: a resource policy that must be policies.ts's document for the stack's account (the bucket's: and the S3
        // gateway endpoint's id), compared in canonical form once known. Unknown (a preview of a new dependency) is
        // check-plan's to hold by URN; known while the endpoint's id is not, it was not built from that endpoint.
        const wait = pulumi.runtime.isDryRun() ? 5_000 : 600_000;
        const policyIs = (actual: unknown, build: (acct: string, endpoint: string | undefined) => PolicyDocument, needsEndpoint: boolean) => {
            if (actual === UNKNOWN) return;
            if (typeof actual !== "string") { bad("policy must be the policy document's JSON text"); return; }
            waits.push(Promise.all([within(ids.get("account"), wait), needsEndpoint ? within(ids.get("s3-endpoint"), wait) : Promise.resolve(undefined)]).then(([acct, endpoint]) => {
                if (acct === undefined) { bad("policy: the stack's account is unknown, so the document cannot be compared"); return; }
                if (needsEndpoint && endpoint === undefined) { bad("policy is known while the S3 gateway endpoint's id is not: it is not built from that endpoint"); return; }
                let got: string;
                try {
                    got = canonicalPolicyText(actual);
                } catch {
                    bad("policy is not JSON");
                    return;
                }
                if (got !== canonicalPolicyText(build(acct, endpoint))) bad("policy is not policies.ts's document for the stack");
            }));
        };

        switch (type) {
        case T.providerAws:
        case T.providerNative:
            only(...PROVIDER_INPUTS);
            eq("region", REGION);
            break;
        case T.vpc: {
            only("cidrBlock", "enableDnsSupport", "enableDnsHostnames", "tags", "region");
            eq("cidrBlock", cfg.vpcCidr);
            const dns = checkVpcDns(cfg, props.enableDnsSupport, props.enableDnsHostnames);
            if (dns) bad(dns);
            break;
        }
        case T.dhcp:
            only("domainNameServers", "tags", "region");
            if (!sameList(props.domainNameServers, cfg.resolvers)) bad(`domainNameServers must be exactly ${cfg.resolvers.join(", ")}, got ${show(props.domainNameServers)}`);
            break;
        case T.dhcpAssociation:
            only("vpcId", "dhcpOptionsId", "region");
            ref("vpcId", "vpc", props.vpcId);
            ref("dhcpOptionsId", "dhcp", props.dhcpOptionsId);
            break;
        case T.igw:
            only("vpcId", "tags", "region");
            ref("vpcId", "vpc", props.vpcId);
            break;
        case T.subnet: {
            const t = tables.get(name)!;
            only("vpcId", "cidrBlock", "availabilityZoneId", "mapPublicIpOnLaunch", "tags", "region");
            ref("vpcId", "vpc", props.vpcId);
            eq("cidrBlock", t === "proxy" ? cfg.proxySubnetCidr : cfg.vmSubnetCidr);
            eq("availabilityZoneId", cfg.azId);
            eq("mapPublicIpOnLaunch", false);
            break;
        }
        case T.routeTable: {
            const t = tables.get(name)!;
            only("vpcId", "routes", "tags", "region");
            ref("vpcId", "vpc", props.vpcId);
            // Inline routes, always an explicit list (the VM table's is empty).
            if (!Array.isArray(props.routes)) { bad("routes must be an explicit list (the VM table's is empty)"); break; }
            const routes: RouteSpec[] = [];
            for (const r of props.routes as Props[]) {
                const keys = Object.keys(r).filter((k) => isSet(r[k]));
                const other = keys.filter((k) => k !== "cidrBlock" && k !== "gatewayId");
                if (other.length > 0 || !isSet(r.gatewayId)) bad(`route ${show(r.cidrBlock)}: only an IPv4 CIDR to the internet gateway (got ${keys.join(", ")})`);
                if (isSet(r.gatewayId)) ref(`route ${String(r.cidrBlock)} gatewayId`, "igw", r.gatewayId);
                routes.push({ cidr: String(r.cidrBlock), target: "igw" });
            }
            const r = checkRoutes(t, routes);
            if (r) bad(r);
            break;
        }
        case T.routeTableAssociation: {
            const t = tables.get(name)!;
            only("subnetId", "routeTableId", "region");
            ref("subnetId", `subnet:${t}`, props.subnetId);
            ref("routeTableId", `rt:${t}`, props.routeTableId);
            break;
        }
        case T.nacl: {
            only("vpcId", "ingress", "egress", "tags", "region");
            ref("vpcId", "vpc", props.vpcId);
            const rules = (dir: "ingress" | "egress"): NaclRuleSpec[] => {
                const list = props[dir];
                if (!Array.isArray(list)) { bad(`${dir} must be an explicit list`); return []; }
                return (list as Props[]).map((r) => {
                    const extra = Object.keys(r).filter((k) => isSet(r[k]) && !["ruleNo", "protocol", "action", "cidrBlock", "fromPort", "toPort"].includes(k));
                    if (extra.length > 0) bad(`${dir} rule ${show(r.ruleNo)}: ${extra.join(", ")} outside the egress spec`);
                    return { ruleNo: r.ruleNo, protocol: r.protocol, action: r.action, cidr: r.cidrBlock, fromPort: r.fromPort, toPort: r.toPort } as NaclRuleSpec;
                });
            };
            const n = checkNacl(cfg, rules("ingress"), rules("egress"));
            if (n) bad(n);
            break;
        }
        case T.naclAssociation:
            only("networkAclId", "subnetId", "region");
            ref("networkAclId", "nacl", props.networkAclId);
            ref("subnetId", "subnet:vms", props.subnetId);
            break;
        case T.defaultSg:
            only("vpcId", "ingress", "egress", "tags", "region");
            ref("vpcId", "vpc", props.vpcId);
            if (!sameList(props.ingress, []) || !sameList(props.egress, [])) bad("the VPC's default security group must have no rules (explicit empty ingress and egress)");
            break;
        case T.sg: {
            const sg = sgKeys.get(name)!;
            // No inline ingress/egress: rules are separate resources this guard checks one by one.
            only("name", "description", "vpcId", "tags", "region");
            eq("name", name);
            eq("description", sgDescriptions.get(sg));
            ref("vpcId", "vpc", props.vpcId);
            break;
        }
        case T.ingress:
        case T.egress: {
            const sg = ruleOwner(spec, name);
            if (sg === undefined) return [`not part of the egress spec: ${type} ${name}`];
            only("securityGroupId", "ipProtocol", "fromPort", "toPort", "cidrIpv4", "referencedSecurityGroupId", "description", "tags", "region");
            ref("securityGroupId", `sg:${sg}`, props.securityGroupId);
            const direction = type === T.ingress ? "ingress" : "egress";
            const peers = [isSet(props.cidrIpv4), isSet(props.referencedSecurityGroupId)].filter(Boolean).length;
            if (peers !== 1) { bad("exactly one peer: cidrIpv4 or referencedSecurityGroupId"); break; }
            // What the rule opens must be visible here: literals only, never a computed value.
            const computed = ["ipProtocol", "fromPort", "toPort", "cidrIpv4"].filter((k) => props[k] === UNKNOWN);
            if (computed.length > 0) { bad(`${computed.join(", ")} must be literal values`); break; }
            if (props.fromPort !== props.toPort) { bad(`one port only, got ${String(props.fromPort)}-${String(props.toPort)}`); break; }
            // The only referenced group in the spec: the proxy's and the relay's ingress name the VM group.
            if (isSet(props.referencedSecurityGroupId)) ref("referencedSecurityGroupId", "sg:vm", props.referencedSecurityGroupId);
            const rule: RuleSpec = {
                direction, protocol: props.ipProtocol as RuleSpec["protocol"], port: props.fromPort as number,
                peer: isSet(props.cidrIpv4) ? { cidr: String(props.cidrIpv4) } : { sg: "vm" }, description: "",
            };
            const r = checkRule(cfg, sg, rule);
            if (r) bad(r);
            if (sg === "vm") once(`rules of ${cfg.vmSecurityGroupName}`, 2);
            if (sg === "proxy" && direction === "ingress") once(`ingress rules of ${cfg.proxySecurityGroupName}`, 1);
            if (sg === "relay" && direction === "ingress") once(`ingress rules of ${cfg.relaySecurityGroupName}`, 2);
            break;
        }
        // The proxy, and (S13) the relay by its name: both in the proxy subnet, each with its own group, address and profile.
        case T.instance: {
            const relay = name === NET.relayInstance;
            only("ami", "instanceType", "subnetId", "privateIp", "associatePublicIpAddress", "vpcSecurityGroupIds", "iamInstanceProfile", "metadataOptions",
                "rootBlockDevice", "creditSpecification", "userData", "userDataReplaceOnChange", "tags", "volumeTags", "region");
            ref("subnetId", "subnet:proxy", props.subnetId);
            const sgs = props.vpcSecurityGroupIds;
            if (!Array.isArray(sgs) || sgs.length !== 1) bad(`vpcSecurityGroupIds must be exactly the ${relay ? "relay" : "proxy"} security group`);
            else ref("vpcSecurityGroupIds[0]", relay ? "sg:relay" : "sg:proxy", sgs[0]);
            eq("privateIp", relay ? cfg.relayIp : cfg.proxyIp);
            eq("associatePublicIpAddress", true);
            eq("instanceType", relay ? cfg.relayInstanceType : cfg.instanceType);
            eq("iamInstanceProfile", relay ? RELAY_INSTANCE_PROFILE_NAME : cfg.proxyInstanceProfileName);
            const md = (props.metadataOptions ?? {}) as Props;
            if (md.httpTokens !== "required" || md.httpPutResponseHopLimit !== 1) bad("metadataOptions must require IMDSv2 with hop limit 1");
            break;
        }
        // S13: the relay's Elastic IP (a VPC address, nothing else set) and its association (that address, the relay instance).
        case T.eip:
            only("domain", "tags", "region");
            eq("domain", "vpc");
            break;
        case T.eipAssociation:
            only("allocationId", "instanceId", "region");
            ref("allocationId", "relay-eip", props.allocationId);
            ref("instanceId", "relay-instance", props.instanceId);
            break;
        // S13: the relay's artifact object (the image zip falls through, as before): its hash-keyed key, a binary.
        case T.bucketObject:
            if (name !== NET.relayArtifact) break;
            only("bucket", "key", "source", "contentType", "tags", "region");
            if (props.key !== UNKNOWN && !(typeof props.key === "string" && RELAY_KEY_RE.test(props.key))) bad(`key must be relay/ai-env-relay-<sha256[:16]>, got ${show(props.key)}`);
            eq("contentType", "application/octet-stream");
            break;
        case T.connector: {
            only("name", "configuration", "operatorRole", "tags");
            eq("name", cfg.connectorName);
            const c = (((props.configuration ?? {}) as Props).vpcEgressConfiguration ?? {}) as Props;
            for (const k of Object.keys(c)) if (!["subnetIds", "securityGroupIds", "networkProtocol", "associatedComputeResourceTypes"].includes(k) && isSet(c[k])) bad(`configuration.vpcEgressConfiguration.${k} is outside the egress spec`);
            const one = (field: string, key: IdKey, v: unknown) => {
                if (!Array.isArray(v) || v.length !== 1) bad(`configuration.vpcEgressConfiguration.${field} must be exactly the egress ${key}`);
                else ref(`configuration.vpcEgressConfiguration.${field}[0]`, key, v[0]);
            };
            one("subnetIds", "subnet:vms", c.subnetIds);
            one("securityGroupIds", "sg:vm", c.securityGroupIds);
            if (c.networkProtocol !== "IPv4") bad(`networkProtocol must be IPv4, got ${show(c.networkProtocol)}`);
            if (!sameList(c.associatedComputeResourceTypes, ["MicroVm"])) bad("associatedComputeResourceTypes must be [MicroVm]");
            break;
        }
        case T.parameter:
            only("name", "type", "tier", "dataType", "insecureValue", "description", "tags", "region");
            eq("name", parameterNames.get(name));
            eq("type", "String");
            eq("tier", "Standard");
            break;
        case T.logGroup:
            eq("name", logGroups.get(name));
            break;
        // IAM: the inputs iam.ts and egress.ts set, nothing else (no managedPolicyArns, inlinePolicies or permissions
        // boundary on a role; on a user only its name, forceDestroy and tags; MacRuntimePolicy, the inventory's only user
        // policy, stays on ai-env-runtime; a user policy attachment binds exactly the stack's user and policy its name
        // says). A user known here (an update, or a literal) is compared; in a fresh preview it is another resource's
        // output, unknown, and check-plan.ts holds it by URN. The policy documents themselves are compared by
        // check-plan.ts, which knows the account id.
        case T.role:
            only("name", "description", "assumeRolePolicy", "tags");
            eq("name", name);
            break;
        case T.rolePolicy:
            only("name", "role", "policy");
            eq("name", name);
            break;
        case T.user:
            only("name", "forceDestroy", "tags");
            eq("name", name);
            eq("forceDestroy", true);
            break;
        case T.userPolicy:
            only("name", "user", "policy");
            eq("name", name);
            // On another user (ai-env-ops, say) the runtime grants would follow it: RunMicrovm, the shell token, PassRole.
            if (props.user !== UNKNOWN) eq("user", RUNTIME_USER_NAME);
            break;
        case T.policy:
            only("name", "description", "policy", "tags");
            eq("name", name);
            // Frozen: IAM cannot change a description in place, so a new one replaces the policy.
            eq("description", POLICY_DESCRIPTIONS.get(name));
            break;
        case T.userAttachment: {
            const [user, policy] = userAttachments.get(name)!;
            only("user", "policyArn");
            if (props.user !== UNKNOWN) eq("user", user);
            const arn = props.policyArn;
            if (arn !== UNKNOWN && !(typeof arn === "string" && /^arn:aws:iam::[0-9]{12}:policy\/[A-Za-z0-9+=,.@_-]+$/.test(arn) && arn.slice(arn.lastIndexOf("/") + 1) === policy)) {
                bad(`policyArn must be the stack's policy ${policy}, got ${show(arn)}`);
            }
            break;
        }
        case T.document: {
            const role = documentRoles.get(name)!;
            only("name", "content", "documentType", "documentFormat", "targetType", "tags", "region");
            eq("name", name);
            eq("documentType", "Command");
            eq("documentFormat", "JSON");
            eq("targetType", "/AWS::EC2::Instance");
            if (typeof props.content !== "string") { bad(`content must be a literal, the canonical ${documentFile(role)}`); break; }
            if (props.content !== documents[role]) bad(`content is not ${documentFile(role)}`);
            for (const p of checkProxyDocument(role, props.content)) bad(p);
            break;
        }
        case T.instanceProfile:
            only("name", "role", "tags");
            eq("name", name);
            break;
        case T.attachment:
            only("role", "policyArn", "region");
            eq("policyArn", attachments.get(name));
            break;
        case T.budget:
        case T.image:
            eq("name", name);
            break;
        case T.fwDomainList:
            only("name", "domains", "tags", "region");
            eq("name", NET.firewall);
            if (!sameList(props.domains, ["*"])) bad("the DNS Firewall domain list must be exactly [*]");
            break;
        case T.fwRuleGroup:
            only("name", "tags", "region");
            eq("name", NET.firewall);
            break;
        case T.fwRule:
            // No qType (it would block one record type only) and no override: every name gets NXDOMAIN.
            only("name", "action", "blockResponse", "firewallDomainRedirectionAction", "firewallDomainListId", "firewallRuleGroupId", "priority", "region");
            eq("name", NET.firewall);
            eq("action", "BLOCK");
            eq("blockResponse", FIREWALL_BLOCK_RESPONSE);
            eq("firewallDomainRedirectionAction", FIREWALL_REDIRECTION);
            eq("priority", FIREWALL_RULE_PRIORITY);
            ref("firewallDomainListId", "fw-list", props.firewallDomainListId);
            ref("firewallRuleGroupId", "fw-group", props.firewallRuleGroupId);
            break;
        case T.fwAssociation:
            only("name", "firewallRuleGroupId", "vpcId", "priority", "mutationProtection", "tags", "region");
            eq("name", NET.firewall);
            eq("priority", FIREWALL_ASSOCIATION_PRIORITY);
            eq("mutationProtection", "DISABLED");
            ref("firewallRuleGroupId", "fw-group", props.firewallRuleGroupId);
            ref("vpcId", "vpc", props.vpcId);
            break;
        case T.fwConfig:
            only("resourceId", "firewallFailOpen", "region");
            ref("resourceId", "vpc", props.resourceId);
            eq("firewallFailOpen", "DISABLED");
            break;
        case T.queryLog:
            only("name", "destinationArn", "tags", "region");
            eq("name", NET.queryLog);
            break;
        case T.queryLogAssociation:
            only("resolverQueryLogConfigId", "resourceId", "region");
            ref("resolverQueryLogConfigId", "query-log", props.resolverQueryLogConfigId);
            ref("resourceId", "vpc", props.resourceId);
            break;
        // S9: the S3 gateway endpoint: Gateway, S3 of the region, exactly the proxy's route table, policies.ts's policy.
        case T.endpoint: {
            only("vpcId", "serviceName", "vpcEndpointType", "routeTableIds", "policy", "tags", "region");
            ref("vpcId", "vpc", props.vpcId);
            eq("serviceName", S3_ENDPOINT_SERVICE);
            eq("vpcEndpointType", "Gateway");
            const tables = props.routeTableIds;
            if (!Array.isArray(tables) || tables.length !== 1) bad("routeTableIds must be exactly the proxy's route table (never the VM table: squid stays the only way out)");
            else ref("routeTableIds[0]", "rt:proxy", tables[0]);
            policyIs(props.policy, (acct) => s3EndpointPolicy({ accountId: acct, transcriptsBucket: transcriptsBucketName(acct) }), false);
            break;
        }
        // S9: the transcripts bucket (the artifacts bucket, auto-named, stays S3's unchecked one) and its settings.
        case T.bucket:
            if (name !== TRANSCRIPTS_RESOURCE) break;
            only("bucket", "forceDestroy", "tags", "region");
            eq("forceDestroy", true);
            if (props.bucket !== UNKNOWN) {
                waits.push(within(ids.get("account"), wait).then((acct) => {
                    if (acct === undefined || props.bucket !== transcriptsBucketName(acct)) bad(`bucket must be ${acct === undefined ? "ai-env-transcripts-<the stack's account>" : transcriptsBucketName(acct)}, got ${show(props.bucket)}`);
                }));
            }
            break;
        case T.versioning: {
            only("bucket", "versioningConfiguration", "region");
            ref("bucket", "transcripts", props.bucket);
            const v = (props.versioningConfiguration ?? {}) as Props;
            if (v.status !== "Enabled" || isSet(v.mfaDelete)) bad(`versioningConfiguration must be exactly { status: "Enabled" }, got ${show(props.versioningConfiguration)}`);
            break;
        }
        case T.encryption: {
            only("bucket", "rules", "region");
            ref("bucket", "transcripts", props.bucket);
            const rules = props.rules;
            const rule = Array.isArray(rules) && rules.length === 1 ? (rules[0] as Props) : undefined;
            const sse = (rule?.applyServerSideEncryptionByDefault ?? {}) as Props;
            if (rule === undefined || sse.sseAlgorithm !== "AES256" || isSet(sse.kmsMasterKeyId) || rule.bucketKeyEnabled === true) bad(`rules must be exactly one SSE-S3 (AES256) rule, got ${show(rules)}`);
            break;
        }
        case T.ownership:
            only("bucket", "rule", "region");
            ref("bucket", "transcripts", props.bucket);
            if (((props.rule ?? {}) as Props).objectOwnership !== "BucketOwnerEnforced") bad(`rule must be { objectOwnership: "BucketOwnerEnforced" }, got ${show(props.rule)}`);
            break;
        case T.publicAccess:
            if (name !== TRANSCRIPTS_RESOURCE) break;
            only("bucket", "blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets", "region");
            ref("bucket", "transcripts", props.bucket);
            for (const k of ["blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets"]) eq(k, true);
            break;
        case T.lifecycle:
            only("bucket", "rules", "region");
            ref("bucket", "transcripts", props.bucket);
            if (canonicalPolicyText(props.rules ?? null) !== canonicalPolicyText(TRANSCRIPTS_LIFECYCLE)) bad(`rules must be exactly transcripts.ts TRANSCRIPTS_LIFECYCLE, got ${show(props.rules)}`);
            break;
        case T.bucketPolicy:
            only("bucket", "policy", "region");
            ref("bucket", "transcripts", props.bucket);
            policyIs(props.policy, (acct, endpoint) => transcriptsBucketPolicy({ accountId: acct, transcriptsBucket: transcriptsBucketName(acct), s3EndpointId: endpoint }), true);
            break;
        default:
            // In the inventory, but without checks here: S3's artifacts bucket and its public access block.
            break;
        }
        await Promise.all(waits);
        return problems;
    }

    const guard: pulumi.ResourceTransform = async (args) => {
        const problems = await check(args.type, args.name, args.custom, (await settle(args.props)) as Props, args.opts ?? {});
        if (problems.length > 0) throw new Error(`egress guard (infra/egress.ts) refused ${args.type} ${args.name}: ${problems.join("; ")}`);
        return undefined;
    };
    pulumi.runtime.registerResourceTransform(guard); // scratch:guard
    sealTransforms();

    return {
        track(key: IdKey, id: pulumi.Output<string>): void {
            // Resolves once the id is known (never for an unknown one: `within` bounds the wait).
            ids.set(key, new Promise((resolve) => {
                id.apply((v) => {
                    resolve(v);
                    return v;
                });
            }));
        },
    };
}

// ---- the resources ----

export interface EgressProviders {
    aws: aws.Provider;
    native: awsnative.Provider;
}

export interface Egress {
    vpc: aws.ec2.Vpc;
    vmSubnet: aws.ec2.Subnet;
    vmSecurityGroup: aws.ec2.SecurityGroup;
    proxySecurityGroup: aws.ec2.SecurityGroup;
    instance: aws.ec2.Instance;
    logGroup: aws.cloudwatch.LogGroup;
    parameters: Record<ProxyParameter, aws.ssm.Parameter>;
    proxyRole: aws.iam.Role;
    operatorRole: aws.iam.Role;
    connector: awsnative.lambda.NetworkConnector;
    /** S8 operators: the proxy's SSM Command documents by role (reload, status, patch). */
    documents: Record<DocumentRole, aws.ssm.Document>;
    /**
     * Lowercase hex SHA-256 of the exact `squid.conf` and `allow` values the program writes (`ai-env egress status`
     * compares the live ones); `allow`'s an Output since S9 (it carries the transcripts bucket's host, the account's).
     */
    squidConfSha256: string;
    allowSha256: pulumi.Output<string>;
    /** S9: the S3 gateway endpoint, its policy's JSON as written, and the proxy's route table it sits on. */
    s3Endpoint: aws.ec2.VpcEndpoint;
    s3EndpointPolicy: pulumi.Output<string>;
    proxyRouteTable: aws.ec2.RouteTable;
    /**
     * S13: the relay's security group and its rules, and what the relay instance (relay.ts) sits on and boots through:
     * the proxy subnet, its route table association and the VPC's DHCP options.
     */
    relaySecurityGroup: aws.ec2.SecurityGroup;
    relayRules: pulumi.Resource[];
    proxySubnet: aws.ec2.Subnet;
    proxyRouteAssociation: aws.ec2.RouteTableAssociation;
    dhcpAssociation: aws.ec2.VpcDhcpOptionsAssociation;
}

/** The initial value of a parameter `ai-env egress` owns (an SSM parameter cannot be empty; `#` lines are comments). */
const OWNED_INITIAL: Record<"extras" | "suspended", string> = {
    extras: "# ai-env egress extras: host<TAB>slug[,slug...] per line, written by `ai-env egress allow`\n",
    suspended: "# ai-env egress suspended hosts: one per line, written by `ai-env egress suspend`\n",
};
/**
 * Every input of an owned parameter but its tags. A change to any of them (a description, the tier, a provider
 * default) makes the provider PutParameter with Overwrite=true, the initial header over `ai-env egress`'s value:
 * every extra and every suspended host (T7.5's kill switch) gone. check-plan.ts refuses any step on them but create
 * and same. A renamed prefix therefore leaves these two at the old name: move them by hand.
 */
const OWNED_IGNORE = ["allowedPattern", "arn", "dataType", "description", "insecureValue", "keyId", "name", "overwrite", "region", "tier", "type", "value", "valueWo", "valueWoVersion"];

/**
 * The egress resources, every one with the Pulumi name the inventory lists. The scratch:* markers are edited by
 * `make preview-scratch NEGATIVE=dns-support-on-in-none-mode|miswired|dns-firewall-qtype|iam-widen|document-widen|
 * endpoint-on-vm-table|endpoint-policy-widen` in a scratch copy. `docs` are the proxy's documents as index.ts read and
 * asserted them (readProxyDocuments). `accountId` is the stack's account (S9: the transcripts bucket's name, the S3
 * endpoint's policy and the allow value are built from it alone, so a preview knows them).
 */
export function createEgress(
    spec: EgressSpec, guard: EgressGuard, names: pulumi.Output<Names>, accountId: pulumi.Output<string>, docs: ProxyDocuments, tags: Record<string, string>, providers: EgressProviders,
): Egress {
    const cfg = spec.cfg;
    const opts = { provider: providers.aws };
    const named = (name: string) => ({ ...tags, Name: name });
    const files = renderProxyFiles(cfg, REGION);

    // ---- network ----
    const vpc = new aws.ec2.Vpc(spec.vpc.name, {
        cidrBlock: spec.vpc.cidr,
        enableDnsSupport: spec.vpc.enableDnsSupport, // scratch:dns
        enableDnsHostnames: spec.vpc.enableDnsHostnames,
        tags: named(spec.vpc.name),
    }, opts);
    guard.track("vpc", vpc.id);
    const dhcp = new aws.ec2.VpcDhcpOptions(spec.dhcp.name, { domainNameServers: spec.dhcp.domainNameServers, tags: named(spec.dhcp.name) }, opts);
    guard.track("dhcp", dhcp.id);
    const dhcpAssociation = new aws.ec2.VpcDhcpOptionsAssociation(spec.dhcp.name, { vpcId: vpc.id, dhcpOptionsId: dhcp.id }, opts);
    const igw = new aws.ec2.InternetGateway(spec.igw.name, { vpcId: vpc.id, tags: named(spec.igw.name) }, opts);
    guard.track("igw", igw.id);

    const subnet = (t: "proxy" | "vms") => {
        const s = spec.subnets[t];
        const r = new aws.ec2.Subnet(s.name, { vpcId: vpc.id, cidrBlock: s.cidr, availabilityZoneId: cfg.azId, mapPublicIpOnLaunch: false, tags: named(s.name) }, opts);
        guard.track(`subnet:${t}`, r.id);
        return r;
    };
    const proxySubnet = subnet("proxy");
    const vmSubnet = subnet("vms");
    // Inline, explicit route lists. `pulumi up` does not refresh, so a route (or NACL entry, or default-SG rule) added
    // out of band persists and no preview shows it, the plan check's included (it sees the program's inputs only).
    // The drift check is `ai-env egress status`, which `make deploy` runs at the end.
    // The association, and the route table itself (S9: the S3 gateway endpoint sits on the proxy's).
    const table = (t: "proxy" | "vms", s: aws.ec2.Subnet) => {
        const rt = spec.routeTables[t];
        const r = new aws.ec2.RouteTable(rt.name, { vpcId: vpc.id, routes: rt.routes.map((x) => ({ cidrBlock: x.cidr, gatewayId: igw.id })), tags: named(rt.name) }, opts);
        guard.track(`rt:${t}`, r.id);
        return { table: r, association: new aws.ec2.RouteTableAssociation(rt.name, { subnetId: s.id, routeTableId: r.id }, opts) };
    };
    const [proxyRoutes, vmRoutes] = [table("proxy", proxySubnet), table("vms", vmSubnet)]; // scratch:assoc

    // S9: the S3 gateway endpoint, on the proxy's route table only. The proxy reaches S3 through it from now on (its
    // dnf, the AL2023 repositories its policy allows); the VMs reach S3 only through squid, which serves our bucket's
    // virtual-hosted name alone, and the endpoint's policy admits nothing but the runtime user's `v1/*` of that bucket.
    const s3EndpointPolicyJson = accountId.apply((acct) => JSON.stringify(s3EndpointPolicy({ accountId: acct, transcriptsBucket: transcriptsBucketName(acct) })));
    const s3Endpoint = new aws.ec2.VpcEndpoint(NET.s3Endpoint, {
        vpcId: vpc.id,
        serviceName: S3_ENDPOINT_SERVICE,
        vpcEndpointType: "Gateway",
        routeTableIds: [proxyRoutes.table.id], // scratch:endpoint-table
        policy: s3EndpointPolicyJson, // scratch:endpoint-policy
        tags: named(NET.s3Endpoint),
    }, opts);
    guard.track("s3-endpoint", s3Endpoint.id);

    // The VM subnet's own network ACL: a second, stateless layer under the VM security group.
    const naclRule = (r: NaclRuleSpec) => ({ ruleNo: r.ruleNo, protocol: r.protocol, action: r.action, cidrBlock: r.cidr, fromPort: r.fromPort, toPort: r.toPort });
    const nacl = new aws.ec2.NetworkAcl(spec.nacl.name, {
        vpcId: vpc.id, ingress: spec.nacl.ingress.map(naclRule), egress: spec.nacl.egress.map(naclRule), tags: named(spec.nacl.name),
    }, opts);
    guard.track("nacl", nacl.id);
    const naclAssociation = new aws.ec2.NetworkAclAssociation(spec.nacl.name, { networkAclId: nacl.id, subnetId: vmSubnet.id }, opts);

    // The VPC's default security group, emptied: nothing in the VPC can fall back on it.
    new aws.ec2.DefaultSecurityGroup(spec.defaultSecurityGroup.name, { vpcId: vpc.id, ingress: [], egress: [], tags: named(spec.defaultSecurityGroup.name) }, opts);
    const securityGroup = (k: SgKey) => {
        const s = spec.securityGroups[k];
        const r = new aws.ec2.SecurityGroup(s.name, { name: s.name, description: s.description, vpcId: vpc.id, tags: named(s.name) }, opts);
        guard.track(`sg:${k}`, r.id);
        return r;
    };
    const sgs = {} as Record<SgKey, aws.ec2.SecurityGroup>;
    for (const k of SG_KEYS) sgs[k] = securityGroup(k);
    const rules: Record<SgKey, pulumi.Resource[]> = { vm: [], proxy: [], relay: [] };
    for (const k of SG_KEYS) {
        for (const rule of spec.securityGroups[k].rules) {
            const name = ruleName(spec, k, rule);
            const args = {
                securityGroupId: sgs[k].id, ipProtocol: rule.protocol, fromPort: rule.port, toPort: rule.port, description: rule.description, // scratch:rule-sg
                ...("sg" in rule.peer ? { referencedSecurityGroupId: sgs[rule.peer.sg].id } : { cidrIpv4: rule.peer.cidr }), // scratch:rule-peer
                tags: named(name),
            };
            rules[k].push(rule.direction === "ingress" ? new aws.vpc.SecurityGroupIngressRule(name, args, opts) : new aws.vpc.SecurityGroupEgressRule(name, args, opts));
        }
    }

    // ---- the proxy: log group, parameters, role, profile, instance ----
    const logGroup = new aws.cloudwatch.LogGroup(NET.logGroup, { name: cfg.logGroup, retentionInDays: cfg.logRetentionDays, tags }, opts);
    // S9: allow.txt plus the transcripts bucket's host (egress-spec.ts allowValue), from the account: a preview knows it.
    const allow = accountId.apply((acct) => {
        const v = allowValue(files.allow, transcriptsBucketName(acct));
        const bytes = Buffer.byteLength(v, "utf-8");
        if (bytes > PARAMETER_MAX_BYTES) throw new Error(`the allow parameter (infra/proxy/allow.txt and the transcripts bucket's host) is ${bytes} bytes, over the ${PARAMETER_MAX_BYTES}-byte standard parameter`);
        return v;
    });
    const values: Record<ProxyParameter, pulumi.Input<string>> = { "squid.conf": files.squidConf, allow, ...OWNED_INITIAL };
    const parameters = {} as Record<ProxyParameter, aws.ssm.Parameter>;
    for (const p of PROXY_PARAMETERS) {
        const owned = p === "extras" || p === "suspended";
        parameters[p] = new aws.ssm.Parameter(`ai-env-proxy-${p}`, {
            name: `${cfg.parameterPrefix}/${p}`, type: "String", tier: "Standard", dataType: "text", insecureValue: values[p],
            description: owned ? `ai-env egress proxy ${p} (owned by ai-env egress after creation)` : `ai-env egress proxy ${p} (from infra/proxy)`, tags,
        }, { ...opts, ignoreChanges: owned ? OWNED_IGNORE : [] });
    }

    // S8 operators: the proxy's documents, the only commands ai-env-ops (and the deployer) may send it. The content is
    // the file's canonical JSON; never permissions (a shared document), versionName or attachments.
    const documents = {} as Record<DocumentRole, aws.ssm.Document>;
    for (const role of DOCUMENT_ROLES) {
        const name = documentNames(cfg)[role];
        documents[role] = new aws.ssm.Document(name, {
            name, documentType: "Command", documentFormat: "JSON", targetType: "/AWS::EC2::Instance", content: docs[role], tags, // scratch:document
        }, opts);
    }

    const proxyRole = new aws.iam.Role(cfg.proxyRoleName, {
        name: cfg.proxyRoleName, description: "ai-env egress proxy: SSM agent, its own parameters, the squid log group", assumeRolePolicy: JSON.stringify(proxyTrustPolicy()), tags,
    }, opts);
    const proxySsm = new aws.iam.RolePolicyAttachment(`${cfg.proxyRoleName}-ssm`, { role: proxyRole.name, policyArn: SSM_INSTANCE_POLICY_ARN }, opts);
    const proxyPolicy = new aws.iam.RolePolicy(cfg.proxyRoleName, { name: cfg.proxyRoleName, role: proxyRole.id, policy: names.apply((n) => JSON.stringify(proxyRolePolicy(n))) }, opts);
    const profile = new aws.iam.InstanceProfile(cfg.proxyInstanceProfileName, { name: cfg.proxyInstanceProfileName, role: proxyRole.name, tags }, opts);

    const ami = aws.ssm.getParameterOutput({ name: AMI_PARAMETER }, opts).insecureValue;
    const instance = new aws.ec2.Instance(NET.instance, {
        ami,
        instanceType: cfg.instanceType,
        subnetId: proxySubnet.id,
        privateIp: cfg.proxyIp,
        associatePublicIpAddress: true,
        vpcSecurityGroupIds: [sgs.proxy.id],
        iamInstanceProfile: profile.name,
        metadataOptions: { httpEndpoint: "enabled", httpTokens: "required", httpPutResponseHopLimit: 1, instanceMetadataTags: "disabled" },
        rootBlockDevice: { volumeType: "gp3", volumeSize: 8, encrypted: true, deleteOnTermination: true },
        creditSpecification: { cpuCredits: "standard" },
        userData: files.userData,
        userDataReplaceOnChange: true,
        tags: named(NET.instance),
        volumeTags: named(NET.instance),
    }, {
        ...opts,
        // A newer AMI is picked up by `make proxy-patch` / a deliberate replacement, never by a routine deploy.
        ignoreChanges: ["ami"],
        // The fixed private IP cannot be held by two instances.
        deleteBeforeReplace: true,
        // Boot fetches packages (route), the parameters and ships logs: all of it must exist first.
        dependsOn: [proxyRoutes.association, dhcpAssociation, ...rules.proxy, logGroup, ...Object.values(parameters), proxyPolicy, proxySsm],
    });

    // ---- the connector and its operator role ----
    // The managed operator policy lets the role create ENIs in any subnet with any security group; its inline Deny
    // (policies.ts operatorRolePolicy: ec2:CreateNetworkInterface outside [the VM subnet, the VM SG,
    // network-interface/*]) confines them to the VM subnet and the VM security group. A RolePolicy of its own: the
    // guard and the plan check refuse inline policies on a role.
    const operatorRole = new aws.iam.Role(cfg.operatorRoleName, {
        name: cfg.operatorRoleName, description: "Lambda network connector ai-env-egress: creates and tags its ENIs in the VM subnet", assumeRolePolicy: JSON.stringify(operatorTrustPolicy()), tags, // scratch:operator-role
    }, opts);
    const operatorPolicy = new aws.iam.RolePolicyAttachment(cfg.operatorRoleName, { role: operatorRole.name, policyArn: CONNECTOR_OPERATOR_POLICY_ARN }, opts);
    const operatorDeny = new aws.iam.RolePolicy(cfg.operatorRoleName, {
        name: cfg.operatorRoleName, role: operatorRole.id,
        policy: pulumi.all([names, vmSubnet.id, sgs.vm.id]).apply(([n, vmSubnetId, vmSecurityGroupId]) => JSON.stringify(operatorRolePolicy({ ...n, egress: { ...n.egress, vmSubnetId, vmSecurityGroupId } }))), // scratch:operator-deny
    }, opts);
    // Only on real updates: a preview never waits (and never has a known ARN for a new role anyway). The Deny is not
    // among these inputs (the connector depends on it instead): with it, the preview of the deploy that adds the Deny
    // would show the connector's operatorRole unknown, which the plan check refuses, and the connector as changed.
    const operatorRoleArn = pulumi.all([operatorRole.arn, operatorPolicy.id]).apply(async ([arn]) => {
        if (!pulumi.runtime.isDryRun()) await new Promise((resolve) => setTimeout(resolve, CONNECTOR_IAM_PROPAGATION_MS));
        return arn;
    });

    // dnsMode "firewall": the VPC resolver answers nothing (the proxy uses the DHCP resolvers, never it).
    const dnsFirewall: pulumi.Resource[] = [];
    if (cfg.dnsMode === "firewall") {
        const list = new aws.route53.ResolverFirewallDomainList(NET.firewall, { name: NET.firewall, domains: ["*"], tags }, opts);
        guard.track("fw-list", list.id);
        const group = new aws.route53.ResolverFirewallRuleGroup(NET.firewall, { name: NET.firewall, tags }, opts);
        guard.track("fw-group", group.id);
        const rule = new aws.route53.ResolverFirewallRule(NET.firewall, {
            name: NET.firewall, action: "BLOCK", blockResponse: FIREWALL_BLOCK_RESPONSE, firewallDomainRedirectionAction: FIREWALL_REDIRECTION, // scratch:fw-rule
            firewallDomainListId: list.id, firewallRuleGroupId: group.id, priority: FIREWALL_RULE_PRIORITY,
        }, opts);
        dnsFirewall.push(new aws.route53.ResolverFirewallRuleGroupAssociation(NET.firewall, {
            name: NET.firewall, firewallRuleGroupId: group.id, vpcId: vpc.id, priority: FIREWALL_ASSOCIATION_PRIORITY, mutationProtection: "DISABLED", tags,
        }, { ...opts, dependsOn: [rule] }));
        dnsFirewall.push(new aws.route53.ResolverFirewallConfig(NET.vpc, { resourceId: vpc.id, firewallFailOpen: "DISABLED" }, opts));
        if (cfg.enableDnsQueryLog) {
            const dnsLog = new aws.cloudwatch.LogGroup(NET.dnsLogGroup, { name: dnsQueryLogGroup(cfg), retentionInDays: cfg.logRetentionDays, tags }, opts);
            const queryLog = new aws.route53.ResolverQueryLogConfig(NET.queryLog, { name: NET.queryLog, destinationArn: dnsLog.arn, tags }, opts);
            guard.track("query-log", queryLog.id);
            dnsFirewall.push(new aws.route53.ResolverQueryLogConfigAssociation(NET.queryLog, { resolverQueryLogConfigId: queryLog.id, resourceId: vpc.id }, opts));
        }
    }

    const connector = new awsnative.lambda.NetworkConnector(cfg.connectorName, {
        name: cfg.connectorName,
        configuration: {
            vpcEgressConfiguration: {
                subnetIds: [vmSubnet.id],
                securityGroupIds: [sgs.vm.id],
                networkProtocol: "IPv4",
                associatedComputeResourceTypes: ["MicroVm"],
            },
        },
        operatorRole: operatorRoleArn,
        tags: Object.entries(tags).map(([key, value]) => ({ key, value })),
    }, {
        provider: providers.native,
        deleteBeforeReplace: true,
        // The ENIs come up in a subnet that already has its route table, NACL, rule and DNS settings, and through an
        // operator role whose Deny exists.
        dependsOn: [vmRoutes.association, naclAssociation, dhcpAssociation, ...rules.vm, ...dnsFirewall, operatorDeny],
    });

    const sha256 = (value: string) => crypto.createHash("sha256").update(value, "utf-8").digest("hex");
    return {
        vpc, vmSubnet, vmSecurityGroup: sgs.vm, proxySecurityGroup: sgs.proxy, instance, logGroup, parameters, proxyRole, operatorRole, connector, documents,
        squidConfSha256: sha256(files.squidConf), allowSha256: allow.apply(sha256), s3Endpoint, s3EndpointPolicy: s3EndpointPolicyJson, proxyRouteTable: proxyRoutes.table,
        relaySecurityGroup: sgs.relay, relayRules: rules.relay, proxySubnet, proxyRouteAssociation: proxyRoutes.association, dhcpAssociation,
    };
}
