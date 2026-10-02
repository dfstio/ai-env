// The final word on the stack's plan (plans/s5-plan.md "W1 review, design changes"): the planned resources and
// their planned inputs, after every transform and the providers' Check, as `pulumi preview --json` reports them.
//
//   pulumi preview --json --show-sames --show-reads --stack <stack> | infra/scripts/check-plan.sh --mode none|firewall --account-id <12 digits>
//       (--show-sames: a plan of an existing stack lists its unchanged resources only with it, and the inventory is
//       counted over all of them; a plan without them fails closed, "missing from the plan")
//       (check-plan.sh compiles this file alone, like print-policies.ts, and passes --egress-config and
//       --image-config of its infra/ unless given again)
//
// Why: the resource transform (egress.ts guardEgress) runs inside the program, the engine does not order stack
// transforms, and a preview of new resources cannot compare ids. This check sees what the engine will create: every
// resource of the plan must be one of the stack inventory (egress-spec.ts stackInventory), by type and name, with
// exact counts; each egress resource's inputs must satisfy the spec's predicates; every reference is checked by
// URN (property dependencies) and, where the ids are known (a resource the plan keeps: its oldState id), by value;
// every IAM document (trust, inline, user and
// managed policy) must be the policies.ts function's output for that resource, for the account given (the caller
// reads it from `aws sts get-caller-identity`; it is only ever an argument); the parameters `ai-env egress` owns
// may only be created, never updated or replaced (that would reset them). It runs in `make preview-scratch` and in
// `make deploy` over the real stack's preview before `pulumi up`. The plan carries the account id: it is read from
// stdin only and never written anywhere; the report names resources and inputs, never documents. A --json plan has
// no stack outputs: `make preview-scratch` checks those over the text preview.
//
// Exit: 0 the plan matches; 1 it does not (each violation on stderr); 2 bad arguments or not a JSON plan.
import * as fs from "fs";
import {
    DNS_MODES, egressNames, FIREWALL_ASSOCIATION_PRIORITY, FIREWALL_BLOCK_RESPONSE, FIREWALL_REDIRECTION, FIREWALL_RULE_PRIORITY, NET, NaclRuleSpec, PARAMETER_MAX_BYTES, PROVIDERS,
    PROVIDER_INPUTS, PROXY_PARAMETERS, PROXY_SG_DESCRIPTION, RouteSpec, RuleSpec, VM_SG_DESCRIPTION, assertEgressSpec, checkNacl, checkRoutes, checkRule,
    checkVpcDns, dnsQueryLogGroup, egressSpec, loadEgressConfig, ruleOwner, stackInventory,
} from "../egress-spec";
import {
    BUILD_ROLE_NAME, CONNECTOR_OPERATOR_POLICY_ARN, DEPLOY_DNS_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME, DEPLOY_POLICY_NAME, EXECUTION_ROLE_NAME, Names,
    PolicyDocument, REGION, RUNTIME_POLICY_NAME, RUNTIME_USER_NAME, SSM_INSTANCE_POLICY_ARN, buildRolePolicy, deployDnsPolicy, deployEgressPolicy, deployPolicy, roleArn,
    executionRolePolicy, lambdaTrustPolicy, operatorTrustPolicy, proxyRolePolicy, proxyTrustPolicy, runtimePolicy,
} from "../policies";

/** The budget's services, written out again (not imported from budget.ts): an edit there must show up here. */
const BUDGET_SERVICES = ["AWS Lambda", "Amazon Elastic Compute Cloud - Compute", "EC2 - Other", "Amazon Virtual Private Cloud", "AmazonCloudWatch", "Amazon Route 53"];
/** How a preview spells a value it does not know yet. */
const UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9";
/** Steps whose resource is gone after the update; every other step's new state is part of the stack. */
const GONE = new Set(["delete", "delete-replaced", "discard", "discard-replaced", "read-discard", "remove-pending-replace"]);
const STACK_TYPE = "pulumi:pulumi:Stack";

function usage(msg: string): never {
    process.stderr.write(`check-plan: ${msg}\nusage: pulumi preview --json --show-sames --show-reads | check-plan --mode none|firewall --account-id <12 digits> --egress-config <file> --image-config <file>\n`);
    process.exit(2);
}

const args = new Map<string, string>();
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (!k.startsWith("--") || v === undefined) usage(`bad argument ${k}`);
    args.set(k.slice(2), v);
}
const mode = args.get("mode") ?? usage("--mode is required (none or firewall)");
if (!(DNS_MODES as readonly string[]).includes(mode)) usage(`--mode must be one of ${DNS_MODES.join(", ")}`);
const accountId = args.get("account-id") ?? usage("--account-id is required (aws sts get-caller-identity --query Account)");
if (!/^[0-9]{12}$/.test(accountId)) usage("--account-id must be 12 digits");
const cfg = loadEgressConfig(args.get("egress-config") ?? usage("--egress-config is required"));
const imageFile = args.get("image-config") ?? usage("--image-config is required");
const imageRaw = JSON.parse(fs.readFileSync(imageFile, "utf-8"));
const image = { imageName: String(imageRaw.imageName), logGroup: String(imageRaw.logGroup) };

let plan: { steps?: Step[]; diagnostics?: { severity?: string; message?: string }[] };
try {
    plan = JSON.parse(fs.readFileSync(0, "utf-8"));
} catch (e) {
    usage(`stdin is not a pulumi preview --json plan (${(e as Error).message})`);
}

interface State {
    urn: string;
    type: string;
    custom?: boolean;
    id?: string;
    parent?: string;
    provider?: string;
    protect?: boolean;
    inputs?: Record<string, unknown>;
    propertyDependencies?: Record<string, string[]>;
}
interface Step {
    op: string;
    urn: string;
    newState?: State;
    oldState?: State;
}
interface Res {
    op: string;
    urn: string;
    type: string;
    name: string;
    custom: boolean;
    id: string;
    parent: string;
    provider: string;
    protect: boolean;
    i: Record<string, unknown>;
    deps: Record<string, string[]>;
}

const problems: string[] = [];
const bad = (m: string) => problems.push(m);
const json = (v: unknown) => JSON.stringify(v);
const known = (v: unknown): v is string => typeof v === "string" && v !== "" && v !== UNKNOWN;
const set = (v: unknown) => v !== undefined && v !== null && v !== "" && v !== false && v !== 0;
/** The inputs a program or a transform set: the bridge's `__defaults` list and an empty engine `__internal` are Pulumi's own. */
const userKeys = (o: Record<string, unknown>) => Object.keys(o).filter((k) => k !== "__defaults" && !(k.startsWith("__") && json(o[k]) === "{}") && set(o[k]));

if (cfg.dnsMode !== mode) bad(`--mode ${mode}, but ${args.get("egress-config")} says dnsMode ${cfg.dnsMode}`);
try {
    assertEgressSpec(egressSpec(cfg));
} catch (e) {
    bad((e as Error).message);
}
for (const d of plan.diagnostics ?? []) if (d.severity === "error") bad(`the preview reported an error: ${String(d.message).trim().split("\n")[0]}`);

// ---- the planned resources (the new state of every step that keeps or makes a resource) ----
const byUrn = new Map<string, Res>();
/** The parameters `ai-env egress` owns: any step but create (the first deploy) and same would put the initial header back. */
const OWNED = new Map([
    ["ai-env-proxy-extras", "every extra `ai-env egress allow` added"],
    ["ai-env-proxy-suspended", "every host `ai-env egress suspend` holds (the T7.5 kill switch)"],
]);
for (const s of plan.steps ?? []) {
    const owned = OWNED.get(s.urn.split("::").pop() ?? "");
    if (owned !== undefined && s.urn.includes("::aws:ssm/parameter:Parameter::") && s.op !== "create" && s.op !== "same") {
        bad(`aws:ssm/parameter:Parameter ${s.urn.split("::").pop()}: a ${s.op} step would reset the parameter to its initial header, wiping ${owned}; only create (first deploy) and same are allowed`);
    }
    if (GONE.has(s.op)) continue;
    const st = s.newState ?? s.oldState;
    if (st === undefined) { bad(`step ${s.op} ${s.urn} has no state`); continue; }
    // A preview's newState carries no id on any step (measured with pulumi 3.266, 1 Oct 2026): a resource the step
    // keeps (same, update) has its id in oldState only; a replaced or created one has none yet.
    const id = st.id || (s.op === "same" || s.op === "update" ? s.oldState?.id : undefined) || "";
    byUrn.set(st.urn, {
        op: s.op, urn: st.urn, type: st.type, name: st.urn.split("::").pop() ?? "", custom: st.custom !== false, id, parent: st.parent ?? "",
        provider: st.provider ?? "", protect: st.protect === true, i: st.inputs ?? {}, deps: st.propertyDependencies ?? {},
    });
}
const all = [...byUrn.values()];
const stacks = all.filter((r) => r.type === STACK_TYPE);
if (stacks.length !== 1) bad(`${stacks.length} ${STACK_TYPE} resources, expected 1`);
const stackUrn = stacks[0]?.urn ?? "";

// ---- inventory: every type and name exactly ----
const inventory = stackInventory(cfg, image);
const found = new Map<string, Res[]>();
for (const r of all) if (r.type !== STACK_TYPE) found.set(r.type, [...(found.get(r.type) ?? []), r]);
const types = [...new Set([...inventory.keys(), ...found.keys()])].sort();
let expectedTotal = 1;
console.log("planned resources per type:");
for (const t of types) {
    const want = (inventory.get(t) ?? []).slice().sort();
    const got = (found.get(t) ?? []).map((r) => r.name).sort();
    expectedTotal += want.length;
    console.log(`  ${String(got.length).padStart(3)}  ${t}${got.length !== want.length ? `   <- expected ${want.length}` : ""}`);
    const extra = got.filter((n) => !want.includes(n));
    const missing = want.filter((n) => !got.includes(n));
    if (extra.length > 0) bad(`${t}: not in the stack inventory: ${extra.join(", ")}`);
    if (missing.length > 0) bad(`${t}: missing from the plan: ${missing.join(", ")} (an existing stack's unchanged resources need pulumi preview --json --show-sames)`);
}
console.log(`  ${String(all.length).padStart(3)}  resources in total, the stack included (expected ${expectedTotal})`);
if (all.length !== expectedTotal) bad(`${all.length} resources, expected ${expectedTotal}`);

// ---- every resource: a child of the stack, the pinned provider of its package, unprotected, in the region ----
const providerUrn = (name: string) => all.find((r) => r.type.startsWith("pulumi:providers:") && r.name === name)?.urn;
// A Map, never an object literal: a package named like an Object.prototype key must not find anything.
const pinned = new Map([["aws", providerUrn(PROVIDERS.aws)], ["aws-native", providerUrn(PROVIDERS.awsNative)]]);
for (const r of all) {
    if (r.type === STACK_TYPE) continue;
    if (!r.custom) bad(`${r.type} ${r.name}: a component resource (the stack has none)`);
    if (r.parent !== stackUrn) bad(`${r.type} ${r.name}: its parent is ${r.parent || "none"}, not the stack`);
    if (r.protect) bad(`${r.type} ${r.name}: protected (no Pulumi protect anywhere: make destroy must work)`);
    if (r.i.region !== undefined && r.i.region !== REGION) bad(`${r.type} ${r.name}: region ${json(r.i.region)}, not ${REGION}`);
    if (r.type.startsWith("pulumi:providers:")) {
        for (const k of userKeys(r.i)) if (!PROVIDER_INPUTS.includes(k)) bad(`provider ${r.name}: input ${k} is outside the allowlist (${json(r.i[k]).slice(0, 200)})`);
        if (r.i.region !== REGION) bad(`provider ${r.name}: region ${json(r.i.region)}, not ${REGION}`);
        continue;
    }
    const pkg = r.type.split(":")[0];
    const want = pinned.get(pkg);
    if (want === undefined || !r.provider.startsWith(`${want}::`)) bad(`${r.type} ${r.name}: provider ${r.provider.split("::").slice(0, -1).join("::") || "none"}, not ${want ?? `the pinned ${pkg} provider`}`);
}

// ---- helpers over the egress resources ----
const EMPTY: Res = { op: "", urn: "(missing)", type: "", name: "", custom: true, id: "", parent: "", provider: "", protect: false, i: {}, deps: {} };
const one = (type: string, name: string): Res => (found.get(type) ?? []).find((r) => r.name === name) ?? EMPTY;
const eq = (what: string, got: unknown, want: unknown) => { if (json(got) !== json(want)) bad(`${what}: ${json(got)}, expected ${json(want)}`); };
const present = (r: Res, k: string) => { if (r.i[k] === undefined || r.i[k] === null || r.i[k] === "") bad(`${r.type} ${r.name}: input ${k} missing`); };
const absent = (r: Res, keys: string[]) => { for (const k of keys) if (set(r.i[k])) bad(`${r.type} ${r.name}: input ${k} must be unset, got ${json(r.i[k])}`); };
/** `prop` depends on exactly these resources (by URN), and, where both are known, its value is their id (not for an ARN). */
const ref = (r: Res, prop: string, targets: Res[], byValue = true) => {
    const deps = (r.deps[prop] ?? []).slice().sort();
    const want = targets.map((t) => t.urn).sort();
    if (json(deps) !== json(want)) bad(`${r.type} ${r.name}: ${prop} depends on ${deps.length > 0 ? deps.map((u) => u.split("::").slice(-2).join("::")).join(", ") : "nothing"}, expected ${want.map((u) => u.split("::").slice(-2).join("::")).join(", ")}`);
    const v = r.i[prop];
    const values = Array.isArray(v) ? v : [v];
    if (byValue && targets.length === 1 && known(targets[0].id)) {
        for (const x of values) if (known(x) && x !== targets[0].id) bad(`${r.type} ${r.name}: ${prop} ${x} is not ${targets[0].type} ${targets[0].name} (${targets[0].id})`);
    }
};

const T = {
    vpc: "aws:ec2/vpc:Vpc", dhcp: "aws:ec2/vpcDhcpOptions:VpcDhcpOptions", dhcpAssoc: "aws:ec2/vpcDhcpOptionsAssociation:VpcDhcpOptionsAssociation",
    igw: "aws:ec2/internetGateway:InternetGateway", subnet: "aws:ec2/subnet:Subnet", rt: "aws:ec2/routeTable:RouteTable",
    rta: "aws:ec2/routeTableAssociation:RouteTableAssociation", nacl: "aws:ec2/networkAcl:NetworkAcl", naclAssoc: "aws:ec2/networkAclAssociation:NetworkAclAssociation",
    defaultSg: "aws:ec2/defaultSecurityGroup:DefaultSecurityGroup", sg: "aws:ec2/securityGroup:SecurityGroup",
    ingress: "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", egress: "aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule",
    instance: "aws:ec2/instance:Instance", profile: "aws:iam/instanceProfile:InstanceProfile", role: "aws:iam/role:Role", rolePolicy: "aws:iam/rolePolicy:RolePolicy",
    attachment: "aws:iam/rolePolicyAttachment:RolePolicyAttachment", parameter: "aws:ssm/parameter:Parameter", logGroup: "aws:cloudwatch/logGroup:LogGroup",
    connector: "aws-native:lambda:NetworkConnector", budget: "aws:budgets/budget:Budget",
    fwList: "aws:route53/resolverFirewallDomainList:ResolverFirewallDomainList", fwGroup: "aws:route53/resolverFirewallRuleGroup:ResolverFirewallRuleGroup",
    fwRule: "aws:route53/resolverFirewallRule:ResolverFirewallRule", fwAssoc: "aws:route53/resolverFirewallRuleGroupAssociation:ResolverFirewallRuleGroupAssociation",
    fwConfig: "aws:route53/resolverFirewallConfig:ResolverFirewallConfig", queryLog: "aws:route53/resolverQueryLogConfig:ResolverQueryLogConfig",
    queryLogAssoc: "aws:route53/resolverQueryLogConfigAssociation:ResolverQueryLogConfigAssociation",
};

// ---- IAM: role-level policy inputs refused, every document exactly the policies.ts function's output ----
const CREATING = new Set(["create", "replace", "create-replacement"]);
const known_ = (v: unknown) => v !== undefined && v !== null && v !== UNKNOWN;
const canon = (v: unknown): unknown => Array.isArray(v) ? v.map(canon)
    : v !== null && typeof v === "object" ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])])) : v;
const bucketRes = (found.get("aws:s3/bucket:Bucket") ?? [])[0] ?? EMPTY;
const bucketName = [bucketRes.i.bucket, bucketRes.id].find((v) => known(v));
const idOf = (r: Res) => (known(r.id) ? r.id : undefined);
const names: Names = {
    accountId, region: REGION, bucket: typeof bucketName === "string" ? bucketName : `${UNKNOWN}`, imageName: image.imageName, logGroup: image.logGroup,
    egress: {
        ...egressNames(cfg),
        vmSubnetId: idOf((found.get("aws:ec2/subnet:Subnet") ?? []).find((r) => r.name === NET.vms) ?? EMPTY) ?? UNKNOWN,
        vmSecurityGroupId: idOf((found.get("aws:ec2/securityGroup:SecurityGroup") ?? []).find((r) => r.name === cfg.vmSecurityGroupName) ?? EMPTY) ?? UNKNOWN,
    },
};
/**
 * `prop` of `r` is the document `fn` builds. An unknown value is accepted only while the resource, or a resource the
 * value depends on, is being created (a new role's ARN, the first deploy's VM subnet id); anywhere else it is refused.
 */
const iamDoc = (r: Res, prop: string, fn: string, want: () => PolicyDocument) => {
    const v = r.i[prop];
    if (r === EMPTY) return;
    if (!known_(v)) {
        const creating = CREATING.has(r.op) || (r.deps[prop] ?? []).some((u) => CREATING.has(byUrn.get(u)?.op ?? ""));
        if (!creating) bad(`${r.type} ${r.name}: ${prop} is unknown on a ${r.op} step whose inputs all exist: cannot prove it is ${fn}()`);
        return;
    }
    let got: { Statement?: { Sid?: string }[] };
    try {
        got = typeof v === "string" ? JSON.parse(v) : (v as typeof got);
    } catch {
        bad(`${r.type} ${r.name}: ${prop} is not JSON`);
        return;
    }
    const expected = want();
    if (json(canon(got)) === json(canon(expected))) return;
    const sids = (d: { Statement?: { Sid?: string }[] }) => (d.Statement ?? []).map((st) => st.Sid ?? "(no Sid)");
    const extra = sids(got).filter((x) => !sids(expected).includes(x));
    const gone = sids(expected).filter((x) => !sids(got).includes(x));
    bad(`${r.type} ${r.name}: ${prop} is not policies.ts ${fn}()${extra.length > 0 ? `; extra statements ${extra.join(", ")}` : ""}${gone.length > 0 ? `; missing ${gone.join(", ")}` : ""}${extra.length + gone.length === 0 ? "; a statement differs" : ""}`);
};
const roles = new Map<string, () => PolicyDocument>([
    [BUILD_ROLE_NAME, lambdaTrustPolicy], [EXECUTION_ROLE_NAME, lambdaTrustPolicy], [cfg.proxyRoleName, proxyTrustPolicy], [cfg.operatorRoleName, operatorTrustPolicy],
]);
for (const r of found.get("aws:iam/role:Role") ?? []) {
    for (const k of ["managedPolicyArns", "inlinePolicies", "permissionsBoundary"]) {
        if (r.i[k] !== undefined && r.i[k] !== null) bad(`aws:iam/role:Role ${r.name}: ${k} must be unset (grants come only from the policies.ts documents), got ${json(r.i[k]).slice(0, 200)}`);
    }
    const trustFn = roles.get(r.name);
    if (trustFn !== undefined) iamDoc(r, "assumeRolePolicy", trustFn.name, trustFn);
}
const roleRes = (n: string) => (found.get("aws:iam/role:Role") ?? []).find((r) => r.name === n) ?? EMPTY;
const inline = new Map<string, [string, (n: Names) => PolicyDocument]>([
    [BUILD_ROLE_NAME, [BUILD_ROLE_NAME, buildRolePolicy]], [EXECUTION_ROLE_NAME, [EXECUTION_ROLE_NAME, executionRolePolicy]], [cfg.proxyRoleName, [cfg.proxyRoleName, proxyRolePolicy]],
]);
for (const r of found.get("aws:iam/rolePolicy:RolePolicy") ?? []) {
    const entry = inline.get(r.name);
    if (entry === undefined) continue;
    ref(r, "role", [roleRes(entry[0])]);
    iamDoc(r, "policy", entry[1].name, () => entry[1](names));
}
for (const r of found.get("aws:iam/userPolicy:UserPolicy") ?? []) {
    if (r.name !== RUNTIME_POLICY_NAME) continue;
    ref(r, "user", [(found.get("aws:iam/user:User") ?? []).find((u) => u.name === RUNTIME_USER_NAME) ?? EMPTY]);
    iamDoc(r, "policy", "runtimePolicy", () => runtimePolicy(names));
}
const managed = new Map<string, (n: Names) => PolicyDocument>([[DEPLOY_POLICY_NAME, deployPolicy], [DEPLOY_EGRESS_POLICY_NAME, deployEgressPolicy], [DEPLOY_DNS_POLICY_NAME, deployDnsPolicy]]);
for (const r of found.get("aws:iam/policy:Policy") ?? []) {
    const fn = managed.get(r.name);
    if (fn !== undefined) iamDoc(r, "policy", fn.name, () => fn(names));
}

// ---- the budget ----
const budget = (found.get(T.budget) ?? [])[0] ?? EMPTY;
const filters = (budget.i.costFilters ?? []) as { name?: string; values?: string[] }[];
eq("budget cost filters", filters.map((f) => f.name), ["Service", "Region"]);
eq("budget Service values", (filters.find((f) => f.name === "Service") ?? {}).values, BUDGET_SERVICES);
eq("budget Region values", (filters.find((f) => f.name === "Region") ?? {}).values, [REGION]);

// ---- the network ----
const vpc = one(T.vpc, NET.vpc);
eq("VPC cidrBlock", vpc.i.cidrBlock, cfg.vpcCidr);
const dnsAttrs = checkVpcDns(cfg, vpc.i.enableDnsSupport, vpc.i.enableDnsHostnames);
if (dnsAttrs) bad(`VPC: ${dnsAttrs}`);
absent(vpc, ["assignGeneratedIpv6CidrBlock", "ipv6CidrBlock", "ipv6IpamPoolId", "ipv4IpamPoolId", "ipv6NetmaskLength"]);
const dhcp = one(T.dhcp, NET.dhcp);
eq("DHCP domainNameServers", dhcp.i.domainNameServers, cfg.resolvers);
absent(dhcp, ["domainName", "ntpServers", "netbiosNameServers", "netbiosNodeType"]);
const dhcpAssoc = one(T.dhcpAssoc, NET.dhcp);
ref(dhcpAssoc, "vpcId", [vpc]);
ref(dhcpAssoc, "dhcpOptionsId", [dhcp]);
const igw = one(T.igw, NET.igw);
ref(igw, "vpcId", [vpc]);

const subnets = { proxy: one(T.subnet, NET.proxy), vms: one(T.subnet, NET.vms) };
const tables = { proxy: one(T.rt, NET.proxy), vms: one(T.rt, NET.vms) };
for (const t of ["proxy", "vms"] as const) {
    const s = subnets[t];
    eq(`subnet ${s.name} cidrBlock`, s.i.cidrBlock, t === "proxy" ? cfg.proxySubnetCidr : cfg.vmSubnetCidr);
    eq(`subnet ${s.name} availabilityZoneId`, s.i.availabilityZoneId, cfg.azId);
    eq(`subnet ${s.name} mapPublicIpOnLaunch`, s.i.mapPublicIpOnLaunch, false);
    absent(s, ["assignIpv6AddressOnCreation", "ipv6CidrBlock", "ipv6Native", "enableDns64", "mapCustomerOwnedIpOnLaunch", "customerOwnedIpv4Pool", "outpostArn"]);
    ref(s, "vpcId", [vpc]);
    const rt = tables[t];
    ref(rt, "vpcId", [vpc]);
    absent(rt, ["propagatingVgws"]);
    const routes = Array.isArray(rt.i.routes) ? (rt.i.routes as Record<string, unknown>[]) : undefined;
    if (routes === undefined) bad(`route table ${rt.name}: routes must be an explicit list`);
    const specRoutes: RouteSpec[] = (routes ?? []).map((r) => {
        const other = userKeys(r).filter((k) => k !== "cidrBlock" && k !== "gatewayId");
        if (other.length > 0) bad(`route table ${rt.name}: route ${json(r.cidrBlock)} has ${other.join(", ")} (only an IPv4 CIDR to the internet gateway)`);
        return { cidr: String(r.cidrBlock), target: "igw" };
    });
    const rr = checkRoutes(t, specRoutes);
    if (rr) bad(`route table ${rt.name}: ${rr}`);
    ref(rt, "routes", t === "proxy" ? [igw] : []);
    const a = one(T.rta, t === "proxy" ? NET.proxy : NET.vms);
    ref(a, "subnetId", [s]);
    ref(a, "routeTableId", [rt]);
    absent(a, ["gatewayId"]);
}

const nacl = one(T.nacl, NET.vms);
ref(nacl, "vpcId", [vpc]);
absent(nacl, ["subnetIds"]);
const naclRules = (dir: "ingress" | "egress"): NaclRuleSpec[] => {
    const list = nacl.i[dir];
    if (!Array.isArray(list)) { bad(`network ACL ${nacl.name}: ${dir} must be an explicit list`); return []; }
    return (list as Record<string, unknown>[]).map((r) => {
        const other = userKeys(r).filter((k) => !["ruleNo", "protocol", "action", "cidrBlock", "fromPort", "toPort"].includes(k));
        if (other.length > 0) bad(`network ACL ${nacl.name}: ${dir} rule ${json(r.ruleNo)} has ${other.join(", ")}`);
        return { ruleNo: r.ruleNo, protocol: r.protocol, action: r.action, cidr: r.cidrBlock, fromPort: r.fromPort, toPort: r.toPort } as NaclRuleSpec;
    });
};
const naclProblem = checkNacl(cfg, naclRules("ingress"), naclRules("egress"));
if (naclProblem) bad(`network ACL ${nacl.name}: ${naclProblem}`);
const naclAssoc = one(T.naclAssoc, NET.vms);
ref(naclAssoc, "networkAclId", [nacl]);
ref(naclAssoc, "subnetId", [subnets.vms]);

// ---- security groups and their rules ----
const defaultSg = one(T.defaultSg, NET.defaultSecurityGroup);
ref(defaultSg, "vpcId", [vpc]);
eq("default SG ingress", defaultSg.i.ingress, []);
eq("default SG egress", defaultSg.i.egress, []);
const sgs = { vm: one(T.sg, cfg.vmSecurityGroupName), proxy: one(T.sg, cfg.proxySecurityGroupName) };
for (const k of ["vm", "proxy"] as const) {
    const g = sgs[k];
    eq(`SG ${g.name} name`, g.i.name, k === "vm" ? cfg.vmSecurityGroupName : cfg.proxySecurityGroupName);
    eq(`SG ${g.name} description`, g.i.description, k === "vm" ? VM_SG_DESCRIPTION : PROXY_SG_DESCRIPTION);
    absent(g, ["ingress", "egress", "namePrefix"]);
    ref(g, "vpcId", [vpc]);
}
const spec = egressSpec(cfg);
for (const r of [...(found.get(T.ingress) ?? []), ...(found.get(T.egress) ?? [])]) {
    const owner = ruleOwner(spec, r.name);
    if (owner === undefined) { bad(`${r.type} ${r.name}: belongs to neither egress security group`); continue; }
    ref(r, "securityGroupId", [sgs[owner]]);
    absent(r, ["cidrIpv6", "prefixListId"]);
    const peers = [set(r.i.cidrIpv4), set(r.i.referencedSecurityGroupId)].filter(Boolean).length;
    if (peers !== 1) { bad(`${r.type} ${r.name}: exactly one peer (cidrIpv4 or referencedSecurityGroupId)`); continue; }
    if (r.i.fromPort !== r.i.toPort) { bad(`${r.type} ${r.name}: one port only, got ${json(r.i.fromPort)}-${json(r.i.toPort)}`); continue; }
    if (set(r.i.referencedSecurityGroupId)) ref(r, "referencedSecurityGroupId", [sgs.vm]);
    else ref(r, "referencedSecurityGroupId", []);
    const rule: RuleSpec = {
        direction: r.type === T.ingress ? "ingress" : "egress", protocol: r.i.ipProtocol as RuleSpec["protocol"], port: r.i.fromPort as number,
        peer: set(r.i.cidrIpv4) ? { cidr: String(r.i.cidrIpv4) } : { sg: "vm" }, description: "",
    };
    const p = checkRule(cfg, owner, rule);
    if (p) bad(`${r.type} ${r.name}: ${p}`);
}

// ---- the proxy ----
const profile = one(T.profile, cfg.proxyInstanceProfileName);
const proxyRole = one(T.role, cfg.proxyRoleName);
const operatorRole = one(T.role, cfg.operatorRoleName);
ref(profile, "role", [proxyRole]);
const inst = one(T.instance, NET.instance);
eq("instance privateIp", inst.i.privateIp, cfg.proxyIp);
eq("instance associatePublicIpAddress", inst.i.associatePublicIpAddress, true);
eq("instance instanceType", inst.i.instanceType, cfg.instanceType);
const md = (inst.i.metadataOptions ?? {}) as Record<string, unknown>;
eq("instance IMDS", [md.httpTokens, md.httpPutResponseHopLimit], ["required", 1]);
const root = (inst.i.rootBlockDevice ?? {}) as Record<string, unknown>;
eq("instance root volume", [root.volumeType, root.volumeSize, root.encrypted], ["gp3", 8, true]);
eq("instance credits", ((inst.i.creditSpecification ?? {}) as Record<string, unknown>).cpuCredits, "standard");
eq("instance userDataReplaceOnChange", inst.i.userDataReplaceOnChange, true);
if (inst.i.sourceDestCheck === false) bad("instance: sourceDestCheck must stay on");
for (const k of ["ami", "userData"]) present(inst, k);
absent(inst, ["keyName", "networkInterfaces", "ipv6AddressCount", "ipv6Addresses", "secondaryPrivateIps", "securityGroups", "launchTemplate"]);
ref(inst, "subnetId", [subnets.proxy]);
ref(inst, "vpcSecurityGroupIds", [sgs.proxy]);
eq("instance security groups", (Array.isArray(inst.i.vpcSecurityGroupIds) ? inst.i.vpcSecurityGroupIds : []).length, 1);
ref(inst, "iamInstanceProfile", [profile]);
const ssmAttachment = one(T.attachment, `${cfg.proxyRoleName}-ssm`);
eq("proxy managed policy", ssmAttachment.i.policyArn, SSM_INSTANCE_POLICY_ARN);
ref(ssmAttachment, "role", [proxyRole]);
const operatorAttachment = one(T.attachment, cfg.operatorRoleName);
eq("operator managed policy", operatorAttachment.i.policyArn, CONNECTOR_OPERATOR_POLICY_ARN);
ref(operatorAttachment, "role", [operatorRole]);
for (const p of PROXY_PARAMETERS) {
    const v = one(T.parameter, `ai-env-proxy-${p}`);
    eq(`parameter ${p} name`, v.i.name, `${cfg.parameterPrefix}/${p}`);
    eq(`parameter ${p} type/tier`, [v.i.type, v.i.tier], ["String", "Standard"]);
    present(v, "insecureValue");
    absent(v, ["value", "valueWo", "keyId"]);
    if (typeof v.i.insecureValue === "string" && Buffer.byteLength(v.i.insecureValue) > PARAMETER_MAX_BYTES) bad(`parameter ${p}: over ${PARAMETER_MAX_BYTES} bytes`);
}
const squid = String(one(T.parameter, "ai-env-proxy-squid.conf").i.insecureValue ?? "");
if (!squid.includes(`${cfg.proxyIp}:${cfg.proxyPort}`) || !squid.includes(cfg.vmSubnetCidr)) bad("parameter squid.conf: the proxy address or the VM subnet is not rendered in");
const squidGroup = one(T.logGroup, NET.logGroup);
eq("squid log group", [squidGroup.i.name, squidGroup.i.retentionInDays], [cfg.logGroup, cfg.logRetentionDays]);

// ---- the connector ----
const conn = one(T.connector, cfg.connectorName);
const vec = (((conn.i.configuration ?? {}) as Record<string, unknown>).vpcEgressConfiguration ?? {}) as Record<string, unknown>;
eq("connector name", conn.i.name, cfg.connectorName);
eq("connector networkProtocol", vec.networkProtocol, "IPv4");
eq("connector associatedComputeResourceTypes", vec.associatedComputeResourceTypes, ["MicroVm"]);
eq("connector subnetIds count", (Array.isArray(vec.subnetIds) ? vec.subnetIds : []).length, 1);
eq("connector securityGroupIds count", (Array.isArray(vec.securityGroupIds) ? vec.securityGroupIds : []).length, 1);
for (const k of userKeys(vec)) if (!["subnetIds", "securityGroupIds", "networkProtocol", "associatedComputeResourceTypes"].includes(k)) bad(`connector: configuration.vpcEgressConfiguration.${k} is outside the spec`);
ref(conn, "configuration", [subnets.vms, sgs.vm]);
if (known(subnets.vms.id) && (vec.subnetIds as unknown[] | undefined)?.some((x) => known(x) && x !== subnets.vms.id)) bad("connector: subnetIds is not the VM subnet");
if (known(sgs.vm.id) && (vec.securityGroupIds as unknown[] | undefined)?.some((x) => known(x) && x !== sgs.vm.id)) bad("connector: securityGroupIds is not the VM security group");
present(conn, "operatorRole");
ref(conn, "operatorRole", [operatorRole, operatorAttachment]);
// The role the connector's service assumes to create its ENIs: exactly the stack's operator role (ref() cannot compare
// an ARN by value). Unknown only while the role or its attachment is being created.
const operatorArn = roleArn(names, cfg.operatorRoleName);
if (known(conn.i.operatorRole) && conn.i.operatorRole !== operatorArn) bad(`connector: operatorRole ${conn.i.operatorRole} is not ${operatorArn}`);
if (conn !== EMPTY && !known(conn.i.operatorRole) && !CREATING.has(conn.op) && ![operatorRole, operatorAttachment].some((r) => CREATING.has(r.op))) {
    bad("connector: operatorRole is unknown on a plan in which neither it nor the operator role is created");
}

// ---- dnsMode firewall: the block-all DNS Firewall ----
if (cfg.dnsMode === "firewall") {
    const list = one(T.fwList, NET.firewall);
    eq("DNS Firewall domains", list.i.domains, ["*"]);
    const group = one(T.fwGroup, NET.firewall);
    const rule = one(T.fwRule, NET.firewall);
    eq("DNS Firewall rule", [rule.i.action, rule.i.blockResponse, rule.i.priority, rule.i.firewallDomainRedirectionAction], ["BLOCK", FIREWALL_BLOCK_RESPONSE, FIREWALL_RULE_PRIORITY, FIREWALL_REDIRECTION]);
    absent(rule, ["qType", "blockOverrideDnsType", "blockOverrideDomain", "blockOverrideTtl"]);
    ref(rule, "firewallDomainListId", [list]);
    ref(rule, "firewallRuleGroupId", [group]);
    const assoc = one(T.fwAssoc, NET.firewall);
    eq("DNS Firewall association", [assoc.i.priority, assoc.i.mutationProtection], [FIREWALL_ASSOCIATION_PRIORITY, "DISABLED"]);
    ref(assoc, "firewallRuleGroupId", [group]);
    ref(assoc, "vpcId", [vpc]);
    const fwConfig = one(T.fwConfig, NET.vpc);
    eq("DNS Firewall fail open", fwConfig.i.firewallFailOpen, "DISABLED");
    ref(fwConfig, "resourceId", [vpc]);
    if (cfg.enableDnsQueryLog) {
        const ql = one(T.queryLog, NET.queryLog);
        ref(ql, "destinationArn", [one(T.logGroup, NET.dnsLogGroup)], false);
        eq("DNS query log group", one(T.logGroup, NET.dnsLogGroup).i.name, dnsQueryLogGroup(cfg));
        const qa = one(T.queryLogAssoc, NET.queryLog);
        ref(qa, "resolverQueryLogConfigId", [ql]);
        ref(qa, "resourceId", [vpc]);
    }
}
if (problems.length > 0) {
    process.stderr.write(`check-plan: the plan does not match the stack inventory and the egress spec (dnsMode ${cfg.dnsMode}):\n`);
    for (const p of problems) process.stderr.write(`  - ${p}\n`);
    process.exit(1);
}
console.log(`check-plan: ok (${all.length} resources, dnsMode ${cfg.dnsMode}: inventory, providers, egress inputs and references by URN)`);
