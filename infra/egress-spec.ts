// The S5 egress network as data (plans/s5-plan.md "Design → Infra", "W1 review, design changes"): the typed loader
// of egress-config.json, the spec every network resource of egress.ts is built from, the inventory of every
// resource the stack may hold, and the predicates that refuse anything else.
//
// Why Pulumi-free: print-policies.ts and check-plan.ts are compiled alone, and the spec must be judged before any
// resource is registered. The predicates are shared by three layers: assertEgressSpec refuses a spec before the
// program registers anything; egress.ts's resource transform (the guard) refuses any resource outside the
// inventory and applies the same predicates (checkRule, checkRoutes, checkNacl, ...) to every network resource the
// program registers; and scripts/check-plan.ts, the final word, applies them again to the planned inputs of
// `pulumi preview --json` (after every transform) with the references checked by URN. The config holds no account
// data; a Rust test (bridge/egress/mod.rs EGRESS_CONSTS) pins every key.
import * as fs from "fs";
import * as path from "path";
import {
    BUCKET_PREFIX, BUDGET_NAME, BUILD_ROLE_NAME, DEPLOY_DNS_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME, DEPLOY_POLICY_NAME, EXECUTION_ROLE_NAME, EgressNames,
    REGION, RUNTIME_POLICY_NAME, RUNTIME_USER_NAME, dnsQueryLogGroupName,
} from "./policies";

export const DNS_MODES = ["none", "firewall"] as const;
export type DnsMode = (typeof DNS_MODES)[number];

export interface EgressConfig {
    vpcCidr: string;
    proxySubnetCidr: string;
    vmSubnetCidr: string;
    /** An AZ id (`euc1-az1`), not a name: names are shuffled per account. */
    azId: string;
    proxyIp: string;
    proxyPort: number;
    instanceType: string;
    /** The only DNS servers in the VPC (DHCP options), reachable from the proxy SG only. */
    resolvers: string[];
    dnsMode: DnsMode;
    /** Route 53 Resolver query logging, `firewall` mode only. */
    enableDnsQueryLog: boolean;
    logGroup: string;
    logRetentionDays: number;
    parameterPrefix: string;
    connectorName: string;
    proxyRoleName: string;
    operatorRoleName: string;
    proxyInstanceProfileName: string;
    vmSecurityGroupName: string;
    proxySecurityGroupName: string;
}

const STRING_KEYS = ["vpcCidr", "proxySubnetCidr", "vmSubnetCidr", "azId", "proxyIp", "instanceType", "dnsMode", "logGroup", "parameterPrefix",
    "connectorName", "proxyRoleName", "operatorRoleName", "proxyInstanceProfileName", "vmSecurityGroupName", "proxySecurityGroupName"] as const;
const NUMBER_KEYS = ["proxyPort", "logRetentionDays"] as const;
const KEYS: readonly string[] = [...STRING_KEYS, ...NUMBER_KEYS, "resolvers", "enableDnsQueryLog"];

/** infra/egress-config.json, typed field by field (values are judged by assertEgressSpec). An unknown key is a typo. */
export function loadEgressConfig(file = path.join(__dirname, "egress-config.json")): EgressConfig {
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    const fail = (what: string): never => { throw new Error(`${file}: ${what}`); };
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) fail("not a JSON object");
    for (const k of Object.keys(raw)) if (!KEYS.includes(k)) fail(`unknown key ${k}`);
    for (const k of STRING_KEYS) if (typeof raw[k] !== "string" || raw[k].length === 0) fail(`${k} must be a non-empty string`);
    for (const k of NUMBER_KEYS) if (!Number.isInteger(raw[k])) fail(`${k} must be an integer`);
    if (!Array.isArray(raw.resolvers) || raw.resolvers.some((r: unknown) => typeof r !== "string")) fail("resolvers must be a list of strings");
    if (typeof raw.enableDnsQueryLog !== "boolean") fail("enableDnsQueryLog must be true or false");
    return raw as EgressConfig;
}

/** What policies.ts needs (the IAM documents of the proxy and operator roles, and the deploy policy). */
export function egressNames(cfg: EgressConfig): EgressNames {
    return {
        parameterPrefix: cfg.parameterPrefix, logGroup: cfg.logGroup, proxyRoleName: cfg.proxyRoleName, operatorRoleName: cfg.operatorRoleName,
        proxyInstanceProfileName: cfg.proxyInstanceProfileName, connectorName: cfg.connectorName,
    };
}

/** The four proxy parameters `<prefix>/<name>` (contract 2); extras and suspended are owned by `ai-env egress` after creation. */
export const PROXY_PARAMETERS = ["squid.conf", "allow", "extras", "suspended"] as const;
export type ProxyParameter = (typeof PROXY_PARAMETERS)[number];
/** The standard tier's limit, also the rendered squid.conf's bound. */
export const PARAMETER_MAX_BYTES = 4096;

/** The AL2023 standard (not minimal) arm64 AMI, an SSM public parameter (t4g is Graviton). */
export const AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64";

/** Route 53 Resolver query logs (`firewall` mode with enableDnsQueryLog only): next to the squid group. */
export function dnsQueryLogGroup(cfg: EgressConfig): string {
    return dnsQueryLogGroupName(cfg.logGroup);
}

// ---- IPv4 ----

/** A dotted quad as an unsigned 32-bit number (no leading zeros, no shorthand), else undefined. */
export function ipv4(s: string): number | undefined {
    const parts = s.split(".");
    if (parts.length !== 4 || parts.some((p) => !/^(0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255)) return undefined;
    return parts.reduce((acc, p) => ((acc << 8) | Number(p)) >>> 0, 0);
}

export interface Cidr {
    base: number;
    bits: number;
}

/** `a.b.c.d/n` whose host bits are zero, else undefined. */
export function cidr(s: string): Cidr | undefined {
    const m = /^([0-9.]+)\/([0-9]{1,2})$/.exec(s);
    if (!m) return undefined;
    const base = ipv4(m[1]);
    const bits = Number(m[2]);
    if (base === undefined || bits > 32) return undefined;
    return (base & mask(bits)) >>> 0 === base ? { base, bits } : undefined;
}

function mask(bits: number): number {
    return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
}

function size(c: Cidr): number {
    return 2 ** (32 - c.bits);
}

export function cidrContains(outer: Cidr, inner: Cidr): boolean {
    return inner.bits >= outer.bits && (inner.base & mask(outer.bits)) >>> 0 === outer.base;
}

export function cidrOverlaps(a: Cidr, b: Cidr): boolean {
    return cidrContains(a, b) || cidrContains(b, a);
}

function isPrivate(ip: number): boolean {
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/3"]
        .some((c) => cidrContains(cidr(c)!, { base: ip, bits: 32 }));
}

// ---- the spec ----

export type SgKey = "vm" | "proxy";
export type Peer = { sg: SgKey } | { cidr: string };

export interface RuleSpec {
    direction: "ingress" | "egress";
    protocol: "tcp" | "udp";
    port: number;
    peer: Peer;
    description: string;
}

export interface SgSpec {
    /** The AWS name, also the Pulumi name (fixed: a new name or description replaces the SG under the connector's ENIs). */
    name: string;
    description: string;
    rules: RuleSpec[];
}

export interface RouteSpec {
    cidr: string;
    target: "igw";
}

export interface RouteTableSpec {
    name: string;
    routes: RouteSpec[];
}

/** One rule of the VM subnet's network ACL (stateless: the return traffic needs its own ingress rule). */
export interface NaclRuleSpec {
    ruleNo: number;
    protocol: "tcp";
    action: "allow";
    cidr: string;
    fromPort: number;
    toPort: number;
}

export interface EgressSpec {
    cfg: EgressConfig;
    vpc: { name: string; cidr: string; enableDnsSupport: boolean; enableDnsHostnames: boolean };
    dhcp: { name: string; domainNameServers: string[] };
    igw: { name: string };
    subnets: { proxy: { name: string; cidr: string }; vms: { name: string; cidr: string } };
    routeTables: { proxy: RouteTableSpec; vms: RouteTableSpec };
    /** The VM subnet's own network ACL: a second layer under the VM security group (defence in depth). */
    nacl: { name: string; ingress: NaclRuleSpec[]; egress: NaclRuleSpec[] };
    defaultSecurityGroup: { name: string };
    securityGroups: { vm: SgSpec; proxy: SgSpec };
}

/** Pulumi names of the network resources (the transform identifies resources by them). */
export const NET = {
    vpc: "ai-env-egress",
    dhcp: "ai-env-egress",
    igw: "ai-env-egress",
    proxy: "ai-env-egress-proxy",
    vms: "ai-env-egress-vms",
    defaultSecurityGroup: "ai-env-egress-default",
    instance: "ai-env-egress-proxy",
    firewall: "ai-env-egress-block-all",
    queryLog: "ai-env-egress-dns",
    /** Pulumi names outside the network (the inventory pins them too). */
    logGroup: "egress-log-group",
    dnsLogGroup: "egress-dns-log-group",
} as const;

/** Fixed: a changed description replaces the security group, which the connector's ENIs hold. */
export const VM_SG_DESCRIPTION = "ai-env MicroVM egress connector ENIs: TCP 3128 to the proxy only";
export const PROXY_SG_DESCRIPTION = "ai-env egress proxy: TCP 3128 from the MicroVM ENIs; HTTPS and DNS out";
export const ANYWHERE = "0.0.0.0/0";
export const HTTPS = 443;
export const DNS = 53;
/** Never open, anywhere: the proxy is reached through SSM only. */
export const SSH = 22;
/** The VM subnet's NACL: the one rule number of each direction, and the client ports the proxy answers to. */
export const NACL_RULE_NO = 100;
export const EPHEMERAL_FROM = 1024;
export const EPHEMERAL_TO = 65535;
/** DNS Firewall (dnsMode "firewall"): the block-all rule and its association. */
export const FIREWALL_RULE_PRIORITY = 100;
export const FIREWALL_ASSOCIATION_PRIORITY = 101;
export const FIREWALL_BLOCK_RESPONSE = "NXDOMAIN";
/** Every name of a CNAME/DNAME chain is checked against the block-all list (the alternative trusts the redirects). */
export const FIREWALL_REDIRECTION = "INSPECT_REDIRECTION_DOMAIN";

/** The proxy's address as the one CIDR the VM subnet may reach. */
export function proxyCidr(cfg: EgressConfig): string {
    return `${cfg.proxyIp}/32`;
}

/**
 * The spec of the egress network, from the config alone. The scratch:* markers are edited by
 * `make preview-scratch NEGATIVE=vm-sg-open|private-route|dns-support-on-in-none-mode|nacl-open` in a scratch copy.
 */
export function egressSpec(cfg: EgressConfig): EgressSpec {
    const dnsRules: RuleSpec[] = cfg.resolvers.flatMap((r) => (["udp", "tcp"] as const).map((protocol) => (
        { direction: "egress" as const, protocol, port: DNS, peer: { cidr: `${r}/32` }, description: `DNS to resolver ${r}` })));
    return {
        cfg,
        vpc: { name: NET.vpc, cidr: cfg.vpcCidr, enableDnsSupport: cfg.dnsMode === "firewall", enableDnsHostnames: false }, // scratch:vpc
        dhcp: { name: NET.dhcp, domainNameServers: [...cfg.resolvers] },
        igw: { name: NET.igw },
        subnets: { proxy: { name: NET.proxy, cidr: cfg.proxySubnetCidr }, vms: { name: NET.vms, cidr: cfg.vmSubnetCidr } },
        routeTables: {
            proxy: { name: NET.proxy, routes: [{ cidr: ANYWHERE, target: "igw" }] },
            vms: { name: NET.vms, routes: [] }, // scratch:vms-routes
        },
        nacl: {
            name: NET.vms,
            ingress: [{ ruleNo: NACL_RULE_NO, protocol: "tcp", action: "allow", cidr: proxyCidr(cfg), fromPort: EPHEMERAL_FROM, toPort: EPHEMERAL_TO }],
            egress: [
                { ruleNo: NACL_RULE_NO, protocol: "tcp", action: "allow", cidr: proxyCidr(cfg), fromPort: cfg.proxyPort, toPort: cfg.proxyPort },
            ], // scratch:nacl-egress
        },
        defaultSecurityGroup: { name: NET.defaultSecurityGroup },
        securityGroups: {
            vm: {
                name: cfg.vmSecurityGroupName, description: VM_SG_DESCRIPTION, rules: [
                    // The proxy's address, not its security group: any interface holding the proxy SG would otherwise be a second proxy.
                    { direction: "egress", protocol: "tcp", port: cfg.proxyPort, peer: { cidr: proxyCidr(cfg) }, description: "to the egress proxy only" },
                ], // scratch:vm-rules
            },
            proxy: {
                name: cfg.proxySecurityGroupName, description: PROXY_SG_DESCRIPTION, rules: [
                    { direction: "ingress", protocol: "tcp", port: cfg.proxyPort, peer: { sg: "vm" }, description: "from the MicroVM egress ENIs" },
                    { direction: "egress", protocol: "tcp", port: HTTPS, peer: { cidr: ANYWHERE }, description: "CONNECT targets, SSM, CloudWatch, dnf" },
                    ...dnsRules,
                ],
            },
        },
    };
}

/** The Pulumi name of a rule: `<sg name>-<to|from>-<peer>-<protocol>-<port>` (a CIDR's `/` becomes `-`). */
export function ruleName(spec: EgressSpec, sg: SgKey, rule: RuleSpec): string {
    const peer = "sg" in rule.peer ? spec.securityGroups[rule.peer.sg].name : rule.peer.cidr.replace("/", "-");
    return `${spec.securityGroups[sg].name}-${rule.direction === "ingress" ? "from" : "to"}-${peer}-${rule.protocol}-${rule.port}`;
}

/** Which security group a rule's Pulumi name belongs to (undefined: not named like a rule of the spec). */
export function ruleOwner(spec: EgressSpec, name: string): SgKey | undefined {
    // assertEgressSpec refuses two names where one prefixes the other, so at most one matches.
    return (["vm", "proxy"] as const).find((k) => name.startsWith(`${spec.securityGroups[k].name}-`));
}

function sameRule(a: RuleSpec, b: RuleSpec): boolean {
    const peer = (p: Peer) => ("sg" in p ? `sg:${p.sg}` : `cidr:${p.cidr}`);
    return a.direction === b.direction && a.protocol === b.protocol && a.port === b.port && peer(a.peer) === peer(b.peer);
}

/**
 * One rule against the design, wherever it comes from (the spec, a rule resource seen by the transform, a planned rule):
 *   vm SG:    egress TCP <proxyPort> → <proxyIp>/32, nothing else;
 *   proxy SG: ingress TCP <proxyPort> ← the vm SG; egress TCP 443 → 0.0.0.0/0; egress UDP/TCP 53 → <resolver>/32.
 * Never port 22, never protocol -1. Undefined when the rule is allowed, else why not.
 */
export function checkRule(cfg: EgressConfig, sg: SgKey, rule: RuleSpec): string | undefined {
    const what = `${sg === "vm" ? cfg.vmSecurityGroupName : cfg.proxySecurityGroupName} ${rule.direction} ${rule.protocol} ${rule.port} ${"sg" in rule.peer ? `sg:${rule.peer.sg}` : rule.peer.cidr}`;
    if (rule.protocol !== "tcp" && rule.protocol !== "udp") return `${what}: only tcp or udp (never all protocols)`;
    if (!Number.isInteger(rule.port) || rule.port < 1 || rule.port > 65535) return `${what}: not a port`;
    if (rule.port === SSH) return `${what}: no port 22 (the proxy is reached through SSM only)`;
    if ("cidr" in rule.peer && cidr(rule.peer.cidr) === undefined) return `${what}: not an IPv4 CIDR`;
    const allowed: RuleSpec[] = sg === "vm"
        ? [{ direction: "egress", protocol: "tcp", port: cfg.proxyPort, peer: { cidr: proxyCidr(cfg) }, description: "" }]
        : [
            { direction: "ingress", protocol: "tcp", port: cfg.proxyPort, peer: { sg: "vm" }, description: "" },
            { direction: "egress", protocol: "tcp", port: HTTPS, peer: { cidr: ANYWHERE }, description: "" },
            ...cfg.resolvers.flatMap((r) => (["udp", "tcp"] as const).map((protocol) => ({ direction: "egress" as const, protocol, port: DNS, peer: { cidr: `${r}/32` }, description: "" }))),
        ];
    if (allowed.some((a) => sameRule(a, rule))) return undefined;
    return sg === "vm"
        ? `${what}: the VM security group allows exactly one rule, egress TCP ${cfg.proxyPort} to ${proxyCidr(cfg)}`
        : `${what}: the proxy security group allows only TCP ${cfg.proxyPort} from the VM security group, TCP 443 to ${ANYWHERE} and UDP/TCP 53 to the resolvers /32`;
}

/** A route table's routes: the VM table has none; the proxy table has exactly 0.0.0.0/0 → the IGW. */
export function checkRoutes(table: "proxy" | "vms", routes: RouteSpec[]): string | undefined {
    if (table === "vms") return routes.length === 0 ? undefined : `the VM route table must have no route (only the implicit local one), got ${routes.map((r) => `${r.cidr} -> ${r.target}`).join(", ")}`;
    return routes.length === 1 && routes[0].cidr === ANYWHERE && routes[0].target === "igw"
        ? undefined : `the proxy route table must have exactly one route, ${ANYWHERE} -> the internet gateway`;
}

/**
 * The VM subnet's NACL against the design: egress exactly TCP <proxyPort> to <proxyIp>/32, ingress exactly TCP
 * 1024–65535 from <proxyIp>/32 (the proxy's answers), both allow, rule 100; everything else hits the implicit deny.
 */
export function checkNacl(cfg: EgressConfig, ingress: NaclRuleSpec[], egress: NaclRuleSpec[]): string | undefined {
    const canon = (rs: NaclRuleSpec[]) => JSON.stringify(rs.map((r) => [r.ruleNo, r.protocol, r.action, r.cidr, r.fromPort, r.toPort]));
    const wantIn: NaclRuleSpec[] = [{ ruleNo: NACL_RULE_NO, protocol: "tcp", action: "allow", cidr: proxyCidr(cfg), fromPort: EPHEMERAL_FROM, toPort: EPHEMERAL_TO }];
    const wantOut: NaclRuleSpec[] = [{ ruleNo: NACL_RULE_NO, protocol: "tcp", action: "allow", cidr: proxyCidr(cfg), fromPort: cfg.proxyPort, toPort: cfg.proxyPort }];
    if (canon(egress) !== canon(wantOut)) return `the VM subnet's network ACL must allow exactly one egress rule, TCP ${cfg.proxyPort} to ${proxyCidr(cfg)}, got ${canon(egress)}`;
    if (canon(ingress) !== canon(wantIn)) return `the VM subnet's network ACL must allow exactly one ingress rule, TCP ${EPHEMERAL_FROM}-${EPHEMERAL_TO} from ${proxyCidr(cfg)}, got ${canon(ingress)}`;
    return undefined;
}

/** The VPC's DNS attributes for a mode: DNS support only in `firewall` mode, hostnames never. */
export function checkVpcDns(cfg: EgressConfig, enableDnsSupport: unknown, enableDnsHostnames: unknown): string | undefined {
    const want = cfg.dnsMode === "firewall";
    if (enableDnsSupport !== want) return `enableDnsSupport must be ${want} in dnsMode ${cfg.dnsMode}, got ${String(enableDnsSupport)}`;
    if (enableDnsHostnames !== false) return `enableDnsHostnames must be false, got ${String(enableDnsHostnames)}`;
    return undefined;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const LOG_RETENTION_DAYS = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];

/**
 * Throws, naming every violation, before any resource is registered: CIDRs not disjoint or outside the VPC; the
 * proxy IP outside its subnet, reserved (.0–.3) or the broadcast address; a resolver that is not a public IPv4
 * address; the VM SG with anything but exactly one egress rule TCP <proxyPort> → the proxy SG; a proxy SG rule
 * outside the design; any route on the VM table; DNS attributes that do not match the mode; a mode outside its enum.
 */
export function assertEgressSpec(spec: EgressSpec): void {
    const cfg = spec.cfg;
    const errors: string[] = [];
    const err = (msg: string) => errors.push(msg);

    if (!(DNS_MODES as readonly string[]).includes(cfg.dnsMode)) err(`dnsMode must be one of ${DNS_MODES.join(", ")}, got ${cfg.dnsMode}`);
    if (typeof cfg.enableDnsQueryLog !== "boolean") err("enableDnsQueryLog must be true or false");
    if (cfg.enableDnsQueryLog && cfg.dnsMode !== "firewall") err("enableDnsQueryLog needs dnsMode firewall (in mode none the VPC has no Amazon DNS to log)");

    const vpc = cidr(cfg.vpcCidr);
    const proxyNet = cidr(cfg.proxySubnetCidr);
    const vmNet = cidr(cfg.vmSubnetCidr);
    for (const [k, c] of [["vpcCidr", vpc], ["proxySubnetCidr", proxyNet], ["vmSubnetCidr", vmNet]] as const) {
        if (c === undefined) err(`${k} is not an IPv4 network address in CIDR form`);
    }
    const rfc1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map((c) => cidr(c)!);
    if (vpc && (vpc.bits < 16 || vpc.bits > 28 || !rfc1918.some((c) => cidrContains(c, vpc)))) err(`vpcCidr ${cfg.vpcCidr} must be an RFC 1918 /16 to /28`);
    if (vpc && proxyNet && !cidrContains(vpc, proxyNet)) err(`proxySubnetCidr ${cfg.proxySubnetCidr} is not inside vpcCidr ${cfg.vpcCidr}`);
    if (vpc && vmNet && !cidrContains(vpc, vmNet)) err(`vmSubnetCidr ${cfg.vmSubnetCidr} is not inside vpcCidr ${cfg.vpcCidr}`);
    if (proxyNet && vmNet && cidrOverlaps(proxyNet, vmNet)) err(`proxySubnetCidr ${cfg.proxySubnetCidr} and vmSubnetCidr ${cfg.vmSubnetCidr} overlap`);
    for (const [k, c] of [["proxySubnetCidr", proxyNet], ["vmSubnetCidr", vmNet]] as const) {
        if (c && (c.bits < 16 || c.bits > 28)) err(`${k} must be a /16 to /28 (the VPC subnet limits)`);
    }

    const ip = ipv4(cfg.proxyIp);
    if (ip === undefined) err(`proxyIp ${cfg.proxyIp} is not an IPv4 address`);
    else if (proxyNet) {
        if (!cidrContains(proxyNet, { base: ip, bits: 32 })) err(`proxyIp ${cfg.proxyIp} is not inside proxySubnetCidr ${cfg.proxySubnetCidr}`);
        else if (ip - proxyNet.base < 4) err(`proxyIp ${cfg.proxyIp} is reserved by AWS (the first four addresses of the subnet)`);
        else if (ip === proxyNet.base + size(proxyNet) - 1) err(`proxyIp ${cfg.proxyIp} is the subnet's broadcast address (reserved by AWS)`);
    }
    if (!Number.isInteger(cfg.proxyPort) || cfg.proxyPort < 1024 || cfg.proxyPort > 65535) err(`proxyPort ${cfg.proxyPort} must be an unprivileged port (1024–65535)`);

    if (cfg.resolvers.length === 0) err("resolvers must name at least one DNS server");
    if (new Set(cfg.resolvers).size !== cfg.resolvers.length) err("resolvers lists a server twice");
    for (const r of cfg.resolvers) {
        const a = ipv4(r);
        if (a === undefined) err(`resolver ${r} is not an IPv4 address`);
        else if (isPrivate(a)) err(`resolver ${r} is not a public address (the Amazon DNS server and anything inside the VPC are out)`);
    }

    if (!/^[a-z]{2,4}[0-9]-az[0-9]+$/.test(cfg.azId)) err(`azId ${cfg.azId} is not an AZ id (euc1-az1)`);
    if (!/^t4g\.[a-z0-9]+$/.test(cfg.instanceType)) err(`instanceType ${cfg.instanceType} must be a t4g type (the AMI is arm64)`);
    if (!LOG_RETENTION_DAYS.includes(cfg.logRetentionDays)) err(`logRetentionDays ${cfg.logRetentionDays} is not a CloudWatch Logs retention`);
    if (!/^(\/[A-Za-z0-9_.-]+)+$/.test(cfg.logGroup)) err(`logGroup ${cfg.logGroup} must be an absolute /a/b path`);
    if (!/^(\/[A-Za-z0-9_.-]+)+$/.test(cfg.parameterPrefix) || cfg.parameterPrefix.startsWith("/aws") || cfg.parameterPrefix.startsWith("/ssm")) {
        err(`parameterPrefix ${cfg.parameterPrefix} must be an absolute /a/b path outside /aws and /ssm, without a trailing /`);
    }
    for (const k of ["connectorName", "proxyRoleName", "operatorRoleName", "proxyInstanceProfileName", "vmSecurityGroupName", "proxySecurityGroupName"] as const) {
        if (!NAME.test(cfg[k])) err(`${k} ${cfg[k]} is not a plain name`);
    }
    if (cfg.vmSecurityGroupName === cfg.proxySecurityGroupName) err("vmSecurityGroupName and proxySecurityGroupName must differ");
    if (cfg.vmSecurityGroupName.startsWith(`${cfg.proxySecurityGroupName}-`) || cfg.proxySecurityGroupName.startsWith(`${cfg.vmSecurityGroupName}-`)) {
        err("one security group name must not prefix the other (rule names are <sg name>-…)");
    }

    // The network resources themselves.
    if (spec.vpc.cidr !== cfg.vpcCidr) err(`the VPC's CIDR ${spec.vpc.cidr} is not vpcCidr ${cfg.vpcCidr}`);
    const dns = checkVpcDns(cfg, spec.vpc.enableDnsSupport, spec.vpc.enableDnsHostnames);
    if (dns) err(`VPC: ${dns}`);
    if (spec.dhcp.domainNameServers.join(",") !== cfg.resolvers.join(",")) err(`the DHCP options must name exactly the resolvers ${cfg.resolvers.join(", ")}`);
    if (spec.subnets.proxy.cidr !== cfg.proxySubnetCidr || spec.subnets.vms.cidr !== cfg.vmSubnetCidr) err("the subnets' CIDRs are not the configured ones");
    for (const t of ["proxy", "vms"] as const) {
        const r = checkRoutes(t, spec.routeTables[t].routes);
        if (r) err(r);
    }
    const nacl = checkNacl(cfg, spec.nacl.ingress, spec.nacl.egress);
    if (nacl) err(nacl);
    for (const sg of ["vm", "proxy"] as const) {
        const s = spec.securityGroups[sg];
        const want = sg === "vm" ? [cfg.vmSecurityGroupName, VM_SG_DESCRIPTION] : [cfg.proxySecurityGroupName, PROXY_SG_DESCRIPTION];
        if (s.name !== want[0] || s.description !== want[1]) err(`security group ${s.name}: the name and description are fixed (${want[0]}: ${want[1]})`);
        for (const rule of s.rules) {
            const r = checkRule(cfg, sg, rule);
            if (r) err(r);
        }
        const names = s.rules.map((rule) => ruleName(spec, sg, rule));
        if (new Set(names).size !== names.length) err(`security group ${s.name} lists a rule twice`);
    }
    const vmRules = spec.securityGroups.vm.rules;
    if (vmRules.length !== 1) err(`the VM security group must have exactly one rule (egress TCP ${cfg.proxyPort} to ${proxyCidr(cfg)}), got ${vmRules.length}`);
    const proxyRules = spec.securityGroups.proxy.rules;
    const expectedProxy = 2 + 2 * cfg.resolvers.length;
    const distinct = proxyRules.filter((r, i) => proxyRules.findIndex((o) => sameRule(o, r)) === i);
    if (distinct.length !== expectedProxy || proxyRules.length !== expectedProxy) {
        err(`the proxy security group must have exactly ${expectedProxy} distinct rules (3128 in, 443 out, UDP/TCP 53 to each resolver), got ${proxyRules.length}`);
    }

    if (errors.length > 0) throw new Error(`egress spec (infra/egress-spec.ts, infra/egress-config.json) refused:\n  - ${errors.join("\n  - ")}`);
}

// ---- the inventory: every resource the stack may hold ----

/** Pulumi type → the Pulumi names of its resources (empty: the type is absent). */
export type Inventory = Map<string, string[]>;

/** The image side's names the inventory needs (infra/image-config.json). */
export interface ImageNames {
    imageName: string;
    logGroup: string;
}

/** The names of the two explicit providers (index.ts; default providers are disabled by the stack config). */
export const PROVIDERS = { aws: `aws-${REGION}`, awsNative: `aws-native-${REGION}` } as const;
/** The inputs those providers may carry (their SDK defaults and the env-derived profile): no endpoints, no assumed role, no proxy. */
export const PROVIDER_INPUTS = ["region", "version", "skipCredentialsValidation", "skipRegionValidation", "skipMetadataApiCheck", "skipGetEc2Platforms", "profile",
    "sharedCredentialsFile", "sharedCredentialsFiles", "sharedConfigFiles"];

/**
 * Every resource of the stack, by type and Pulumi name: S3's (index.ts, image.ts, iam.ts, budget.ts) and the egress
 * side's for the configured mode. The guard refuses any resource outside it (CloudFormation stacks, Cloud Control
 * and other generic resources, SSM associations, extra providers, components); check-plan.ts counts the planned
 * resources against it exactly. A resource added to the program must be added here, or the preview fails.
 */
export function stackInventory(cfg: EgressConfig, image: ImageNames): Inventory {
    const firewall = cfg.dnsMode === "firewall";
    const queryLog = firewall && cfg.enableDnsQueryLog;
    const spec = egressSpec(cfg);
    const rules = (dir: "ingress" | "egress") => (["vm", "proxy"] as const).flatMap((sg) => spec.securityGroups[sg].rules.filter((r) => r.direction === dir).map((r) => ruleName(spec, sg, r)));
    const entries: [string, string[]][] = [
        ["pulumi:providers:aws", [PROVIDERS.aws]],
        ["pulumi:providers:aws-native", [PROVIDERS.awsNative]],
        // S3 (plans/s3-plan.md §8, §9).
        ["aws:s3/bucket:Bucket", [BUCKET_PREFIX]],
        ["aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock", [BUCKET_PREFIX]],
        ["aws:s3/bucketObjectv2:BucketObjectv2", ["image-zip"]],
        ["aws:cloudwatch/logGroup:LogGroup", ["image-log-group", NET.logGroup, ...(queryLog ? [NET.dnsLogGroup] : [])]],
        ["aws:iam/role:Role", [BUILD_ROLE_NAME, EXECUTION_ROLE_NAME, cfg.proxyRoleName, cfg.operatorRoleName]],
        ["aws:iam/rolePolicy:RolePolicy", [BUILD_ROLE_NAME, EXECUTION_ROLE_NAME, cfg.proxyRoleName]],
        ["aws:iam/user:User", [RUNTIME_USER_NAME]],
        ["aws:iam/userPolicy:UserPolicy", [RUNTIME_POLICY_NAME]],
        ["aws:iam/policy:Policy", [DEPLOY_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME, DEPLOY_DNS_POLICY_NAME]],
        ["aws-native:lambda:MicrovmImage", [image.imageName]],
        ["aws:budgets/budget:Budget", [BUDGET_NAME]],
        // S5 egress.
        ["aws:ec2/vpc:Vpc", [NET.vpc]],
        ["aws:ec2/vpcDhcpOptions:VpcDhcpOptions", [NET.dhcp]],
        ["aws:ec2/vpcDhcpOptionsAssociation:VpcDhcpOptionsAssociation", [NET.dhcp]],
        ["aws:ec2/internetGateway:InternetGateway", [NET.igw]],
        ["aws:ec2/subnet:Subnet", [NET.proxy, NET.vms]],
        ["aws:ec2/routeTable:RouteTable", [NET.proxy, NET.vms]],
        ["aws:ec2/routeTableAssociation:RouteTableAssociation", [NET.proxy, NET.vms]],
        ["aws:ec2/networkAcl:NetworkAcl", [NET.vms]],
        ["aws:ec2/networkAclAssociation:NetworkAclAssociation", [NET.vms]],
        ["aws:ec2/defaultSecurityGroup:DefaultSecurityGroup", [NET.defaultSecurityGroup]],
        ["aws:ec2/securityGroup:SecurityGroup", [cfg.vmSecurityGroupName, cfg.proxySecurityGroupName]],
        ["aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", rules("ingress")],
        ["aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", rules("egress")],
        ["aws:iam/rolePolicyAttachment:RolePolicyAttachment", [`${cfg.proxyRoleName}-ssm`, cfg.operatorRoleName]],
        ["aws:iam/instanceProfile:InstanceProfile", [cfg.proxyInstanceProfileName]],
        ["aws:ec2/instance:Instance", [NET.instance]],
        ["aws:ssm/parameter:Parameter", PROXY_PARAMETERS.map((p) => `ai-env-proxy-${p}`)],
        ["aws-native:lambda:NetworkConnector", [cfg.connectorName]],
        ["aws:route53/resolverFirewallDomainList:ResolverFirewallDomainList", firewall ? [NET.firewall] : []],
        ["aws:route53/resolverFirewallRuleGroup:ResolverFirewallRuleGroup", firewall ? [NET.firewall] : []],
        ["aws:route53/resolverFirewallRule:ResolverFirewallRule", firewall ? [NET.firewall] : []],
        ["aws:route53/resolverFirewallRuleGroupAssociation:ResolverFirewallRuleGroupAssociation", firewall ? [NET.firewall] : []],
        ["aws:route53/resolverFirewallConfig:ResolverFirewallConfig", firewall ? [NET.vpc] : []],
        ["aws:route53/resolverQueryLogConfig:ResolverQueryLogConfig", queryLog ? [NET.queryLog] : []],
        ["aws:route53/resolverQueryLogConfigAssociation:ResolverQueryLogConfigAssociation", queryLog ? [NET.queryLog] : []],
    ];
    return new Map(entries.filter(([, names]) => names.length > 0));
}

/** Is `name` one of `type`'s resources in the inventory (never a prototype key: the inventory is a Map of arrays)? */
export function inInventory(inventory: Inventory, type: string, name: string): boolean {
    return (inventory.get(type) ?? []).includes(name);
}
