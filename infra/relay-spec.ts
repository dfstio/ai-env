// The relay instance's boot and artifact as data (S13, plans/s13-contracts.md §I-infra.3.2, §I-infra.4.5): the files
// infra/relay/* rendered into its user data (renderRelayFiles), with the relay's own unit and IMDS guard taken from
// crates/ai-env-relay/deploy as they are (R's files, LD-I17: slice I checks only what its layout and the plan's IMDS
// block rest on: RELAY_REQUIRED_LINES, and no GUARD_WEAKENING word in the guard), and the value of the `artifact`
// parameter, which pins the binary its reload unit installs (relayArtifactValue; reload.py checks the same rules on the
// instance).
//
// Why Pulumi-free: relay.ts renders the user data from it, check-plan.ts checks the artifact parameter with it, and the
// offline tests (tests/infra/relay.rs) compile it alone with tsc in seconds. Nothing in the user data is a secret:
// every parameter value reaches the instance through the reload unit, never user data (a user data change replaces the
// instance). reload.py reaches it gzipped from the committed reload.py.gz (LD-I19: plain, the user data is over EC2's
// 16 KiB; compressed at render time, its bytes would follow Node's bundled zlib and replace the relay after a Node
// upgrade), which must decompress to reload.py byte for byte, so the reviewed text is what runs.
import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { EgressConfig, embedded, renderTemplate } from "./egress-spec";
import { BUCKET_PREFIX, RELAY_KEY_PREFIX } from "./policies";

/** infra/relay: the relay's user-data.sh, reload.py (and its .gz) and cloudwatch-agent.json. */
export const RELAY_DIR = path.join(__dirname, "relay");

/** R's deploy files: `<$AI_ENV_REPO_ROOT, default the parent of infra/>/crates/ai-env-relay/deploy` (as loadImageJson resolves). */
export function relayDeployDir(): string {
    const root = path.resolve(process.env.AI_ENV_REPO_ROOT || path.join(__dirname, ".."));
    return path.join(root, "crates", "ai-env-relay", "deploy");
}

/** Every token each template must carry (renderTemplate: a missing one means a value never reaches the instance). */
export const RELAY_TOKENS: Readonly<Record<"user-data.sh" | "cloudwatch-agent.json" | "ai-env-relay.service", readonly string[]>> = {
    "user-data.sh": ["PARAM_PREFIX", "REGION", "RELAY_IP", "RELAY_PORT", "VM_SUBNET_CIDR", "RELOAD_PY_GZ", "CW_AGENT_JSON", "RELAY_UNIT", "GUARD_UNIT", "GUARD_NFT"],
    "cloudwatch-agent.json": ["LOG_GROUP"],
    // R's file, in relayDeployDir().
    "ai-env-relay.service": ["RELAY_IP", "RELAY_PORT"],
};

/**
 * The whole lines (compared trimmed) each of R's files must hold: I's layout (the paths of §I-infra.3.3, the reload
 * unit's SIGHUP) and the plan's IMDS block (the unit's cgroup filter, the guard's owner match, and its two stateless
 * rules: the relay's user sends no SYN without ACK and no packet but TCP, so it opens no connection, LD-I2) rest on
 * them (I-R27). Every other line (the watchdog, the rest of the hardening, the limits) is R's to set and to test.
 */
export const RELAY_REQUIRED_LINES: Readonly<Record<"ai-env-relay.service" | "ai-env-relay-guard.service" | "guard.nft", readonly string[]>> = {
    "ai-env-relay.service": [
        "Requires=ai-env-relay-guard.service", "ConditionPathExists=/var/lib/ai-env-relay/live/tls.pem", "Type=notify", "ExecStart=/usr/local/libexec/ai-env-relay/current",
        "ExecReload=/bin/kill -HUP $MAINPID", "EnvironmentFile=/etc/ai-env-relay/relay.env", "User=ai-env-relay", "Group=ai-env-relay", "NoNewPrivileges=yes",
        "ProtectSystem=strict", "IPAddressDeny=169.254.0.0/16 fd00:ec2::/32", "LogsDirectory=ai-env-relay/requests",
        "StandardOutput=append:/var/log/ai-env-relay/relay.log", "StandardError=append:/var/log/ai-env-relay/relay.log", "WantedBy=multi-user.target",
    ],
    "ai-env-relay-guard.service": ["ExecStart=/usr/sbin/nft -f /etc/ai-env-relay/guard.nft", "RequiredBy=ai-env-relay.service"],
    "guard.nft": [
        "meta skuid \"ai-env-relay\" ip daddr 169.254.0.0/16 counter reject", "meta skuid \"ai-env-relay\" ip6 daddr fd00:ec2::/32 counter reject",
        "meta skuid \"ai-env-relay\" tcp flags & (syn | ack) == syn counter reject with tcp reset", "meta skuid \"ai-env-relay\" meta l4proto != tcp counter reject",
    ],
};

/**
 * The words guard.nft may not hold outside its comments and its chain's `policy accept` (I-R25): a verdict that lets a
 * packet past the rules after it (accept, return, jump, goto, queue: one before the rules voids them), or conntrack
 * (ct, notrack: the guard is stateless, §Q.8 F4). The likely slips, refused at every render; R's deploy test 2 pins
 * every statement of the guard.
 */
const GUARD_WEAKENING = /\b(accept|return|jump|goto|queue|ct|notrack)\b/;

/** What the relay's user data embeds, each as the instance will hold it. */
export interface RelayFiles {
    userData: string;
    reload: string;
    cwAgent: string;
    relayUnit: string;
    guardUnit: string;
    guardNft: string;
}

/** EC2's limit on raw user data. */
const USER_DATA_MAX_BYTES = 16 * 1024;
/** A placeholder of any template (renderTemplate's form). */
const PLACEHOLDER = /@[A-Z_]+@/;

/**
 * The relay's user data and the files it embeds, from infra/relay (`dir`), R's deploy files (`deployDir`) and the
 * config; throws on: a leftover placeholder (none is kept); a CloudWatch file that is not JSON; a reload.py.gz that
 * does not decompress to reload.py byte for byte; a file of R's missing, carrying a placeholder it should not, or
 * without one of its RELAY_REQUIRED_LINES as a whole line; a GUARD_WEAKENING word in guard.nft; a heredoc delimiter of
 * user-data.sh in a file it embeds as text (the heredoc would end early; base64 cannot hold one); user data over EC2's
 * 16 384 bytes.
 */
export function renderRelayFiles(cfg: EgressConfig, region: string, dir = RELAY_DIR, deployDir = relayDeployDir()): RelayFiles {
    const read = (d: string, file: string): string => {
        const p = path.join(d, file);
        if (!fs.existsSync(p)) throw new Error(`${p} not found (the relay's ${d === dir ? "boot files, infra/relay" : "unit and IMDS guard, crates/ai-env-relay/deploy"})`);
        return fs.readFileSync(p, "utf-8");
    };
    const noPlaceholder = (d: string, file: string, text: string) => {
        const hit = PLACEHOLDER.exec(text);
        if (hit) throw new Error(`${path.join(d, file)}: holds the placeholder ${hit[0]}, which nothing fills`);
    };

    const cwAgent = renderTemplate(dir, "cloudwatch-agent.json", RELAY_TOKENS["cloudwatch-agent.json"], { LOG_GROUP: cfg.relayLogGroup });
    try {
        JSON.parse(cwAgent);
    } catch (e) {
        throw new Error(`${path.join(dir, "cloudwatch-agent.json")}: not JSON after rendering: ${(e as Error).message}`);
    }

    const reload = read(dir, "reload.py");
    noPlaceholder(dir, "reload.py", reload);
    const gz = fs.readFileSync(path.join(dir, "reload.py.gz"));
    let unzipped: Buffer | undefined;
    try {
        unzipped = zlib.gunzipSync(gz);
    } catch {
        unzipped = undefined;
    }
    if (unzipped === undefined || !unzipped.equals(Buffer.from(reload, "utf-8"))) {
        throw new Error(`${path.join(dir, "reload.py.gz")} is not reload.py compressed: run make relay-reload-gz`);
    }

    read(deployDir, "ai-env-relay.service");
    const relayUnit = renderTemplate(deployDir, "ai-env-relay.service", RELAY_TOKENS["ai-env-relay.service"], { RELAY_IP: cfg.relayIp, RELAY_PORT: String(cfg.relayPort) });
    const guardUnit = read(deployDir, "ai-env-relay-guard.service");
    noPlaceholder(deployDir, "ai-env-relay-guard.service", guardUnit);
    const guardNft = read(deployDir, "guard.nft");
    noPlaceholder(deployDir, "guard.nft", guardNft);
    const r: Record<keyof typeof RELAY_REQUIRED_LINES, string> = { "ai-env-relay.service": relayUnit, "ai-env-relay-guard.service": guardUnit, "guard.nft": guardNft };
    for (const [file, text] of Object.entries(r) as [keyof typeof RELAY_REQUIRED_LINES, string][]) {
        const lines = new Set(text.split("\n").map((l) => l.trim()));
        for (const want of RELAY_REQUIRED_LINES[file]) {
            if (!lines.has(want)) throw new Error(`${path.join(deployDir, file)}: the line "${want}" is missing: slice I's layout or the plan's IMDS block rests on it (plans/s13-contracts.md §I-infra.4.5)`);
        }
    }
    for (const line of guardNft.split("\n")) {
        const hit = GUARD_WEAKENING.exec(line.replace(/#.*/, "").replace(/\bpolicy\s+accept\b/, ""));
        if (hit) throw new Error(`${path.join(deployDir, "guard.nft")}: the line "${line.trim()}" holds "${hit[1]}": the guard takes no verdict but its chain's policy (one before the rules lets the relay's user past them) and no conntrack (§Q.8 F4) (plans/s13-contracts.md §I-infra.4.5)`);
    }

    const template = read(dir, "user-data.sh");
    const delimiters = [...template.matchAll(/<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/g)].map((m) => m[2]);
    for (const [d, file, body] of [[dir, "cloudwatch-agent.json", cwAgent], [deployDir, "ai-env-relay.service", relayUnit], [deployDir, "ai-env-relay-guard.service", guardUnit], [deployDir, "guard.nft", guardNft]]) {
        const hit = delimiters.find((x) => body.includes(x));
        if (hit !== undefined) throw new Error(`${path.join(d, file)} contains ${hit}, a heredoc delimiter of user-data.sh: the embedded copy would end early`);
    }
    const base64 = gz.toString("base64").replace(/(.{76})/g, "$1\n").replace(/\n$/, "");
    const userData = renderTemplate(dir, "user-data.sh", RELAY_TOKENS["user-data.sh"], {
        PARAM_PREFIX: cfg.relayParameterPrefix, REGION: region, RELAY_IP: cfg.relayIp, RELAY_PORT: String(cfg.relayPort), VM_SUBNET_CIDR: cfg.vmSubnetCidr,
        RELOAD_PY_GZ: base64, CW_AGENT_JSON: embedded(cwAgent), RELAY_UNIT: embedded(relayUnit), GUARD_UNIT: embedded(guardUnit), GUARD_NFT: embedded(guardNft),
    });
    const bytes = Buffer.byteLength(userData, "utf-8");
    if (bytes > USER_DATA_MAX_BYTES) throw new Error(`${path.join(dir, "user-data.sh")}: rendered ${bytes} bytes, over EC2's ${USER_DATA_MAX_BYTES}-byte user data limit`);
    return { userData, reload, cwAgent, relayUnit, guardUnit, guardNft };
}

// ---- the artifact parameter ----

/** The relay binary's key in the artifacts bucket (`make relay-artifact`: the first 16 hex digits of its SHA-256). */
export const RELAY_KEY_RE = /^relay\/ai-env-relay-[0-9a-f]{16}$/;

/** What the `<relayParameterPrefix>/artifact` parameter pins: the object, its SHA-256 and the workspace version. */
export interface RelayArtifact {
    bucket: string;
    key: string;
    sha256: string;
    version: string;
}

const ARTIFACT_KEYS = ["bucket", "key", "sha256", "version"] as const;
const ARTIFACT_BUCKET_RE = new RegExp(`^${BUCKET_PREFIX}-[a-z0-9-]{1,46}$`);
const VERSION_RE = /^[0-9A-Za-z.+-]{1,32}$/;

/** Why `a` is not an artifact value (reload.py's rules, I-R31), or undefined. */
function artifactProblem(a: Record<string, unknown>): string | undefined {
    const keys = Object.keys(a);
    if (JSON.stringify(keys.slice().sort()) !== JSON.stringify([...ARTIFACT_KEYS].sort())) return `the artifact value holds ${keys.join(", ") || "no key"}, not exactly ${ARTIFACT_KEYS.join(", ")}`;
    const { bucket, key, sha256, version } = a;
    if (typeof bucket !== "string" || !ARTIFACT_BUCKET_RE.test(bucket)) return `bucket ${JSON.stringify(bucket)} is not ${BUCKET_PREFIX}-<suffix>`;
    if (typeof key !== "string" || !RELAY_KEY_RE.test(key)) return `key ${JSON.stringify(key)} is not ${RELAY_KEY_PREFIX}<sha256[:16]>`;
    if (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256)) return `sha256 ${JSON.stringify(sha256)} is not 64 lowercase hex digits`;
    if (key !== `${RELAY_KEY_PREFIX}${sha256.slice(0, 16)}`) return `key ${key} does not end in the sha256's first 16 hex digits (${sha256.slice(0, 16)})`;
    if (typeof version !== "string" || !VERSION_RE.test(version)) return `version ${JSON.stringify(version)} is not 1 to 32 of 0-9 A-Z a-z . + -`;
    return undefined;
}

/** The `<relayParameterPrefix>/artifact` value: JSON of exactly bucket, key, sha256, version, in that order; throws why not. */
export function relayArtifactValue(a: RelayArtifact): string {
    const problem = artifactProblem({ ...a });
    if (problem !== undefined) throw new Error(`relay artifact: ${problem}`);
    return JSON.stringify({ bucket: a.bucket, key: a.key, sha256: a.sha256, version: a.version });
}

/** The value parsed and checked as relayArtifactValue checks it; a string is the reason it is not one. */
export function parseRelayArtifactValue(text: string): RelayArtifact | string {
    let v: unknown;
    try {
        v = JSON.parse(text);
    } catch (e) {
        return `not JSON (${(e as Error).message})`;
    }
    if (v === null || typeof v !== "object" || Array.isArray(v)) return "not a JSON object";
    const problem = artifactProblem(v as Record<string, unknown>);
    if (problem !== undefined) return problem;
    const a = v as RelayArtifact;
    return { bucket: a.bucket, key: a.key, sha256: a.sha256, version: a.version };
}
