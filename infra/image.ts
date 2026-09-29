// The image side of the stack: the artifacts bucket with the hash-keyed zip, the log group and the aws-native
// MicrovmImage `ai-env-agent`.
//
// Why this shape: every image parameter comes from one file, image-config.json (D19; a Rust test asserts it
// against the shim's hook table), and the zip identity comes from image.json, written by `make image-zip`. The 12
// MicrovmImage inputs are write-only (refresh cannot see drift, only a changed value rebuilds), so the description
// is a constant and the only input that moves between deploys is codeArtifact.uri, keyed by the zip's sha256.
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsnative from "@pulumi/aws-native";
import { BUCKET_PREFIX, ZIP_KEY_PREFIX, internetEgressConnectorArn } from "./policies";

type HookState = awsnative.types.enums.lambda.MicrovmImageHookState;
type Capability = awsnative.types.enums.lambda.MicrovmImageAdditionalOsCapabilitiesItem;
type Architecture = awsnative.types.enums.lambda.MicrovmImageCpuConfigurationArchitecture;

const ENABLED: HookState = awsnative.types.enums.lambda.MicrovmImageHookState.Enabled;
const CAPABILITIES: readonly string[] = Object.values(awsnative.types.enums.lambda.MicrovmImageAdditionalOsCapabilitiesItem);
const ARCHITECTURES: readonly string[] = Object.values(awsnative.types.enums.lambda.MicrovmImageCpuConfigurationArchitecture);
/** IAM is eventually consistent: a build role and policy created a moment ago can still be refused by the builder. */
const IAM_PROPAGATION_MS = 15_000;

export interface Hooks {
    port: number;
    runTimeoutSeconds: number;
    resumeTimeoutSeconds: number;
    suspendTimeoutSeconds: number;
    terminateTimeoutSeconds: number;
    readyTimeoutSeconds: number;
    validateTimeoutSeconds: number;
}

export interface ImageConfig {
    imageName: string;
    description: string;
    baseImage: { name: string; version: string };
    architecture: Architecture;
    memoryMiB: number;
    additionalOsCapabilities: Capability[];
    hooks: Hooks;
    logGroup: string;
    logRetentionDays: number;
}

/** What `make image-zip` wrote; `zipPath` is resolved to an absolute path. */
export interface ImageJson {
    zip: string;
    zipPath: string;
    /** The verified, content-addressed, read-only copy the upload reads (`<dir of image.json>/upload/<sha256>.zip`). */
    uploadPath: string;
    sha256: string;
    key: string;
    claudeVersion: string;
    shimVersion: string;
}

function fail(file: string, what: string): never {
    throw new Error(`${file}: ${what}`);
}

function str(file: string, v: unknown, field: string): string {
    if (typeof v !== "string" || v.length === 0) fail(file, `${field} must be a non-empty string`);
    return v;
}

function int(file: string, v: unknown, field: string): number {
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) fail(file, `${field} must be a positive integer`);
    return v;
}

/** infra/image-config.json, validated field by field (a typo must stop the program, not reach the service). */
export function loadImageConfig(file = path.join(__dirname, "image-config.json")): ImageConfig {
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    const h = raw.hooks ?? fail(file, "hooks missing");
    const caps: unknown = raw.additionalOsCapabilities;
    if (!Array.isArray(caps) || caps.some((c) => !CAPABILITIES.includes(c))) fail(file, `additionalOsCapabilities must be a list of ${CAPABILITIES.join(", ")}`);
    if (!ARCHITECTURES.includes(raw.architecture)) fail(file, `architecture must be one of ${ARCHITECTURES.join(", ")}`);
    return {
        imageName: str(file, raw.imageName, "imageName"),
        description: str(file, raw.description, "description"),
        baseImage: { name: str(file, raw.baseImage?.name, "baseImage.name"), version: str(file, raw.baseImage?.version, "baseImage.version") },
        architecture: raw.architecture as Architecture,
        memoryMiB: int(file, raw.memoryMiB, "memoryMiB"),
        additionalOsCapabilities: caps as Capability[],
        hooks: {
            port: int(file, h.port, "hooks.port"),
            runTimeoutSeconds: int(file, h.runTimeoutSeconds, "hooks.runTimeoutSeconds"),
            resumeTimeoutSeconds: int(file, h.resumeTimeoutSeconds, "hooks.resumeTimeoutSeconds"),
            suspendTimeoutSeconds: int(file, h.suspendTimeoutSeconds, "hooks.suspendTimeoutSeconds"),
            terminateTimeoutSeconds: int(file, h.terminateTimeoutSeconds, "hooks.terminateTimeoutSeconds"),
            readyTimeoutSeconds: int(file, h.readyTimeoutSeconds, "hooks.readyTimeoutSeconds"),
            validateTimeoutSeconds: int(file, h.validateTimeoutSeconds, "hooks.validateTimeoutSeconds"),
        },
        logGroup: str(file, raw.logGroup, "logGroup"),
        logRetentionDays: int(file, raw.logRetentionDays, "logRetentionDays"),
    };
}

function sha256Of(bytes: Buffer): string {
    return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * The upload source: a content-addressed copy `<dir>/<sha256>.zip` of bytes already hashed in memory, created
 * exclusively (a complete temporary file hard-linked into place, mode 0444) or reused when it is already there as a
 * regular file with the same hash, and hashed again from disk. Why: the FileAsset reads its path again at upload
 * time, and `make image-zip` rewrites image.zip in place; this path is never rewritten, so what was verified is what
 * gets uploaded. The only thing the program writes, also under `pulumi preview`.
 */
function uploadCopy(file: string, bytes: Buffer, sha256: string, dir: string): string {
    fs.mkdirSync(dir, { recursive: true });
    const copy = path.join(dir, `${sha256}.zip`);
    if (!fs.existsSync(copy)) {
        const tmp = path.join(dir, `.${sha256}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
        try {
            fs.writeFileSync(tmp, bytes, { flag: "wx", mode: 0o444 });
            fs.linkSync(tmp, copy);
        } catch (e) {
            // Another run created it meanwhile: fall through and verify that one.
            if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        } finally {
            fs.rmSync(tmp, { force: true });
        }
    }
    if (!fs.lstatSync(copy).isFile()) fail(file, `${copy} is not a regular file: remove it and rerun`);
    const again = sha256Of(fs.readFileSync(copy));
    if (again !== sha256) fail(file, `${copy} has sha256 ${again}, not ${sha256}: remove it and rerun`);
    return copy;
}

/**
 * image.json from $IMAGE_JSON (default target/image/image.json). A relative $IMAGE_JSON and the paths inside the
 * file are relative to the repo root ($AI_ENV_REPO_ROOT, default the parent of infra/; the scratch preview runs
 * from a copy, so the Makefile passes both). The zip is hashed again: a stale image.json must not upload a zip
 * under another zip's key. The upload then reads a verified copy (uploadCopy), not the zip itself.
 */
export function loadImageJson(): ImageJson {
    const root = path.resolve(process.env.AI_ENV_REPO_ROOT || path.join(__dirname, ".."));
    const file = path.resolve(root, process.env.IMAGE_JSON || path.join("target", "image", "image.json"));
    if (!fs.existsSync(file)) throw new Error(`${file} not found: run make image-zip (it builds the zip and writes image.json)`);
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    const sha256 = str(file, raw.sha256, "sha256");
    if (!/^[0-9a-f]{64}$/.test(sha256)) fail(file, "sha256 must be 64 lowercase hex digits");
    const key = str(file, raw.key, "key");
    const want = `${ZIP_KEY_PREFIX}${sha256.slice(0, 16)}.zip`;
    if (key !== want) fail(file, `key ${key} does not match the sha256 (expected ${want}): run make image-zip`);
    const version = /^[A-Za-z0-9._-]+$/;
    const claudeVersion = str(file, raw.claudeVersion, "claudeVersion");
    const shimVersion = str(file, raw.shimVersion, "shimVersion");
    if (!version.test(claudeVersion) || !version.test(shimVersion)) fail(file, "claudeVersion and shimVersion must match [A-Za-z0-9._-]+");
    const zip = str(file, raw.zip, "zip");
    const zipPath = path.resolve(root, zip);
    if (!fs.existsSync(zipPath)) fail(file, `${zipPath} not found: run make image-zip`);
    // Read once: the bytes hashed here are the bytes copied for the upload.
    const bytes = fs.readFileSync(zipPath);
    const actual = sha256Of(bytes);
    if (actual !== sha256) fail(file, `${zipPath} has sha256 ${actual}, not the recorded one: image.json is stale, run make image-zip`);
    const uploadPath = uploadCopy(file, bytes, sha256, path.join(path.dirname(file), "upload"));
    return { zip, zipPath, uploadPath, sha256, key, claudeVersion, shimVersion };
}

export interface Artifacts {
    bucket: aws.s3.Bucket;
    zip: aws.s3.BucketObjectv2;
    logGroup: aws.cloudwatch.LogGroup;
}

/** Private bucket (auto-named `ai-env-artifacts-<random>`), the zip under its hash key, the one log group. */
export function createArtifacts(cfg: ImageConfig, image: ImageJson, tags: Record<string, string>, provider: aws.Provider): Artifacts {
    const bucket = new aws.s3.Bucket(BUCKET_PREFIX, { forceDestroy: true, tags }, { provider });
    const publicAccess = new aws.s3.BucketPublicAccessBlock(BUCKET_PREFIX, {
        bucket: bucket.id, blockPublicAcls: true, blockPublicPolicy: true, ignorePublicAcls: true, restrictPublicBuckets: true,
    }, { provider });
    // A new zip is a new key, hence a replacement: the new object exists before the image update, the old one
    // is deleted after it.
    const zip = new aws.s3.BucketObjectv2("image-zip", {
        bucket: bucket.id, key: image.key, source: new pulumi.asset.FileAsset(image.uploadPath), contentType: "application/zip", tags,
    }, { provider, dependsOn: [publicAccess] });
    // Created before the image (D21) so the platform never creates it without retention.
    const logGroup = new aws.cloudwatch.LogGroup("image-log-group", { name: cfg.logGroup, retentionInDays: cfg.logRetentionDays, tags }, { provider });
    return { bucket, zip, logGroup };
}

export interface ImageDeps {
    buildRole: aws.iam.Role;
    buildPolicy: aws.iam.RolePolicy;
    artifacts: Artifacts;
}

/** The MicrovmImage with all 12 inputs (plans/s3-plan.md §8). */
export function createImage(cfg: ImageConfig, region: string, tags: Record<string, string>, deps: ImageDeps, provider: awsnative.Provider): awsnative.lambda.MicrovmImage {
    const { buildRole, buildPolicy, artifacts } = deps;
    // Only on real updates: a preview never waits (and never has a known ARN for a new role anyway).
    const buildRoleArn = pulumi.all([buildRole.arn, buildPolicy.id]).apply(async ([arn]) => {
        if (!pulumi.runtime.isDryRun()) await new Promise((resolve) => setTimeout(resolve, IAM_PROPAGATION_MS));
        return arn;
    });
    const h = cfg.hooks;
    // The scratch:* markers are edited by `make preview-scratch NEGATIVE=no-logging|no-logging-cast` in a scratch
    // copy: drop `logging`, hide that behind `as any`, then also bypass the SDK's own required-input guard.
    const imageArgs: awsnative.lambda.MicrovmImageArgs = { // scratch:open
        name: cfg.imageName,
        description: cfg.description,
        additionalOsCapabilities: cfg.additionalOsCapabilities,
        baseImageArn: `arn:aws:lambda:${region}:aws:microvm-image:${cfg.baseImage.name}`,
        baseImageVersion: cfg.baseImage.version,
        buildRoleArn,
        codeArtifact: { uri: pulumi.interpolate`s3://${artifacts.bucket.bucket}/${artifacts.zip.key}` },
        cpuConfigurations: [{ architecture: cfg.architecture }],
        egressNetworkConnectors: [internetEgressConnectorArn(region)],
        // Baked into the snapshot: never anything.
        environmentVariables: [],
        hooks: {
            port: h.port,
            microvmHooks: {
                run: ENABLED, runTimeoutInSeconds: h.runTimeoutSeconds,
                resume: ENABLED, resumeTimeoutInSeconds: h.resumeTimeoutSeconds,
                suspend: ENABLED, suspendTimeoutInSeconds: h.suspendTimeoutSeconds,
                terminate: ENABLED, terminateTimeoutInSeconds: h.terminateTimeoutSeconds,
            },
            microvmImageHooks: {
                ready: ENABLED, readyTimeoutInSeconds: h.readyTimeoutSeconds,
                validate: ENABLED, validateTimeoutInSeconds: h.validateTimeoutSeconds,
            },
        },
        logging: { cloudWatch: { logGroup: artifacts.logGroup.name } }, // scratch:logging
        resources: [{ minimumMemoryInMiB: cfg.memoryMiB }],
        tags: Object.entries(tags).map(([key, value]) => ({ key, value })),
    }; // scratch:close
    return new awsnative.lambda.MicrovmImage(cfg.imageName, imageArgs, { // scratch:new
        provider,
        dependsOn: [artifacts.logGroup, buildPolicy, artifacts.zip],
    });
}
