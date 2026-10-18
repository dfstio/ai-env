// The S9 transcript store (plans/s9-plan.md §5, plans/s9-contracts.md §7.1, §7.2, §7.4): the bucket
// ai-env-transcripts-<accountId> where a remote chat's transcript is kept (never on the Mac), with its six settings, each
// a resource of its own under the bucket's Pulumi name (the non-V2 S3 types of @pulumi/aws 7.10.0): versioning (a
// segment or base is written new-only, If-None-Match: *, so an object never changes; old versions expire after 30
// days), SSE-S3 (no KMS: the runtime principal presigns reads, so a key would not change who can read, only add key
// lifecycle to `make destroy`), ownership BucketOwnerEnforced (no ACLs), the four public access blocks, the lifecycle
// and the bucket policy (policies.ts transcriptsBucketPolicy: Deny only, every object read and the VM's writes through
// the S3 gateway endpoint alone, the Mac's writes never through it, no principal but the runtime user).
//
// Why a fixed name: the allowlist line (egress-spec.ts allowValue) and the policies are exact strings at preview time.
// forceDestroy: `make destroy` deletes the bucket (the guard rules; the deployer's TranscriptsObjectsDestroy). No
// Pulumi protect, retainOnDelete or deletedWith (the guard refuses each). The scratch:bucket-policy marker is edited
// by `make preview-scratch NEGATIVE=bucket-policy-no-vpce` in a scratch copy.
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import type { EgressGuard } from "./egress";
import { EGRESS_CHECK_PREFIX, TRANSCRIPTS_RESOURCE, transcriptsBucketName, transcriptsBucketPolicy } from "./policies";

/** The lifecycle rules (contracts §7.2): current versions never expire by age (`ai-env session gc --remote` removes them). */
export const TRANSCRIPTS_LIFECYCLE = [
    { id: "abort-multipart", status: "Enabled", filter: {}, abortIncompleteMultipartUpload: { daysAfterInitiation: 1 } },
    { id: "noncurrent-30-days", status: "Enabled", filter: {}, noncurrentVersionExpiration: { noncurrentDays: 30 }, expiration: { expiredObjectDeleteMarker: true } },
    { id: "egress-check-1-day", status: "Enabled", filter: { prefix: EGRESS_CHECK_PREFIX }, expiration: { days: 1 } },
];

export interface Transcripts {
    bucket: aws.s3.Bucket;
    versioning: aws.s3.BucketVersioning;
    encryption: aws.s3.BucketServerSideEncryptionConfiguration;
    ownership: aws.s3.BucketOwnershipControls;
    publicAccess: aws.s3.BucketPublicAccessBlock;
    lifecycle: aws.s3.BucketLifecycleConfiguration;
    policy: aws.s3.BucketPolicy;
    /** The bucket policy's document as the program writes it (index.ts hashes it for `ai-env egress status`). */
    policyDocument: pulumi.Output<string>;
}

/**
 * The bucket and its settings, every one named `ai-env-transcripts`. The bucket's name is the account's
 * (transcriptsBucketName of `accountId`, known in a preview); `endpointId` is the S3 gateway endpoint's id (egress.ts),
 * which the bucket policy's `aws:SourceVpce` conditions name, so the policy is built from that very resource
 * (check-plan holds the dependency).
 */
export function createTranscripts(guard: EgressGuard, accountId: pulumi.Output<string>, endpointId: pulumi.Output<string>, tags: Record<string, string>, provider: aws.Provider): Transcripts {
    const opts = { provider };
    const bucket = new aws.s3.Bucket(TRANSCRIPTS_RESOURCE, { bucket: accountId.apply(transcriptsBucketName), forceDestroy: true, tags }, opts);
    guard.track("transcripts", bucket.id);
    const versioning = new aws.s3.BucketVersioning(TRANSCRIPTS_RESOURCE, { bucket: bucket.id, versioningConfiguration: { status: "Enabled" } }, opts);
    const encryption = new aws.s3.BucketServerSideEncryptionConfiguration(TRANSCRIPTS_RESOURCE, {
        bucket: bucket.id, rules: [{ applyServerSideEncryptionByDefault: { sseAlgorithm: "AES256" } }],
    }, opts);
    const ownership = new aws.s3.BucketOwnershipControls(TRANSCRIPTS_RESOURCE, { bucket: bucket.id, rule: { objectOwnership: "BucketOwnerEnforced" } }, opts);
    const publicAccess = new aws.s3.BucketPublicAccessBlock(TRANSCRIPTS_RESOURCE, {
        bucket: bucket.id, blockPublicAcls: true, blockPublicPolicy: true, ignorePublicAcls: true, restrictPublicBuckets: true,
    }, opts);
    // Noncurrent-version rules apply to a versioned bucket: versioning first.
    const lifecycle = new aws.s3.BucketLifecycleConfiguration(TRANSCRIPTS_RESOURCE, { bucket: bucket.id, rules: TRANSCRIPTS_LIFECYCLE }, { ...opts, dependsOn: [versioning] });
    const policyDocument = pulumi.all([accountId, endpointId]).apply(([acct, s3EndpointId]) => JSON.stringify(transcriptsBucketPolicy({ accountId: acct, transcriptsBucket: transcriptsBucketName(acct), s3EndpointId }))); // scratch:bucket-policy
    // The public access block first: a bucket policy with Principal "*" is judged against it (BlockPublicPolicy), and ours
    // is Deny only, which the block allows.
    const policy = new aws.s3.BucketPolicy(TRANSCRIPTS_RESOURCE, { bucket: bucket.id, policy: policyDocument }, { ...opts, dependsOn: [publicAccess, ownership] });
    return { bucket, versioning, encryption, ownership, publicAccess, lifecycle, policy, policyDocument };
}
