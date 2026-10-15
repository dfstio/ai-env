// IAM of the stack (plans/s3-plan.md §9, plans/s8-operators-plan.md §1): the build role the image builder assumes, the
// execution role passed at run-microvm, the runtime user ai-env-runtime with MacRuntimePolicy, the operator users
// ai-env-deployer and ai-env-ops, and the stack's five customer-managed policies with the six attachments that bind
// them: ai-env-deployer holds ai-env-deploy, ai-env-deploy-egress, ai-env-deploy-dns, its supplement ai-env-deployer
// and ai-env-ops; ai-env-ops holds ai-env-ops alone.
//
// Why: credentials never enter Pulumi (D17, D23). The three users are created without an access key, with forceDestroy
// (so `make destroy`, which only the account root runs, also removes the keys issued out of band) and nothing else:
// `make runtime-key` and `make ops-key` seal the runtime and ops keys with `ai-env creds aws-set`, and the deployer's
// key goes to Strongbox through `ai-env creds deployer-key` (`make operator-keys` the first time, as the account root).
// No key, login profile, group, PolicyAttachment or UserPolicyAttachmentsExclusive ever exists here; the guard and the
// plan check refuse each. The deployer is admin-equivalent inside the account (it versions its own policies), not a
// boundary: the protection is its offline key. A managed policy's description cannot change in place (a change
// replaces the policy), so the descriptions are frozen in policies.ts POLICY_DESCRIPTIONS since the bootstrap. The
// documents themselves are pure functions in policies.ts, shared with `make check-policies`. The scratch:exec-role,
// scratch:runtime-user, scratch:deployer-user, scratch:attach-user and scratch:attach markers are edited by `make
// preview-scratch` (NEGATIVE=iam-widen and identity-widen) in a scratch copy.
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import {
    BUILD_ROLE_NAME, DEPLOYER_POLICY_NAME, DEPLOYER_USER_NAME, DEPLOY_DNS_POLICY_NAME, DEPLOY_EGRESS_POLICY_NAME, DEPLOY_POLICY_NAME, EXECUTION_ROLE_NAME, Names,
    OPS_POLICY_NAME, OPS_USER_NAME, PolicyDocument, RUNTIME_POLICY_NAME, RUNTIME_USER_NAME, USER_POLICY_ATTACHMENTS, attachmentName, buildRolePolicy, deployDnsPolicy,
    deployEgressPolicy, deployPolicy, deployerPolicy, executionRolePolicy, lambdaTrustPolicy, opsPolicy, policyDescription, runtimePolicy,
} from "./policies";

export interface Iam {
    buildRole: aws.iam.Role;
    buildPolicy: aws.iam.RolePolicy;
    executionRole: aws.iam.Role;
    executionPolicy: aws.iam.RolePolicy;
    runtimeUser: aws.iam.User;
    runtimePolicy: aws.iam.UserPolicy;
    deployPolicy: aws.iam.Policy;
    deployEgressPolicy: aws.iam.Policy;
    deployDnsPolicy: aws.iam.Policy;
    /** S8 operators. */
    deployerUser: aws.iam.User;
    opsUser: aws.iam.User;
    deployerPolicy: aws.iam.Policy;
    opsPolicy: aws.iam.Policy;
    attachments: aws.iam.UserPolicyAttachment[];
}

function render(names: pulumi.Output<Names>, build: (n: Names) => PolicyDocument): pulumi.Output<string> {
    return names.apply((n) => JSON.stringify(build(n)));
}

/**
 * Three names objects carry what exists only once the egress stack created it, so each document waits for exactly the
 * resources it names: `deployNames` the VM subnet and security group ids (the deploy policy's CreateNetworkConnector
 * condition, S5), `runtimeNames` the connector's ARN (the runtime policy's ReadTheEgressConnector, S7 D5), `opsNames`
 * the proxy instance's id (the ops policy's ProxyInstance and ProxyCommands, S8 operators).
 */
export function createIam(
    names: pulumi.Output<Names>, deployNames: pulumi.Output<Names>, runtimeNames: pulumi.Output<Names>, opsNames: pulumi.Output<Names>,
    tags: Record<string, string>, provider: aws.Provider,
): Iam {
    const opts = { provider };
    const trust = JSON.stringify(lambdaTrustPolicy());

    const buildRole = new aws.iam.Role(BUILD_ROLE_NAME, {
        name: BUILD_ROLE_NAME, description: "ai-env MicroVM image builder: reads the image zip, writes the build log", assumeRolePolicy: trust, tags,
    }, opts);
    const buildPolicy = new aws.iam.RolePolicy(BUILD_ROLE_NAME, { name: BUILD_ROLE_NAME, role: buildRole.id, policy: render(names, buildRolePolicy) }, opts);

    const executionRole = new aws.iam.Role(EXECUTION_ROLE_NAME, {
        name: EXECUTION_ROLE_NAME, description: "ai-env MicroVM execution role (run-microvm): runtime logs only", assumeRolePolicy: trust, tags, // scratch:exec-role
    }, opts);
    const executionPolicy = new aws.iam.RolePolicy(EXECUTION_ROLE_NAME, { name: EXECUTION_ROLE_NAME, role: executionRole.id, policy: render(names, executionRolePolicy) }, opts);

    // No aws.iam.AccessKey here, ever (D17, D23): every key is issued out of band (make runtime-key, make ops-key,
    // make operator-keys / deployer-key) and never appears in config, outputs or state.
    const user = (name: string, extra: pulumi.CustomResourceOptions = {}) => new aws.iam.User(name, { name, forceDestroy: true, tags }, { ...opts, ...extra });
    const runtimeUser = user(RUNTIME_USER_NAME);
    const opsUser = user(OPS_USER_NAME);
    const runtime = new aws.iam.UserPolicy(RUNTIME_POLICY_NAME, { name: RUNTIME_POLICY_NAME, user: runtimeUser.name, policy: render(runtimeNames, runtimePolicy) }, opts); // scratch:runtime-user

    const managed = (name: string, policy: pulumi.Output<string>) => new aws.iam.Policy(name, { name, description: policyDescription(name), policy, tags }, opts);
    const deploy = managed(DEPLOY_POLICY_NAME, render(deployNames, deployPolicy));
    const deployEgress = managed(DEPLOY_EGRESS_POLICY_NAME, render(names, deployEgressPolicy));
    const deployDns = managed(DEPLOY_DNS_POLICY_NAME, render(names, deployDnsPolicy));
    const deployer = managed(DEPLOYER_POLICY_NAME, render(names, deployerPolicy));
    const ops = managed(OPS_POLICY_NAME, render(opsNames, opsPolicy));
    // ai-env-deployer comes into being only once its five policies exist, with their frozen descriptions: check-plan
    // reads "the bootstrap is over" from that user in the old state (D12), so a bootstrap that failed before its deploy
    // policies were replaced is still the bootstrap when it runs again.
    const deployerUser = user(DEPLOYER_USER_NAME, { dependsOn: [deploy, deployEgress, deployDns, deployer, ops] }); // scratch:deployer-user

    // Exactly USER_POLICY_ATTACHMENTS, each named `<user>--<policy>`, binding the stack's user to the stack's policy.
    // Maps, never object literals: a name like `constructor` must not find Object.prototype's.
    const users = new Map<string, aws.iam.User>([[DEPLOYER_USER_NAME, deployerUser], [OPS_USER_NAME, opsUser]]);
    const policies = new Map<string, aws.iam.Policy>([
        [DEPLOY_POLICY_NAME, deploy], [DEPLOY_EGRESS_POLICY_NAME, deployEgress], [DEPLOY_DNS_POLICY_NAME, deployDns], [DEPLOYER_POLICY_NAME, deployer], [OPS_POLICY_NAME, ops],
    ]);
    const attachments = USER_POLICY_ATTACHMENTS.map(([u, p]) => {
        const holder = users.get(u), held = policies.get(p);
        if (holder === undefined || held === undefined) throw new Error(`iam.ts: the attachment ${attachmentName(u, p)} names a user or policy the stack does not create`);
        return new aws.iam.UserPolicyAttachment(attachmentName(u, p), {
            user: holder.name, // scratch:attach-user
            policyArn: held.arn, // scratch:attach
        }, opts);
    });

    return {
        buildRole, buildPolicy, executionRole, executionPolicy, runtimeUser, runtimePolicy: runtime, deployPolicy: deploy, deployEgressPolicy: deployEgress, deployDnsPolicy: deployDns,
        deployerUser, opsUser, deployerPolicy: deployer, opsPolicy: ops, attachments,
    };
}
