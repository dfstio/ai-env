// IAM of the stack (plans/s3-plan.md §9): the build role the image builder assumes, the execution role passed at
// run-microvm, the runtime user ai-env-runtime with MacRuntimePolicy, and the customer-managed ai-env-deploy.
//
// Why: runtime credentials never enter Pulumi (D23). The user is created without an access key and with
// forceDestroy, so `make destroy` also removes the key `make runtime-key` created out of band; the key itself is
// sealed by `ai-env creds aws-set` and never appears in config, outputs or state. ai-env-deploy is attached to
// nothing (`rust` is an administrator); it records what a non-administrator deployer would need for everything
// except creating, changing or deleting ai-env-deploy itself, which needs an administrator. The documents
// themselves are pure functions in policies.ts, shared with `make check-policies`.
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import {
    BUILD_ROLE_NAME, DEPLOY_POLICY_NAME, EXECUTION_ROLE_NAME, Names, PolicyDocument, RUNTIME_POLICY_NAME, RUNTIME_USER_NAME,
    buildRolePolicy, deployPolicy, executionRolePolicy, lambdaTrustPolicy, runtimePolicy,
} from "./policies";

export interface Iam {
    buildRole: aws.iam.Role;
    buildPolicy: aws.iam.RolePolicy;
    executionRole: aws.iam.Role;
    executionPolicy: aws.iam.RolePolicy;
    runtimeUser: aws.iam.User;
    runtimePolicy: aws.iam.UserPolicy;
    deployPolicy: aws.iam.Policy;
}

function render(names: pulumi.Output<Names>, build: (n: Names) => PolicyDocument): pulumi.Output<string> {
    return names.apply((n) => JSON.stringify(build(n)));
}

export function createIam(names: pulumi.Output<Names>, tags: Record<string, string>, provider: aws.Provider): Iam {
    const opts = { provider };
    const trust = JSON.stringify(lambdaTrustPolicy());

    const buildRole = new aws.iam.Role(BUILD_ROLE_NAME, {
        name: BUILD_ROLE_NAME, description: "ai-env MicroVM image builder: reads the image zip, writes the build log", assumeRolePolicy: trust, tags,
    }, opts);
    const buildPolicy = new aws.iam.RolePolicy(BUILD_ROLE_NAME, { name: BUILD_ROLE_NAME, role: buildRole.id, policy: render(names, buildRolePolicy) }, opts);

    const executionRole = new aws.iam.Role(EXECUTION_ROLE_NAME, {
        name: EXECUTION_ROLE_NAME, description: "ai-env MicroVM execution role (run-microvm): runtime logs only", assumeRolePolicy: trust, tags,
    }, opts);
    const executionPolicy = new aws.iam.RolePolicy(EXECUTION_ROLE_NAME, { name: EXECUTION_ROLE_NAME, role: executionRole.id, policy: render(names, executionRolePolicy) }, opts);

    // No aws.iam.AccessKey here, ever (D23): `make runtime-key` creates and seals it.
    const runtimeUser = new aws.iam.User(RUNTIME_USER_NAME, { name: RUNTIME_USER_NAME, forceDestroy: true, tags }, opts);
    const runtime = new aws.iam.UserPolicy(RUNTIME_POLICY_NAME, { name: RUNTIME_POLICY_NAME, user: runtimeUser.name, policy: render(names, runtimePolicy) }, opts);

    const deploy = new aws.iam.Policy(DEPLOY_POLICY_NAME, {
        name: DEPLOY_POLICY_NAME, description: "ai-env deploy/destroy without administrator rights, except creating, changing or deleting this policy (attached to nothing)", policy: render(names, deployPolicy), tags,
    }, opts);

    return { buildRole, buildPolicy, executionRole, executionPolicy, runtimeUser, runtimePolicy: runtime, deployPolicy: deploy };
}
