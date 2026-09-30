#!/usr/bin/env bash
# make check-policies: prove every IAM document of the stack before any deploy (T3.6, agent half).
#
# Why: `iam simulate-*` accepts invented action names, so names are proven with Access Analyzer validate-policy
# (an unknown action is an ERROR finding); then simulate-custom-policy proves the runtime principal's allowed and
# implicitly denied actions of plans/s3-plan.md §9. The documents come from infra/policies.ts (the ones Pulumi
# creates), compiled into target/infra-policies. The caller's account id only lives in shell variables: nothing
# here writes it to a file. Read-only against AWS; region always $REGION.
#
# Env (set by infra/infra.mk): AI_ENV_REPO_ROOT, REGION, POLICIES_OUT.
set -euo pipefail

root=${AI_ENV_REPO_ROOT:?}
region=${REGION:?}
out=${POLICIES_OUT:-$root/target/infra-policies}
infra="$root/infra"

test -x "$infra/node_modules/.bin/tsc" || { echo "check-policies: $infra/node_modules missing: make infra-install" >&2; exit 1; }
rm -rf "$out"
# Compile only the printer and the pure policies module (no Pulumi at run time).
(cd "$infra" && node_modules/.bin/tsc --strict --target es2022 --module commonjs --moduleResolution node --types node \
    --rootDir . --outDir "$out" scripts/print-policies.ts)

acct=$(aws sts get-caller-identity --region "$region" --query Account --output text)
pp() { node "$out/scripts/print-policies.js" --account-id "$acct" --image-config "$infra/image-config.json" "$@"; }

# ---- 1. Access Analyzer: every identity policy and every trust policy ----
# First a canary: the check must be able to fail, so an invented action name has to come back as an ERROR.
canary='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:TagResource20170331v2"],"Resource":"*"}]}'
got=$(aws accessanalyzer validate-policy --region "$region" --policy-type IDENTITY_POLICY --policy-document "$canary" \
    --query "findings[?findingType=='ERROR'].issueCode" --output text)
test "$got" = INVALID_ACTION || { echo "check-policies: Access Analyzer did not flag an invented action (got '$got')" >&2; exit 1; }
echo "validate-policy canary           IDENTITY_POLICY  invented action flagged: ERROR INVALID_ACTION"
list=$(pp)
test -n "$list" || { echo "check-policies: print-policies listed nothing" >&2; exit 1; }
bad=0
while IFS=$'\t' read -r name type rtype; do
    doc=$(pp --name "$name")
    extra=()
    if [ "$rtype" != "-" ]; then extra=(--validate-policy-resource-type "$rtype"); fi
    findings=$(aws accessanalyzer validate-policy --region "$region" --policy-type "$type" ${extra[@]+"${extra[@]}"} \
        --policy-document "$doc" --query 'findings[].[findingType,issueCode,findingDetails]' --output text)
    if [ -z "$findings" ]; then
        printf 'validate-policy %-16s %-16s no findings\n' "$name" "$type"
        continue
    fi
    printf 'validate-policy %-16s %-16s findings:\n' "$name" "$type"
    printf '%s\n' "$findings" | sed 's/^/    /'
    if printf '%s\n' "$findings" | cut -f1 | grep -qE '^(ERROR|SECURITY_WARNING)$'; then bad=1; fi
done <<<"$list"
test "$bad" -eq 0 || { echo "check-policies: Access Analyzer reported ERROR or SECURITY_WARNING findings (above)" >&2; exit 1; }

# ---- 2. simulate-custom-policy: the runtime principal's §9 table ----
runtime=$(pp --name runtime)
image=$(pp --arn image)
exec_role=$(pp --arn execution-role)
build_role=$(pp --arn build-role)
egress=$(pp --arn egress)
other_image="arn:aws:lambda:$region:$acct:microvm-image:not-ai-env"
other_role="arn:aws:iam::$acct:role/not-ai-env"
to_lambda="ContextKeyName=iam:PassedToService,ContextKeyValues=lambda.amazonaws.com,ContextKeyType=string"
failed=0

# sim <allowed|implicitDeny> <label> <resource arn> <context entry or -> <action>...
sim() {
    local want=$1 label=$2 resource=$3 context=$4
    shift 4
    local ctx=()
    if [ "$context" != "-" ]; then ctx=(--context-entries "$context"); fi
    local results
    results=$(aws iam simulate-custom-policy --region "$region" --policy-input-list "$runtime" --action-names "$@" \
        --resource-arns "$resource" ${ctx[@]+"${ctx[@]}"} --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text) \
        || { echo "simulate $label: simulate-custom-policy failed" >&2; exit 1; }
    local n_ok=0 action decision
    while IFS=$'\t' read -r action decision; do
        test -n "$action$decision" || continue
        if [ "$decision" = "$want" ]; then
            n_ok=$((n_ok + 1))
        else
            echo "simulate $label: $action is $decision, expected $want" >&2
            failed=1
        fi
    done <<<"$results"
    # Every requested action must come back, once, with the expected decision: a result missing from the answer
    # must not count as a pass.
    local count
    for action in "$@"; do
        count=$(cut -f1 <<<"$results" | grep -cixF -- "$action" || true)
        if [ "$count" -ne 1 ]; then
            echo "simulate $label: $action came back $count times, expected once" >&2
            failed=1
        fi
    done
    if [ "$n_ok" -ne "$#" ]; then
        echo "simulate $label: $n_ok of $# requested actions came back $want" >&2
        failed=1
    fi
    printf 'simulate %-36s %2d/%-2d %s\n' "$label" "$n_ok" "$#" "$want"
}

# Allowed (§9).
sim allowed "runtime actions on the image" "$image" - \
    lambda:RunMicrovm lambda:GetMicrovm lambda:SuspendMicrovm lambda:ResumeMicrovm lambda:TerminateMicrovm \
    lambda:CreateMicrovmAuthToken lambda:CreateMicrovmShellAuthToken \
    lambda:GetMicrovmImage lambda:GetMicrovmImageVersion lambda:ListMicrovmImageVersions
sim allowed "list actions" "*" - lambda:ListMicrovms lambda:ListManagedMicrovmImages lambda:ListManagedMicrovmImageVersions
sim allowed "get the egress connector (tentative)" "$egress" - lambda:GetNetworkConnector
sim allowed "pass a connector (tentative)" "*" - lambda:PassNetworkConnector
sim allowed "pass execution role to lambda" "$exec_role" "$to_lambda" iam:PassRole
# RunMicrovm's PassRole check does not match iam:PassedToService = lambda.amazonaws.com (S4 T4.1): no condition.
sim allowed "pass execution role, no service key" "$exec_role" - iam:PassRole
# Implicitly denied (§9).
sim implicitDeny "image and version mutations" "$image" - \
    lambda:CreateMicrovmImage lambda:UpdateMicrovmImage lambda:DeleteMicrovmImage \
    lambda:UpdateMicrovmImageVersion lambda:DeleteMicrovmImageVersion lambda:TagResource lambda:UntagResource
sim implicitDeny "runtime actions on another image" "$other_image" - lambda:RunMicrovm lambda:GetMicrovmImage lambda:CreateMicrovmAuthToken
sim implicitDeny "pass the build role" "$build_role" "$to_lambda" iam:PassRole
sim implicitDeny "pass any other role" "$other_role" - iam:PassRole
sim implicitDeny "cloudformation, budgets, s3, logs, iam" "*" - \
    cloudformation:CreateResource cloudformation:UpdateResource cloudformation:DeleteResource cloudformation:GetResource \
    budgets:ModifyBudget budgets:ViewBudget \
    s3:GetObject s3:PutObject s3:ListBucket s3:DeleteObject \
    logs:CreateLogGroup logs:CreateLogStream logs:PutLogEvents logs:FilterLogEvents \
    iam:CreateAccessKey iam:CreateUser iam:PutUserPolicy iam:AttachUserPolicy iam:CreateRole iam:PutRolePolicy iam:GetUser

test "$failed" -eq 0 || { echo "check-policies: the runtime policy does not match plans/s3-plan.md §9 (above)" >&2; exit 1; }
echo "check-policies: ok (Access Analyzer clean of ERROR and SECURITY_WARNING; runtime policy matches §9)"
