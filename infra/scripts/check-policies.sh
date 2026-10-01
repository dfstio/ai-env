#!/usr/bin/env bash
# make check-policies: prove every IAM document of the stack before any deploy (T3.6, agent half).
#
# Why: `iam simulate-*` accepts invented action names, so names are proven with Access Analyzer validate-policy
# (an unknown action is an ERROR finding); then simulate-custom-policy proves the runtime principal's allowed and
# implicitly denied actions of plans/s3-plan.md §9 and plans/s5-plan.md; then the egress proxy's role, its inline
# policy and the AWS managed SSM agent policy evaluated together (what the instance really holds). The documents
# come from infra/policies.ts (the ones Pulumi creates), compiled into target/infra-policies; the two AWS managed
# policies the egress roles attach are read from IAM (iam get-policy / get-policy-version), which also proves their
# ARNs. The caller's account id only lives in shell variables: nothing here writes it to a file. Read-only against
# AWS; region always $REGION.
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
pp() { node "$out/scripts/print-policies.js" --account-id "$acct" --image-config "$infra/image-config.json" --egress-config "$infra/egress-config.json" "$@"; }

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
    # IAM's size quotas (characters without whitespace; the printed JSON has none): a managed policy 6144, the runtime
    # user's inline policy 2048, a role's trust policy 2048. Access Analyzer only warns; a deploy would fail.
    max=6144
    if [ "$name" = runtime ] || [ "$type" = RESOURCE_POLICY ]; then max=2048; fi
    if [ "${#doc}" -gt "$max" ]; then
        printf 'size            %-16s %d characters, over the %d-character quota\n' "$name" "${#doc}" "$max" >&2
        bad=1
    fi
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
test "$bad" -eq 0 || { echo "check-policies: Access Analyzer reported ERROR or SECURITY_WARNING findings, or a document is over its size quota (above)" >&2; exit 1; }

# ---- 2. the AWS managed policies the egress roles attach: they exist, and their default version is read ----
# managed <arn>: the default version's document (JSON), or exit 1 naming the ARN.
managed() {
    local arn=$1 version
    version=$(aws iam get-policy --region "$region" --policy-arn "$arn" --query Policy.DefaultVersionId --output text) \
        || { echo "check-policies: the managed policy $arn does not exist (or cannot be read)" >&2; exit 1; }
    aws iam get-policy-version --region "$region" --policy-arn "$arn" --version-id "$version" --query PolicyVersion.Document --output json \
        || { echo "check-policies: cannot read $arn $version" >&2; exit 1; }
    echo "managed policy $arn: default version $version" >&2
}
ssm_managed=$(managed "$(pp --arn ssm-instance-policy)")
operator_managed=$(managed "$(pp --arn operator-policy)")
grep -q 'ec2:CreateNetworkInterface' <<<"$operator_managed" \
    || { echo "check-policies: the operator policy no longer grants ec2:CreateNetworkInterface (the connector could not create its ENIs)" >&2; exit 1; }

# ---- 3. simulate-custom-policy: the runtime principal's §9 table (S5: PassNetworkConnector only) ----
runtime=$(pp --name runtime)
image=$(pp --arn image)
exec_role=$(pp --arn execution-role)
build_role=$(pp --arn build-role)
egress=$(pp --arn egress)
connector=$(pp --arn connector)
proxy_param=$(pp --arn proxy-parameter)
proxy_role=$(pp --arn proxy-role)
operator_role=$(pp --arn operator-role)
other_image="arn:aws:lambda:$region:$acct:microvm-image:not-ai-env"
other_role="arn:aws:iam::$acct:role/not-ai-env"
image_group=$(pp --arn image-log-group)
runtime_user=$(pp --arn runtime-user)
# Concrete ARNs of the resource type each action authorizes on: a grant scoped to a type (security-group/*,
# instance/*, a document, a log group...) never matches a simulation against "*", so "*" is kept only for actions
# without a resource type. The ids are zeros (any id of the type exercises the same scope).
ec2_arn="arn:aws:ec2:$region:$acct"
sg_arn="$ec2_arn:security-group/sg-00000000000000000"
rt_arn="$ec2_arn:route-table/rtb-00000000000000000"
instance_arn="$ec2_arn:instance/i-00000000000000000"
subnet_arn="$ec2_arn:subnet/subnet-00000000000000000"
eni_arn="$ec2_arn:network-interface/eni-00000000000000000"
vpc_arn="$ec2_arn:vpc/vpc-00000000000000000"
shell_doc="arn:aws:ssm:$region::document/AWS-RunShellScript"
session_doc="arn:aws:ssm:$region:$acct:document/SSM-SessionManagerRunShell"
budget_arn="arn:aws:budgets::$acct:budget/ai-env-monthly"
bucket_arn="arn:aws:s3:::ai-env-artifacts-0000000"
zip_arn="$bucket_arn/ai-env/image-0000000000000000.zip"
to_lambda="ContextKeyName=iam:PassedToService,ContextKeyValues=lambda.amazonaws.com,ContextKeyType=string"
failed=0
# The documents the simulated principal holds (set before each group of sims).
docs=("$runtime")

# sim <allowed|implicitDeny> <label> <resource arn> <context entry or -> <action>...
sim() {
    local want=$1 label=$2 resource=$3 context=$4
    shift 4
    local ctx=()
    if [ "$context" != "-" ]; then ctx=(--context-entries "$context"); fi
    local results
    results=$(aws iam simulate-custom-policy --region "$region" --policy-input-list "${docs[@]}" --action-names "$@" \
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
sim allowed "pass a connector" "*" - lambda:PassNetworkConnector
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
# Cloud Control has no resource type: "*".
sim implicitDeny "cloud control" "*" - \
    cloudformation:CreateResource cloudformation:UpdateResource cloudformation:DeleteResource cloudformation:GetResource
sim implicitDeny "the budget" "$budget_arn" - budgets:ModifyBudget budgets:ViewBudget
sim implicitDeny "the artifacts bucket" "$bucket_arn" - s3:ListBucket s3:PutBucketPolicy s3:DeleteBucket
sim implicitDeny "the image zip" "$zip_arn" - s3:GetObject s3:PutObject s3:DeleteObject
sim implicitDeny "the image log group" "$image_group" - logs:CreateLogGroup logs:FilterLogEvents logs:DeleteLogGroup logs:PutRetentionPolicy
sim implicitDeny "the image log group's streams" "$image_group:*" - logs:CreateLogStream logs:PutLogEvents
sim implicitDeny "the runtime user itself" "$runtime_user" - \
    iam:CreateAccessKey iam:CreateUser iam:PutUserPolicy iam:AttachUserPolicy iam:GetUser iam:DeleteUserPolicy
sim implicitDeny "the stack's roles" "$exec_role" - iam:CreateRole iam:PutRolePolicy iam:AttachRolePolicy iam:UpdateAssumeRolePolicy
sim implicitDeny "the proxy role" "$proxy_role" - iam:PutRolePolicy iam:AttachRolePolicy iam:UpdateAssumeRolePolicy
sim implicitDeny "the operator role" "$operator_role" - iam:PutRolePolicy iam:AttachRolePolicy iam:UpdateAssumeRolePolicy
# S5: the runtime key reads, creates, changes and deletes no connector (GetNetworkConnectorsTentative is gone), and
# has no hand on the proxy, its parameters or the egress network.
sim implicitDeny "connector calls on the egress connector" "$connector" - \
    lambda:GetNetworkConnector lambda:CreateNetworkConnector lambda:UpdateNetworkConnector lambda:DeleteNetworkConnector
sim implicitDeny "connector calls on INTERNET_EGRESS" "$egress" - lambda:GetNetworkConnector lambda:UpdateNetworkConnector lambda:DeleteNetworkConnector
sim implicitDeny "list connectors" "*" - lambda:ListNetworkConnectors
sim implicitDeny "the proxy parameters" "$proxy_param" - ssm:GetParameter ssm:GetParameters ssm:PutParameter ssm:DeleteParameter
# No resource type: "*".
sim implicitDeny "ssm and ec2 describes" "*" - ssm:DescribeInstanceInformation ssm:DescribeParameters ec2:DescribeInstances ec2:DescribeNetworkInterfaces
sim implicitDeny "a shell document" "$shell_doc" - ssm:SendCommand
sim implicitDeny "a session document" "$session_doc" - ssm:StartSession
sim implicitDeny "an instance (the proxy)" "$instance_arn" - \
    ssm:SendCommand ssm:StartSession ec2:StartInstances ec2:StopInstances ec2:ModifyInstanceAttribute ec2:TerminateInstances
sim implicitDeny "a security group" "$sg_arn" - \
    ec2:AuthorizeSecurityGroupEgress ec2:AuthorizeSecurityGroupIngress ec2:RevokeSecurityGroupEgress ec2:ModifySecurityGroupRules
sim implicitDeny "a route table" "$rt_arn" - ec2:CreateRoute ec2:ReplaceRoute ec2:DeleteRoute ec2:AssociateRouteTable
sim implicitDeny "a VPC" "$vpc_arn" - ec2:ModifyVpcAttribute ec2:AssociateDhcpOptions
sim implicitDeny "a subnet" "$subnet_arn" - ec2:CreateNetworkInterface ec2:ModifySubnetAttribute
sim implicitDeny "a network interface" "$eni_arn" - ec2:CreateNetworkInterface ec2:ModifyNetworkInterfaceAttribute ec2:DeleteNetworkInterface
sim implicitDeny "pass the proxy role" "$proxy_role" - iam:PassRole
sim implicitDeny "pass the operator role" "$operator_role" - iam:PassRole
test "$failed" -eq 0 || { echo "check-policies: the runtime policy does not match plans/s3-plan.md §9 / plans/s5-plan.md (above)" >&2; exit 1; }

# ---- 4. the egress proxy's role: its inline policy and the managed SSM agent policy together ----
docs=("$(pp --name proxy)" "$ssm_managed")
squid_group=$(pp --arn squid-log-group)
prefix_param=${proxy_param%/allow}
sim allowed "proxy: its own parameters" "$proxy_param" - ssm:GetParameter ssm:GetParameters
sim allowed "proxy: another of its parameters" "$prefix_param/squid.conf" - ssm:GetParameter ssm:GetParameters
sim allowed "proxy: the squid log group" "$squid_group" - logs:CreateLogGroup logs:DescribeLogStreams
# The simulator does not match a policy's `*` across the `:` of a concrete log-stream ARN (the S3 execution role,
# which writes runtime logs in practice, simulates the same way), so the streams are simulated as `<group>:*`.
sim allowed "proxy: the squid log streams" "$squid_group:*" - logs:CreateLogStream logs:PutLogEvents
sim allowed "proxy: the SSM agent (managed policy)" "*" - ssm:UpdateInstanceInformation ssmmessages:CreateControlChannel ec2messages:GetMessages
sim implicitDeny "proxy: another parameter path" "arn:aws:ssm:$region:$acct:parameter/not-ai-env/proxy/allow" - ssm:GetParameter ssm:GetParameters
sim implicitDeny "proxy: a sibling of its prefix" "$prefix_param-other/allow" - ssm:GetParameter ssm:GetParameters
sim implicitDeny "proxy: the parent path" "${prefix_param%/*}" - ssm:GetParameter ssm:GetParameters ssm:GetParametersByPath
sim implicitDeny "proxy: writes its own parameters" "$proxy_param" - ssm:PutParameter ssm:DeleteParameter ssm:LabelParameterVersion
sim implicitDeny "proxy: another log group's streams" "arn:aws:logs:$region:$acct:log-group:/ai-env/egress/other:*" - logs:CreateLogStream logs:PutLogEvents
sim implicitDeny "proxy: a sibling group's streams" "$squid_group-other:*" - logs:CreateLogStream logs:PutLogEvents
sim implicitDeny "proxy: another log group itself" "arn:aws:logs:$region:$acct:log-group:/aws/lambda-microvms/x" - logs:CreateLogGroup logs:DescribeLogStreams
sim implicitDeny "proxy: an instance (itself)" "$instance_arn" - \
    ec2:StopInstances ec2:ModifyInstanceAttribute ec2:TerminateInstances ssm:SendCommand ssm:StartSession
sim implicitDeny "proxy: a shell document" "$shell_doc" - ssm:SendCommand
sim implicitDeny "proxy: a security group" "$sg_arn" - ec2:AuthorizeSecurityGroupEgress ec2:AuthorizeSecurityGroupIngress ec2:ModifySecurityGroupRules
sim implicitDeny "proxy: a route table" "$rt_arn" - ec2:CreateRoute ec2:ReplaceRoute
sim implicitDeny "proxy: its own role" "$proxy_role" - iam:PassRole iam:PutRolePolicy iam:AttachRolePolicy iam:UpdateAssumeRolePolicy
sim implicitDeny "proxy: the operator role" "$operator_role" - iam:PassRole iam:PutRolePolicy
sim implicitDeny "proxy: the image" "$image" - lambda:RunMicrovm lambda:CreateMicrovmShellAuthToken
sim implicitDeny "proxy: the egress connector" "$connector" - lambda:UpdateNetworkConnector lambda:DeleteNetworkConnector
sim implicitDeny "proxy: ec2 describes" "*" - ec2:DescribeInstances ec2:DescribeSecurityGroups
test "$failed" -eq 0 || { echo "check-policies: the egress proxy's role does not match plans/s5-plan.md (above)" >&2; exit 1; }
echo "check-policies: ok (Access Analyzer clean of ERROR and SECURITY_WARNING; runtime policy matches §9 and S5; the proxy role holds its own parameters and log group only)"
