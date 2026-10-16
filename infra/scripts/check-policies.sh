#!/usr/bin/env bash
# make check-policies: prove every IAM document of the stack before any deploy (T3.6, agent half).
#
# Why: `iam simulate-*` accepts invented action names, so names are proven with Access Analyzer validate-policy
# (an unknown action is an ERROR finding); then simulate-custom-policy proves the runtime principal's allowed and
# implicitly denied actions of plans/s3-plan.md §9 and plans/s5-plan.md; then the egress proxy's role, its inline
# policy and the AWS managed SSM agent policy evaluated together (what the instance really holds); then the
# connector's operator role the same way, its inline Deny and the AWS managed operator policy (an ENI in the VM
# subnet with the VM security group allowed; any other subnet or group, in another region or account too, explicitly
# denied). The documents come from infra/policies.ts (the ones Pulumi creates), compiled into target/infra-policies;
# the two AWS managed policies the egress roles attach are read from IAM (iam get-policy / get-policy-version), which
# also proves their ARNs, and the operator policy's allowed (action, resource) pairs are pinned: operatorRolePolicy's
# Deny narrows ec2:CreateNetworkInterface on the subnet and the security groups only, so any change there stops the
# deploy until the Deny is reviewed. The Deny's own shape (one statement, no condition) is asserted before its
# simulations, which a negated condition would pass. S8 operators adds the operator identities: section 6 simulates
# ai-env-ops' policy (the proxy's start, stop and three documents, the suspended list, the status reads allowed; every
# "never" of plans/s8-operators-plan.md §1 implicitly denied: any other document, another account's of the same name
# included, instance or session, parameter write, every EC2 write but the proxy's start and stop (a launch, an
# interface, an address, a NACL, the proxy's role or disks), every IAM write and PassRole, image, VM and connector
# writes, deploy actions, S3, Budgets and Logs writes, a CloudTrail log group read), section 7 the deployer's five
# policies together (its self-management, the ops user's lifecycle, its own keys, the documents' lifecycle, `extras`,
# G7's pairs, the CloudTrail log groups allowed; AWS-RunShellScript, another account's documents, a session, attaching
# AdministratorAccess, any policy but ai-env-ops attached to or detached from ops, an inline policy, login or group of
# ops', detaching or deleting itself, CreatePolicy, a foreign user, sharing a document denied: the documented limits of
# an admin-equivalent identity, not a boundary); section 8 proves every action a deny row names exists (Access
# Analyzer), since a misspelled one would pass its row without proving anything. The proxy instance's and the
# documents' ARNs are built here from egress-config.json, never printed, so a wrong ARN shape in policies.ts fails the
# allowed rows. The caller's account id only lives in shell variables: nothing here writes it to a file. Read-only
# against AWS; region always $REGION.
#
# Env (set by infra/infra.mk): AI_ENV_REPO_ROOT, REGION, POLICIES_OUT.
set -euo pipefail

root=${AI_ENV_REPO_ROOT:?}
region=${REGION:?}
out=${POLICIES_OUT:-$root/target/infra-policies}
infra="$root/infra"

test -x "$infra/node_modules/.bin/tsc" || { echo "check-policies: $infra/node_modules missing: make infra-install" >&2; exit 1; }
rm -rf "$out"
# Compile only the printer and the pure policies module (no Pulumi at run time), never with an operator key or the
# stack's passphrase in the environment (D18: `make deploy` runs this under ai-env as deployer, and A39's unseal); the
# aws and node calls below keep the key.
(cd "$infra" && env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AI_ENV_BRIDGE_AS -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE \
    node_modules/.bin/tsc --strict --target es2022 --module commonjs --moduleResolution node --types node \
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
# The pin (plans/s5-closing-design.md, step 0: four statements, CreateNetworkInterface on subnet/*, security-group/*
# and network-interface/*, CreateTags on network-interface/* at creation only), as (action, resource) pairs, a
# statement without Resource counted as `<action> NotResource`: operatorRolePolicy's Deny narrows
# ec2:CreateNetworkInterface and nothing else, so another Allow action or any NotAction could reach what it does not
# cover; and a new resource the managed policy authorizes CreateNetworkInterface on (a vpc/*, say) is one the Deny
# refuses live, so ENIs would fail closed, first seen as a FAILED connector. Exact strings: a wildcard or a respelled
# action or ARN fails too, and is reviewed like a new one.
pinned='ec2:CreateNetworkInterface arn:aws:ec2:*:*:network-interface/*
ec2:CreateNetworkInterface arn:aws:ec2:*:*:security-group/*
ec2:CreateNetworkInterface arn:aws:ec2:*:*:subnet/*
ec2:CreateTags arn:aws:ec2:*:*:network-interface/*'
pin=$(node -e '
const d = JSON.parse(require("fs").readFileSync(0, "utf-8"));
const statements = [].concat(d.Statement ?? []);
if (statements.some((s) => s.NotAction !== undefined)) { process.stdout.write("NotAction"); process.exit(0); }
const pairs = statements.filter((s) => s.Effect === "Allow").flatMap((s) => [].concat(s.Action ?? [])
    .flatMap((a) => (s.Resource === undefined ? ["NotResource"] : [].concat(s.Resource)).map((r) => `${a} ${r}`)));
process.stdout.write([...new Set(pairs)].sort().join("\n"));
' <<<"$operator_managed") || { echo "check-policies: cannot read the statements of the operator policy" >&2; exit 1; }
case "$pin" in
"$pinned")
    echo "managed policy pin                the operator policy allows exactly these (action, resource) pairs:"
    sed 's/^/    /' <<<"$pin"
    ;;
NotAction) echo "check-policies: AWS changed AWSLambdaNetworkConnectorOperatorPolicy (a statement uses NotAction): review operatorRolePolicy" >&2; exit 1 ;;
*)
    { echo "check-policies: AWS changed AWSLambdaNetworkConnectorOperatorPolicy (its allowed (action, resource) pairs are not the pinned ones): review operatorRolePolicy"
        echo "  allowed:"; sed 's/^/    /' <<<"${pin:-nothing}"; echo "  pinned:"; sed 's/^/    /' <<<"$pinned"; } >&2
    exit 1
    ;;
esac

# ---- 3. simulate-custom-policy: the runtime principal's §9 table (S5: PassNetworkConnector; S7 D5: + GetNetworkConnector on the egress connector) ----
runtime=$(pp --name runtime)
image=$(pp --arn image)
exec_role=$(pp --arn execution-role)
build_role=$(pp --arn build-role)
egress=$(pp --arn egress)
connector=$(pp --arn connector)
connector_by_name=$(pp --arn connector-by-name)
other_connector=$(pp --arn other-connector)
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
# Every action a deny row names, for section 8 (simulate-custom-policy accepts invented names).
denied_actions=()

# sim <allowed|implicitDeny|explicitDeny> <label> <resource arn> <context entries or -> <action>...
# The context is one shorthand entry or a JSON list of entries (several keys at once), passed as given.
sim() {
    local want=$1 label=$2 resource=$3 context=$4
    shift 4
    case "$want" in allowed | implicitDeny | explicitDeny) ;; *) echo "simulate $label: unknown decision $want (allowed, implicitDeny or explicitDeny)" >&2; exit 2 ;; esac
    if [ "$want" != allowed ]; then denied_actions+=("$@"); fi
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
# S7 D5: the runtime key READS the egress connector (the credential gate compares its live configuration), and only
# that one — it still creates, changes and deletes none, reaches no other connector, and has no hand on the proxy, its
# parameters or the egress network.
sim allowed "read the egress connector" "$connector" - lambda:GetNetworkConnector
# The IAM service reference documents the networkConnector ARN by name, the service reports it by id: both are granted.
sim allowed "read the egress connector by name" "$connector_by_name" - lambda:GetNetworkConnector
sim implicitDeny "connector mutations on the egress connector" "$connector" - \
    lambda:CreateNetworkConnector lambda:UpdateNetworkConnector lambda:DeleteNetworkConnector
sim implicitDeny "connector calls on another connector" "$other_connector" - \
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

# ---- 5. the connector's operator role: its inline Deny and the AWS managed operator policy together ----
# The VM subnet and group get ids of the real shape that are not print-policies' placeholders, because the zero ids
# of $subnet_arn and $sg_arn stand for "another subnet" and "another group" here. The VM ARNs are built here, never
# printed, so a wrong ARN shape in policies.ts fails the allowed rows. CreateNetworkInterface authorizes on the
# subnet, each security group and the new ENI separately: each is simulated on its own.
vm_subnet_id=subnet-0123456789abcdef0
vm_sg_id=sg-0123456789abcdef0
vm_subnet_arn="$ec2_arn:subnet/$vm_subnet_id"
vm_sg_arn="$ec2_arn:security-group/$vm_sg_id"
# Another account: the documentation one (the only literal account id the repository allows), never the caller's.
other_acct=123456789012
docs=("$(pp --vm-subnet-id "$vm_subnet_id" --vm-security-group-id "$vm_sg_id" --name operator)" "$operator_managed")
# The Deny's shape first, which the rows below cannot see: they carry no request context, and a negated condition
# (StringNotEquals ec2:Vpc, say) is true for a key the request lacks, so every explicitDeny row would still pass while
# a real CreateNetworkInterface, which carries the key, escapes the Deny. One unconditional Deny of exactly
# ec2:CreateNetworkInterface on a NotResource of three (a positive condition fails the rows anyway). Its entries are
# pinned too: the rows probe only sampled ARNs, so a wildcard such as subnet/subnet-01* would match the VM subnet and
# none of them while it lets ENIs into other subnets. The new-ENI entry may name this account, or any account (the
# documented fallback, plans/s5-closing-design.md I).
node -e '
const [doc, subnet, sg, acct, region] = process.argv.slice(1);
const s = [].concat(JSON.parse(doc).Statement ?? []);
const d = s[0] ?? {};
const nr = Array.isArray(d.NotResource) ? d.NotResource : [];
const rest = nr.filter((r) => r !== subnet && r !== sg);
process.exit(s.length === 1 && d.Effect === "Deny" && d.Condition === undefined && d.Resource === undefined && d.NotAction === undefined
    && JSON.stringify(d.Action) === JSON.stringify(["ec2:CreateNetworkInterface"]) && nr.length === 3 && nr.includes(subnet) && nr.includes(sg)
    && rest.length === 1 && [`arn:aws:ec2:${region}:${acct}:network-interface/*`, `arn:aws:ec2:${region}:*:network-interface/*`].includes(rest[0]) ? 0 : 1);
' "${docs[0]}" "$vm_subnet_arn" "$vm_sg_arn" "$acct" "$region" || { echo "check-policies: operatorRolePolicy is no longer one unconditional Deny of ec2:CreateNetworkInterface on a NotResource of exactly the VM subnet, the VM SG and network-interface/*: review it (plans/s5-closing-design.md I)" >&2; exit 1; }
echo "operator Deny shape               one unconditional Deny of ec2:CreateNetworkInterface, NotResource of exactly the VM subnet, the VM SG and network-interface/*"
# The managed policy's conditions (step 0): the new ENI may carry only the two Lambda tag keys (ForAllValues, so also
# true without tags; given here to be exact), and it is tagged only while the connector service creates it.
lambda_tags='[{"ContextKeyName":"aws:TagKeys","ContextKeyValues":["aws:lambda:networkConnectorName","aws:lambda:networkConnectorId"],"ContextKeyType":"stringList"}]'
tag_on_create='[{"ContextKeyName":"ec2:CreateAction","ContextKeyValues":["CreateNetworkInterface"],"ContextKeyType":"string"},{"ContextKeyName":"ec2:ManagedResourceOperator","ContextKeyValues":["network-connectors.lambda.amazonaws.com"],"ContextKeyType":"string"}]'
sim allowed "operator: an ENI in the VM subnet" "$vm_subnet_arn" - ec2:CreateNetworkInterface
sim allowed "operator: an ENI with the VM SG" "$vm_sg_arn" - ec2:CreateNetworkInterface
sim allowed "operator: the new ENI" "$eni_arn" "$lambda_tags" ec2:CreateNetworkInterface
# The Deny names CreateNetworkInterface only: the tags written at creation still pass (a Deny on them would fail
# every ENI creation).
sim allowed "operator: tag the new ENI" "$eni_arn" "$tag_on_create" ec2:CreateTags
sim explicitDeny "operator: an ENI in another subnet" "$subnet_arn" - ec2:CreateNetworkInterface
sim explicitDeny "operator: an ENI with another SG" "$sg_arn" - ec2:CreateNetworkInterface
sim explicitDeny "operator: the VM subnet id, other region" "arn:aws:ec2:eu-west-1:$acct:subnet/$vm_subnet_id" - ec2:CreateNetworkInterface
sim explicitDeny "operator: the VM SG id, other region" "arn:aws:ec2:eu-west-1:$acct:security-group/$vm_sg_id" - ec2:CreateNetworkInterface
sim explicitDeny "operator: the VM subnet id, other account" "arn:aws:ec2:$region:$other_acct:subnet/$vm_subnet_id" - ec2:CreateNetworkInterface
sim explicitDeny "operator: the VM SG id, other account" "arn:aws:ec2:$region:$other_acct:security-group/$vm_sg_id" - ec2:CreateNetworkInterface
# Implicitly denied: the managed policy grants nothing else, and the Deny grants nothing.
sim implicitDeny "operator: tag an ENI after its creation" "$eni_arn" - ec2:CreateTags ec2:DeleteTags
sim implicitDeny "operator: change, attach or delete an ENI" "$eni_arn" - \
    ec2:ModifyNetworkInterfaceAttribute ec2:AttachNetworkInterface ec2:DetachNetworkInterface ec2:DeleteNetworkInterface ec2:CreateNetworkInterfacePermission
sim implicitDeny "operator: the VM SG's rules and tags" "$vm_sg_arn" - \
    ec2:AuthorizeSecurityGroupEgress ec2:AuthorizeSecurityGroupIngress ec2:RevokeSecurityGroupEgress ec2:ModifySecurityGroupRules ec2:CreateTags
sim implicitDeny "operator: another SG's rules" "$sg_arn" - ec2:AuthorizeSecurityGroupEgress ec2:AuthorizeSecurityGroupIngress
sim implicitDeny "operator: the VM subnet" "$vm_subnet_arn" - ec2:ModifySubnetAttribute ec2:CreateTags
sim implicitDeny "operator: its own role (and its Deny)" "$operator_role" - \
    iam:PassRole iam:PutRolePolicy iam:DeleteRolePolicy iam:AttachRolePolicy iam:DetachRolePolicy iam:UpdateAssumeRolePolicy
sim implicitDeny "operator: the egress connector" "$connector" - lambda:UpdateNetworkConnector lambda:DeleteNetworkConnector lambda:CreateNetworkConnector
test "$failed" -eq 0 || { echo "check-policies: the operator role does not match plans/s5-closing-design.md (I, above)" >&2; exit 1; }

# ---- 6. ai-env-ops (S8 operators): the operator commands and status reads; nothing that deploys or widens egress ----
# The proxy instance gets an id of the real shape that is not "another instance" ($instance_arn, zeros); its ARN and
# the three documents' are built here from egress-config.json's names (one scalar per line, read as ops.sh reads it),
# never printed by print-policies, so a wrong ARN shape in policies.ts fails the allowed rows. SendCommand authorizes
# the document and every target separately: each is simulated on its own, with one resource per row.
econf() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$infra/egress-config.json" | head -1; }
proxy_id=i-0123456789abcdef0
proxy_i="$ec2_arn:instance/$proxy_id"
doc_arn="arn:aws:ssm:$region:$acct:document"
proxy_docs=()
for k in reloadDocumentName statusDocumentName patchDocumentName; do
    d=$(econf "$k")
    test -n "$d" || { echo "check-policies: no $k in $infra/egress-config.json" >&2; exit 1; }
    proxy_docs+=("$doc_arn/$d")
done
reload_doc=${proxy_docs[0]}
dns_group=$(pp --arn dns-log-group)
ops_user=$(pp --arn ops-user)
deployer_user=$(pp --arn deployer-user)
deploy_policy=$(pp --arn deploy-policy)
ops_policy=$(pp --arn ops-policy)
stack_users=("$runtime_user" "$ops_user" "$deployer_user")
stack_policies=("$deploy_policy" "$(pp --arn deploy-egress-policy)" "$(pp --arn deploy-dns-policy)" "$(pp --arn deployer-policy)" "$ops_policy")
lambda_slr="arn:aws:iam::$acct:role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda"
quota_arn="arn:aws:servicequotas:$region:$acct"
# A CloudTrail log group as the console names a trail's (cloudtrail-payload prints a command per such group).
cloudtrail_group="arn:aws:logs:$region:$acct:log-group:aws-cloudtrail-logs-probe"
proxy_profile_name=$(econf proxyInstanceProfileName)
test -n "$proxy_profile_name" || { echo "check-policies: no proxyInstanceProfileName in $infra/egress-config.json" >&2; exit 1; }
proxy_profile="arn:aws:iam::$acct:instance-profile/$proxy_profile_name"
docs=("$(pp --proxy-instance-id "$proxy_id" --name ops)")
# Allowed: what the operator commands call (plans/s8-operators-design.md B5).
sim allowed "ops: start and stop the proxy" "$proxy_i" - ec2:StartInstances ec2:StopInstances
for d in "${proxy_docs[@]}"; do sim allowed "ops: send ${d##*/}" "$d" - ssm:SendCommand; done
sim allowed "ops: send to the proxy instance" "$proxy_i" - ssm:SendCommand
for p in squid.conf allow extras suspended; do sim allowed "ops: read the $p parameter" "$prefix_param/$p" - ssm:GetParameters ssm:GetParameterHistory; done
sim allowed "ops: write the suspended parameter" "$prefix_param/suspended" - ssm:PutParameter
# No resource type: "*".
sim allowed "ops: the unscoped reads" "*" - \
    ssm:GetCommandInvocation ssm:DescribeInstanceInformation \
    ec2:DescribeInstances ec2:DescribeNetworkInterfaces ec2:DescribeRouteTables ec2:DescribeNetworkAcls ec2:DescribeSecurityGroups ec2:DescribeVpcs \
    ec2:DescribeVpcAttribute ec2:DescribeDhcpOptions ec2:DescribeVpcEndpoints ec2:DescribeVpcPeeringConnections ec2:DescribeNatGateways \
    ec2:DescribeVpcBlockPublicAccessOptions ec2:DescribeVpcBlockPublicAccessExclusions route53resolver:ListFirewallRuleGroupAssociations \
    lambda:ListNetworkConnectors lambda:ListMicrovmImages lambda:ListManagedMicrovmImages lambda:ListManagedMicrovmImageVersions lambda:ListMicrovms \
    logs:DescribeLogGroups cloudtrail:DescribeTrails cloudtrail:GetEventSelectors cloudtrail:ListChannels cloudtrail:GetChannel \
    iam:GetAccountSummary access-analyzer:ValidatePolicy iam:SimulateCustomPolicy
sim allowed "ops: the DNS Firewall rules" "arn:aws:route53resolver:$region:$acct:firewall-rule-group/rslvr-frg-0000000000000000" - route53resolver:ListFirewallRules
sim allowed "ops: the DNS Firewall domains" "arn:aws:route53resolver:$region:$acct:firewall-domain-list/rslvr-fdl-0000000000000000" - route53resolver:ListFirewallDomains
sim allowed "ops: the DNS Firewall config" "arn:aws:route53resolver:$region:$acct:firewall-config/rslvr-fc-0000000000000000" - route53resolver:GetFirewallConfig
sim allowed "ops: read the egress connector" "$connector" - lambda:GetNetworkConnector
sim allowed "ops: read it by name" "$connector_by_name" - lambda:GetNetworkConnector
sim allowed "ops: read another connector" "$other_connector" - lambda:GetNetworkConnector
sim allowed "ops: read the image" "$image" - lambda:GetMicrovmImage lambda:GetMicrovmImageVersion lambda:ListMicrovmImageVersions lambda:ListMicrovmImageBuilds
for g in "$image_group" "$squid_group" "$dns_group"; do
    sim allowed "ops: read ${g##*:log-group:}" "$g" - logs:FilterLogEvents logs:StartLiveTail
    sim allowed "ops: read ${g##*:log-group:}'s streams" "$g:*" - logs:FilterLogEvents logs:StartLiveTail
done
sim allowed "ops: the MicroVM memory quota" "$quota_arn:lambda/L-CD1C0CC4" - servicequotas:GetServiceQuota
sim allowed "ops: the VPC quota" "$quota_arn:vpc/L-F678F1CE" - servicequotas:GetServiceQuota
for u in "${stack_users[@]}"; do
    sim allowed "ops: ${u##*:} (G7, doctor, creds)" "$u" - iam:SimulatePrincipalPolicy iam:ListAccessKeys iam:ListAttachedUserPolicies iam:ListUserPolicies iam:ListGroupsForUser
done
for p in "${stack_policies[@]}" "$(pp --arn ssm-instance-policy)" "$(pp --arn operator-policy)"; do
    sim allowed "ops: read ${p##*:}" "$p" - iam:GetPolicy iam:GetPolicyVersion
done
sim allowed "ops: the Lambda service-linked role" "$lambda_slr" - iam:GetRole
# Implicitly denied: everything that deploys, widens egress or reaches another resource.
sim implicitDeny "ops: AWS-RunShellScript" "$shell_doc" - ssm:SendCommand
sim implicitDeny "ops: another account document" "$doc_arn/not-ai-env" - ssm:SendCommand
# The grant names this account's documents: another account's document of the same name (shared with this one) would
# run its own script as root on the proxy.
for d in "${proxy_docs[@]}"; do sim implicitDeny "ops: ${d##*/} of another account" "arn:aws:ssm:$region:$other_acct:document/${d##*/}" - ssm:SendCommand; done
sim implicitDeny "ops: another instance" "$instance_arn" - ec2:StartInstances ec2:StopInstances ssm:SendCommand ssm:StartSession
sim implicitDeny "ops: the proxy's attributes, tags, a session" "$proxy_i" - \
    ec2:ModifyInstanceAttribute ec2:ModifyInstanceMetadataOptions ec2:TerminateInstances ec2:CreateTags ec2:DeleteTags ssm:StartSession
sim implicitDeny "ops: a session document" "$session_doc" - ssm:StartSession
for d in "${proxy_docs[@]}"; do
    sim implicitDeny "ops: write ${d##*/}" "$d" - ssm:CreateDocument ssm:UpdateDocument ssm:UpdateDocumentDefaultVersion ssm:DeleteDocument ssm:ModifyDocumentPermission
done
for p in squid.conf allow extras; do
    sim implicitDeny "ops: write the $p parameter" "$prefix_param/$p" - ssm:PutParameter ssm:DeleteParameter ssm:LabelParameterVersion
done
sim implicitDeny "ops: delete the suspended parameter" "$prefix_param/suspended" - ssm:DeleteParameter ssm:LabelParameterVersion
sim implicitDeny "ops: associations, automation" "*" - ssm:CreateAssociation ssm:StartAutomationExecution
for u in "${stack_users[@]}"; do
    sim implicitDeny "ops: write ${u##*:}" "$u" - \
        iam:CreateAccessKey iam:DeleteAccessKey iam:UpdateAccessKey iam:AttachUserPolicy iam:DetachUserPolicy iam:PutUserPolicy iam:CreateLoginProfile iam:AddUserToGroup iam:DeleteUser
done
for p in "${stack_policies[@]}"; do
    sim implicitDeny "ops: write ${p##*:}" "$p" - iam:CreatePolicyVersion iam:SetDefaultPolicyVersion iam:DeletePolicyVersion iam:DeletePolicy
done
sim implicitDeny "ops: another user" "arn:aws:iam::$acct:user/not-ai-env" - iam:CreateUser iam:CreateAccessKey iam:SimulatePrincipalPolicy iam:ListAccessKeys
for r in "$exec_role" "$build_role" "$proxy_role" "$operator_role"; do sim implicitDeny "ops: pass ${r##*/}" "$r" - iam:PassRole; done
# No IAM write at all: no role (a trust policy rewritten to name user/ai-env-ops is a role it could then assume), no
# policy and no group of its own.
for r in "$exec_role" "$build_role" "$proxy_role" "$operator_role" "$other_role"; do
    sim implicitDeny "ops: write ${r##*/}" "$r" - \
        iam:CreateRole iam:DeleteRole iam:UpdateRole iam:UpdateAssumeRolePolicy iam:PutRolePolicy iam:DeleteRolePolicy iam:AttachRolePolicy iam:DetachRolePolicy
done
sim implicitDeny "ops: another policy" "arn:aws:iam::$acct:policy/not-ai-env" - iam:CreatePolicy iam:CreatePolicyVersion iam:DeletePolicy
sim implicitDeny "ops: a group" "arn:aws:iam::$acct:group/not-ai-env" - iam:CreateGroup iam:PutGroupPolicy iam:AttachGroupPolicy iam:AddUserToGroup
sim implicitDeny "ops: the image's writes and VMs" "$image" - \
    lambda:UpdateMicrovmImage lambda:UpdateMicrovmImageVersion lambda:DeleteMicrovmImageVersion lambda:DeleteMicrovmImage lambda:RunMicrovm lambda:CreateMicrovmShellAuthToken
sim implicitDeny "ops: deploy (no resource type)" "*" - \
    lambda:CreateMicrovmImage lambda:PassNetworkConnector cloudformation:CreateResource cloudformation:UpdateResource cloudformation:DeleteResource
sim implicitDeny "ops: change a connector" "$connector" - lambda:UpdateNetworkConnector lambda:DeleteNetworkConnector lambda:CreateNetworkConnector
sim implicitDeny "ops: INTERNET_EGRESS" "$egress" - lambda:GetNetworkConnector
sim implicitDeny "ops: a security group" "$sg_arn" - ec2:AuthorizeSecurityGroupEgress ec2:AuthorizeSecurityGroupIngress ec2:RevokeSecurityGroupEgress ec2:ModifySecurityGroupRules
sim implicitDeny "ops: a route table" "$rt_arn" - ec2:CreateRoute ec2:ReplaceRoute ec2:DeleteRoute ec2:AssociateRouteTable
sim implicitDeny "ops: a VPC" "$vpc_arn" - ec2:ModifyVpcAttribute ec2:AssociateDhcpOptions
sim implicitDeny "ops: the image zip" "$zip_arn" - s3:PutObject s3:GetObject s3:DeleteObject
sim implicitDeny "ops: the budget" "$budget_arn" - budgets:ModifyBudget
sim implicitDeny "ops: the squid log group's settings" "$squid_group" - logs:CreateLogGroup logs:DeleteLogGroup logs:PutRetentionPolicy
sim implicitDeny "ops: another log group" "arn:aws:logs:$region:$acct:log-group:/not-ai-env" - logs:FilterLogEvents logs:StartLiveTail
sim implicitDeny "ops: another quota" "$quota_arn:lambda/L-00000000" - servicequotas:GetServiceQuota
# The rest of every "never" of plans/s8-operators-plan.md §1 (design B7), each on the resource types its calls authorize
# on: a grant scoped to a type never matches "*", and "*" catches what OpsUnscoped could gain. EC2, any write but the
# proxy's start and stop: a launch (RunInstances authorizes on the new instance, its subnet, security groups and
# interface), the proxy's role, disks, network and reboot, a shell through EC2 Instance Connect, any interface, subnet,
# NACL, VPC or address write, and the account-wide switches.
sim implicitDeny "ops: EC2 writes, no resource type" "*" - \
    ec2:RunInstances ec2:EnableSerialConsoleAccess ec2:ModifyInstanceMetadataDefaults ec2:ModifyVpcBlockPublicAccessOptions
sim implicitDeny "ops: launch an instance" "$instance_arn" - ec2:RunInstances
sim implicitDeny "ops: the proxy's role, disks, network" "$proxy_i" - \
    ec2:RebootInstances ec2:AssociateIamInstanceProfile ec2:ReplaceIamInstanceProfileAssociation ec2:DisassociateIamInstanceProfile \
    ec2:AttachNetworkInterface ec2:AssociateAddress ec2:AttachVolume ec2:DetachVolume ec2:CreateImage ec2:ModifyInstanceCreditSpecification
sim implicitDeny "ops: a shell on the proxy (Instance Connect)" "$proxy_i" - ec2-instance-connect:SendSSHPublicKey ec2-instance-connect:SendSerialConsoleSSHPublicKey
sim implicitDeny "ops: a network interface" "$eni_arn" - \
    ec2:CreateNetworkInterface ec2:ModifyNetworkInterfaceAttribute ec2:AttachNetworkInterface ec2:DeleteNetworkInterface ec2:AssignPrivateIpAddresses \
    ec2:AssociateAddress ec2:RunInstances
sim implicitDeny "ops: a subnet" "$subnet_arn" - ec2:RunInstances ec2:CreateNetworkInterface ec2:ModifySubnetAttribute ec2:DeleteSubnet ec2:CreateNatGateway
sim implicitDeny "ops: launch into a security group" "$sg_arn" - ec2:RunInstances ec2:CreateNetworkInterface ec2:DeleteSecurityGroup
sim implicitDeny "ops: a network ACL" "$ec2_arn:network-acl/acl-00000000000000000" - \
    ec2:CreateNetworkAclEntry ec2:ReplaceNetworkAclEntry ec2:DeleteNetworkAclEntry ec2:ReplaceNetworkAclAssociation ec2:DeleteNetworkAcl
sim implicitDeny "ops: build in a VPC" "$vpc_arn" - \
    ec2:CreateSubnet ec2:CreateRouteTable ec2:CreateNetworkAcl ec2:CreateSecurityGroup ec2:AttachInternetGateway ec2:CreateVpcEndpoint \
    ec2:CreateVpcPeeringConnection ec2:DeleteVpc
sim implicitDeny "ops: an Elastic IP" "$ec2_arn:elastic-ip/eipalloc-00000000000000000" - ec2:AllocateAddress ec2:AssociateAddress ec2:ReleaseAddress
# IAM, any write: no other credential or setting of the three users either, no role swapped into the proxy's instance
# profile, no service-linked role.
for u in "${stack_users[@]}"; do
    sim implicitDeny "ops: other credentials of ${u##*:}" "$u" - \
        iam:CreateServiceSpecificCredential iam:UploadSSHPublicKey iam:UploadSigningCertificate iam:UpdateLoginProfile iam:EnableMFADevice \
        iam:UpdateUser iam:TagUser iam:DeleteUserPolicy iam:PutUserPermissionsBoundary iam:RemoveUserFromGroup
done
sim implicitDeny "ops: the proxy's instance profile" "$proxy_profile" - \
    iam:AddRoleToInstanceProfile iam:RemoveRoleFromInstanceProfile iam:DeleteInstanceProfile iam:CreateInstanceProfile
sim implicitDeny "ops: the Lambda service-linked role's writes" "$lambda_slr" - iam:CreateServiceLinkedRole iam:DeleteServiceLinkedRole iam:PassRole
# Lambda, no image or connector write and no VM: the token calls, a VM's lifecycle, tags.
sim implicitDeny "ops: the image's VMs, tokens and tags" "$image" - \
    lambda:CreateMicrovmAuthToken lambda:TerminateMicrovm lambda:SuspendMicrovm lambda:ResumeMicrovm lambda:TagResource lambda:UntagResource
sim implicitDeny "ops: tag a connector" "$connector" - lambda:TagResource lambda:UntagResource
# S3 and Budgets, no write.
sim implicitDeny "ops: the artifacts bucket" "$bucket_arn" - \
    s3:CreateBucket s3:DeleteBucket s3:PutBucketPolicy s3:DeleteBucketPolicy s3:PutBucketPublicAccessBlock s3:PutBucketAcl s3:PutLifecycleConfiguration
sim implicitDeny "ops: the budget's tags" "$budget_arn" - budgets:TagResource budgets:UntagResource
sim implicitDeny "ops: S3 and Logs writes, no resource type" "*" - \
    s3:PutAccountPublicAccessBlock logs:PutResourcePolicy logs:DeleteResourcePolicy logs:CreateLogDelivery logs:DeleteLogDelivery logs:PutAccountPolicy \
    logs:DeleteAccountPolicy
# Logs, no write on the stack's three groups or a CloudTrail group, their streams included (forged squid lines would be
# `egress check`'s evidence, a forged CloudTrail record cloudtrail-payload's), in a group's ARN and in its `:*` form; and
# no read of a CloudTrail group (the command cloudtrail-payload prints for one is the deployer's: section 7).
log_writes=(logs:CreateLogGroup logs:DeleteLogGroup logs:PutRetentionPolicy logs:DeleteRetentionPolicy logs:PutSubscriptionFilter logs:PutDataProtectionPolicy
    logs:DeleteDataProtectionPolicy logs:TagResource logs:UntagResource logs:AssociateKmsKey logs:CreateLogStream logs:PutLogEvents logs:DeleteLogStream)
for g in "$image_group" "$squid_group" "$dns_group" "$cloudtrail_group"; do
    sim implicitDeny "ops: write ${g##*:log-group:}" "$g" - "${log_writes[@]}"
    sim implicitDeny "ops: write ${g##*:log-group:}'s streams" "$g:*" - "${log_writes[@]}"
done
sim implicitDeny "ops: read a CloudTrail log group" "$cloudtrail_group" - logs:FilterLogEvents logs:Unmask logs:StartLiveTail
sim implicitDeny "ops: read a CloudTrail group's streams" "$cloudtrail_group:*" - logs:FilterLogEvents logs:Unmask logs:StartLiveTail
test "$failed" -eq 0 || { echo "check-policies: the ops policy does not match plans/s8-operators-plan.md §1 (above)" >&2; exit 1; }

# ---- 7. ai-env-deployer: its five policies together (the three deploy policies, its supplement, ai-env-ops) ----
# The context entry carries iam:PolicyARN for the attach and detach rows (the supplement's ArnEquals conditions).
ppd() { pp --vm-subnet-id "$vm_subnet_id" --vm-security-group-id "$vm_sg_id" --proxy-instance-id "$proxy_id" "$@"; }
docs=("$(ppd --name deploy)" "$(ppd --name deploy-egress)" "$(ppd --name deploy-dns)" "$(ppd --name deployer)" "$(ppd --name ops)")
with_policy() { printf 'ContextKeyName=iam:PolicyARN,ContextKeyValues=%s,ContextKeyType=string' "$1"; }
admin=arn:aws:iam::aws:policy/AdministratorAccess
# Allowed: self-management, the ops user and the keys, the documents, egress allow, G7's pairs.
for p in "${stack_policies[@]}"; do
    sim allowed "deployer: manage ${p##*:}" "$p" - iam:CreatePolicyVersion iam:DeletePolicyVersion iam:ListPolicyVersions iam:SetDefaultPolicyVersion \
        iam:GetPolicy iam:GetPolicyVersion iam:ListPolicyTags iam:ListEntitiesForPolicy iam:TagPolicy iam:UntagPolicy
done
# Every action the supplement grants on the two users has its allowed row: one dropped by mistake (a tag call Pulumi
# makes, a cleanup step forceDestroy takes, a rotation step) fails here, not half-way through a deploy or a destroy.
sim allowed "deployer: the ops user's lifecycle" "$ops_user" - iam:CreateUser iam:DeleteUser iam:GetUser iam:TagUser iam:UntagUser iam:ListUserTags \
    iam:ListAccessKeys iam:CreateAccessKey iam:UpdateAccessKey iam:DeleteAccessKey iam:GetAccessKeyLastUsed iam:ListUserPolicies iam:ListAttachedUserPolicies \
    iam:ListGroupsForUser iam:ListSigningCertificates iam:DeleteSigningCertificate iam:ListSSHPublicKeys iam:DeleteSSHPublicKey \
    iam:ListServiceSpecificCredentials iam:DeleteServiceSpecificCredential iam:ListMFADevices iam:DeactivateMFADevice iam:GetLoginProfile iam:DeleteLoginProfile
sim allowed "deployer: destroy's lookups" "*" - iam:ListVirtualMFADevices s3:ListAllMyBuckets
sim allowed "deployer: attach ai-env-ops to ops" "$ops_user" "$(with_policy "$ops_policy")" iam:AttachUserPolicy iam:DetachUserPolicy
for p in "${stack_policies[@]}"; do sim allowed "deployer: attach ${p##*:} to itself" "$deployer_user" "$(with_policy "$p")" iam:AttachUserPolicy; done
sim allowed "deployer: its own user and keys" "$deployer_user" - iam:GetUser iam:TagUser iam:UntagUser iam:ListUserTags iam:ListUserPolicies \
    iam:ListAttachedUserPolicies iam:ListGroupsForUser iam:ListAccessKeys iam:CreateAccessKey iam:UpdateAccessKey iam:DeleteAccessKey iam:GetAccessKeyLastUsed
# The command `ai-env lab run cloudtrail-payload` prints per CloudTrail log group (ai-env-ops may not: section 6).
sim allowed "deployer: a CloudTrail log group" "$cloudtrail_group" - logs:FilterLogEvents logs:Unmask
sim allowed "deployer: a CloudTrail group's streams" "$cloudtrail_group:*" - logs:FilterLogEvents logs:Unmask
for d in "${proxy_docs[@]}"; do
    sim allowed "deployer: the lifecycle of ${d##*/}" "$d" - ssm:CreateDocument ssm:UpdateDocument ssm:UpdateDocumentDefaultVersion ssm:DeleteDocument \
        ssm:DescribeDocument ssm:GetDocument ssm:DescribeDocumentPermission ssm:ListDocumentVersions ssm:AddTagsToResource ssm:RemoveTagsFromResource ssm:ListTagsForResource
done
sim allowed "deployer: egress allow (extras)" "$prefix_param/extras" - ssm:PutParameter ssm:GetParameterHistory
sim allowed "deployer: send ${reload_doc##*/} (as ops)" "$reload_doc" - ssm:SendCommand
sim allowed "deployer: send to the proxy (as ops)" "$proxy_i" - ssm:SendCommand
sim allowed "deployer: G7, the runtime user" "$runtime_user" - iam:CreateUser iam:CreateAccessKey
sim allowed "deployer: G7, the ops user's key" "$ops_user" - iam:CreateAccessKey
sim allowed "deployer: G7, the budget" "$budget_arn" - budgets:ModifyBudget
# Implicitly denied: the documented limits (with these five policies the deployer is admin-equivalent, not bounded).
sim implicitDeny "deployer: AWS-RunShellScript" "$shell_doc" - ssm:SendCommand
for d in "${proxy_docs[@]}"; do sim implicitDeny "deployer: ${d##*/} of another account" "arn:aws:ssm:$region:$other_acct:document/${d##*/}" - ssm:SendCommand; done
sim implicitDeny "deployer: a session on the proxy" "$proxy_i" - ssm:StartSession
sim implicitDeny "deployer: AdministratorAccess on itself" "$deployer_user" "$(with_policy "$admin")" iam:AttachUserPolicy
sim implicitDeny "deployer: AdministratorAccess on ops" "$ops_user" "$(with_policy "$admin")" iam:AttachUserPolicy
# On ops it attaches and detaches ai-env-ops alone: never one of its four other policies (the daily key would deploy) or
# another customer policy; and it gives ops no inline policy, console login, group or other name.
for p in "${stack_policies[@]}" "arn:aws:iam::$acct:policy/not-ai-env"; do
    test "$p" != "$ops_policy" || continue
    sim implicitDeny "deployer: ${p##*/} on ops" "$ops_user" "$(with_policy "$p")" iam:AttachUserPolicy iam:DetachUserPolicy
done
sim implicitDeny "deployer: widen ops" "$ops_user" - iam:PutUserPolicy iam:CreateLoginProfile iam:UpdateLoginProfile iam:AddUserToGroup iam:UpdateUser
sim implicitDeny "deployer: another policy on itself" "$deployer_user" "$(with_policy "arn:aws:iam::$acct:policy/not-ai-env")" iam:AttachUserPolicy
sim implicitDeny "deployer: detach its own policy" "$deployer_user" "$(with_policy "$deploy_policy")" iam:DetachUserPolicy
sim implicitDeny "deployer: delete or widen itself" "$deployer_user" - iam:DeleteUser iam:CreateLoginProfile iam:UpdateLoginProfile iam:DeleteLoginProfile \
    iam:PutUserPolicy iam:AddUserToGroup iam:RemoveUserFromGroup iam:UpdateUser
for p in "${stack_policies[@]}"; do sim implicitDeny "deployer: create or delete ${p##*:}" "$p" - iam:CreatePolicy iam:DeletePolicy; done
sim implicitDeny "deployer: another policy" "arn:aws:iam::$acct:policy/not-ai-env" - iam:CreatePolicy
sim implicitDeny "deployer: another user" "arn:aws:iam::$acct:user/not-ai-env" - iam:CreateUser iam:CreateAccessKey iam:AttachUserPolicy
sim implicitDeny "deployer: share a document" "$reload_doc" - ssm:ModifyDocumentPermission
sim implicitDeny "deployer: a group" "arn:aws:iam::$acct:group/not-ai-env" - iam:CreateGroup
test "$failed" -eq 0 || { echo "check-policies: ai-env-deployer's five policies do not match plans/s8-operators-plan.md §1 (above)" >&2; exit 1; }

# ---- 8. every action a deny row names exists ----
# simulate-custom-policy accepts invented names, so a deny row naming a misspelled action passes without proving
# anything. Each is validated as section 1 validates the documents (its canary proved an invented name is an ERROR):
# Allow statements on "*" in documents under the managed policy size, validated only, never attached anywhere.
deny_names=$(printf '%s\n' ${denied_actions[@]+"${denied_actions[@]}"} | sort -u)
test -n "$deny_names" || { echo "check-policies: no deny row named an action" >&2; exit 1; }
chunks=$(node -e '
const actions = require("fs").readFileSync(0, "utf-8").split("\n").filter(Boolean);
const doc = (a) => JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: a, Resource: "*" }] });
const out = [];
let cur = [];
for (const a of actions) {
    if (cur.length > 0 && doc([...cur, a]).length > 5000) { out.push(doc(cur)); cur = []; }
    cur.push(a);
}
if (cur.length > 0) out.push(doc(cur));
process.stdout.write(out.join("\n"));
' <<<"$deny_names") || { echo "check-policies: cannot build the deny rows' name documents" >&2; exit 1; }
bad=0
while IFS= read -r d; do
    errors=$(aws accessanalyzer validate-policy --region "$region" --policy-type IDENTITY_POLICY --policy-document "$d" \
        --query "findings[?findingType=='ERROR'].[issueCode,findingDetails]" --output text)
    if [ -n "$errors" ]; then printf '%s\n' "$errors" | sed 's/^/    /' >&2; bad=1; fi
done <<<"$chunks"
test "$bad" -eq 0 || { echo "check-policies: a deny row names an action that does not exist (above): it passes without proving anything" >&2; exit 1; }
printf 'validate-policy %-16s %-16s %d actions, no ERROR\n' "deny rows" IDENTITY_POLICY "$(wc -l <<<"$deny_names" | tr -d ' ')"
echo "check-policies: ok (Access Analyzer clean of ERROR and SECURITY_WARNING; runtime policy matches §9 and S5; the proxy role holds its own parameters and log group only; the operator role creates ENIs only in the VM subnet with the VM security group, under the pinned managed policy; ai-env-ops runs the proxy's three documents and reads, nothing that deploys or widens egress; ai-env-deployer's five policies manage themselves, the ops user and the keys within their documented limits; every action a deny row names exists)"
