# S5 egress fixtures

`lambda-core.get-network-connector.json` is the golden `aws lambda-core
get-network-connector` answer, in the response shape of the CLI's model
(botocore `lambda-core/2026-04-30`, `GetNetworkConnectorResponse`: unwrapped
`Arn`, `Name`, `Id`, `Version`, `Configuration.VpcEgressConfiguration`,
`OperatorRole`, `State`, `StateReason`, `StateReasonCode`,
`LastUpdateStatus*`, `LastModified`). The account is the documentation
account `123456789012`; the Id, subnet and security group ids are made up.
Tests copy it into a `FAKE_AWS_ANSWERS` directory (tests/fakes/aws.sh).
