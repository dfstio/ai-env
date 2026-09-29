// The monthly cost alarm ai-env-monthly (D25): an email at 80 % and 100 % of actual spend on AWS Lambda in the
// pinned region. Why both filters: Lambda functions of other projects exist in two other regions and must not eat
// this budget. The budget is an alarm with a lag, not a stop.
//
// The email and the limit come from config/<stack>.env (not committed; only config/dev.env.example is), so the
// public repo never carries an address.
import * as aws from "@pulumi/aws";
import { BUDGET_NAME } from "./policies";

export interface BudgetSettings {
    email: string;
    /** USD, as the budgets API spells it ("40", "40.5"). */
    limitUsd: string;
}

export const DEFAULT_LIMIT_USD = "40";
/** Cost Explorer's service name for Lambda (MicroVM usage bills under it). */
const LAMBDA_SERVICE_NAME = "AWS Lambda";

/** BUDGET_EMAIL (required) and BUDGET_LIMIT_USD (default 40) from the stack's env file. */
export function budgetSettings(env: Record<string, string>, file: string): BudgetSettings {
    const email = env.BUDGET_EMAIL ?? "";
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        throw new Error(`${file}: BUDGET_EMAIL is missing or not an email address (copy config/dev.env.example to ${file} and set it)`);
    }
    const limitUsd = env.BUDGET_LIMIT_USD || DEFAULT_LIMIT_USD;
    if (!/^[0-9]+(\.[0-9]{1,2})?$/.test(limitUsd) || Number(limitUsd) <= 0) throw new Error(`${file}: BUDGET_LIMIT_USD must be a positive amount in USD, got ${limitUsd}`);
    return { email, limitUsd };
}

export function createBudget(settings: BudgetSettings, region: string, tags: Record<string, string>, provider: aws.Provider): aws.budgets.Budget {
    const notify = (threshold: number) => ({
        comparisonOperator: "GREATER_THAN", threshold, thresholdType: "PERCENTAGE", notificationType: "ACTUAL", subscriberEmailAddresses: [settings.email],
    });
    return new aws.budgets.Budget(BUDGET_NAME, {
        name: BUDGET_NAME,
        budgetType: "COST",
        timeUnit: "MONTHLY",
        limitAmount: settings.limitUsd,
        limitUnit: "USD",
        // Fallback if the API refuses the Region key: Service only, and record it (D25).
        costFilters: [{ name: "Service", values: [LAMBDA_SERVICE_NAME] }, { name: "Region", values: [region] }],
        notifications: [notify(80), notify(100)],
        tags,
    }, { provider });
}
