import { BaseMetric } from './models';
// TODO replace with mapping
export const humanizeBaseMetric = (metric) => {
    switch (metric) {
        case BaseMetric.ATTACK_VECTOR:
            return 'Attack Vector';
        case BaseMetric.ATTACK_COMPLEXITY:
            return 'Attack Complexity';
        case BaseMetric.PRIVILEGES_REQUIRED:
            return 'Privileges Required';
        case BaseMetric.USER_INTERACTION:
            return 'User Interaction';
        case BaseMetric.SCOPE:
            return 'Scope';
        case BaseMetric.CONFIDENTIALITY:
            return 'Confidentiality';
        case BaseMetric.INTEGRITY:
            return 'Integrity';
        case BaseMetric.AVAILABILITY:
            return 'Availability';
        default:
            return 'Unknown';
    }
};
// eslint-disable-next-line complexity
export const humanizeBaseMetricValue = (value, metric) => {
    switch (value) {
        case 'A':
            return 'Adjacent';
        case 'C':
            return 'Changed';
        case 'H':
            return 'High';
        case 'L':
            return metric === BaseMetric.ATTACK_VECTOR ? 'Local' : 'Low';
        case 'N':
            return metric === BaseMetric.ATTACK_VECTOR ? 'Network' : 'None';
        case 'P':
            return 'Physical';
        case 'R':
            return 'Required';
        case 'U':
            return 'Unchanged';
        default:
            return 'Unknown';
    }
};
/**
 * Stringify an score into a severity string ('None' | 'Low' | 'Medium' | 'High' | 'Critical')
 * @param score
 */
export const toSeverity = (score) => score <= 0 ? 'None' : score <= 3 ? 'Low' : score <= 6 ? 'Medium' : score <= 8.5 ? 'High' : 'Critical';
