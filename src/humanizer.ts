import { BaseMetric, Metric, MetricValue } from './models';

// TODO replace with mapping
export const humanizeBaseMetric = (metric: Metric): string => {
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
export const humanizeBaseMetricValue = (value: MetricValue, metric: Metric): string => {
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

type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

/**
 * Stringify an score into a severity string ('None' | 'Low' | 'Medium' | 'High' | 'Critical')
 * @param score
 */
export const toSeverity = (score: number): Severity =>
  score <= 0 ? 'None' : score <= 3.9 ? 'Low' : score <= 6.9 ? 'Medium' : score <= 8.9 ? 'High' : 'Critical';
