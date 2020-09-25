import { Metric, MetricValue } from './models';
export declare const humanizeBaseMetric: (metric: Metric) => string;
export declare const humanizeBaseMetricValue: (value: MetricValue, metric: Metric) => string;
declare type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
/**
 * Stringify an score into a severity string ('None' | 'Low' | 'Medium' | 'High' | 'Critical')
 * @param score
 */
export declare const toSeverity: (score: number) => Severity;
export {};
