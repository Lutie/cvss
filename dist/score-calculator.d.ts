import { Metric, MetricValue } from './models';
export declare const calculateIss: (metricsMap: Map<Metric, MetricValue>) => number;
export declare const calculateMiss: (metricsMap: Map<Metric, MetricValue>) => number;
export declare const calculateImpact: (metricsMap: Map<Metric, MetricValue>, iss: number) => number;
export declare const calculateMImpact: (metricsMap: Map<Metric, MetricValue>, miss: number, versionStr: string | null) => number;
export declare const calculateExploitability: (metricsMap: Map<Metric, MetricValue>) => number;
export declare const calculateMExploitability: (metricsMap: Map<Metric, MetricValue>) => number;
declare type ScoreResult = {
    score: number;
    impact: number;
    exploitability: number;
    metricsMap: Map<Metric, MetricValue>;
};
export declare const populateUndefinedMetrics: (metricsMap: Map<Metric, MetricValue>) => Map<Metric, MetricValue>;
export declare const calculateEnvironmentalScore: (cvssString: string) => ScoreResult;
export declare const calculateBaseScore: (cvssString: string) => ScoreResult;
export declare const calculateTemporalScore: (cvssString: string) => ScoreResult;
export {};
