var BaseMetric;
(function (BaseMetric) {
    BaseMetric["ATTACK_VECTOR"] = "AV";
    BaseMetric["ATTACK_COMPLEXITY"] = "AC";
    BaseMetric["PRIVILEGES_REQUIRED"] = "PR";
    BaseMetric["USER_INTERACTION"] = "UI";
    BaseMetric["SCOPE"] = "S";
    BaseMetric["CONFIDENTIALITY"] = "C";
    BaseMetric["INTEGRITY"] = "I";
    BaseMetric["AVAILABILITY"] = "A";
})(BaseMetric || (BaseMetric = {}));
var TemporalMetric;
(function (TemporalMetric) {
    TemporalMetric["EXPLOITABILITY"] = "E";
    TemporalMetric["REMEDIATION_LEVEL"] = "RL";
    TemporalMetric["REPORT_CONFIDENCE"] = "RC";
})(TemporalMetric || (TemporalMetric = {}));
var EnvironmentalMetric;
(function (EnvironmentalMetric) {
    EnvironmentalMetric["ATTACK_VECTOR"] = "MAV";
    EnvironmentalMetric["ATTACK_COMPLEXITY"] = "MAC";
    EnvironmentalMetric["PRIVILEGES_REQUIRED"] = "MPR";
    EnvironmentalMetric["USER_INTERACTION"] = "MUI";
    EnvironmentalMetric["SCOPE"] = "MS";
    EnvironmentalMetric["CONFIDENTIALITY"] = "MC";
    EnvironmentalMetric["INTEGRITY"] = "MI";
    EnvironmentalMetric["AVAILABILITY"] = "MA";
    EnvironmentalMetric["CONFIDENTIALITY_REQUIREMENT"] = "CR";
    EnvironmentalMetric["INTEGRITY_REQUIREMENT"] = "IR";
    EnvironmentalMetric["AVAILABILITY_REQUIREMENT"] = "AR";
})(EnvironmentalMetric || (EnvironmentalMetric = {}));
const baseMetricValues = {
    [BaseMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P'],
    [BaseMetric.ATTACK_COMPLEXITY]: ['L', 'H'],
    [BaseMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H'],
    [BaseMetric.USER_INTERACTION]: ['N', 'R'],
    [BaseMetric.SCOPE]: ['U', 'C'],
    [BaseMetric.CONFIDENTIALITY]: ['N', 'L', 'H'],
    [BaseMetric.INTEGRITY]: ['N', 'L', 'H'],
    [BaseMetric.AVAILABILITY]: ['N', 'L', 'H']
};
const environmentalMetricValues = {
    [EnvironmentalMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P', 'X'],
    [EnvironmentalMetric.ATTACK_COMPLEXITY]: ['L', 'H', 'X'],
    [EnvironmentalMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.USER_INTERACTION]: ['N', 'R', 'X'],
    [EnvironmentalMetric.SCOPE]: ['U', 'C', 'X'],
    [EnvironmentalMetric.CONFIDENTIALITY]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.INTEGRITY]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.AVAILABILITY]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: ['M', 'L', 'H', 'X'],
    [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: ['M', 'L', 'H', 'X'],
    [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: ['M', 'L', 'H', 'X']
};
const temporalMetricValues = {
    [TemporalMetric.EXPLOITABILITY]: ['X', 'U', 'P', 'F', 'H'],
    [TemporalMetric.REMEDIATION_LEVEL]: ['X', 'O', 'T', 'W', 'U'],
    [TemporalMetric.REPORT_CONFIDENCE]: ['X', 'U', 'R', 'C']
};
const baseMetrics = [
    BaseMetric.ATTACK_VECTOR,
    BaseMetric.ATTACK_COMPLEXITY,
    BaseMetric.PRIVILEGES_REQUIRED,
    BaseMetric.USER_INTERACTION,
    BaseMetric.SCOPE,
    BaseMetric.CONFIDENTIALITY,
    BaseMetric.INTEGRITY,
    BaseMetric.AVAILABILITY
];
const temporalMetrics = [
    TemporalMetric.EXPLOITABILITY,
    TemporalMetric.REMEDIATION_LEVEL,
    TemporalMetric.REPORT_CONFIDENCE
];
const environmentalMetrics = [
    EnvironmentalMetric.ATTACK_VECTOR,
    EnvironmentalMetric.ATTACK_COMPLEXITY,
    EnvironmentalMetric.PRIVILEGES_REQUIRED,
    EnvironmentalMetric.USER_INTERACTION,
    EnvironmentalMetric.SCOPE,
    EnvironmentalMetric.CONFIDENTIALITY,
    EnvironmentalMetric.INTEGRITY,
    EnvironmentalMetric.AVAILABILITY,
    EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
    EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
    EnvironmentalMetric.INTEGRITY_REQUIREMENT
];

// TODO replace with mapping
const humanizeBaseMetric = (metric) => {
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
const humanizeBaseMetricValue = (value, metric) => {
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
const toSeverity = (score) => score <= 0 ? 'None' : score <= 3 ? 'Low' : score <= 6 ? 'Medium' : score <= 8.5 ? 'High' : 'Critical';

const VERSION_REGEX = /^CVSS:(\d(?:\.\d)?)(.*)?$/;
const parseVersion = (cvssStr) => {
    const versionRegexRes = VERSION_REGEX.exec(cvssStr);
    return versionRegexRes && versionRegexRes[1];
};
const parseVector = (cvssStr) => {
    const versionRegexRes = VERSION_REGEX.exec(cvssStr);
    return versionRegexRes && versionRegexRes[2] && versionRegexRes[2].substr(1);
};
const parseMetrics = (vectorStr) => (vectorStr ? vectorStr.split('/') : []).map((metric) => {
    if (!metric) {
        return { key: '', value: '' };
    }
    const parts = metric.split(':');
    return { key: parts[0], value: parts[1] };
});
const parseMetricsAsMap = (cvssStr) => parseMetrics(parseVector(cvssStr) || '').reduce((res, metric) => {
    if (res.has(metric.key)) {
        throw new Error(`Duplicated metric: "${metric.key}:${metric.value || ''}"`);
    }
    return res.set(metric.key, metric.value);
}, new Map());

const validateVersion = (versionStr) => {
    if (!versionStr) {
        throw new Error('Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L');
    }
    if (versionStr !== '3.0' && versionStr !== '3.1') {
        throw new Error(`Unsupported CVSS version: ${versionStr}. Only 3.0 and 3.1 are supported`);
    }
};
const validateVector = (vectorStr) => {
    if (!vectorStr || vectorStr.includes('//')) {
        throw new Error('Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L');
    }
};
const checkUnknownMetrics = (metricsMap, knownMetrics) => {
    const allKnownMetrics = knownMetrics || [...baseMetrics, ...temporalMetrics, ...environmentalMetrics];
    [...metricsMap.keys()].forEach((userMetric) => {
        if (!allKnownMetrics.includes(userMetric)) {
            throw new Error(`Unknown CVSS metric "${userMetric}". Allowed metrics: ${allKnownMetrics.join(', ')}`);
        }
    });
};
const checkMandatoryMetrics = (metricsMap, metrics = baseMetrics) => {
    metrics.forEach((metric) => {
        if (!metricsMap.has(metric)) {
            // eslint-disable-next-line max-len
            throw new Error(`Missing mandatory CVSS metric ${metrics} (${humanizeBaseMetric(metric)})`);
        }
    });
};
const checkMetricsValues = (metricsMap, metrics, metricsValues) => {
    metrics.forEach((metric) => {
        const userValue = metricsMap.get(metric);
        if (!userValue) {
            return;
        }
        if (!metricsValues[metric].includes(userValue)) {
            const allowedValuesHumanized = metricsValues[metric]
                .map((value) => `${value} (${humanizeBaseMetricValue(value, metric)})`)
                .join(', ');
            throw new Error(`Invalid value for CVSS metric ${metric} (${humanizeBaseMetric(metric)})${userValue ? `: ${userValue}` : ''}. Allowed values: ${allowedValuesHumanized}`);
        }
    });
};
/**
 * Validate that the given string is a valid cvss vector
 * @param cvssStr
 */
const validate = (cvssStr) => {
    if (!cvssStr || !cvssStr.startsWith('CVSS:')) {
        throw new Error('CVSS vector must start with "CVSS:"');
    }
    const allKnownMetrics = [...baseMetrics, ...temporalMetrics, ...environmentalMetrics];
    const allKnownMetricsValues = { ...baseMetricValues, ...temporalMetricValues, ...environmentalMetricValues };
    const versionStr = parseVersion(cvssStr);
    validateVersion(versionStr);
    const vectorStr = parseVector(cvssStr);
    validateVector(vectorStr);
    const metricsMap = parseMetricsAsMap(cvssStr);
    checkMandatoryMetrics(metricsMap);
    checkUnknownMetrics(metricsMap, allKnownMetrics);
    checkMetricsValues(metricsMap, allKnownMetrics, allKnownMetricsValues);
    const isTemporal = [...metricsMap.keys()].some((metric) => temporalMetrics.includes(metric));
    const isEnvironmental = [...metricsMap.keys()].some((metric) => environmentalMetrics.includes(metric));
    return {
        metricsMap,
        isTemporal,
        isEnvironmental
    };
};

// https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values
const baseMetricValueScores = {
    [BaseMetric.ATTACK_VECTOR]: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    [BaseMetric.ATTACK_COMPLEXITY]: { L: 0.77, H: 0.44 },
    [BaseMetric.PRIVILEGES_REQUIRED]: null,
    [BaseMetric.USER_INTERACTION]: { N: 0.85, R: 0.62 },
    [BaseMetric.SCOPE]: { U: 0, C: 0 },
    [BaseMetric.CONFIDENTIALITY]: { N: 0, L: 0.22, H: 0.56 },
    [BaseMetric.INTEGRITY]: { N: 0, L: 0.22, H: 0.56 },
    [BaseMetric.AVAILABILITY]: { N: 0, L: 0.22, H: 0.56 }
};
const temporalMetricValueScores = {
    [TemporalMetric.EXPLOITABILITY]: { X: 1, U: 0.91, F: 0.97, P: 0.94, H: 1 },
    [TemporalMetric.REMEDIATION_LEVEL]: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
    [TemporalMetric.REPORT_CONFIDENCE]: { X: 1, U: 0.92, R: 0.96, C: 1 }
};
const environmentalMetricValueScores = {
    [EnvironmentalMetric.ATTACK_VECTOR]: { N: 0.85, A: 0.62, L: 0.55, P: 0.2, X: 1 },
    [EnvironmentalMetric.ATTACK_COMPLEXITY]: { X: 1, L: 0.77, H: 0.44 },
    [EnvironmentalMetric.PRIVILEGES_REQUIRED]: null,
    [EnvironmentalMetric.USER_INTERACTION]: { N: 0.85, R: 0.62, X: 1 },
    [EnvironmentalMetric.SCOPE]: { U: 0, C: 0, X: 0 },
    [EnvironmentalMetric.CONFIDENTIALITY]: { N: 0, L: 0.22, H: 0.56, X: 0.22 },
    [EnvironmentalMetric.INTEGRITY]: { N: 0, L: 0.22, H: 0.56, X: 0.22 },
    [EnvironmentalMetric.AVAILABILITY]: { N: 0, L: 0.22, H: 0.56, X: 0.22 },
    [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: { M: 1, L: 0.5, H: 1.5, X: 1 },
    [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: { M: 1, L: 0.5, H: 1.5, X: 1 },
    [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: { M: 1, L: 0.5, H: 1.5, X: 1 }
};
const getPrivilegesRequiredNumericValue = (value, scopeValue) => {
    if (scopeValue !== 'U' && scopeValue !== 'C' && scopeValue !== 'X') {
        throw new Error(`Unknown Scope value: ${scopeValue}`);
    }
    switch (value) {
        case 'N':
            return 0.85;
        case 'L':
            return scopeValue !== 'C' ? 0.62 : 0.68;
        case 'H':
            return scopeValue !== 'C' ? 0.27 : 0.5;
        default:
            throw new Error(`Unknown PrivilegesRequired value: ${value}`);
    }
};
const getMetricValue = (metric, metricsMap) => {
    if (!metricsMap.has(metric)) {
        throw new Error(`Missing metric: ${metric}`);
    }
    return metricsMap.get(metric);
};
const getMetricNumericValue = (metric, metricsMap) => {
    const value = getMetricValue(metric, metricsMap);
    if (metric === BaseMetric.PRIVILEGES_REQUIRED) {
        return getPrivilegesRequiredNumericValue(value, getMetricValue(BaseMetric.SCOPE, metricsMap));
    }
    if (metric === EnvironmentalMetric.PRIVILEGES_REQUIRED) {
        return getPrivilegesRequiredNumericValue(value, getMetricValue(EnvironmentalMetric.SCOPE, metricsMap));
    }
    const score = {
        ...baseMetricValueScores,
        ...temporalMetricValueScores,
        ...environmentalMetricValueScores
    }[metric];
    if (!score) {
        throw new Error(`Internal error. Missing metric score: ${metric}`);
    }
    return score[value];
};
// ISS = 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
const calculateIss = (metricsMap) => {
    const confidentiality = getMetricNumericValue(BaseMetric.CONFIDENTIALITY, metricsMap);
    const integrity = getMetricNumericValue(BaseMetric.INTEGRITY, metricsMap);
    const availability = getMetricNumericValue(BaseMetric.AVAILABILITY, metricsMap);
    return 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
};
// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// MISS =Minimum ( 1 - [ (1 - ConfidentialityRequirement × ModifiedConfidentiality) × (1 - IntegrityRequirement × ModifiedIntegrity) × (1 - AvailabilityRequirement × ModifiedAvailability) ],
// 0.915)
const calculateMiss = (metricsMap) => {
    const rConfidentiality = getMetricNumericValue(EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT, metricsMap);
    const mConfidentiality = getMetricNumericValue(EnvironmentalMetric.CONFIDENTIALITY, metricsMap);
    const rIntegrity = getMetricNumericValue(EnvironmentalMetric.INTEGRITY_REQUIREMENT, metricsMap);
    const mIntegrity = getMetricNumericValue(EnvironmentalMetric.INTEGRITY, metricsMap);
    const rAvailability = getMetricNumericValue(EnvironmentalMetric.AVAILABILITY_REQUIREMENT, metricsMap);
    const mAvailability = getMetricNumericValue(EnvironmentalMetric.AVAILABILITY, metricsMap);
    return Math.min(1 - (1 - rConfidentiality * mConfidentiality) * (1 - rIntegrity * mIntegrity) * (1 - rAvailability * mAvailability), 0.915);
};
// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Impact =
//   If Scope is Unchanged 	6.42 × ISS
//   If Scope is Changed 	7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)
const calculateImpact = (metricsMap, iss) => metricsMap.get(BaseMetric.SCOPE) !== 'C' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// ModifiedImpact =
// If ModifiedScope is Unchanged	6.42 × MISS
// If ModifiedScope is Changed	7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)13
// ModifiedExploitability =	8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
const calculateMImpact = (metricsMap, miss) => metricsMap.get(EnvironmentalMetric.SCOPE) !== 'C'
    ? 6.42 * miss
    : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
const calculateExploitability = (metricsMap) => 8.22 *
    getMetricNumericValue(BaseMetric.ATTACK_VECTOR, metricsMap) *
    getMetricNumericValue(BaseMetric.ATTACK_COMPLEXITY, metricsMap) *
    getMetricNumericValue(BaseMetric.PRIVILEGES_REQUIRED, metricsMap) *
    getMetricNumericValue(BaseMetric.USER_INTERACTION, metricsMap);
// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// Exploitability = 8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
const calculateMExploitability = (metricsMap) => 8.22 *
    getMetricNumericValue(EnvironmentalMetric.ATTACK_VECTOR, metricsMap) *
    getMetricNumericValue(EnvironmentalMetric.ATTACK_COMPLEXITY, metricsMap) *
    getMetricNumericValue(EnvironmentalMetric.PRIVILEGES_REQUIRED, metricsMap) *
    getMetricNumericValue(EnvironmentalMetric.USER_INTERACTION, metricsMap);
// https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
const roundUp = (input) => {
    const intInput = Math.round(input * 100000);
    return intInput % 10000 === 0 ? intInput / 100000 : (Math.floor(intInput / 10000) + 1) / 10;
};
// https://www.first.org/cvss/v3.0/specification-document#7-3-Environmental-Metrics-Equations
// If ModifiedImpact <= 0 =>	0; else
// If ModifiedScope is	Roundup ( Roundup [Minimum ([ModifiedImpact + ModifiedExploitability], 10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
// Unchanged
// If ModifiedScope is	Roundup (
//   Roundup [
//     Minimum (
//       1.08 × [ModifiedImpact + ModifiedExploitability], 10
//     )
//   ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
// Changed
const calculateEnvironmentalScore = (cvssString) => {
    const { metricsMap } = validate(cvssString);
    // populate temp and env metrics if not provided
    [...temporalMetrics, ...environmentalMetrics].map((metric) => {
        if (![...metricsMap.keys()].includes(metric)) {
            metricsMap.set(metric, 'X');
        }
    });
    const miss = calculateMiss(metricsMap);
    const impact = calculateMImpact(metricsMap, miss);
    const exploitability = calculateMExploitability(metricsMap);
    const scopeUnchanged = metricsMap.get(EnvironmentalMetric.SCOPE) !== 'C';
    const score = impact <= 0
        ? 0
        : scopeUnchanged
            ? roundUp(roundUp(Math.min(impact + exploitability, 10)) *
                getMetricNumericValue(TemporalMetric.EXPLOITABILITY, metricsMap) *
                getMetricNumericValue(TemporalMetric.REMEDIATION_LEVEL, metricsMap) *
                getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap))
            : roundUp(roundUp(Math.min(1.08 * (impact + exploitability), 10)) *
                getMetricNumericValue(TemporalMetric.EXPLOITABILITY, metricsMap) *
                getMetricNumericValue(TemporalMetric.REMEDIATION_LEVEL, metricsMap) *
                getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap));
    return {
        score,
        impact: impact <= 0 ? 0 : roundUp(impact),
        exploitability: impact <= 0 ? 0 : roundUp(exploitability)
    };
};
// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// If Impact <= 0 => 0; else
// If Scope is Unchanged => Roundup (Minimum [(Impact + Exploitability), 10])
// If Scope is Changed => Roundup (Minimum [1.08 × (Impact + Exploitability), 10])
const calculateBaseScore = (cvssString) => {
    const { metricsMap } = validate(cvssString);
    const iss = calculateIss(metricsMap);
    const impact = calculateImpact(metricsMap, iss);
    const exploitability = calculateExploitability(metricsMap);
    const scopeUnchanged = metricsMap.get(BaseMetric.SCOPE) !== 'C';
    const score = impact <= 0
        ? 0
        : scopeUnchanged
            ? roundUp(Math.min(impact + exploitability, 10))
            : roundUp(Math.min(1.08 * (impact + exploitability), 10));
    return {
        score,
        impact: impact <= 0 ? 0 : roundUp(impact),
        exploitability: impact <= 0 ? 0 : roundUp(exploitability)
    };
};
// https://www.first.org/cvss/v3.1/specification-document#7-2-Temporal-Metrics-Equations
// 	Roundup (BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
const calculateTemporalScore = (cvssString) => {
    const { metricsMap } = validate(cvssString);
    // populate temp metrics if not provided
    [...temporalMetrics].map((metric) => {
        if (![...metricsMap.keys()].includes(metric)) {
            metricsMap.set(metric, 'X');
        }
    });
    const { score, impact, exploitability } = calculateBaseScore(cvssString);
    const tempScore = roundUp(score *
        getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap) *
        getMetricNumericValue(TemporalMetric.EXPLOITABILITY, metricsMap) *
        getMetricNumericValue(TemporalMetric.REMEDIATION_LEVEL, metricsMap));
    return {
        score: tempScore,
        impact,
        exploitability
    };
};

export { BaseMetric, EnvironmentalMetric, TemporalMetric, baseMetricValues, baseMetrics, calculateBaseScore, calculateEnvironmentalScore, calculateExploitability, calculateImpact, calculateIss, calculateMExploitability, calculateMImpact, calculateMiss, calculateTemporalScore, environmentalMetricValues, environmentalMetrics, humanizeBaseMetric, humanizeBaseMetricValue, parseMetrics, parseMetricsAsMap, parseVector, parseVersion, temporalMetricValues, temporalMetrics, toSeverity, validate, validateVersion };
