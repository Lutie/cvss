import { BaseMetric, BaseMetricValue, humanizeBaseMetric, humanizeBaseMetricValue, toRiskStr } from '../src';
import { expect } from 'chai';

describe('humanizer', () => {
  it('should humanize base metric AV', () => {
    const result = humanizeBaseMetric(BaseMetric.ATTACK_VECTOR);
    expect(result).to.equal('Attack Vector');
  });

  it('should produce "Unknown" for unknown metric', () => {
    const result = humanizeBaseMetric(('X' as unknown) as BaseMetric);
    expect(result).to.equal('Unknown');
  });

  it('should humanize base metric AV value L', () => {
    const result = humanizeBaseMetricValue('L', BaseMetric.ATTACK_VECTOR);
    expect(result).to.equal('Local');
  });

  it('should humanize base metric A value L', () => {
    const result = humanizeBaseMetricValue('L', BaseMetric.AVAILABILITY);
    expect(result).to.equal('Low');
  });

  it('should humanize base metric AV value N', () => {
    const result = humanizeBaseMetricValue('N', BaseMetric.ATTACK_VECTOR);
    expect(result).to.equal('Network');
  });

  it('should humanize base metric C value N', () => {
    const result = humanizeBaseMetricValue('N', BaseMetric.CONFIDENTIALITY);
    expect(result).to.equal('None');
  });

  it('should produce "Unknown" for unknown value of existing metric', () => {
    const result = humanizeBaseMetricValue(('X' as unknown) as BaseMetricValue, BaseMetric.SCOPE);
    expect(result).to.equal('Unknown');
  });

  it('should produce "Unknown" for unknown value of unknown metric', () => {
    const result = humanizeBaseMetricValue(('X' as unknown) as BaseMetricValue, ('X' as unknown) as BaseMetric);
    expect(result).to.equal('Unknown');
  });
});

describe('risk levels', () => {
  it('Should give None risk level when score is below 0', () => {
    expect(toRiskStr(0)).to.equal('None');
    expect(toRiskStr(-7)).to.equal('None');
  });
  it('Should give Low risk level when score is below 3', () => {
    expect(toRiskStr(3)).to.equal('Low');
    expect(toRiskStr(1.2654)).to.equal('Low');
  });
  it('Should give Medium risk level when score is below 6', () => {
    expect(toRiskStr(6)).to.equal('Medium');
    expect(toRiskStr(4.2654)).to.equal('Medium');
  });
  it('Should give High risk level when score is below 8.5', () => {
    expect(toRiskStr(8.5)).to.equal('High');
    expect(toRiskStr(7.2654)).to.equal('High');
  });
});
