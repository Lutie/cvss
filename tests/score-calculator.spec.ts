import { calculateBaseScore, calculateEnvironmentalScore, calculateTemporalScore } from '../src';
import { expect } from 'chai';

describe('Calculator', () => {
  it('should calculate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" score as 8.6', () => {
    const { score } = calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N');
    expect(score).to.equal(8.6);
  });

  it('should calculate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" score as 10.0', () => {
    const { score } = calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    expect(score).to.equal(10);
  });

  it('should calculate "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N" score as 0.0', () => {
    const { score } = calculateBaseScore('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N');
    expect(score).to.equal(0);
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should calculate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" score as 7.5', () => {
    const { score } = calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
    expect(score).to.equal(7.5);
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should calculate "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" score as 7.8', () => {
    const { score } = calculateBaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H');
    expect(score).to.equal(7.8);
  });

  // https://www.first.org/cvss/user-guide#3-6-Vulnerable-Components-Protected-by-a-Firewall
  it('should calculate "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N" score as 6.4', () => {
    const { score } = calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N');
    expect(score).to.equal(6.4);
  });

  it('should calculate "CVSS:3.1/S:C/C:L/I:L/A:N/AV:N/AC:L/PR:L/UI:N" (non-normalized order) score as 6.4', () => {
    const { score } = calculateBaseScore('CVSS:3.1/S:C/C:L/I:L/A:N/AV:N/AC:L/PR:L/UI:N');
    expect(score).to.equal(6.4);
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseScore('')).to.throw();
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on missing metric', () => {
    expect(() => calculateBaseScore('CVSS:3.1/A:H')).to.throw();
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on unsupported version', () => {
    expect(() => calculateBaseScore('CVSS:2.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')).to.throw();
  });
});

describe('Calculator for temporal scope', () => {
  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:H/MA:X" score as 4.1', () => {
    const { score } = calculateTemporalScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:H/MA:X'
    );
    expect(score).to.equal(4.1);
  });
});

describe('Calculator for environmental scope', () => {
  it('should calculate "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N/E:U/RL:T/RC:C/CR:X/IR:L/AR:L/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L" score as 5.4', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N/E:U/RL:T/RC:C/CR:X/IR:L/AR:L/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L'
    );
    expect(score).to.equal(3.6);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N/E:P/RL:W/RC:C/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MI:L/MA:L" score as 4.0', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N/E:P/RL:W/RC:C/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MI:L/MA:L'
    );
    expect(score).to.equal(4.0);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N" score as 0.0', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N'
    );
    expect(score).to.equal(0);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:H/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H" score as 10.0', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:H/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H'
    );
    expect(score).to.equal(10);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:M/IR:M/AR:L/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:N/MA:L" score as 2.4', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:M/IR:M/AR:L/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:N/MA:L'
    );
    expect(score).to.equal(2.4);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MC:N/MI:H/MA:N" score as 4.8', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MC:N/MI:H/MA:N'
    );
    expect(score).to.equal(4.8);
  });

  it('Should calculate "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:N" environmental score as 5.6', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:N'
    );
    expect(score).to.equal(5.6);
  });
});

describe('Calculate correctly impact and exploitability', () => {
  it('base impact should be 0', () => {
    const { impact, exploitability } = calculateBaseScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N'
    );
    expect(impact).to.equal(3.8);
    expect(exploitability).to.equal(1);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N" base score as 6.1', () => {
    const { score } = calculateBaseScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N'
    );
    expect(score).to.equal(5.1);
  });

  it('should calculate "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N" environmental score as 6.1', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N'
    );
    expect(score).to.equal(0);
  });
});

describe('v3.0 and 3.1 are calculated with their respectives rules', () => {
  it('should calculate "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:H/RL:U/RC:C/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:L" environmental score as 6.1', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:H/RL:U/RC:C/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:L'
    );
    expect(score).to.equal(6.1);
  });
  it('should calculate "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:H/RL:U/RC:C/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:L" environmental score as 6.2', () => {
    const { score } = calculateEnvironmentalScore(
      'CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:H/RL:U/RC:C/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:L'
    );
    expect(score).to.equal(6.2);
  });
});
