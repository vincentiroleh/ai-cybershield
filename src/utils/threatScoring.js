class ThreatScoring {
  constructor() {
    this.severityWeights = {
      HIGH: 70,
      MEDIUM: 40,
      LOW: 20,
      INFO: 0,
    };

    this.categoryWeights = {
      AUTH: 25,
      INJECTION: 30,
      XSS: 25,
      RECONNAISSANCE: 20,
      MALWARE: 30,
      FILE_SYSTEM: 25,
      NETWORK: 20,
      DATABASE: 25,
    };
  }

  calculateThreatScore(threat, context, behaviorAnalysis) {
    let score = 0;

    // Base severity score
    score += this.severityWeights[threat.severity] || 0;

    // Category-based score
    score += this.categoryWeights[threat.category] || 0;

    // Context-based scoring
    score += this.calculateContextScore(context);

    // Behavior-based scoring
    if (behaviorAnalysis) {
      score += this.calculateBehaviorScore(behaviorAnalysis);
    }

    // Time-based factors
    score += this.calculateTimeBasedScore(threat.timestamp);

    // Normalize final score to 0-100 range
    return Math.min(Math.max(Math.round(score), 0), 100);
  }

  calculateContextScore(context) {
    let contextScore = 0;

    if (!context) return contextScore;

    // Multiple occurrences increase the score
    if (context.occurrences > 1) {
      contextScore += Math.min(context.occurrences * 5, 20);
    }

    // Related events increase the score
    if (context.relatedEvents && context.relatedEvents.length > 0) {
      contextScore += Math.min(context.relatedEvents.length * 3, 15);
    }

    return contextScore;
  }

  calculateBehaviorScore(behaviorAnalysis) {
    let behaviorScore = 0;

    if (!behaviorAnalysis) return behaviorScore;

    // Frequency-based scoring
    if (
      behaviorAnalysis.frequency &&
      behaviorAnalysis.frequency.isHighFrequency
    ) {
      behaviorScore += 15;
    }

    // Timing pattern scoring
    if (
      behaviorAnalysis.unusualTiming &&
      behaviorAnalysis.unusualTiming.suspicious
    ) {
      behaviorScore += 10;
      if (behaviorAnalysis.unusualTiming.regularPattern) {
        behaviorScore += 5; // Additional points for potential automated attacks
      }
    }

    // Suspicious sequence scoring
    if (
      behaviorAnalysis.suspiciousSequence &&
      behaviorAnalysis.suspiciousSequence.suspicious
    ) {
      behaviorScore += 15;
    }

    return behaviorScore;
  }

  calculateTimeBasedScore(timestamp) {
    let timeScore = 0;
    const eventTime = new Date(timestamp);
    const hour = eventTime.getHours();

    // Higher score for events during unusual hours (night time)
    if (hour >= 22 || hour <= 5) {
      timeScore += 10;
    }

    // Weekend check
    const day = eventTime.getDay();
    if (day === 0 || day === 6) {
      // Sunday = 0, Saturday = 6
      timeScore += 5;
    }

    return timeScore;
  }

  getThreatLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'INFO';
  }

  getRecommendedActions(score, category) {
    const categorySpecificActions = {
      AUTH: {
        CRITICAL: [
          'Reset all user credentials',
          'Enable 2FA for all users',
          'Lock affected accounts',
        ],
        HIGH: [
          'Review authentication logs',
          'Enable additional monitoring for auth endpoints',
        ],
        MEDIUM: [
          'Review failed login attempts',
          'Check for unusual login patterns',
        ],
        LOW: ['Monitor authentication activity'],
      },
      INJECTION: {
        CRITICAL: [
          'Block malicious IPs',
          'Patch vulnerable endpoints',
          'Review input validation',
        ],
        HIGH: ['Enable WAF rules', 'Review input sanitization'],
        MEDIUM: ['Monitor SQL queries', 'Review application logs'],
        LOW: ['Log suspicious requests'],
      },
      XSS: {
        CRITICAL: [
          'Implement Content Security Policy',
          'Sanitize all user inputs',
        ],
        HIGH: ['Review output encoding', 'Enable XSS protection headers'],
        MEDIUM: ['Monitor suspicious patterns', 'Review client-side scripts'],
        LOW: ['Log suspicious requests'],
      },
      RECONNAISSANCE: {
        CRITICAL: ['Block scanning IPs', 'Review firewall rules'],
        HIGH: ['Enable rate limiting', 'Monitor unusual traffic patterns'],
        MEDIUM: ['Review access logs', 'Monitor port scanning attempts'],
        LOW: ['Log suspicious activity'],
      },
      MALWARE: {
        CRITICAL: [
          'Isolate affected systems',
          'Run full system scan',
          'Update antivirus',
        ],
        HIGH: ['Review file integrity', 'Scan for indicators of compromise'],
        MEDIUM: ['Monitor system behavior', 'Update security definitions'],
        LOW: ['Log suspicious files'],
      },
      FILE_SYSTEM: {
        CRITICAL: ['Lock down file permissions', 'Review file access logs'],
        HIGH: ['Monitor file operations', 'Check file integrity'],
        MEDIUM: ['Review access patterns', 'Monitor sensitive directories'],
        LOW: ['Log file access attempts'],
      },
      NETWORK: {
        CRITICAL: ['Block suspicious traffic', 'Review firewall rules'],
        HIGH: ['Monitor network patterns', 'Review network logs'],
        MEDIUM: ['Check unusual connections', 'Monitor bandwidth usage'],
        LOW: ['Log network activity'],
      },
      DATABASE: {
        CRITICAL: ['Block database access', 'Review database permissions'],
        HIGH: ['Monitor query patterns', 'Review database logs'],
        MEDIUM: ['Check unusual queries', 'Monitor database load'],
        LOW: ['Log database access'],
      },
    };

    const threatLevel = this.getThreatLevel(score);
    const baseActions = {
      CRITICAL: {
        immediate: true,
        actions: [
          'Block source IP immediately',
          'Alert security team',
          'Initiate incident response',
        ],
      },
      HIGH: {
        immediate: true,
        actions: [
          'Investigate immediately',
          'Consider IP blocking',
          'Monitor related systems',
        ],
      },
      MEDIUM: {
        immediate: false,
        actions: [
          'Investigate within 4 hours',
          'Increase monitoring',
          'Review security logs',
        ],
      },
      LOW: {
        immediate: false,
        actions: ['Monitor activity', 'Log for future reference'],
      },
    };

    // Combine base actions with category-specific actions
    const baseActionSet = baseActions[threatLevel] || baseActions.LOW;
    const categoryActions =
      category && categorySpecificActions[category]
        ? categorySpecificActions[category][threatLevel] || []
        : [];

    return {
      ...baseActionSet,
      actions: [...baseActionSet.actions, ...categoryActions],
    };
  }
}

export default ThreatScoring;