export default class CorrelationEngine {
  constructor() {
    this.timeWindowMs = 15 * 60 * 1000; // 15 minutes default window
    this.correlationRules = {
      AUTH: {
        relatedCategories: ['RECONNAISSANCE', 'INJECTION'],
        threshold: 3,
        timeWindow: 5 * 60 * 1000, // 5 minutes
      },
      RECONNAISSANCE: {
        relatedCategories: ['INJECTION', 'XSS', 'AUTH'],
        threshold: 2,
        timeWindow: 10 * 60 * 1000, // 10 minutes
      },
      INJECTION: {
        relatedCategories: ['XSS', 'AUTH'],
        threshold: 2,
        timeWindow: 5 * 60 * 1000,
      },
    };
  }

  correlateThreats(threats) {
    if (!Array.isArray(threats) || threats.length === 0) {
      return { correlatedEvents: [], patterns: [] };
    }

    const correlatedEvents = this.findCorrelatedEvents(threats);
    const patterns = this.identifyAttackPatterns(threats);

    return {
      correlatedEvents,
      patterns,
      summary: this.generateCorrelationSummary(correlatedEvents, patterns),
    };
  }

  findCorrelatedEvents(threats) {
    const correlatedGroups = [];
    const processedThreats = new Set();

    threats.forEach((threat, index) => {
      if (processedThreats.has(index)) return;

      const correlatedGroup = {
        primaryThreat: threat,
        relatedThreats: [],
        correlationType: [],
        riskLevel: threat.threatLevel || 'MEDIUM',
      };

      // Look for related threats
      threats.forEach((relatedThreat, relatedIndex) => {
        if (index === relatedIndex || processedThreats.has(relatedIndex))
          return;

        const correlation = this.checkCorrelation(threat, relatedThreat);
        if (correlation.isCorrelated) {
          correlatedGroup.relatedThreats.push(relatedThreat);
          correlatedGroup.correlationType.push(correlation.type);
          processedThreats.add(relatedIndex);

          // Upgrade risk level if necessary
          if (
            this.getThreatLevelWeight(relatedThreat.threatLevel) >
            this.getThreatLevelWeight(correlatedGroup.riskLevel)
          ) {
            correlatedGroup.riskLevel = relatedThreat.threatLevel;
          }
        }
      });

      if (correlatedGroup.relatedThreats.length > 0) {
        processedThreats.add(index);
        correlatedGroups.push(correlatedGroup);
      }
    });

    return correlatedGroups;
  }

  checkCorrelation(threat1, threat2) {
    const timeDiff = Math.abs(
      new Date(threat1.timestamp) - new Date(threat2.timestamp),
    );
    const sameIP =
      threat1.sourceIP &&
      threat2.sourceIP &&
      threat1.sourceIP === threat2.sourceIP;
    const rule = this.correlationRules[threat1.category];

    const correlation = {
      isCorrelated: false,
      type: [],
    };

    // Check time-based correlation
    if (timeDiff <= (rule?.timeWindow || this.timeWindowMs)) {
      correlation.type.push('temporal');
      correlation.isCorrelated = true;
    }

    // Check IP-based correlation
    if (sameIP) {
      correlation.type.push('source');
      correlation.isCorrelated = true;
    }

    // Check category-based correlation
    if (rule?.relatedCategories?.includes(threat2.category)) {
      correlation.type.push('categorical');
      correlation.isCorrelated = true;
    }

    return correlation;
  }

  identifyAttackPatterns(threats) {
    const patterns = [];
    const timeOrderedThreats = [...threats].sort(
      (a, b) => new Date(a.timestamp) - new Date(b.timestamp),
    );

    // Known attack pattern definitions
    const knownPatterns = [
      {
        name: 'Reconnaissance followed by Attack',
        sequence: ['RECONNAISSANCE', ['INJECTION', 'XSS', 'AUTH']],
        timeWindow: 30 * 60 * 1000, // 30 minutes
      },
      {
        name: 'Brute Force Attack',
        category: 'AUTH',
        minOccurrences: 5,
        timeWindow: 5 * 60 * 1000, // 5 minutes
      },
      {
        name: 'Multi-Vector Attack',
        uniqueCategories: 3,
        timeWindow: 15 * 60 * 1000, // 15 minutes
      },
    ];

    knownPatterns.forEach(pattern => {
      const matchedPattern = this.matchPattern(timeOrderedThreats, pattern);
      if (matchedPattern) {
        patterns.push(matchedPattern);
      }
    });

    return patterns;
  }

  matchPattern(threats, pattern) {
    if (pattern.sequence) {
      return this.matchSequencePattern(threats, pattern);
    } else if (pattern.minOccurrences) {
      return this.matchFrequencyPattern(threats, pattern);
    } else if (pattern.uniqueCategories) {
      return this.matchDiversityPattern(threats, pattern);
    }
    return null;
  }

  matchSequencePattern(threats, pattern) {
    for (let i = 0; i < threats.length - 1; i++) {
      if (threats[i].category === pattern.sequence[0]) {
        const nextThreats = threats.slice(i + 1);
        const matchingFollow = nextThreats.find(
          threat =>
            pattern.sequence[1].includes(threat.category) &&
            new Date(threat.timestamp) - new Date(threats[i].timestamp) <=
              pattern.timeWindow,
        );

        if (matchingFollow) {
          return {
            name: pattern.name,
            threats: [threats[i], matchingFollow],
            timestamp: threats[i].timestamp,
            confidence: 'HIGH',
          };
        }
      }
    }
    return null;
  }

  matchFrequencyPattern(threats, pattern) {
    const categoryThreats = threats.filter(
      t => t.category === pattern.category,
    );
    const windows = this.findTimeWindows(categoryThreats, pattern.timeWindow);

    const matchedWindow = windows.find(
      window => window.threats.length >= pattern.minOccurrences,
    );
    if (matchedWindow) {
      return {
        name: pattern.name,
        threats: matchedWindow.threats,
        timestamp: matchedWindow.threats[0].timestamp,
        confidence: 'HIGH',
      };
    }
    return null;
  }

  matchDiversityPattern(threats, pattern) {
    const windows = this.findTimeWindows(threats, pattern.timeWindow);

    const matchedWindow = windows.find(window => {
      const uniqueCategories = new Set(window.threats.map(t => t.category));
      return uniqueCategories.size >= pattern.uniqueCategories;
    });

    if (matchedWindow) {
      return {
        name: pattern.name,
        threats: matchedWindow.threats,
        timestamp: matchedWindow.threats[0].timestamp,
        confidence: 'MEDIUM',
      };
    }
    return null;
  }

  findTimeWindows(threats, windowSize) {
    const windows = [];
    for (let i = 0; i < threats.length; i++) {
      const windowThreats = [threats[i]];
      const windowStart = new Date(threats[i].timestamp);

      for (let j = i + 1; j < threats.length; j++) {
        const timeDiff = new Date(threats[j].timestamp) - windowStart;
        if (timeDiff <= windowSize) {
          windowThreats.push(threats[j]);
        } else {
          break;
        }
      }

      if (windowThreats.length > 1) {
        windows.push({ threats: windowThreats });
      }
    }
    return windows;
  }

  getThreatLevelWeight(level) {
    const weights = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      INFO: 0,
    };
    return weights[level] || 0;
  }

  generateCorrelationSummary(correlatedEvents, patterns) {
    return {
      totalCorrelatedGroups: correlatedEvents.length,
      totalPatterns: patterns.length,
      criticalCorrelations: correlatedEvents.filter(
        group => group.riskLevel === 'CRITICAL',
      ).length,
      patternTypes: patterns.map(p => p.name),
      mostCommonCorrelationType:
        this.getMostCommonCorrelationType(correlatedEvents),
    };
  }

  getMostCommonCorrelationType(correlatedEvents) {
    const typeCounts = {};
    correlatedEvents.forEach(group => {
      group.correlationType.forEach(type => {
        typeCounts[type] = (typeCounts[type] || 0) + 1;
      });
    });

    return (
      Object.entries(typeCounts)
        .sort(([, a], [, b]) => b - a)
        .map(([type]) => type)[0] || 'none'
    );
  }
}
