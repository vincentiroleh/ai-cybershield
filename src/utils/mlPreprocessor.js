class MLPreprocessor {
  constructor() {
    this.featureConfig = {
      timeFeatures: true,
      ipFeatures: true,
      textFeatures: true,
      behaviorFeatures: true,
      contextFeatures: true,
    };

    this.categoryEncoding = {
      AUTH: 1,
      INJECTION: 2,
      XSS: 3,
      RECONNAISSANCE: 4,
      MALWARE: 5,
      FILE_SYSTEM: 6,
      NETWORK: 7,
      DATABASE: 8,
    };

    this.severityEncoding = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      INFO: 0,
    };
  }

  prepareForML(threats) {
    if (!Array.isArray(threats)) {
      throw new Error('Input must be an array of threats');
    }

    const features = threats.map(threat => ({
      ...this.extractTimeFeatures(threat),
      ...this.extractIPFeatures(threat),
      ...this.extractTextFeatures(threat),
      ...this.extractBehaviorFeatures(threat),
      ...this.extractContextFeatures(threat),
      ...this.extractBasicFeatures(threat),
    }));

    return {
      features,
      metadata: this.generateMetadata(features),
    };
  }

  extractTimeFeatures(threat) {
    if (!this.featureConfig.timeFeatures) return {};

    const timestamp = new Date(threat.timestamp);
    return {
      hour: timestamp.getHours(),
      minute: timestamp.getMinutes(),
      dayOfWeek: timestamp.getDay(),
      isWeekend: [0, 6].includes(timestamp.getDay()) ? 1 : 0,
      isBusinessHours:
        timestamp.getHours() >= 9 && timestamp.getHours() <= 17 ? 1 : 0,
      isNightTime:
        timestamp.getHours() >= 22 || timestamp.getHours() <= 5 ? 1 : 0,
    };
  }

  extractIPFeatures(threat) {
    if (!this.featureConfig.ipFeatures || !threat.sourceIP) return {};

    const ipParts = threat.sourceIP.split('.');
    return {
      ipFirstOctet: parseInt(ipParts[0]) || 0,
      ipSecondOctet: parseInt(ipParts[1]) || 0,
      isPrivateIP: this.isPrivateIP(threat.sourceIP) ? 1 : 0,
      hasSourceIP: threat.sourceIP ? 1 : 0,
    };
  }

  extractTextFeatures(threat) {
    if (!this.featureConfig.textFeatures) return {};

    const message = threat.message.toLowerCase();
    return {
      messageLength: threat.message.length,
      containsError: /error|fail|invalid/i.test(message) ? 1 : 0,
      containsAdmin: /admin|root|supervisor/i.test(message) ? 1 : 0,
      containsSQLKeywords: /select|insert|update|delete|union|drop/i.test(
        message,
      )
        ? 1
        : 0,
      containsScriptTags: /<script|javascript:/i.test(message) ? 1 : 0,
    };
  }

  extractBehaviorFeatures(threat) {
    if (!this.featureConfig.behaviorFeatures || !threat.behaviorAnalysis)
      return {};

    const behavior = threat.behaviorAnalysis;
    return {
      frequencyRate: behavior.frequency?.rate || 0,
      isHighFrequency: behavior.frequency?.isHighFrequency ? 1 : 0,
      hasSuspiciousTiming: behavior.unusualTiming?.suspicious ? 1 : 0,
      hasRegularPattern: behavior.unusualTiming?.regularPattern ? 1 : 0,
      hasSuspiciousSequence: behavior.suspiciousSequence?.suspicious ? 1 : 0,
      behaviorRiskScore: behavior.riskScore || 0,
    };
  }

  extractContextFeatures(threat) {
    if (!this.featureConfig.contextFeatures || !threat.context) return {};

    return {
      contextOccurrences: threat.context.occurrences || 0,
      hasRelatedEvents: threat.context.relatedEvents?.length > 0 ? 1 : 0,
      relatedEventsCount: threat.context.relatedEvents?.length || 0,
    };
  }

  extractBasicFeatures(threat) {
    return {
      categoryEncoded: this.categoryEncoding[threat.category] || 0,
      severityEncoded: this.severityEncoding[threat.severity] || 0,
      threatScore: threat.threatScore || 0,
    };
  }

  isPrivateIP(ip) {
    if (!ip) return false;
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    );
  }

  generateMetadata(features) {
    if (features.length === 0) return {};

    const numericColumns = [];
    const categoricalColumns = [];
    const binaryColumns = [];

    // Analyze first feature object to determine column types
    const sampleFeature = features[0];
    Object.entries(sampleFeature).forEach(([key, value]) => {
      if (typeof value === 'number') {
        if (value === 0 || value === 1) {
          binaryColumns.push(key);
        } else {
          numericColumns.push(key);
        }
      } else {
        categoricalColumns.push(key);
      }
    });

    // Calculate basic statistics for numeric columns
    const statistics = {};
    numericColumns.forEach(column => {
      const values = features.map(f => f[column]);
      statistics[column] = {
        min: Math.min(...values),
        max: Math.max(...values),
        mean: values.reduce((a, b) => a + b, 0) / values.length,
        std: this.calculateStd(values),
      };
    });

    return {
      totalFeatures: features.length,
      numericColumns,
      categoricalColumns,
      binaryColumns,
      statistics,
      categoryMapping: this.categoryEncoding,
      severityMapping: this.severityEncoding,
    };
  }

  calculateStd(values) {
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squareDiffs = values.map(value => Math.pow(value - mean, 2));
    const avgSquareDiff =
      squareDiffs.reduce((a, b) => a + b, 0) / squareDiffs.length;
    return Math.sqrt(avgSquareDiff);
  }

  // Utility method to normalize features for ML
  normalizeFeatures(features) {
    const normalized = [...features];
    const metadata = this.generateMetadata(features);

    metadata.numericColumns.forEach(column => {
      const stats = metadata.statistics[column];
      normalized.forEach(feature => {
        feature[column] =
          (feature[column] - stats.min) / (stats.max - stats.min);
      });
    });

    return normalized;
  }
}

export default MLPreprocessor;
