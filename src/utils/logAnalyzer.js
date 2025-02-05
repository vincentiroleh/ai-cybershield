import { SUSPICIOUS_PATTERNS } from './patterns.js';
import BehaviorAnalyzer from './behaviorAnalyzer.js';
import ThreatScoring from './threatScoring.js';
import CorrelationEngine from './correlationEngine.js';
import MLPreprocessor from './mlPreprocessor.js';

const behaviorAnalyzer = new BehaviorAnalyzer();
const threatScoring = new ThreatScoring();
const correlationEngine = new CorrelationEngine();
const mlPreprocessor = new MLPreprocessor();

const analyzeContext = (line, previousLines = [], nextLines = []) => {
  const context = {
    timeWindow: 5 * 60 * 1000, // 5 minutes
    occurrences: 0,
    relatedEvents: [],
  };

  // Simple context analysis for now
  [...previousLines, ...nextLines].forEach(contextLine => {
    if (contextLine.includes(line.substring(0, 20))) {
      // Basic similarity check
      context.occurrences++;
      context.relatedEvents.push(contextLine);
    }
  });

  return context;
};

const extractIP = logLine => {
  // Basic IP extraction - you might want to improve this based on your log format
  const ipMatch = logLine.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  return ipMatch ? ipMatch[0] : null;
};

const extractAction = (logLine, category) => {
  // Convert log line and category into an action type
  if (logLine.includes('failed login')) return 'failed_login';
  if (logLine.includes('successful login')) return 'success_login';
  if (category === 'RECONNAISSANCE') return 'port_scan';
  // Add more action types as needed
  return 'unknown';
};

export const analyzeLogs = logData => {
  if (typeof logData !== 'string') {
    throw new Error('Log data must be a string');
  }

  const threats = [];
  const lines = logData.split('\n');

  lines.forEach((line, index) => {
    const previousLines = lines.slice(Math.max(0, index - 5), index);
    const nextLines = lines.slice(index + 1, index + 6);
    const ip = extractIP(line);

    SUSPICIOUS_PATTERNS.forEach(pattern => {
      if (pattern.pattern.test(line)) {
        const action = extractAction(line, pattern.category);
        if (ip) {
          behaviorAnalyzer.trackActivity(ip, action, new Date().toISOString());
        }

        const context = analyzeContext(line, previousLines, nextLines);
        const behaviorAnalysis = ip
          ? behaviorAnalyzer.analyzePattern(ip)
          : null;

        // Calculate threat score
        const threatScore = threatScoring.calculateThreatScore(
          {
            severity: pattern.severity,
            category: pattern.category,
            timestamp: new Date().toISOString(),
          },
          context,
          behaviorAnalysis,
        );

        // Get recommended actions
        const recommendedActions = threatScoring.getRecommendedActions(
          threatScore,
          pattern.category,
        );

        const threat = {
          message: line.trim(),
          severity: pattern.severity,
          category: pattern.category,
          timestamp: new Date().toISOString(),
          lineNumber: index + 1,
          context: context,
          sourceIP: ip,
          behaviorAnalysis,
          threatScore,
          threatLevel: threatScoring.getThreatLevel(threatScore),
          recommendedActions,
        };
        threats.push(threat);
      }
    });
  });

  // After collecting all threats, perform correlation analysis
  const correlationResults = correlationEngine.correlateThreats(threats);

  // Prepare features for ML
  const mlFeatures = mlPreprocessor.prepareForML(threats);

  return {
    threats: threats.length
      ? threats
      : [{ message: 'No threats detected.', severity: 'INFO' }],
    correlations: correlationResults,
    mlFeatures,
    summary: {
      totalThreats: threats.length,
      highSeverity: threats.filter(t => t.severity === 'HIGH').length,
      criticalThreats: threats.filter(t => t.threatLevel === 'CRITICAL').length,
      averageThreatScore: threats.length
        ? Math.round(
          threats.reduce((acc, t) => acc + t.threatScore, 0) / threats.length,
        )
        : 0,
      categories: [...new Set(threats.map(t => t.category))],
      suspiciousIPs: Array.from(behaviorAnalyzer.activityLog.keys()).filter(
        ip => behaviorAnalyzer.analyzePattern(ip).riskScore > 70,
      ),
      correlationSummary: correlationResults.summary,
      mlMetadata: mlFeatures.metadata,
    },
  };
};
