const SUSPICIOUS_PATTERNS = [
  // Authentication & Access Patterns with improved regex
  {
    pattern: /(unauthorized|invalid|failed|denied)\s*(access|login|logon|authentication)/i,
    severity: 'HIGH',
    category: 'AUTH',
    threshold: 3, // Alert after 3 occurrences in timeWindow
    timeWindow: 300000, // 5 minutes in milliseconds
  },
  {
    pattern: /invalid\s*credentials|password\s*incorrect|authentication\s*failed/i,
    severity: 'MEDIUM',
    category: 'AUTH',
    threshold: 2,
    timeWindow: 300000,
  },
  
  // Brute Force Detection
  {
    pattern: /(multiple|repeated|excessive)\s*(failed|invalid)\s*(login|attempt)/i,
    severity: 'HIGH',
    category: 'BRUTE_FORCE',
    threshold: 1, // Immediate alert
    timeWindow: 300000,
  },

  // Suspicious Account Patterns
  {
    pattern: /(unknown|invalid|non-existent)\s*(user|account)/i,
    severity: 'MEDIUM',
    category: 'SUSPICIOUS_ACCOUNT',
    threshold: 2,
    timeWindow: 300000,
  },

  // Privilege Escalation
  {
    pattern: /(privilege|permission)\s*(escalation|elevation)|sudo\s*abuse/i,
    severity: 'HIGH',
    category: 'PRIVILEGE_ESCALATION',
    threshold: 1,
    timeWindow: 300000,
  },

  // System Access Patterns
  {
    pattern: /system\s*(access|modification)|registry\s*change/i,
    severity: 'HIGH',
    category: 'SYSTEM_ACCESS',
    threshold: 1,
    timeWindow: 300000,
  },

  // Network Patterns
  {
    pattern: /(port|network)\s*scan|reconnaissance/i,
    severity: 'HIGH',
    category: 'RECONNAISSANCE',
    threshold: 1,
    timeWindow: 300000,
  },

  // Malware & Suspicious Execution
  {
    pattern: /malware|virus|trojan|suspicious\s*(execution|process|file)/i,
    severity: 'HIGH',
    category: 'MALWARE',
    threshold: 1,
    timeWindow: 300000,
  }
];


const validatePatterns = patterns => {
  return patterns.every(
    p =>
      p.pattern instanceof RegExp &&
      typeof p.severity === 'string' &&
      typeof p.category === 'string' &&
      ['HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(p.severity),
  );
};

if (!validatePatterns(SUSPICIOUS_PATTERNS)) {
  throw new Error('Invalid pattern configuration');
}

export { SUSPICIOUS_PATTERNS };