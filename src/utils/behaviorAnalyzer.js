class BehaviorAnalyzer {
  constructor() {
    this.activityLog = new Map();
    this.ipThresholds = {
      maxAttemptsPerMinute: 30,
      maxFailedLogins: 5,
      suspiciousTimeWindow: 5 * 60 * 1000, // 5 minutes in milliseconds
    };
  }

  trackActivity(ip, action, timestamp) {
    if (!this.activityLog.has(ip)) {
      this.activityLog.set(ip, []);
    }
    this.activityLog.get(ip).push({ action, timestamp });

    // Cleanup old entries (older than 1 hour)
    this.cleanup(ip);
  }

  cleanup(ip) {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const activities = this.activityLog.get(ip);
    if (activities) {
      this.activityLog.set(
        ip,
        activities.filter(
          activity => new Date(activity.timestamp).getTime() > oneHourAgo,
        ),
      );
    }
  }

  analyzePattern(ip) {
    const activities = this.activityLog.get(ip) || [];

    return {
      frequency: this.calculateFrequency(activities),
      unusualTiming: this.checkTimingPatterns(activities),
      suspiciousSequence: this.checkActionSequence(activities),
      riskScore: this.calculateRiskScore(activities),
    };
  }

  calculateFrequency(activities) {
    if (activities.length === 0) return { rate: 0, isHighFrequency: false };

    const now = Date.now();
    const recentActivities = activities.filter(
      activity => now - new Date(activity.timestamp).getTime() <= 60000, // Last minute
    );

    return {
      rate: recentActivities.length,
      isHighFrequency:
        recentActivities.length > this.ipThresholds.maxAttemptsPerMinute,
    };
  }

  checkTimingPatterns(activities) {
    if (activities.length === 0) return { suspicious: false };

    const timestamps = activities.map(a => new Date(a.timestamp).getTime());
    const intervals = [];

    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }

    // Check for suspiciously regular intervals (potential automated attacks)
    const isRegularPattern = this.checkRegularIntervals(intervals);

    // Check if activity is during unusual hours (e.g., 2 AM - 5 AM)
    const hasUnusualTiming = activities.some(activity => {
      const hour = new Date(activity.timestamp).getHours();
      return hour >= 2 && hour <= 5;
    });

    return {
      suspicious: isRegularPattern || hasUnusualTiming,
      regularPattern: isRegularPattern,
      unusualTiming: hasUnusualTiming,
    };
  }

  checkRegularIntervals(intervals) {
    if (intervals.length < 3) return false;

    // Calculate average deviation between intervals
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const deviation =
      intervals.reduce(
        (acc, interval) => acc + Math.abs(interval - avgInterval),
        0,
      ) / intervals.length;

    // If deviation is very low, it might indicate automated activity
    return deviation < 100; // 100ms threshold
  }

  checkActionSequence(activities) {
    const failedLogins = activities.filter(
      activity => activity.action === 'failed_login',
    ).length;

    const suspiciousSequences = {
      failedLogins: failedLogins >= this.ipThresholds.maxFailedLogins,
      rapidSuccession: this.checkRapidSuccession(activities),
      patternDetected: this.detectKnownPatterns(activities),
    };

    return {
      suspicious: Object.values(suspiciousSequences).some(value => value),
      details: suspiciousSequences,
    };
  }

  checkRapidSuccession(activities) {
    if (activities.length < 2) return false;

    for (let i = 1; i < activities.length; i++) {
      const timeDiff =
        new Date(activities[i].timestamp).getTime() -
        new Date(activities[i - 1]).getTime();
      if (timeDiff < 1000) {
        // Less than 1 second between actions
        return true;
      }
    }
    return false;
  }

  detectKnownPatterns(activities) {
    // Example pattern: failed login followed by successful login followed by sensitive action
    const actions = activities.map(a => a.action);
    const knownPatterns = [
      ['failed_login', 'success_login', 'access_sensitive'],
      ['port_scan', 'vulnerability_scan', 'exploit_attempt'],
    ];

    return knownPatterns.some(pattern =>
      this.containsSequence(actions, pattern),
    );
  }

  containsSequence(array, sequence) {
    return array.join(',').includes(sequence.join(','));
  }

  calculateRiskScore(activities) {
    let score = 0;
    const frequency = this.calculateFrequency(activities);
    const timing = this.checkTimingPatterns(activities);
    const sequence = this.checkActionSequence(activities);

    if (frequency.isHighFrequency) score += 30;
    if (timing.suspicious) score += 25;
    if (sequence.suspicious) score += 25;

    // Add points for total volume of activities
    score += Math.min(20, activities.length);

    return Math.min(100, score);
  }
}

export default BehaviorAnalyzer;
