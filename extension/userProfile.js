// User Profile & Adaptive Security System
class UserProfileManager {
  constructor() {
    this.defaultProfile = {
      userId: null,
      department: 'general',
      riskLevel: 'medium',
      jobRole: 'employee',
      sensitivityLevel: 0.6,
      learningData: {
        falsePositives: 0,
        confirmedThreats: 0,
        userFeedback: [],
        lastUpdated: Date.now()
      },
      preferences: {
        alertStyle: 'standard', // standard, minimal, detailed
        language: 'en',
        notificationFrequency: 'immediate'
      },
      organizationId: null
    };
    this.loadProfile();
  }

  async loadProfile() {
    const stored = await chrome.storage.local.get(['userProfile']);
    this.profile = stored.userProfile || { ...this.defaultProfile };
    this.adaptSensitivity();
  }

  async saveProfile() {
    await chrome.storage.local.set({ userProfile: this.profile });
  }

  // Adaptive sensitivity based on user role and feedback
  adaptSensitivity() {
    const { department, jobRole, learningData } = this.profile;
    
    // Base sensitivity by role
    let baseSensitivity = 0.6;
    
    // High-risk roles get higher sensitivity
    const highRiskRoles = ['ceo', 'cfo', 'finance', 'hr', 'it-admin', 'executive'];
    const mediumRiskRoles = ['manager', 'supervisor', 'accountant'];
    
    if (highRiskRoles.includes(jobRole.toLowerCase()) || 
        ['finance', 'hr', 'executive'].includes(department.toLowerCase())) {
      baseSensitivity = 0.8;
      this.profile.riskLevel = 'high';
    } else if (mediumRiskRoles.includes(jobRole.toLowerCase())) {
      baseSensitivity = 0.7;
      this.profile.riskLevel = 'medium';
    } else {
      this.profile.riskLevel = 'low';
    }

    // Adjust based on user feedback
    const { falsePositives, confirmedThreats } = learningData;
    const totalFeedback = falsePositives + confirmedThreats;
    
    if (totalFeedback > 5) {
      const accuracy = confirmedThreats / totalFeedback;
      if (accuracy < 0.7 && falsePositives > 3) {
        // User getting too many false positives, reduce sensitivity
        baseSensitivity *= 0.9;
      } else if (accuracy > 0.9) {
        // User confirms most threats, can increase sensitivity
        baseSensitivity *= 1.1;
      }
    }

    this.profile.sensitivityLevel = Math.min(1.0, Math.max(0.3, baseSensitivity));
    this.saveProfile();
  }

  // Record user feedback for adaptive learning
  async recordFeedback(threatId, isActualThreat, userAction) {
    if (isActualThreat) {
      this.profile.learningData.confirmedThreats++;
    } else {
      this.profile.learningData.falsePositives++;
    }

    this.profile.learningData.userFeedback.push({
      threatId,
      isActualThreat,
      userAction,
      timestamp: Date.now()
    });

    // Keep only last 50 feedback entries
    if (this.profile.learningData.userFeedback.length > 50) {
      this.profile.learningData.userFeedback = 
        this.profile.learningData.userFeedback.slice(-50);
    }

    this.profile.learningData.lastUpdated = Date.now();
    await this.adaptSensitivity();
  }

  // Get personalized threat score adjustment
  getPersonalizedThreatMultiplier(baseScore) {
    const { sensitivityLevel, riskLevel } = this.profile;
    
    // Apply user's learned sensitivity
    let adjustedScore = baseScore * sensitivityLevel;
    
    // Additional role-based adjustments
    if (riskLevel === 'high') {
      adjustedScore *= 1.2; // More aggressive for high-risk users
    } else if (riskLevel === 'low') {
      adjustedScore *= 0.8; // Less aggressive for low-risk users
    }

    return Math.min(100, Math.max(0, adjustedScore));
  }

  // Setup user profile (for first-time setup)
  async setupProfile(profileData) {
    this.profile = {
      ...this.defaultProfile,
      ...profileData,
      userId: profileData.email || Date.now().toString()
    };
    
    await this.saveProfile();
    this.adaptSensitivity();
  }

  // Get organization context
  getOrganizationContext() {
    return {
      orgId: this.profile.organizationId,
      department: this.profile.department,
      riskLevel: this.profile.riskLevel
    };
  }

  // Get user's preferred alert style
  getAlertConfiguration() {
    const { alertStyle, riskLevel } = this.profile;
    
    return {
      showDetailedReasons: alertStyle === 'detailed' || riskLevel === 'high',
      alertPersistence: riskLevel === 'high' ? 'sticky' : 'auto-dismiss',
      warningLevel: riskLevel === 'high' ? 'aggressive' : 'standard',
      educationalTips: alertStyle !== 'minimal'
    };
  }
}

// Department-specific threat patterns
const DEPARTMENT_THREAT_PATTERNS = {
  finance: {
    keywordWeights: {
      'invoice': 1.3,
      'payment': 1.4,
      'wire transfer': 1.5,
      'account details': 1.4,
      'urgent payment': 1.6
    },
    suspiciousSenders: ['accounting@', 'finance@', 'billing@']
  },
  hr: {
    keywordWeights: {
      'resume': 1.2,
      'employee': 1.3,
      'payroll': 1.5,
      'benefits': 1.2,
      'performance review': 1.3
    },
    suspiciousSenders: ['hr@', 'recruiting@', 'careers@']
  },
  it: {
    keywordWeights: {
      'system maintenance': 1.4,
      'password reset': 1.5,
      'security update': 1.3,
      'server': 1.2,
      'access required': 1.4
    },
    suspiciousSenders: ['admin@', 'support@', 'noreply@']
  },
  executive: {
    keywordWeights: {
      'confidential': 1.4,
      'board meeting': 1.3,
      'strategic': 1.2,
      'acquisition': 1.5,
      'legal matter': 1.4
    },
    suspiciousSenders: ['ceo@', 'board@', 'legal@']
  }
};

// Real-time adaptation based on current threat landscape
class ThreatLandscapeAdapter {
  constructor() {
    this.currentThreats = new Map();
    this.organizationThreats = new Map();
  }

  // Update global threat intelligence
  updateThreatLandscape(threats) {
    threats.forEach(threat => {
      this.currentThreats.set(threat.signature, {
        ...threat,
        lastSeen: Date.now(),
        confidence: threat.confidence,
        affected_departments: threat.departments || []
      });
    });
  }

  // Get department-specific threat adjustment
  getDepartmentThreatMultiplier(department, threatPatterns) {
    const deptPatterns = DEPARTMENT_THREAT_PATTERNS[department.toLowerCase()];
    if (!deptPatterns) return 1.0;

    let multiplier = 1.0;
    
    // Check for department-specific keywords
    Object.entries(deptPatterns.keywordWeights).forEach(([keyword, weight]) => {
      if (threatPatterns.some(pattern => 
          pattern.toLowerCase().includes(keyword.toLowerCase()))) {
        multiplier *= weight;
      }
    });

    return Math.min(2.0, multiplier);
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserProfileManager, ThreatLandscapeAdapter, DEPARTMENT_THREAT_PATTERNS };
}