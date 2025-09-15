// Collaborative Threat Intelligence System
class ThreatIntelligenceHub {
  constructor() {
    this.orgThreats = new Map();
    this.globalThreats = new Map();
    this.lastSync = 0;
    this.syncInterval = 5 * 60 * 1000; // 5 minutes
  }

  // Generate threat signature for sharing
  generateThreatSignature(emailData, analysisResult) {
    const { text, headers } = emailData;
    
    // Create a unique but privacy-preserving signature
    const keyFeatures = {
      subjectHash: this.hashString(headers.subject || ''),
      senderDomain: this.extractDomain(headers.from || ''),
      contentFingerprint: this.extractContentFingerprint(text),
      threatType: this.classifyThreatType(analysisResult.reasons || []),
      confidence: analysisResult.score || 0
    };
    
    return {
      id: this.hashString(JSON.stringify(keyFeatures)),
      signature: keyFeatures,
      timestamp: Date.now(),
      reportedBy: 'anonymous' // Privacy-preserving
    };
  }

  // Share threat with organization
  async shareThreatIntelligence(threatSignature, organizationId) {
    if (!organizationId) return;

    try {
      // In a real implementation, this would sync with a backend
      const orgThreats = await chrome.storage.local.get([`org_threats_${organizationId}`]);
      const currentThreats = orgThreats[`org_threats_${organizationId}`] || [];
      
      // Add new threat if not already reported
      if (!currentThreats.find(t => t.id === threatSignature.id)) {
        currentThreats.push(threatSignature);
        
        // Keep only last 100 threats
        if (currentThreats.length > 100) {
          currentThreats.splice(0, currentThreats.length - 100);
        }
        
        await chrome.storage.local.set({
          [`org_threats_${organizationId}`]: currentThreats
        });
        
        // Broadcast to other users in organization (simulated)
        this.broadcastThreatAlert(threatSignature, organizationId);
      }
    } catch (error) {
      console.error('Failed to share threat intelligence:', error);
    }
  }

  // Check if email matches known organizational threats
  async checkOrganizationalThreats(emailData, organizationId) {
    if (!organizationId) return null;

    try {
      const orgThreats = await chrome.storage.local.get([`org_threats_${organizationId}`]);
      const threats = orgThreats[`org_threats_${organizationId}`] || [];
      
      const emailSignature = this.generateThreatSignature(emailData, { reasons: [], score: 0 });
      
      // Check for matches
      const matchingThreat = threats.find(threat => {
        return this.compareSignatures(threat.signature, emailSignature.signature);
      });
      
      if (matchingThreat) {
        return {
          isKnownThreat: true,
          confidence: 0.95,
          lastSeen: matchingThreat.timestamp,
          threatType: matchingThreat.signature.threatType,
          message: 'This threat was recently reported by a colleague in your organization'
        };
      }
      
      return null;
    } catch (error) {
      console.error('Failed to check organizational threats:', error);
      return null;
    }
  }

  // Broadcast threat alert to organization
  broadcastThreatAlert(threatSignature, organizationId) {
    // In real implementation, would use WebSockets or server-sent events
    console.log(`🚨 Broadcasting threat alert to org ${organizationId}:`, threatSignature);
    
    // Simulate real-time notification
    chrome.storage.local.set({
      [`latest_threat_${organizationId}`]: {
        ...threatSignature,
        broadcastTime: Date.now()
      }
    });
  }

  // Extract domain from email address
  extractDomain(email) {
    const match = email.match(/@([^>]+)/);
    return match ? match[1].toLowerCase() : '';
  }

  // Create content fingerprint for similarity matching
  extractContentFingerprint(text) {
    const cleanText = text.toLowerCase()
      .replace(/[^a-z\s]/g, '')
      .split(/\s+/)
      .filter(word => word.length > 3)
      .slice(0, 20) // First 20 meaningful words
      .join(' ');
    
    return this.hashString(cleanText);
  }

  // Classify threat type from analysis reasons
  classifyThreatType(reasons) {
    const types = {
      'financial': ['financial', 'money', 'payment', 'invoice', 'bank'],
      'credential': ['password', 'login', 'verify', 'account', 'security'],
      'executive': ['ceo', 'urgent', 'confidential', 'board'],
      'technical': ['it', 'system', 'update', 'maintenance', 'server']
    };
    
    const reasonText = reasons.join(' ').toLowerCase();
    
    for (const [type, keywords] of Object.entries(types)) {
      if (keywords.some(keyword => reasonText.includes(keyword))) {
        return type;
      }
    }
    
    return 'general';
  }

  // Compare threat signatures for similarity
  compareSignatures(sig1, sig2) {
    // Check domain match
    if (sig1.senderDomain && sig2.senderDomain && 
        sig1.senderDomain === sig2.senderDomain) {
      return true;
    }
    
    // Check content similarity
    if (sig1.contentFingerprint === sig2.contentFingerprint) {
      return true;
    }
    
    // Check subject similarity
    if (sig1.subjectHash === sig2.subjectHash) {
      return true;
    }
    
    return false;
  }

  // Simple hash function for privacy
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
  }

  // Get organization threat statistics
  async getOrganizationStats(organizationId) {
    if (!organizationId) return null;

    try {
      const orgThreats = await chrome.storage.local.get([`org_threats_${organizationId}`]);
      const threats = orgThreats[`org_threats_${organizationId}`] || [];
      
      const now = Date.now();
      const last24h = threats.filter(t => now - t.timestamp < 24 * 60 * 60 * 1000);
      const last7d = threats.filter(t => now - t.timestamp < 7 * 24 * 60 * 60 * 1000);
      
      const threatTypes = {};
      threats.forEach(threat => {
        const type = threat.signature.threatType;
        threatTypes[type] = (threatTypes[type] || 0) + 1;
      });
      
      return {
        totalThreats: threats.length,
        threatsLast24h: last24h.length,
        threatsLast7d: last7d.length,
        threatTypes,
        mostCommonType: Object.keys(threatTypes).reduce((a, b) => 
          threatTypes[a] > threatTypes[b] ? a : b, 'none')
      };
    } catch (error) {
      console.error('Failed to get organization stats:', error);
      return null;
    }
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ThreatIntelligenceHub };
}