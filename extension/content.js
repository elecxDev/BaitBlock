

let baitPanel = null;
let scanCache = new Map();
let userProfileManager = null;
let threatAdapter = null;

// Initialize user profile system
async function initializeUserProfile() {
  if (typeof UserProfileManager !== 'undefined') {
    userProfileManager = new UserProfileManager();
    threatAdapter = new ThreatLandscapeAdapter();
    await userProfileManager.loadProfile();
    
    // Check if user needs setup
    const stored = await chrome.storage.local.get(['setupComplete']);
    if (!stored.setupComplete && !userProfileManager.profile.setupComplete) {
      // Show setup notification after a delay
      setTimeout(() => {
        showSetupPrompt();
      }, 3000);
    }
  }
}

function showSetupPrompt() {
  const setupPrompt = document.createElement('div');
  setupPrompt.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #1a1a1a;
    border: 1px solid #333;
    color: #e5e5e5;
    padding: 16px 20px;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    z-index: 10001;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    max-width: 300px;
    cursor: pointer;
    transition: transform 0.2s ease;
  `;
  
  setupPrompt.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <img src="${chrome.runtime.getURL('icon.png')}" style="width: 24px; height: 24px;" alt="BaitBlock">
      <div>
        <div style="font-weight: 600; margin-bottom: 4px;">BaitBlock Setup</div>
        <div style="opacity: 0.9; font-size: 13px;">Personalize your phishing protection</div>
      </div>
      <div style="margin-left: auto; font-size: 20px; opacity: 0.7;">→</div>
    </div>
  `;
  
  setupPrompt.addEventListener('mouseenter', () => {
    setupPrompt.style.transform = 'translateY(-2px)';
  });
  
  setupPrompt.addEventListener('mouseleave', () => {
    setupPrompt.style.transform = 'translateY(0)';
  });
  
  setupPrompt.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'OPEN_SETUP' });
    setupPrompt.remove();
  });
  
  document.body.appendChild(setupPrompt);
  
  // Auto-hide after 10 seconds
  setTimeout(() => {
    if (setupPrompt.parentNode) {
      setupPrompt.remove();
    }
  }, 10000);
}

function extractEmailContent() {
  const isGmail = window.location.hostname.includes('mail.google.com');
  const isOutlook = window.location.hostname.includes('outlook');
  
  if (isGmail) {
    return extractGmailContent();
  } else if (isOutlook) {
    return extractOutlookContent();
  }
  return null;
}

function extractGmailContent() {
  const emailBody = document.querySelector('[data-message-id] .ii.gt') || 
                   document.querySelector('.ii.gt') ||
                   document.querySelector('[role="listitem"] .ii.gt');
  
  if (!emailBody) return null;
  
  const messageId = emailBody.closest('[data-message-id]')?.getAttribute('data-message-id');
  const fromElement = document.querySelector('[email]');
  const subjectElement = document.querySelector('h2[data-thread-perm-id]');
  
  return {
    html: emailBody.innerHTML,
    text: emailBody.innerText,
    messageId,
    headers: {
      from: fromElement?.getAttribute('email') || '',
      subject: subjectElement?.innerText || ''
    }
  };
}

function extractOutlookContent() {
  const emailBody = document.querySelector('[role="main"] .rps_1f31') ||
                   document.querySelector('.rps_1f31') ||
                   document.querySelector('[data-testid="message-body"]');
  
  if (!emailBody) return null;
  
  const fromElement = document.querySelector('[data-testid="message-from"]');
  const subjectElement = document.querySelector('[data-testid="message-subject"]');
  
  return {
    html: emailBody.innerHTML,
    text: emailBody.innerText,
    messageId: window.location.hash,
    headers: {
      from: fromElement?.innerText || '',
      subject: subjectElement?.innerText || ''
    }
  };
}

function extractUrls(text) {
  const linkRegex = /https?:\/\/[^\s<>"]+/gi;
  const matches = text.match(linkRegex) || [];
  return matches.map(url => String(url).replace(/[.,;!?]+$/, ''));
}

function extractLinks(html, text) {
  const allUrls = new Set();
  
  // Extract from text
  const textLinks = extractUrls(text);
  textLinks.forEach(url => allUrls.add(url));
  
  // Extract from HTML href attributes
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(html)) !== null) {
    allUrls.add(match[1]);
  }
  
  return Array.from(allUrls).map(url => ({ url, suspicious: isSuspiciousUrl(url) }));
}

function isSuspiciousUrl(url) {
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.xyz'];
  const typosquatPatterns = {
    'google': ['goog1e', 'g00gle', 'googIe'],
    'microsoft': ['microsft', 'microsooft', 'micr0soft'],
    'amazon': ['amaz0n', 'amazom', 'arnazon']
  };
  
  try {
    const domain = new URL(url).hostname.toLowerCase();
    
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) return true;
    
    for (const [brand, variants] of Object.entries(typosquatPatterns)) {
      if (variants.some(variant => domain.includes(variant))) return true;
    }
    
    return false;
  } catch {
    return true;
  }
}

async function scanText(text, emailData = null) {
  console.log('🔍 BaitBlock: Starting scan for:', text);
  
  const cacheKey = emailData?.messageId || text.substring(0, 100);
  if (scanCache.has(cacheKey)) {
    console.log('📋 BaitBlock: Using cached result');
    return scanCache.get(cacheKey);
  }
  
  try {
    const result = await chrome.runtime.sendMessage({
      type: "ANALYZE_TEXT",
      text: emailData ? emailData.text : text,
      sender: emailData ? emailData.headers.from : null,
      userContext: userProfileManager ? userProfileManager.getOrganizationContext() : null
    });
    
    // Check if result exists and has expected structure
    if (!result) {
      throw new Error("No response from background script");
    }
    
    if (result.error) {
      throw new Error(result.error);
    }
    
    // Apply personalized scoring if profile is available and result has details
    if (userProfileManager && result.details) {
      const baseScore = result.details.score || 0;
      const personalizedScore = userProfileManager.getPersonalizedThreatMultiplier(baseScore);
      
      // Apply department-specific adjustments
      if (threatAdapter) {
        const deptMultiplier = threatAdapter.getDepartmentThreatMultiplier(
          userProfileManager.profile.department,
          result.details.reasons || []
        );
        result.details.personalizedScore = personalizedScore * deptMultiplier;
        result.details.adaptiveFactors = {
          userSensitivity: userProfileManager.profile.sensitivityLevel,
          departmentMultiplier: deptMultiplier,
          riskLevel: userProfileManager.profile.riskLevel
        };
      } else {
        result.details.personalizedScore = personalizedScore;
      }
      
      // Update the main result based on personalized scoring
      const personalizedConfidence = Math.min(1.0, result.details.personalizedScore / 100);
      result.data = [
        result.data[0],
        personalizedConfidence
      ];
    }
    
    scanCache.set(cacheKey, result);
    
    if (scanCache.size > 50) {
      const firstKey = scanCache.keys().next().value;
      scanCache.delete(firstKey);
    }
    
    return result;
  } catch (err) {
    console.error('❌ BaitBlock: Error:', err);
    return { error: err.message || "Network error" };
  }
}

function createResultPanel(data, links = []) {
  console.log('🎨 BaitBlock: Creating panel with data:', data);
  removePanel();
  
  baitPanel = document.createElement('div');
  baitPanel.id = 'baitblock-panel';
  
  const linkIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/></svg>`;
  const warningIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M13,13H11V7H13M13,17H11V15H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/></svg>`;
  const checkIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M11,16.5L18,9.5L16.59,8.09L11,13.67L7.41,10.09L6,11.5L11,16.5Z"/></svg>`;
  
  const linksHtml = links.length > 0 ? `
    <div class="phish-links">
      <div class="phish-links-header">${linkIcon} Links Found:</div>
      ${links.map(link => `
        <div class="phish-link ${link.suspicious ? 'suspicious' : 'safe'}">
          ${link.suspicious ? warningIcon : checkIcon} <a href="${link.url}" target="_blank">${link.url}</a>
        </div>
      `).join('')}
    </div>
  ` : '';
  
  if (data.loading) {
    const closeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z"/></svg>`;
    
    baitPanel.innerHTML = `
      <div class="phish-header">
        <span class="header-title"><img src="${chrome.runtime.getURL('icon.png')}" width="20" height="20" style="vertical-align: middle; margin-right: 8px;"> BaitBlock</span>
        <button class="phish-close">${closeIcon}</button>
      </div>
      <div class="phish-content">
        <div class="phish-loading">
          <div class="loading-spinner"></div>
          <div class="loading-text">Analyzing content...</div>
        </div>
      </div>
    `;
  } else if (data.error) {
    const closeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z"/></svg>`;
    const errorIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M11,15H13V17H11V15M11,7H13V13H11V7M12,2C6.47,2 2,6.5 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20Z"/></svg>`;
    
    baitPanel.innerHTML = `
      <div class="phish-header">
        <span class="header-title"><img src="${chrome.runtime.getURL('icon.png')}" width="20" height="20" style="vertical-align: middle; margin-right: 8px;"> BaitBlock</span>
        <button class="phish-close">${closeIcon}</button>
      </div>
      <div class="phish-content">
        <div class="phish-error">${errorIcon} ${data.error}</div>
      </div>
    `;
  } else {
    // Parse Gradio response
    const gradioData = data.data || data;
    const label = Array.isArray(gradioData) ? gradioData[0] : (gradioData.label || 'unknown');
    const confidence = Array.isArray(gradioData) && gradioData[1] ? gradioData[1] : (gradioData.confidence || 0);
    const details = data.details || {};
    
    const isPhishing = label.toLowerCase().includes('phish');
    const riskLevel = isPhishing ? 'high' : 'low';
    const score = Math.round(confidence * 100);
    
    // Get personalized alert configuration
    const alertConfig = userProfileManager ? 
      userProfileManager.getAlertConfiguration() : 
      { showDetailedReasons: true, educationalTips: true };
    
    // Format reasons
    const reasons = details.reasons || [];
    const adaptiveFactors = details.adaptiveFactors || {};
    
    // Add personalized insights
    const personalizedInsights = [];
    if (userProfileManager) {
      const profile = userProfileManager.profile;
      if (profile.riskLevel === 'high' && isPhishing) {
        personalizedInsights.push(`⚠️ High-priority alert for ${profile.department} role`);
      }
      if (adaptiveFactors.departmentMultiplier > 1.2) {
        personalizedInsights.push(`🎯 Department-specific threat detected`);
      }
      if (profile.learningData.confirmedThreats > 5) {
        personalizedInsights.push(`🧠 Adapted based on your feedback history`);
      }
    }
    
    const allReasons = [...personalizedInsights, ...reasons];
    
    const reasonsHtml = allReasons.length > 0 ? `
      <div class="phish-reasons-list">
        ${allReasons.map((reason, index) => {
          const isPersonalized = index < personalizedInsights.length;
          return `<div class="reason-item ${isPersonalized ? 'personalized' : ''}">${reason}</div>`;
        }).join('')}
      </div>
    ` : '';
    
    // Feedback section - always show for any result
    const feedbackHtml = `
      <div class="feedback-section">
        <div class="feedback-header">Is this assessment correct?</div>
        <div class="feedback-buttons">
          <button class="feedback-btn correct" data-feedback="correct">✓ Yes, correct</button>
          <button class="feedback-btn incorrect" data-feedback="incorrect">✗ No, incorrect</button>
        </div>
      </div>
    `;
    
    // Educational tip based on threat type
    const educationalTip = alertConfig.educationalTips && isPhishing ? getEducationalTip(reasons) : '';
    
    const closeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z"/></svg>`;
    const warningIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M13,13H11V7H13M13,17H11V15H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/></svg>`;
    const checkIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M11,16.5L18,9.5L16.59,8.09L11,13.67L7.41,10.09L6,11.5L11,16.5Z"/></svg>`;
    
    baitPanel.innerHTML = `
      <div class="phish-header">
        <span class="header-title"><img src="${chrome.runtime.getURL('icon.png')}" width="20" height="20" style="vertical-align: middle; margin-right: 8px;"> BaitBlock</span>
        <button class="phish-close">${closeIcon}</button>
      </div>
      <div class="phish-content">
        <div class="phish-score ${riskLevel}">
          <div class="score-bar">
            <div class="score-fill" style="width: ${score}%; background: ${isPhishing ? '#e74c3c' : '#27ae60'}"></div>
          </div>
          <div class="score-text">${label} (${score}% confidence)</div>
          ${userProfileManager ? `<div class="personalized-note">Personalized for ${userProfileManager.profile.riskLevel} risk ${userProfileManager.profile.department} role</div>` : ''}
        </div>
        <div class="phish-reasons">
          <div class="reasons-header">
            ${isPhishing ? `${warningIcon} Insights:` : `${checkIcon} Content appears safe`}
          </div>
          ${reasonsHtml}
        </div>
        ${educationalTip}
        ${feedbackHtml}
        ${linksHtml}
      </div>
    `;
  }
  
  document.body.appendChild(baitPanel);
  
  baitPanel.querySelector('.phish-close').onclick = removePanel;
  
  // Handle feedback buttons
  const feedbackButtons = baitPanel.querySelectorAll('.feedback-btn');
  console.log('🎯 Found feedback buttons:', feedbackButtons.length);
  
  feedbackButtons.forEach((btn, index) => {
    console.log(`🎯 Setting up button ${index}:`, btn);
    btn.addEventListener('click', (e) => {
      console.log('🎯 Feedback button clicked!', e.target);
      
      const feedback = e.target.dataset.feedback;
      const isCorrect = feedback === 'correct';
      
      // Immediate visual response
      e.target.style.background = '#4caf50';
      e.target.style.color = 'white';
      e.target.style.transform = 'scale(0.95)';
      e.target.innerHTML = '✓ Feedback collected!';
      
      // Disable all buttons
      feedbackButtons.forEach(b => {
        b.disabled = true;
        b.style.opacity = b === e.target ? '1' : '0.5';
      });
      
      // Show success message after a brief moment
      setTimeout(() => {
        const feedbackSection = e.target.closest('.feedback-section');
        if (feedbackSection) {
          feedbackSection.innerHTML = `
            <div style="
              background: linear-gradient(135deg, #4caf50, #45a049);
              color: white;
              padding: 12px;
              border-radius: 8px;
              text-align: center;
              font-size: 14px;
              font-weight: 500;
              animation: fadeIn 0.3s ease;
            ">
              ✓ Feedback collected! Thanks for helping improve BaitBlock
            </div>
          `;
        }
      }, 200);
      
      // Log the feedback
      console.log(`📝 User feedback collected: ${isCorrect ? 'Correct assessment' : 'Incorrect assessment'}`);
    });
  });
}

function getEducationalTip(reasons) {
  const tips = {
    'urgency': 'Tip: Legitimate organizations rarely require immediate action via email.',
    'fear': 'Tip: Scare tactics are a common phishing technique. Verify through official channels.',
    'financial': 'Tip: Never provide financial details via email. Contact your bank directly.',
    'authority': 'Tip: Always verify requests from authority figures through independent means.',
    'spelling': 'Tip: Poor spelling/grammar is often a sign of phishing attempts.',
    'generic': 'Tip: Personalized emails from legitimate sources address you by name.'
  };
  
  for (const [key, tip] of Object.entries(tips)) {
    if (reasons.some(reason => reason.toLowerCase().includes(key))) {
      return `<div class="educational-tip">💡 ${tip}</div>`;
    }
  }
  
  return '';
}

function removePanel() {
  if (baitPanel) {
    baitPanel.remove();
    baitPanel = null;
  }
}

// Auto-scan emails on Gmail/Outlook
function autoScanEmail() {
  const emailData = extractEmailContent();
  if (emailData && emailData.messageId) {
    const cacheKey = emailData.messageId;
    if (!scanCache.has(cacheKey)) {
      setTimeout(async () => {
        const links = extractLinks(emailData.html, emailData.text);
        const result = await scanText(emailData.text, emailData);
        
        // Check if result indicates phishing
        const gradioData = result.data || result;
        const label = Array.isArray(gradioData) ? gradioData[0] : (gradioData.label || '');
        const confidence = Array.isArray(gradioData) && gradioData[1] ? gradioData[1] : (gradioData.confidence || 0);
        
        if (label.toLowerCase().includes('phish') && confidence > 0.7) {
          createResultPanel(result, links);
        }
      }, 1000);
    }
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  console.log('📨 BaitBlock: Received message:', message);
  
  if (message.type === "SHOW_LOADING") {
    createResultPanel({ loading: true });
  } else if (message.type === "SHOW_RESULT") {
    const emailData = extractEmailContent();
    const links = emailData ? extractLinks(emailData.html, emailData.text) : [];
    createResultPanel(message.result, links);
  } else if (message.type === "SCAN_EMAIL") {
    const emailData = extractEmailContent();
    if (emailData) {
      createResultPanel({ loading: true });
      
      const links = extractLinks(emailData.html, emailData.text);
      const result = await scanText(emailData.text, emailData);
      
      createResultPanel(result, links);
    } else {
      createResultPanel({ error: "No email content found" });
    }
  } else if (message.type === "ANALYZE_POPUP_TEXT") {
    createResultPanel({ loading: true });
    
    const result = await scanText(message.text);
    createResultPanel(result, []);
  }
});

// Auto-scan on Gmail/Outlook
if (window.location.hostname.includes('mail.google.com') || window.location.hostname.includes('outlook')) {
  const observer = new MutationObserver(() => {
    autoScanEmail();
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Initial scan
  setTimeout(autoScanEmail, 2000);
}

// Initialize user profile system when page loads
initializeUserProfile();