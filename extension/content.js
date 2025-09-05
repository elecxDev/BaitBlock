

let baitPanel = null;
let scanCache = new Map();

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
      text: emailData ? emailData.text : text
    });
    
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
    const shieldIcon = `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10.5V11.5C15.4,11.5 16,12.4 16,13V16C16,17.4 15.4,18 14.8,18H9.2C8.6,18 8,17.4 8,16V13C8,12.4 8.6,11.5 9.2,11.5V10.5C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,10.5V11.5H13.5V10.5C13.5,8.7 12.8,8.2 12,8.2Z"/></svg>`;
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
    const shieldIcon = `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10.5V11.5C15.4,11.5 16,12.4 16,13V16C16,17.4 15.4,18 14.8,18H9.2C8.6,18 8,17.4 8,16V13C8,12.4 8.6,11.5 9.2,11.5V10.5C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,10.5V11.5H13.5V10.5C13.5,8.7 12.8,8.2 12,8.2Z"/></svg>`;
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
    
    // Format reasons
    const reasons = details.reasons || [];
    const reasonsHtml = reasons.length > 0 ? `
      <div class="phish-reasons-list">
        ${reasons.map(reason => `<div class="reason-item">${reason}</div>`).join('')}
      </div>
    ` : '';
    
    const shieldIcon = `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10.5V11.5C15.4,11.5 16,12.4 16,13V16C16,17.4 15.4,18 14.8,18H9.2C8.6,18 8,17.4 8,16V13C8,12.4 8.6,11.5 9.2,11.5V10.5C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,10.5V11.5H13.5V10.5C13.5,8.7 12.8,8.2 12,8.2Z"/></svg>`;
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
        </div>
        <div class="phish-reasons">
          <div class="reasons-header">
            ${isPhishing ? `${warningIcon} Why this looks like phishing:` : `${checkIcon} Content appears safe`}
          </div>
          ${reasonsHtml}
        </div>
        ${linksHtml}
      </div>
    `;
  }
  
  document.body.appendChild(baitPanel);
  
  baitPanel.querySelector('.phish-close').onclick = removePanel;
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