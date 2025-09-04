

let phishPanel = null;
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
  const links = [];
  const hrefRegex = /href=["']([^"']+)["']/gi;
  
  // Extract from text
  const textLinks = extractUrls(text);
  textLinks.forEach(url => links.push({ url, source: 'text' }));
  
  // Extract from HTML href attributes
  let match;
  while ((match = hrefRegex.exec(html)) !== null) {
    links.push({ url: match[1], source: 'html' });
  }
  
  return [...new Set(links.map(l => l.url))].map(url => ({ url, suspicious: isSuspiciousUrl(url) }));
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
  console.log('🔍 PhishGuard: Starting scan for:', text);
  
  const cacheKey = emailData?.messageId || text.substring(0, 100);
  if (scanCache.has(cacheKey)) {
    console.log('📋 PhishGuard: Using cached result');
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
    console.error('❌ PhishGuard: Error:', err);
    return { error: err.message || "Network error" };
  }
}

function createResultPanel(data, links = []) {
  console.log('🎨 PhishGuard: Creating panel with data:', data);
  removePanel();
  
  phishPanel = document.createElement('div');
  phishPanel.id = 'phishguard-panel';
  
  const linksHtml = links.length > 0 ? `
    <div class="phish-links">
      <div class="phish-links-header">🔗 Links Found:</div>
      ${links.map(link => `
        <div class="phish-link ${link.suspicious ? 'suspicious' : 'safe'}">
          ${link.suspicious ? '⚠️' : '✅'} <a href="${link.url}" target="_blank">${link.url}</a>
        </div>
      `).join('')}
    </div>
  ` : '';
  
  if (data.loading) {
    phishPanel.innerHTML = `
      <div class="phish-header">
        <span>🛡️ PhishGuard</span>
        <button class="phish-close">×</button>
      </div>
      <div class="phish-content">
        <div class="phish-loading">🔍 Analyzing...</div>
      </div>
    `;
  } else if (data.error) {
    phishPanel.innerHTML = `
      <div class="phish-header">
        <span>🛡️ PhishGuard</span>
        <button class="phish-close">×</button>
      </div>
      <div class="phish-content">
        <div class="phish-error">❌ ${data.error}</div>
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
        ${reasons.map(reason => `<div class="reason-item">• ${reason}</div>`).join('')}
      </div>
    ` : '';
    
    phishPanel.innerHTML = `
      <div class="phish-header">
        <span>🛡️ PhishGuard</span>
        <button class="phish-close">×</button>
      </div>
      <div class="phish-content">
        <div class="phish-score ${riskLevel}">
          <div class="score-bar">
            <div class="score-fill" style="width: ${score}%; background: ${isPhishing ? '#e74c3c' : '#27ae60'}"></div>
          </div>
          <div class="score-text">${label} (${score}% confidence)</div>
        </div>
        <div class="phish-reasons">
          ${isPhishing ? '⚠️ Why this looks like phishing:' : '✅ Content appears safe'}
          ${reasonsHtml}
        </div>
        ${linksHtml}
      </div>
    `;
  }
  
  document.body.appendChild(phishPanel);
  
  phishPanel.querySelector('.phish-close').onclick = removePanel;
}

function removePanel() {
  if (phishPanel) {
    phishPanel.remove();
    phishPanel = null;
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
  console.log('📨 PhishGuard: Received message:', message);
  
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