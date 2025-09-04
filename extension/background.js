const LOCAL_ENDPOINT = "http://localhost:5000/predict";

async function callLocalAPI(text) {
  try {
    const response = await fetch(LOCAL_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: [text] })
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    const result = await response.json();
    console.log('✅ Local API Response:', result);
    return result;
  } catch (error) {
    console.error('❌ PhishGuard API Error:', error);
    return { error: "PhishGuard server is offline. Start the local server." };
  }
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ PhishGuard: Extension installed');
  chrome.contextMenus.create({
    id: "phishguard-scan",
    title: "Check for phishing",
    contexts: ["selection"]
  });
  chrome.contextMenus.create({
    id: "phishguard-scan-email",
    title: "🛡️ Scan this email",
    contexts: ["page"],
    documentUrlPatterns: [
      "https://mail.google.com/*",
      "https://outlook.live.com/*",
      "https://outlook.office.com/*",
      "https://outlook.office365.com/*"
    ]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  console.log('🖱️ PhishGuard: Context menu clicked:', info);
  if (info.menuItemId === "phishguard-scan" && info.selectionText) {
    console.log('📤 PhishGuard: Sending scan request for:', info.selectionText);
    
    // Show loading sidebar immediately
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_LOADING"
    });
    
    const result = await callLocalAPI(info.selectionText);
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_RESULT",
      result: result
    });
  } else if (info.menuItemId === "phishguard-scan-email") {
    console.log('📧 PhishGuard: Scanning email');
    chrome.tabs.sendMessage(tab.id, {
      type: "SCAN_EMAIL"
    });
  }
});

chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.type === "ANALYZE_TEXT") {
    const result = await callLocalAPI(message.text);
    sendResponse(result);
  }
  return true;
});