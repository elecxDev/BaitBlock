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
    console.error('❌ BaitBlock API Error:', error);
    return { error: "BaitBlock server is offline. Start the local server." };
  }
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ BaitBlock: Extension installed');
  chrome.contextMenus.create({
    id: "baitblock-scan",
    title: "Check for phishing",
    contexts: ["selection"]
  });
  chrome.contextMenus.create({
    id: "baitblock-scan-email",
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
  console.log('🖱️ BaitBlock: Context menu clicked:', info);
  if (info.menuItemId === "baitblock-scan" && info.selectionText) {
    console.log('📤 BaitBlock: Sending scan request for:', info.selectionText);
    
    // Show loading sidebar immediately
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_LOADING"
    });
    
    const result = await callLocalAPI(info.selectionText);
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_RESULT",
      result: result
    });
  } else if (info.menuItemId === "baitblock-scan-email") {
    console.log('📧 BaitBlock: Scanning email');
    chrome.tabs.sendMessage(tab.id, {
      type: "SCAN_EMAIL"
    });
  }
});

chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.type === "ANALYZE_TEXT") {
    const result = await callLocalAPI(message.text);
    sendResponse(result);
  } else if (message.type === "POPUP_SCAN") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_LOADING"
    });
    
    const result = await callLocalAPI(message.text);
    
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_RESULT",
      result: result
    });
  }
  return true;
});