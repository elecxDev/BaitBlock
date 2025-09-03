chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ PhishGuard: Extension installed');
  chrome.contextMenus.create({
    id: "phishguard-scan",
    title: "Check for phishing",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  console.log('🖱️ PhishGuard: Context menu clicked:', info);
  if (info.menuItemId === "phishguard-scan" && info.selectionText) {
    console.log('📤 PhishGuard: Sending scan request for:', info.selectionText);
    chrome.tabs.sendMessage(tab.id, {
      type: "SCAN_SELECTED_TEXT",
      text: info.selectionText
    });
  }
});