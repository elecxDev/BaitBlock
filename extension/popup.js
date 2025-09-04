document.addEventListener('DOMContentLoaded', () => {
  const textInput = document.getElementById('textInput');
  const scanBtn = document.getElementById('scanBtn');

  scanBtn.addEventListener('click', async () => {
    const text = textInput.value.trim();
    if (!text) return;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_LOADING"
    });
    
    const result = await chrome.runtime.sendMessage({
      type: "ANALYZE_TEXT",
      text: text
    });
    
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_RESULT",
      result: result
    });
    
    window.close();
  });
});