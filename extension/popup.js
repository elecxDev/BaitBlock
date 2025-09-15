document.addEventListener('DOMContentLoaded', () => {
  const textInput = document.getElementById('textInput');
  const scanBtn = document.getElementById('scanBtn');
  const setupBtn = document.getElementById('setupBtn');

  scanBtn.addEventListener('click', async () => {
    const text = textInput.value.trim();
    if (!text) return;

    chrome.runtime.sendMessage({
      type: "POPUP_SCAN",
      text: text
    });
    
    window.close();
  });
  
  setupBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      type: "OPEN_SETUP"
    });
    window.close();
  });
});