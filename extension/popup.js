document.addEventListener('DOMContentLoaded', () => {
  const textInput = document.getElementById('textInput');
  const scanBtn = document.getElementById('scanBtn');

  scanBtn.addEventListener('click', async () => {
    const text = textInput.value.trim();
    if (!text) return;

    chrome.runtime.sendMessage({
      type: "POPUP_SCAN",
      text: text
    });
    
    window.close();
  });
});