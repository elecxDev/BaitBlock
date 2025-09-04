document.addEventListener('DOMContentLoaded', () => {
  const textInput = document.getElementById('textInput');
  const scanBtn = document.getElementById('scanBtn');
  const resultDiv = document.getElementById('result');

  scanBtn.addEventListener('click', async () => {
    const text = textInput.value.trim();
    if (!text) return;

    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    resultDiv.innerHTML = '';

    try {
      const data = await chrome.runtime.sendMessage({
        type: "ANALYZE_TEXT",
        text: text
      });
      displayResult(data);
    } catch (err) {
      displayResult({ error: err.message || "Network error" });
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = 'Scan for Phishing';
    }
  });

  function displayResult(data) {
    if (data.error) {
      resultDiv.innerHTML = `<div class="result error">❌ ${data.error}</div>`;
      return;
    }

    // Parse Gradio response
    const gradioData = data.data || data;
    const label = Array.isArray(gradioData) ? gradioData[0] : (gradioData.label || 'unknown');
    const confidence = Array.isArray(gradioData) && gradioData[1] ? gradioData[1] : (gradioData.confidence || 0);
    
    const isPhishing = label.toLowerCase().includes('phish');
    const riskLevel = isPhishing ? 'high' : 'low';
    const score = Math.round(confidence * 100);

    resultDiv.innerHTML = `
      <div class="result ${riskLevel}">
        <div class="score-bar">
          <div class="score-fill" style="width: ${score}%; background: linear-gradient(90deg, #27ae60 0%, #f39c12 50%, #e74c3c 100%); background-size: 100% 100%; background-position: ${score}% 0;"></div>
        </div>
        <div class="score">${label} (${score}% confidence)</div>
        <div class="reasons">
          ${isPhishing ? 
            '⚠️ Potential phishing content detected' : 
            '✅ Content appears safe'
          }
        </div>
      </div>
    `;
  }
});