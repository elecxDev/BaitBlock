const SUPABASE_FUNCTION_URL = "https://tlxglrmzbfmzpknmyjnh.supabase.co/functions/v1/get-result";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRseGdscm16YmZtenBrbm15am5oIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY5MTA1NDcsImV4cCI6MjA3MjQ4NjU0N30.84Ex9aTrJ97N0v1akYgIntq601eXP5QR-L6briMZ5sM";

let phishPanel = null;

async function scanText(text) {
  console.log('🔍 PhishGuard: Starting scan for:', text);
  try {
    const response = await fetch(SUPABASE_FUNCTION_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${SUPABASE_ANON_KEY}`
      },
      body: JSON.stringify({ text })
    });
    console.log('📡 PhishGuard: Response status:', response.status);
    const data = await response.json();
    console.log('📊 PhishGuard: Response data:', data);
    return data;
  } catch (err) {
    console.error('❌ PhishGuard: Error:', err);
    return { error: err.message || "Network error" };
  }
}

function createResultPanel(data) {
  console.log('🎨 PhishGuard: Creating panel with data:', data);
  removePanel();
  
  phishPanel = document.createElement('div');
  phishPanel.id = 'phishguard-panel';
  phishPanel.innerHTML = `
    <div class="phish-header">
      <span>PhishGuard</span>
      <button class="phish-close">×</button>
    </div>
    <div class="phish-content">
      ${data.loading ? 
        '<div class="phish-loading">Analyzing...</div>' :
        `<div class="phish-score ${data.result?.risk_level?.toLowerCase() || 'unknown'}">
          Score: ${data.result?.score || 0}/100 (${data.result?.risk_level || 'Unknown'})
        </div>
        ${data.result?.error ? 
          `<div class="phish-error">Error: ${data.result.error}</div>` :
          `<div class="phish-reasons">
            ${data.result?.reasons?.map(reason => `<div>• ${reason}</div>`).join('') || 'No specific threats detected'}
          </div>`
        }`
      }
    </div>
  `;
  
  document.body.appendChild(phishPanel);
  
  phishPanel.querySelector('.phish-close').onclick = removePanel;
  setTimeout(removePanel, 10000);
}

function removePanel() {
  if (phishPanel) {
    phishPanel.remove();
    phishPanel = null;
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  console.log('📨 PhishGuard: Received message:', message);
  
  if (message.type === "SCAN_SELECTED_TEXT") {
    const text = message.text;
    if (text) {
      createResultPanel({ loading: true });
      const result = await scanText(text);
      createResultPanel({ result });
    }
  }
});