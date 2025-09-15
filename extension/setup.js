document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('setupForm');
  const jobRoleSelect = document.getElementById('jobRole');
  const skipBtn = document.getElementById('skipBtn');

  // Show risk indicator based on job role
  jobRoleSelect.addEventListener('change', (e) => {
    const existingIndicator = document.querySelector('.risk-indicator');
    if (existingIndicator) existingIndicator.remove();

    const value = e.target.value;
    let riskLevel, riskText;

    const highRisk = ['ceo', 'cfo', 'executive', 'finance', 'hr', 'it-admin'];
    const mediumRisk = ['manager', 'supervisor'];

    if (highRisk.includes(value)) {
      riskLevel = 'high';
      riskText = 'High Risk';
    } else if (mediumRisk.includes(value)) {
      riskLevel = 'medium';
      riskText = 'Medium Risk';
    } else {
      riskLevel = 'low';
      riskText = 'Low Risk';
    }

    if (value) {
      const indicator = document.createElement('span');
      indicator.className = `risk-indicator risk-${riskLevel}`;
      indicator.textContent = riskText;
      e.target.parentNode.appendChild(indicator);
    }
  });

  // Handle form submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const profileData = {
      email: document.getElementById('email').value,
      jobRole: document.getElementById('jobRole').value,
      department: document.getElementById('department').value,
      alertStyle: document.getElementById('alertStyle').value,
      organizationId: document.getElementById('orgId').value || null,
      setupComplete: true
    };

    // Save to chrome storage
    await chrome.storage.local.set({ 
      userProfile: {
        ...profileData,
        userId: profileData.email,
        sensitivityLevel: 0.6,
        learningData: {
          falsePositives: 0,
          confirmedThreats: 0,
          userFeedback: [],
          lastUpdated: Date.now()
        },
        preferences: {
          alertStyle: profileData.alertStyle,
          language: 'en',
          notificationFrequency: 'immediate'
        }
      },
      setupComplete: true
    });

    // Notify background script
    chrome.runtime.sendMessage({
      type: 'PROFILE_SETUP_COMPLETE',
      profile: profileData
    });

    // Close setup
    window.close();
  });

  // Skip setup
  skipBtn.addEventListener('click', async () => {
    await chrome.storage.local.set({ setupComplete: false });
    window.close();
  });

  // Load existing profile if any
  chrome.storage.local.get(['userProfile']).then(result => {
    if (result.userProfile) {
      const profile = result.userProfile;
      document.getElementById('email').value = profile.email || '';
      document.getElementById('jobRole').value = profile.jobRole || '';
      document.getElementById('department').value = profile.department || '';
      document.getElementById('alertStyle').value = profile.alertStyle || 'standard';
      document.getElementById('orgId').value = profile.organizationId || '';
    }
  });
});