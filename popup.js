document.addEventListener('DOMContentLoaded', function() {
  // Tab navigation
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      // Remove active class from all buttons and tabs
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));
      
      // Add active class to clicked button and corresponding tab
      button.classList.add('active');
      const tabId = button.getAttribute('data-tab');
      document.getElementById(`${tabId}-tab`).classList.add('active');
    });
  });
  
  // Collapsible sections
  const collapsibles = document.querySelectorAll('.collapsible');
  
  collapsibles.forEach(collapsible => {
    collapsible.addEventListener('click', function() {
      this.classList.toggle('active');
      const content = this.nextElementSibling;
      if (content.style.maxHeight) {
        content.style.maxHeight = null;
      } else {
        content.style.maxHeight = content.scrollHeight + "px";
      }
    });
  });

  // UI Elements
  const startScanButton = document.getElementById('startScan');
  const stopScanButton = document.getElementById('stopScan');
  const scanResults = document.getElementById('scanResults');
  const scanSummary = document.getElementById('scanSummary');
  const scanLogs = document.getElementById('scanLogs');
  const progressBar = document.getElementById('progress');
  
  // Scan state
  let scanInProgress = false;
  let scanStartTime = null;
  
  // Load saved settings
  chrome.storage.local.get([
    'scanOptions', 
    'securityOptions',
    'performanceOptions',
    'networkOptions',
    'stressOptions',
    'customPaths'
  ], function(result) {
    if (result.scanOptions) {
      document.getElementById('scanAdminPaths').checked = result.scanOptions.adminPaths;
      document.getElementById('scanTech').checked = result.scanOptions.technologies;
      document.getElementById('scanVulnerablePaths').checked = result.scanOptions.vulnerablePaths;
    }
    
    if (result.securityOptions) {
      document.getElementById('useProxy').checked = result.securityOptions.useProxy;
      document.getElementById('proxyAddress').value = result.securityOptions.proxyAddress || '';
      document.getElementById('randomUserAgent').checked = result.securityOptions.randomUserAgent;
    }
    
    if (result.performanceOptions) {
      document.getElementById('testLoadTime').checked = result.performanceOptions.loadTime;
      document.getElementById('testResponseSize').checked = result.performanceOptions.responseSize;
      document.getElementById('testResourceCount').checked = result.performanceOptions.resourceCount;
    }
    
    if (result.networkOptions) {
      document.getElementById('analyzeHeaders').checked = result.networkOptions.headers;
      document.getElementById('checkSecurity').checked = result.networkOptions.security;
      document.getElementById('checkCookies').checked = result.networkOptions.cookies;
    }
    
    if (result.stressOptions) {
      document.getElementById('stressTest').checked = result.stressOptions.enabled;
      document.getElementById('requestsPerSecond').value = result.stressOptions.requestsPerSecond;
      document.getElementById('stressDuration').value = result.stressOptions.duration;
    }
    
    if (result.customPaths) {
      document.getElementById('customPaths').value = result.customPaths.join('\n');
    }
  });
  
  // Helper function to add log entries
  function addLogEntry(message, type = 'info') {
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${type}`;
    logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    scanLogs.insertBefore(logEntry, scanLogs.firstChild);
    
    // If this is the first log entry, clear the placeholder
    if (scanLogs.querySelector('em')) {
      scanLogs.innerHTML = '';
      scanLogs.appendChild(logEntry);
    }
  }
  
  // Helper function to update progress
  function updateProgress(percent) {
    progressBar.style.width = `${percent}%`;
    progressBar.textContent = `${percent}%`;
  }
  
  // Start scan button click handler
  startScanButton.addEventListener('click', function() {
    if (scanInProgress) return;
    
    scanInProgress = true;
    scanStartTime = Date.now();
    startScanButton.disabled = true;
    stopScanButton.disabled = false;
    
    // Reset UI
    scanSummary.innerHTML = '<p>Scan in progress...</p>';
    scanResults.innerHTML = '<p>Detailed results will appear here as they are discovered...</p>';
    scanLogs.innerHTML = '';
    updateProgress(0);
    
    // Get all scan options
    const scanOptions = {
      adminPaths: document.getElementById('scanAdminPaths').checked,
      technologies: document.getElementById('scanTech').checked,
      vulnerablePaths: document.getElementById('scanVulnerablePaths').checked
    };
    
    const securityOptions = {
      useProxy: document.getElementById('useProxy').checked,
      proxyAddress: document.getElementById('proxyAddress').value,
      randomUserAgent: document.getElementById('randomUserAgent').checked
    };
    
    const performanceOptions = {
      loadTime: document.getElementById('testLoadTime')?.checked || false,
      responseSize: document.getElementById('testResponseSize')?.checked || false,
      resourceCount: document.getElementById('testResourceCount')?.checked || false
    };
    
    const networkOptions = {
      headers: document.getElementById('analyzeHeaders')?.checked || false,
      security: document.getElementById('checkSecurity')?.checked || false,
      cookies: document.getElementById('checkCookies')?.checked || false
    };
    
    const stressOptions = {
      enabled: document.getElementById('stressTest')?.checked || false,
      requestsPerSecond: parseInt(document.getElementById('requestsPerSecond')?.value || '10'),
      duration: parseInt(document.getElementById('stressDuration')?.value || '10')
    };
    
    // Parse custom paths
    const customPathsInput = document.getElementById('customPaths')?.value || '';
    const customPaths = customPathsInput
      .split('\n')
      .map(path => path.trim())
      .filter(path => path.length > 0);
    
    // Save all settings
    chrome.storage.local.set({
      scanOptions,
      securityOptions,
      performanceOptions,
      networkOptions,
      stressOptions,
      customPaths
    });
    
    addLogEntry('Starting scan...', 'info');
    
    // Get the current tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const currentTab = tabs[0];
      
      addLogEntry(`Target URL: ${currentTab.url}`, 'info');
      
      // Send message to background script to start the scan
      chrome.runtime.sendMessage({
        action: 'startScan',
        url: currentTab.url,
        tabId: currentTab.id,
        scanOptions,
        securityOptions,
        performanceOptions,
        networkOptions,
        stressOptions,
        customPaths
      }, function(response) {
        if (response && response.status === 'started') {
          addLogEntry('Scan started successfully', 'success');
          
          // Listen for scan results
          chrome.runtime.onMessage.addListener(scanMessageListener);
        } else {
          scanInProgress = false;
          startScanButton.disabled = false;
          stopScanButton.disabled = true;
          
          addLogEntry('Error starting scan', 'error');
          scanSummary.innerHTML = '<p>Error starting scan.</p>';
        }
      });
    });
  });
  
  // Stop scan button click handler
  stopScanButton.addEventListener('click', function() {
    if (!scanInProgress) return;
    
    chrome.runtime.sendMessage({
      action: 'stopScan'
    }, function(response) {
      addLogEntry('Scan stopped by user', 'warning');
      
      scanInProgress = false;
      startScanButton.disabled = false;
      stopScanButton.disabled = true;
      
      // Update UI
      updateProgress(100);
      scanSummary.innerHTML = '<p>Scan stopped by user.</p>';
    });
  });
  
  // Function to handle scan messages
  function scanMessageListener(message) {
    if (message.action === 'scanResult') {
      const data = message.data;
      
      // Update logs
      if (data.log) {
        addLogEntry(data.log.message, data.log.type || 'info');
      }
      
      // Update progress
      if (data.progress !== undefined) {
        updateProgress(data.progress);
      }
      
      // Update results
      updateResults(data);
      
      // If scan is complete, reset UI
      if (data.complete) {
        const scanDuration = ((Date.now() - scanStartTime) / 1000).toFixed(2);
        addLogEntry(`Scan completed in ${scanDuration} seconds`, 'success');
        
        scanInProgress = false;
        startScanButton.disabled = false;
        stopScanButton.disabled = true;
        updateProgress(100);
        
        // Remove the listener
        chrome.runtime.onMessage.removeListener(scanMessageListener);
      }
    }
  }
  
  // Function to update results in the UI
  function updateResults(data) {
    // Update summary tab with brief results
    if (data.complete) {
      let summaryHTML = '<h3>Scan Complete</h3>';
      
      if (data.technology && data.technology.length > 0) {
        summaryHTML += `<p><strong>Technologies:</strong> ${data.technology.join(', ')}</p>`;
      }
      
      if (data.adminPaths && data.adminPaths.length > 0) {
        summaryHTML += `<p><strong>Admin paths found:</strong> ${data.adminPaths.length}</p>`;
      }
      
      if (data.vulnerablePaths && data.vulnerablePaths.length > 0) {
        summaryHTML += `<p><strong>Vulnerable paths found:</strong> ${data.vulnerablePaths.length}</p>`;
      }
      
      scanSummary.innerHTML = summaryHTML;
    }
    
    // Update detailed results tab
    let detailedHTML = '';
    
    // Add technology results
    if (data.technology && data.technology.length > 0) {
      detailedHTML += `<div><strong>Technologies Detected:</strong><ul>${data.technology.map(tech => `<li>${tech}</li>`).join('')}</ul></div>`;
    }
    
    // Add performance results
    if (data.performance) {
      detailedHTML += '<div><strong>Performance Results:</strong><ul>';
      if (data.performance.loadTime) {
        detailedHTML += `<li>Load time: ${data.performance.loadTime} ms</li>`;
      }
      if (data.performance.responseSize) {
        detailedHTML += `<li>Response size: ${data.performance.responseSize}</li>`;
      }
      if (data.performance.resources) {
        detailedHTML += `<li>Resources: ${data.performance.resources.total} total (${data.performance.resources.js} JS, ${data.performance.resources.css} CSS, ${data.performance.resources.img} images)</li>`;
      }
      detailedHTML += '</ul></div>';
    }
    
    // Add admin paths results
    if (data.adminPaths && data.adminPaths.length > 0) {
      detailedHTML += `<div><strong>Admin Paths Found:</strong><ul>${data.adminPaths.map(path => 
        `<li><a href="${path.url}" target="_blank">${path.path}</a> - Status: ${path.status}</li>`).join('')}</ul></div>`;
    }
    
    // Add vulnerable paths results
    if (data.vulnerablePaths && data.vulnerablePaths.length > 0) {
      detailedHTML += `<div><strong>Potentially Vulnerable Paths:</strong><ul>${data.vulnerablePaths.map(path => 
        `<li><a href="${path.url}" target="_blank">${path.path}</a> - Status: ${path.status}</li>`).join('')}</ul></div>`;
    }
    
    // Add network analysis results
    if (data.network) {
      detailedHTML += '<div><strong>Network Analysis:</strong><ul>';
      if (data.network.headers) {
        detailedHTML += `<li>Headers: ${Object.keys(data.network.headers).length} headers analyzed</li>`;
        detailedHTML += '<ul>';
        for (const [key, value] of Object.entries(data.network.headers)) {
          detailedHTML += `<li>${key}: ${value}</li>`;
        }
        detailedHTML += '</ul>';
      }
      if (data.network.security) {
        detailedHTML += '<li>Security headers:';
        detailedHTML += '<ul>';
        for (const [header, present] of Object.entries(data.network.security)) {
          const icon = present ? '✅' : '❌';
          detailedHTML += `<li>${icon} ${header}</li>`;
        }
        detailedHTML += '</ul></li>';
      }
      if (data.network.cookies) {
        detailedHTML += `<li>Cookies: ${data.network.cookies.length} found</li>`;
        if (data.network.cookies.length > 0) {
          detailedHTML += '<ul>';
          data.network.cookies.forEach(cookie => {
            detailedHTML += `<li>${cookie.name}: ${cookie.secure ? '🔒' : '🔓'} ${cookie.httpOnly ? '(HTTP only)' : ''}</li>`;
          });
          detailedHTML += '</ul>';
        }
      }
      detailedHTML += '</ul></div>';
    }
    
    // Add stress test results
    if (data.stress) {
      detailedHTML += '<div><strong>Stress Test Results:</strong><ul>';
      detailedHTML += `<li>Requests sent: ${data.stress.requestsSent}</li>`;
      detailedHTML += `<li>Successful responses: ${data.stress.successful}</li>`;
      detailedHTML += `<li>Failed responses: ${data.stress.failed}</li>`;
      detailedHTML += `<li>Average response time: ${data.stress.averageTime} ms</li>`;
      detailedHTML += '</ul></div>';
    }
    
    // Add error information
    if (data.error) {
      detailedHTML += `<div style="color: red;"><strong>Error:</strong> ${data.error}</div>`;
    }
    
    // Only replace contents if we have new detailed results
    if (detailedHTML) {
      // If first result, clear the placeholder
      if (scanResults.querySelector('p')) {
        scanResults.innerHTML = '';
      }
      
      // Add the new content
      const resultDiv = document.createElement('div');
      resultDiv.innerHTML = detailedHTML;
      scanResults.appendChild(resultDiv);
    }
  }
}); 