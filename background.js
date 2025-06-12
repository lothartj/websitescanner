// Common admin paths to check
const ADMIN_PATHS = [
  '/admin',
  '/administrator',
  '/wp-admin',
  '/dashboard',
  '/admin/login.php',
  '/admin/index.php',
  '/manager',
  '/webadmin',
  '/adminpanel',
  '/control',
  '/member',
  '/backend',
  '/manage',
  '/login',
  '/adm',
  '/panel',
  '/admin-panel',
  '/cp',
  '/cpanel',
  '/portal',
  '/admin-login',
  '/moderator',
  '/webmaster',
  '/backend',
  '/admin-area'
];

// Common vulnerable paths
const VULNERABLE_PATHS = [
  '/config',
  '/.env',
  '/.git',
  '/backup',
  '/db',
  '/debug',
  '/api',
  '/log',
  '/logs',
  '/test',
  '/install',
  '/setup',
  '/conf',
  '/sql',
  '/phpinfo.php',
  '/info.php',
  '/server-status',
  '/server-info',
  '/wp-config.php.bak',
  '/config.php.bak',
  '/database.sql',
  '/backup.sql',
  '/error.log',
  '/debug.log',
  '/robots.txt',
  '/sitemap.xml',
  '/.htaccess'
];

// Technology signatures
const TECH_SIGNATURES = [
  { name: 'WordPress', patterns: ['wp-content', 'wp-includes', 'wordpress'] },
  { name: 'Joomla', patterns: ['com_content', 'joomla', '/administrator'] },
  { name: 'Drupal', patterns: ['drupal', 'sites/all', '/node/'] },
  { name: 'Laravel', patterns: ['laravel', '/vendor/laravel'] },
  { name: 'Angular', patterns: ['ng-app', 'angular.js', 'angular.min.js'] },
  { name: 'React', patterns: ['react.js', 'react-dom.js', 'react.min.js'] },
  { name: 'Vue', patterns: ['vue.js', 'vue.min.js'] },
  { name: 'Bootstrap', patterns: ['bootstrap.css', 'bootstrap.min.css'] },
  { name: 'jQuery', patterns: ['jquery.js', 'jquery.min.js'] },
  { name: 'PHP', patterns: ['.php'] },
  { name: 'ASP.NET', patterns: ['.aspx', '.asp'] },
  { name: 'Node.js', patterns: ['node_modules'] }
];

// Security headers to check
const SECURITY_HEADERS = [
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Content-Type-Options',
  'X-Frame-Options',
  'X-XSS-Protection',
  'Referrer-Policy',
  'Feature-Policy',
  'Permissions-Policy'
];

// Random user agents for anonymity
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'
];

// Global scan state
let scanInProgress = false;
let stopRequested = false;
let currentScanOptions = null;

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'startScan') {
    // Only start if no scan is in progress
    if (scanInProgress) {
      sendResponse({ status: 'busy', message: 'A scan is already in progress' });
      return true;
    }
    
    // Start the scan process
    scanInProgress = true;
    stopRequested = false;
    currentScanOptions = message;
    
    sendResponse({ status: 'started' });
    
    // Run the scan
    scanWebsite(message.url, message.tabId, message.scanOptions, message.securityOptions,
                message.performanceOptions, message.networkOptions, message.stressOptions,
                message.customPaths);
    
    // Return true to indicate we'll send a response asynchronously
    return true;
  } 
  else if (message.action === 'stopScan') {
    // Set flag to stop the scan
    stopRequested = true;
    sendResponse({ status: 'stopping' });
    return true;
  }
});

// Helper function to send log messages
function sendLog(message, type = 'info') {
  chrome.runtime.sendMessage({
    action: 'scanResult',
    data: {
      log: {
        message,
        type
      },
      complete: false
    }
  });
}

// Helper function to update progress
function updateProgress(percent) {
  chrome.runtime.sendMessage({
    action: 'scanResult',
    data: {
      progress: percent,
      complete: false
    }
  });
}

// Helper function to format bytes
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

// Main scan function
async function scanWebsite(url, tabId, scanOptions, securityOptions,
                          performanceOptions, networkOptions, stressOptions,
                          customPaths) {
  try {
    const baseUrl = new URL(url).origin;
    sendLog(`Starting scan of ${baseUrl}`, 'info');
    
    const results = {
      adminPaths: [],
      vulnerablePaths: [],
      technology: [],
      network: {},
      performance: {},
      stress: null,
      complete: false
    };
    
    let totalTasks = 0;
    let completedTasks = 0;
    
    // Count total tasks for progress tracking
    if (scanOptions.technologies) totalTasks++;
    if (scanOptions.adminPaths) totalTasks += ADMIN_PATHS.length;
    if (scanOptions.vulnerablePaths) totalTasks += VULNERABLE_PATHS.length;
    if (customPaths && customPaths.length > 0) totalTasks += customPaths.length;
    if (performanceOptions.loadTime || performanceOptions.responseSize || performanceOptions.resourceCount) totalTasks++;
    if (networkOptions.headers || networkOptions.security || networkOptions.cookies) totalTasks++;
    if (stressOptions.enabled) totalTasks++;
    
    updateProgress(0);
    
    // Detect technologies if enabled
    if (scanOptions.technologies && !stopRequested) {
      sendLog('Detecting website technologies...', 'info');
      await detectTechnologies(baseUrl, results, securityOptions);
      completedTasks++;
      updateProgress(Math.floor((completedTasks / totalTasks) * 100));
    }
    
    // Perform network analysis if enabled
    if ((networkOptions.headers || networkOptions.security || networkOptions.cookies) && !stopRequested) {
      sendLog('Analyzing network information...', 'info');
      await analyzeNetwork(baseUrl, results, securityOptions, networkOptions);
      completedTasks++;
      updateProgress(Math.floor((completedTasks / totalTasks) * 100));
    }
    
    // Perform performance testing if enabled
    if ((performanceOptions.loadTime || performanceOptions.responseSize || performanceOptions.resourceCount) && !stopRequested) {
      sendLog('Running performance tests...', 'info');
      await testPerformance(baseUrl, results, securityOptions, performanceOptions, tabId);
      completedTasks++;
      updateProgress(Math.floor((completedTasks / totalTasks) * 100));
    }
    
    // Scan for admin paths if enabled
    if (scanOptions.adminPaths && !stopRequested) {
      sendLog('Scanning for admin paths...', 'info');
      await scanPaths(baseUrl, ADMIN_PATHS, results, 'adminPaths', securityOptions, () => {
        completedTasks++;
        updateProgress(Math.floor((completedTasks / totalTasks) * 100));
      });
    }
    
    // Scan for vulnerable paths if enabled
    if (scanOptions.vulnerablePaths && !stopRequested) {
      sendLog('Scanning for vulnerable paths...', 'info');
      await scanPaths(baseUrl, VULNERABLE_PATHS, results, 'vulnerablePaths', securityOptions, () => {
        completedTasks++;
        updateProgress(Math.floor((completedTasks / totalTasks) * 100));
      });
    }
    
    // Scan custom paths if provided
    if (customPaths && customPaths.length > 0 && !stopRequested) {
      sendLog('Scanning custom paths...', 'info');
      await scanPaths(baseUrl, customPaths, results, 'customPaths', securityOptions, () => {
        completedTasks++;
        updateProgress(Math.floor((completedTasks / totalTasks) * 100));
      });
    }
    
    // Run stress test if enabled
    if (stressOptions.enabled && !stopRequested) {
      sendLog('Running stress test...', 'warning');
      await runStressTest(baseUrl, results, securityOptions, stressOptions);
      completedTasks++;
      updateProgress(Math.floor((completedTasks / totalTasks) * 100));
    }
    
    // Check if scan was stopped
    if (stopRequested) {
      sendLog('Scan stopped by user', 'warning');
      results.complete = true;
      chrome.runtime.sendMessage({
        action: 'scanResult',
        data: results
      });
      scanInProgress = false;
      return;
    }
    
    // Mark scan as complete
    sendLog('Scan completed successfully', 'success');
    results.complete = true;
    updateProgress(100);
    
    // Send final results
    chrome.runtime.sendMessage({
      action: 'scanResult',
      data: results
    });
    
    scanInProgress = false;
    
  } catch (error) {
    console.error('Scan error:', error);
    sendLog(`Error: ${error.message}`, 'error');
    
    chrome.runtime.sendMessage({
      action: 'scanResult',
      data: {
        error: error.message,
        complete: true
      }
    });
    
    scanInProgress = false;
  }
}

// Function to detect website technologies
async function detectTechnologies(baseUrl, results, securityOptions) {
  try {
    const response = await fetch(baseUrl, {
      method: 'GET',
      headers: getRequestHeaders(securityOptions)
    });
    
    if (response.ok) {
      const html = await response.text();
      
      // Check for technologies based on patterns in the HTML
      const detectedTech = [];
      
      for (const tech of TECH_SIGNATURES) {
        for (const pattern of tech.patterns) {
          if (html.toLowerCase().includes(pattern.toLowerCase())) {
            if (!detectedTech.includes(tech.name)) {
              detectedTech.push(tech.name);
              sendLog(`Detected technology: ${tech.name}`, 'success');
            }
            break;
          }
        }
      }
      
      results.technology = detectedTech;
      
      // Send intermediate results
      chrome.runtime.sendMessage({
        action: 'scanResult',
        data: {
          technology: detectedTech,
          complete: false
        }
      });
    }
  } catch (error) {
    sendLog(`Error detecting technologies: ${error.message}`, 'error');
    console.error('Error detecting technologies:', error);
  }
}

// Function to analyze network information
async function analyzeNetwork(baseUrl, results, securityOptions, networkOptions) {
  try {
    // Initialize network results
    results.network = {};
    
    const response = await fetch(baseUrl, {
      method: 'GET',
      headers: getRequestHeaders(securityOptions),
      credentials: 'include'
    });
    
    // Analyze headers if enabled
    if (networkOptions.headers) {
      results.network.headers = {};
      
      // Get response headers
      for (const [key, value] of response.headers.entries()) {
        results.network.headers[key] = value;
      }
      
      sendLog(`Analyzed ${Object.keys(results.network.headers).length} HTTP headers`, 'info');
    }
    
    // Check security headers if enabled
    if (networkOptions.security) {
      results.network.security = {};
      
      for (const header of SECURITY_HEADERS) {
        const hasHeader = response.headers.has(header);
        results.network.security[header] = hasHeader;
        
        if (hasHeader) {
          sendLog(`Security header found: ${header}`, 'success');
        } else {
          sendLog(`Missing security header: ${header}`, 'warning');
        }
      }
    }
    
    // Analyze cookies if enabled
    if (networkOptions.cookies) {
      results.network.cookies = [];
      
      const cookieHeader = response.headers.get('set-cookie');
      if (cookieHeader) {
        const cookies = cookieHeader.split(',');
        for (let cookie of cookies) {
          const parts = cookie.split(';');
          const nameValue = parts[0].trim().split('=');
          
          if (nameValue.length >= 2) {
            const cookieObj = {
              name: nameValue[0],
              value: nameValue[1],
              secure: cookie.toLowerCase().includes('secure'),
              httpOnly: cookie.toLowerCase().includes('httponly')
            };
            
            results.network.cookies.push(cookieObj);
            
            const secureStatus = cookieObj.secure ? 'secure' : 'insecure';
            sendLog(`Cookie found: ${cookieObj.name} (${secureStatus})`, cookieObj.secure ? 'success' : 'warning');
          }
        }
      }
    }
    
    // Send intermediate results
    chrome.runtime.sendMessage({
      action: 'scanResult',
      data: {
        network: results.network,
        complete: false
      }
    });
    
  } catch (error) {
    sendLog(`Error analyzing network: ${error.message}`, 'error');
    console.error('Error analyzing network:', error);
  }
}

// Function to test performance
async function testPerformance(baseUrl, results, securityOptions, performanceOptions, tabId) {
  try {
    results.performance = {};
    
    // Test load time if enabled
    if (performanceOptions.loadTime) {
      const startTime = Date.now();
      
      const response = await fetch(baseUrl, {
        method: 'GET',
        headers: getRequestHeaders(securityOptions)
      });
      
      const endTime = Date.now();
      results.performance.loadTime = endTime - startTime;
      
      sendLog(`Page load time: ${results.performance.loadTime} ms`, 'info');
    }
    
    // Test response size if enabled
    if (performanceOptions.responseSize) {
      const response = await fetch(baseUrl, {
        method: 'GET',
        headers: getRequestHeaders(securityOptions)
      });
      
      const text = await response.text();
      const size = new Blob([text]).size;
      
      results.performance.responseSize = formatBytes(size);
      
      sendLog(`Response size: ${results.performance.responseSize}`, 'info');
    }
    
    // Count resources if enabled
    if (performanceOptions.resourceCount) {
      // This requires executing a content script on the page
      try {
        // Execute content script to count resources
        const [resourcesTab] = await chrome.scripting.executeScript({
          target: { tabId: tabId },
          function: countPageResources
        });
        
        if (resourcesTab && resourcesTab.result) {
          results.performance.resources = resourcesTab.result;
          
          sendLog(`Resources: ${results.performance.resources.total} total (${results.performance.resources.js} JS, ${results.performance.resources.css} CSS, ${results.performance.resources.img} images)`, 'info');
        }
      } catch (scriptError) {
        console.error('Error executing content script:', scriptError);
        sendLog(`Error counting resources: ${scriptError.message}`, 'error');
      }
    }
    
    // Send intermediate results
    chrome.runtime.sendMessage({
      action: 'scanResult',
      data: {
        performance: results.performance,
        complete: false
      }
    });
    
  } catch (error) {
    sendLog(`Error testing performance: ${error.message}`, 'error');
    console.error('Error testing performance:', error);
  }
}

// Function to count page resources (executed as content script)
function countPageResources() {
  const scripts = document.querySelectorAll('script[src]');
  const styles = document.querySelectorAll('link[rel="stylesheet"]');
  const images = document.querySelectorAll('img');
  
  return {
    js: scripts.length,
    css: styles.length,
    img: images.length,
    total: scripts.length + styles.length + images.length
  };
}

// Function to run stress test
async function runStressTest(baseUrl, results, securityOptions, stressOptions) {
  try {
    const requestsPerSecond = stressOptions.requestsPerSecond;
    const duration = stressOptions.duration;
    const totalRequests = requestsPerSecond * duration;
    
    sendLog(`Starting stress test with ${requestsPerSecond} req/s for ${duration} seconds (${totalRequests} total)`, 'info');
    
    // Initialize stress test results
    results.stress = {
      requestsSent: 0,
      successful: 0,
      failed: 0,
      averageTime: 0
    };
    
    let totalTime = 0;
    const interval = 1000 / requestsPerSecond;
    const startTime = Date.now();
    let endTime = startTime + (duration * 1000);
    
    // Send requests
    while (Date.now() < endTime && !stopRequested) {
      const batchStart = Date.now();
      
      // Send a batch of requests (one per interval)
      const requests = [];
      for (let i = 0; i < requestsPerSecond; i++) {
        if (stopRequested) break;
        
        requests.push(
          fetch(baseUrl, {
            method: 'GET',
            headers: getRequestHeaders(securityOptions)
          })
          .then(response => {
            results.stress.requestsSent++;
            if (response.ok) {
              results.stress.successful++;
            } else {
              results.stress.failed++;
            }
            return Date.now();
          })
          .catch(error => {
            results.stress.requestsSent++;
            results.stress.failed++;
            console.error('Stress test request error:', error);
            return Date.now();
          })
        );
        
        // Small delay to spread requests over the second
        if (i < requestsPerSecond - 1) {
          await new Promise(resolve => setTimeout(resolve, interval));
        }
      }
      
      // Wait for all requests to complete
      const endTimes = await Promise.all(requests);
      
      // Calculate total time for this batch
      for (const endTime of endTimes) {
        totalTime += (endTime - batchStart);
      }
      
      // Update average time
      if (results.stress.requestsSent > 0) {
        results.stress.averageTime = Math.round(totalTime / results.stress.requestsSent);
      }
      
      // Send intermediate results
      chrome.runtime.sendMessage({
        action: 'scanResult',
        data: {
          stress: results.stress,
          complete: false
        }
      });
      
      // Check if we should stop
      if (stopRequested) break;
      
      // Wait for the next second
      const elapsed = Date.now() - batchStart;
      if (elapsed < 1000) {
        await new Promise(resolve => setTimeout(resolve, 1000 - elapsed));
      }
    }
    
    sendLog(`Stress test completed: ${results.stress.successful} successful, ${results.stress.failed} failed`, 'success');
    
  } catch (error) {
    sendLog(`Error during stress test: ${error.message}`, 'error');
    console.error('Stress test error:', error);
  }
}

// Function to scan for specific paths
async function scanPaths(baseUrl, paths, results, resultType, securityOptions, progressCallback) {
  if (!results[resultType]) {
    results[resultType] = [];
  }
  
  for (const path of paths) {
    // Check if scan should stop
    if (stopRequested) {
      break;
    }
    
    try {
      const url = `${baseUrl}${path}`;
      
      // Send request to check if path exists
      const response = await fetch(url, {
        method: 'HEAD',  // Use HEAD to avoid downloading the full page
        headers: getRequestHeaders(securityOptions),
        redirect: 'manual'  // Don't follow redirects automatically
      });
      
      // Add to results if status is 200 OK, 301 Moved Permanently, or 302 Found
      if (response.status === 200 || response.status === 301 || response.status === 302) {
        const result = {
          path: path,
          url: url,
          status: response.status
        };
        
        results[resultType].push(result);
        
        // Send intermediate result
        const updateData = {
          complete: false
        };
        updateData[resultType] = results[resultType];
        
        chrome.runtime.sendMessage({
          action: 'scanResult',
          data: updateData
        });
        
        const statusText = response.status === 200 ? 'OK' : 
                          (response.status === 301 ? 'Moved Permanently' : 'Found');
        
        sendLog(`Found path: ${path} (${response.status} ${statusText})`, 'success');
      }
      
      // Call progress callback
      if (progressCallback) {
        progressCallback();
      }
      
      // Add a small delay to avoid overwhelming the server
      await new Promise(resolve => setTimeout(resolve, 300));
      
    } catch (error) {
      console.error(`Error scanning path ${path}:`, error);
      sendLog(`Error scanning ${path}: ${error.message}`, 'error');
      
      // Call progress callback even on error
      if (progressCallback) {
        progressCallback();
      }
    }
  }
}

// Function to get request headers based on security options
function getRequestHeaders(securityOptions) {
  const headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
  };
  
  // Add random user agent if enabled
  if (securityOptions.randomUserAgent) {
    const randomIndex = Math.floor(Math.random() * USER_AGENTS.length);
    headers['User-Agent'] = USER_AGENTS[randomIndex];
  }
  
  // Note: Proxy settings would need to be handled differently as fetch API doesn't directly
  // support proxy settings. In a real implementation, you might need to use a proxy server
  // or proxy settings available in Chrome extensions.
  
  return headers;
} 