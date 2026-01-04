// Use built-in fetch (Node.js 18+) or http module
const http = require('http');
const https = require('https');

const services = [
  { name: 'Frontend', url: 'http://localhost:4000', port: 4000 },
  { name: 'Backend API', url: 'http://localhost:4002/api/health', port: 4002 },
  { name: 'CTF Automation', url: 'http://localhost:4003/health', port: 4003 },
  { name: 'Guacamole', url: 'http://localhost:8081', port: 8081 },
];

function checkHealth(service) {
  return new Promise((resolve) => {
    const url = new URL(service.url);
    const client = url.protocol === 'https:' ? https : http;
    
    const req = client.get(url, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ ...service, status: 'healthy', response: json });
        } catch {
          resolve({ ...service, status: 'healthy', response: null });
        }
      });
    });
    
    req.on('error', (error) => {
      resolve({ ...service, status: 'unavailable', error: error.message });
    });
    
    req.on('timeout', () => {
      req.destroy();
      resolve({ ...service, status: 'unavailable', error: 'Request timeout' });
    });
    
    req.setTimeout(5000);
  });
}

function checkAllServices() {
  console.log('🏥 Health Check - CTF Platform Services\n');
  console.log('='.repeat(60));
  
  return Promise.all(services.map(checkHealth)).then(results => {
  
  let allHealthy = true;
  
  // Check if all services are healthy
  for (const result of results) {
    if (result.status !== 'healthy') {
      allHealthy = false;
      break;
    }
  }
  
  for (const result of results) {
    const statusIcon = result.status === 'healthy' ? '✅' : '❌';
    console.log(`${statusIcon} ${result.name} (Port ${result.port})`);
    console.log(`   Status: ${result.status}`);
    
    if (result.error) {
      console.log(`   Error: ${result.error}`);
      allHealthy = false;
    }
    
    if (result.response) {
      console.log(`   Response: ${JSON.stringify(result.response)}`);
    }
    
    console.log('');
  }
  
  console.log('='.repeat(60));
  
  if (allHealthy) {
    console.log('✅ All services are healthy!');
    process.exit(0);
  } else {
    console.log('❌ Some services are unhealthy');
    process.exit(1);
  }
  });
}

checkAllServices().then(() => {
  // Already handled in function
}).catch(error => {
  console.error('❌ Health check failed:', error);
  process.exit(1);
});

