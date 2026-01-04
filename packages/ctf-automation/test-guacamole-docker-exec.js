/**
 * Test Guacamole Docker Exec Implementation
 * This will create a test connection to verify the new approach works
 */

import axios from 'axios';

const API_URL = 'http://localhost:3003/api';

async function testGuacamoleConnection() {
  console.log('🧪 Testing Guacamole Docker Exec Implementation\n');
  
  try {
    // Deploy a simple challenge
    console.log('📦 Deploying test challenge...');
    const response = await axios.post(`${API_URL}/chat`, {
      message: 'Create a web challenge called test-docker-exec-connection with a simple PHP file upload vulnerability',
      sessionId: 'test-session-docker-exec'
    }, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000 // 2 minutes
    });

    console.log('\n✅ API Response:');
    console.log(JSON.stringify(response.data, null, 2));

    if (response.data.challengeInfo) {
      console.log('\n🎉 SUCCESS! Challenge deployed with Docker exec approach');
      console.log(`   Challenge: ${response.data.challengeInfo.challengeName}`);
      console.log(`   Attacker IP: ${response.data.challengeInfo.attackerIP}`);
      console.log(`   Guacamole Connection ID: ${response.data.challengeInfo.guacamoleConnectionId}`);
      console.log('\n🌐 Access via: http://localhost:8080/guacamole/#/');
    }

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    if (error.response) {
      console.error('   Response:', error.response.data);
    }
    if (error.code === 'ETIMEDOUT') {
      console.error('   This should NOT happen with Docker exec approach!');
    }
  }
}

console.log('Starting test in 3 seconds...\n');
setTimeout(testGuacamoleConnection, 3000);
