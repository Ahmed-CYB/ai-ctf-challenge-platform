/**
 * Test Guacamole Agent
 * Quick test to verify the specialized Guacamole agent works correctly
 */

import { guacamoleAgent } from './agents/guacamole-agent.js';

async function testGuacamoleAgent() {
  console.log('🧪 Testing Guacamole Agent\n');

  try {
    // Test 1: Database connection
    console.log('Test 1: Testing database connection...');
    const connected = await guacamoleAgent.testConnection();
    if (!connected) {
      console.error('❌ Database connection failed');
      process.exit(1);
    }
    console.log('✅ Database connection successful\n');

    // Test 2: List existing connections
    console.log('Test 2: Listing existing connections...');
    await guacamoleAgent.listConnections();
    console.log('');

    // Test 3: Create test connection
    console.log('Test 3: Creating test connection...');
    const testConnection = await guacamoleAgent.createConnection({
      challengeName: 'test-agent-challenge',
      attackerIP: '172.22.0.100',
      username: 'kali',
      password: 'kali'
    });
    console.log('✅ Test connection created:', testConnection);
    console.log('');

    // Test 4: Update connection
    console.log('Test 4: Updating connection hostname...');
    const updated = await guacamoleAgent.updateConnection({
      connectionName: 'test-agent-challenge-ssh',
      hostname: '172.22.0.101'
    });
    console.log('✅ Connection updated:', updated);
    console.log('');

    // Test 5: List connections again
    console.log('Test 5: Listing connections after update...');
    await guacamoleAgent.listConnections();
    console.log('');

    // Test 6: Delete test connection
    console.log('Test 6: Cleaning up - deleting test connection...');
    await guacamoleAgent.deleteConnection('test-agent-challenge-ssh');
    console.log('✅ Test connection deleted\n');

    console.log('🎉 All tests passed! Guacamole Agent is working correctly.');

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run tests
testGuacamoleAgent();
