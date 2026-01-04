/**
 * Test script for Guacamole automation
 * This demonstrates how to automatically create users and connections
 * for CTF challenges
 */

import GuacamolePostgreSQLManager from './src/guacamole-postgresql-manager.js';
import dotenv from 'dotenv';

dotenv.config();

async function testAutomation() {
  console.log('🧪 Testing Guacamole Automation\n');
  
  const guacManager = new GuacamolePostgreSQLManager();

  try {
    // Simulate a user deploying a CTF challenge
    const testSession = {
      sessionId: 'test-session-123',
      challengeName: 'sql-injection-lab',
      attackerIP: '172.20.0.5', // This would come from your Docker deployment
      userId: 1,
      username: 'testuser',
      email: 'testuser@example.com'
    };

    console.log('📝 Test Scenario:');
    console.log(`   User: ${testSession.username}`);
    console.log(`   Challenge: ${testSession.challengeName}`);
    console.log(`   Container IP: ${testSession.attackerIP}\n`);

    // Step 1: Create mock user in HackyTalk database (if not exists)
    console.log('Step 1: Setting up test user in HackyTalk database...');
    await setupTestUser(guacManager, testSession);

    // Step 2: Create Guacamole user and connection
    console.log('\nStep 2: Creating Guacamole user and connection...');
    const result = await guacManager.createUserWithConnection(
      testSession.sessionId,
      testSession.challengeName,
      testSession.attackerIP
    );

    console.log('\n✅ Automation Complete!');
    console.log('━'.repeat(60));
    console.log('📋 Generated Credentials:');
    console.log(`   Guacamole Username: ${result.guacUsername}`);
    console.log(`   Password: ${result.password}`);
    console.log(`   Connection ID: ${result.connectionId}`);
    console.log(`   Connection Name: ${result.connectionName}`);
    console.log(`   Target: VNC to ${result.attackerIP}:5901`);
    console.log('━'.repeat(60));

    // Step 3: Generate direct access URL
    console.log('\nStep 3: Generating direct access URL...');
    const accessUrl = await guacManager.generateDirectAccessURL(
      testSession.sessionId,
      result.connectionId
    );

    console.log(`\n🔗 Direct Access URL:`);
    console.log(`   ${accessUrl}`);

    console.log('\n💡 How this works:');
    console.log('   1. User creates a CTF challenge');
    console.log('   2. System automatically creates Guacamole user');
    console.log('   3. System creates VNC connection to their Kali container');
    console.log('   4. User gets a direct link to access their challenge');
    console.log('   5. When challenge is deleted, Guacamole user is removed');

    console.log('\n🧹 Cleaning up test data...');
    await guacManager.removeUserAndConnection(
      testSession.challengeName,
      testSession.sessionId
    );

    console.log('✅ Test cleanup complete!');

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await guacManager.close();
  }
}

/**
 * Setup test user in HackyTalk database
 */
async function setupTestUser(guacManager, testSession) {
  try {
    // Check if test user exists
    const existingUser = await guacManager.hackyTalkPool.query(
      'SELECT user_id FROM users WHERE user_id = $1',
      [testSession.userId]
    );

    if (existingUser.rows.length === 0) {
      console.log('   Creating test user in HackyTalk database...');
      await guacManager.hackyTalkPool.query(
        `INSERT INTO users (user_id, username, email, password_hash, created_at)
         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
         ON CONFLICT (user_id) DO NOTHING`,
        [testSession.userId, testSession.username, testSession.email, 'test-hash']
      );
      console.log('   ✅ Test user created');
    } else {
      console.log('   ✅ Test user already exists');
    }

    // Create or update session
    await guacManager.hackyTalkPool.query(
      `INSERT INTO sessions (session_id, user_id, created_at, is_active)
       VALUES ($1, $2, CURRENT_TIMESTAMP, true)
       ON CONFLICT (session_id) DO UPDATE 
       SET last_activity = CURRENT_TIMESTAMP, is_active = true`,
      [testSession.sessionId, testSession.userId]
    );
    console.log('   ✅ Test session created');

    // Ensure guacamole_auth_tokens table exists
    await guacManager.hackyTalkPool.query(`
      CREATE TABLE IF NOT EXISTS guacamole_auth_tokens (
        session_id VARCHAR(255) NOT NULL,
        connection_id INTEGER NOT NULL,
        token VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (session_id, connection_id)
      )
    `);
    console.log('   ✅ Auth tokens table ready');

  } catch (error) {
    console.error('   ⚠️  Setup warning:', error.message);
  }
}

// Run the test
testAutomation();
