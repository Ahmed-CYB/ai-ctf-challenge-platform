// Test the Guacamole create-user API
import fetch from 'node-fetch';

async function testCreateUser() {
  console.log('\n=== Testing Guacamole Create User API ===\n');
  
  try {
    const response = await fetch('http://localhost:3003/api/guacamole/create-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: 'testplayer',
        password: 'TestPass2025!',
        email: 'player@ctf.local',
        fullName: 'Test Player'
      })
    });

    const data = await response.json();
    
    if (data.success) {
      console.log('✅ User created successfully!\n');
      console.log('Username:', data.user.username);
      console.log('Entity ID:', data.user.entityId);
      console.log('User ID:', data.user.userId);
      console.log('\nLogin Information:');
      console.log('URL:', data.loginInfo.url);
      console.log('Username:', data.loginInfo.username);
      console.log('Password:', data.loginInfo.password);
      
      return data;
    } else {
      console.log('❌ Failed to create user:', data.error);
    }
  } catch (error) {
    console.log('❌ Error:', error.message);
  }
}

testCreateUser();
