/**
 * Test Claude SQL Validator
 * This will test the Claude-powered SQL validation before executing MySQL commands
 */

import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

async function testSQLValidation(sql) {
  console.log(`\n🧪 Testing SQL: ${sql}\n`);
  
  try {
    const message = await anthropic.messages.create({
      model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      messages: [{
        role: 'user',
        content: `You are a MySQL syntax validator. Analyze this SQL query for a MySQL 8.0 database and respond ONLY with a JSON object (no markdown, no explanation):

SQL Query:
${sql}

Context:
- This will be executed via: docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "QUERY" -sN
- The query is wrapped in double quotes in the shell command
- Single quotes inside the query work fine
- Table: guacamole_entity (columns: entity_id, name, type)
- Table: guacamole_connection (columns: connection_id, connection_name, protocol, max_connections)

Respond with JSON only:
{
  "valid": true/false,
  "correctedSql": "the corrected SQL if needed, or original if valid",
  "issues": "explanation of any syntax errors, or empty string if valid"
}`
      }]
    });

    const response = message.content[0].text.trim();
    console.log('📝 Claude Response:\n', response);
    
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const result = JSON.parse(jsonMatch[0]);
      console.log('\n✅ Parsed Result:');
      console.log('   Valid:', result.valid);
      console.log('   Issues:', result.issues || 'None');
      console.log('   Corrected SQL:', result.correctedSql);
      return result;
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Test 1: Valid SQL (same as manual command that worked)
console.log('='.repeat(80));
console.log('TEST 1: Valid SQL (Simple INSERT)');
console.log('='.repeat(80));
await testSQLValidation("INSERT INTO guacamole_connection (connection_name, protocol, max_connections) VALUES ('test-challenge', 'ssh', 5)");

// Test 2: SQL with potential escaping issues
console.log('\n' + '='.repeat(80));
console.log('TEST 2: SQL with hyphens in values');
console.log('='.repeat(80));
await testSQLValidation("INSERT INTO guacamole_entity (name, type) VALUES ('guacadmin-test-challenge', 'USER')");

// Test 3: Invalid SQL
console.log('\n' + '='.repeat(80));
console.log('TEST 3: Invalid SQL (missing VALUES)');
console.log('='.repeat(80));
await testSQLValidation("INSERT INTO guacamole_connection (connection_name, protocol) 'broken-sql', 'ssh'");

console.log('\n✅ All tests complete!');
