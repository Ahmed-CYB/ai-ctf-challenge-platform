const mysql = require('mysql2/promise');

async function test() {
  try {
    console.log('🔗 Connecting to MySQL...');
    const pool = mysql.createPool({
      host: 'localhost',
      port: 3306,
      user: 'guacamole_user',
      password: 'guacamole_pass',
      database: 'guacamole_db',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      connectTimeout: 15000
    });

    console.log('✅ Pool created, testing query...');
    const [rows] = await pool.query('SELECT 1 as test');
    console.log('✅ Query successful:', rows);
    
    await pool.end();
    console.log('✅ Connection test passed!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

test();
