const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const scriptDir = __dirname;
const projectRoot = path.resolve(scriptDir, '..');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform';
const schemaFile = path.join(projectRoot, 'database', 'schema.sql');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: false,
});

async function resetDatabase() {
  console.log('🔄 Resetting database...');
  
  try {
    // Read schema file
    if (!fs.existsSync(schemaFile)) {
      console.error(`❌ Schema file not found: ${schemaFile}`);
      process.exit(1);
    }

    const schema = fs.readFileSync(schemaFile, 'utf-8');
    
    // Execute schema
    console.log('📝 Executing schema...');
    await pool.query(schema);
    
    // Clear migrations table
    console.log('🗑️  Clearing migrations history...');
    await pool.query('TRUNCATE TABLE schema_migrations');
    
    console.log('✅ Database reset complete!');
    console.log('💡 Run "npm run db:migrate" to apply migrations');
  } catch (error) {
    console.error('❌ Database reset failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Confirm before resetting (only in interactive mode)
if (process.argv.includes('--force') || process.env.FORCE_RESET === 'true') {
  resetDatabase();
} else {
  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });

  readline.question('⚠️  This will DELETE ALL DATA. Are you sure? (yes/no): ', answer => {
    if (answer.toLowerCase() === 'yes') {
      resetDatabase();
    } else {
      console.log('❌ Reset cancelled');
      process.exit(0);
    }
    readline.close();
  });
}
