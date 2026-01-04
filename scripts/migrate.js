const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Get project root (parent of scripts directory)
const scriptDir = __dirname;
const projectRoot = path.resolve(scriptDir, '..');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform';
const migrationsDir = path.join(projectRoot, 'database', 'migrations');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: false,
});

async function migrate() {
  console.log('🔄 Starting database migrations...');
  console.log(`📁 Migrations directory: ${migrationsDir}`);
  
  try {
    // Create migrations table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description TEXT
      )
    `);
    console.log('✅ Migrations table ready');

    // Get applied migrations
    const appliedResult = await pool.query('SELECT version FROM schema_migrations ORDER BY applied_at');
    const appliedVersions = new Set(appliedResult.rows.map(r => r.version));
    console.log(`📋 Found ${appliedVersions.size} applied migrations`);

    // Get all migration files
    if (!fs.existsSync(migrationsDir)) {
      console.log(`⚠️  Migrations directory does not exist: ${migrationsDir}`);
      return;
    }

    const files = fs.readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    console.log(`📦 Found ${files.length} migration files`);

    // Apply pending migrations
    let appliedCount = 0;
    for (const file of files) {
      const version = file.replace('.sql', '');
      
      if (appliedVersions.has(version)) {
        console.log(`⏭️  Skipping ${file} (already applied)`);
        continue;
      }

      console.log(`🔄 Applying migration: ${file}`);
      
      try {
        const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf-8');
        
        // Execute migration in a transaction
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query(sql);
          await client.query(
            'INSERT INTO schema_migrations (version, description) VALUES ($1, $2)',
            [version, `Migration from ${file}`]
          );
          await client.query('COMMIT');
          appliedCount++;
          console.log(`✅ Applied ${file}`);
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        } finally {
          client.release();
        }
      } catch (err) {
        console.error(`❌ Failed to apply ${file}:`, err.message);
        throw err;
      }
    }

    console.log(`\n✅ Migration complete! Applied ${appliedCount} new migration(s)`);
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Run migrations
migrate().catch(console.error);
