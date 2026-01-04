const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform';

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: false,
});

async function seed() {
  console.log('🌱 Seeding database...');
  
  try {
    // Create demo user
    const passwordHash = await bcrypt.hash('demo123!', 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, name, avatar_animal_id, is_verified, is_active)
       VALUES ($1, $2, $3, $4, $5, TRUE, TRUE)
       ON CONFLICT (username) DO NOTHING
       RETURNING user_id, username, email`,
      ['demo', 'demo@ctf-platform.com', passwordHash, 'Demo User', 'lion']
    );
    
    if (result.rows.length > 0) {
      console.log('✅ Created demo user:');
      console.log('   Username: demo');
      console.log('   Email: demo@ctf-platform.com');
      console.log('   Password: demo123!');
    } else {
      console.log('ℹ️  Demo user already exists');
    }
    
    console.log('\n✅ Seeding complete!');
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

seed().catch(console.error);

