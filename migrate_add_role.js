import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

async function run() {
  const cfg = {
    host: process.env.DB_HOST || '5.189.183.23',
    port: Number(process.env.DB_PORT || 4567),
    user: process.env.DB_USER || 'dsak24-11',
    password: process.env.DB_PASSWORD || 'GSUFQ20228',
    database: process.env.DB_NAME || 'dsak24-11'
  };

  console.log('Connecting to', cfg.host + ':' + cfg.port, 'db:', cfg.database);
  const conn = await mysql.createConnection(cfg);
  try {
    // Check if column exists
    const [cols] = await conn.execute("SHOW COLUMNS FROM users LIKE 'role'");
    if (cols && cols.length) {
      console.log('Column `role` already exists. No action needed.');
      return;
    }

    console.log('Adding `role` column to users table...');
    await conn.execute("ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'member'");
    console.log('Column added successfully.');
  } catch (err) {
    console.error('Failed to alter table:', err.message || err);
    process.exitCode = 1;
  } finally {
    await conn.end();
  }
}

run();
