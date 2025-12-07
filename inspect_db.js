import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

async function run() {
  try {
    const conn = await mysql.createConnection({
      host: process.env.DB_HOST || '5.189.183.23',
      port: process.env.DB_PORT || 4567,
      user: process.env.DB_USER || 'dsak24-11',
      password: process.env.DB_PASSWORD || 'GSUFQ20228',
      database: process.env.DB_NAME || 'dsak24-11'
    });
    console.log('Connected to DB. Querying users...');
    const [rows] = await conn.execute('SELECT id, username, role FROM users LIMIT 10');
    console.log('Users (up to 10):', rows);
    await conn.end();
  } catch (err) {
    console.error('DB check failed:', err.message || err);
    process.exit(1);
  }
}

run();
