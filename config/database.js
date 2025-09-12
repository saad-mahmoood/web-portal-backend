const { Pool } = require('pg');

class Database {
  constructor() {
    this.pool = null;
  }

  async connect() {
    try {
      if (!process.env.DATABASE_URL) {
        throw new Error('DATABASE_URL environment variable is not defined');
      }

      this.pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      });

      // Test connection
      const client = await this.pool.connect();
      console.log('Connected to PostgreSQL');
      client.release();

      // Initialize database schema
      await this.initializeSchema();
    } catch (error) {
      console.error('Database connection error:', error.message || error);
      console.log('\n📋 To fix this error:');
      console.log('1. Set up a PostgreSQL database');
      console.log('2. Set DATABASE_URL in your .env file');
      console.log('3. Restart the server');
      throw error;
    }
  }

  async initializeSchema() {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Create company table
      await client.query(`
        CREATE TABLE IF NOT EXISTS company (
          id BIGSERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          domain_name TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      // Create user table
      await client.query(`
        CREATE TABLE IF NOT EXISTS "user" (
          id BIGSERIAL PRIMARY KEY,
          company_id BIGINT NOT NULL REFERENCES company(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          is_email_verified BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ,
          is_active BOOLEAN DEFAULT TRUE,
          last_login_time TIMESTAMPTZ,
          last_login_ip INET,
          allowed_ip_list INET[]
        )
      `);

      // Add additional fields for authentication
      await client.query(`
        ALTER TABLE "user" 
        ADD COLUMN IF NOT EXISTS password_hash TEXT,
        ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user',
        ADD COLUMN IF NOT EXISTS email_verification_token TEXT,
        ADD COLUMN IF NOT EXISTS email_verification_expires TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS password_reset_token TEXT,
        ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS two_factor_secret TEXT,
        ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS two_factor_backup_codes JSONB,
        ADD COLUMN IF NOT EXISTS email_validated BOOLEAN DEFAULT FALSE
      `);

      // Create indexes
      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);
        CREATE INDEX IF NOT EXISTS idx_user_company_id ON "user"(company_id);
        CREATE INDEX IF NOT EXISTS idx_company_domain ON company(domain_name);
      `);

      await client.query('COMMIT');
      console.log('Database schema initialized');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async query(text, params) {
    const client = await this.pool.connect();
    try {
      const result = await client.query(text, params);
      return result;
    } finally {
      client.release();
    }
  }

  async transaction(callback) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async disconnect() {
    if (this.pool) {
      await this.pool.end();
      console.log('Database disconnected');
    }
  }
}

module.exports = new Database();