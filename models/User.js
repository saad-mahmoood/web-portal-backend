const database = require('../config/database');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const speakeasy = require('speakeasy');

class User {
  constructor(data = {}) {
    this.id = data.id;
    this.company_id = data.company_id;
    this.name = data.name;
    this.email = data.email;
    this.password_hash = data.password_hash;
    this.role = data.role || 'user';
    this.is_email_verified = data.is_email_verified || false;
    this.created_at = data.created_at;
    this.updated_at = data.updated_at;
    this.is_active = data.is_active !== undefined ? data.is_active : true;
    this.last_login_time = data.last_login_time;
    this.last_login_ip = data.last_login_ip;
    this.allowed_ip_list = data.allowed_ip_list;
    this.email_verification_token = data.email_verification_token;
    this.email_verification_expires = data.email_verification_expires;
    this.password_reset_token = data.password_reset_token;
    this.password_reset_expires = data.password_reset_expires;
    this.two_factor_secret = data.two_factor_secret;
    this.two_factor_enabled = data.two_factor_enabled || false;
    this.two_factor_backup_codes = data.two_factor_backup_codes;
    this.email_validated = data.email_validated || false;
  }

  static async create(userData) {
    const { company_id, name, email, password, role = 'user' } = userData;

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(password, salt);

    const query = `
      INSERT INTO "user" (company_id, name, email, password_hash, role, updated_at)
      VALUES ($1, $2, $3, $4, $5, now())
      RETURNING *
    `;
    
    const result = await database.query(query, [company_id, name, email, password_hash, role]);
    return new User(result.rows[0]);
  }

  static async findById(id, includePassword = false) {
    let query = 'SELECT * FROM "user" WHERE id = $1';
    if (!includePassword) {
      query = 'SELECT id, company_id, name, email, role, is_email_verified, created_at, updated_at, is_active, last_login_time, last_login_ip, allowed_ip_list, email_verification_token, email_verification_expires, password_reset_token, password_reset_expires, two_factor_enabled, two_factor_backup_codes, email_validated FROM "user" WHERE id = $1';
    }
    
    const result = await database.query(query, [id]);
    return result.rows[0] ? new User(result.rows[0]) : null;
  }

  static async findByEmail(email, includePassword = false) {
    let query = 'SELECT * FROM "user" WHERE email = $1';
    if (!includePassword) {
      query = 'SELECT id, company_id, name, email, role, is_email_verified, created_at, updated_at, is_active, last_login_time, last_login_ip, allowed_ip_list, email_verification_token, email_verification_expires, password_reset_token, password_reset_expires, two_factor_enabled, two_factor_backup_codes, email_validated FROM "user" WHERE email = $1';
    }
    
    const result = await database.query(query, [email]);
    return result.rows[0] ? new User(result.rows[0]) : null;
  }

  static async findAll(page = 1, limit = 20, adminView = false) {
    const offset = (page - 1) * limit;
    
    let selectFields = 'u.id, u.company_id, u.name, u.email, u.role, u.is_email_verified, u.is_active, c.name as company_name';
    if (adminView) {
      selectFields += ', u.created_at, u.updated_at, u.last_login_time, u.last_login_ip';
    }
    
    const query = `
      SELECT ${selectFields}
      FROM "user" u
      LEFT JOIN company c ON u.company_id = c.id
      WHERE u.is_active = true
      ORDER BY u.created_at DESC
      LIMIT $1 OFFSET $2
    `;
    
    const countQuery = 'SELECT COUNT(*) FROM "user" WHERE is_active = true';
    
    const [result, countResult] = await Promise.all([
      database.query(query, [limit, offset]),
      database.query(countQuery)
    ]);
    
    return {
      users: result.rows.map(row => ({
        id: row.id,
        company_id: row.company_id,
        name: row.name,
        email: row.email,
        role: row.role,
        is_email_verified: row.is_email_verified,
        is_active: row.is_active,
        company_name: row.company_name,
        ...(adminView && {
          created_at: row.created_at,
          updated_at: row.updated_at,
          last_login_time: row.last_login_time,
          last_login_ip: row.last_login_ip
        })
      })),
      total: parseInt(countResult.rows[0].count)
    };
  }

  static async update(id, updateData) {
    const allowedFields = ['name', 'email', 'role', 'is_email_verified', 'is_active'];
    const updates = [];
    const values = [];
    let paramCount = 1;

    Object.keys(updateData).forEach(key => {
      if (allowedFields.includes(key)) {
        updates.push(`${key} = $${paramCount + 1}`);
        values.push(updateData[key]);
        paramCount++;
      }
    });

    if (updates.length === 0) {
      throw new Error('No valid fields to update');
    }

    updates.push(`updated_at = now()`);
    values.unshift(id);

    const query = `
      UPDATE "user" 
      SET ${updates.join(', ')}
      WHERE id = $1
      RETURNING *
    `;
    
    const result = await database.query(query, values);
    return result.rows[0] ? new User(result.rows[0]) : null;
  }

  static async delete(id) {
    const query = 'DELETE FROM "user" WHERE id = $1 RETURNING *';
    const result = await database.query(query, [id]);
    return result.rows[0] ? new User(result.rows[0]) : null;
  }

  async comparePassword(candidatePassword) {
    if (!this.password_hash) {
      throw new Error('Password hash not loaded');
    }
    return await bcrypt.compare(candidatePassword, this.password_hash);
  }

  async updatePassword(newPassword) {
    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(newPassword, salt);
    
    const query = 'UPDATE "user" SET password_hash = $1, updated_at = now() WHERE id = $2';
    await database.query(query, [password_hash, this.id]);
    this.password_hash = password_hash;
  }

  generateEmailVerificationToken() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    this.email_verification_token = hashedToken;
    this.email_verification_expires = expires;
    
    return resetToken;
  }

  generatePasswordResetToken() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    this.password_reset_token = hashedToken;
    this.password_reset_expires = expires;
    
    return resetToken;
  }

  generate2FASecret() {
    const secret = speakeasy.generateSecret({
      name: `Saher Flow Solutions (${this.email})`,
      issuer: 'Saher Flow Solutions',
      length: 32
    });
    
    this.two_factor_secret = secret.base32;
    return secret;
  }

  verify2FAToken(token) {
    if (!this.two_factor_secret) {
      return false;
    }
    
    const cleanToken = token.toString().replace(/\D/g, '');
    
    if (cleanToken.length !== 6) {
      return false;
    }
    
    return speakeasy.totp.verify({
      secret: this.two_factor_secret,
      encoding: 'base32',
      token: cleanToken,
      window: 2,
      step: 30
    });
  }

  generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      codes.push({
        code: crypto.randomBytes(4).toString('hex').toUpperCase(),
        used: false
      });
    }
    this.two_factor_backup_codes = codes;
    return codes.map(c => c.code);
  }

  verifyBackupCode(code) {
    if (!this.two_factor_backup_codes) return false;
    
    const backupCode = this.two_factor_backup_codes.find(
      bc => bc.code === code.toUpperCase() && !bc.used
    );
    
    if (backupCode) {
      backupCode.used = true;
      return true;
    }
    return false;
  }

  async save() {
    const query = `
      UPDATE "user" 
      SET email_verification_token = $1,
          email_verification_expires = $2,
          password_reset_token = $3,
          password_reset_expires = $4,
          two_factor_secret = $5,
          two_factor_enabled = $6,
          two_factor_backup_codes = $7,
          is_email_verified = $8,
          email_validated = $9,
          last_login_time = $10,
          last_login_ip = $11,
          updated_at = now()
      WHERE id = $12
      RETURNING *
    `;
    
    const result = await database.query(query, [
      this.email_verification_token,
      this.email_verification_expires,
      this.password_reset_token,
      this.password_reset_expires,
      this.two_factor_secret,
      this.two_factor_enabled,
      this.two_factor_backup_codes ? JSON.stringify(this.two_factor_backup_codes) : null,
      this.is_email_verified,
      this.email_validated,
      this.last_login_time,
      this.last_login_ip,
      this.id
    ]);
    
    if (result.rows[0]) {
      Object.assign(this, result.rows[0]);
    }
  }

  // For compatibility with frontend
  toJSON() {
    const json = {
      _id: this.id,
      id: this.id,
      firstName: this.name.split(' ')[0] || this.name,
      lastName: this.name.split(' ').slice(1).join(' ') || '',
      name: this.name,
      email: this.email,
      company: this.company_name || '',
      company_id: this.company_id,
      role: this.role,
      isEmailVerified: this.is_email_verified,
      isActive: this.is_active,
      twoFactorEnabled: this.two_factor_enabled,
      emailValidated: this.email_validated
    };

    // Only include sensitive fields for admin users
    if (this.role === 'admin') {
      json.createdAt = this.created_at;
      json.updatedAt = this.updated_at;
      json.lastLogin = this.last_login_time;
      json.lastLoginIP = this.last_login_ip;
    }

    return json;
  }
}

module.exports = User;