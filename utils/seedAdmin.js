const User = require('../models/User');
const Company = require('../models/Company');

const createAdminUser = async () => {
  try {
    // Check if admin already exists
    const existingAdmin = await User.findByEmail('admin@saherflow.com');
    
    if (existingAdmin) {
      console.log('Admin user already exists');
      return;
    }

    // Find or create Saher Flow Solutions company
    let company = await Company.findByDomain('saherflow.com');
    if (!company) {
      company = await Company.create({
        name: 'Saher Flow Solutions',
        domain_name: 'saherflow.com'
      });
    }

    // Create admin user
    const adminUser = await User.create({
      company_id: company.id,
      name: 'Admin User',
      email: 'admin@saherflow.com',
      password: 'Admin123',
      role: 'admin'
    });

    // Mark as verified
    const query = 'UPDATE "user" SET is_email_verified = true, email_validated = true WHERE id = $1';
    await require('../config/database').query(query, [adminUser.id]);

    console.log('✅ Admin user created successfully');
    console.log('📧 Email: admin@saherflow.com');
    console.log('🔑 Password: Admin123');
    console.log('');
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
  }
};

module.exports = createAdminUser;