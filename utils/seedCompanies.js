const Company = require('../models/Company');

// Initial companies data
const initialCompanies = [
  {
    name: 'Saudi Aramco',
    domain_name: 'aramco.com'
  },
  {
    name: 'Abu Dhabi National Oil Company',
    domain_name: 'adnoc.ae'
  },
  {
    name: 'Qatar Terminal',
    domain_name: 'qtm.com.qa'
  },
  {
    name: 'Petroleum Development Oman',
    domain_name: 'pdo.co.om'
  },
  {
    name: 'DNV',
    domain_name: 'dnv.com'
  },
  {
    name: 'Saher Flow Solutions',
    domain_name: 'saherflow.com'
  }
];

const seedCompanies = async () => {
  try {
    // Check if companies already exist
    const existingCompanies = await Company.findAll();
    
    if (existingCompanies.length > 0) {
      console.log('Companies already exist in database. Skipping seed.');
      return;
    }

    // Insert initial companies
    for (const companyData of initialCompanies) {
      await Company.create(companyData);
    }
    
    console.log('✅ Initial companies seeded successfully');
    
    // Log the seeded companies
    const companies = await Company.findAll();
    console.log('\n📋 Approved companies and domains:');
    companies.forEach(company => {
      console.log(`  • ${company.name}: ${company.domain_name}`);
    });
    console.log('');
    
  } catch (error) {
    console.error('❌ Error seeding companies:', error);
    throw error;
  }
};

module.exports = seedCompanies;