# Saher Flow Solutions Backend API

A complete authentication backend built with Express.js, MongoDB, and JWT tokens.

## Features

- User registration with email verification
- Live email validation with DNS checking
- Two-Factor Authentication (2FA) with TOTP
- Backup codes for 2FA recovery
- User login/logout
- Password reset functionality
- JWT-based authentication
- Role-based access control (User/Admin)
- Profile management
- Email notifications
- Input validation and sanitization
- Security best practices

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Environment Variables:**
   Create a `.env` file in the root directory with the following variables:
   ```
   PORT=5000
   MONGODB_URI=mongodb+srv://your-username:your-password@cluster0.mongodb.net/saher-flow-solutions?retryWrites=true&w=majority
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   JWT_EXPIRE=7d
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   CLIENT_URL=http://localhost:5173
   ```

   **Note**: For email validation to work properly, ensure your server has internet access for DNS lookups.

3. **Database Setup:**
   
   **Option A: MongoDB Atlas (Recommended for development)**
   1. Create a free account at [MongoDB Atlas](https://www.mongodb.com/atlas)
   2. Create a new cluster
   3. Create a database user
   4. Get your connection string and update `MONGODB_URI` in `.env`
   
   **Option B: Local MongoDB**
   1. Install MongoDB on your system
   2. Start the MongoDB service
   3. Use: `MONGODB_URI=mongodb://localhost:27017/saher-flow-solutions`

4. **Run the server:**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## API Endpoints

### Authentication Routes (`/api/auth`)

- `POST /register` - Register a new user
- `POST /login` - Login user
- `GET /verify-email/:token` - Verify email address
- `POST /forgot-password` - Request password reset
- `PUT /reset-password/:token` - Reset password
- `POST /validate-email` - Validate email address (live check)
- `POST /setup-2fa` - Setup Two-Factor Authentication
- `POST /verify-2fa` - Verify and enable 2FA
- `POST /disable-2fa` - Disable 2FA
- `POST /generate-backup-codes` - Generate new backup codes
- `GET /me` - Get current user (Protected)
- `POST /logout` - Logout user (Protected)

### User Routes (`/api/user`)

- `PUT /profile` - Update user profile (Protected)
- `PUT /change-password` - Change password (Protected)
- `DELETE /account` - Deactivate account (Protected)
- `GET /all` - Get all users (Admin only)
- `GET /companies` - Get all companies (Admin only)

### Company Routes (`/api/company`)

- `GET /` - Get all active companies (Public)
- `GET /:id` - Get company by ID (Admin only)
- `POST /` - Create new company (Admin only)
- `PUT /:id` - Update company (Admin only)
- `DELETE /:id` - Deactivate company (Admin only)
- `GET /check-domain/:domain` - Check if domain is allowed (Public)

### Health Check

- `GET /api/health` - API health check

## Request/Response Examples

### Create Company (Admin only)
```bash
POST /api/company
Authorization: Bearer <admin-jwt-token>
Content-Type: application/json

{
  "name": "Example Corp",
  "domains": ["example.com", "example.org"],
  "description": "Example company description",
  "contactEmail": "admin@example.com"
}
```

### Check Domain
```bash
GET /api/company/check-domain/example.com
```

### Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "company": "Tech Corp",
  "password": "Password123"
}
```

### Login User
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "Password123"
}
```

### Setup 2FA
```bash
POST /api/auth/setup-2fa
Authorization: Bearer <jwt-token>
```

### Verify 2FA Token
```bash
POST /api/auth/verify-2fa
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "token": "123456"
}
```

### Login with 2FA
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password",
  "twoFactorToken": "123456"
}
```

### Validate Email
```bash
POST /api/auth/validate-email
Content-Type: application/json

{
  "email": "user@example.com"
}
```

### Protected Routes
Include the JWT token in the Authorization header:
```bash
Authorization: Bearer <your-jwt-token>
```

## Security Features

- Password hashing with bcrypt
- Two-Factor Authentication (TOTP)
- Live email validation with DNS checking
- Disposable email blocking
- Backup codes for 2FA recovery
- JWT token authentication
- Input validation and sanitization
- Rate limiting ready
- CORS configuration
- Email verification
- Password reset with time-limited tokens
- Role-based access control

## Database Schema

### Company Model
- name (String, required, unique)
- domains (Array of Strings, required)
- isActive (Boolean, default: true)
- description (String, optional)
- contactEmail (String, optional)
- createdAt (Date)
- updatedAt (Date)

### User Model
- firstName (String, required)
- lastName (String, required)
- email (String, required, unique)
- company (String, required)
- password (String, required, hashed)
- role (String, enum: ['user', 'admin'])
- isEmailVerified (Boolean)
- emailVerificationToken (String)
- emailVerificationExpires (Date)
- passwordResetToken (String)
- passwordResetExpires (Date)
- lastLogin (Date)
- isActive (Boolean)
- createdAt (Date)
- updatedAt (Date)
- twoFactorSecret (String, encrypted)
- twoFactorEnabled (Boolean)
- twoFactorBackupCodes (Array)
- emailValidated (Boolean)

## Email Configuration

The API uses Nodemailer for sending emails. Configure your email provider in the `.env` file:

For Gmail:
1. Enable 2-factor authentication
2. Generate an app password
3. Use the app password in `EMAIL_PASS`

## Two-Factor Authentication

The API supports TOTP-based 2FA using authenticator apps like:
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any TOTP-compatible app

### 2FA Setup Process:
1. User calls `/api/auth/setup-2fa` to get QR code
2. User scans QR code with authenticator app
3. User calls `/api/auth/verify-2fa` with token to enable 2FA
4. System generates backup codes for recovery

### 2FA Login Process:
1. User provides email/password
2. If 2FA enabled, system requests 2FA token
3. User provides TOTP token or backup code
4. System validates and completes login

## Error Handling

The API returns consistent error responses:
```json
{
  "success": false,
  "message": "Error description",
  "errors": [] // Validation errors if any
}
```

## Success Responses

Success responses follow this format:
```json
{
  "success": true,
  "message": "Success message",
  "data": {
    // Response data
  }
}
```