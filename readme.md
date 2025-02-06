# Modern Express Template

A robust and secure backend application template built with Express.js, MongoDB, and TypeScript, featuring comprehensive authentication and authorization systems.

## 🚀 Features

- **Authentication & Authorization**
  - JWT-based authentication with access and refresh tokens
  - Role-based access control
  - Account lockout protection
  - Password reset functionality
  - Email verification
  - Secure password hashing

- **Security Measures**
  - Rate limiting
  - CORS protection
  - Helmet security headers
  - Request validation
  - MongoDB injection protection
  - Secure error handling

- **Architecture**
  - TypeScript for type safety
  - Clean architecture principles
  - Modular project structure
  - Comprehensive error handling
  - Request validation using Zod
  - Detailed logging system

## 📋 Prerequisites

- Node.js (v16 or higher)
- MongoDB (v4.4 or higher)
- TypeScript knowledge
- npm or yarn package manager

## 🛠️ Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure-express-backend
```

2. Install dependencies:
```bash
npm install
```

3. Create environment file:
```bash
cp .env.example .env
```

4. Configure environment variables:
```env
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/your_database
JWT_ACCESS_SECRET=your_jwt_access_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_email
SMTP_PASS=your_password
```

## 🚀 Running the Application

### Development
```bash
npm run dev
```

### Production
```bash
npm run build
npm start
```

## 📁 Project Structure

```
src/
├── config/          # Configuration files
├── middleware/      # Public Reusable Middlewares
├── modules          # Contains all the modules(self isolated services, controllers, routes and models)
├── routes/          # Main routes
├── utils/           # Utility functions
├── types/          # TypeScript type definitions
├── app.ts          # Express app setup
└── server.ts       # Application entry point
```

## 🔒 API Endpoints

### Authentication
```
POST /api/auth/register           # Register new user
POST /api/auth/login              # Login user
POST /api/auth/refresh           # Refresh access token
POST /api/auth/forgot-password   # Request password reset
POST /api/auth/reset-password    # Reset password
POST /api/auth/verify-email      # Verify email
```

### Users
```
GET    /api/users/profile        # Get user profile
PUT    /api/users/profile        # Update user profile
```

## 🔐 Security Features

1. **Password Security**
   - Passwords are hashed using bcrypt
   - Minimum password requirements enforced
   - Password reset with expiring tokens

2. **Authentication**
   - JWT with access and refresh tokens
   - Token expiration and rotation
   - Account lockout after failed attempts

3. **Request Security**
   - Input validation
   - Rate limiting
   - CORS protection
   - Security headers

## 🧪 Testing

Run the test suite:
```bash
npm test
```

Run tests with coverage:
```bash
npm run test:coverage
```

## 📝 Error Handling

The application includes a comprehensive error handling system:
- Custom error classes for different scenarios
- Structured error responses
- Detailed logging in development
- Sanitized errors in production

## 🛡️ Middleware

1. **Authentication Middleware**
   - Token validation
   - Role-based access control
   - User session management

2. **Security Middleware**
   - Rate limiting
   - CORS configuration
   - Helmet security headers

## 📦 Dependencies

Core dependencies:
- `express`: Web framework
- `mongodb`: MongoDB driver
- `jsonwebtoken`: JWT implementation
- `bcryptjs`: Password hashing
- `zod`: Schema validation
- `pino`: Logging

Development dependencies:
- `typescript`: TypeScript compiler
- `ts-node`: TypeScript execution
- `jest`: Testing framework
- `nodemon`: Development server

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Express.js documentation
- MongoDB best practices
- TypeScript handbook
- Security best practices from OWASP

## 🆘 Support

For support, please create an issue in the repository or contact the maintainers.
