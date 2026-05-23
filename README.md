# Authentication API

![Go Version](https://img.shields.io/github/go-mod/go-version/gofiber/fiber)
![Fiber Version](https://img.shields.io/github/v/release/gofiber/fiber)
![GORM](https://img.shields.io/badge/GORM-1.21.12-orange)

This is an Authentication API built with Go and Fiber. It supports user sign-in, session refreshing, password reset, email verification, and user CRUD operations. The API is designed to be cross-platform using Docker.

## 🚀 Features

- ✨ **Sign-In**: Authenticate users with username and password.
- 🔄 **Session Refresh**: Refresh user sessions with refresh tokens.
- 🔒 **Password Reset**: Reset user passwords securely.
- 📧 **Email Verification**: Verify user email addresses.
- 🛠️ **User CRUD**: Create, read, update, and delete user information.

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Run (Docker)

```bash
git clone https://github.com/ArnoldPMolenaar/api-auth.git
cd api-auth
docker-compose up dev --build
```

API default: `http://localhost:5001`

## API Routes

### Machine-protected routes

- `POST /v1/apps`
- `POST /v1/sign-up`
- `POST /v1/refresh-token`
- `GET /v1/user/recipes`
- `GET /v1/user/username/available`
- `GET /v1/user/email/available`
- `GET /v1/user/phone-number/available`
- `POST /v1/username-password/sign-in`
- `POST /v1/token/password`

### JWT-protected routes

- `GET /v1/token`
- `GET /v1/token/verify`
- `GET /v1/token/refresh`
- `POST /v1/token/email`
- `POST /v1/token/app`
- `POST /v1/sign-out`
- `GET /v1/user`
- `PATCH /v1/user`
- `PATCH /v1/user/password`
- `GET /v1/users`
- `POST /v1/users`
- `GET /v1/users/lookup`
- `GET /v1/users/:id`
- `PATCH /v1/users/:id`
- `DELETE /v1/users/:id`
- `POST /v1/users/:id/restore`

### Password token routes

- `GET /v1/token/password/verify`
- `POST /v1/token/password/reset`

### Email token routes
- `GET /v1/token/email/verify`
- `POST /v1/token/email/verification`

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📝 License

This project is licensed under the MIT License.

## 📞 Contact

For any questions or support, please contact [arnold.molenaar@webmi.nl](mailto:arnold.molenaar@webmi.nl).
<hr> Made with ❤️ by Arnold Molenaar
