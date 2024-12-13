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

### 🛠️ Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/ArnoldPMolenaar/api-auth.git
    cd api-auth
    ```

2. Build and run the Docker containers:

    ```bash
    docker-compose up dev --build
    ```

3. The API will be available at `http://localhost:5001`.

## 🧑‍💻 API Endpoints

### User Authentication

- **Sign-Up**: `POST /v1/sign-up`
    - Register a new user.
    - Request body: `{ "username": "user", "email": "user@example.com", "password": "password" }`

- **Sign-In**: `POST /v1/username-password/sign-in`
    - Authenticate a user with username and password.
    - Request body: `{ "username": "user", "password": "password" }`

- **Refresh Token**: `POST /v1/refresh-token`
    - Refresh the user session with a refresh token.
    - Request body: `{ "refresh_token": "token" }`

### Password Management

- **Password Reset**: `POST /v1/token/password`
    - Reset the user password.
    - Request body: `{ "email": "user@example.com" }`

### Email Verification

- **Verify Email**: `POST /v1/verify-email`
    - Verify the user's email address.
    - Request body: `{ "user_id": 1, "email": "user@example.com" }`

### User Management

- **Get User Recipes**: `GET /v1/user/recipes`
    - Get recipes associated with the user.
    - Request parameters: `username`

- **Update User**: `PUT /v1/user`
    - Update user information.
    - Request body: `{ "username": "newuser", "email": "newuser@example.com", "phone_number": "1234567890" }`

- **Delete User**: `DELETE /v1/user`
    - Delete a user.
    - Request parameters: `user_id`

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📝 License

This project is licensed under the MIT License.

## 📞 Contact

For any questions or support, please contact [arnold.molenaar@webmi.nl](mailto:arnold.molenaar@webmi.nl).
<hr></hr> Made with ❤️ by Arnold Molenaar