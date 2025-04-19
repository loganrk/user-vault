# UserVault - Secure User Authentication System

UserVault is a Go-based microservice that implements a complete user authentication system. It includes registration, login, logout, password reset, account activation, and refresh token validation, with secure password hashing and JWT-based token management.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Validation Rules](#validation-rules)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

## Features

- ✅ User Registration with Activation Email
- 🔐 Secure Password Hashing using bcrypt + salt
- 🔑 JWT Access and Refresh Token Authentication
- 🔁 Refresh Token Rotation and Validation
- 🧠 Rate Limiting on Failed Login Attempts
- 📧 Email-based Account Activation and Password Reset
- 📦 Hexagonal Architecture with Clean Adapter Separation
- 🧪 Validator-Based Input Validation (GET or POST)

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/loganrk/userVault
    cd userVault
    ```

2. Initialize dependencies:

    ```sh
    go mod tidy
    ```

3. Create a `.env` or config file with required credentials (DB, JWT secrets, etc.).

## Usage

Start the service:

```sh
go run main.go
```

## API Endpoints

### 📥 Authentication APIs

| Method   | Endpoint                    | Description                         |
|----------|-----------------------------|-------------------------------------|
| POST/GET | `/api/v1/login`             | User login                          |
| POST/GET | `/api/v1/register`          | Register user                       |
| POST/GET | `/api/v1/activate`          | Activate account with token         |
| POST/GET | `/api/v1/logout`            | Logout (invalidate refresh token)   |
| POST/GET | `/api/v1/forgot-password`   | Send password reset link            |
| POST/GET | `/api/v1/reset-password`    | Reset password using token          |
| POST/GET | `/api/v1/refresh-token`     | Validate and rotate refresh token   |
| POST/GET | `/api/v1/resend-activation` | Resend activation email             |

> 🔒 All routes support both `application/json` POST and query-based GET formats.

## Validation Rules

All request bodies are validated using `github.com/go-playground/validator/v10`.

Example:
```go
Username string `validate:"required,email"`
Password string `validate:"required,password"`
```

Custom `password` validation ensures:
- At least 8 characters
- Includes digit, lowercase, uppercase, and special character

## Project Structure

```text
├── cmd/                               # Main application entrypoint
│  │── main.go                         # Application bootstrap
│  └── .env                            #Load the config details
├── config/                            # Configuration loaders
├── internal/
│   ├── adapters/
│   │   ├── cipher/aes/                # AES encryption helpers
│   │   ├── handler/http/v1/           # HTTP handler layer (v1 API)
│   │   ├── logger/zapLogger/          # Zap-based logger adapter
│   │   ├── middleware/auth/           # Auth middleware (API key, JWT)
│   │   ├── repository/mysql/          # MySQL persistence layer
│   │   └── router/gin/                # Gin router integration
│   │   └── token/jwt/                 # JWT token handling adapter
│   ├── domain/                        # DTOs, interfaces, types
│   ├── port/                          # Interface ports (contracts)
│   ├── usecase/                       # Business logic (see user.go)
│   └── utils/                         # Utilities (e.g. crypto, random)
└── README.md

```

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.
