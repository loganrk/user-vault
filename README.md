# UserVault - Secure User Authentication System

UserVault is a Go-based microservice for secure and scalable user authentication. It supports full account lifecycle operations like registration, login, logout, password reset, token validation, and account activation, with a clean hexagonal architecture.

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
- 🔑 JWT Access and Refresh Token Authentication (HS256/RS256)  
- 🔁 Refresh Token Rotation and Validation  
- 📧 Kafka-based Email Delivery for Account Activation and Password Reset  
- 🧪 Validator-Based Request Validation (GET or POST)  
- 📦 Hexagonal Architecture with Domain-Driven Design  
- 🧱 Modular Adapters for DB, Messaging, Email, Tokens, Logging  
- 🔄 Graceful Error Handling with Logger Middleware  

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
.
├── cmd/                           # Main application entrypoint
│   ├── main.go                    # Application bootstrap logic
│   └── .env                       # Environment variables for the service
├── config/                        # YAML/ENV configuration loaders
├── internal/
│   ├── adapters/                  # Infrastructure layer (driven adapters)
│   │   ├── cipher/aes/            # AES encryption helpers
│   │   ├── email/                 # Email template and content builder
│   │   ├── handler/http/v1/       # HTTP API handlers (v1)
│   │   ├── logger/zapLogger/      # Zap-based logging adapter
│   │   ├── message/kafka/         # Kafka producer for email events
│   │   ├── middleware/auth/       # JWT/API key middleware
│   │   ├── repository/mysql/      # MySQL persistence adapter
│   │   ├── router/gin/            # Gin router setup
│   │   └── token/jwt/             # JWT token generation and validation
│   ├── domain/                    # Core domain models and logic
│   ├── port/                      # Interface ports for adapters/usecases
│   ├── usecase/                   # Business logic and services
│   └── utils/                     # Utility helpers (crypto, random, etc.)
├── conf.yml                       # YAML-based application configuration
└── README.md                      # Project documentation

```

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.
