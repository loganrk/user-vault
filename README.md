# User Vault - Secure User Authentication System

User Vault is a Go-based microservice for secure and scalable user authentication. It supports full account lifecycle operations like registration, login, logout, password reset, token validation, and account verification, with a clean hexagonal architecture.

The project is structured using a clean **Hexagonal Architecture** to ensure maintainability and testability.

## 📘 [Project Wiki](https://github.com/loganrk/user-vault/wiki)

Detailed documentation is available in the [Wiki](https://github.com/loganrk/user-vault/wiki), including setup guides, API reference, and architectural overviews.

## Table of Contents
- [Wiki](https://github.com/loganrk/user-vault/wiki)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

## Features

- ✅ User Registration with Verification Email  
- 🔐 Secure Password Hashing using bcrypt + salt  
- 🔑 JWT Access and Refresh Token Authentication (HS256/RS256)  
- 🔁 Refresh Token Rotation and Validation  
- 📧 Kafka-based Email Delivery for Account Verification and Password Reset  
- 🧪 Validator-Based Request Validation (GET or POST)  
- 📦 Hexagonal Architecture with Domain-Driven Design  
- 🧱 Modular Adapters for DB, Messaging, Email, Tokens, Logging  
- 🔄 Graceful Error Handling with Logger Middleware  

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/loganrk/user-vault
    cd user-vault
    ```

2. Initialize dependencies:

    ```sh
    go mod tidy
    ```

3. Create a `cmd/.env` or config file with required credentials (DB, JWT secrets, etc.).

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
| POST/GET | `/api/v1/resend-verification` | Resend verification email             |

> 🔒 All routes support both `application/json` POST and query-based GET formats.

## Project Structure

```text
.
├── cmd/                           # Main application entrypoint
│   ├── main.go                    # Application bootstrap logic
│   └── .env                       # Environment variables for the service
├── config/                        # YAML/ENV configuration loaders
├── internal/
│   ├── adapters/                  # Infrastructure layer (driven adapters)
│   │   ├── handler/http/v1/       # HTTP API handlers (v1)
│   │   ├── middleware/auth/       # JWT/API key middleware
│   │   ├── repository/mysql/      # MySQL persistence adapter
│   │   └── router/gin/            # Gin router setup
│   ├── core/      
│   │    ├── domain/               # Core domain models and logic
│   │    ├── port/                 # Interface ports for adapters/usecases
│   │    └── usecase/              # Business logic and services
│   ├── router/gin/                # Gin router setup
│   └── utils/                     # Utility helpers (crypto, random, etc.)
├── conf.yml                       # YAML-based application configuration
└── README.md                      # Project documentation

```

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.
