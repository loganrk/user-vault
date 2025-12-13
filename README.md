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


## 🚀 Installation

### 1. Clone the repository
```sh
git clone https://github.com/loganrk/user-vault
cd user-vault
```

### 2. Create your configuration file
Copy the example:
```sh
cp conf.yaml.example /absolute/path/to/config.yaml
```

Fill in required values such as DB credentials, JWT secrets, and server settings.

### 3. Set up environment variables
Create your environment file:
```sh
cp cmd/.env.example /absolute/path/to/release.env
```

Update the `release.env` file and set the path to your configuration file:
```
CONFIG_FILE_PATH=/absolute/path/to/config.yaml
```
Set the DEPLOYMENT_ENV_PATH
```
export DEPLOYMENT_ENV_PATH=/absolute/path/to/release.env
```

### 4. Install Go dependencies
```sh
go mod tidy
```

##  Usage
Run the service:
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

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.
