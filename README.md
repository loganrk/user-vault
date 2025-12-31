# User Vault — Secure User Authentication System

**User Vault** is a production-ready Go microservice designed for **secure, scalable, and extensible user authentication**.

It supports the full user account lifecycle including **registration, login, logout, password reset, token validation, and account verification**, and is built using **Hexagonal Architecture (Ports & Adapters)** to ensure clean separation of concerns, maintainability, and testability.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Installation](#installation)
  - [Using Binary](#using-binary)
  - [Using Docker](#using-docker)
- [API Access](#api-access)
- [Security Notes](#security-notes)
- [Contributing](#contributing)

---

## Features

- 🔐 Secure password hashing using **bcrypt**
- 🔑 JWT authentication with **Access & Refresh Tokens** (HS256 / RS256)
- 🔁 Refresh token rotation and validation
- 📧 Kafka-based email events for:
  - Account verification
  - Password reset
- 🧪 Validator-based request validation (GET / POST)
- 📦 Hexagonal Architecture with Domain-Driven Design (DDD)
- 🧱 Pluggable adapters for:
  - Database
  - Messaging
  - Email
  - Token generation
  - Logging
- 🔄 Graceful shutdown support

---

## Architecture Overview

User Vault follows **Hexagonal Architecture**, ensuring that:

- Business logic lives in the **domain**
- External systems (DB, Kafka, Email, JWT, Logging) are implemented as **adapters**
- Infrastructure changes do not impact core logic

This design makes the service:
- Easy to test
- Easy to extend
- Easy to replace infrastructure components

---

## Dependencies

User Vault depends on the following **external services**:

### MySQL
- Version: **8.0+**
- Used for persistent user data storage

### Kafka
- Used for asynchronous email workflows
- Required topics:
  - `user-verification`
  - `user-password-reset`

---

## Dependencies Setup

### 1. MySQL Setup

```sql
CREATE DATABASE userVault;

CREATE USER 'user_vault_user'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON userVault.* TO 'user_vault_user'@'%';
FLUSH PRIVILEGES;
```

---

### 2. Kafka Setup

```bash
kafka-topics.sh --create   --topic user-verification   --bootstrap-server localhost:9092   --partitions 1   --replication-factor 1
```

```bash
kafka-topics.sh --create   --topic user-password-reset   --bootstrap-server localhost:9092   --partitions 1   --replication-factor 1
```

---

### 3. Verify Dependencies

Ensure the following before starting User Vault:

- ✅ MySQL is running
- ✅ Database `userVault` exists
- ✅ Kafka broker is running
- ✅ Kafka topics are created

---

## Configuration

### Clone the Repository

```bash
git clone https://github.com/loganrk/user-vault.git
cd user-vault
```

---

### Configuration File

Rename the sample configuration:

```bash
mv conf/local.yaml.sample conf/local.yaml
```

Update values in `conf/local.yaml` as needed.

---

### Environment Variables

These variables can be set locally, via `.env`, or in `docker-compose.yml`.

```bash
# Config
CONFIG_PATH=/app/conf/local.yaml

# Optional encryption
CIPHER_SECRET_ENCRYPTION_ENABLED=false
CIPHER_SECRET_KEY=

# JWT
JWT_METHOD=HS256
JWT_HMAC_KEY=supersecretkeyforhmac
JWT_RSA_PRIVATE_KEY_PATH=
JWT_RSA_PUBLIC_KEY_PATH=

# MySQL
DB_HOST=mysqlHost
DB_PORT=3306
DB_USERNAME=user_vault_user
DB_PASSWORD=password
DB_NAME=userVault

# Kafka
KAFKA_BROKERS=kafkaHost:9092
```

---

## Encrypted Credentials (Optional)

User Vault supports **environment variable encryption** for sensitive values.

### Enable Encryption

```bash
export CIPHER_SECRET_ENCRYPTION_ENABLED=true
export CIPHER_SECRET_KEY=your-secret-key
```

Generate encryption keys using the provided scripts:

🔗 https://github.com/loganrk/user-vault/tree/main/scripts

### Encrypted Values Example

```bash
export DB_PASSWORD=ENC(encrypted_value)
export KAFKA_BROKERS=ENC(encrypted_value)
```

> When encryption is enabled, **all sensitive fields must be encrypted**.

---

## Installation

### Using Binary

#### Build

```bash
go build -o user-vault cmd/main.go
```

#### Run

```bash
./user-vault
```

---

### Using Docker

#### Prerequisites

- Docker
- Docker Compose v2+

```bash
docker --version
docker compose version
```

#### Start the Service

```bash
docker compose up -d --build
```

The service automatically loads:
- `conf/local.yaml`

---

## API Access

Once running, the API is available at:

```
http://localhost:8080
```

Comprehensive API documentation, architecture details, and usage examples are available in the Wiki:

🔗 https://github.com/loganrk/user-vault/wiki

---

## Security Notes

- Always use **RS256** in production environments
- Rotate JWT keys regularly
- Use encrypted environment variables for secrets
- Run Kafka and MySQL on secured networks

---

## Contributing

Contributions are welcome! 🎉

Feel free to:
- Open issues
- Submit pull requests
- Suggest improvements

Please ensure code follows project conventions and includes tests where applicable.
