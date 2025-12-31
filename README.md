# User Vault - Secure User Authentication System

**User Vault** is a Go-based microservice for secure and scalable user authentication.  
It supports the full account lifecycle: registration, login, logout, password reset, token validation, and account verification.  

The project is structured using a clean **Hexagonal Architecture** for maintainability and testability.

---

## Table of Contents

- [Features](#features)
- [Dependencies Installation](#dependencies-installation)
- [Configuration](#configuration)
- [Installation](#installation)
  - [Using Binary](#installation-using-binary)
  - [Using Docker](#installation-using-docker)
- [Access the API](#access-the-api)
- [Contributing](#contributing)

---

## Features

- 🔐 Secure Password Hashing using **bcrypt**  
- 🔑 JWT Access and Refresh Token Authentication (**HS256/RS256**)  
- 🔁 Refresh Token Rotation and Validation  
- 📧 Kafka-based Email Delivery for Account Verification and Password Reset  
- 🧪 Validator-Based Request Validation (GET/POST)  
- 📦 Hexagonal Architecture with Domain-Driven Design  
- 🧱 Modular Adapters for Database, Messaging, Email, Tokens, Logging  
- 🔄 Graceful Shutdown  

---

## Dependencies Installation

User Vault requires **MySQL** and **Kafka** to be installed and running externally.

### 1️⃣ Install MySQL

1. Install **MySQL 8.0+**  
2. Start the MySQL service  
3. Create the required database and user:

```sql
CREATE DATABASE userVault;

CREATE USER 'user_vault_user'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON userVault.* TO 'user_vault_user'@'%';
FLUSH PRIVILEGES;
```

---

### 2️⃣ Install Kafka

1. Install **Apache Kafka**  
2. Start **Zookeeper** (if required)  
3. Start the **Kafka broker**  
4. Create the required Kafka topic:

```bash
kafka-topics.sh --create  --topic user-verification  --bootstrap-server localhost:9092  --partitions 1  --replication-factor 1
```


```bash
kafka-topics.sh --create  --topic user-password-reset  --bootstrap-server localhost:9092  --partitions 1  --replication-factor 1

```

---

### 3️⃣ Verify Dependencies

Ensure that the following are available:

- ✅ MySQL is running  
- ✅ Database `userVault` exists  
- ✅ Kafka broker is running  
- ✅ Kafka topic is created  

---

## Configuration


### Clone the Repository

```bash
git clone https://github.com/loganrk/user-vault
cd user-vault
```

---

### Prepare Configuration File

Rename the sample config file:

```bash
mv .yaml.sample local.yaml
```

Update values in `local.yaml` if required.

---

### Environment Variables (for Docker or local)

You can define environment variables in `.env` or directly in `docker-compose.yml`:

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

# MySQL (external)
DB_HOST=mysqlHost
DB_PORT=3306
DB_USERNAME=user_vault_user
DB_PASSWORD=password
DB_NAME=userVault

# Kafka (external)
KAFKA_BROKERS=kafkaHost:9092
```

---

### Encrypted Credentials (Optional)

If encryption is enabled:

```bash
export CIPHER_SECRET_ENCRYPTION_ENABLED=true
export CIPHER_SECRET_KEY=your-secret-key
```

All sensitive values must then be encrypted, including `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD`, `DB_NAME`, `KAFKA_BROKERS`.

Example:

```bash
export DB_PASSWORD=ENC(encrypted_value)
export KAFKA_BROKERS=ENC(encrypted_value)
```

---


## Installation Using Binary

### Build the Binary

```bash
go build -o user-vault cmd/main.go
```

### Run the Binary

```bash
./user-vault
```

---

## Installation Using Docker

### Prerequisites

- Docker  
- Docker Compose v2+  

```bash
docker --version
docker compose version
```

---



### Start User Vault

```bash
docker compose up -d --build
```

The service automatically reads:

- `local.yaml`  

---

## Access the API

```
http://localhost:8080
```

---

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

