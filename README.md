# User Vault - Secure User Authentication System

User Vault is a Go-based microservice for secure and scalable user authentication. It supports full account lifecycle operations like registration, login, logout, password reset, token validation, and account verification, with a clean hexagonal architecture.

The project is structured using a clean **Hexagonal Architecture** to ensure maintainability and testability.

## 📘 [Project Wiki](https://github.com/loganrk/user-vault/wiki)

Detailed documentation is available in the [Wiki](https://github.com/loganrk/user-vault/wiki), including setup guides, API reference, and architectural overviews.

## Table of Contents
- [Wiki](https://github.com/loganrk/user-vault/wiki)
- [Features](#features)
- [Installation Using Docker](#installation-using-docker)
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


## Installation Using Docker 

This setup runs **User-Vault**, **MySQL**, and **Kafka** fully via Docker. All configuration files are **mounted by `docker-compose`**.

---

###  Prerequisites

- Docker
- Docker Compose v2+

```sh
docker --version
docker compose version
```

---

### Clone the repository

```sh
git clone https://github.com/loganrk/user-vault
cd user-vault
```

---

### Prepare configuration files (local only)

Your `docker-compose` already mounts these paths:

```yaml
volumes:
  - ./etc/conf/:/app/config/:ro
  - ./etc/env/:/app/config/env/:ro
  - ./etc/secrets/:/app/config/secrets/:ro
```

### Create files locally:

```sh
rm etc/conf/docker.yaml.sample etc/conf/local.yaml
cp etc/env/docker.env.sample etc/env/local.env
```

> **Important:** Do not use absolute paths. Docker will mount these files automatically.

---

### Create shared Docker network (one-time)

```sh
docker network create app-network
```

---

### Start MySQL

```sh
docker compose -f docker-compose-mysql.yml up -d
```

✔ Persistent data
✔ No additional config required inside the container

---

### Start Kafka (topics auto-created)

```sh
docker compose -f docker-compose-kafka.yml up -d
```

✔ Kafka data persisted
✔ Topics created automatically if missing

---

### Start User-Vault

```sh
docker compose -f docker-compose-app.yml up -d --build
```

The service automatically reads:
- `/app/config/conf.yaml`
- `/app/config/env/local.env`

---

### Verify Services

```sh
docker ps
```

Check Kafka topics:

```sh
docker exec -it kafka kafka-topics.sh --list --bootstrap-server kafka:9092
```

Verify MySQL:

```sh
docker exec -it mysql mysql -uadmin -padmin123 userVault
```

---

### Access the API

```
http://localhost:8080
```

---


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
