# 🧪 Mock File Generator

This file documents how to generate mock implementations of interfaces using [`mockgen`](https://github.com/golang/mock).

Ensure `mockgen` is installed:

```bash
go install go.uber.org/mock/mockgen@latest
```

---

## 🔄 Mock Generation Commands

Run the following commands from the **project root** to (re)generate interface mocks:

```bash
mockgen -package=mocks -destination=test/mocks/adapter_handler.go github.com/loganrk/user-vault/internal/core/port Handler

mockgen -package=mocks -destination=test/mocks/adapter_repository_mysql_port.go github.com/loganrk/user-vault/internal/core/port RepositoryMySQL

mockgen -package=mocks -destination=test/mocks/adapter_cipher_port.go github.com/loganrk/user-vault/internal/core/port Cipher

mockgen -package=mocks -destination=test/mocks/adapter_token_port.go github.com/loganrk/user-vault/internal/core/port Token

mockgen -package=mocks -destination=test/mocks/adapter_middleware_gin_port.go github.com/loganrk/user-vault/internal/core/port GinMiddleware

mockgen -package=mocks -destination=test/mocks/adapter_logger_port.go github.com/loganrk/user-vault/internal/core/port Logger

mockgen -package=mocks -destination=test/mocks/adapter_messager_port.go github.com/loganrk/user-vault/internal/adapter/port Messager

mockgen -package=mocks -destination=test/mocks/usecase_user_port.go github.com/loganrk/user-vault/internal/core/port UserSvr
```

---

## 📌 Tips

- Ensure all interfaces are **exported** (start with a capital letter).
- Always run from the root of the module to keep import paths correct.
- Consider using `go:generate` directives in your source files for automation:

```go
//go:generate mockgen -package=mocks -destination=../../../test/mocks/usecase_user_port.go github.com/loganrk/user-vault/internal/core/port UserSvr
```

Then regenerate all mocks with:

```bash
go generate ./...
```

---
