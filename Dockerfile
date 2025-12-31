# ───────────────────────────────────────────────
# Build Stage
# ───────────────────────────────────────────────
FROM golang:1.22 AS builder

WORKDIR /app

# Copy all source code
COPY . .
RUN go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o user-vault ./cmd/main.go


# ───────────────────────────────────────────────
# Runtime Stage
# ───────────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

# Copy compiled binary
COPY --from=builder /app/user-vault .

EXPOSE 8080

CMD ["./user-vault"]