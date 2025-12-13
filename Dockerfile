# ───────────────────────────────────────────────
# Build Stage
# ───────────────────────────────────────────────
FROM golang:1.21 AS builder

WORKDIR /app

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o user-vault ./cmd/main.go


# ───────────────────────────────────────────────
# Runtime Stage
# ───────────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

# Copy compiled binary
COPY --from=builder /app/user-vault .

# Expose service port
EXPOSE 8080

# Run the application
CMD ["./user-vault"]
