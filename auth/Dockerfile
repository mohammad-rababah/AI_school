# syntax=docker/dockerfile:1
FROM golang:1.25.0 AS builder
WORKDIR /app
COPY go.work .
COPY auth/go.mod .
COPY auth/src/ ./src
COPY auth/main.go .
RUN go mod tidy
RUN GOOS=linux GOARCH=amd64 go build -o auth_service main.go

FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/auth_service ./auth_service
RUN chmod +x ./auth_service
CMD ["./auth_service"]
