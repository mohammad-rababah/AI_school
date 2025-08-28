# syntax=docker/dockerfile:1
FROM golang:1.25.0 AS builder
WORKDIR /app
COPY go.mod .
RUN go mod tidy
COPY main.go .
RUN GOOS=linux GOARCH=amd64 go build -o onboard_service main.go

FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/onboard_service ./onboard_service
RUN chmod +x ./onboard_service
CMD ["./onboard_service"]
