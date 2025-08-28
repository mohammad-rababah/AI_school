package main

import (
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"learing_project/auth/src/controller"
	"learing_project/auth/src/server"
	"learing_project/auth/src/service"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func StartService() {
	fmt.Println("auth service running")
	port := os.Getenv("PORT")
	if port == "" {
		port = ":8080"
	} else {
		port = ":" + port
	}

	srv := server.NewServer(port)

	// Create base API group
	api := srv.Engine().Group("/api/v1")

	// Register Tutor APIs under base group
	tutorService := service.NewTutorService()
	controller.InitTutorAPIs(api, tutorService)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	select {
	case sig := <-shutdown:
		fmt.Println("Received signal:", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("Server Shutdown Failed:%+v", err)
		}
		fmt.Println("Server exited gracefully")
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	StartService()
}
