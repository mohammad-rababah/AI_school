// @title AI School Auth API
// @version 1.0
// @description API for authentication and tutor onboarding
// @host localhost:8080
// @BasePath /api/v1
package main

import (
	"context"
	"fmt"
	"github.com/joho/godotenv"
	_ "github.com/mohammad-rababah/AI_school/auth/docs"
	"github.com/mohammad-rababah/AI_school/auth/src/controller"
	"github.com/mohammad-rababah/AI_school/auth/src/migration"
	"github.com/mohammad-rababah/AI_school/auth/src/repo"
	"github.com/mohammad-rababah/AI_school/auth/src/server"
	"github.com/mohammad-rababah/AI_school/auth/src/service"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func StartService() {
	fmt.Println("auth service running")

	// Initialize DB and run migration
	db, err := migration.InitDB()
	if err != nil {
		log.Fatalf("failed to initialize DB: %v", err)
	}

	tutorRepo := repo.NewTutorRepo(db)
	tutorService := service.NewTutorService(tutorRepo)

	port := os.Getenv("PORT")
	if port == "" {
		port = ":8080"
	} else {
		port = ":" + port
	}

	srv := server.NewServer(port)

	// Add Swagger UI route
	srv.Engine().GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Create base API group
	api := srv.Engine().Group("/api/v1")

	// Register Tutor APIs under base group using InitTutorAPIs
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
