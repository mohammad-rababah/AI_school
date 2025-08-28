package migration

import (
	"fmt"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// InitDB loads env, connects to DB, and migrates Tutor
func InitDB() (*gorm.DB, error) {
	// Load .env file
	_ = godotenv.Load(".env")
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, fmt.Errorf("DATABASE_URL not set")
	}

	database, err := gorm.Open(postgres.Open(url), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Migrate Tutor model
	if err := database.AutoMigrate(&db.Tutor{}); err != nil {
		return nil, err
	}

	log.Println("Database migrated successfully.")
	return database, nil
}
