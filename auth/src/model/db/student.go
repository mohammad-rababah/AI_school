package db

import "time"

// StudentStatus represents the various statuses a student can have
// For students, status is simple: PENDING, VERIFIED

type StudentStatus string

const (
	StudentStatusPending  StudentStatus = "PENDING"
	StudentStatusVerified StudentStatus = "VERIFIED"
)

// Student represents the database model for a student
// GORM tags are used for mapping

type Student struct {
	ID        uint          `gorm:"primaryKey"`
	FirstName string        `gorm:"size:100"`
	LastName  string        `gorm:"size:100"`
	Email     string        `gorm:"size:100;unique"`
	Phone     string        `gorm:"size:20;unique"`
	Password  string        `gorm:"not null"` // store hashed password
	Status    StudentStatus `gorm:"type:varchar(20);default:'PENDING';not null"`
	CreatedAt time.Time     `gorm:"autoCreateTime"`
	UpdatedAt time.Time     `gorm:"autoUpdateTime"`
}

func (Student) TableName() string {
	return "students"
}
