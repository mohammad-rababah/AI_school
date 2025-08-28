package db

// TutorStatus represents the various statuses a tutor can have during the onboarding lifecycle
type TutorStatus string

const (
	TutorStatusPending    TutorStatus = "PENDING"
	TutorStatusVerified   TutorStatus = "VERIFIED"
	TutorStatusOnboarding TutorStatus = "ONBOARDING"
	TutorStatusApproved   TutorStatus = "APPROVED"
	TutorStatusRejected   TutorStatus = "REJECTED"
)

// Tutor represents the database model for a tutor
// Add more fields as needed
// GORM tags are used for mapping

type Tutor struct {
	ID        uint        `gorm:"primaryKey"`
	FirstName string      `gorm:"size:100"`
	LastName  string      `gorm:"size:100"`
	Email     string      `gorm:"size:100;unique"`
	Phone     string      `gorm:"size:20;unique"`
	Password  string      `gorm:"not null"` // store hashed password
	Status    TutorStatus `gorm:"type:varchar(20);default:'PENDING';not null"`
}

// TableName sets the table name for Tutor
func (Tutor) TableName() string {
	return "tutors"
}
