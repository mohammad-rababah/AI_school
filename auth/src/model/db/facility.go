package db

import "time"

type FacilityType string

const (
	FacilityTypeTrainingCenter FacilityType = "training_center"
	FacilityTypeNGO            FacilityType = "ngo"
	FacilityTypeUniversity     FacilityType = "university"
	FacilityTypeSchool         FacilityType = "school"
)

type FacilityStatus string

const (
	FacilityStatusPending    FacilityStatus = "PENDING"
	FacilityStatusOnboarding FacilityStatus = "ONBOARDING"
	FacilityStatusApproved   FacilityStatus = "APPROVED"
	FacilityStatusRejected   FacilityStatus = "REJECTED"
)

type Facility struct {
	ID        uint           `gorm:"primaryKey"`
	OwnerID   uint           `gorm:"not null"`
	Name      string         `gorm:"size:255;not null"`
	Type      FacilityType   `gorm:"type:varchar(20);not null"`
	Documents string         `gorm:"type:jsonb"` // JSONB for uploaded docs
	Status    FacilityStatus `gorm:"type:varchar(20);default:'PENDING';not null"`
	CreatedAt time.Time      `gorm:"autoCreateTime"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime"`
}

func (Facility) TableName() string {
	return "facilities"
}
