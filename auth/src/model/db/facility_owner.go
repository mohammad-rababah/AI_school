package db

import "time"

type FacilityOwnerStatus string

const (
	FacilityOwnerStatusPending    FacilityOwnerStatus = "PENDING"
	FacilityOwnerStatusVerified   FacilityOwnerStatus = "VERIFIED"
	FacilityOwnerStatusOnboarding FacilityOwnerStatus = "ONBOARDING"
	FacilityOwnerStatusApproved   FacilityOwnerStatus = "APPROVED"
	FacilityOwnerStatusRejected   FacilityOwnerStatus = "REJECTED"
)

type FacilityOwner struct {
	ID        uint                `gorm:"primaryKey"`
	Email     string              `gorm:"size:100;unique"`
	Phone     string              `gorm:"size:20;unique"`
	Password  string              `gorm:"not null"`
	Role      string              `gorm:"type:varchar(20);default:'facility_owner';not null"`
	Status    FacilityOwnerStatus `gorm:"type:varchar(20);default:'PENDING';not null"`
	CreatedAt time.Time           `gorm:"autoCreateTime"`
	UpdatedAt time.Time           `gorm:"autoUpdateTime"`
}

func (FacilityOwner) TableName() string {
	return "facility_owners"
}
