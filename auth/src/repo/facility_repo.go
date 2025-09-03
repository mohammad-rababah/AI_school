package repo

import (
	"context"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"gorm.io/gorm"
)

type FacilityRepo interface {
	CreateFacility(ctx context.Context, facility db.Facility, resultChan chan ChanResult[db.Facility])
	GetFacilityByID(ctx context.Context, id uint, resultChan chan ChanResult[*db.Facility])
	UpdateFacility(ctx context.Context, facility db.Facility, resultChan chan ChanResult[db.Facility])
}

type facilityRepo struct {
	db *gorm.DB
}

func NewFacilityRepo(db *gorm.DB) FacilityRepo {
	return &facilityRepo{db: db}
}

func (r *facilityRepo) CreateFacility(ctx context.Context, facility db.Facility, resultChan chan ChanResult[db.Facility]) {
	go func() {
		res := r.db.WithContext(ctx).Create(&facility)
		resultChan <- ChanResult[db.Facility]{Data: facility, Error: res.Error}
	}()
}

func (r *facilityRepo) GetFacilityByID(ctx context.Context, id uint, resultChan chan ChanResult[*db.Facility]) {
	go func() {
		var facility db.Facility
		res := r.db.WithContext(ctx).Where("id = ?", id).First(&facility)
		if res.Error != nil {
			resultChan <- ChanResult[*db.Facility]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.Facility]{Data: &facility, Error: nil}
	}()
}

func (r *facilityRepo) UpdateFacility(ctx context.Context, facility db.Facility, resultChan chan ChanResult[db.Facility]) {
	go func() {
		res := r.db.WithContext(ctx).Save(&facility)
		resultChan <- ChanResult[db.Facility]{Data: facility, Error: res.Error}
	}()
}
