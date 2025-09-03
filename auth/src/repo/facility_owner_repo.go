package repo

import (
	"context"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"gorm.io/gorm"
)

type FacilityOwnerRepo interface {
	CreateFacilityOwner(ctx context.Context, owner db.FacilityOwner, resultChan chan ChanResult[db.FacilityOwner])
	GetFacilityOwnerByEmail(ctx context.Context, email string, resultChan chan ChanResult[*db.FacilityOwner])
	GetFacilityOwnerByPhone(ctx context.Context, phone string, resultChan chan ChanResult[*db.FacilityOwner])
	GetFacilityOwnerByID(ctx context.Context, id uint, resultChan chan ChanResult[*db.FacilityOwner])
	IsEmailExists(ctx context.Context, email string, resultChan chan ChanResult[bool])
	IsPhoneExists(ctx context.Context, phone string, resultChan chan ChanResult[bool])
	UpdateFacilityOwner(ctx context.Context, owner db.FacilityOwner, resultChan chan ChanResult[db.FacilityOwner])
}

type facilityOwnerRepo struct {
	db *gorm.DB
}

func NewFacilityOwnerRepo(db *gorm.DB) FacilityOwnerRepo {
	return &facilityOwnerRepo{db: db}
}

func (r *facilityOwnerRepo) CreateFacilityOwner(ctx context.Context, owner db.FacilityOwner, resultChan chan ChanResult[db.FacilityOwner]) {
	go func() {
		res := r.db.WithContext(ctx).Create(&owner)
		resultChan <- ChanResult[db.FacilityOwner]{Data: owner, Error: res.Error}
	}()
}

func (r *facilityOwnerRepo) GetFacilityOwnerByEmail(ctx context.Context, email string, resultChan chan ChanResult[*db.FacilityOwner]) {
	go func() {
		var owner db.FacilityOwner
		res := r.db.WithContext(ctx).Where("email = ?", email).First(&owner)
		if res.Error != nil {
			resultChan <- ChanResult[*db.FacilityOwner]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.FacilityOwner]{Data: &owner, Error: nil}
	}()
}

func (r *facilityOwnerRepo) GetFacilityOwnerByPhone(ctx context.Context, phone string, resultChan chan ChanResult[*db.FacilityOwner]) {
	go func() {
		var owner db.FacilityOwner
		res := r.db.WithContext(ctx).Where("phone = ?", phone).First(&owner)
		if res.Error != nil {
			resultChan <- ChanResult[*db.FacilityOwner]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.FacilityOwner]{Data: &owner, Error: nil}
	}()
}

func (r *facilityOwnerRepo) GetFacilityOwnerByID(ctx context.Context, id uint, resultChan chan ChanResult[*db.FacilityOwner]) {
	go func() {
		var owner db.FacilityOwner
		res := r.db.WithContext(ctx).Where("id = ?", id).First(&owner)
		if res.Error != nil {
			resultChan <- ChanResult[*db.FacilityOwner]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.FacilityOwner]{Data: &owner, Error: nil}
	}()
}

func (r *facilityOwnerRepo) IsEmailExists(ctx context.Context, email string, resultChan chan ChanResult[bool]) {
	go func() {
		var count int64
		res := r.db.WithContext(ctx).Model(&db.FacilityOwner{}).Where("email = ?", email).Count(&count)
		resultChan <- ChanResult[bool]{Data: count > 0, Error: res.Error}
	}()
}

func (r *facilityOwnerRepo) IsPhoneExists(ctx context.Context, phone string, resultChan chan ChanResult[bool]) {
	go func() {
		var count int64
		res := r.db.WithContext(ctx).Model(&db.FacilityOwner{}).Where("phone = ?", phone).Count(&count)
		resultChan <- ChanResult[bool]{Data: count > 0, Error: res.Error}
	}()
}

func (r *facilityOwnerRepo) UpdateFacilityOwner(ctx context.Context, owner db.FacilityOwner, resultChan chan ChanResult[db.FacilityOwner]) {
	go func() {
		res := r.db.WithContext(ctx).Save(&owner)
		resultChan <- ChanResult[db.FacilityOwner]{Data: owner, Error: res.Error}
	}()
}
