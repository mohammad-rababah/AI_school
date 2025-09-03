package repo

import (
	"context"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"gorm.io/gorm"
)

// TutorRepo is the public interface for tutor repository
// All methods return results via channels

type TutorRepo interface {
	CreateTutor(ctx context.Context, tutor db.Tutor, result chan<- ChanResult[db.Tutor])
	GetTutorByID(ctx context.Context, id uint, result chan<- ChanResult[*db.Tutor])
	GetTutorByEmail(ctx context.Context, email string, result chan<- ChanResult[*db.Tutor])
	IsEmailExists(ctx context.Context, email string, result chan<- ChanResult[bool])
	IsPhoneExists(ctx context.Context, phone string, result chan<- ChanResult[bool])
	GetTutorByPhone(ctx context.Context, phone string, result chan<- ChanResult[*db.Tutor])
	UpdateTutor(ctx context.Context, tutor db.Tutor, result chan<- ChanResult[db.Tutor])
}

// tutorRepo is the private implementation

type tutorRepo struct {
	db *gorm.DB
}

func NewTutorRepo(db *gorm.DB) TutorRepo {
	return &tutorRepo{db: db}
}

func (r *tutorRepo) CreateTutor(ctx context.Context, tutor db.Tutor, result chan<- ChanResult[db.Tutor]) {
	err := r.db.WithContext(ctx).Create(&tutor).Error
	result <- ChanResult[db.Tutor]{Data: tutor, Error: err}
}

func (r *tutorRepo) GetTutorByID(ctx context.Context, id uint, result chan<- ChanResult[*db.Tutor]) {
	var tutor db.Tutor
	err := r.db.WithContext(ctx).First(&tutor, id).Error
	if err != nil {
		result <- ChanResult[*db.Tutor]{Data: nil, Error: err}
	} else {
		result <- ChanResult[*db.Tutor]{Data: &tutor, Error: nil}
	}
}

func (r *tutorRepo) GetTutorByEmail(ctx context.Context, email string, result chan<- ChanResult[*db.Tutor]) {
	var tutor db.Tutor
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&tutor).Error
	if err != nil {
		result <- ChanResult[*db.Tutor]{Data: nil, Error: err}
	} else {
		result <- ChanResult[*db.Tutor]{Data: &tutor, Error: nil}
	}
}

func (r *tutorRepo) IsEmailExists(ctx context.Context, email string, result chan<- ChanResult[bool]) {
	var count int64
	err := r.db.WithContext(ctx).Model(&db.Tutor{}).Where("email = ?", email).Count(&count).Error
	result <- ChanResult[bool]{Data: count > 0, Error: err}
}

func (r *tutorRepo) IsPhoneExists(ctx context.Context, phone string, result chan<- ChanResult[bool]) {
	var count int64
	err := r.db.WithContext(ctx).Model(&db.Tutor{}).Where("phone = ?", phone).Count(&count).Error
	result <- ChanResult[bool]{Data: count > 0, Error: err}
}

func (r *tutorRepo) GetTutorByPhone(ctx context.Context, phone string, result chan<- ChanResult[*db.Tutor]) {
	var tutor db.Tutor
	err := r.db.WithContext(ctx).Where("phone = ?", phone).First(&tutor).Error
	if err != nil {
		result <- ChanResult[*db.Tutor]{Data: nil, Error: err}
	} else {
		result <- ChanResult[*db.Tutor]{Data: &tutor, Error: nil}
	}
}

func (r *tutorRepo) UpdateTutor(ctx context.Context, tutor db.Tutor, result chan<- ChanResult[db.Tutor]) {
	err := r.db.WithContext(ctx).Model(&db.Tutor{}).Where("id = ?", tutor.ID).Updates(tutor).Error
	result <- ChanResult[db.Tutor]{Data: tutor, Error: err}
}
