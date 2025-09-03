package repo

import (
	"context"
	"github.com/mohammad-rababah/AI_school/auth/src/model/db"
	"gorm.io/gorm"
)

type StudentRepo interface {
	CreateStudent(ctx context.Context, student db.Student, resultChan chan ChanResult[db.Student])
	GetStudentByEmail(ctx context.Context, email string, resultChan chan ChanResult[*db.Student])
	GetStudentByPhone(ctx context.Context, phone string, resultChan chan ChanResult[*db.Student])
	GetStudentByID(ctx context.Context, id uint, resultChan chan ChanResult[*db.Student])
	IsEmailExists(ctx context.Context, email string, resultChan chan ChanResult[bool])
	IsPhoneExists(ctx context.Context, phone string, resultChan chan ChanResult[bool])
	UpdateStudent(ctx context.Context, student db.Student, resultChan chan ChanResult[db.Student])
}

type studentRepo struct {
	db *gorm.DB
}

func NewStudentRepo(db *gorm.DB) StudentRepo {
	return &studentRepo{db: db}
}

func (r *studentRepo) CreateStudent(ctx context.Context, student db.Student, resultChan chan ChanResult[db.Student]) {
	go func() {
		res := r.db.WithContext(ctx).Create(&student)
		resultChan <- ChanResult[db.Student]{Data: student, Error: res.Error}
	}()
}

func (r *studentRepo) GetStudentByEmail(ctx context.Context, email string, resultChan chan ChanResult[*db.Student]) {
	go func() {
		var student db.Student
		res := r.db.WithContext(ctx).Where("email = ?", email).First(&student)
		if res.Error != nil {
			resultChan <- ChanResult[*db.Student]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.Student]{Data: &student, Error: nil}
	}()
}

func (r *studentRepo) GetStudentByPhone(ctx context.Context, phone string, resultChan chan ChanResult[*db.Student]) {
	go func() {
		var student db.Student
		res := r.db.WithContext(ctx).Where("phone = ?", phone).First(&student)
		if res.Error != nil {
			resultChan <- ChanResult[*db.Student]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.Student]{Data: &student, Error: nil}
	}()
}

func (r *studentRepo) GetStudentByID(ctx context.Context, id uint, resultChan chan ChanResult[*db.Student]) {
	go func() {
		var student db.Student
		res := r.db.WithContext(ctx).Where("id = ?", id).First(&student)
		if res.Error != nil {
			resultChan <- ChanResult[*db.Student]{Data: nil, Error: res.Error}
			return
		}
		resultChan <- ChanResult[*db.Student]{Data: &student, Error: nil}
	}()
}

func (r *studentRepo) IsEmailExists(ctx context.Context, email string, resultChan chan ChanResult[bool]) {
	go func() {
		var count int64
		res := r.db.WithContext(ctx).Model(&db.Student{}).Where("email = ?", email).Count(&count)
		resultChan <- ChanResult[bool]{Data: count > 0, Error: res.Error}
	}()
}

func (r *studentRepo) IsPhoneExists(ctx context.Context, phone string, resultChan chan ChanResult[bool]) {
	go func() {
		var count int64
		res := r.db.WithContext(ctx).Model(&db.Student{}).Where("phone = ?", phone).Count(&count)
		resultChan <- ChanResult[bool]{Data: count > 0, Error: res.Error}
	}()
}

func (r *studentRepo) UpdateStudent(ctx context.Context, student db.Student, resultChan chan ChanResult[db.Student]) {
	go func() {
		res := r.db.WithContext(ctx).Save(&student)
		resultChan <- ChanResult[db.Student]{Data: student, Error: res.Error}
	}()
}
