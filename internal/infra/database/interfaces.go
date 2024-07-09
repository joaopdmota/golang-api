package database

import (
	"api/internal/entity"
)

type UserDBIntercace interface {
	Create(user *entity.User) error
	FindByEmail(email string) (*entity.User, error)
}

type ProductDBInterface interface {
	Create(product *entity.Product) error
	FindByID(id string) (*entity.Product, error)
	FindAll(page, limit int, sort string) ([]entity.Product, error)
	Delete(id string) error
	Update(product *entity.Product) error
}
