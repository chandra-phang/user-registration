// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import (
	"context"

	"github.com/chandra-phang/user-registration/model"
)

//go:generate mockgen -source=interfaces.go -destination=./interfaces.mock.gen.go -package=repository .
type RepositoryInterface interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	UpdateUser(ctx context.Context, user model.User) error

	CreateLoginLog(ctx context.Context, loginLog model.LoginLog) error
}
