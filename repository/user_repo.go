// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import (
	"context"

	"github.com/chandra-phang/sawit-pro/model"
)

//go:generate mockgen -source=user_repo.go -destination=./mock_repository/user_repo_mock.go
type RepositoryInterface interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	UpdateUser(ctx context.Context, user model.User) error
}
