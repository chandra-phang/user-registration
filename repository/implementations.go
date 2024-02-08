package repository

import (
	"context"
	"errors"
	"time"

	"github.com/chandra-phang/sawit-pro/apperror"
	"github.com/chandra-phang/sawit-pro/model"
)

func (r *Repository) CreateUser(ctx context.Context, user model.User) error {
	query := `
		INSERT INTO users (id, name, phone_number, password, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	params := []interface{}{
		user.ID, user.Name, user.PhoneNumber, user.Password, time.Now(), time.Now(),
	}
	res, err := r.Db.ExecContext(ctx, query, params...)
	if err != nil {
		return nil
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return errors.New("create user failed")
	}

	return nil
}

func (r *Repository) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*model.User, error) {
	query := `
		SELECT
			id, name, phone_number, password, created_at, updated_at
		FROM users
		WHERE phone_number = $1
		LIMIT 1
	`
	rows, err := r.Db.QueryContext(ctx, query, phoneNumber)
	if err != nil {
		return nil, errors.New("get record failed")
	}

	var user = &model.User{}
	for rows.Next() {
		err = rows.Scan(
			&user.ID, &user.Name, &user.PhoneNumber, &user.Password, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, errors.New("scan record failed")
		}
	}

	if user.ID == "" {
		return nil, apperror.ErrObjectNotExists
	}

	return user, nil
}

func (r *Repository) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	query := `
		SELECT
			id, name, phone_number, password, created_at, updated_at
		FROM users
		WHERE id = $1
		LIMIT 1
	`
	rows, err := r.Db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, errors.New("get record failed")
	}

	var user = &model.User{}
	for rows.Next() {
		err = rows.Scan(
			&user.ID, &user.Name, &user.PhoneNumber, &user.Password, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, errors.New("scan record failed")
		}
	}

	if user.ID == "" {
		return nil, apperror.ErrObjectNotExists
	}

	return user, nil
}

func (r *Repository) UpdateUser(ctx context.Context, user model.User) error {
	query := `
		UPDATE users
		SET name = $2, phone_number = $3, updated_at = $4
		WHERE id = $1
	`
	params := []interface{}{
		user.ID, user.Name, user.PhoneNumber, time.Now(),
	}
	res, err := r.Db.ExecContext(ctx, query, params...)
	if err != nil {
		return nil
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return errors.New("update user failed")
	}

	return nil
}

func (r *Repository) CreateLoginLog(ctx context.Context, loginLog model.LoginLog) error {
	query := `
		INSERT INTO login_logs (id, user_id, created_at)
		VALUES ($1, $2, $3)
	`
	params := []interface{}{
		loginLog.ID, loginLog.User.ID, time.Now(),
	}
	res, err := r.Db.ExecContext(ctx, query, params...)
	if err != nil {
		return nil
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return errors.New("create loginLog failed")
	}

	return nil
}
