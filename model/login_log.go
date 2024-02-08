package model

import "time"

type LoginLog struct {
	ID        string
	User      User
	CreatedAt time.Time
}
