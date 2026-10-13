package models

import "github.com/golang-jwt/jwt/v5"

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`

	jwt.RegisteredClaims
}
