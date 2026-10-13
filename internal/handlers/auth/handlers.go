package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"github.com/veyron-agent/veyron/internal/httpx"
	"github.com/veyron-agent/veyron/internal/models"
	"github.com/veyron-agent/veyron/internal/store"
)

func Register(
	w http.ResponseWriter,
	r *http.Request,
) {

	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "invalid request body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	if req.Username == "" || req.Email == "" || req.Password == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "username, email and password are required"})
		return
	}

	if _, err := mail.ParseAddress(req.Email); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "invalid email address"})
		return
	}

	if len(req.Password) < 8 || len(req.Password) > 72 {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "password must be between 8 and 72 characters"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not hash password"})
		return
	}

	var id int64
	err = store.DB.QueryRow(
		r.Context(),
		`
		INSERT INTO users (username, email, password)
		VALUES ($1, $2, $3)
		RETURNING id
		`,
		req.Username,
		req.Email,
		string(hash),
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httpx.WriteJSON(w, http.StatusConflict, httpx.ErrorResponse{Error: "username or email already in use"})
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not create user"})
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":       id,
		"username": req.Username,
		"email":    req.Email,
	})
}

func Login(
	w http.ResponseWriter,
	r *http.Request,
) {

	// 1) İstek gövdesini oku
	var req models.LoginReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "invalid request body"})
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	if req.Email == "" || req.Password == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "email and password are required"})
		return
	}

	// 2) Kullanıcıyı email ile bul
	var (
		userID       int64
		username     string
		passwordHash string
	)

	err := store.DB.QueryRow(
		r.Context(),
		`
		SELECT id, username, password
		FROM users
		WHERE email = $1
		`,
		req.Email,
	).Scan(
		&userID,
		&username,
		&passwordHash,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteJSON(w, http.StatusUnauthorized, httpx.ErrorResponse{Error: "invalid email or password"})
		return
	}

	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not fetch user"})
		return
	}

	// 3) Şifreyi doğrula
	err = bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(req.Password),
	)
	if err != nil {
		httpx.WriteJSON(w, http.StatusUnauthorized, httpx.ErrorResponse{Error: "invalid email or password"})
		return
	}

	// 4) JWT token üret
	signed, err := createAccessToken(userID, username)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not create token"})
		return
	}

	// 5) Refresh token üret (DB'ye SHA-256 hash'i kaydedilir)
	refreshToken, err := createRefreshToken(r.Context(), store.DB, userID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not create refresh token"})
		return
	}

	// 6) Cevabı dön
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"token":         signed,
		"refresh_token": refreshToken,
		"username":      username,
	})
}

func Refresh(
	w http.ResponseWriter,
	r *http.Request,
) {

	// 1) İstek gövdesini oku
	var req models.RefreshReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "invalid request body"})
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if req.RefreshToken == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, httpx.ErrorResponse{Error: "refresh_token is required"})
		return
	}

	// 2) Transaction başlat
	ctx := r.Context()

	tx, err := store.DB.Begin(ctx)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not start transaction"})
		return
	}

	defer tx.Rollback(ctx)

	// 3) Token'ı doğrula ve sil (rotation)
	var userID int64

	err = tx.QueryRow(
		ctx,
		`
		DELETE FROM refresh_tokens
		WHERE token = $1
		AND expires_at > NOW()
		RETURNING user_id
		`,
		hashToken(req.RefreshToken),
	).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteJSON(w, http.StatusUnauthorized, httpx.ErrorResponse{Error: "invalid or expired refresh token"})
		return
	}

	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not verify refresh token"})
		return
	}

	// 4) Kullanıcıyı bul
	var username string

	err = tx.QueryRow(
		ctx,
		`
		SELECT username
		FROM users
		WHERE id = $1
		`,
		userID,
	).Scan(&username)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not fetch user"})
		return
	}

	// 5) Yeni JWT ve yeni refresh token üret
	accessToken, err := createAccessToken(userID, username)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not create token"})
		return
	}

	refreshToken, err := createRefreshToken(ctx, tx, userID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not create refresh token"})
		return
	}

	// 6) Transaction'ı commit et
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, httpx.ErrorResponse{Error: "could not commit transaction"})
		return
	}

	// 7) Cevabı dön
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"token":         accessToken,
		"refresh_token": refreshToken,
		"username":      username,
	})
}
