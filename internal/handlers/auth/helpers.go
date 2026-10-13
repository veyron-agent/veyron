package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/veyron-agent/veyron/internal/config"
	"github.com/veyron-agent/veyron/internal/models"
)

// tokenTTL: access token'ın (JWT) geçerlilik süresi
const tokenTTL = 1 * time.Hour

// refreshTokenTTL: refresh token'ın geçerlilik süresi
const refreshTokenTTL = 30 * 24 * time.Hour

// execer: hem *pgxpool.Pool hem de pgx.Tx tarafından karşılanır
type execer interface {
	Exec(
		ctx context.Context,
		sql string,
		arguments ...any,
	) (pgconn.CommandTag, error)
}

// createAccessToken kullanıcı için HS256 imzalı JWT üretir
func createAccessToken(
	userID int64,
	username string,
) (string, error) {

	now := time.Now()

	claims := models.Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := token.SignedString([]byte(config.JWT_SECRET))
	if err != nil {
		return "", err
	}

	return signed, nil
}

// hashToken token'ı SHA-256 ile hash'leyip hex string olarak döner
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// createRefreshToken rastgele bir refresh token üretir,
// verilen executor ile DB'ye SHA-256 hash'ini kaydeder
// ve kullanıcıya ham token'ı döner.
func createRefreshToken(
	ctx context.Context,
	db execer,
	userID int64,
) (string, error) {

	// 1) Kriptografik olarak güvenli rastgele token üret
	randomBytes := make([]byte, 32)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(randomBytes)

	// 2) DB'ye yazmadan önce SHA-256 ile hashle
	hashedToken := hashToken(token)

	// 3) Hash'i son kullanma tarihiyle birlikte kaydet
	expiresAt := time.Now().Add(refreshTokenTTL)

	_, err := db.Exec(
		ctx,
		`
		INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		`,
		userID,
		hashedToken,
		expiresAt,
	)
	if err != nil {
		return "", err
	}

	// 4) Kullanıcıya ham token'ı ver
	return token, nil
}
