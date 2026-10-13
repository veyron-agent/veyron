package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/veyron-agent/veyron/internal/config"
	"github.com/veyron-agent/veyron/internal/httpx"
	"github.com/veyron-agent/veyron/internal/models"
)

type contextKey string

const claimsContextKey contextKey = "claims"

// Auth, Authorization header'ındaki "Bearer <jwt>" token'ını doğrular.
// Standart http middleware imzasında olduğu için chi'de şöyle kullanılır:
//
//	r.With(middlewares.Auth).Get("/me", handler)
func Auth(
	next http.Handler,
) http.Handler {

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			// 1) Authorization header'ını oku
			header := r.Header.Get("Authorization")

			if header == "" {
				httpx.WriteJSON(w, http.StatusUnauthorized, httpx.ErrorResponse{Error: "authorization header is required"})
				return
			}

			tokenString := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))

			if tokenString == "" || tokenString == header {
				httpx.WriteJSON(w, http.StatusUnauthorized, httpx.ErrorResponse{Error: "invalid authorization header"})
				return
			}

			// 2) JWT'yi doğrula (imza + exp otomatik kontrol edilir)
			claims := &models.Claims{}

			token, err := jwt.ParseWithClaims(
				tokenString,
				claims,
				func(token *jwt.Token) (any, error) {

					// Sadece HS256 kabul et
					if token.Method != jwt.SigningMethodHS256 {
						return nil, jwt.ErrSignatureInvalid
					}

					return []byte(config.JWT_SECRET), nil
				},
			)

			if err != nil || !token.Valid {
				httpx.WriteJSON(w, http.StatusUnauthorized, httpx.ErrorResponse{Error: "invalid or expired token"})
				return
			}

			// 3) Claims'i context'e koy ve devam et
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		},
	)
}

// ClaimsFromContext, Auth middleware'inin context'e koyduğu
// doğrulanmış kullanıcı claims'ini döner.
func ClaimsFromContext(
	ctx context.Context,
) (*models.Claims, bool) {

	claims, ok := ctx.Value(claimsContextKey).(*models.Claims)

	return claims, ok
}
