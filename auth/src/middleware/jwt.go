package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mohammad-rababah/AI_school/auth/src/model/response"
	"github.com/mohammad-rababah/AI_school/auth/src/util"
	"net/http"
	"strings"
)

// JWTAuthMiddleware checks for JWT in Authorization header
func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response.ErrorResponse{Error: "Missing or invalid token"})
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := util.ValidateJWT(tokenString)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response.ErrorResponse{Error: "Invalid token"})
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response.ErrorResponse{Error: "Invalid claims"})
			return
		}
		c.Set("user_id", claims["user_id"])
		c.Next()
	}
}
