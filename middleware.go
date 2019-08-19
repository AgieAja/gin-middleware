package middleware

import (
	"net/http"
	"os"
	"strings"

	b64 "encoding/base64"

	"github.com/gin-gonic/gin"
)

//BasicAuth - authentication with basic auth
func BasicAuth(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")

	if !strings.Contains(authHeader, "Basic") {
		result := gin.H{
			"status":  http.StatusForbidden,
			"message": "invalid token",
			"href":    c.Request.RequestURI,
		}
		c.JSON(http.StatusForbidden, result)
		c.Abort()
		return
	}

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	tokenString := strings.Replace(authHeader, "Basic ", "", -1)
	myToken := clientID + ":" + clientSecret
	myBasicAuth := b64.StdEncoding.EncodeToString([]byte(myToken))
	if tokenString != myBasicAuth {
		result := gin.H{
			"status":  http.StatusUnauthorized,
			"message": "Unauthorized user",
			"href":    c.Request.RequestURI,
		}
		c.JSON(http.StatusUnauthorized, result)
		c.Abort()
		return
	}
}
