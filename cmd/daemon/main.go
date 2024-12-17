package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	authName = "Authorization"
)

func main() {
	r := gin.Default()

	// public route
	r.GET("/public", LoginHandler)

	// Protected route
	protected := r.Group("/protected")
	protected.Use(RequireAuth)
	{
		protected.GET("/profile", func(c *gin.Context) {
			user, _ := c.Get("user")
			c.JSON(http.StatusOK, gin.H{"message": "Welcome to your profile", "user": user})
		})
	}

	r.Run(":8080")

}

// Hypothetical login handler
func LoginHandler(c *gin.Context) {
	// After validating user credentials
	userID := "123"
	expirationTime := time.Now().Add(time.Hour * 24).Unix()

	claims := jwt.MapClaims{
		"sub": userID,
		"exp": expirationTime,
	}

	// token
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tk.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create token"})
		return
	}

	// Set the token as a cookie
	c.SetCookie(authName, tokenString, 3600*24, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged in", "token": tokenString})
}

func RequireAuth(c *gin.Context) {
	// Retrieve the token from the cookie
	tokenString, err := c.Cookie(authName)
	if err != nil || tokenString == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no authorization token provided"})
		return
	}

	// Optionally remove a "Bearer" prefix
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Parse the token and validate its signature and expiration
	tk, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Ensure the token's algorithm is as expected
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signig method: %v", t.Header)
		}
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	claims, ok := tk.Claims.(jwt.MapClaims)
	if !ok || !tk.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	// check the expiration
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
		return
	}

	// Use claims["sub"] to find the user in the database
	c.Next()
}
