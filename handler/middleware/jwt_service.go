package middleware

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	userIdKey   = "user_id"
	expiryAtKey = "expiry_at"
)

type IJwtService interface {
	GenerateToken(userID string) (string, error)
	Auth(r *http.Request) (*User, error)
}

type JwtService struct {
	pubKey     []byte
	privateKey []byte
}

type User struct {
	ID string
}

func InitAuthService(privateKeyPath string, publicKeyPath string) *JwtService {
	svc := &JwtService{}

	err := svc.loadPrivateKey(privateKeyPath)
	if err != nil {
		return svc
	}

	err = svc.loadPubKey(publicKeyPath)
	if err != nil {
		return svc
	}

	return svc
}

func (svc *JwtService) Auth(r *http.Request) (*User, error) {
	authorization := r.Header.Get("Authorization")
	cleanToken := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	if cleanToken == "" {
		return nil, errors.New("token is missing")
	}

	token, err := jwt.Parse(cleanToken, svc.parsePubKey)
	if err != nil {
		return nil, err
	}

	// check expiry
	decodedExpiryTime := svc.retrieveInt64FromToken(token, expiryAtKey)
	now := time.Now().UTC().Unix()
	if now > decodedExpiryTime {
		return nil, errors.New("expiry time is expired")
	}

	// return identity
	decodedID := svc.retrieveStringFromToken(token, userIdKey)
	return &User{ID: decodedID}, nil
}

func (svc *JwtService) GenerateToken(userID string) (string, error) {
	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims[userIdKey] = userID
	claims[expiryAtKey] = now.Add(1 * time.Hour).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()                          // The time at which the token was issued.
	claims["nbf"] = now.Unix()                          // The time before which the token must be disregarded.

	key, err := svc.parsePrivateKey()
	if err != nil {
		return "", fmt.Errorf("parse: private token: %w", err)
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func (svc *JwtService) loadPubKey(publicKeyPath string) error {
	pubKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}
	svc.pubKey = pubKey

	if _, err := svc.parsePubKey(nil); err != nil {
		return err
	}

	return nil
}

func (svc *JwtService) loadPrivateKey(privateKeyPath string) error {
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	svc.privateKey = privateKey

	if _, err := svc.parsePrivateKey(); err != nil {
		return err
	}

	return nil
}

func (svc *JwtService) parsePubKey(_ *jwt.Token) (interface{}, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(svc.pubKey)
	return key, err
}

func (svc *JwtService) parsePrivateKey() (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(svc.privateKey)
	return key, err
}

func (svc *JwtService) retrieveStringFromToken(token *jwt.Token, keyname string) string {
	value := token.Claims.(jwt.MapClaims)[keyname]
	if value == nil {
		return ""
	}
	return value.(string)
}

func (svc *JwtService) retrieveInt64FromToken(token *jwt.Token, keyname string) int64 {
	value := token.Claims.(jwt.MapClaims)[keyname]
	if value == nil {
		return 0
	}
	return int64(value.(float64))
}
