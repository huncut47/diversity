package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func genSalt(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("salt length must be at least 1")
	}

	out := make([]byte, length)
	for i := 0; i < length; i++ {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", fmt.Errorf("rand: %w", err)
			}
			v := int(b[0])
			limit := 256 - (256 % len(saltChars))
			if v < limit {
				out[i] = saltChars[v%len(saltChars)]
				break
			}
		}
	}
	return string(out), nil
}

func GeneratePasswordHash(password string) (string, error) {

	salt, err := genSalt(16)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 64)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("scrypt:32768:8:1$%s$%s", salt, hex.EncodeToString(dk)), nil
}

func CheckPasswordHash(hash string, password string) bool {
	parts := strings.SplitN(hash, "$", 3)
	if len(parts) != 3 {
		return false
	}

	method := parts[0]
	salt := parts[1]
	hashHex := parts[2]

	if !strings.HasPrefix(method, "scrypt:") {
		return false
	}
	m := strings.Split(method, ":")
	if len(m) != 4 {
		return false
	}
	N, err := strconv.Atoi(m[1])
	if err != nil || N <= 1 {
		return false
	}
	r, err := strconv.Atoi(m[2])
	if err != nil || r <= 0 {
		return false
	}
	p, err := strconv.Atoi(m[3])
	if err != nil || p <= 0 {
		return false
	}

	dk, err := scrypt.Key([]byte(password), []byte(salt), N, r, p, 64)
	if err != nil {
		return false
	}
	computedHex := hex.EncodeToString(dk)

	if len(computedHex) != len(hashHex) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computedHex), []byte(hashHex)) == 1
}
