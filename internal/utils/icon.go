package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

func GravatarURL(email string, size int) string {
	clean := strings.TrimSpace(strings.ToLower(email))
	hash := md5.Sum([]byte(clean))
	hashStr := hex.EncodeToString(hash[:])

	return fmt.Sprintf(
		"https://www.gravatar.com/avatar/%s?d=identicon&s=%d",
		hashStr,
		size,
	)
}
