package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

func main() {
	secret := os.Args[1]

	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	now := time.Now().Unix()
	counter := uint64(now / 30)

	otp := GenerateTOTP(counter, secret)
	fmt.Println(otp)
}

func GenerateTOTP(input uint64, secret string) string {
	key, _ := base32.StdEncoding.DecodeString(secret)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, input)

	h := hmac.New(sha1.New, key)
	h.Write(buf)

	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0xf

	binary :=
		(int(hash[offset]&0x7f) << 24) |
			(int(hash[offset+1]&0xff) << 16) |
			(int(hash[offset+2]&0xff) << 8) |
			int(hash[offset+3]&0xff)

	otp := int32(binary % int(math.Pow10(6)))

	return fmt.Sprint(otp)
}
