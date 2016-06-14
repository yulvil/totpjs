package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash"
	"time"

	"github.com/gopherjs/gopherjs/js"
)

var step int64 = 30
var epoch int64 = 0

func Totp(k []byte, t int64, h func() hash.Hash, l int64) (string, int64, error) {

	if l > 9 || l < 1 {
		return "", 0, errors.New("Totp: Length out of range.")
	}

	time := new(bytes.Buffer)

	expires := step - (t % step)
	err := binary.Write(time, binary.BigEndian, (t-epoch)/step)
	if err != nil {
		return "", 0, err
	}

	hash := hmac.New(h, k)
	hash.Write(time.Bytes())
	v := hash.Sum(nil)

	o := v[len(v)-1] & 0xf
	c := (int32(v[o]&0x7f)<<24 | int32(v[o+1])<<16 | int32(v[o+2])<<8 | int32(v[o+3])) % 1000000000

	return fmt.Sprintf("%010d", c)[10-l : 10], expires, nil
}

type MfaCodeResponse struct {
	SecretKey      string `json:"secretKey"`
	ValidationCode string `json:"validationCode"`
	Expires        int64  `json:"expires"`
}

func GetMfaCode(key string) string {
	k, _ := base32.StdEncoding.DecodeString(key)

	totp, expires, _ := Totp(k, time.Now().Unix(), sha1.New, 6)
	// fmt.Printf("AUTH Key: %s TOTP:%s EXPIRES:%v\n", key, totp, expires)
	return fmt.Sprintf(`{ "secretKey": "%s", "validationCode": "%s", "expires" : %d }`, key, totp, expires)
}

var key string

func init() {
	flag.StringVar(&key, "key", "ABCDEFGHIJKLMNOP", "Secret key")
}

func main() {
	if js.Global != nil {
		js.Global.Set("agol", map[string]interface{}{
			"Totp": func(key string) string { return GetMfaCode(key) },
		})
	} else {
		flag.Parse()
		fmt.Printf("%s\n", GetMfaCode(key))
	}
}
