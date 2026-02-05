package useragent

import (
	"math/rand"
	"time"
)

// Init seed agar random benar-benar acak setiap kali run
func init() {
	rand.Seed(time.Now().UnixNano())
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/108.0.0.0",
	"Mozilla/5.0 (Linux; Android 12; Samsung Galaxy S22 Ultra) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0 Mobile Safari/537.36 Accept-Language:en-US",
	"Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S22 Ultra) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0 Mobile Safari/537.36 Accept-Language:en-GB",
}

// GetRandom mengembalikan satu User Agent secara acak
func GetRandom() string {
	return userAgents[rand.Intn(len(userAgents))]
}
