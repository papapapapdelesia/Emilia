package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"Emilia/useragent"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// === KONFIGURASI ===
const (
	Debug         = false // false or true
	TimeoutSec    = 5
	MaxConcurrent = 150
)

var workerURLs = []string{
	"https://api-check4.checkv4.workers.dev",
	"https://api-check1.api-check1.workers.dev",
	"https://api-check2.shirokoyumi.workers.dev",
	"https://api-check3.sokove5110.workers.dev",
}

const (
	TraceURL     = "https://1.1.1.1/cdn-cgi/trace"
	AwsURL       = "https://checkip.amazonaws.com"
	FileInput    = "Data/IPPROXY23K.txt"
	FileAlive    = "Data/Alive.txt"
	FilePriority = "Data/Priority.txt"
)

var PriorityCountries = map[string]bool{"ID": true, "MY": true, "SG": true, "HK": true}
var regexOrg = regexp.MustCompile(`[^a-zA-Z0-9\s]`)

// === STRUKTUR DATA ===
type WorkerResponse struct {
	IP  string `json:"ip"`
	Org string `json:"as_organization"`
}

type ProxyInput struct {
	IP       string
	Port     string
	Country  string
	OrgInput string
}

type ValidProxy struct {
	IP      string
	Port    string
	Country string
	Org     string
	Source  string
}

type CheckResult struct {
	Valid bool
	Data  *ValidProxy
}

type Stats struct {
	Total   int32
	Live    int32
	Checked int32
}

// === FUNGSI UTAMA ===
func main() {
	os.MkdirAll("Data", os.ModePerm)

	fmt.Println("==========================================")
	fmt.Println("   GOLANG SOCKET SCANNER (SORTING PRO)  ")
	fmt.Printf("   Debug Mode: %v\n", Debug)
	fmt.Println("==========================================")

	// 1. DAPATKAN IP ASLI
	fmt.Print("🔍 Mendapatkan IP Asli... ")
	realIP := getPublicIPDirect()
	if realIP == "" {
		fmt.Println("\n❌ Gagal mendapatkan IP Asli. Cek koneksi internet.")
		return
	}
	fmt.Printf("%s\n\n", realIP)

	// 2. BACA FILE INPUT
	proxies, err := readInputFile(FileInput)
	if err != nil {
		fmt.Printf("Error membaca file: %v\n", err)
		return
	}
	fmt.Printf("📂 Total Proxy Loaded: %d\n", len(proxies))
	fmt.Println("🚀 Memulai scan socket parallel, Mohon tunggu.\n")

	// 3. SCANNING
	stats := &Stats{Total: int32(len(proxies))}
	resultsChan := make(chan CheckResult, len(proxies))

	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrent)

	// Progress monitor Aktifkan satu
	// ticker := time.NewTicker(500 * time.Millisecond)
	ticker := time.NewTicker(10 * time.Second)
	// ticker := time.NewTicker(1 * time.Minute)
	// ticker := time.NewTicker(1 * time.Hour)
	done := make(chan bool)
	go progressMonitor(ticker, done, stats)

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}

		go func(proxy ProxyInput) {
			defer wg.Done()
			defer func() { <-sem }()

			res := checkProxyManualSocket(proxy, realIP)
			atomic.AddInt32(&stats.Checked, 1)
			
			if res.Valid {
				atomic.AddInt32(&stats.Live, 1)
				if Debug {
					fmt.Printf("\n✅ LIVE: %s:%s | Org: %s",
						res.Data.IP, res.Data.Port, res.Data.Org)
				}
			}

			resultsChan <- res
		}(p)
	}

	wg.Wait()
	done <- true
	close(resultsChan)

	// 4. SORTING & SAVING
	fmt.Println("\n\n🏁 Scanning selesai. Menyimpan hasil.")
	saveValidResults(resultsChan)
}

// === FUNGSI BANTU UTAMA ===
func checkProxyManualSocket(input ProxyInput, realIP string) CheckResult {
	// Layer 1: Worker URLs (JSON response)
	for i, target := range workerURLs {
		body, code := rawSocketRequest(target, input.IP, input.Port)
		if code == 200 {
			var resp WorkerResponse
			if err := json.Unmarshal(body, &resp); err == nil {
				if isValidIP(resp.IP) && resp.IP != realIP {
					finalOrg := input.OrgInput
					if resp.Org != "" {
						finalOrg = cleanOrgName(resp.Org)
					}
					return CheckResult{
						Valid: true,
						Data: &ValidProxy{
							IP:      input.IP,
							Port:    input.Port,
							Country: input.Country,
							Org:     finalOrg,
							Source:  fmt.Sprintf("Worker-%d", i+1),
						},
					}
				}
			}
		}
	}

	// Layer 2: Cloudflare Trace
	body, code := rawSocketRequest(TraceURL, input.IP, input.Port)
	if code == 200 {
		ip := parseTraceIP(string(body))
		if isValidIP(ip) && ip != realIP {
			return CheckResult{
				Valid: true,
				Data: &ValidProxy{
					IP:      input.IP,
					Port:    input.Port,
					Country: input.Country,
					Org:     cleanOrgName(input.OrgInput),
					Source:  "CF Trace",
				},
			}
		}
	}

	// Layer 3: AWS CheckIP
	body, code = rawSocketRequest(AwsURL, input.IP, input.Port)
	if code == 200 {
		ip := strings.TrimSpace(string(body))
		if isValidIP(ip) && ip != realIP {
			return CheckResult{
				Valid: true,
				Data: &ValidProxy{
					IP:      input.IP,
					Port:    input.Port,
					Country: input.Country,
					Org:     cleanOrgName(input.OrgInput),
					Source:  "AWS",
				},
			}
		}
	}

	return CheckResult{Valid: false}
}

func rawSocketRequest(targetURL, proxyIP, proxyPort string) ([]byte, int) {
	parsedURL, _ := url.Parse(targetURL)
	host := parsedURL.Hostname()
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Establish TCP connection to proxy
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyIP, proxyPort), 
		time.Duration(TimeoutSec)*time.Second)
	if err != nil {
		return nil, 0
	}
	defer conn.Close()

	// Setup TLS
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(time.Duration(TimeoutSec) * time.Second))

	// TLS Handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, 0
	}

	// Send HTTP request
	rawRequest := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host, uagen.GetRandom(),
	)

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil {
		return nil, 0
	}

	// Read response
	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode
	}

	return body, resp.StatusCode
}

// === FUNGSI UTILITAS ===
func getPublicIPDirect() string {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Try worker URLs first
	for _, u := range workerURLs {
		resp, err := client.Get(u)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			var w WorkerResponse
			if json.Unmarshal(body, &w) == nil && isValidIP(w.IP) {
				return w.IP
			}
		}
	}
	
	// Fallback to AWS
	resp, err := client.Get(AwsURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		ip := strings.TrimSpace(string(body))
		if isValidIP(ip) {
			return ip
		}
	}
	
	return ""
}

func parseTraceIP(text string) string {
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimPrefix(line, "ip=")
		}
	}
	return ""
}

func cleanOrgName(org string) string {
	cleaned := regexOrg.ReplaceAllString(org, "")
	return strings.TrimSpace(cleaned)
}

func readInputFile(path string) ([]ProxyInput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []ProxyInput
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 4 {
			proxies = append(proxies, ProxyInput{
				IP:       strings.TrimSpace(parts[0]),
				Port:     strings.TrimSpace(parts[1]),
				Country:  strings.TrimSpace(parts[2]),
				OrgInput: strings.TrimSpace(parts[3]),
			})
		}
	}
	return proxies, scanner.Err()
}

func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	return net.ParseIP(ip) != nil
}

func progressMonitor(ticker *time.Ticker, done chan bool, stats *Stats) {
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&stats.Checked)
			live := atomic.LoadInt32(&stats.Live)
			fmt.Printf("\r⏳ Progress: %d/%d | ✅ Live: %d   ",
				current, stats.Total, live)
		}
	}
}

func saveValidResults(resultsChan chan CheckResult) {
	var validProxies []ValidProxy
	for res := range resultsChan {
		if res.Valid && res.Data != nil {
			validProxies = append(validProxies, *res.Data)
		}
	}
	saveResults(validProxies)
}

func saveResults(proxies []ValidProxy) {
	// 1. SAVE ALIVE (A-Z Biasa)
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].Country < proxies[j].Country
	})

	fAlive, _ := os.Create(FileAlive)
	wAlive := bufio.NewWriter(fAlive)
	for _, p := range proxies {
		line := fmt.Sprintf("%s,%s,%s,%s\n", p.IP, p.Port, p.Country, p.Org)
		wAlive.WriteString(line)
	}
	wAlive.Flush()
	fAlive.Close()

	// 2. SAVE PRIORITY (Custom Sort: ID/MY/SG/HK di atas)
	prioList := make([]ValidProxy, len(proxies))
	copy(prioList, proxies)

	sort.SliceStable(prioList, func(i, j int) bool {
		c1 := prioList[i].Country
		c2 := prioList[j].Country

		isPrio1 := PriorityCountries[c1]
		isPrio2 := PriorityCountries[c2]

		if isPrio1 && !isPrio2 {
			return true
		}
		if !isPrio1 && isPrio2 {
			return false
		}

		return c1 < c2
	})

	fPrio, _ := os.Create(FilePriority)
	wPrio := bufio.NewWriter(fPrio)
	for _, p := range prioList {
		line := fmt.Sprintf("%s,%s,%s,%s\n", p.IP, p.Port, p.Country, p.Org)
		wPrio.WriteString(line)
	}
	wPrio.Flush()
	fPrio.Close()

	fmt.Printf("\n\n📁 Output Report:\n")
	fmt.Printf("   ✓ Alive.txt    : %d proxies (Urut A-Z)\n", len(proxies))
	fmt.Printf("   ✓ Priority.txt : %d proxies (Prio di atas -> A-Z)\n", len(prioList))
}
