package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

//
// ─────────────────────────────────────────────────────────────
//  Domain Types & YAML Structures
// ─────────────────────────────────────────────────────────────
//

type DelegatedRecord struct {
	Registry    string
	CountryCode string
	Date        string
	Status      string
}

type DelegatedIPv4 struct {
	DelegatedRecord
	StartIP string
	Count   int
}

func (r DelegatedIPv4) ToCIDR() (string, error) {
	prefix, err := countToPrefix(r.Count)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d", r.StartIP, prefix), nil
}

type TraefikConfig struct {
	HTTP HTTPBlock `yaml:"http"`
}

type HTTPBlock struct {
	Middlewares map[string]IPAllowlistMiddleware `yaml:"middlewares"`
}

type IPAllowlistMiddleware struct {
	IPAllowList IPAllowList `yaml:"ipAllowList"`
}

type IPAllowList struct {
	SourceRange []string `yaml:"sourceRange"`
}

//
// ─────────────────────────────────────────────────────────────
//  Global State
// ─────────────────────────────────────────────────────────────
//

var yamlContent atomic.Value

//
// ─────────────────────────────────────────────────────────────
//  Configuration
// ─────────────────────────────────────────────────────────────
//

type Config struct {
	ListenAddr      string
	OutputPath      string
	RefreshInterval time.Duration
	CountryCode     string
	RIPEURL         string
}

func loadConfig() Config {
	listenFlag := flag.String("listen-addr", "", "HTTP listen address (env LISTEN_ADDR)")
	outputFlag := flag.String("output-path", "", "Output file path (env OUTPUT_PATH)")
	refreshFlag := flag.String("refresh-interval", "", "Refresh interval like 24h (env REFRESH_INTERVAL)")
	countryFlag := flag.String("country", "", "Country code to filter (env COUNTRY_CODE)")
	ripeURLFlag := flag.String("ripe-url", "", "RIPE delegated file URL (env RIPE_URL)")
	flag.Parse()

	refresh := resolve("REFRESH_INTERVAL", *refreshFlag, "24h")
	refreshDuration, err := time.ParseDuration(refresh)
	if err != nil {
		log.Fatalf("Invalid refresh duration: %v", err)
	}

	return Config{
		ListenAddr:      resolve("LISTEN_ADDR", *listenFlag, ":8123"),
		OutputPath:      resolve("OUTPUT_PATH", *outputFlag, "./allowlist.yaml"),
		RefreshInterval: refreshDuration,
		CountryCode:     resolve("COUNTRY_CODE", *countryFlag, "IS"),
		RIPEURL:         resolve("RIPE_URL", *ripeURLFlag, "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"),
		//RIPEURL: resolve("RIPE_URL", *ripeURLFlag, "http://localhost:9187/delegated-ripencc-latest"),
	}
}

func resolve(env string, flagVal string, def string) string {
	if flagVal != "" {
		return flagVal
	}
	if envVal := os.Getenv(env); envVal != "" {
		return envVal
	}
	return def
}

//
// ─────────────────────────────────────────────────────────────
//  RIPE File Processing
// ─────────────────────────────────────────────────────────────
//

func downloadRIPEFile(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func parseDelegatedIPv4(data []byte, country string) ([]DelegatedIPv4, error) {
	const (
		fieldRegistry    = 0
		fieldCountryCode = 1
		fieldType        = 2
		fieldStart       = 3
		fieldCount       = 4
		fieldDate        = 5
		fieldStatus      = 6
	)

	var results []DelegatedIPv4
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" || strings.Count(line, "|") < 6 {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) < 7 || fields[fieldCountryCode] != country || fields[fieldType] != "ipv4" {
			continue
		}

		count, err := strconv.Atoi(fields[fieldCount])
		if err != nil {
			continue
		}

		record := DelegatedIPv4{
			DelegatedRecord: DelegatedRecord{
				Registry:    fields[fieldRegistry],
				CountryCode: fields[fieldCountryCode],
				Date:        fields[fieldDate],
				Status:      fields[fieldStatus],
			},
			StartIP: fields[fieldStart],
			Count:   count,
		}

		results = append(results, record)
	}

	return results, scanner.Err()
}

//
// ─────────────────────────────────────────────────────────────
//  YAML Generation
// ─────────────────────────────────────────────────────────────
//

func toTraefikYAML(ipv4 []DelegatedIPv4, countryCode string) ([]byte, error) {
	var cidrs []string
	for _, r := range ipv4 {
		cidr, err := r.ToCIDR()
		if err != nil {
			continue
		}
		cidrs = append(cidrs, cidr)
	}

	middlewareName := fmt.Sprintf("ipallowlist-%s", countryCode)

	config := TraefikConfig{
		HTTP: HTTPBlock{
			Middlewares: map[string]IPAllowlistMiddleware{
				middlewareName: {
					IPAllowList: IPAllowList{
						SourceRange: cidrs,
					},
				},
			},
		},
	}

	return yaml.Marshal(config)
}

//
// ─────────────────────────────────────────────────────────────
//  CIDR Conversion Helpers
// ─────────────────────────────────────────────────────────────
//

func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

func countToPrefix(count int) (int, error) {
	if count <= 0 || !isPowerOfTwo(count) {
		return 0, fmt.Errorf("invalid IPv4 count: %d", count)
	}
	return 32 - int(math.Log2(float64(count))), nil
}

//
// ─────────────────────────────────────────────────────────────
//  Refresh + File Writing
// ─────────────────────────────────────────────────────────────
//

func refreshAndStore(config Config) ([]byte, error) {
	data, err := downloadRIPEFile(config.RIPEURL)
	if err != nil {
		log.Printf("Download failed, falling back to local cache: %v", err)
		return loadFromDisk(config.OutputPath)
	}

	ipv4, err := parseDelegatedIPv4(data, config.CountryCode)
	if err != nil {
		log.Printf("Parse failed, falling back to local cache: %v", err)
		return loadFromDisk(config.OutputPath)
	}

	yamlData, err := toTraefikYAML(ipv4, config.CountryCode)
	if err != nil {
		log.Printf("YAML conversion failed, falling back to local cache: %v", err)
		return loadFromDisk(config.OutputPath)
	}

	// Only write if all stages succeeded
	tmpPath := config.OutputPath + ".tmp"
	if err := os.WriteFile(tmpPath, yamlData, 0644); err != nil {
		log.Printf("Failed to write temp file, not updating cache: %v", err)
		return loadFromDisk(config.OutputPath)
	}

	if err := os.Rename(tmpPath, config.OutputPath); err != nil {
		log.Printf("Failed to replace cache file: %v", err)
		return loadFromDisk(config.OutputPath)
	}

	log.Printf("Refreshed and updated %s", config.OutputPath)
	return yamlData, nil
}

func loadFromDisk(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load fallback YAML: %w", err)
	}
	log.Printf("Loaded YAML from disk (%s)", path)
	return data, nil
}

func startPeriodicRefresh(config Config) {
	tick := make(chan struct{})
	limiter := rate.NewLimiter(rate.Every(config.RefreshInterval), 1)

	go func() {
		for {
			if err := limiter.Wait(context.Background()); err != nil {
				log.Println("Rate limiter error:", err)
				continue
			}
			tick <- struct{}{}
		}
	}()

	for range tick {
		yamlData, err := refreshAndStore(config)
		if err != nil {
			log.Printf("Refresh error: %v", err)
		} else {
			yamlContent.Store(yamlData)
			log.Printf("YAML updated (%d bytes)", len(yamlData))
		}
	}
}

//
// ─────────────────────────────────────────────────────────────
//  HTTP Server
// ─────────────────────────────────────────────────────────────
//

func serveYAML(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/allowlist.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		if data, ok := yamlContent.Load().([]byte); ok {
			w.Write(data)
		} else {
			http.Error(w, "YAML not ready", http.StatusServiceUnavailable)
		}
		log.Printf("%s %s", r.Method, r.URL.Path)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		log.Printf("Serving on http://localhost%s/allowlist.yaml", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

//
// ─────────────────────────────────────────────────────────────
//  Main Entry Point
// ─────────────────────────────────────────────────────────────
//

func main() {
	config := loadConfig()

	go startPeriodicRefresh(config)

	if err := serveYAML(config.ListenAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
