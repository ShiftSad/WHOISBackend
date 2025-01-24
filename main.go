package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"github.com/patrickmn/go-cache"
)

type DomainInfo struct {
	Domain       string `json:"domain"`
	CreatedDate  string `json:"created_date"`
	IsLessThan6M bool   `json:"is_less_than_6_months"`
	Error        string `json:"error,omitempty"`
}

var (
	domainCache *cache.Cache
	mu          sync.Mutex // Protect WHOIS rate limit
)

// Parse the date from WHOIS data with multiple formats
func parseCreationDate(dateStr string) (time.Time, error) {
	// Remove extra characters if present (e.g., "#22814823")
	cleanedDate := strings.Fields(dateStr)[0]

	// Try parsing the date in different formats
	formats := []string{
		"2006-01-02T15:04:05Z", // ISO 8601
		"2006-01-02",           // Simple YYYY-MM-DD
		"20060102",             // Compact YYYYMMDD (e.g., 20210507)
	}

	var parsedTime time.Time
	var err error

	for _, format := range formats {
		parsedTime, err = time.Parse(format, cleanedDate)
		if err == nil {
			return parsedTime, nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported date format: %s", dateStr)
}

func checkDomainAge(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing 'domain' parameter", http.StatusBadRequest)
		return
	}

	// Check if the domain info is cached
	if cached, found := domainCache.Get(domain); found {
		// Return the cached result
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cached)
		return
	}

	result := DomainInfo{Domain: domain}

	// Mutex lock to ensure WHOIS queries are rate-limited
	mu.Lock()
	defer mu.Unlock()

	// Perform WHOIS lookup
	rawWhois, err := whois.Whois(domain)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to fetch WHOIS: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	// Parse the WHOIS data
	parsedWhois, err := whoisparser.Parse(rawWhois)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse WHOIS data: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	// Extract the creation date
	creationDate := parsedWhois.Domain.CreatedDate
	if creationDate == "" {
		result.Error = "Creation date not found in WHOIS data"
		json.NewEncoder(w).Encode(result)
		return
	}

	// Parse the creation date using the custom parser
	creationTime, err := parseCreationDate(creationDate)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse creation date: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	// Check if the domain is less than 6 months old
	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	result.CreatedDate = creationTime.Format("2006-01-02")
	result.IsLessThan6M = creationTime.After(sixMonthsAgo)

	// Cache the result
	domainCache.Set(domain, result, cache.DefaultExpiration)

	// Return the result as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	// Initialize the cache with a default expiration of 24 hours
	domainCache = cache.New(24*time.Hour, 1*time.Hour)

	http.HandleFunc("/check-domain", checkDomainAge)

	fmt.Println("Server is running on http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}
