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
	mu          sync.Mutex
)

// Add CORS headers to allow cross-origin requests
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow requests from any origin
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// Parse the date from WHOIS data
func parseCreationDate(dateStr string) (time.Time, error) {
	cleanedDate := strings.Fields(dateStr)[0]
	formats := []string{"2006-01-02T15:04:05Z", "2006-01-02", "20060102"}
	for _, format := range formats {
		if t, err := time.Parse(format, cleanedDate); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported date format: %s", dateStr)
}

// Main handler to check domain age
func checkDomainAge(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing 'domain' parameter", http.StatusBadRequest)
		return
	}

	if cached, found := domainCache.Get(domain); found {
		json.NewEncoder(w).Encode(cached)
		return
	}

	result := DomainInfo{Domain: domain}
	mu.Lock()
	defer mu.Unlock()

	rawWhois, err := whois.Whois(domain)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to fetch WHOIS: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	parsedWhois, err := whoisparser.Parse(rawWhois)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse WHOIS data: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	creationDate := parsedWhois.Domain.CreatedDate
	if creationDate == "" {
		result.Error = "Creation date not found in WHOIS data"
		json.NewEncoder(w).Encode(result)
		return
	}

	creationTime, err := parseCreationDate(creationDate)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse creation date: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	result.CreatedDate = creationTime.Format("2006-01-02")
	result.IsLessThan6M = creationTime.After(sixMonthsAgo)
	domainCache.Set(domain, result, cache.DefaultExpiration)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	domainCache = cache.New(24*time.Hour, 1*time.Hour)
	http.HandleFunc("/check-domain", enableCORS(checkDomainAge))

	fmt.Println("Server is running")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
