package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
)

type DomainInfo struct {
	Domain       string `json:"domain"`
	CreatedDate  string `json:"created_date"`
	IsLessThan6M bool   `json:"is_less_than_6_months"`
	Error        string `json:"error,omitempty"`
}

func checkDomainAge(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing 'domain' parameter", http.StatusBadRequest)
		return
	}

	result := DomainInfo{Domain: domain}

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
	createdDate := parsedWhois.Domain.CreatedDate
	result.CreatedDate = createdDate

	// Check if the domain is less than 6 months old
	creationTime, err := time.Parse("2006-01-02T15:04:05Z", createdDate)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse creation date: %v", err)
		json.NewEncoder(w).Encode(result)
		return
	}

	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	result.IsLessThan6M = creationTime.After(sixMonthsAgo)

	// Return the result as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	http.HandleFunc("/check-domain", checkDomainAge)

	fmt.Println("Server is running on http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}
