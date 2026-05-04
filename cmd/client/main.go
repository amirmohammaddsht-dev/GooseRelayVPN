package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Optimized for Iranian ISP Throttling
var fastClient = &http.Client{
	Timeout: 45 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        50,
		IdleConnTimeout:     120 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true, // Harder to block than HTTP/1.1
	},
}

func SendToRelay(gasUrl string, encryptedData []byte) ([]byte, error) {
	// 1. Create Request
	req, err := http.NewRequest("POST", gasUrl, bytes.NewBuffer(encryptedData))
	if err != nil {
		return nil, err
	}

	// 2. Set Headers to look like a standard Google Docs update
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")

	// 3. Execute
	resp, err := fastClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 4. Strip Padding and Decode Base64
	// Data format is: [EncodedData].[Noise]
	contentStr := string(body)
	parts := strings.Split(contentStr, ".")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid response format")
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		// If decoding fails, return raw (in case script error returned)
		return body, nil
	}

	return decoded, nil
}

func main() {
	fmt.Println("GooseRelayVPN Optimized Client Running...")
    // Integration logic goes here
}
