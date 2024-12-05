package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

type sessionData struct {
	client   *tls_client.HttpClient
	lastUsed time.Time
}

var (
	clientStore     = make(map[string]*sessionData)
	clientStoreLock sync.Mutex
)

func init() {
	// Start background cleanup for stale sessions
	go cleanStaleSessions()
}

func cleanStaleSessions() {
	for {
		time.Sleep(1 * time.Minute)
		clientStoreLock.Lock()
		for key, data := range clientStore {
			if time.Since(data.lastUsed) > 10*time.Minute {
				delete(clientStore, key)
			}
		}
		clientStoreLock.Unlock()
	}
}

// -- Helper --
func validateProxyURL(proxyURL string) bool {
	regex := regexp.MustCompile(`^(http|https)://(?:[^:]*:[^@]*)?@?.*$`)
	return regex.MatchString(proxyURL)
}

// List of available profiles from the tls-client profiles package
var profileList = []profiles.ClientProfile{
	profiles.Chrome_117,
	profiles.Chrome_120,
	profiles.Chrome_124,
	profiles.Safari_15_6_1,
	profiles.Safari_16_0,
	profiles.Safari_Ipad_15_6,
	profiles.Safari_IOS_16_0,
	profiles.Safari_IOS_17_0,
	profiles.Firefox_117,
	profiles.Firefox_120,
	profiles.Firefox_123,
	profiles.Opera_89,
	profiles.Opera_90,
	profiles.Opera_91,
	profiles.Okhttp4Android10,
	profiles.Okhttp4Android11,
	profiles.Okhttp4Android12,
	profiles.Okhttp4Android13,
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func getRandomProfile() profiles.ClientProfile {
	return profileList[rand.Intn(len(profileList))]
}

func createClient(w fhttp.ResponseWriter, r *fhttp.Request) {
	// Retrieve necessary headers
	proxyURL := r.Header.Get("MX-Proxy-URL")

	// Validate Proxy URL
	if proxyURL == "" || !validateProxyURL(proxyURL) {
		fhttp.Error(w, "Bad Proxy URL", fhttp.StatusBadRequest)
		return
	}

	profile := getRandomProfile()

	// Create TLS Client
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(60),
		tls_client.WithClientProfile(profile),
		tls_client.WithProxyUrl(proxyURL),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		fhttp.Error(w, "Internal Server Error", fhttp.StatusServiceUnavailable)
		return
	}

	// Generate session key and store client
	sessionKey := uuid.New().String()
	clientStoreLock.Lock()
	clientStore[sessionKey] = &sessionData{
		client:   &client,
		lastUsed: time.Now(),
	}
	clientStoreLock.Unlock()

	// Return session key
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"session_key": sessionKey, "client": profile.GetClientHelloId().Client})
}

// TLS API (Endpoint)
func makeRequest(w fhttp.ResponseWriter, r *fhttp.Request) {
	// Retrieve necessary headers
	clientURL := r.Header.Get("MX-URL")
	method := r.Header.Get("MX-Method")
	sessionKey := r.Header.Get("MX-Session-Key")
	followRedirects := r.Header.Get("MX-Follow-Redirects")

	// Validate Session Key
	clientStoreLock.Lock()
	data, exists := clientStore[sessionKey]
	if !exists {
		clientStoreLock.Unlock()
		fhttp.Error(w, "Invalid Session Key", fhttp.StatusBadRequest)
		return
	}
	data.lastUsed = time.Now()
	clientStoreLock.Unlock()

	if strings.ToLower(followRedirects) == "true" {
		(*data.client).SetFollowRedirect(true)
	} else {
		(*data.client).SetFollowRedirect(false)
	}

	// Create new request with the original body
	req, err := fhttp.NewRequest(method, clientURL, r.Body)
	if err != nil {
		log.Printf("Error creating new HTTP request: %v", err)
		fhttp.Error(w, "Bad Request", fhttp.StatusBadRequest)
		return
	}

	// SET HEADERS
	forwardHeaders := make([][2]string, 0, len(r.Header))
	for key, values := range r.Header {
		if !strings.HasPrefix(strings.ToLower(key), "mx-") {
			for _, value := range values {
				forwardHeaders = append(forwardHeaders, [2]string{key, value})
			}
		}
	}

	for _, header := range forwardHeaders {
		req.Header.Add(header[0], header[1])
	}

	// Send Request
	client := *data.client
	resp, err := client.Do(req)
	if err != nil {
		fhttp.Error(w, fmt.Sprintf("Internal server error: %v", err), fhttp.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read Body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fhttp.Error(w, "Internal server error", fhttp.StatusInternalServerError)
		return
	}

	// Get Response Headers
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		responseHeaders[key] = strings.Join(values, ", ")
	}

	// Get Session Cookies
	cookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	// Form Response
	response := struct {
		StatusCode int               `json:"statusCode"`
		Body       string            `json:"body"`
		Headers    map[string]string `json:"headers"`
		Cookies    map[string]string `json:"cookies"`
	}{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		Headers:    responseHeaders,
		Cookies:    cookies,
	}

	// Respond
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Endpoints
	fhttp.HandleFunc("/createClient", createClient)
	fhttp.HandleFunc("/makeRequest", makeRequest)

	addr := ":6060"

	log.Println("Server starting on", addr)
	log.Fatal(fhttp.ListenAndServe(addr, nil))
}
