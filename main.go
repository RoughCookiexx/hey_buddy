package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

// Store credentials globally or in a proper config struct
var (
	clientID     = os.Getenv("TWITCH_CLIENT_ID")
	clientSecret = os.Getenv("TWITCH_CLIENT_SECRET")
	// This MUST match the redirect URL in your Twitch Dev Console
	redirectURI = "https://hey.gutgenug.dev/twitch/callback"
)

func main() {
	if clientID == "" || clientSecret == "" {
		log.Fatal("TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET must be set.")
	}

	// This route starts the login process
	http.HandleFunc("/login", handleLogin)

	// Twitch redirects the user back to this route
	http.HandleFunc("/twitch/callback", handleCallback)

	fmt.Println("Server starting on port 6979...")
	// Your Nginx should proxy to this port
	if err := http.ListenAndServe(":6979", nil); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// The scopes you actually need for your subscriptions
	scopes := "moderator:read:followers channel:read:subscriptions"
	
	authURL := fmt.Sprintf("https://id.twitch.tv/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s",
		clientID, url.QueryEscape(redirectURI), url.QueryEscape(scopes))
	
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		log.Println("Error: Twitch callback didn't contain a code.")
		return
	}

	// --- This is your original code, now as a function ---
	accessToken, err := getAccessToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		log.Println("Token exchange failed:", err)
		return
	}

	// SUCCESS! You now have the token.
	log.Println("Successfully got access token.")
	fmt.Fprintf(w, "Authentication successful! You can close this window. Token: %s", accessToken)
	
	// TODO: Now that you have the token, you can store it and
	// start your WebSocket/EventSub logic here.
}

func getAccessToken(code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	resp, err := http.PostForm("https://id.twitch.tv/oauth2/token", data)
	if err != nil {
		return "", fmt.Errorf("failed to POST to token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("twitch API error: %d %s", resp.StatusCode, string(body))
	}

	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	
	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found in response")
	}

	return accessToken, nil
}
