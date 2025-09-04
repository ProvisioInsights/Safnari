package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type releaseInfo struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
}

const releaseURL = "https://api.github.com/repos/ProvisioInsights/Safnari/releases/latest"

func CheckForUpdate(current string) (string, string, bool, error) {
	return checkForUpdateURL(current, releaseURL)
}

func checkForUpdateURL(current, url string) (string, string, bool, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", false, fmt.Errorf("unexpected status: %s", resp.Status)
	}
	var info releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", "", false, err
	}
	latest := strings.TrimPrefix(info.TagName, "v")
	if latest != current {
		return latest, info.Body, true, nil
	}
	return latest, "", false, nil
}
