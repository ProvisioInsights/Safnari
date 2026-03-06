package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type releaseInfo struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
}

const releaseURL = "https://api.github.com/repos/ProvisioInsights/Safnari/releases/latest"

var datedReleasePattern = regexp.MustCompile(`^safnari-\d{8}[a-z]?$`)

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
	currentClean := strings.TrimPrefix(current, "v")
	if isNewerRelease(currentClean, latest) {
		return latest, info.Body, true, nil
	}
	return latest, "", false, nil
}

func isNewerRelease(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if current == "" || current == "dev" || latest == "" || current == latest {
		return false
	}
	if datedReleasePattern.MatchString(current) && datedReleasePattern.MatchString(latest) {
		return latest > current
	}
	if newer, ok := compareSemver(latest, current); ok {
		return newer > 0
	}
	return latest != current
}

func compareSemver(left, right string) (int, bool) {
	leftParts, leftOK := parseSemverParts(left)
	rightParts, rightOK := parseSemverParts(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	for i := range leftParts {
		switch {
		case leftParts[i] > rightParts[i]:
			return 1, true
		case leftParts[i] < rightParts[i]:
			return -1, true
		}
	}
	return 0, true
}

func parseSemverParts(value string) ([3]int, bool) {
	var parts [3]int
	if strings.ContainsAny(value, "+-") {
		return parts, false
	}
	segments := strings.Split(value, ".")
	if len(segments) != 3 {
		return parts, false
	}
	for i, segment := range segments {
		n, err := strconv.Atoi(segment)
		if err != nil || n < 0 {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}
