//go:build windows
// +build windows

package scanner

import (
	"os"

	"golang.org/x/sys/windows"
)

func getFileOwnership(path string, _ os.FileInfo) (string, error) {
	// Get the security descriptor
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}

	// Get the owner SID
	ownerSID, _, err := sd.Owner()
	if err != nil {
		return "", err
	}

	// Convert the SID to a string
	sidString := ownerSID.String()

	return sidString, nil
}
