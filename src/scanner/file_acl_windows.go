//go:build windows
// +build windows

package scanner

import "golang.org/x/sys/windows"

func getFileACL(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}
