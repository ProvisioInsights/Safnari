//go:build !windows
// +build !windows

package scanner

import (
	"encoding/base64"
	"errors"

	"golang.org/x/sys/unix"
)

func getXattrs(path string, maxValueSize int) (map[string]string, error) {
	size, err := unix.Listxattr(path, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, errNotSupported
		}
		return nil, err
	}
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := unix.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	result := make(map[string]string)
	for len(buf) > 0 {
		i := 0
		for i < len(buf) && buf[i] != 0 {
			i++
		}
		name := string(buf[:i])
		if name != "" {
			val, _ := readXattrValue(path, name, maxValueSize)
			if val != "" {
				result[name] = val
			} else {
				result[name] = ""
			}
		}
		if i+1 >= len(buf) {
			break
		}
		buf = buf[i+1:]
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func readXattrValue(path, name string, maxValueSize int) (string, error) {
	if maxValueSize == 0 {
		return "", nil
	}
	size, err := unix.Getxattr(path, name, nil)
	if err != nil {
		return "", err
	}
	if size <= 0 {
		return "", nil
	}
	if maxValueSize > 0 && size > maxValueSize {
		size = maxValueSize
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf[:n]), nil
}
