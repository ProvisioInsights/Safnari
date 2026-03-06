package fuzzy

import (
	"bufio"
	"os"

	"github.com/glaslos/tlsh"
)

type TLSHHasher struct{}

func (h TLSHHasher) Name() string {
	return "tlsh"
}

func (h TLSHHasher) HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	hash, err := tlsh.HashReader(reader)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

func (h TLSHHasher) HashBytes(content []byte) (string, error) {
	hash, err := tlsh.HashBytes(content)
	if err != nil {
		return "", err
	}
	if hash == nil {
		return "", nil
	}
	return hash.String(), nil
}

func init() {
	Register(TLSHHasher{})
}
