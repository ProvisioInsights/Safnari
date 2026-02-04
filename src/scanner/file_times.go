package scanner

import (
	"time"

	"github.com/djherbis/times"
)

type FileTimes struct {
	CreationTime string
	AccessTime   string
	ChangeTime   string
}

func fileTimes(path string) (FileTimes, error) {
	ts, err := times.Stat(path)
	if err != nil {
		return FileTimes{}, err
	}
	result := FileTimes{
		AccessTime:   ts.AccessTime().Format(time.RFC3339),
		ChangeTime:   "",
		CreationTime: "",
	}
	if ts.HasChangeTime() {
		result.ChangeTime = ts.ChangeTime().Format(time.RFC3339)
	}
	if ts.HasBirthTime() {
		result.CreationTime = ts.BirthTime().Format(time.RFC3339)
	}
	return result, nil
}
