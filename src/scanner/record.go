package scanner

// FileRecord is the canonical v2 scan result record.
// It is intentionally typed to avoid hot-path map mutation costs.
type FileRecord struct {
	Path                     string                 `json:"path"`
	Name                     string                 `json:"name,omitempty"`
	Size                     int64                  `json:"size,omitempty"`
	ModTime                  string                 `json:"mod_time,omitempty"`
	CreationTime             string                 `json:"creation_time,omitempty"`
	AccessTime               string                 `json:"access_time,omitempty"`
	ChangeTime               string                 `json:"change_time,omitempty"`
	Attributes               []string               `json:"attributes,omitempty"`
	Permissions              string                 `json:"permissions,omitempty"`
	Owner                    string                 `json:"owner,omitempty"`
	FileID                   string                 `json:"file_id,omitempty"`
	MimeType                 string                 `json:"mime_type,omitempty"`
	Hashes                   map[string]string      `json:"hashes,omitempty"`
	FuzzyHashes              map[string]string      `json:"fuzzy_hashes,omitempty"`
	Metadata                 map[string]interface{} `json:"metadata,omitempty"`
	Xattrs                   map[string]string      `json:"xattrs,omitempty"`
	ACL                      string                 `json:"acl,omitempty"`
	AlternateDataStreams     []string               `json:"alternate_data_streams,omitempty"`
	SensitiveData            map[string][]string    `json:"sensitive_data,omitempty"`
	SensitiveDataMatchCounts map[string]int         `json:"sensitive_data_match_counts,omitempty"`
	SensitiveDataTruncated   bool                   `json:"sensitive_data_truncated,omitempty"`
	SearchHits               map[string]int         `json:"search_hits,omitempty"`
}

func (r *FileRecord) HasSignalData() bool {
	if r == nil {
		return false
	}
	return len(r.SensitiveData) > 0 ||
		len(r.SearchHits) > 0 ||
		len(r.FuzzyHashes) > 0 ||
		len(r.Xattrs) > 0 ||
		r.ACL != "" ||
		len(r.AlternateDataStreams) > 0
}
