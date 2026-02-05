package metadata

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"maps"
	"os"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/rwcarlsen/goexif/exif"
)

func ExtractMetadata(path string, mimeType string, maxBytes int64) map[string]interface{} {
	metadata := make(map[string]interface{})

	switch mimeType {
	case "image/jpeg", "image/png":
		meta := extractImageMetadata(path, maxBytes)
		maps.Copy(metadata, meta)
	case "application/pdf":
		meta := extractPDFMetadata(path, maxBytes)
		maps.Copy(metadata, meta)
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		meta := extractDOCXMetadata(path, maxBytes)
		maps.Copy(metadata, meta)
	default:
		// Unsupported MIME type for metadata extraction
	}

	return metadata
}

// extractImageMetadata extracts a subset of EXIF tags from images.
func extractImageMetadata(path string, maxBytes int64) map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var reader io.Reader = f
	if maxBytes > 0 {
		reader = io.LimitReader(f, maxBytes)
	}
	x, err := exif.Decode(reader)
	if err != nil {
		return nil
	}

	meta := make(map[string]interface{})
	if tm, err := x.DateTime(); err == nil {
		meta["datetime"] = tm.Format(time.RFC3339)
	}
	if makeTag, err := x.Get(exif.Make); err == nil {
		meta["make"] = makeTag.String()
	}
	if modelTag, err := x.Get(exif.Model); err == nil {
		meta["model"] = modelTag.String()
	}
	return meta
}

// extractPDFMetadata reads standard PDF document information.
func extractPDFMetadata(path string, maxBytes int64) map[string]interface{} {
	if maxBytes > 0 {
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxBytes {
			return nil
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := api.PDFInfo(f, path, nil, false, nil)
	if err != nil {
		return nil
	}

	meta := make(map[string]interface{})
	if info.Title != "" {
		meta["title"] = info.Title
	}
	if info.Author != "" {
		meta["author"] = info.Author
	}
	if info.Creator != "" {
		meta["creator"] = info.Creator
	}
	if info.Producer != "" {
		meta["producer"] = info.Producer
	}
	return meta
}

// extractDOCXMetadata parses core properties from a DOCX file.
func extractDOCXMetadata(path string, maxBytes int64) map[string]interface{} {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()

	var coreFile *zip.File
	for _, f := range r.File {
		if f.Name == "docProps/core.xml" {
			if maxBytes > 0 && f.UncompressedSize64 > uint64(maxBytes) {
				return nil
			}
			coreFile = f
			break
		}
	}
	if coreFile == nil {
		return nil
	}

	rc, err := coreFile.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()

	type coreProperties struct {
		Title       string `xml:"title"`
		Subject     string `xml:"subject"`
		Creator     string `xml:"creator"`
		Keywords    string `xml:"keywords"`
		Description string `xml:"description"`
	}

	var props coreProperties
	var reader io.Reader = rc
	if maxBytes > 0 {
		reader = io.LimitReader(rc, maxBytes)
	}
	if err := xml.NewDecoder(reader).Decode(&props); err != nil {
		return nil
	}

	meta := make(map[string]interface{})
	if props.Title != "" {
		meta["title"] = props.Title
	}
	if props.Subject != "" {
		meta["subject"] = props.Subject
	}
	if props.Creator != "" {
		meta["creator"] = props.Creator
	}
	if props.Keywords != "" {
		meta["keywords"] = props.Keywords
	}
	if props.Description != "" {
		meta["description"] = props.Description
	}
	return meta
}
