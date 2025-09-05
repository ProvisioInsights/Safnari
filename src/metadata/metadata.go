package metadata

import (
	"archive/zip"
	"encoding/xml"
	"maps"
	"os"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/rwcarlsen/goexif/exif"
)

func ExtractMetadata(path string, mimeType string) map[string]interface{} {
	metadata := make(map[string]interface{})

	switch mimeType {
	case "image/jpeg", "image/png":
		meta := extractImageMetadata(path)
		maps.Copy(metadata, meta)
	case "application/pdf":
		meta := extractPDFMetadata(path)
		maps.Copy(metadata, meta)
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		meta := extractDOCXMetadata(path)
		maps.Copy(metadata, meta)
	default:
		// Unsupported MIME type for metadata extraction
	}

	return metadata
}

// extractImageMetadata extracts a subset of EXIF tags from images.
func extractImageMetadata(path string) map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	x, err := exif.Decode(f)
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
func extractPDFMetadata(path string) map[string]interface{} {
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
func extractDOCXMetadata(path string) map[string]interface{} {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()

	var coreFile *zip.File
	for _, f := range r.File {
		if f.Name == "docProps/core.xml" {
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
	if err := xml.NewDecoder(rc).Decode(&props); err != nil {
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
