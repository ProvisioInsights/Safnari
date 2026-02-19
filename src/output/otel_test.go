package output

import (
	"testing"

	"safnari/config"

	otelLog "go.opentelemetry.io/otel/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

func findAttr(kvs []otelLog.KeyValue, key string) (otelLog.Value, bool) {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return otelLog.Value{}, false
}

func findAttrIndex(kvs []otelLog.KeyValue, key string) int {
	for i, kv := range kvs {
		if kv.Key == key {
			return i
		}
	}
	return -1
}

func TestResolveOtelEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "https://logs.example.test/v1/logs")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://fallback.example.test")

	cfg := &config.Config{OtelEndpoint: "  https://explicit.example.test  ", OtelFromEnv: true}
	if got := resolveOtelEndpoint(cfg); got != "https://explicit.example.test" {
		t.Fatalf("expected explicit endpoint, got %q", got)
	}

	cfg = &config.Config{OtelFromEnv: true}
	if got := resolveOtelEndpoint(cfg); got != "https://logs.example.test/v1/logs" {
		t.Fatalf("expected logs env endpoint, got %q", got)
	}

	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	cfg = &config.Config{OtelFromEnv: true}
	if got := resolveOtelEndpoint(cfg); got != "https://fallback.example.test" {
		t.Fatalf("expected fallback env endpoint, got %q", got)
	}

	cfg = &config.Config{OtelFromEnv: false}
	if got := resolveOtelEndpoint(cfg); got != "" {
		t.Fatalf("expected empty endpoint when env fallback disabled, got %q", got)
	}
}

func TestSanitizePayloadFileAndProcess(t *testing.T) {
	filePayload := map[string]interface{}{
		"path":           "/tmp/secret.txt",
		"sensitive_data": map[string]interface{}{"email": []string{"a@example.com"}},
		"search_hits":    map[string]interface{}{"token": 1},
		"name":           "secret.txt",
	}
	fileSanitized, ok := sanitizePayload("file", filePayload, otelPolicy{}).(map[string]interface{})
	if !ok {
		t.Fatalf("expected sanitized file payload map")
	}
	if _, ok := fileSanitized["path"]; ok {
		t.Fatal("expected file path to be stripped")
	}
	if _, ok := fileSanitized["sensitive_data"]; ok {
		t.Fatal("expected sensitive_data to be stripped")
	}
	if _, ok := fileSanitized["search_hits"]; ok {
		t.Fatal("expected search_hits to be stripped")
	}
	if _, ok := filePayload["path"]; !ok {
		t.Fatal("expected original file payload to remain unchanged")
	}

	processPayload := map[string]interface{}{
		"name":    "proc",
		"exe":     "/usr/bin/proc",
		"cmdline": "proc --secret",
	}
	processSanitized, ok := sanitizePayload("process", processPayload, otelPolicy{}).(map[string]interface{})
	if !ok {
		t.Fatalf("expected sanitized process payload map")
	}
	if _, ok := processSanitized["exe"]; ok {
		t.Fatal("expected exe path to be stripped")
	}
	if _, ok := processSanitized["cmdline"]; ok {
		t.Fatal("expected cmdline to be stripped")
	}
}

func TestSanitizePayloadSystemInfo(t *testing.T) {
	systemPayload := map[string]interface{}{
		"os_version":         "macOS 26.2",
		"users":              []string{"alice", "bob"},
		"installed_patches":  []interface{}{"p1"},
		"running_services":   []map[string]interface{}{{"name": "svc"}},
		"network_interfaces": []interface{}{"en0", "lo0"},
	}

	sanitized, ok := sanitizePayload("system_info", systemPayload, otelPolicy{}).(map[string]interface{})
	if !ok {
		t.Fatalf("expected sanitized system payload map")
	}
	if _, ok := sanitized["users"]; ok {
		t.Fatal("expected users list to be omitted")
	}
	if got, ok := sanitized["users_count"]; !ok || got != 2 {
		t.Fatalf("expected users_count=2, got %#v", got)
	}
	if got, ok := sanitized["installed_patches_count"]; !ok || got != 1 {
		t.Fatalf("expected installed_patches_count=1, got %#v", got)
	}
	if got, ok := sanitized["running_services_count"]; !ok || got != 1 {
		t.Fatalf("expected running_services_count=1, got %#v", got)
	}
}

func TestSemanticAttributesFile(t *testing.T) {
	payload := map[string]interface{}{
		"path":           "/tmp/dir/report.txt",
		"size":           int64(42),
		"attributes":     []string{"hidden", "read-only"},
		"hashes":         map[string]string{"sha256": "abc123"},
		"sensitive_data": map[string]interface{}{"email": []string{"a@example.com"}},
	}

	attrs := semanticAttributes("file", payload, otelPolicy{includePaths: true, includeSensitive: true})
	if value, ok := findAttr(attrs, string(semconv.FilePathKey)); !ok || value.AsString() != "/tmp/dir/report.txt" {
		t.Fatalf("expected file path semantic attribute, got %#v", value)
	}
	if value, ok := findAttr(attrs, string(semconv.FileNameKey)); !ok || value.AsString() != "report.txt" {
		t.Fatalf("expected file name semantic attribute, got %#v", value)
	}
	if value, ok := findAttr(attrs, string(semconv.FileSizeKey)); !ok || value.AsInt64() != 42 {
		t.Fatalf("expected file size semantic attribute, got %#v", value)
	}
	if _, ok := findAttr(attrs, "safnari.file.hash.sha256"); !ok {
		t.Fatal("expected hash semantic attribute")
	}
	if _, ok := findAttr(attrs, "safnari.file.sensitive_data"); !ok {
		t.Fatal("expected sensitive data semantic attribute when enabled")
	}

	attrsNoPaths := semanticAttributes("file", payload, otelPolicy{includePaths: false})
	if _, ok := findAttr(attrsNoPaths, string(semconv.FilePathKey)); ok {
		t.Fatal("did not expect file path semantic attribute when paths are disabled")
	}
	if _, ok := findAttr(attrsNoPaths, "safnari.file.sensitive_data"); ok {
		t.Fatal("did not expect sensitive data semantic attribute when sensitive export is disabled")
	}
}

func TestSemanticAttributesSystemInfoCounts(t *testing.T) {
	payload := map[string]interface{}{
		"os_version":      "linux-6.12",
		"users":           []string{"alice", "bob", "carol"},
		"scheduled_tasks": []interface{}{"task-a"},
	}

	attrs := semanticAttributes("system_info", payload, otelPolicy{})
	if value, ok := findAttr(attrs, string(semconv.OSDescriptionKey)); !ok || value.AsString() != "linux-6.12" {
		t.Fatalf("expected os description semantic attribute, got %#v", value)
	}
	if value, ok := findAttr(attrs, "safnari.system.users_count"); !ok || value.AsInt64() != 3 {
		t.Fatalf("expected users count semantic attribute, got %#v", value)
	}
	if _, ok := findAttr(attrs, "safnari.system.users"); ok {
		t.Fatal("did not expect raw users semantic attribute when sensitive export is disabled")
	}

	attrsSensitive := semanticAttributes("system_info", payload, otelPolicy{includeSensitive: true})
	if _, ok := findAttr(attrsSensitive, "safnari.system.users"); !ok {
		t.Fatal("expected raw users semantic attribute when sensitive export is enabled")
	}
}

func TestPayloadToMapFromStruct(t *testing.T) {
	payload := Metrics{
		StartTime:      "2026-02-18T00:00:00Z",
		TotalFiles:     7,
		FilesScanned:   6,
		FilesProcessed: 5,
		TotalProcesses: 4,
	}
	data := payloadToMap(payload)
	if data == nil {
		t.Fatal("expected payloadToMap to decode struct payload")
	}
	if got := getStringField(data, "start_time"); got != payload.StartTime {
		t.Fatalf("expected start_time=%q, got %q", payload.StartTime, got)
	}
	if got, ok := getInt64Field(data, "total_files"); !ok || got != 7 {
		t.Fatalf("expected total_files=7, got %d (ok=%v)", got, ok)
	}
}

func TestSemanticAttributesProcess(t *testing.T) {
	payload := map[string]interface{}{
		"pid":            int64(101),
		"ppid":           int64(99),
		"name":           "safnari",
		"exe":            "/usr/local/bin/safnari",
		"cmdline":        "safnari --scan",
		"username":       "alice",
		"start_time":     "2026-02-18T00:00:00Z",
		"cpu_percent":    12.5,
		"memory_percent": 3.75,
	}

	attrs := semanticAttributes("process", payload, otelPolicy{includePaths: true, includeCmdline: true})
	if value, ok := findAttr(attrs, string(semconv.ProcessPIDKey)); !ok || value.AsInt64() != 101 {
		t.Fatalf("expected process pid semantic attribute, got %#v", value)
	}
	if value, ok := findAttr(attrs, string(semconv.ProcessExecutablePathKey)); !ok || value.AsString() != "/usr/local/bin/safnari" {
		t.Fatalf("expected process executable path semantic attribute, got %#v", value)
	}
	if _, ok := findAttr(attrs, string(semconv.ProcessCommandLineKey)); !ok {
		t.Fatal("expected process command line semantic attribute")
	}
	if value, ok := findAttr(attrs, "safnari.process.cpu_percent"); !ok || value.AsFloat64() != 12.5 {
		t.Fatalf("expected process cpu semantic attribute, got %#v", value)
	}

	attrsNoPaths := semanticAttributes("process", payload, otelPolicy{})
	if _, ok := findAttr(attrsNoPaths, string(semconv.ProcessExecutablePathKey)); ok {
		t.Fatal("did not expect process executable path semantic attribute when paths are disabled")
	}
	if _, ok := findAttr(attrsNoPaths, string(semconv.ProcessCommandLineKey)); ok {
		t.Fatal("did not expect process command line semantic attribute when cmdline is disabled")
	}
}

func TestSemanticAttributesMetrics(t *testing.T) {
	payload := map[string]interface{}{
		"start_time":      "2026-02-18T00:00:00Z",
		"end_time":        "2026-02-18T00:01:00Z",
		"total_files":     int64(11),
		"files_scanned":   int64(10),
		"files_processed": int64(9),
		"total_processes": int64(8),
	}

	attrs := semanticAttributes("metrics", payload, otelPolicy{})
	if _, ok := findAttr(attrs, "safnari.metrics.start_time"); !ok {
		t.Fatal("expected metrics start_time semantic attribute")
	}
	if value, ok := findAttr(attrs, "safnari.metrics.total_files"); !ok || value.AsInt64() != 11 {
		t.Fatalf("expected metrics total_files semantic attribute, got %#v", value)
	}
	if value, ok := findAttr(attrs, "safnari.metrics.total_processes"); !ok || value.AsInt64() != 8 {
		t.Fatalf("expected metrics total_processes semantic attribute, got %#v", value)
	}
}

func TestToLogValueCompositeTypes(t *testing.T) {
	mapValue := toLogValue(map[string]string{"a": "b"})
	if mapValue.Kind() != otelLog.KindMap {
		t.Fatalf("expected map kind, got %v", mapValue.Kind())
	}
	intSliceValue := toLogValue([]int{1, 2, 3})
	if intSliceValue.Kind() != otelLog.KindSlice || len(intSliceValue.AsSlice()) != 3 {
		t.Fatalf("expected int slice kind/len, got kind=%v len=%d", intSliceValue.Kind(), len(intSliceValue.AsSlice()))
	}
	if empty := toLogValue(struct{}{}); empty.Kind() != otelLog.KindEmpty {
		t.Fatalf("expected empty kind for unsupported type, got %v", empty.Kind())
	}
}

func TestOtelLoggerEndpointAndValidation(t *testing.T) {
	var nilLogger *otelLogger
	if got := nilLogger.Endpoint(); got != "" {
		t.Fatalf("expected empty endpoint for nil logger, got %q", got)
	}

	ol := &otelLogger{endpoint: "https://otel.example.test"}
	if got := ol.Endpoint(); got != "https://otel.example.test" {
		t.Fatalf("unexpected endpoint from logger: %q", got)
	}

	loggerNilCfg, err := newOtelLogger(nil)
	if err != nil {
		t.Fatalf("newOtelLogger(nil) returned error: %v", err)
	}
	if loggerNilCfg != nil {
		t.Fatal("expected nil logger for nil config")
	}

	_, err = newOtelLogger(&config.Config{
		OtelEndpoint:    "localhost:4318",
		OtelServiceName: "safnari",
		OtelTimeout:     1,
	})
	if err == nil {
		t.Fatal("expected validation error for endpoint without scheme")
	}
}

func TestToLogKeyValuesSortedOrder(t *testing.T) {
	values := map[string]interface{}{
		"zeta":   1,
		"alpha":  2,
		"middle": 3,
	}
	kvs := toLogKeyValues(values)
	if len(kvs) != 3 {
		t.Fatalf("expected 3 key values, got %d", len(kvs))
	}
	if kvs[0].Key != "alpha" || kvs[1].Key != "middle" || kvs[2].Key != "zeta" {
		t.Fatalf("expected sorted keys, got order %q, %q, %q", kvs[0].Key, kvs[1].Key, kvs[2].Key)
	}
}

func TestFileSemanticAttributesHashOrderDeterministic(t *testing.T) {
	payload := map[string]interface{}{
		"path": "/tmp/hash-order.txt",
		"hashes": map[string]string{
			"sha256": "bbb",
			"md5":    "aaa",
		},
		"fuzzy_hashes": map[string]string{
			"ssdeep": "ddd",
			"tlsh":   "ccc",
		},
	}
	attrs := fileSemanticAttributes(payload, otelPolicy{includePaths: true})

	md5Idx := findAttrIndex(attrs, "safnari.file.hash.md5")
	shaIdx := findAttrIndex(attrs, "safnari.file.hash.sha256")
	if md5Idx == -1 || shaIdx == -1 {
		t.Fatalf("expected both md5 and sha256 attrs, got attrs=%v", attrs)
	}
	if md5Idx > shaIdx {
		t.Fatalf("expected md5 attr before sha256 attr, got md5=%d sha256=%d", md5Idx, shaIdx)
	}

	tlshIdx := findAttrIndex(attrs, "safnari.file.fuzzy_hash.tlsh")
	ssdeepIdx := findAttrIndex(attrs, "safnari.file.fuzzy_hash.ssdeep")
	if tlshIdx == -1 || ssdeepIdx == -1 {
		t.Fatalf("expected both fuzzy hash attrs, got attrs=%v", attrs)
	}
	if ssdeepIdx > tlshIdx {
		t.Fatalf("expected ssdeep attr before tlsh attr, got ssdeep=%d tlsh=%d", ssdeepIdx, tlshIdx)
	}
}
