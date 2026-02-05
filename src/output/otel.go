package output

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"safnari/config"
	"safnari/logger"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otelLog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

type otelLogger struct {
	provider *sdklog.LoggerProvider
	logger   otelLog.Logger
	timeout  time.Duration
	endpoint string
	policy   otelPolicy
}

type otelPolicy struct {
	includePaths     bool
	includeSensitive bool
	includeCmdline   bool
}

func newOtelLogger(cfg *config.Config) (*otelLogger, error) {
	if cfg == nil {
		return nil, nil
	}
	endpoint := resolveOtelEndpoint(cfg)
	if endpoint == "" {
		return nil, nil
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("otel endpoint must include scheme (http or https)")
	}

	opts := []otlploghttp.Option{otlploghttp.WithEndpointURL(endpoint)}
	if len(cfg.OtelHeaders) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(cfg.OtelHeaders))
	}
	if cfg.OtelTimeout > 0 {
		opts = append(opts, otlploghttp.WithTimeout(cfg.OtelTimeout))
	}

	exp, err := otlploghttp.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(cfg.OtelServiceName),
	)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		sdklog.WithResource(res),
	)

	return &otelLogger{
		provider: provider,
		logger:   provider.Logger("safnari"),
		timeout:  cfg.OtelTimeout,
		endpoint: endpoint,
		policy: otelPolicy{
			includePaths:     cfg.OtelExportPaths,
			includeSensitive: cfg.OtelExportSensitive,
			includeCmdline:   cfg.OtelExportCmdline,
		},
	}, nil
}

func resolveOtelEndpoint(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if endpoint := strings.TrimSpace(cfg.OtelEndpoint); endpoint != "" {
		return endpoint
	}
	if !cfg.OtelFromEnv {
		return ""
	}
	if endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")); endpoint != "" {
		return endpoint
	}
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
}

func (o *otelLogger) Endpoint() string {
	if o == nil {
		return ""
	}
	return o.endpoint
}

func (o *otelLogger) Emit(recordType string, payload interface{}) {
	if o == nil || o.logger == nil {
		return
	}
	safePayload := sanitizePayload(recordType, payload, o.policy)

	var record otelLog.Record
	record.SetTimestamp(time.Now())
	record.SetObservedTimestamp(time.Now())
	record.SetEventName("safnari.record")
	record.AddAttributes(
		otelLog.String("record_type", recordType),
		otelLog.String("schema_version", SchemaVersion),
	)
	if attrs := semanticAttributes(recordType, safePayload, o.policy); len(attrs) > 0 {
		record.AddAttributes(attrs...)
	}

	value := toLogValue(safePayload)
	if value.Kind() == otelLog.KindEmpty {
		if data, err := json.Marshal(safePayload); err == nil {
			var decoded interface{}
			if err := json.Unmarshal(data, &decoded); err == nil {
				decodedValue := toLogValue(decoded)
				if decodedValue.Kind() != otelLog.KindEmpty {
					record.SetBody(decodedValue)
				} else {
					record.SetBody(otelLog.StringValue(string(data)))
				}
			} else {
				record.SetBody(otelLog.StringValue(string(data)))
			}
		}
	} else {
		record.SetBody(value)
	}

	o.logger.Emit(context.Background(), record)
}

func (o *otelLogger) Shutdown() {
	if o == nil || o.provider == nil {
		return
	}
	timeout := o.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := o.provider.Shutdown(ctx); err != nil {
		logger.Debugf("OTEL shutdown failed: %v", err)
	}
}

func sanitizePayload(recordType string, payload interface{}, policy otelPolicy) interface{} {
	data := payloadToMap(payload)
	if len(data) == 0 {
		return payload
	}

	switch recordType {
	case "file":
		sanitized := cloneMap(data)
		if !policy.includePaths {
			delete(sanitized, "path")
		}
		if !policy.includeSensitive {
			delete(sanitized, "sensitive_data")
			delete(sanitized, "search_hits")
		}
		return sanitized
	case "process":
		sanitized := cloneMap(data)
		if !policy.includeCmdline {
			delete(sanitized, "cmdline")
		}
		if !policy.includePaths {
			delete(sanitized, "exe")
		}
		return sanitized
	case "system_info":
		if policy.includeSensitive {
			return data
		}
		sanitized := map[string]interface{}{}
		if osVersion := getFieldValue(data, "os_version"); osVersion != nil {
			sanitized["os_version"] = osVersion
		}
		addSliceCount(sanitized, "installed_patches_count", getFieldValue(data, "installed_patches"))
		addSliceCount(sanitized, "startup_programs_count", getFieldValue(data, "startup_programs"))
		addSliceCount(sanitized, "installed_apps_count", getFieldValue(data, "installed_apps"))
		addSliceCount(sanitized, "network_interfaces_count", getFieldValue(data, "network_interfaces"))
		addSliceCount(sanitized, "open_connections_count", getFieldValue(data, "open_connections"))
		addSliceCount(sanitized, "running_services_count", getFieldValue(data, "running_services"))
		addSliceCount(sanitized, "users_count", getFieldValue(data, "users"))
		addSliceCount(sanitized, "groups_count", getFieldValue(data, "groups"))
		addSliceCount(sanitized, "admins_count", getFieldValue(data, "admins"))
		addSliceCount(sanitized, "scheduled_tasks_count", getFieldValue(data, "scheduled_tasks"))
		addSliceCount(sanitized, "running_processes_count", getFieldValue(data, "running_processes"))
		return sanitized
	default:
		return payload
	}
}

func addSliceCount(dst map[string]interface{}, key string, value interface{}) {
	if count, ok := valueCount(value); ok {
		dst[key] = count
	}
}

func valueCount(value interface{}) (int, bool) {
	switch v := value.(type) {
	case []interface{}:
		return len(v), true
	case []string:
		return len(v), true
	case []map[string]interface{}:
		return len(v), true
	default:
		return 0, false
	}
}

func cloneMap(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func toLogValue(value interface{}) otelLog.Value {
	switch v := value.(type) {
	case nil:
		return otelLog.Value{}
	case string:
		return otelLog.StringValue(v)
	case []byte:
		return otelLog.BytesValue(v)
	case bool:
		return otelLog.BoolValue(v)
	case int:
		return otelLog.IntValue(v)
	case int64:
		return otelLog.Int64Value(v)
	case float64:
		return otelLog.Float64Value(v)
	case float32:
		return otelLog.Float64Value(float64(v))
	case map[string]interface{}:
		return otelLog.MapValue(toLogKeyValues(v)...)
	case map[string]string:
		kvs := make([]otelLog.KeyValue, 0, len(v))
		for k, val := range v {
			kvs = append(kvs, otelLog.String(k, val))
		}
		return otelLog.MapValue(kvs...)
	case []string:
		values := make([]otelLog.Value, 0, len(v))
		for _, item := range v {
			values = append(values, otelLog.StringValue(item))
		}
		return otelLog.SliceValue(values...)
	case []int:
		values := make([]otelLog.Value, 0, len(v))
		for _, item := range v {
			values = append(values, otelLog.IntValue(item))
		}
		return otelLog.SliceValue(values...)
	case []int64:
		values := make([]otelLog.Value, 0, len(v))
		for _, item := range v {
			values = append(values, otelLog.Int64Value(item))
		}
		return otelLog.SliceValue(values...)
	case []float64:
		values := make([]otelLog.Value, 0, len(v))
		for _, item := range v {
			values = append(values, otelLog.Float64Value(item))
		}
		return otelLog.SliceValue(values...)
	case []bool:
		values := make([]otelLog.Value, 0, len(v))
		for _, item := range v {
			values = append(values, otelLog.BoolValue(item))
		}
		return otelLog.SliceValue(values...)
	case []interface{}:
		values := make([]otelLog.Value, 0, len(v))
		for _, item := range v {
			values = append(values, toLogValue(item))
		}
		return otelLog.SliceValue(values...)
	default:
		_ = v
		return otelLog.Value{}
	}
}

func toLogKeyValues(values map[string]interface{}) []otelLog.KeyValue {
	kvs := make([]otelLog.KeyValue, 0, len(values))
	for key, value := range values {
		kvs = append(kvs, otelLog.KeyValue{Key: key, Value: toLogValue(value)})
	}
	return kvs
}

func semanticAttributes(recordType string, payload interface{}, policy otelPolicy) []otelLog.KeyValue {
	data := payloadToMap(payload)
	if len(data) == 0 {
		return nil
	}

	switch recordType {
	case "file":
		return fileSemanticAttributes(data, policy)
	case "process":
		return processSemanticAttributes(data, policy)
	case "system_info":
		return systemSemanticAttributes(data, policy)
	case "metrics":
		return metricsSemanticAttributes(data)
	default:
		return nil
	}
}

func fileSemanticAttributes(data map[string]interface{}, policy otelPolicy) []otelLog.KeyValue {
	var kvs []otelLog.KeyValue

	path := getStringField(data, "path")
	name := getStringField(data, "name")
	if name == "" && path != "" {
		name = filepath.Base(path)
	}
	if policy.includePaths && path != "" {
		kvs = append(kvs, otelLog.String(string(semconv.FilePathKey), path))
		kvs = append(kvs, otelLog.String(string(semconv.FileDirectoryKey), filepath.Dir(path)))
		ext := strings.TrimPrefix(filepath.Ext(path), ".")
		if ext != "" {
			kvs = append(kvs, otelLog.String(string(semconv.FileExtensionKey), ext))
		}
	}
	if name != "" {
		kvs = append(kvs, otelLog.String(string(semconv.FileNameKey), name))
	}
	if size, ok := getInt64Field(data, "size"); ok {
		kvs = append(kvs, otelLog.Int64(string(semconv.FileSizeKey), size))
	}

	kvs = appendStringAttr(kvs, "safnari.file.mime_type", getStringField(data, "mime_type"))
	kvs = appendStringAttr(kvs, "safnari.file.mod_time", getStringField(data, "mod_time"))
	kvs = appendStringAttr(kvs, "safnari.file.creation_time", getStringField(data, "creation_time"))
	kvs = appendStringAttr(kvs, "safnari.file.access_time", getStringField(data, "access_time"))
	kvs = appendStringAttr(kvs, "safnari.file.change_time", getStringField(data, "change_time"))
	kvs = appendStringAttr(kvs, "safnari.file.permissions", getStringField(data, "permissions"))
	kvs = appendStringAttr(kvs, "safnari.file.owner", getStringField(data, "owner"))
	kvs = appendStringAttr(kvs, "safnari.file.id", getStringField(data, "file_id"))

	if attrs := getStringSliceField(data, "attributes"); len(attrs) > 0 {
		values := make([]otelLog.Value, 0, len(attrs))
		for _, item := range attrs {
			values = append(values, otelLog.StringValue(item))
		}
		kvs = append(kvs, otelLog.KeyValue{Key: "safnari.file.attributes", Value: otelLog.SliceValue(values...)})
	}

	if hashes := getStringMapField(data, "hashes"); len(hashes) > 0 {
		kvs = append(kvs, otelLog.KeyValue{Key: "safnari.file.hashes", Value: toLogValue(hashes)})
		for algo, value := range hashes {
			if value == "" {
				continue
			}
			kvs = append(kvs, otelLog.String(fmt.Sprintf("safnari.file.hash.%s", algo), value))
		}
	}

	if hashes := getStringMapField(data, "fuzzy_hashes"); len(hashes) > 0 {
		kvs = append(kvs, otelLog.KeyValue{Key: "safnari.file.fuzzy_hashes", Value: toLogValue(hashes)})
		for algo, value := range hashes {
			if value == "" {
				continue
			}
			kvs = append(kvs, otelLog.String(fmt.Sprintf("safnari.file.fuzzy_hash.%s", algo), value))
		}
	}

	kvs = appendInterfaceAttr(kvs, "safnari.file.metadata", getFieldValue(data, "metadata"))
	kvs = appendInterfaceAttr(kvs, "safnari.file.xattrs", getFieldValue(data, "xattrs"))
	kvs = appendInterfaceAttr(kvs, "safnari.file.acl", getFieldValue(data, "acl"))
	kvs = appendInterfaceAttr(kvs, "safnari.file.alternate_data_streams", getFieldValue(data, "alternate_data_streams"))
	if policy.includeSensitive {
		kvs = appendInterfaceAttr(kvs, "safnari.file.sensitive_data", getFieldValue(data, "sensitive_data"))
		kvs = appendInterfaceAttr(kvs, "safnari.file.search_hits", getFieldValue(data, "search_hits"))
	}

	return kvs
}

func processSemanticAttributes(data map[string]interface{}, policy otelPolicy) []otelLog.KeyValue {
	var kvs []otelLog.KeyValue

	if pid, ok := getInt64Field(data, "pid"); ok {
		kvs = append(kvs, otelLog.Int64(string(semconv.ProcessPIDKey), pid))
	}
	if ppid, ok := getInt64Field(data, "ppid"); ok {
		kvs = append(kvs, otelLog.Int64(string(semconv.ProcessParentPIDKey), ppid))
	}

	name := getStringField(data, "name")
	exe := getStringField(data, "exe")
	if name != "" {
		kvs = append(kvs, otelLog.String(string(semconv.ProcessExecutableNameKey), name))
	}
	if policy.includePaths && exe != "" {
		kvs = append(kvs, otelLog.String(string(semconv.ProcessExecutablePathKey), exe))
	}
	if policy.includeCmdline {
		kvs = appendStringAttr(kvs, string(semconv.ProcessCommandLineKey), getStringField(data, "cmdline"))
	}
	kvs = appendStringAttr(kvs, string(semconv.ProcessOwnerKey), getStringField(data, "username"))
	kvs = appendStringAttr(kvs, string(semconv.ProcessCreationTimeKey), getStringField(data, "start_time"))

	if cpu, ok := getFloat64Field(data, "cpu_percent"); ok {
		kvs = append(kvs, otelLog.Float64("safnari.process.cpu_percent", cpu))
	}
	if mem, ok := getFloat64Field(data, "memory_percent"); ok {
		kvs = append(kvs, otelLog.Float64("safnari.process.memory_percent", mem))
	}

	return kvs
}

func systemSemanticAttributes(data map[string]interface{}, policy otelPolicy) []otelLog.KeyValue {
	var kvs []otelLog.KeyValue

	osVersion := getStringField(data, "os_version")
	if osVersion != "" {
		kvs = append(kvs, otelLog.String(string(semconv.OSDescriptionKey), osVersion))
		kvs = append(kvs, otelLog.String(string(semconv.OSVersionKey), osVersion))
	}

	if policy.includeSensitive {
		kvs = appendInterfaceAttr(kvs, "safnari.system.installed_patches", getFieldValue(data, "installed_patches"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.startup_programs", getFieldValue(data, "startup_programs"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.installed_apps", getFieldValue(data, "installed_apps"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.network_interfaces", getFieldValue(data, "network_interfaces"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.open_connections", getFieldValue(data, "open_connections"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.running_services", getFieldValue(data, "running_services"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.users", getFieldValue(data, "users"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.groups", getFieldValue(data, "groups"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.admins", getFieldValue(data, "admins"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.scheduled_tasks", getFieldValue(data, "scheduled_tasks"))
		kvs = appendInterfaceAttr(kvs, "safnari.system.running_processes", getFieldValue(data, "running_processes"))
	}

	kvs = appendCountAttr(
		kvs,
		"safnari.system.installed_patches_count",
		getCountFieldOrSliceLength(data, "installed_patches_count", "installed_patches"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.startup_programs_count",
		getCountFieldOrSliceLength(data, "startup_programs_count", "startup_programs"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.installed_apps_count",
		getCountFieldOrSliceLength(data, "installed_apps_count", "installed_apps"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.network_interfaces_count",
		getCountFieldOrSliceLength(data, "network_interfaces_count", "network_interfaces"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.open_connections_count",
		getCountFieldOrSliceLength(data, "open_connections_count", "open_connections"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.running_services_count",
		getCountFieldOrSliceLength(data, "running_services_count", "running_services"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.users_count",
		getCountFieldOrSliceLength(data, "users_count", "users"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.groups_count",
		getCountFieldOrSliceLength(data, "groups_count", "groups"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.admins_count",
		getCountFieldOrSliceLength(data, "admins_count", "admins"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.scheduled_tasks_count",
		getCountFieldOrSliceLength(data, "scheduled_tasks_count", "scheduled_tasks"),
	)
	kvs = appendCountAttr(
		kvs,
		"safnari.system.running_processes_count",
		getCountFieldOrSliceLength(data, "running_processes_count", "running_processes"),
	)

	return kvs
}

func metricsSemanticAttributes(data map[string]interface{}) []otelLog.KeyValue {
	var kvs []otelLog.KeyValue

	kvs = appendStringAttr(kvs, "safnari.metrics.start_time", getStringField(data, "start_time"))
	kvs = appendStringAttr(kvs, "safnari.metrics.end_time", getStringField(data, "end_time"))
	if totalFiles, ok := getInt64Field(data, "total_files"); ok {
		kvs = appendInt64Attr(kvs, "safnari.metrics.total_files", totalFiles, ok)
	}
	if filesScanned, ok := getInt64Field(data, "files_scanned"); ok {
		kvs = appendInt64Attr(kvs, "safnari.metrics.files_scanned", filesScanned, ok)
	}
	if filesProcessed, ok := getInt64Field(data, "files_processed"); ok {
		kvs = appendInt64Attr(kvs, "safnari.metrics.files_processed", filesProcessed, ok)
	}
	if totalProcesses, ok := getInt64Field(data, "total_processes"); ok {
		kvs = appendInt64Attr(kvs, "safnari.metrics.total_processes", totalProcesses, ok)
	}

	return kvs
}

func payloadToMap(payload interface{}) map[string]interface{} {
	switch v := payload.(type) {
	case map[string]interface{}:
		return v
	case map[string]string:
		out := make(map[string]interface{}, len(v))
		for key, value := range v {
			out[key] = value
		}
		return out
	default:
		data, err := json.Marshal(payload)
		if err != nil {
			return nil
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil
		}
		return decoded
	}
}

func getFieldValue(values map[string]interface{}, key string) interface{} {
	if values == nil {
		return nil
	}
	return values[key]
}

func getStringField(values map[string]interface{}, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func getInt64Field(values map[string]interface{}, key string) (int64, bool) {
	value, ok := values[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case float32:
		return int64(v), true
	case json.Number:
		if parsed, err := v.Int64(); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func getFloat64Field(values map[string]interface{}, key string) (float64, bool) {
	value, ok := values[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		if parsed, err := v.Float64(); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func getStringSliceField(values map[string]interface{}, key string) []string {
	value, ok := values[key]
	if !ok || value == nil {
		return nil
	}
	switch v := value.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item == nil {
				continue
			}
			out = append(out, fmt.Sprint(item))
		}
		return out
	default:
		return nil
	}
}

func getStringMapField(values map[string]interface{}, key string) map[string]string {
	value, ok := values[key]
	if !ok || value == nil {
		return nil
	}
	switch v := value.(type) {
	case map[string]string:
		return v
	case map[string]interface{}:
		out := make(map[string]string, len(v))
		for k, val := range v {
			if val == nil {
				continue
			}
			out[k] = fmt.Sprint(val)
		}
		return out
	default:
		return nil
	}
}

func getSliceLength(values map[string]interface{}, key string) int64 {
	value, ok := values[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case []interface{}:
		return int64(len(v))
	case []string:
		return int64(len(v))
	default:
		return 0
	}
}

func getCountFieldOrSliceLength(values map[string]interface{}, countKey, sliceKey string) int64 {
	if count, ok := getInt64Field(values, countKey); ok {
		return count
	}
	return getSliceLength(values, sliceKey)
}

func appendStringAttr(kvs []otelLog.KeyValue, key, value string) []otelLog.KeyValue {
	if value == "" {
		return kvs
	}
	return append(kvs, otelLog.String(key, value))
}

func appendInt64Attr(kvs []otelLog.KeyValue, key string, value int64, ok bool) []otelLog.KeyValue {
	if !ok {
		return kvs
	}
	return append(kvs, otelLog.Int64(key, value))
}

func appendCountAttr(kvs []otelLog.KeyValue, key string, count int64) []otelLog.KeyValue {
	if count <= 0 {
		return kvs
	}
	return append(kvs, otelLog.Int64(key, count))
}

func appendInterfaceAttr(kvs []otelLog.KeyValue, key string, value interface{}) []otelLog.KeyValue {
	if value == nil {
		return kvs
	}
	converted := toLogValue(value)
	if converted.Kind() == otelLog.KindEmpty {
		return kvs
	}
	return append(kvs, otelLog.KeyValue{Key: key, Value: converted})
}
