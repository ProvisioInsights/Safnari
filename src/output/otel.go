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
}

func newOtelLogger(cfg *config.Config) (*otelLogger, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.OtelEndpoint == "" && os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") == "" &&
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return nil, nil
	}

	opts := []otlploghttp.Option{}
	if cfg.OtelEndpoint != "" {
		opts = append(opts, otlploghttp.WithEndpointURL(cfg.OtelEndpoint))
	}
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
	}, nil
}

func (o *otelLogger) Emit(recordType string, payload interface{}) {
	if o == nil || o.logger == nil {
		return
	}
	var record otelLog.Record
	record.SetTimestamp(time.Now())
	record.SetObservedTimestamp(time.Now())
	record.SetEventName("safnari.record")
	record.AddAttributes(
		otelLog.String("record_type", recordType),
		otelLog.String("schema_version", SchemaVersion),
	)
	if attrs := semanticAttributes(recordType, payload); len(attrs) > 0 {
		record.AddAttributes(attrs...)
	}

	value := toLogValue(payload)
	if value.Kind() == otelLog.KindEmpty {
		if data, err := json.Marshal(payload); err == nil {
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

func semanticAttributes(recordType string, payload interface{}) []otelLog.KeyValue {
	data := payloadToMap(payload)
	if len(data) == 0 {
		return nil
	}

	switch recordType {
	case "file":
		return fileSemanticAttributes(data)
	case "process":
		return processSemanticAttributes(data)
	case "system_info":
		return systemSemanticAttributes(data)
	case "metrics":
		return metricsSemanticAttributes(data)
	default:
		return nil
	}
}

func fileSemanticAttributes(data map[string]interface{}) []otelLog.KeyValue {
	var kvs []otelLog.KeyValue

	path := getStringField(data, "path")
	name := getStringField(data, "name")
	if name == "" && path != "" {
		name = filepath.Base(path)
	}
	if path != "" {
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
	kvs = appendInterfaceAttr(kvs, "safnari.file.sensitive_data", getFieldValue(data, "sensitive_data"))
	kvs = appendInterfaceAttr(kvs, "safnari.file.search_hits", getFieldValue(data, "search_hits"))

	return kvs
}

func processSemanticAttributes(data map[string]interface{}) []otelLog.KeyValue {
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
	if exe != "" {
		kvs = append(kvs, otelLog.String(string(semconv.ProcessExecutablePathKey), exe))
	}
	kvs = appendStringAttr(kvs, string(semconv.ProcessCommandLineKey), getStringField(data, "cmdline"))
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

func systemSemanticAttributes(data map[string]interface{}) []otelLog.KeyValue {
	var kvs []otelLog.KeyValue

	osVersion := getStringField(data, "os_version")
	if osVersion != "" {
		kvs = append(kvs, otelLog.String(string(semconv.OSDescriptionKey), osVersion))
		kvs = append(kvs, otelLog.String(string(semconv.OSVersionKey), osVersion))
	}

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

	kvs = appendCountAttr(kvs, "safnari.system.installed_patches_count", getSliceLength(data, "installed_patches"))
	kvs = appendCountAttr(kvs, "safnari.system.startup_programs_count", getSliceLength(data, "startup_programs"))
	kvs = appendCountAttr(kvs, "safnari.system.installed_apps_count", getSliceLength(data, "installed_apps"))
	kvs = appendCountAttr(kvs, "safnari.system.network_interfaces_count", getSliceLength(data, "network_interfaces"))
	kvs = appendCountAttr(kvs, "safnari.system.open_connections_count", getSliceLength(data, "open_connections"))
	kvs = appendCountAttr(kvs, "safnari.system.running_services_count", getSliceLength(data, "running_services"))
	kvs = appendCountAttr(kvs, "safnari.system.users_count", getSliceLength(data, "users"))
	kvs = appendCountAttr(kvs, "safnari.system.groups_count", getSliceLength(data, "groups"))
	kvs = appendCountAttr(kvs, "safnari.system.admins_count", getSliceLength(data, "admins"))
	kvs = appendCountAttr(kvs, "safnari.system.scheduled_tasks_count", getSliceLength(data, "scheduled_tasks"))
	kvs = appendCountAttr(kvs, "safnari.system.running_processes_count", getSliceLength(data, "running_processes"))

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
