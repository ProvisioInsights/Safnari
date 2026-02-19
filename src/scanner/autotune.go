package scanner

import (
	"context"
	"math"
	"runtime"
	runtimemetrics "runtime/metrics"
	"time"

	"safnari/config"
	"safnari/logger"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/time/rate"
)

type autoTuneState struct {
	concurrency      int
	ioLimit          int
	maxIOLimit       int
	cpuEWMA          float64
	runQueueEWMA     float64
	schedLatencyEWMA float64
	heapLiveEWMA     float64
	cpuPID           pidController
	lastProcessed    int64
	throughputEWMA   float64
	queueWaitEWMA    float64
}

type autoTuneTelemetry struct {
	queueDepthFn     func() int
	queueCapacityFn  func() int
	processedCountFn func() int64
	runtimeSampleFn  func() runtimeSignal
}

func (t autoTuneTelemetry) queueDepth() int {
	if t.queueDepthFn == nil {
		return 0
	}
	return maxInt(0, t.queueDepthFn())
}

func (t autoTuneTelemetry) queueCapacity() int {
	if t.queueCapacityFn == nil {
		return 0
	}
	return maxInt(0, t.queueCapacityFn())
}

func (t autoTuneTelemetry) processedCount() int64 {
	if t.processedCountFn == nil {
		return 0
	}
	value := t.processedCountFn()
	if value < 0 {
		return 0
	}
	return value
}

func (t autoTuneTelemetry) runtimeSignal() (runtimeSignal, bool) {
	if t.runtimeSampleFn != nil {
		sample := t.runtimeSampleFn()
		return sample, sample.valid()
	}
	sample := sampleRuntimeSignal()
	return sample, sample.valid()
}

type runtimeSignal struct {
	runQueueRatio float64
	latencySec    float64
	heapLiveBytes float64
}

func (s runtimeSignal) valid() bool {
	return s.runQueueRatio >= 0 || s.latencySec >= 0 || s.heapLiveBytes >= 0
}

func sampleRuntimeSignal() runtimeSignal {
	// Keys:
	// - /sched/goroutines:goroutines
	// - /sched/latencies:seconds
	// - /gc/heap/live:bytes
	samples := []runtimemetrics.Sample{
		{Name: "/sched/goroutines:goroutines"},
		{Name: "/sched/latencies:seconds"},
		{Name: "/gc/heap/live:bytes"},
	}
	runtimemetrics.Read(samples)

	signal := runtimeSignal{
		runQueueRatio: -1,
		latencySec:    -1,
		heapLiveBytes: -1,
	}

	if value := samples[0].Value; value.Kind() == runtimemetrics.KindUint64 {
		goroutines := float64(value.Uint64())
		procs := float64(maxInt(1, runtime.GOMAXPROCS(0)))
		signal.runQueueRatio = goroutines / procs
	}

	if value := samples[1].Value; value.Kind() == runtimemetrics.KindFloat64Histogram {
		h := value.Float64Histogram()
		if h != nil {
			latency := histogramQuantileFloat64(h, 0.95)
			if latency >= 0 {
				signal.latencySec = latency
			}
		}
	}

	if value := samples[2].Value; value.Kind() == runtimemetrics.KindUint64 {
		signal.heapLiveBytes = float64(value.Uint64())
	}

	return signal
}

func histogramQuantileFloat64(hist *runtimemetrics.Float64Histogram, quantile float64) float64 {
	if hist == nil || len(hist.Counts) == 0 || len(hist.Buckets) == 0 {
		return -1
	}
	if quantile < 0 {
		quantile = 0
	}
	if quantile > 1 {
		quantile = 1
	}
	var total uint64
	for _, count := range hist.Counts {
		total += count
	}
	if total == 0 {
		return -1
	}
	target := uint64(math.Ceil(float64(total) * quantile))
	if target == 0 {
		target = 1
	}
	var cumulative uint64
	for idx, count := range hist.Counts {
		cumulative += count
		if cumulative < target {
			continue
		}
		if idx+1 >= len(hist.Buckets) {
			break
		}
		upper := hist.Buckets[idx+1]
		if math.IsInf(upper, 0) {
			if idx < len(hist.Buckets) {
				upper = hist.Buckets[idx]
			}
		}
		return upper
	}
	return -1
}

type pidController struct {
	kp float64
	ki float64
	kd float64

	integral    float64
	prevError   float64
	hasPrev     bool
	minIntegral float64
	maxIntegral float64
	minOutput   float64
	maxOutput   float64
}

func applyAutoTune(cfg *config.Config, limiter *rate.Limiter) *autoTuneState {
	state := initialAutoTune(cfg)
	if !cfg.ConcurrencySet {
		cfg.ConcurrencyLevel = state.concurrency
		runtime.GOMAXPROCS(state.concurrency)
	}
	if !cfg.MaxIOSet && state.ioLimit > 0 {
		cfg.MaxIOPerSecond = state.ioLimit
		if limiter != nil {
			limiter.SetLimit(rate.Limit(state.ioLimit))
			limiter.SetBurst(state.ioLimit)
		}
	}
	return state
}

func startAutoTuneLoop(
	ctx context.Context,
	cfg *config.Config,
	limiter *rate.Limiter,
	state *autoTuneState,
	telemetry autoTuneTelemetry,
) {
	if !cfg.AutoTune || state == nil {
		return
	}
	go autoTuneLoop(ctx, cfg, limiter, state, telemetry)
}

func initialAutoTune(cfg *config.Config) *autoTuneState {
	numCPU := runtime.NumCPU()
	concurrency := numCPU
	switch cfg.NiceLevel {
	case "low":
		concurrency = 1
	case "medium":
		concurrency = int(math.Max(1, float64(numCPU/2)))
	case "high":
		concurrency = numCPU
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		totalGB := vm.Total / (1024 * 1024 * 1024)
		switch {
		case totalGB <= 4:
			concurrency = minInt(concurrency, 2)
		case totalGB <= 8:
			concurrency = minInt(concurrency, 4)
		}
	}
	diskType := detectDiskType()
	ioLimit := defaultIOLimit(cfg.NiceLevel, diskType)
	maxIOLimit := maxIOLimit(cfg.NiceLevel, diskType)
	return &autoTuneState{
		concurrency: maxInt(1, concurrency),
		ioLimit:     ioLimit,
		maxIOLimit:  maxIOLimit,
		cpuPID:      newCPUPIDController(cfg.NiceLevel),
	}
}

func autoTuneLoop(
	ctx context.Context,
	cfg *config.Config,
	limiter *rate.Limiter,
	state *autoTuneState,
	telemetry autoTuneTelemetry,
) {
	ticker := time.NewTicker(cfg.AutoTuneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if !cfg.AutoTune {
			continue
		}
		cpuPct := currentCPUPercent()
		if cpuPct <= 0 {
			continue
		}
		concurrencyDelta, ioDelta := computeAutoTuneDeltas(cfg, state, cpuPct, telemetry)
		applyAutoTuneAdjustments(cfg, limiter, state, concurrencyDelta, ioDelta)
	}
}

func applyAutoTuneAdjustments(cfg *config.Config, limiter *rate.Limiter, state *autoTuneState, concurrencyDelta, ioDelta int) {
	if !cfg.ConcurrencySet && concurrencyDelta != 0 {
		next := clampInt(state.concurrency+concurrencyDelta, 1, runtime.NumCPU())
		if next != state.concurrency {
			state.concurrency = next
			runtime.GOMAXPROCS(state.concurrency)
		}
	}

	if !cfg.MaxIOSet && limiter != nil && ioDelta != 0 {
		maxIOLimit := state.maxIOLimit
		if maxIOLimit <= 0 {
			maxIOLimit = 5000
		}
		next := clampInt(state.ioLimit+ioDelta, 100, maxIOLimit)
		if next != state.ioLimit {
			state.ioLimit = next
			limiter.SetLimit(rate.Limit(state.ioLimit))
			limiter.SetBurst(state.ioLimit)
		}
	}
}

func computeAutoTuneDeltas(cfg *config.Config, state *autoTuneState, cpuSample float64, telemetry autoTuneTelemetry) (int, int) {
	if cpuSample <= 0 {
		return 0, 0
	}

	const (
		ewmaAlpha = 0.30
		deadband  = 2.0
	)
	state.cpuEWMA = ewma(state.cpuEWMA, cpuSample, ewmaAlpha)

	dt := cfg.AutoTuneInterval.Seconds()
	if dt <= 0 {
		dt = 1
	}
	cpuError := cfg.AutoTuneTargetCPU - state.cpuEWMA
	cpuControl := state.cpuPID.Update(cpuError, dt)

	queueRatio, queueWait, hasQueueSignal := queueSignals(state, telemetry, dt)
	queueError := 0.0
	waitError := 0.0
	if hasQueueSignal {
		targetQueueRatio, targetQueueWait := queueTargets(cfg.NiceLevel)
		queueError = queueRatio - targetQueueRatio
		if targetQueueWait > 0 {
			waitError = (queueWait - targetQueueWait) / targetQueueWait
		}
	}

	runQueueError := 0.0
	latencyError := 0.0
	heapPressure := 0.0
	hasRuntimeSignal := false
	if cfg.AutoTuneRuntimeMetrics {
		if runtimeSignal, ok := telemetry.runtimeSignal(); ok {
			hasRuntimeSignal = true
			if runtimeSignal.runQueueRatio >= 0 {
				state.runQueueEWMA = ewma(state.runQueueEWMA, runtimeSignal.runQueueRatio, 0.30)
				runQueueError = state.runQueueEWMA - cfg.AutoTuneTargetRunQ
			}
			if runtimeSignal.latencySec >= 0 {
				state.schedLatencyEWMA = ewma(state.schedLatencyEWMA, runtimeSignal.latencySec, 0.30)
				targetLatency := float64(cfg.AutoTuneTargetLatencyMs) / 1000.0
				if targetLatency > 0 {
					latencyError = (state.schedLatencyEWMA - targetLatency) / targetLatency
				}
			}
			if runtimeSignal.heapLiveBytes >= 0 {
				prevHeapEWMA := state.heapLiveEWMA
				state.heapLiveEWMA = ewma(state.heapLiveEWMA, runtimeSignal.heapLiveBytes, 0.20)
				if prevHeapEWMA > 0 {
					heapPressure = clampFloat((runtimeSignal.heapLiveBytes-prevHeapEWMA)/prevHeapEWMA, -1.0, 1.0)
				}
			}
		}
	}

	// Blend CPU control with queue-depth and latency pressure. Positive queue/wait error means
	// backlog is growing faster than desired and we should scale up despite low CPU.
	queueControl := queueError*2.2 + waitError*1.4
	runtimeControl := runQueueError*1.8 + latencyError*1.6 - heapPressure*0.8
	control := cpuControl + queueControl + runtimeControl

	// Inside combined deadband, decay integral to avoid hunting around the setpoint.
	inRuntimeDeadband := !hasRuntimeSignal || (math.Abs(runQueueError) <= 0.05 && math.Abs(latencyError) <= 0.20 && math.Abs(heapPressure) <= 0.15)
	if math.Abs(cpuError) <= deadband && (!hasQueueSignal || (math.Abs(queueError) <= 0.05 && math.Abs(waitError) <= 0.20)) && inRuntimeDeadband {
		state.cpuPID.integral *= 0.85
		return 0, 0
	}

	// Dampen reactions to noisy one-off CPU spikes.
	noise := math.Abs(cpuSample - state.cpuEWMA)
	switch {
	case noise > 35:
		control *= 0.25
	case noise > 20:
		control *= 0.5
	}

	concurrencyScale, ioScale := controlScales(cfg.NiceLevel)
	concurrencyDelta := boundedIntStep(int(math.Round(control*concurrencyScale)), 2)
	ioDelta := boundedIntStep(int(math.Round(control*ioScale)), 250)
	return concurrencyDelta, ioDelta
}

func queueSignals(state *autoTuneState, telemetry autoTuneTelemetry, dt float64) (float64, float64, bool) {
	depth := float64(telemetry.queueDepth())
	capacityValue := telemetry.queueCapacity()
	capacity := float64(capacityValue)
	hasQueueSignal := capacityValue > 0
	queueRatio := 0.0
	if hasQueueSignal {
		queueRatio = clampFloat(depth/capacity, 0, 2)
	}

	processed := telemetry.processedCount()
	deltaProcessed := processed - state.lastProcessed
	if deltaProcessed < 0 {
		deltaProcessed = 0
	}
	state.lastProcessed = processed

	throughput := float64(deltaProcessed) / dt
	state.throughputEWMA = ewma(state.throughputEWMA, throughput, 0.35)

	waitSeconds := 0.0
	if depth > 0 {
		if state.throughputEWMA > 0.01 {
			waitSeconds = depth / state.throughputEWMA
		} else {
			// If throughput is near zero while queue has work, model this as strong pressure.
			waitSeconds = 5.0
		}
	}
	state.queueWaitEWMA = ewma(state.queueWaitEWMA, waitSeconds, 0.35)
	return queueRatio, state.queueWaitEWMA, hasQueueSignal
}

func queueTargets(nice string) (targetQueueRatio, targetQueueWait float64) {
	switch nice {
	case "low":
		return 0.20, 0.60
	case "medium":
		return 0.35, 0.40
	default:
		return 0.45, 0.30
	}
}

func currentCPUPercent() float64 {
	percents, err := cpu.Percent(0, false)
	if err != nil || len(percents) == 0 {
		logger.Debugf("Auto-tune CPU percent unavailable: %v", err)
		return 0
	}
	return percents[0]
}

func defaultIOLimit(nice, diskType string) int {
	base := 800
	switch diskType {
	case "ssd":
		base = 1200
	case "hdd":
		base = 400
	}
	switch nice {
	case "low":
		return minInt(base, 250)
	case "medium":
		return minInt(base, 600)
	default:
		return base
	}
}

func maxIOLimit(nice, diskType string) int {
	base := 5000
	switch diskType {
	case "ssd":
		base = 7000
	case "hdd":
		base = 3000
	}
	switch nice {
	case "low":
		return minInt(base, 1500)
	case "medium":
		return minInt(base, 3500)
	default:
		return base
	}
}

func controlScales(nice string) (float64, float64) {
	switch nice {
	case "low":
		return 0.6, 90
	case "medium":
		return 1.0, 130
	default:
		return 1.25, 170
	}
}

func newCPUPIDController(nice string) pidController {
	// Tuned for smooth control with bounded output; nice controls aggressiveness.
	controller := pidController{
		kp:          0.07,
		ki:          0.012,
		kd:          0.03,
		minIntegral: -200,
		maxIntegral: 200,
		minOutput:   -3.5,
		maxOutput:   3.5,
	}
	switch nice {
	case "low":
		controller.kp = 0.05
		controller.ki = 0.009
		controller.kd = 0.02
	case "high":
		controller.kp = 0.085
		controller.ki = 0.015
		controller.kd = 0.04
	}
	return controller
}

func (p *pidController) Update(error, dt float64) float64 {
	if dt <= 0 {
		dt = 1
	}
	p.integral += error * dt
	p.integral = clampFloat(p.integral, p.minIntegral, p.maxIntegral)

	derivative := 0.0
	if p.hasPrev {
		derivative = (error - p.prevError) / dt
	}
	p.prevError = error
	p.hasPrev = true

	output := p.kp*error + p.ki*p.integral + p.kd*derivative
	return clampFloat(output, p.minOutput, p.maxOutput)
}

func ewma(current, sample, alpha float64) float64 {
	if current == 0 {
		return sample
	}
	return alpha*sample + (1-alpha)*current
}

func boundedIntStep(value, maxStep int) int {
	switch {
	case value > maxStep:
		return maxStep
	case value < -maxStep:
		return -maxStep
	default:
		return value
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
