package scanner

import (
	"testing"
	"time"

	"safnari/config"

	"golang.org/x/time/rate"
)

func TestComputeAutoTuneDeltasScaleUpWhenUnderTarget(t *testing.T) {
	cfg := &config.Config{
		AutoTuneTargetCPU: 60,
		AutoTuneInterval:  5 * time.Second,
		NiceLevel:         "medium",
	}
	state := &autoTuneState{
		concurrency: 2,
		ioLimit:     400,
		maxIOLimit:  3500,
		cpuPID:      newCPUPIDController(cfg.NiceLevel),
	}

	concurrencyDelta, ioDelta := computeAutoTuneDeltas(cfg, state, 20, autoTuneTelemetry{})
	if concurrencyDelta <= 0 {
		t.Fatalf("expected positive concurrency delta, got %d", concurrencyDelta)
	}
	if ioDelta <= 0 {
		t.Fatalf("expected positive io delta, got %d", ioDelta)
	}
}

func TestComputeAutoTuneDeltasScaleDownWhenOverTarget(t *testing.T) {
	cfg := &config.Config{
		AutoTuneTargetCPU: 60,
		AutoTuneInterval:  5 * time.Second,
		NiceLevel:         "medium",
	}
	state := &autoTuneState{
		concurrency: 6,
		ioLimit:     1500,
		maxIOLimit:  3500,
		cpuPID:      newCPUPIDController(cfg.NiceLevel),
	}

	concurrencyDelta, ioDelta := computeAutoTuneDeltas(cfg, state, 95, autoTuneTelemetry{})
	if concurrencyDelta >= 0 {
		t.Fatalf("expected negative concurrency delta, got %d", concurrencyDelta)
	}
	if ioDelta >= 0 {
		t.Fatalf("expected negative io delta, got %d", ioDelta)
	}
}

func TestComputeAutoTuneDeltasDeadband(t *testing.T) {
	cfg := &config.Config{
		AutoTuneTargetCPU: 60,
		AutoTuneInterval:  5 * time.Second,
		NiceLevel:         "medium",
	}
	state := &autoTuneState{
		cpuEWMA: 60,
		cpuPID:  newCPUPIDController(cfg.NiceLevel),
	}

	concurrencyDelta, ioDelta := computeAutoTuneDeltas(cfg, state, 61, autoTuneTelemetry{})
	if concurrencyDelta != 0 || ioDelta != 0 {
		t.Fatalf("expected zero deltas in deadband, got concurrency=%d io=%d", concurrencyDelta, ioDelta)
	}
}

func TestComputeAutoTuneDeltasQueuePressureScalesUp(t *testing.T) {
	cfg := &config.Config{
		AutoTuneTargetCPU: 60,
		AutoTuneInterval:  5 * time.Second,
		NiceLevel:         "medium",
	}
	var processed int64 = 100
	state := &autoTuneState{
		concurrency: 2,
		ioLimit:     400,
		maxIOLimit:  3500,
		cpuPID:      newCPUPIDController(cfg.NiceLevel),
	}

	telemetry := autoTuneTelemetry{
		queueDepthFn: func() int { return 90 },
		queueCapacityFn: func() int {
			return 100
		},
		processedCountFn: func() int64 { return processed },
	}
	concurrencyDelta, ioDelta := computeAutoTuneDeltas(cfg, state, 60, telemetry)
	if concurrencyDelta <= 0 {
		t.Fatalf("expected positive concurrency delta under queue pressure, got %d", concurrencyDelta)
	}
	if ioDelta <= 0 {
		t.Fatalf("expected positive io delta under queue pressure, got %d", ioDelta)
	}
}

func TestComputeAutoTuneDeltasLowQueueScalesDown(t *testing.T) {
	cfg := &config.Config{
		AutoTuneTargetCPU: 60,
		AutoTuneInterval:  5 * time.Second,
		NiceLevel:         "medium",
	}
	var processed int64 = 1000
	state := &autoTuneState{
		concurrency:    6,
		ioLimit:        1500,
		maxIOLimit:     3500,
		cpuPID:         newCPUPIDController(cfg.NiceLevel),
		throughputEWMA: 30,
	}

	telemetry := autoTuneTelemetry{
		queueDepthFn:     func() int { return 0 },
		queueCapacityFn:  func() int { return 100 },
		processedCountFn: func() int64 { return processed },
	}
	concurrencyDelta, ioDelta := computeAutoTuneDeltas(cfg, state, 60, telemetry)
	if concurrencyDelta >= 0 {
		t.Fatalf("expected negative concurrency delta when queue is empty, got %d", concurrencyDelta)
	}
	if ioDelta >= 0 {
		t.Fatalf("expected negative io delta when queue is empty, got %d", ioDelta)
	}
}

func TestApplyAutoTuneAdjustmentsClampIOLimits(t *testing.T) {
	cfg := &config.Config{
		ConcurrencySet: true,
		MaxIOSet:       false,
	}
	limiter := rate.NewLimiter(rate.Limit(1000), 1000)
	state := &autoTuneState{
		ioLimit:    1000,
		maxIOLimit: 1200,
	}

	applyAutoTuneAdjustments(cfg, limiter, state, 0, 600)
	if state.ioLimit != 1200 {
		t.Fatalf("expected io limit to clamp to max, got %d", state.ioLimit)
	}
	applyAutoTuneAdjustments(cfg, limiter, state, 0, -2000)
	if state.ioLimit != 100 {
		t.Fatalf("expected io limit to clamp to min 100, got %d", state.ioLimit)
	}
}

func TestPIDControllerOutputBounded(t *testing.T) {
	pid := pidController{
		kp:          1.0,
		ki:          1.0,
		kd:          1.0,
		minIntegral: -10,
		maxIntegral: 10,
		minOutput:   -3,
		maxOutput:   3,
	}

	out := pid.Update(1000, 1)
	if out > 3 {
		t.Fatalf("expected bounded output <= 3, got %f", out)
	}
	out = pid.Update(-1000, 1)
	if out < -3 {
		t.Fatalf("expected bounded output >= -3, got %f", out)
	}
}
