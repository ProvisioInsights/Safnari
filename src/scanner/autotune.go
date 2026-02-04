package scanner

import (
	"context"
	"math"
	"runtime"
	"time"

	"safnari/config"
	"safnari/logger"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/time/rate"
)

type autoTuneState struct {
	concurrency int
	ioLimit     int
}

func applyAutoTune(ctx context.Context, cfg *config.Config, limiter *rate.Limiter) *autoTuneState {
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
	if cfg.AutoTune {
		go autoTuneLoop(ctx, cfg, limiter, state)
	}
	return state
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
	ioLimit := defaultIOLimit(cfg.NiceLevel, detectDiskType())
	return &autoTuneState{
		concurrency: maxInt(1, concurrency),
		ioLimit:     ioLimit,
	}
}

func autoTuneLoop(ctx context.Context, cfg *config.Config, limiter *rate.Limiter, state *autoTuneState) {
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
		target := cfg.AutoTuneTargetCPU
		step := 1
		limitStep := 100

		if cpuPct > target+10 {
			if !cfg.ConcurrencySet && state.concurrency > 1 {
				state.concurrency = maxInt(1, state.concurrency-step)
				runtime.GOMAXPROCS(state.concurrency)
			}
			if !cfg.MaxIOSet && limiter != nil && state.ioLimit > 100 {
				state.ioLimit = maxInt(100, state.ioLimit-limitStep)
				limiter.SetLimit(rate.Limit(state.ioLimit))
				limiter.SetBurst(state.ioLimit)
			}
		} else if cpuPct < target-10 {
			if !cfg.ConcurrencySet && state.concurrency < runtime.NumCPU() {
				state.concurrency = minInt(runtime.NumCPU(), state.concurrency+step)
				runtime.GOMAXPROCS(state.concurrency)
			}
			if !cfg.MaxIOSet && limiter != nil {
				state.ioLimit = minInt(state.ioLimit+limitStep, 5000)
				limiter.SetLimit(rate.Limit(state.ioLimit))
				limiter.SetBurst(state.ioLimit)
			}
		}
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
