package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"safnari/config"
)

type schedulerLane int

const (
	schedulerLaneSmall schedulerLane = iota
	schedulerLaneMedium
	schedulerLaneLarge
	schedulerLaneExpensive
)

const schedulerAgingThreshold = 150 * time.Millisecond

type scheduledTask struct {
	task       fileScanTask
	lane       schedulerLane
	enqueuedAt time.Time
}

// SizeLaneScheduler classifies file work into size-aware lanes and emits tasks
// using weighted round-robin with simple aging to prevent starvation.
type SizeLaneScheduler struct {
	incoming chan scheduledTask
	depth    atomic.Int64
	capacity int
}

func newSizeLaneScheduler(capacity int) *SizeLaneScheduler {
	if capacity < 1 {
		capacity = 1
	}
	return &SizeLaneScheduler{
		incoming: make(chan scheduledTask, capacity),
		capacity: capacity,
	}
}

func (s *SizeLaneScheduler) Enqueue(ctx context.Context, task fileScanTask, cfg *config.Config) error {
	if s == nil {
		return nil
	}
	item := scheduledTask{
		task:       task,
		lane:       classifyScheduledLane(task, cfg),
		enqueuedAt: time.Now(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.incoming <- item:
		s.depth.Add(1)
		return nil
	}
}

func (s *SizeLaneScheduler) Close() {
	if s == nil {
		return
	}
	close(s.incoming)
}

func (s *SizeLaneScheduler) Depth() int {
	if s == nil {
		return 0
	}
	return int(s.depth.Load())
}

func (s *SizeLaneScheduler) Capacity() int {
	if s == nil {
		return 0
	}
	return s.capacity
}

func (s *SizeLaneScheduler) Run(ctx context.Context, out chan<- fileScanTask) {
	if s == nil {
		close(out)
		return
	}
	defer close(out)

	lanes := map[schedulerLane][]scheduledTask{
		schedulerLaneSmall:     nil,
		schedulerLaneMedium:    nil,
		schedulerLaneLarge:     nil,
		schedulerLaneExpensive: nil,
	}
	order := []schedulerLane{
		schedulerLaneSmall,
		schedulerLaneSmall,
		schedulerLaneMedium,
		schedulerLaneSmall,
		schedulerLaneLarge,
		schedulerLaneExpensive,
	}
	orderIndex := 0
	incomingOpen := true

	for {
		if task, ok := pickScheduledTask(lanes, order, &orderIndex); ok {
			select {
			case <-ctx.Done():
				return
			case out <- task.task:
				s.depth.Add(-1)
				continue
			}
		}

		if !incomingOpen {
			return
		}
		select {
		case <-ctx.Done():
			return
		case item, ok := <-s.incoming:
			if !ok {
				incomingOpen = false
				continue
			}
			lanes[item.lane] = append(lanes[item.lane], item)
		}
	}
}

func pickScheduledTask(
	lanes map[schedulerLane][]scheduledTask,
	order []schedulerLane,
	orderIndex *int,
) (scheduledTask, bool) {
	now := time.Now()
	for _, lane := range []schedulerLane{schedulerLaneLarge, schedulerLaneExpensive, schedulerLaneMedium} {
		queue := lanes[lane]
		if len(queue) == 0 {
			continue
		}
		if now.Sub(queue[0].enqueuedAt) >= schedulerAgingThreshold {
			task := queue[0]
			lanes[lane] = queue[1:]
			return task, true
		}
	}
	if len(order) == 0 {
		return scheduledTask{}, false
	}
	for i := 0; i < len(order); i++ {
		lane := order[(*orderIndex+i)%len(order)]
		queue := lanes[lane]
		if len(queue) == 0 {
			continue
		}
		task := queue[0]
		lanes[lane] = queue[1:]
		*orderIndex = (*orderIndex + i + 1) % len(order)
		return task, true
	}
	return scheduledTask{}, false
}

func classifyScheduledLane(task fileScanTask, cfg *config.Config) schedulerLane {
	if task.info == nil {
		return schedulerLaneMedium
	}
	if isExpensiveScheduledTask(task, cfg) {
		return schedulerLaneExpensive
	}
	size := task.info.Size()
	switch {
	case size <= 64*1024:
		return schedulerLaneSmall
	case size <= 4*1024*1024:
		return schedulerLaneMedium
	default:
		return schedulerLaneLarge
	}
}

func isExpensiveScheduledTask(task fileScanTask, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.FuzzyHash && task.info != nil {
		size := task.info.Size()
		if size >= cfg.FuzzyMinSize && (cfg.FuzzyMaxSize <= 0 || size <= cfg.FuzzyMaxSize) {
			return true
		}
	}
	if !cfg.ScanFiles {
		return false
	}
	switch strings.ToLower(filepath.Ext(task.path)) {
	case ".jpg", ".jpeg", ".png", ".pdf", ".docx":
		return true
	default:
		return false
	}
}
