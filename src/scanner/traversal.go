package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"safnari/config"
)

type walker interface {
	Walk(ctx context.Context, startPath string, fn fs.WalkDirFunc) error
}

type fastWalker struct{}

func (w fastWalker) Walk(ctx context.Context, startPath string, fn fs.WalkDirFunc) error {
	info, err := os.Stat(startPath)
	if err != nil {
		return fn(startPath, nil, err)
	}
	root := fs.FileInfoToDirEntry(info)
	type item struct {
		path  string
		entry fs.DirEntry
	}
	stack := []item{{path: startPath, entry: root}}
	for len(stack) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if err := fn(current.path, current.entry, nil); err != nil {
			if err == fs.SkipDir {
				continue
			}
			return err
		}
		if !current.entry.IsDir() {
			continue
		}

		entries, err := os.ReadDir(current.path)
		if err != nil {
			if ferr := fn(current.path, current.entry, err); ferr != nil && ferr != fs.SkipDir {
				return ferr
			}
			continue
		}
		for i := range entries {
			child := entries[i]
			stack = append(stack, item{
				path:  filepath.Join(current.path, child.Name()),
				entry: child,
			})
		}
	}
	return nil
}

func selectWalker(cfg *config.Config) walker {
	_ = cfg
	return fastWalker{}
}
