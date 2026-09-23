package scanner

import (
	"context"
	"fmt"
	"io"
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
	info, err := os.Lstat(startPath)
	if err != nil {
		return fn(startPath, nil, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fn(startPath, nil, fmt.Errorf("refusing symlink scan root: %s", startPath))
	}
	root := fs.FileInfoToDirEntry(info)
	type frame struct {
		path    string
		entry   fs.DirEntry
		dir     *os.File
		entries []fs.DirEntry
		index   int
		visited bool
	}
	stack := []frame{{path: startPath, entry: root}}
	defer func() {
		for i := range stack {
			if stack[i].dir != nil {
				_ = stack[i].dir.Close()
			}
		}
	}()
	for len(stack) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		current := &stack[len(stack)-1]
		if !current.visited {
			current.visited = true
			if err := fn(current.path, current.entry, nil); err != nil {
				if err == fs.SkipDir {
					stack = stack[:len(stack)-1]
					continue
				}
				return err
			}
			if !current.entry.IsDir() {
				stack = stack[:len(stack)-1]
				continue
			}
			dir, err := os.Open(current.path)
			if err != nil {
				if ferr := fn(current.path, current.entry, err); ferr != nil && ferr != fs.SkipDir {
					return ferr
				}
				stack = stack[:len(stack)-1]
				continue
			}
			current.dir = dir
		}
		if current.index == len(current.entries) {
			entries, err := current.dir.ReadDir(128)
			if err != nil && err != io.EOF {
				if ferr := fn(current.path, current.entry, err); ferr != nil && ferr != fs.SkipDir {
					return ferr
				}
			}
			if len(entries) == 0 || (err != nil && err != io.EOF) {
				_ = current.dir.Close()
				stack = stack[:len(stack)-1]
				continue
			}
			current.entries = entries
			current.index = 0
		}
		child := current.entries[current.index]
		current.index++
		stack = append(stack, frame{
			path:  filepath.Join(current.path, child.Name()),
			entry: child,
		})
	}
	return nil
}

func selectWalker(cfg *config.Config) walker {
	_ = cfg
	return fastWalker{}
}
