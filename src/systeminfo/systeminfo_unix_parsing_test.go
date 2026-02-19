//go:build !windows
// +build !windows

package systeminfo

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestReadColonFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "colon.txt")
	content := "# comment\n\nroot:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000::/home/user1:/bin/zsh\ninvalidline\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := readColonFile(path)
	if err != nil {
		t.Fatalf("readColonFile: %v", err)
	}
	want := []string{"root", "user1", "invalidline"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed values: got=%v want=%v", got, want)
	}
}

func TestParseCronLines(t *testing.T) {
	data := []byte("\n# comment\n0 2 * * * /usr/bin/backup\n\n@reboot /usr/bin/startup\n")
	got := parseCronLines(data)
	want := []string{"0 2 * * * /usr/bin/backup", "@reboot /usr/bin/startup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected cron lines: got=%v want=%v", got, want)
	}
}

func TestCollectScheduledTaskPaths(t *testing.T) {
	tmpDir := t.TempDir()
	dirA := filepath.Join(tmpDir, "dir-a")
	dirB := filepath.Join(tmpDir, "dir-b")
	if err := os.MkdirAll(dirA, 0700); err != nil {
		t.Fatalf("mkdir dir-a: %v", err)
	}
	if err := os.MkdirAll(dirB, 0700); err != nil {
		t.Fatalf("mkdir dir-b: %v", err)
	}
	fileA := filepath.Join(dirA, "task-a")
	fileB := filepath.Join(dirB, "task-b")
	if err := os.WriteFile(fileA, []byte("x"), 0600); err != nil {
		t.Fatalf("write task-a: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("x"), 0600); err != nil {
		t.Fatalf("write task-b: %v", err)
	}

	got := collectScheduledTaskPaths([]string{dirA, filepath.Join(tmpDir, "missing"), dirB})
	if !reflect.DeepEqual(got, []string{fileA, fileB}) {
		t.Fatalf("unexpected collected task paths: %v", got)
	}
}

func TestAppendParsedCronTasks(t *testing.T) {
	base := []string{"/tmp/existing-task"}
	out := appendParsedCronTasks(base, []byte("# ignore\n@hourly /usr/bin/do\n"))
	want := []string{"/tmp/existing-task", "@hourly /usr/bin/do"}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("unexpected appended cron tasks: got=%v want=%v", out, want)
	}
}

func TestGatherUsersGroupsAdminsWithInjectedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	passwdPath := filepath.Join(tmpDir, "passwd")
	groupPath := filepath.Join(tmpDir, "group")
	if err := os.WriteFile(passwdPath, []byte("alice:x:1:1::/home/alice:/bin/sh\nbob:x:2:2::/home/bob:/bin/sh\n"), 0600); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte("staff:x:20:\nwheel:x:0:\nadmin:x:80:\n"), 0600); err != nil {
		t.Fatalf("write group: %v", err)
	}

	origUsersPath := usersFilePath
	origGroupsPath := groupsFilePath
	t.Cleanup(func() {
		usersFilePath = origUsersPath
		groupsFilePath = origGroupsPath
	})
	usersFilePath = passwdPath
	groupsFilePath = groupPath

	sys := &SystemInfo{}
	if err := gatherUsers(sys); err != nil {
		t.Fatalf("gatherUsers: %v", err)
	}
	if err := gatherGroups(sys); err != nil {
		t.Fatalf("gatherGroups: %v", err)
	}
	if err := gatherAdmins(sys); err != nil {
		t.Fatalf("gatherAdmins: %v", err)
	}

	if !reflect.DeepEqual(sys.Users, []string{"alice", "bob"}) {
		t.Fatalf("unexpected users: %v", sys.Users)
	}
	if !reflect.DeepEqual(sys.Groups, []string{"staff", "wheel", "admin"}) {
		t.Fatalf("unexpected groups: %v", sys.Groups)
	}
	if !reflect.DeepEqual(sys.Admins, []string{"wheel", "admin"}) {
		t.Fatalf("unexpected admins: %v", sys.Admins)
	}
}

func TestGatherScheduledTasksWithInjectedSources(t *testing.T) {
	tmpDir := t.TempDir()
	dirA := filepath.Join(tmpDir, "a")
	dirB := filepath.Join(tmpDir, "b")
	if err := os.MkdirAll(dirA, 0700); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := os.MkdirAll(dirB, 0700); err != nil {
		t.Fatalf("mkdir b: %v", err)
	}
	fileA := filepath.Join(dirA, "task-a")
	fileB := filepath.Join(dirB, "task-b")
	if err := os.WriteFile(fileA, []byte("x"), 0600); err != nil {
		t.Fatalf("write task-a: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("x"), 0600); err != nil {
		t.Fatalf("write task-b: %v", err)
	}

	sys := &SystemInfo{}
	wantCronLine := "@daily /usr/bin/run-task"

	switch runtime.GOOS {
	case "linux":
		crontabPath := filepath.Join(tmpDir, "crontab")
		if err := os.WriteFile(crontabPath, []byte("# ignore\n"+wantCronLine+"\n"), 0600); err != nil {
			t.Fatalf("write linux crontab: %v", err)
		}

		origDirs := linuxScheduledTaskDirs
		origCrontabPath := linuxCrontabPath
		t.Cleanup(func() {
			linuxScheduledTaskDirs = origDirs
			linuxCrontabPath = origCrontabPath
		})
		linuxScheduledTaskDirs = []string{dirA, dirB}
		linuxCrontabPath = crontabPath
	case "darwin":
		origDirsFn := darwinScheduledTaskDirs
		origCrontabFn := darwinCrontabOutput
		t.Cleanup(func() {
			darwinScheduledTaskDirs = origDirsFn
			darwinCrontabOutput = origCrontabFn
		})
		darwinScheduledTaskDirs = func() []string { return []string{dirA, dirB} }
		darwinCrontabOutput = func() ([]byte, error) {
			return []byte("# ignore\n" + wantCronLine + "\n"), nil
		}
	default:
		t.Skip("unsupported runtime for scheduled task collector test")
	}

	if err := gatherScheduledTasks(sys); err != nil {
		t.Fatalf("gatherScheduledTasks: %v", err)
	}

	foundA := false
	foundB := false
	foundCron := false
	for _, task := range sys.ScheduledTasks {
		switch task {
		case fileA:
			foundA = true
		case fileB:
			foundB = true
		case wantCronLine:
			foundCron = true
		}
	}
	if !foundA || !foundB || !foundCron {
		t.Fatalf("expected scheduled tasks to include injected sources, got %v", sys.ScheduledTasks)
	}
}

func TestGatherUsersErrorWithInjectedMissingFile(t *testing.T) {
	origUsersPath := usersFilePath
	t.Cleanup(func() {
		usersFilePath = origUsersPath
	})
	usersFilePath = filepath.Join(t.TempDir(), "missing-passwd")

	err := gatherUsers(&SystemInfo{})
	if err == nil {
		t.Fatal("expected gatherUsers to return error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestGatherGroupsAndAdminsErrorWithInjectedMissingFile(t *testing.T) {
	origGroupsPath := groupsFilePath
	t.Cleanup(func() {
		groupsFilePath = origGroupsPath
	})
	groupsFilePath = filepath.Join(t.TempDir(), "missing-group")

	err := gatherGroups(&SystemInfo{})
	if err == nil {
		t.Fatal("expected gatherGroups to return error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist error from gatherGroups, got %v", err)
	}

	err = gatherAdmins(&SystemInfo{})
	if err == nil {
		t.Fatal("expected gatherAdmins to return error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist error from gatherAdmins, got %v", err)
	}
}
