package backup

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func testTarget() Target {
	return Target{
		Endpoint: "s3.gra.io.cloud.ovh.net", Bucket: "b", Region: "gra", Prefix: "apps/x/",
		AccessKeyID: "AKID", SecretAccessKey: "SECRET",
		RetentionMode: "COMPLIANCE", RetentionDays: 35,
	}
}

func TestTargetValidate(t *testing.T) {
	if err := testTarget().validate(); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	for name, mut := range map[string]func(*Target){
		"no bucket":         func(t *Target) { t.Bucket = "" },
		"no secret":         func(t *Target) { t.SecretAccessKey = "" },
		"scheme":            func(t *Target) { t.Endpoint = "https://s3.example" },
		"bad mode":          func(t *Target) { t.RetentionMode = "FOREVER" },
		"mode without days": func(t *Target) { t.RetentionDays = 0 },
	} {
		tg := testTarget()
		mut(&tg)
		if err := tg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRetentionArgs(t *testing.T) {
	got := Retention{Hourly: 48, Daily: 35, Monthly: 13}.args()
	want := []string{"--keep-latest=0", "--keep-hourly=48", "--keep-daily=35",
		"--keep-weekly=0", "--keep-monthly=13", "--keep-annual=0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	if got := (Retention{}).args(); got != nil {
		t.Fatalf("empty retention args = %v, want none", got)
	}
}

// fakeKopia writes a kopia stand-in that logs each call (args, then the
// secrets it received through its environment) and answers like kopia for the
// calls Backup and List make. With uninitialised set, connect fails the way
// kopia does on an empty prefix until create has run.
func fakeKopia(t *testing.T, uninitialised bool) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	state := filepath.Join(dir, "initialised")
	if !uninitialised {
		if err := os.WriteFile(state, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
echo "ARGS $*" >> ` + logPath + `
echo "ENV pw=$KOPIA_PASSWORD ak=$AWS_ACCESS_KEY_ID sk=$AWS_SECRET_ACCESS_KEY" >> ` + logPath + `
case "$1 $2" in
"repository connect")
  [ -f ` + state + ` ] || { echo "ERROR repository not initialized in the provided storage" >&2; exit 1; } ;;
"repository create") touch ` + state + ` ;;
"snapshot create")
  echo '{"id":"k1","startTime":"2026-10-29T10:00:00Z","endTime":"2026-10-29T10:00:05Z","rootEntry":{"summ":{"size":4096,"files":3,"numFailed":0}}}' ;;
"blob stats")
  echo "Count: 3"; echo "Total: 12345" ;;
"snapshot list")
  echo '[{"id":"k1","startTime":"2026-10-29T10:00:00Z","rootEntry":{"summ":{"size":4096,"files":3}},"retentionReason":["latest-1"]}]' ;;
esac
exit 0
`
	bin = filepath.Join(dir, "kopia")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, logPath
}

func calls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(l, "ARGS ") {
			args = append(args, strings.TrimPrefix(l, "ARGS "))
		}
	}
	return args
}

func TestBackupCreatesRepositoryOnFirstUse(t *testing.T) {
	bin, logPath := fakeKopia(t, true)
	r := &Runner{log: zap.NewNop(), Binary: bin, StateBase: t.TempDir()}
	res, err := r.Backup(context.Background(), "myapp", "pw-hex", testTarget(),
		Retention{Daily: 35}, "/run/backups/myapp", "manual")
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if snap := res.Snapshot; snap.ID != "k1" || snap.SizeBytes != 4096 || snap.Files != 3 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if len(res.Snapshots) != 1 || res.StoredBytes != 12345 {
		t.Fatalf("repository state = %d snapshots, %d bytes", len(res.Snapshots), res.StoredBytes)
	}

	got := calls(t, logPath)
	wantPrefixes := []string{
		"repository connect s3",
		"repository create s3",
		"maintenance set --owner=me --full-interval=24h --extend-object-locks=true",
		"policy set --global --compression=zstd --keep-latest=0 --keep-hourly=0 --keep-daily=35 --keep-weekly=0 --keep-monthly=0 --keep-annual=0",
		"snapshot create /run/backups/myapp --json --no-progress --description=manual",
		"maintenance run",
		"snapshot list --all --json",
		"blob stats --raw",
		"repository disconnect",
	}
	if len(got) != len(wantPrefixes) {
		t.Fatalf("calls = %q", got)
	}
	for i, p := range wantPrefixes {
		if !strings.HasPrefix(got[i], p) {
			t.Errorf("call %d = %q, want prefix %q", i, got[i], p)
		}
	}
	create := got[1]
	for _, want := range []string{"--bucket=b", "--prefix=apps/x/", "--region=gra",
		"--override-hostname=privasys", "--override-username=myapp",
		"--retention-mode=COMPLIANCE", "--retention-period=840h"} {
		if !strings.Contains(create, want) {
			t.Errorf("create %q lacks %q", create, want)
		}
	}

	// Secrets reach kopia only through its environment.
	log, _ := os.ReadFile(logPath)
	for _, l := range strings.Split(string(log), "\n") {
		if strings.HasPrefix(l, "ARGS ") && (strings.Contains(l, "SECRET") || strings.Contains(l, "pw-hex") || strings.Contains(l, "AKID")) {
			t.Errorf("secret on the command line: %q", l)
		}
	}
	if !strings.Contains(string(log), "ENV pw=pw-hex ak=AKID sk=SECRET") {
		t.Error("secrets not delivered through the environment")
	}
	// The state directory is gone afterwards.
	if ents, _ := os.ReadDir(r.StateBase); len(ents) != 0 {
		t.Errorf("state left behind: %v", ents)
	}
}

func TestBackupReusesExistingRepository(t *testing.T) {
	bin, logPath := fakeKopia(t, false)
	r := &Runner{log: zap.NewNop(), Binary: bin, StateBase: t.TempDir()}
	if _, err := r.Backup(context.Background(), "myapp", "pw", testTarget(), Retention{}, "/src", ""); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	for _, c := range calls(t, logPath) {
		if strings.HasPrefix(c, "repository create") || strings.HasPrefix(c, "maintenance set") {
			t.Errorf("existing repository re-initialised: %q", c)
		}
	}
}

func TestListWithoutRepositoryIsEmpty(t *testing.T) {
	bin, logPath := fakeKopia(t, true)
	r := &Runner{log: zap.NewNop(), Binary: bin, StateBase: t.TempDir()}
	snaps, err := r.List(context.Background(), "myapp", "pw", testTarget())
	if err != nil || len(snaps) != 0 {
		t.Fatalf("List = %v, %v; want empty", snaps, err)
	}
	for _, c := range calls(t, logPath) {
		if strings.HasPrefix(c, "repository create") {
			t.Errorf("List created a repository: %q", c)
		}
	}
}

func TestListParsesSnapshots(t *testing.T) {
	bin, _ := fakeKopia(t, false)
	r := &Runner{log: zap.NewNop(), Binary: bin, StateBase: t.TempDir()}
	snaps, err := r.List(context.Background(), "myapp", "pw", testTarget())
	if err != nil || len(snaps) != 1 || snaps[0].ID != "k1" || snaps[0].Retention[0] != "latest-1" {
		t.Fatalf("List = %+v, %v", snaps, err)
	}
}

func TestRestorePicksSnapshotAndNeverCreates(t *testing.T) {
	bin, logPath := fakeKopia(t, false)
	r := &Runner{log: zap.NewNop(), Binary: bin, StateBase: t.TempDir()}
	snap, err := r.Restore(context.Background(), "myapp", "pw", testTarget(), "latest", "/run/containers/myapp")
	if err != nil || snap.ID != "k1" {
		t.Fatalf("Restore = %+v, %v", snap, err)
	}
	var restored bool
	for _, c := range calls(t, logPath) {
		if strings.HasPrefix(c, "repository create") {
			t.Errorf("Restore created a repository: %q", c)
		}
		if strings.HasPrefix(c, "snapshot restore k1 /run/containers/myapp") {
			restored = true
		}
	}
	if !restored {
		t.Error("snapshot restore not called with the picked snapshot and destination")
	}
	if _, err := r.Restore(context.Background(), "myapp", "pw", testTarget(), "nope", "/x"); err == nil {
		t.Error("unknown snapshot id accepted")
	}
}

func TestPickSnapshotLatest(t *testing.T) {
	var a, b kopiaManifest
	a.ID, b.ID = "old", "new"
	a.StartTime = b.StartTime.AddDate(0, 0, -1)
	if got := pickSnapshot([]kopiaManifest{b, a}, "latest"); got == nil || got.ID != "new" {
		t.Fatalf("latest = %+v", got)
	}
	if got := pickSnapshot([]kopiaManifest{a, b}, "old"); got == nil || got.ID != "old" {
		t.Fatalf("by id = %+v", got)
	}
}

func TestInvalidAppName(t *testing.T) {
	r := &Runner{log: zap.NewNop(), Binary: "/bin/false", StateBase: t.TempDir()}
	if _, err := r.List(context.Background(), "a/b", "pw", testTarget()); err == nil {
		t.Fatal("app name with a slash accepted")
	}
}

func TestChangePasswordIsIdempotent(t *testing.T) {
	// The fake opens any password once the repository exists, so the
	// new-password probe succeeds and nothing is changed.
	bin, logPath := fakeKopia(t, false)
	r := &Runner{log: zap.NewNop(), Binary: bin, StateBase: t.TempDir()}
	if err := r.ChangePassword(context.Background(), "myapp", "old", "new", testTarget()); err != nil {
		t.Fatal(err)
	}
	for _, c := range calls(t, logPath) {
		if strings.HasPrefix(c, "repository change-password") {
			t.Fatalf("changed a repository that already opens with the new password: %q", c)
		}
	}
	// No repository: nothing to change, no error.
	bin, _ = fakeKopia(t, true)
	r.Binary = bin
	if err := r.ChangePassword(context.Background(), "myapp", "old", "new", testTarget()); err != nil {
		t.Fatalf("no repository: %v", err)
	}
}
