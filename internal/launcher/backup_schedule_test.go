package launcher

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func scheduleTestLauncher() *Launcher {
	return &Launcher{
		log:             zap.NewNop(),
		backupJobs:      make(map[string]*BackupJob),
		backupBases:     make(map[string]LoadRequest),
		backupSchedules: make(map[string]*scheduledBackup),
	}
}

func TestFirstRunDelayBounds(t *testing.T) {
	for i := 0; i < 200; i++ {
		if d := firstRunDelay(time.Hour); d < 0 || d >= 30*time.Minute {
			t.Fatalf("delay %v outside [0, 30m)", d)
		}
		if d := firstRunDelay(20 * time.Minute); d < 0 || d >= 20*time.Minute {
			t.Fatalf("delay %v outside [0, 20m)", d)
		}
	}
}

func TestArmBackupSchedule(t *testing.T) {
	l := scheduleTestLauncher()
	req := LoadRequest{Name: "app", AppId: "id", KeyHandle: "h", KeyCreationGrant: "g",
		Backup: &BackupPolicy{IntervalMinutes: 60}}
	l.armBackupSchedule(req, req.Backup)

	s := l.backupSchedules["app"]
	if s == nil {
		t.Fatal("schedule not armed")
	}
	if s.req.Description != "scheduled" || s.req.KeyHandle != "h" || s.req.AppId != "id" {
		t.Fatalf("job request = %+v", s.req)
	}
	if base := l.backupBases["app"]; base.KeyCreationGrant != "" || base.Backup != nil {
		t.Fatalf("base keeps one-shot fields: %+v", base)
	}

	// A live change keeps the cadence; nil disables, but the app stays known.
	first := s.nextRun
	if err := l.SetBackupPolicy("app", &BackupPolicy{IntervalMinutes: 1440}); err != nil {
		t.Fatal(err)
	}
	if got := l.backupSchedules["app"].nextRun; got.After(first) {
		t.Fatalf("policy change pushed the next run from %v to %v", first, got)
	}
	if err := l.SetBackupPolicy("app", nil); err != nil {
		t.Fatal(err)
	}
	if l.backupSchedules["app"] != nil {
		t.Fatal("nil policy left a schedule")
	}
	if err := l.SetBackupPolicy("other", &BackupPolicy{IntervalMinutes: 60}); err == nil {
		t.Fatal("policy accepted for an app that is not loaded")
	}

	l.disarmBackupSchedule("app")
	if err := l.SetBackupPolicy("app", &BackupPolicy{IntervalMinutes: 60}); err == nil {
		t.Fatal("policy accepted after unload")
	}
}

func TestPlatformKeyAppGetsNoSchedule(t *testing.T) {
	l := scheduleTestLauncher()
	l.armBackupSchedule(LoadRequest{Name: "app"}, &BackupPolicy{IntervalMinutes: 60})
	if l.backupSchedules["app"] != nil {
		t.Fatal("an app without a vault key got a schedule")
	}
}
