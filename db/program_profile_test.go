package db

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestProgramProfileValidation(t *testing.T) {
	p := ProgramProfile{
		Platform: " HackerOne ", Handle: " acme ",
		Scope:    []string{" example.com ", "EXAMPLE.com", ""},
		Excluded: []string{"admin.example.com"}, RPS: 1.234,
	}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Platform != "hackerone" || p.Handle != "acme" || len(p.Scope) != 1 || p.RPS != 1.23 {
		t.Fatalf("normalize = %+v", p)
	}
	bad := ProgramProfile{RPS: 101}
	if err := bad.Normalize(); err == nil {
		t.Fatal("rps>100 must fail")
	}
	for _, h := range []string{"a\r\nX-Evil: 1", "a\tb", "a\x00b"} {
		if err := (&ProgramProfile{Handle: h}).Normalize(); err == nil {
			t.Fatalf("handle %q should be rejected", h)
		}
	}

	tooMany := ProgramProfile{Scope: make([]string, ProgramProfileMaxScope+1)}
	for i := range tooMany.Scope {
		tooMany.Scope[i] = fmt.Sprintf("host%d.example.com", i)
	}
	if err := tooMany.Normalize(); err == nil || !strings.Contains(err.Error(), "超过") {
		t.Fatalf("too many scope should fail: %v", err)
	}
}

func TestProgramProfileRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()

	task, err := d.CreateTask("program profile fixture", "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	id := strconv.FormatInt(task.ID, 10)

	// 未配置：task 存在，profile=nil。
	p, found, err := d.GetTaskProgramProfile(id)
	if err != nil || !found || p != nil {
		t.Fatalf("initial profile = %+v found=%v err=%v", p, found, err)
	}

	want := &ProgramProfile{
		Platform: "hackerone", Handle: "acme",
		Scope: []string{"example.com"}, Excluded: []string{"admin.example.com"},
		ScannersAllowed: []string{"nuclei"}, AllowRace: true, DryRun: true, RPS: 2.5,
	}
	if err := d.SaveTaskProgramProfile(id, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := d.GetTaskProgramProfile(id)
	if err != nil || !found || got == nil {
		t.Fatalf("get = %+v found=%v err=%v", got, found, err)
	}
	if got.Handle != "acme" || got.RPS != 2.5 || !got.DryRun || !got.AllowRace || len(got.Scope) != 1 || len(got.ScannersAllowed) != 1 {
		t.Fatalf("round trip = %+v", got)
	}

	// 空 profile = 清除，回到 NULL。
	if err := d.SaveTaskProgramProfile(id, &ProgramProfile{}); err != nil {
		t.Fatal(err)
	}
	got, found, err = d.GetTaskProgramProfile(id)
	if err != nil || !found || got != nil {
		t.Fatalf("after clear = %+v found=%v err=%v", got, found, err)
	}

	// 不存在的任务：Save 返回 ErrTaskNotFound；Get found=false。
	if err := d.SaveTaskProgramProfile("999999999", want); err != ErrTaskNotFound {
		t.Fatalf("save missing = %v", err)
	}
	if _, found, _ := d.GetTaskProgramProfile("999999999"); found {
		t.Fatal("missing task should not be found")
	}
}
