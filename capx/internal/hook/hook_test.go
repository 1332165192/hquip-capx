package hook

import (
	"strings"
	"testing"

	"github.com/hquip/capx/internal/store"
)

func TestListProcesses(t *testing.T) {
	m := New(store.New(16))
	procs, err := m.ListProcesses()
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}
	// The capx test process itself must be in the list on any real OS.
	if len(procs) == 0 {
		t.Skip("no processes enumerated (unsupported platform)")
	}
	for _, p := range procs {
		if p.PID == 0 && p.Name == "" {
			t.Fatalf("empty process entry: %+v", p)
		}
	}
}

func TestBuiltinAgent(t *testing.T) {
	for _, name := range []string{"", "tls"} {
		if _, ok := builtinAgent(name); !ok {
			t.Fatalf("expected builtin agent for %q", name)
		}
	}
	if _, ok := builtinAgent("does-not-exist"); ok {
		t.Fatalf("unexpected agent for unknown name")
	}
}

func TestAttachWithoutPythonFails(t *testing.T) {
	m := &Manager{st: store.New(16), python: "", frida: "", sessions: map[string]*Session{}}
	if _, err := m.Attach(1234, "tls"); err != ErrNoFrida {
		t.Fatalf("want ErrNoFrida, got %v", err)
	}
}

func TestFridaCLIArgs(t *testing.T) {
	args, err := fridaCLIArgs([]string{"--pid", "42"}, `C:\a\agent.js`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-q", "-p", "42", "-l", `C:\a\agent.js`}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v", args)
	}
	args, err = fridaCLIArgs([]string{"--spawn", "app.exe", "--flag"}, "agent.js")
	if err != nil {
		t.Fatal(err)
	}
	if args[1] != "-f" || args[2] != "app.exe" {
		t.Fatalf("spawn args = %v", args)
	}
}

func TestBackendPrefersPythonDriver(t *testing.T) {
	// python 驱动(frida 绑定)会话保活可靠,优先于 frida CLI;
	// CLI 在批处理模式下注入后自行退出(frida 16 实测),仅作无 python 时的回退。
	m := &Manager{frida: "frida.exe", python: "python"}
	if m.Backend() != "frida" || !m.Available() {
		t.Fatalf("backend=%s available=%v", m.Backend(), m.Available())
	}
	m = &Manager{frida: "frida.exe"}
	if m.Backend() != "frida-cli" || !m.Available() {
		t.Fatalf("cli fallback backend=%s available=%v", m.Backend(), m.Available())
	}
}

func TestPreview(t *testing.T) {
	if got := preview([]byte("GET / HTTP/1.1\r\n")); got != "GET / HTTP/1.1\r\n" {
		t.Fatalf("printable preview altered: %q", got)
	}
	bin := []byte{0x00, 0x01, 0x02, 0x03, 0xff}
	if got := preview(bin); !strings.HasPrefix(got, "0001020") {
		t.Fatalf("binary preview not hex: %q", got)
	}
}
