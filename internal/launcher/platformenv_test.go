package launcher

import (
	"encoding/json"
	"testing"
)

func TestPlatformEnvIsTheRuntimes(t *testing.T) {
	l := &Launcher{cfg: Config{Issuer: "https://privasys.id/", Audience: "privasys-platform-test"}}
	env := map[string]string{ConfigureGrantEnv: "0", "PRIVASYS_ISSUER": "https://evil.example", "PRIVASYS_AUDIENCE": "x"}
	l.stampPlatformEnv(env)
	if env[ConfigureGrantEnv] != "1" || env["PRIVASYS_ISSUER"] != "https://privasys.id" || env["PRIVASYS_AUDIENCE"] != "privasys-platform-test" {
		t.Fatalf("env = %v", env)
	}
	// No issuer or audience configured: none given, whatever was there.
	env = map[string]string{"PRIVASYS_ISSUER": "https://evil.example", "PRIVASYS_AUDIENCE": "x"}
	(&Launcher{}).stampPlatformEnv(env)
	if _, ok := env["PRIVASYS_ISSUER"]; ok {
		t.Fatalf("issuer kept: %v", env)
	}
	if _, ok := env["PRIVASYS_AUDIENCE"]; ok {
		t.Fatalf("audience kept: %v", env)
	}
	if env[ConfigureGrantEnv] != "1" {
		t.Fatal("marker missing")
	}
}

// A load request has no way to name container environment: anything it sends
// under env-like keys is dropped, so the runtime's values are the only ones.
func TestLoadRequestCannotSetEnv(t *testing.T) {
	var req LoadRequest
	body := `{"name":"a","image":"i","env":{"` + ConfigureGrantEnv + `":"1"},"environment":{"` + ConfigureGrantEnv + `":"1"}}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if env := req.runtimeEnv(); len(env) != 0 {
		t.Fatalf("a load request set env: %v", env)
	}
	if spec := req.toContainerSpec(); len(spec.Env) != 0 {
		t.Fatalf("a load request set the spec env: %v", spec.Env)
	}
}
