package sandboxpolicy

import "testing"

func TestNativeExperimentalRuntimeProfile(t *testing.T) {
	p := ExampleProfiles()[0]
	p.Runtime = Native
	if err := p.Validate(); err != nil {
		t.Fatalf("expected experimental native policy to validate: %v", err)
	}
	p.AllowHostMounts = true
	if err := p.Validate(); err == nil {
		t.Fatal("native runtime must not allow host mounts")
	}
}
