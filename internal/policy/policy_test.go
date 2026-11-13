package policy

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"
)

const sample = `
services:
  portal:  {path: /portal/,  roles: [viewer, researcher, admin]}
  records: {path: /records/, roles: [researcher, admin]}
  admin:   {path: /admin/,   roles: [admin]}
devices:
  ih-alice: {owner: alice, services: [portal, records, admin]}
  ih-bob:   {owner: bob,   services: [portal, records]}
`

func mustParse(t *testing.T, s string) *Policy {
	t.Helper()
	p, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRepositoryPolicyIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	if _, err := Load(filepath.Join(filepath.Dir(file), "..", "..", "config", "policy.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestRBACMapping(t *testing.T) {
	p := mustParse(t, sample)
	cases := []struct {
		roles   []string
		service string
		want    bool
	}{
		{[]string{"viewer"}, "portal", true},
		{[]string{"viewer"}, "records", false},
		{[]string{"viewer", "offline_access"}, "admin", false},
		{[]string{"researcher"}, "records", true},
		{[]string{"researcher"}, "admin", false},
		{[]string{"admin"}, "admin", true},
		{nil, "portal", false},
		{[]string{"admin"}, "nope", false},
	}
	for _, c := range cases {
		if got := p.RolesAllow(c.roles, c.service); got != c.want {
			t.Errorf("RolesAllow(%v, %s) = %v, want %v", c.roles, c.service, got, c.want)
		}
	}
	if got := p.ServicesForRoles([]string{"researcher"}); len(got) != 2 || got[0] != "portal" || got[1] != "records" {
		t.Errorf("ServicesForRoles(researcher) = %v", got)
	}
}

func TestAuthorizeTraditionalIgnoresRoles(t *testing.T) {
	p := mustParse(t, sample)
	if err := p.AuthorizeTraditional("ih-bob", "records"); err != nil {
		t.Errorf("traditional mode should let bob's device reach records: %v", err)
	}
	if err := p.AuthorizeTraditional("ih-bob", "admin"); !errors.Is(err, ErrForbidden) {
		t.Errorf("service not listed for device: got %v", err)
	}
	if err := p.AuthorizeTraditional("ih-mallory", "portal"); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("unknown device: got %v", err)
	}
	if err := p.AuthorizeTraditional("ih-alice", "nope"); !errors.Is(err, ErrUnknownService) {
		t.Errorf("unknown service: got %v", err)
	}
}

func TestAuthorizeProposed(t *testing.T) {
	p := mustParse(t, sample)
	if err := p.AuthorizeProposed("ih-alice", "alice", []string{"researcher"}, "records"); err != nil {
		t.Errorf("alice/researcher -> records: %v", err)
	}
	// Missing role.
	if err := p.AuthorizeProposed("ih-bob", "bob", []string{"viewer"}, "records"); !errors.Is(err, ErrForbidden) {
		t.Errorf("bob/viewer -> records should be forbidden, got %v", err)
	}
	// Token of another user on alice's device (stolen device, attacker's own account).
	if err := p.AuthorizeProposed("ih-alice", "bob", []string{"admin"}, "portal"); !errors.Is(err, ErrForbidden) {
		t.Errorf("device/user mismatch should be forbidden, got %v", err)
	}
	if err := p.AuthorizeProposed("ih-alice", "", []string{"admin"}, "portal"); !errors.Is(err, ErrForbidden) {
		t.Errorf("empty username should be forbidden, got %v", err)
	}
}

func TestServiceForPath(t *testing.T) {
	p := mustParse(t, sample)
	for path, want := range map[string]string{
		"/portal/":          "portal",
		"/portal":           "portal",
		"/records/x/y.json": "records",
		"/admin/index.html": "admin",
	} {
		got, ok := p.ServiceForPath(path)
		if !ok || got != want {
			t.Errorf("ServiceForPath(%q) = %q, %v; want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{"/", "/recordsx", "/other/"} {
		if got, ok := p.ServiceForPath(path); ok {
			t.Errorf("ServiceForPath(%q) = %q, want no match", path, got)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := []string{
		`services: {}`,
		`services: {a: {path: nope, roles: [x]}}`,
		`services: {a: {path: /a/, roles: []}}`,
		`services: {a: {path: /a/, roles: [x]}, b: {path: /a/, roles: [x]}}`,
		"services: {a: {path: /a/, roles: [x]}}\ndevices: {d: {owner: '', services: [a]}}",
		"services: {a: {path: /a/, roles: [x]}}\ndevices: {d: {owner: u, services: [zz]}}",
		"services: {a: {path: /a/, roles: [x]}}\nunknown: 1",
		"services: {'A B': {path: /a/, roles: [x]}}",
	}
	for _, s := range bad {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}
