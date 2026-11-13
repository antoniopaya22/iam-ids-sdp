// Package policy holds the member registry (devices) and the service catalogue with the
// role-based access rules (RBAC) that map Keycloak realm roles to protected services.
//
// The same file is read by the controller (policy decision point) and by every
// Accepting Host, which re-checks the roles of each request on its own (the paper's
// "AH independently verifies the IH's credentials and permissions").
package policy

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Service is a resource published behind the Accepting Hosts.
type Service struct {
	Description string   `yaml:"description"`
	Path        string   `yaml:"path"`  // URL prefix on the AH reverse proxy, e.g. /records/
	Roles       []string `yaml:"roles"` // realm roles allowed in proposed mode (any of)
}

// Device is a registered Initiating Host. Its mTLS certificate CN is the map key.
type Device struct {
	Owner    string   `yaml:"owner"`    // Keycloak username the device is bound to (proposed mode)
	Services []string `yaml:"services"` // services the device may reach (both modes)
}

// Policy is the parsed policy file.
type Policy struct {
	Services map[string]Service `yaml:"services"`
	Devices  map[string]Device  `yaml:"devices"`
}

// Sentinel errors, so callers can map them to HTTP status codes.
var (
	ErrUnknownService = errors.New("unknown service")
	ErrUnknownDevice  = errors.New("unknown device")
	ErrForbidden      = errors.New("forbidden")
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses and validates policy YAML.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if len(p.Services) == 0 {
		return errors.New("no services defined")
	}
	paths := map[string]string{}
	for name, s := range p.Services {
		if !namePattern.MatchString(name) {
			return fmt.Errorf("invalid service name %q", name)
		}
		if !strings.HasPrefix(s.Path, "/") || !strings.HasSuffix(s.Path, "/") {
			return fmt.Errorf("service %s: path must start and end with '/'", name)
		}
		if other, dup := paths[s.Path]; dup {
			return fmt.Errorf("services %s and %s share path %s", name, other, s.Path)
		}
		paths[s.Path] = name
		if len(s.Roles) == 0 {
			return fmt.Errorf("service %s: at least one role is required", name)
		}
	}
	for id, d := range p.Devices {
		if !namePattern.MatchString(id) {
			return fmt.Errorf("invalid device id %q", id)
		}
		if d.Owner == "" {
			return fmt.Errorf("device %s: owner is required", id)
		}
		for _, s := range d.Services {
			if _, ok := p.Services[s]; !ok {
				return fmt.Errorf("device %s: unknown service %s", id, s)
			}
		}
	}
	return nil
}

// Service returns the named service.
func (p *Policy) Service(name string) (Service, error) {
	s, ok := p.Services[name]
	if !ok {
		return Service{}, fmt.Errorf("%w: %s", ErrUnknownService, name)
	}
	return s, nil
}

// ServiceForPath returns the service whose path prefix matches an HTTP request path
// (longest prefix wins).
func (p *Policy) ServiceForPath(path string) (string, bool) {
	best, bestLen := "", -1
	for name, s := range p.Services {
		prefix := s.Path
		if (strings.HasPrefix(path, prefix) || path+"/" == prefix) && len(prefix) > bestLen {
			best, bestLen = name, len(prefix)
		}
	}
	return best, bestLen >= 0
}

// RolesAllow reports whether any of roles grants access to service (RBAC).
func (p *Policy) RolesAllow(roles []string, service string) bool {
	s, ok := p.Services[service]
	if !ok {
		return false
	}
	for _, have := range roles {
		for _, want := range s.Roles {
			if have == want {
				return true
			}
		}
	}
	return false
}

// AuthorizeTraditional is the baseline decision: the device key pair is the only
// credential, so a registered device may open any service listed for it.
func (p *Policy) AuthorizeTraditional(device, service string) error {
	d, ok := p.Devices[device]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownDevice, device)
	}
	if _, err := p.Service(service); err != nil {
		return err
	}
	if !contains(d.Services, service) {
		return fmt.Errorf("%w: device %s is not allowed to reach %s", ErrForbidden, device, service)
	}
	return nil
}

// AuthorizeProposed adds identity checks on top of the baseline: the token's user must
// own the device (the device key pair alone is not enough) and one of the user's realm
// roles must grant the service.
func (p *Policy) AuthorizeProposed(device, username string, roles []string, service string) error {
	if err := p.AuthorizeTraditional(device, service); err != nil {
		return err
	}
	d := p.Devices[device]
	if username == "" || d.Owner != username {
		return fmt.Errorf("%w: device %s belongs to %s, token is for %q", ErrForbidden, device, d.Owner, username)
	}
	if !p.RolesAllow(roles, service) {
		return fmt.Errorf("%w: roles %v do not grant %s (requires one of %v)",
			ErrForbidden, roles, service, p.Services[service].Roles)
	}
	return nil
}

// ServicesForRoles lists the services the roles grant, sorted.
func (p *Policy) ServicesForRoles(roles []string) []string {
	var out []string
	for name := range p.Services {
		if p.RolesAllow(roles, name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
