// Command sdp-pki creates the lab certificate authority and issues component
// certificates (see lab/pki-bootstrap.sh). It only runs inside the lab's one-shot `pki`
// container; keys never leave the Docker volume.
//
//	sdp-pki ca    --dir /pki/ca
//	sdp-pki issue --ca /pki/ca --id ih-alice --role device --out /pki/members/ih-alice
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/cli"
	"github.com/antoniopaya22/iam-ids-sdp/internal/pki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "ca":
		fs := flag.NewFlagSet("ca", flag.ExitOnError)
		dir := fs.String("dir", "/pki/ca", "CA directory")
		days := fs.Int("days", 365, "validity in days")
		_ = fs.Parse(os.Args[2:])
		if _, err := os.Stat(filepath.Join(*dir, "ca.key")); err == nil {
			fmt.Println("CA already exists in", *dir)
			return
		}
		ca, err := pki.NewCA("iam-ids-sdp lab CA", time.Duration(*days)*24*time.Hour)
		if err != nil {
			cli.Fatalf(1, "ca: %v", err)
		}
		if err := ca.Save(*dir); err != nil {
			cli.Fatalf(1, "ca: %v", err)
		}
		fmt.Println("CA created in", *dir)
	case "issue":
		fs := flag.NewFlagSet("issue", flag.ExitOnError)
		caDir := fs.String("ca", "/pki/ca", "CA directory")
		id := fs.String("id", "", "component id (certificate CN)")
		role := fs.String("role", "", "device, gateway, controller, ids or server (certificate OU)")
		dns := fs.String("dns", "", "comma-separated DNS SANs")
		ips := fs.String("ip", "", "comma-separated IP SANs")
		out := fs.String("out", "", "output directory")
		days := fs.Int("days", 90, "validity in days")
		_ = fs.Parse(os.Args[2:])
		if *id == "" || *role == "" || *out == "" {
			fs.Usage()
			os.Exit(2)
		}
		ca, err := pki.LoadCA(*caDir)
		if err != nil {
			cli.Fatalf(1, "issue: %v", err)
		}
		m := pki.Member{ID: *id, Role: *role, DNSNames: cli.List(*dns), Validity: time.Duration(*days) * 24 * time.Hour}
		for _, s := range cli.List(*ips) {
			ip := net.ParseIP(s)
			if ip == nil {
				cli.Fatalf(2, "issue: invalid ip %q", s)
			}
			m.IPs = append(m.IPs, ip)
		}
		if err := ca.IssueTo(m, *out); err != nil {
			cli.Fatalf(1, "issue: %v", err)
		}
		fmt.Printf("issued %s (%s) -> %s\n", *id, *role, *out)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sdp-pki ca --dir DIR | sdp-pki issue --ca DIR --id ID --role ROLE [--dns ..] [--ip ..] --out DIR")
	os.Exit(2)
}
