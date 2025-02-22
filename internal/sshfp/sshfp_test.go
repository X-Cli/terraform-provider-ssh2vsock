// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sshfp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

type MockExchanger struct {
	queryMapper map[string]*dns.Msg
}

func (me *MockExchanger) ExchangeContext(ctx context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	if len(m.Question) != 1 {
		return nil, time.Millisecond, fmt.Errorf("too many questions: %d", len(m.Question))
	}
	qry := fmt.Sprintf("%s %d", m.Question[0].Name, m.Question[0].Qtype)
	return me.queryMapper[qry], time.Millisecond, nil
}

func TestSSHFPValid(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRR, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 2 ac98cf33320e8d967d7ca9359077183001c6a42ce94d7d1622d967316b92dd82")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRR)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	if err := c.Check(context.Background(), "www.example.com.", pubKey); err != nil {
		t.Fatalf("failed to check key: %s", err.Error())
	}
}

func TestSSHFPValidSHA1(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRR, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 1 76db57aaacb8032ea3fe032df8147923be4617f5")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRR)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
		t.Fatal("should not have validated")
	case ErrPublicKeyNotFound:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPValidSHA1AndSHA256(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRRSHA1, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 1 76db57aaacb8032ea3fe032df8147923be4617f5")
			if err != nil {
				return nil, err
			}
			exampleSSHFPRRSHA2, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 2 ac98cf33320e8d967d7ca9359077183001c6a42ce94d7d1622d967316b92dd82")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRRSHA1, exampleSSHFPRRSHA2)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPAlgoMismatch(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRR, err := dns.NewRR("www.example.com. 3600 IN SSHFP 3 2 ac98cf33320e8d967d7ca9359077183001c6a42ce94d7d1622d967316b92dd82")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRR)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
		t.Fatalf("unexpected success")
	case ErrPublicKeyNotFound:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPAlgoSomeMismatch(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRR, err := dns.NewRR("www.example.com. 3600 IN SSHFP 3 2 ac98cf33320e8d967d7ca9359077183001c6a42ce94d7d1622d967316b92dd82")
			if err != nil {
				return nil, err
			}
			exampleSSHFPRRSHA2, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 2 ac98cf33320e8d967d7ca9359077183001c6a42ce94d7d1622d967316b92dd82")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRR, exampleSSHFPRRSHA2)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}

	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPNXDomain(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Rcode = dns.RcodeNXRrset
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
		t.Fatalf("unexpected success")
	case ErrPublicKeyRetrieval:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPServFail(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.Rcode = dns.RcodeServerFailure
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
		t.Fatalf("unexpected success")
	case ErrPublicKeyRetrieval:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPFakeData(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRR, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 1 76db57aaacb8032ea3fe032df8147923be4617f5")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = false
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRR)

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
		t.Fatalf("unexpected success")
	case ErrUnauthenticatedData:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestSSHFPUnsupportedHashType(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := Checker{
		initClient: func() (exchangerWithContext, error) {
			exampleSSHFPRR, err := dns.NewRR("www.example.com. 3600 IN SSHFP 4 3 76db57aaacb8032ea3fe032df8147923be4617f5")
			if err != nil {
				return nil, err
			}

			exampleSSHFP := new(dns.Msg)
			exampleSSHFP.SetQuestion("www.example.com.", dns.TypeSSHFP)
			exampleSSHFP.RecursionDesired = true
			exampleSSHFP.RecursionAvailable = true
			exampleSSHFP.AuthenticatedData = true
			exampleSSHFP.Answer = append(exampleSSHFP.Answer, exampleSSHFPRR)

			return &MockExchanger{
				queryMapper: map[string]*dns.Msg{
					"www.example.com. 44": exampleSSHFP,
				},
			}, nil
		},
	}
	err = c.Check(context.Background(), "www.example.com.", pubKey)
	switch err {
	case nil:
		t.Fatalf("unexpected success")
	case ErrPublicKeyNotFound:
	default:
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestInstanceTLSChecker(t *testing.T) {
	tmpdir := t.TempDir()

	caFilePath := path.Join(tmpdir, "ca-certificates.crt")
	f, err := os.OpenFile(caFilePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("failed to write CA file: %s", err.Error())
	}
	if _, err := io.WriteString(f, `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----`); err != nil {
		t.Fatalf("failed to write CA cert to file: %s", err.Error())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close ca file: %s", err.Error())
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(`AAAAC3NzaC1lZDI1NTE5AAAAIOanI/n31T2H+H0ec01BXkxSBbdk4vrLA1QJf2eTwOF2`)
	if err != nil {
		t.Fatalf("failed to decode public key: %s", err.Error())
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key during setup: %s", err.Error())
	}

	c := NewChecker("localhost:1", caFilePath)
	err = c.Check(context.Background(), "www.example.com", pubKey)

	if err == nil {
		t.Fatal("unexpected success; should have failed to connect on port 1")
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("unexpected error: should have been a connection failure: %s", err.Error())
	}
	sysErr, ok := opErr.Err.(*os.SyscallError)
	if !ok {
		t.Fatalf("unexpected error: should have been a connection failure: %s", err.Error())
	}
	if sysErr.Err != syscall.ECONNREFUSED {
		t.Fatalf("unexpected error: should have been a connection failure: %s", err.Error())
	}
}
