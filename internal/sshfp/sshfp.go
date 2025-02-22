// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sshfp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

const (
	caFileMaxSize = 5 * 1024 * 102
)

var (
	ErrPublicKeyNotFound   = errors.New("public key not found")
	ErrPublicKeyRetrieval  = errors.New("failed to retrieve public key")
	ErrUnauthenticatedData = errors.New("unauthenticated data refused")
	ErrInvalidSSHFPRecord  = errors.New("invalid SSHFP error")

	// https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml
	SSHFPAlgoToKeyType = map[int][]string{
		1: {ssh.KeyAlgoRSA},
		2: {ssh.KeyAlgoDSA},
		3: {ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
		4: {ssh.KeyAlgoED25519},
		6: {}, // Not implemented by x/crypto/ssh at the time of writing
	}
	KeyTypeToSSHFPAlgo = map[string]int{
		ssh.KeyAlgoRSA:      1,
		ssh.KeyAlgoDSA:      2,
		ssh.KeyAlgoECDSA256: 3,
		ssh.KeyAlgoECDSA384: 3,
		ssh.KeyAlgoECDSA521: 3,
		ssh.KeyAlgoED25519:  4,
	}
)

type exchangerWithContext interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type Checker struct {
	dnsServer  string
	initClient func() (exchangerWithContext, error)
}

func getRootCAsFromFile(caFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	f, err := os.Open(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %w", caFile, err)
	}
	defer f.Close()
	fileContent, err := io.ReadAll(io.LimitReader(f, caFileMaxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read from certificate files: %w", err)
	}

	for len(fileContent) > 0 {
		derCert, rest := pem.Decode(fileContent)
		if len(rest) == len(fileContent) {
			// No more recognizable cert
			break
		}
		fileContent = rest
		cert, err := x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

func realInitClient(caFile string) (exchangerWithContext, error) {
	c := new(dns.Client)
	if caFile != "" {
		c.Net = "tcp-tls"
		rootCAs, err := getRootCAsFromFile(caFile)
		if err != nil {
			return nil, err
		}
		c.TLSConfig = &tls.Config{
			RootCAs: rootCAs,
		}
	} else {
		c.Net = "tcp"
	}
	return c, nil
}

func NewChecker(dnsServer, caFile string) *Checker {
	return &Checker{
		initClient: func() (exchangerWithContext, error) {
			return realInitClient(caFile)
		},
		dnsServer: dnsServer,
	}
}

func (c *Checker) queryDNSRecords(ctx context.Context, hostname string) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(hostname, dns.TypeSSHFP)
	req.RecursionDesired = true
	req.SetEdns0(4096, true)

	dnsClient, err := c.initClient()
	if err != nil {
		return nil, err
	}

	resp, _, err := dnsClient.ExchangeContext(ctx, req, c.dnsServer)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, ErrPublicKeyRetrieval
	}
	if !resp.AuthenticatedData {
		return nil, ErrUnauthenticatedData // DNSSEC is not strictly required by the RFC, but we follow a secure by default approach
	}
	return resp, nil
}

func (c *Checker) Check(ctx context.Context, hostname string, pubKey ssh.PublicKey) error {
	canonName := dns.CanonicalName(hostname)
	resp, err := c.queryDNSRecords(ctx, canonName)
	if err != nil {
		return err
	}

	publicKeyWire := pubKey.Marshal()
	hashObj := sha256.New()
	if _, err := hashObj.Write(publicKeyWire); err != nil {
		return err
	}
	publicKeySHA256HexDigest := hex.EncodeToString(hashObj.Sum(nil))

	for _, answer := range resp.Answer {
		if answer.Header().Name != canonName {
			continue
		}
		if answer.Header().Rrtype != dns.TypeSSHFP {
			continue
		}
		sshfpAnswer, ok := answer.(*dns.SSHFP)
		if !ok {
			return ErrInvalidSSHFPRecord
		}

		var found bool
		validAlgos := SSHFPAlgoToKeyType[int(sshfpAnswer.Algorithm)]
		for _, validAlgo := range validAlgos {
			if pubKey.Type() == validAlgo {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		switch sshfpAnswer.Type {
		case 1: // SHA1
			continue // SHA1 is weak, deprecated, and should no longer be used; adopting a secure by default approach
		case 2: // SHA256
			if publicKeySHA256HexDigest == sshfpAnswer.FingerPrint {
				return nil
			}
		default:
			continue // Invalid or unknown hash type
		}
	}
	return ErrPublicKeyNotFound
}

func (c *Checker) PubKeyTypes(ctx context.Context, hostname string) (map[string]struct{}, error) {
	canonName := dns.CanonicalName(hostname)
	resp, err := c.queryDNSRecords(ctx, canonName)
	if err != nil {
		return nil, err
	}

	pubKeyTypes := make(map[string]struct{})
	for _, answer := range resp.Answer {
		if answer.Header().Name != canonName {
			continue
		}
		if answer.Header().Rrtype != dns.TypeSSHFP {
			continue
		}
		sshfpAnswer, ok := answer.(*dns.SSHFP)
		if !ok {
			return nil, ErrInvalidSSHFPRecord
		}
		for _, algo := range SSHFPAlgoToKeyType[int(sshfpAnswer.Algorithm)] {
			pubKeyTypes[algo] = struct{}{}
		}
	}
	return pubKeyTypes, nil
}
