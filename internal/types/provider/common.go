// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package types

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/sshfp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	PrivateKeyMaxSize = 100 * 1024
)

var (
	ErrHostnameNotFound           = errors.New("hostname not found")
	ErrPublicKeyNotFound          = errors.New("public key not found")
	ErrNoAuthnMethodDefined       = errors.New("no authentication method defined")
	ErrNoAgentSocketPathSpecified = errors.New("no agent socket path specified")
)

type PrivateKeySpec struct {
	Path       string
	Passphrase string
}

type AgentSpec struct {
	Use      bool
	SockPath string
}

type KnownHostsSpec struct {
	Ignore bool
	List   []string
	File   string
}

type SSHFPSpec struct {
	Use                       bool
	DNSRecursiveServerAddress string
	CAFile                    string
}

func getAuthMethodFromAgent(sockPath string) (ssh.AuthMethod, error) {
	if sockPath == "" {
		sockPath = os.Getenv("SSH_AUTH_SOCK")
	}
	if sockPath == "" {
		return nil, ErrNoAgentSocketPathSpecified
	}
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the agent socket: %w", err)
	}
	agent := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agent.Signers), nil
}

func getAuthMethodFromPrivateKey(pk PrivateKeySpec) (ssh.AuthMethod, error) {
	f, err := os.Open(pk.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key file %q: %w", pk.Path, err)
	}
	defer f.Close()
	privateKeyBytes, err := io.ReadAll(io.LimitReader(f, PrivateKeyMaxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	if pk.Passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(pk.Passphrase))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %q with passphrase: %w", pk.Path, err)
		}
		return ssh.PublicKeys(signer), nil
	}
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key %q: %w", pk.Path, err)
	}
	return ssh.PublicKeys(signer), nil
}

func CompareKnownHostWithHMAC(soughtHostname, hostEntry string) (bool, error) {
	hostParts := strings.Split(hostEntry, "|")
	if len(hostParts) != 4 {
		return false, fmt.Errorf(`invalid hashed known host entry: host is malformed; expected "|1|salt|hmac", found %q`, hostEntry)
	}
	salt := hostParts[2]
	hashedHostname := hostParts[3]

	decodedSalt, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false, fmt.Errorf("invalid hashed known host entry: failed to decode base64 representation of the salt %q: %s", hostEntry, err.Error())
	}
	hmacSha1 := hmac.New(sha1.New, decodedSalt)
	hmacSha1.Write([]byte(soughtHostname))
	hashedGuestHostname := hmacSha1.Sum(nil)
	encodedHashedGuestHostname := base64.StdEncoding.EncodeToString(hashedGuestHostname)
	return hashedHostname == encodedHashedGuestHostname, nil
}

func checkHostname(soughtHostname string, hostnameCandidates []string) error {
	for _, hostnameCandidate := range hostnameCandidates {
		if strings.HasPrefix(hostnameCandidate, "|1|") {
			if ok, err := CompareKnownHostWithHMAC(soughtHostname, hostnameCandidate); err != nil {
				return fmt.Errorf("failed to compare hostnames %q and %q: %w", soughtHostname, hostnameCandidate, err)
			} else if ok {
				return nil
			}
		} else if hostnameCandidate == soughtHostname {
			return nil
		}
	}
	return ErrHostnameNotFound
}

func getKnownHostsFromList(soughtHostname string, unfilteredKnownHosts []string) ([]ssh.PublicKey, error) {
	var knownHosts []ssh.PublicKey
	for _, unfilteredKnownHost := range unfilteredKnownHosts {
		_, hosts, publicKey, _, rest, err := ssh.ParseKnownHosts([]byte(unfilteredKnownHost))
		if err != nil {
			return nil, fmt.Errorf("invalid known host entry: %q is invalid or truncated: %w", unfilteredKnownHost, err)
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("invalid known host entry: %q is longer than expected. Only one known host is expected per list entry: %w", unfilteredKnownHost, err)
		}

		if err := checkHostname(soughtHostname, hosts); err != nil {
			continue
		}
		knownHosts = append(knownHosts, publicKey)
	}
	return knownHosts, nil
}

func getKnownHostsFromFile(soughtHostname, knownHostsFile string) ([]ssh.PublicKey, error) {
	if knownHostsFile == "" {
		return nil, nil
	}

	f, err := os.Open(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open known host file %q: %w", knownHostsFile, err)
	}
	defer f.Close()

	var knownHosts []ssh.PublicKey
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		_, hosts, publicKey, _, rest, err := ssh.ParseKnownHosts(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse a ligne in known hosts file: %q: %w", scanner.Text(), err)
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("invalid known hosts line: %q is longer than expected. Only one known host is expected per list entry: %w", scanner.Text(), err)
		}

		if err := checkHostname(soughtHostname, hosts); err != nil {
			continue
		}
		knownHosts = append(knownHosts, publicKey)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("invalid known hosts file: %w", err)
	}
	return knownHosts, nil
}

func getPubKeys(hostname string, port int, knownHostList []string, knownHostFile string) ([]ssh.PublicKey, error) {
	hostAddr := knownhosts.Normalize(fmt.Sprintf("%s:%d", hostname, port))

	var pubKeys []ssh.PublicKey
	if pubKeysFromList, err := getKnownHostsFromList(hostAddr, knownHostList); err != nil {
		return nil, err
	} else {
		pubKeys = append(pubKeys, pubKeysFromList...)
	}

	if pubKeysFromFile, err := getKnownHostsFromFile(hostAddr, knownHostFile); err != nil {
		return nil, err
	} else {
		pubKeys = append(pubKeys, pubKeysFromFile...)
	}
	return pubKeys, nil
}

func verifyKeys(ctx context.Context, hostname string, sshfpConfig SSHFPSpec, pubKeys []ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		keyBytes := key.Marshal()

		for _, knownPubKey := range pubKeys {
			if bytes.Equal(keyBytes, knownPubKey.Marshal()) {
				return nil
			}
		}

		if sshfpConfig.Use {
			c := sshfp.NewChecker(sshfpConfig.DNSRecursiveServerAddress, sshfpConfig.CAFile)
			return c.Check(ctx, hostname, key)
		}
		return ErrPublicKeyNotFound
	}
}

func getAcceptedAlgorithms(ctx context.Context, hostname string, port int, knownHostList []string, knownHostFile string, sshfpSpec SSHFPSpec) ([]string, error) {
	pubKeys, err := getPubKeys(hostname, port, knownHostList, knownHostFile)
	if err != nil {
		return nil, err
	}
	pubKeyTypes := make(map[string]struct{})
	for _, pubKey := range pubKeys {
		pubKeyTypes[pubKey.Type()] = struct{}{}
	}

	if sshfpSpec.Use {
		c := sshfp.NewChecker(sshfpSpec.DNSRecursiveServerAddress, sshfpSpec.CAFile)
		sshfpTypes, err := c.PubKeyTypes(ctx, hostname)
		if err != nil {
			return nil, err
		}
		for algo := range sshfpTypes {
			pubKeyTypes[algo] = struct{}{}
		}

	}
	var pubKeyTypeList []string
	for pubKeyType := range pubKeyTypes {
		pubKeyTypeList = append(pubKeyTypeList, pubKeyType)
	}

	return pubKeyTypeList, nil
}

type HypervisorConnectionSpec interface {
	HypervisorHostname() string
	HypervisorPort() int
	HypervisorUsername() string
	HypervisorHostKeyCallback(context.Context) (ssh.HostKeyCallback, error)
	HypervisorAcceptedAlgorithms(context.Context) ([]string, error)
	HypervisorAuthMethod() (ssh.AuthMethod, error)
}

type GuestConnectionSpec interface {
	GuestCID() int
	GuestPort() int
	GuestUsername() string
	GuestHostKeyCallback(context.Context) (ssh.HostKeyCallback, error)
	GuestAcceptedAlgorithms(context.Context) ([]string, error)
	GuestAuthMethod() (ssh.AuthMethod, error)
}
