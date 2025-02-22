// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"context"
	"fmt"

	ssh2vsock_types "github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/provider"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/crypto/ssh"
)

const (
	socatProxyCommand = "/usr/bin/socat - VSOCK-CONNECT:%d:%d"
)

func openHypervisorConnection(reqCtx, sshContext context.Context, hypervisor ssh2vsock_types.HypervisorConnectionSpec) (*ssh.Client, diag.Diagnostics) {
	hypervisorHostKeyCallback, err := hypervisor.HypervisorHostKeyCallback(reqCtx)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to generate hypervisor host key callback",
				fmt.Sprintf("failed to generate hypervisor host key callback: %s", err.Error()),
			),
		}
	}
	hypervisorAuthMethod, err := hypervisor.HypervisorAuthMethod()
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to get hypervisor authn methods",
				fmt.Sprintf("failed to get hypervisor authn methods: %s", err.Error()),
			),
		}
	}
	var hypervisorAuthMethodList []ssh.AuthMethod
	if hypervisorAuthMethod != nil {
		hypervisorAuthMethodList = append(hypervisorAuthMethodList, hypervisorAuthMethod)
	}

	acceptedAlgorithms, err := hypervisor.HypervisorAcceptedAlgorithms(reqCtx)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to get accepted algorithms",
				fmt.Sprintf("failed to get accepted algorithms: %s", err.Error()),
			),
		}
	}

	sshConfig := ssh.ClientConfig{
		User:              hypervisor.HypervisorUsername(),
		HostKeyCallback:   hypervisorHostKeyCallback,
		Auth:              hypervisorAuthMethodList,
		HostKeyAlgorithms: acceptedAlgorithms,
	}

	sshServerAddr := fmt.Sprintf("%s:%d", hypervisor.HypervisorHostname(), hypervisor.HypervisorPort())
	sshClient, err := ssh.Dial("tcp", sshServerAddr, &sshConfig)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to connect to the hypervisor",
				fmt.Sprintf("failed to connect to the hypervisor %s: %s", sshServerAddr, err.Error()),
			),
		}
	}

	// Simulates that the ssh client handles context cancellation
	go func() {
		<-sshContext.Done()
		if err := sshClient.Close(); err != nil {
			tflog.Error(sshContext, fmt.Sprintf("failed to close hypervisor connection: %s", err.Error()))
		}
	}()
	return sshClient, nil
}

func openGuestConnection(reqCtx, sshContext context.Context, hypervisorSSHClient *ssh.Client, hypervisor ssh2vsock_types.HypervisorConnectionSpec, guest ssh2vsock_types.GuestConnectionSpec, keyAlgorithmConstraints []string) (*ssh.Client, diag.Diagnostics) {
	// Starting a new SSH session to run the proxy command
	sess, err := hypervisorSSHClient.NewSession()
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to establish a new session",
				fmt.Sprintf("failed to establish a new session: %s", err.Error()),
			),
		}
	}

	cmd := fmt.Sprintf(socatProxyCommand, guest.GuestCID(), guest.GuestPort())

	// Wrap the ProxyCommand into a net.Conn type so that we can start a new SSH connection over it
	innerNetConn, err := FromSSHSession(sess, guest.GuestCID(), guest.GuestPort())
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to wrap session as a network connection",
				fmt.Sprintf("failed to wrap session as a network connection: %s", err.Error()),
			),
		}
	}

	if err := sess.Start(cmd); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to start command",
				fmt.Sprintf("failed to start command %q: %s", cmd, err.Error()),
			),
		}
	}

	// Simulates that the ssh client handles context cancellation
	go func() {
		<-sshContext.Done()
		if err := sess.Signal(ssh.SIGINT); err != nil {
			tflog.Error(sshContext, fmt.Sprintf("failed to send signal the proxy command: %s", err.Error()))
		}
	}()

	guestHostKeyCallback, err := guest.GuestHostKeyCallback(reqCtx)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to get host key callback for the guest",
				fmt.Sprintf("failed to get host key callback for the guest %d: %s", guest.GuestCID(), err.Error()),
			),
		}
	}
	guestAuthMethod, err := guest.GuestAuthMethod()
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to get the guest authn method",
				fmt.Sprintf("failed to get the guest authn method: %s", err.Error()),
			),
		}
	}
	var guestAuthMethodList []ssh.AuthMethod
	if guestAuthMethod != nil {
		guestAuthMethodList = append(guestAuthMethodList, guestAuthMethod)
	}

	acceptedAlgorithms := keyAlgorithmConstraints
	if acceptedAlgorithms == nil {
		acceptedAlgorithms, err = hypervisor.HypervisorAcceptedAlgorithms(reqCtx)
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"failed to get accepted algorithms",
					fmt.Sprintf("failed to get accepted algorithms: %s", err.Error()),
				),
			}
		}
	}

	guestSSHConfig := ssh.ClientConfig{
		HostKeyCallback:   guestHostKeyCallback,
		Auth:              guestAuthMethodList,
		User:              guest.GuestUsername(),
		HostKeyAlgorithms: acceptedAlgorithms,
	}

	innerSSHConn, newChannelChan, requestChan, err := ssh.NewClientConn(innerNetConn, fmt.Sprintf("vsock:%d:%d", guest.GuestCID(), guest.GuestPort()), &guestSSHConfig)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to establish SSH connection to the guest",
				fmt.Sprintf("failed to establish SSH connection to the guest: %s", err.Error()),
			),
		}
	}
	innerSSHClient := ssh.NewClient(innerSSHConn, newChannelChan, requestChan)
	return innerSSHClient, nil
}
