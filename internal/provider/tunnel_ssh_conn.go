// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	_ net.Conn = (*SSHConnFromSession)(nil)
	_ net.Addr = (*VSockAddr)(nil)
)

type VSockAddr struct {
	cid  int
	port int
}

func (a *VSockAddr) Network() string {
	return "vsock"
}

func (a *VSockAddr) String() string {
	return fmt.Sprintf("vsock:%d:%d", a.cid, a.port)
}

type SSHConnFromSession struct {
	readPipe  io.Reader
	writePipe io.WriteCloser
	cid       int
	port      int
}

func FromSSHSession(sess *ssh.Session, CID, port int) (net.Conn, error) {
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}

	return &SSHConnFromSession{
		readPipe:  stdout,
		writePipe: stdin,
		cid:       CID,
		port:      port,
	}, nil
}

func (c *SSHConnFromSession) Read(b []byte) (n int, err error) {
	return c.readPipe.Read(b)
}

func (c *SSHConnFromSession) Write(b []byte) (n int, err error) {
	return c.writePipe.Write(b)
}

func (c *SSHConnFromSession) Close() error {
	return c.writePipe.Close()
}

func (c *SSHConnFromSession) LocalAddr() net.Addr {
	return nil
}

func (c *SSHConnFromSession) RemoteAddr() net.Addr {
	return &VSockAddr{
		cid:  c.cid,
		port: c.port,
	}
}

func (c *SSHConnFromSession) SetDeadline(_ time.Time) error {
	return nil
}

func (c *SSHConnFromSession) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *SSHConnFromSession) SetWriteDeadline(_ time.Time) error {
	return nil
}
