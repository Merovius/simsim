// Copyright 2018 Axel Wagner
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kr/pty"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

var newGroup = flag.String("group", "", "Primary group of newly created users")

func run() error {
	listen := flag.String("listen", "0.0.0.0:22", "Port to listen on")
	flag.Parse()

	cfg := ssh.ServerConfig{
		PublicKeyCallback: checkPublicKey,
		AuthLogCallback:   logAuth,
	}
	if err := ed25519key(&cfg); err != nil {
		return err
	}

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go serveConn(c, cfg)
	}
}

func ed25519key(cfg *ssh.ServerConfig) error {
	buf, err := ioutil.ReadFile("ed25519.key")
	if err == nil {
		return pemKey(cfg, buf)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sig, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return err
	}

	w := new(bytes.Buffer)
	w.WriteString("openssh-key-v1\x00")

	key := struct {
		Pub     []byte
		Priv    []byte
		Comment string
		Pad     []byte `ssh:"rest"`
	}{pub, priv, "", nil}

	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}{0, 0, ssh.KeyAlgoED25519, ssh.Marshal(key)}

	k := struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}{"none", "none", "", 1, nil, ssh.Marshal(&pk1)}

	w.Write(ssh.Marshal(k))

	buf = pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: w.Bytes()})
	if err := ioutil.WriteFile("ed25519.key", buf, 0600); err != nil {
		return err
	}
	cfg.AddHostKey(sig)
	return nil
}

func pemKey(cfg *ssh.ServerConfig, b []byte) error {
	k, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return err
	}
	cfg.AddHostKey(k)
	return nil
}

func logAuth(md ssh.ConnMetadata, method string, err error) {
	if err == nil {
		log.Printf("Successful %q login for %q from %v", method, md.User(), md.RemoteAddr())
		return
	}
	log.Printf("Failed %q login for %q from %v: %v", method, md.User(), md.RemoteAddr(), err)
}

func checkPublicKey(md ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
	username := strings.ToLower(md.User())
	for _, r := range username {
		if r < 'a' || r > 'z' {
			return nil, errors.New("invalid user name")
		}
	}

	u, err := lookupUser(username)
	if err != nil {
		if _, err = createUser(username, ssh.MarshalAuthorizedKey(pub)); err != nil {
			return nil, err
		}
		return permissions, nil
	}
	f, err := os.Open(filepath.Join(u.HomeDir, ".ssh", "authorized_keys"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		k, _, _, _, err := ssh.ParseAuthorizedKey(s.Bytes())
		if err != nil {
			return nil, err
		}
		if k.Type() != pub.Type() {
			continue
		}
		if bytes.Compare(k.Marshal(), pub.Marshal()) == 0 {
			return permissions, nil
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("unauthorized")
}

var permissions = &ssh.Permissions{}

func serveConn(c net.Conn, cfg ssh.ServerConfig) {
	defer c.Close()

	sc, ch, reqs, err := ssh.NewServerConn(c, &cfg)
	if err != nil {
		log.Println(err)
		return
	}
	defer sc.Close()

	u, err := lookupUser(strings.ToLower(sc.User()))
	if err != nil {
		log.Println(err)
		return
	}

	for {
		select {
		case nch, ok := <-ch:
			if !ok {
				log.Println("conn closed")
				return
			}
			log.Printf("NewChannel(%q): %q", nch.ChannelType(), nch.ExtraData())
			switch nch.ChannelType() {
			case "session":
				ch, reqs, err := nch.Accept()
				go serveSession(u, ch, reqs, err)
			default:
				nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("channel type %q not supported", nch.ChannelType()))
			}
		case req := <-reqs:
			log.Printf("Request(%q, %v): %q", req.Type, req.WantReply, req.Payload)
			if err := req.Reply(false, []byte(fmt.Sprintf("request type %q not supported", req.Type))); err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func serveSession(u *user, ch ssh.Channel, reqs <-chan *ssh.Request, err error) {
	defer func() {
		ch.Close()
		for range reqs {
		}
	}()
	if err != nil {
		log.Println(err)
		return
	}

	var (
		env      []string
		allocPty *requestPTY
	)

	done := make(chan struct{})

	for {
		var req *ssh.Request
		select {
		case r, ok := <-reqs:
			if !ok {
				return
			}
			req = r
		case <-done:
			return
		}
		r, err := parseRequest(req.Type, req.Payload)
		if err != nil {
			log.Println(err)
			req.Reply(false, []byte(err.Error()))
			continue
		}
		switch r := r.(type) {
		case *requestEnv:
			env = append(env, fmt.Sprintf("%s=%s", r.Name, r.Value))
		case *requestPTY:
			if allocPty != nil {
				err = errors.New("duplicate pty-req")
			}
			allocPty = r
			env = append(env, "TERM="+r.Term)
		case *requestExec:
			cmd := exec.Command(r.Command)
			err = runCommand(ch, cmd, env, u, allocPty, done)
			if err == nil {
				defer cmd.Process.Kill()
			}
		case *requestShell:
			shell := u.Shell
			if shell == "" {
				shell = "/bin/bash"
			}
			cmd := exec.Command(shell, "-l")
			err = runCommand(ch, cmd, env, u, allocPty, done)
			if err == nil {
				defer cmd.Process.Kill()
			}
		default:
			err = fmt.Errorf("request type %T not handled")
		}
		if err != nil {
			log.Println(err)
			req.Reply(false, []byte(err.Error()))
		} else if req.WantReply {
			req.Reply(true, nil)
		}
	}
}

func runCommand(ch io.ReadWriter, cmd *exec.Cmd, env []string, u *user, allocPty *requestPTY, done chan struct{}) error {
	cmd.Dir = u.HomeDir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(u.Uid),
			Gid: uint32(u.Gid),
		},
		Setsid:  true,
		Setctty: true,
	}
	for _, g := range u.Groups {
		cmd.SysProcAttr.Credential.Groups = append(cmd.SysProcAttr.Credential.Groups, uint32(g.Gid))
	}

	var err error
	if allocPty != nil {
		var f *os.File
		f, err = pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(allocPty.Rows), Cols: uint16(allocPty.Columns), X: uint16(allocPty.Height), Y: uint16(allocPty.Width)})
		if err == nil {
			defer f.Close()
		}
		go io.Copy(ch, f)
		go io.Copy(f, ch)
	} else {
		err = cmd.Start()
	}
	if err == nil {
		go func() {
			if err := cmd.Wait(); err != nil {
				log.Println(err)
			}
			close(done)
		}()
	}
	return err
}

type requestPTY struct {
	Term    string
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
	Modes   string
}

type requestEnv struct {
	Name  string
	Value string
}

type requestShell struct {
}

type requestExec struct {
	Command string
}

func parseRequest(t string, b []byte) (interface{}, error) {
	var r interface{}
	switch t {
	case "pty-req":
		r = new(requestPTY)
	case "env":
		r = new(requestEnv)
	case "exec":
		r = new(requestExec)
	case "shell":
		return new(requestShell), nil
	default:
		return nil, fmt.Errorf("request %q not supported", t)
	}
	return r, ssh.Unmarshal(b, r)
}
