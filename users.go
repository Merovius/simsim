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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type user struct {
	Uid      int
	Gid      int
	Username string
	Name     string
	HomeDir  string
	Shell    string
	Groups   []group
}

type group struct {
	Gid  int
	Name string
}

func lookupUser(name string) (*user, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var u *user

	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		if !strings.HasPrefix(l, name+":") || strings.HasPrefix(l, "#") {
			continue
		}
		u, err = parsePasswd(l)
		if err == nil {
			break
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("user %q not found", name)
	}

	f, err = os.Open("/etc/group")
	if err != nil {
		return u, nil
	}
	defer f.Close()

	s = bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		// wireshark:x:974:mero
		sp := strings.SplitN(l, ":", 5)
		if len(sp) != 4 || strings.HasPrefix(l, "#") {
			continue
		}
		members := strings.Split(sp[3], ",")
		for _, uname := range members {
			if uname != name {
				continue
			}
			gid, err := strconv.Atoi(sp[2])
			if err != nil {
				continue
			}
			u.Groups = append(u.Groups, group{
				Gid:  gid,
				Name: sp[0],
			})
			break
		}
	}
	return u, nil
}

func parsePasswd(line string) (*user, error) {
	// mero:x:1000:1000:Axel Wagner:/home/mero:/usr/bin/zsh
	sp := strings.SplitN(line, ":", 8)
	if len(sp) != 7 {
		return nil, errors.New("wrong number of fields")
	}
	uid, err := strconv.Atoi(sp[2])
	if err != nil {
		return nil, fmt.Errorf("invalid uid: %v", err)
	}
	gid, err := strconv.Atoi(sp[3])
	if err != nil {
		return nil, fmt.Errorf("invalid gid: %v", err)
	}
	i := strings.IndexByte(sp[4], ',')
	if i >= 0 {
		sp[4] = sp[4][:i]
	}
	return &user{
		Uid:      uid,
		Gid:      gid,
		Username: sp[0],
		Name:     sp[4],
		HomeDir:  sp[5],
		Shell:    sp[6],
	}, nil
}

func createUser(name string, pubkey []byte) (u *user, err error) {
	args := []string{"-m", name}
	if *newGroup != "" {
		args = append(args, "-g", *newGroup)
	}

	if err = exec.Command("useradd", args...).Run(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			exec.Command("userdel", "-r", "-Z", "-f", name)
		}
	}()
	if u, err = lookupUser(name); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Join(u.HomeDir, ".ssh"), 0700); err != nil {
		return nil, err
	}
	if err = os.Chown(filepath.Join(u.HomeDir, ".ssh"), u.Uid, u.Gid); err != nil {
		return nil, err
	}
	if err = ioutil.WriteFile(filepath.Join(u.HomeDir, ".ssh", "authorized_keys"), pubkey, 0600); err != nil {
		return nil, err
	}
	if err = os.Chown(filepath.Join(u.HomeDir, ".ssh", "authorized_keys"), u.Uid, u.Gid); err != nil {
		return nil, err
	}
	return u, nil
}
