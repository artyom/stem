// +build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"syscall"

	"github.com/artyom/autoflags"
)

func main() {
	conf := config{}
	if err := autoflags.Define(&conf); err != nil {
		log.Fatal(err)
	}
	flag.Parse()
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	mounts, err := conf.Mounts.Get()
	if err != nil {
		log.Fatal(err)
	}
	for _, mt := range mounts {
		if err := mt.Check(conf.Dir); err != nil {
			log.Fatal(err)
		}
	}

	// need to lock thread so that mounts are done in the same thread to
	// which Unshare was applied
	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		log.Fatal(err)
	}
	for _, m := range mounts {
		to := path.Join(conf.Dir, m.To)
		if err := syscall.Mount(m.From, to, "", syscall.MS_BIND, ""); err != nil {
			log.Fatalf("mount %s to %s: %v", m.From, to, err)
		}
	}
	if conf.MountDev {
		if err := syscall.Mount("none", path.Join(conf.Dir, "dev"), "devtmpfs", 0, ""); err != nil {
			log.Fatal("mount /dev inside chroot: " + err.Error())
		}
	}
	cmd := exec.Command(flag.Args()[0], flag.Args()[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:     conf.Dir,
		Cloneflags: syscall.CLONE_NEWPID,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	Dir      string `flag:"root,root filesystem to start chrooted process into"`
	MountDev bool   `flag:"withdev,mount devtmpfs on /dev inside chroot (directory should exist)"`
	Mounts   Mounts `flag:"mount,bind-mount pairs "target:destination", where destination is relative to chroot dir"`
}

type Mounts []string

func (m *Mounts) String() string { return fmt.Sprint(*m) }
func (m *Mounts) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func (mounts Mounts) Get() ([]Mount, error) {
	out := make([]Mount, len(mounts))
	for i, cand := range mounts {
		s := strings.SplitN(cand, ":", 2)
		if len(s) != 2 || s[0] == "" || s[1] == "" {
			return nil, errors.New("invalid flag format, should be \"souce:destination\": " + cand)
		}
		out[i] = Mount{From: s[0], To: s[1]}
	}
	return out, nil
}

type Mount struct {
	From string
	To   string
}

func (m *Mount) Check(root string) error {
	if !path.IsAbs(m.From) {
		return errors.New("mounts should use absolute paths: " + m.From)
	}
	if !path.IsAbs(m.To) {
		return errors.New("mounts should use absolute paths: " + m.To)
	}
	if _, err := os.Stat(m.From); err != nil {
		return err
	}
	to := path.Join(root, m.To)
	if to == root {
		return errors.New("mount destination should not be the chroot directory itself")
	}
	if _, err := os.Stat(to); err != nil {
		return err
	}
	return nil
}

func init() {
	log.SetFlags(log.Lshortfile)
}
