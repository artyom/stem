// +build linux

// Command stem runs program in a linux container-like environment: chrooted to
// given directory and with separate pid and mount namespaces.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"

	"github.com/artyom/autoflags"
)

func main() {
	conf := &config{}
	autoflags.Parse(conf)
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if err := run(conf, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(conf *config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("empty argument list")
	}
	mounts, err := conf.Mounts.Get()
	if err != nil {
		return err
	}
	for _, mt := range mounts {
		if err := mt.Check(conf.Dir); err != nil {
			return err
		}
	}
	signals := make(chan os.Signal, 1)
	defer close(signals)
	signal.Notify(signals,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGQUIT,
	)
	defer signal.Stop(signals)

	// need to lock thread so that mounts are done in the same thread to
	// which Unshare was applied
	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		return err
	}
	for _, m := range mounts {
		to := path.Join(conf.Dir, m.To)
		if err := syscall.Mount(m.From, to, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("mount %s to %s: %v", m.From, to, err)
		}
	}
	if conf.MountDev {
		if err := syscall.Mount("none", path.Join(conf.Dir, "dev"), "devtmpfs", 0, ""); err != nil {
			return fmt.Errorf("mount /dev inside chroot: %v", err)
		}
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:     conf.Dir,
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if isDevice(os.Stdin) {
		cmd.Stdin = os.Stdin
	}
	if conf.Noenv {
		cmd.Env = []string{}
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	runtime.UnlockOSThread()
	go func(sigch chan os.Signal, p *os.Process) {
		for s := range sigch {
			log.Print(s)
			p.Signal(s)
		}
	}(signals, cmd.Process)
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s / %s", exitReason(err), processStats(cmd.ProcessState))
	}
	if !conf.Quiet {
		log.Print(processStats(cmd.ProcessState))
	}
	return nil
}

type config struct {
	Dir      string `flag:"root,root filesystem to start chrooted process into"`
	MountDev bool   `flag:"withdev,mount devtmpfs on /dev inside chroot (directory should exist)"`
	Mounts   Mounts `flag:"mount,bind-mount pairs 'target:destination', where destination is relative to chroot dir"`
	Quiet    bool   `flag:"q,be quiet if everything's ok"`
	Noenv    bool   `flag:"noenv,empty environment variables"`
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
			return nil, fmt.Errorf("invalid flag format, should be 'souce:destination': %q", cand)
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
		return fmt.Errorf("mounts should use absolute paths: %q", m.From)
	}
	if !path.IsAbs(m.To) {
		return fmt.Errorf("mounts should use absolute paths: %q", m.To)
	}
	if _, err := os.Stat(m.From); err != nil {
		return err
	}
	to := path.Join(root, m.To)
	if to == root {
		return fmt.Errorf("mount destination should not be the chroot directory itself")
	}
	if _, err := os.Stat(to); err != nil {
		return err
	}
	return nil
}

func init() {
	log.SetFlags(0)
	log.SetPrefix(path.Base(os.Args[0]) + ": ")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [flags] command-in-chroot [command args]\n", path.Base(os.Args[0]))
	flag.PrintDefaults()
}

// exitReason translates error returned by os.Process.Wait() into human-readable
// form.
func exitReason(err error) string {
	exiterr, ok := err.(*exec.ExitError)
	if !ok {
		return err.Error()
	}
	status := exiterr.Sys().(syscall.WaitStatus)
	switch {
	case status.Exited():
		return fmt.Sprintf("exit code %d", status.ExitStatus())
	case status.Signaled():
		return fmt.Sprintf("exit code %d (%s)",
			128+int(status.Signal()), status.Signal())
	}
	return err.Error()
}

// processStats returns finished process' CPU / memory statistics in
// human-readable form.
func processStats(st *os.ProcessState) string {
	if st == nil {
		return ""
	}
	if r, ok := st.SysUsage().(*syscall.Rusage); ok && r != nil {
		return fmt.Sprintf("sys: %s, user: %s, maxRSS: %s",
			st.SystemTime(),
			st.UserTime(),
			ByteSize(r.Maxrss),
		)
	}
	return fmt.Sprintf("sys: %s, user: %s", st.SystemTime(), st.UserTime())
}

// ByteSize implements Stringer interface for printing size in human-readable
// form
type ByteSize float64

const (
	_           = iota // ignore first value by assigning to blank identifier
	KB ByteSize = 1 << (10 * iota)
	MB
	GB
	TB
	PB
	EB
	ZB
	YB
)

func (b ByteSize) String() string {
	switch {
	case b >= YB:
		return fmt.Sprintf("%.2fYB", b/YB)
	case b >= ZB:
		return fmt.Sprintf("%.2fZB", b/ZB)
	case b >= EB:
		return fmt.Sprintf("%.2fEB", b/EB)
	case b >= PB:
		return fmt.Sprintf("%.2fPB", b/PB)
	case b >= TB:
		return fmt.Sprintf("%.2fTB", b/TB)
	case b >= GB:
		return fmt.Sprintf("%.2fGB", b/GB)
	case b >= MB:
		return fmt.Sprintf("%.2fMB", b/MB)
	case b >= KB:
		return fmt.Sprintf("%.2fKB", b/KB)
	}
	return fmt.Sprintf("%.2fB", b)
}

// isDevice returns true if f is a device file
func isDevice(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeDevice != 0
}
