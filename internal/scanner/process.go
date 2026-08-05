package scanner

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const externalCommandWaitDelay = 2 * time.Second

// configureExternalCommand places the tool and all descendants in a dedicated
// process group. Context cancellation can then terminate the whole tree instead
// of only the direct child, and WaitDelay bounds descendants that retain copied
// stdout/stderr descriptors after the group leader exits.
func configureExternalCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	} else {
		attributes := *cmd.SysProcAttr
		cmd.SysProcAttr = &attributes
	}
	cmd.SysProcAttr.Setpgid = true
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = externalCommandWaitDelay
	}
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			return killExternalCommandGroup(cmd)
		}
	}
}

func killExternalCommandGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func runExternalCommand(cmd *exec.Cmd) error {
	configureExternalCommand(cmd)
	err := cmd.Run()
	// Kill any worker a tool left behind even when its group leader reported a
	// successful exit and closed all inherited output descriptors.
	_ = killExternalCommandGroup(cmd)
	return err
}
