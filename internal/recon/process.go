package recon

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
	// exec.Cmd rejects a non-nil Cancel on commands created without
	// exec.CommandContext. executeBoundedLines independently watches its context,
	// while CommandContext callers get whole-group cancellation here.
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

// terminateExternalCommandGroup is also called after a normal leader exit. A
// tool must not leave a detached worker running target traffic after HawkEye has
// already recorded the invocation as complete.
func terminateExternalCommandGroup(cmd *exec.Cmd) {
	_ = killExternalCommandGroup(cmd)
}
