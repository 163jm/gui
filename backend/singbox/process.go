package singbox

import (
	"bufio"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type Status struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	Error   string `json:"error,omitempty"`
}

type Process struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	status Status
	log    []string
	maxLog int
}

func NewProcess() *Process {
	return &Process{maxLog: 500}
}

func (p *Process) Start(binPath, cfgPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil && p.cmd.Process != nil {
		return fmt.Errorf("sing-box 已在运行")
	}

	p.cmd = exec.Command(binPath, "run", "-c", cfgPath)
	p.log = []string{}

	// capture stdout+stderr
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := p.cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := p.cmd.Start(); err != nil {
		p.cmd = nil
		return fmt.Errorf("启动失败: %v", err)
	}

	p.status = Status{Running: true, PID: p.cmd.Process.Pid}
	p.appendLog(fmt.Sprintf("[%s] sing-box 已启动 PID=%d", now(), p.cmd.Process.Pid))

	// read logs
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			p.appendLog(scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			p.appendLog(scanner.Text())
		}
	}()

	// watch process
	go func() {
		err := p.cmd.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		if err != nil {
			p.appendLog(fmt.Sprintf("[%s] sing-box 退出: %v", now(), err))
			p.status = Status{Running: false, Error: err.Error()}
		} else {
			p.appendLog(fmt.Sprintf("[%s] sing-box 正常退出", now()))
			p.status = Status{Running: false}
		}
		p.cmd = nil
	}()

	return nil
}

func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd == nil || p.cmd.Process == nil {
		p.status = Status{Running: false}
		return nil
	}

	if err := p.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("停止失败: %v", err)
	}
	p.appendLog(fmt.Sprintf("[%s] sing-box 已停止", now()))
	p.cmd = nil
	p.status = Status{Running: false}
	return nil
}

func (p *Process) GetStatus() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

func (p *Process) GetLog() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]string, len(p.log))
	copy(result, p.log)
	return result
}

func (p *Process) appendLog(line string) {
	p.log = append(p.log, line)
	if len(p.log) > p.maxLog {
		p.log = p.log[len(p.log)-p.maxLog:]
	}
}

func now() string {
	return time.Now().Format("15:04:05")
}
