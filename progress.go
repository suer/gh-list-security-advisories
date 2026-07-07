package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/mattn/go-isatty"
)

type ProgressBar struct {
	total   atomic.Int64
	current atomic.Int64
	stop    chan struct{}
	done    chan struct{}
	isTTY   bool
}

func NewProgressBar() *ProgressBar {
	return &ProgressBar{
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		isTTY: isatty.IsTerminal(os.Stdout.Fd()),
	}
}

func (p *ProgressBar) AddTotal(n int) {
	p.total.Add(int64(n))
}

func (p *ProgressBar) Increment() {
	p.current.Add(1)
}

func (p *ProgressBar) IncrementBy(n int) {
	p.current.Add(int64(n))
}

func (p *ProgressBar) render(frame string) {
	total := p.total.Load()
	current := p.current.Load()
	if total <= 0 {
		fmt.Fprintf(os.Stderr, "\r%s Fetching repositories...", frame)
		return
	}
	const width = 30
	filled := int(float64(current) / float64(total) * width)
	if filled > width {
		filled = width
	}
	bar := make([]rune, width)
	for i := range bar {
		if i < filled {
			bar[i] = '█'
		} else {
			bar[i] = '░'
		}
	}
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d repos", string(bar), current, total)
}

func (p *ProgressBar) Start() {
	if !p.isTTY {
		return
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	go func() {
		defer close(p.done)
		i := 0
		for {
			select {
			case <-p.stop:
				fmt.Fprintf(os.Stderr, "\r%-60s\r", "")
				return
			default:
				p.render(frames[i%len(frames)])
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

func (p *ProgressBar) Stop() {
	if !p.isTTY {
		return
	}
	close(p.stop)
	<-p.done
}
