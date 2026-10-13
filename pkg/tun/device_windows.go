//go:build windows

package tun

import (
	"fmt"
	"os/exec"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// windowsDevice implements Device using Wintun via wireguard/tun.
type windowsDevice struct {
	native tun.Device
	name   string
	mtu    int
	closed atomic.Bool
}

// CreateDevice allocates and provisions a Wintun virtual adapter on Windows.
func CreateDevice(cfg Config) (Device, error) {
	if cfg.Name == "" {
		cfg.Name = DefaultTUNName
	}
	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}

	// Allocate virtual interface via Wintun
	dev, err := tun.CreateTUN(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("novatun/tun: failed to create Wintun adapter %s: %w", cfg.Name, err)
	}

	actualName, err := dev.Name()
	if err != nil {
		actualName = cfg.Name
	}

	// Configure IP and subnet mask using netsh
	// netsh interface ip set address name="novatun0" static 10.255.0.2 255.255.255.0 10.255.0.1
	if cfg.LocalIP != nil {
		maskStr := "255.255.255.0"
		if len(cfg.Netmask) == 4 {
			maskStr = fmt.Sprintf("%d.%d.%d.%d", cfg.Netmask[0], cfg.Netmask[1], cfg.Netmask[2], cfg.Netmask[3])
		}
		cmd := exec.Command("netsh", "interface", "ip", "set", "address",
			fmt.Sprintf("name=%s", actualName),
			"static",
			cfg.LocalIP.String(),
			maskStr,
			cfg.GatewayIP.String(),
			"store=active",
		)
		_ = cmd.Run() // Netsh might return warnings if already assigned, non-fatal
	}

	return &windowsDevice{
		native: dev,
		name:   actualName,
		mtu:    cfg.MTU,
	}, nil
}

func (w *windowsDevice) Name() string {
	return w.name
}

func (w *windowsDevice) MTU() int {
	return w.mtu
}

func (w *windowsDevice) Read(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, ErrDeviceClosed
	}
	// wireguard/tun expects a slice of buffers [][][]byte
	sizes := make([]int, 1)
	bufs := [][]byte{p}
	n, err := w.native.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (w *windowsDevice) Write(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, ErrDeviceClosed
	}
	bufs := [][]byte{p}
	n, err := w.native.Write(bufs, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(p), nil
}

func (w *windowsDevice) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	return w.native.Close()
}
