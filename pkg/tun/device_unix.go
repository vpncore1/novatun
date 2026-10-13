//go:build !windows

package tun

import (
	"fmt"
	"os/exec"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// unixDevice implements Device on Linux / macOS via wireguard/tun.
type unixDevice struct {
	native tun.Device
	name   string
	mtu    int
	closed atomic.Bool
}

// CreateDevice allocates and provisions a TUN virtual adapter on Linux/macOS.
func CreateDevice(cfg Config) (Device, error) {
	if cfg.Name == "" {
		cfg.Name = DefaultTUNName
	}
	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}

	dev, err := tun.CreateTUN(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("novatun/tun: failed to create TUN interface %s: %w", cfg.Name, err)
	}

	actualName, err := dev.Name()
	if err != nil {
		actualName = cfg.Name
	}

	// Configure IP and MTU via ip link/addr
	if cfg.LocalIP != nil {
		maskBits := 24
		if len(cfg.Netmask) == 4 {
			ones, _ := cfg.Netmask.Size()
			if ones > 0 {
				maskBits = ones
			}
		}
		cidr := fmt.Sprintf("%s/%d", cfg.LocalIP.String(), maskBits)
		_ = exec.Command("ip", "addr", "add", cidr, "dev", actualName).Run()
		_ = exec.Command("ip", "link", "set", "dev", actualName, "mtu", fmt.Sprintf("%d", cfg.MTU), "up").Run()
	}

	return &unixDevice{
		native: dev,
		name:   actualName,
		mtu:    cfg.MTU,
	}, nil
}

func (u *unixDevice) Name() string {
	return u.name
}

func (u *unixDevice) MTU() int {
	return u.mtu
}

func (u *unixDevice) Read(p []byte) (int, error) {
	if u.closed.Load() {
		return 0, ErrDeviceClosed
	}
	sizes := make([]int, 1)
	bufs := [][]byte{p}
	n, err := u.native.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (u *unixDevice) Write(p []byte) (int, error) {
	if u.closed.Load() {
		return 0, ErrDeviceClosed
	}
	bufs := [][]byte{p}
	n, err := u.native.Write(bufs, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(p), nil
}

func (u *unixDevice) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	return u.native.Close()
}
