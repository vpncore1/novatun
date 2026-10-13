package tun

import (
	"errors"
	"io"
	"net"
)

// Default configuration constants for the novatun virtual network adapter.
const (
	DefaultTUNName   = "novatun0"
	DefaultMTU       = 1420
	DefaultLocalIPv4 = "10.255.0.2"
	DefaultGWIPv4    = "10.255.0.1"
	DefaultMaskIPv4  = "255.255.255.0"
)

// Device wraps a virtual Layer-3 TUN interface for cross-platform packet I/O.
type Device interface {
	io.ReadWriteCloser

	// Name returns the virtual adapter's interface name (e.g. "novatun0").
	Name() string

	// MTU returns the configured Maximum Transmission Unit in bytes.
	MTU() int
}

// Config specifies parameters for creating and provisioning the TUN adapter.
type Config struct {
	Name      string
	MTU       int
	LocalIP   net.IP
	GatewayIP net.IP
	Netmask   net.IPMask
}

// DefaultConfig returns recommended production settings for novatun TUN.
func DefaultConfig() Config {
	return Config{
		Name:      DefaultTUNName,
		MTU:       DefaultMTU,
		LocalIP:   net.ParseIP(DefaultLocalIPv4).To4(),
		GatewayIP: net.ParseIP(DefaultGWIPv4).To4(),
		Netmask:   net.IPv4Mask(255, 255, 255, 0),
	}
}

var (
	ErrDeviceClosed = errors.New("novatun/tun: device is closed")
)
