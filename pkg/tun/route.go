package tun

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// Router manages OS routing table rules to capture system traffic into the TUN interface
// while preventing routing loops by retaining direct routes to the remote novatun server.
type Router struct {
	serverEndpoint string
	gatewayIP      string
	origGateway    string
	tunDevName     string
}

// NewRouter initializes a platform-aware routing table manager.
func NewRouter(serverEndpoint, gatewayIP, tunDevName string) *Router {
	return &Router{
		serverEndpoint: serverEndpoint,
		gatewayIP:      gatewayIP,
		tunDevName:     tunDevName,
	}
}

// SetupRoutes provisions system routes:
// 1. Adds a /32 host bypass route for the novatun remote server IP via the original default gateway.
// 2. Sets split default routes (0.0.0.0/1 and 128.0.0.0/1) pointing through the TUN gateway.
func (r *Router) SetupRoutes() error {
	serverHost, _, err := net.SplitHostPort(r.serverEndpoint)
	if err != nil {
		serverHost = r.serverEndpoint
	}

	serverIP := net.ParseIP(serverHost)
	if serverIP == nil {
		// Resolve domain to IP if necessary
		addrs, err := net.LookupHost(serverHost)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("novatun/tun: cannot resolve server address %s: %w", serverHost, err)
		}
		serverIP = net.ParseIP(addrs[0])
	}

	origGW, err := getDefaultGateway()
	if err == nil {
		r.origGateway = origGW
	}

	switch runtime.GOOS {
	case "windows":
		return r.setupWindowsRoutes(serverIP.String())
	case "linux", "darwin":
		return r.setupUnixRoutes(serverIP.String())
	default:
		return errors.New("novatun/tun: unsupported operating system for routing")
	}
}

// RestoreRoutes removes bypass and VPN routes, restoring the system's original network state.
func (r *Router) RestoreRoutes() error {
	serverHost, _, _ := net.SplitHostPort(r.serverEndpoint)
	serverIP := net.ParseIP(serverHost)
	serverIPStr := ""
	if serverIP != nil {
		serverIPStr = serverIP.String()
	}

	switch runtime.GOOS {
	case "windows":
		return r.restoreWindowsRoutes(serverIPStr)
	case "linux", "darwin":
		return r.restoreUnixRoutes(serverIPStr)
	default:
		return nil
	}
}

func (r *Router) setupWindowsRoutes(serverIP string) error {
	// 1. Add host route for remote novatun server through the original physical gateway
	if r.origGateway != "" && serverIP != "" {
		_ = exec.Command("route", "add", serverIP, "mask", "255.255.255.255", r.origGateway, "metric", "1").Run()
	}

	// 2. Split default route: 0.0.0.0/1 and 128.0.0.0/1 via TUN gateway
	// Using /1 covers the entire IPv4 address space with higher specificity than the 0.0.0.0/0 default route.
	_ = exec.Command("route", "add", "0.0.0.0", "mask", "128.0.0.0", r.gatewayIP, "metric", "5").Run()
	_ = exec.Command("route", "add", "128.0.0.0", "mask", "128.0.0.0", r.gatewayIP, "metric", "5").Run()

	return nil
}

func (r *Router) restoreWindowsRoutes(serverIP string) error {
	if serverIP != "" {
		_ = exec.Command("route", "delete", serverIP).Run()
	}
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	return nil
}

func (r *Router) setupUnixRoutes(serverIP string) error {
	if r.origGateway != "" && serverIP != "" {
		_ = exec.Command("ip", "route", "add", serverIP+"/32", "via", r.origGateway).Run()
	}

	_ = exec.Command("ip", "route", "add", "0.0.0.0/1", "via", r.gatewayIP, "dev", r.tunDevName).Run()
	_ = exec.Command("ip", "route", "add", "128.0.0.0/1", "via", r.gatewayIP, "dev", r.tunDevName).Run()

	return nil
}

func (r *Router) restoreUnixRoutes(serverIP string) error {
	if serverIP != "" {
		_ = exec.Command("ip", "route", "del", serverIP+"/32").Run()
	}
	_ = exec.Command("ip", "route", "del", "0.0.0.0/1").Run()
	_ = exec.Command("ip", "route", "del", "128.0.0.0/1").Run()
	return nil
}

func getDefaultGateway() (string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("netsh", "interface", "ipv4", "show", "route").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 5 && fields[0] == "0.0.0.0/0" {
				return fields[4], nil
			}
		}
	} else {
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return "", err
		}
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", errors.New("default gateway not found")
}
