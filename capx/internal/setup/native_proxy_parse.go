package setup

import (
	"net"
	"strings"
)

func parseNetworkProxy(output string) (uint32, string) {
	var enabled uint32
	var host, port string
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "enabled":
			if strings.EqualFold(value, "yes") {
				enabled = 1
			}
		case "server":
			host = value
		case "port":
			port = value
		}
	}
	if host == "" || port == "" || port == "0" {
		return enabled, ""
	}
	return enabled, net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func parseNetworkPAC(output string) (uint32, string) {
	var enabled uint32
	var address string
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "enabled" && strings.EqualFold(value, "yes") {
			enabled = 1
		}
		if key == "url" && value != "(null)" {
			address = value
		}
	}
	return enabled, address
}

func gsettingsValue(output string) string { return strings.Trim(strings.TrimSpace(output), "'\"") }
