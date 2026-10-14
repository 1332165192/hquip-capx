package wxhook

import "strings"

func processRole(commandLine string) string {
	role := ""
	for _, field := range strings.Fields(strings.ToLower(commandLine)) {
		field = strings.Trim(field, "\"'")
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "\"'")
		if key == "--utility-sub-type" && value == "network.mojom.networkservice" {
			return "network"
		}
		if key == "--type" {
			switch value {
			case "gpu-process":
				role = "gpu"
			case "renderer":
				role = "renderer"
			case "utility":
				role = "utility"
			}
		}
	}
	return role
}
