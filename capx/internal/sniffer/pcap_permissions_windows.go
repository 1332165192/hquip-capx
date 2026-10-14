//go:build pcap && windows

package sniffer

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func readNpcapAdminOnly() (uint64, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\npcap\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return 0, err
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue("AdminOnly")
	return value, err
}

// Npcap's administrator-only installation can invoke its elevation helper
// even during pcap_findalldevs. Reject before entering the native driver so a
// hidden desktop worker cannot wait indefinitely on a UAC prompt.
func checkNpcapPermissions(readAdminOnly func() (uint64, error), elevated func() bool) error {
	adminOnly, err := readAdminOnly()
	if errors.Is(err, registry.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取 Npcap 权限设置失败: %w", err)
	}
	if adminOnly != 0 && !elevated() {
		return fmt.Errorf("%w: Npcap 设置为仅管理员可用，当前进程未以管理员权限运行，无法枚举网卡或开始网卡采集", os.ErrPermission)
	}
	return nil
}

func checkPCapPermissions() error {
	return checkNpcapPermissions(readNpcapAdminOnly, func() bool {
		return windows.GetCurrentProcessToken().IsElevated()
	})
}
