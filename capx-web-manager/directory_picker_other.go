//go:build !windows

package main

import "errors"

func selectNativeDirectory(string, string) (string, error) {
	return "", errors.New("当前平台未配置原生目录选择器")
}
