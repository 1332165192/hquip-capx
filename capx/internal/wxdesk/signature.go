package wxdesk

import (
	"fmt"
	"strings"
)

func validateTencentSignature(status, subject string) error {
	normalized := strings.ToLower(strings.ReplaceAll(subject, " ", ""))
	if status != "Valid" || !strings.Contains(","+normalized+",", ",o=tencenttechnology(shenzhen)companylimited,") {
		return fmt.Errorf("安装包必须具有有效的腾讯官方数字签名（当前状态：%s）", status)
	}
	return nil
}
