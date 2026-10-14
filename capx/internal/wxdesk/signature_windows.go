//go:build windows

package wxdesk

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/hquip/capx/internal/backgroundprocess"
)

// Verify Windows Authenticode on the staged installer. EncodedCommand and a
// single-quoted PowerShell literal preserve Unicode paths without shell expansion.
func verifyTencentInstaller(path string) error {
	path = strings.ReplaceAll(path, "'", "''")
	script := `$taskSignature = Get-AuthenticodeSignature -LiteralPath '` + path + `'; $taskSubject = ''; if ($taskSignature.SignerCertificate) { $taskSubject = $taskSignature.SignerCertificate.Subject }; [pscustomobject]@{status=[string]$taskSignature.Status;subject=$taskSubject} | ConvertTo-Json -Compress`
	units := utf16.Encode([]rune(script))
	bytes := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(bytes[i*2:], u)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := backgroundprocess.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(bytes))
	cmd.WaitDelay = time.Second
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("微信安装包签名校验失败: %w", err)
	}
	var signature struct {
		Status  string `json:"status"`
		Subject string `json:"subject"`
	}
	if err = json.Unmarshal(data, &signature); err != nil {
		return fmt.Errorf("无法读取安装包签名结果")
	}
	return validateTencentSignature(signature.Status, signature.Subject)
}
