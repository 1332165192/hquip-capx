// Package wxapkg exposes capx's native mini-program unpacker to local hosts.
// This adapter does not start capture services or execute bundle JavaScript.
package wxapkg

import native "github.com/hquip/capx/internal/wxapkg"

type File = native.File

func IsEncrypted(data []byte) bool                            { return native.IsEncrypted(data) }
func Decrypt(appID string, data []byte) ([]byte, error)       { return native.Decrypt(appID, data) }
func Unpack(data []byte) ([]File, error)                      { return native.Unpack(data) }
func Process(appID string, data []byte) ([]File, bool, error) { return native.Process(appID, data) }
func Reconstruct(files []File) ([]File, []string)             { return native.Reconstruct(files) }
