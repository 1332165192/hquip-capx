package mobile

import "os"

func writeTempCA(pem []byte) string {
	f, err := os.CreateTemp("", "capx-ca-*.pem")
	if err != nil {
		return ""
	}
	if _, err := f.Write(pem); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return ""
	}
	_ = f.Close()
	return f.Name()
}

func removeTempCA(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}
