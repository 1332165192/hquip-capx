package decode

import "fmt"

// WSExplain gives a human-readable label for a WebSocket text frame of a known
// subprotocol (Socket.IO / Engine.IO, SignalR JSON). It returns ("", false)
// when the frame is not recognised, so the caller can fall back to raw text.
func WSExplain(data string) (string, bool) {
	if data == "" {
		return "", false
	}
	// SignalR JSON protocol frames are terminated by 0x1e (record separator).
	if i := indexByte(data, 0x1e); i >= 0 {
		return "SignalR frame (" + fmt.Sprintf("%d", i) + "B json)", true
	}
	return explainEngineIO(data)
}

// explainEngineIO decodes the Engine.IO packet type prefix and, for messages,
// the Socket.IO packet type. Engine.IO types: 0 open, 1 close, 2 ping, 3 pong,
// 4 message, 5 upgrade, 6 noop. Socket.IO types (inside a "4" message): 0
// CONNECT, 1 DISCONNECT, 2 EVENT, 3 ACK, 4 CONNECT_ERROR, 5 BINARY_EVENT, 6
// BINARY_ACK.
func explainEngineIO(s string) (string, bool) {
	eio := map[byte]string{'0': "OPEN", '1': "CLOSE", '2': "PING", '3': "PONG", '4': "MESSAGE", '5': "UPGRADE", '6': "NOOP"}
	t, ok := eio[s[0]]
	if !ok {
		return "", false
	}
	if s[0] != '4' || len(s) < 2 {
		return "engine.io " + t, true
	}
	sio := map[byte]string{'0': "CONNECT", '1': "DISCONNECT", '2': "EVENT", '3': "ACK", '4': "CONNECT_ERROR", '5': "BINARY_EVENT", '6': "BINARY_ACK"}
	st, ok := sio[s[1]]
	if !ok {
		return "engine.io MESSAGE", true
	}
	return "socket.io " + st, true
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
