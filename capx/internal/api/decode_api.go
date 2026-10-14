package api

// Schema-less decoders for captured binary payloads: protobuf wire format and
// gRPC framing. The UI posts a selected body (hex or base64) and gets back a
// readable field tree, so gRPC/protobuf traffic capx already captures over
// HTTP/2 becomes inspectable without a .proto.

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/hquip/capx/internal/decode"
)

// decodeBytesFromReq pulls the input bytes from a {hex|b64} body.
func decodeBytesFromReq(r *http.Request) ([]byte, error) {
	var req struct {
		Hex string `json:"hex"`
		B64 string `json:"b64"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, errBadJSON
	}
	if req.Hex != "" {
		return hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(req.Hex), " ", ""))
	}
	if req.B64 != "" {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(req.B64))
	}
	return nil, errNoInput
}

var (
	errBadJSON = &decodeErr{"bad json"}
	errNoInput = &decodeErr{"provide hex or b64 input"}
)

type decodeErr struct{ s string }

func (e *decodeErr) Error() string { return e.s }

// decodeProtobuf decodes posted bytes as a protobuf message.
func (s *Server) decodeProtobuf(w http.ResponseWriter, r *http.Request) {
	b, err := decodeBytesFromReq(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	fields, err := decode.DecodeProtobuf(b)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "not valid protobuf: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": fields})
}

// decodeGRPC decodes posted bytes as gRPC length-prefixed protobuf frames.
func (s *Server) decodeGRPC(w http.ResponseWriter, r *http.Request) {
	b, err := decodeBytesFromReq(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	msgs, err := decode.DecodeGRPC(b)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

// decodeQUIC decrypts a QUIC v1 packet. Initial packets need no secrets (keys
// derive from the DCID). Handshake / 0-RTT / 1-RTT packets are decrypted with
// the TLS secrets capx has collected in its key log (or secrets posted inline).
// For short-header (1-RTT) packets the connection's DCID length must be supplied
// (dcid_len) because it is not carried in the packet.
func (s *Server) decodeQUIC(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hex          string   `json:"hex"`
		B64          string   `json:"b64"`
		DCIDLen      int      `json:"dcid_len"`
		LargestPN    uint64   `json:"largest_pn"`
		ClientRandom string   `json:"client_random"`
		Keylog       []string `json:"keylog"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	var (
		b   []byte
		err error
	)
	switch {
	case req.Hex != "":
		b, err = hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(req.Hex), " ", ""))
	case req.B64 != "":
		b, err = base64.StdEncoding.DecodeString(strings.TrimSpace(req.B64))
	default:
		err = errNoInput
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Secrets: prefer inline keylog, else the collected store.
	lines := req.Keylog
	if len(lines) == 0 {
		lines = s.st.Keylog()
	}
	kl := decode.ParseQUICKeylog(lines)
	var clientRandom []byte
	if req.ClientRandom != "" {
		clientRandom, _ = hex.DecodeString(strings.TrimSpace(req.ClientRandom))
	}

	out, err := decode.DecryptQUIC(b, kl, req.DCIDLen, req.LargestPN, clientRandom)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// decodePacket decodes a raw frame (Ethernet or raw IP) into a layer tree.
func (s *Server) decodePacket(w http.ResponseWriter, r *http.Request) {
	b, err := decodeBytesFromReq(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"layers": decode.DecodePacket(b)})
}
