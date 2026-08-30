package protocol

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func BuildSigningPayload(
	requestID string,
	challenge string,
	clientNonce string,
	source string,
	kind string,
	resource string,
	message string,
	decision string,
) []byte {
	var buf bytes.Buffer
	fmt.Fprint(&buf, "universal-auth:v2\n")
	fmt.Fprintf(&buf, "request_id=%s\n", b64url(requestID))
	fmt.Fprintf(&buf, "challenge=%s\n", challenge)
	fmt.Fprintf(&buf, "client_nonce=%s\n", clientNonce)
	fmt.Fprintf(&buf, "decision=%s\n", b64url(decision))
	fmt.Fprintf(&buf, "source=%s\n", b64url(source))
	fmt.Fprintf(&buf, "kind=%s\n", b64url(kind))
	fmt.Fprintf(&buf, "resource=%s\n", b64url(resource))
	fmt.Fprintf(&buf, "message=%s\n", b64url(message))
	return buf.Bytes()
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
