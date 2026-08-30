package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func buildSigningPayload(req *Request, decision string) []byte {
	var buf bytes.Buffer
	fmt.Fprint(&buf, "universal-auth:v2\n")
	fmt.Fprintf(&buf, "request_id=%s\n", b64url(req.ID))
	fmt.Fprintf(&buf, "challenge=%s\n", req.Challenge)
	fmt.Fprintf(&buf, "client_nonce=%s\n", req.ClientNonce)
	fmt.Fprintf(&buf, "decision=%s\n", b64url(decision))
	fmt.Fprintf(&buf, "source=%s\n", b64url(req.Source))
	fmt.Fprintf(&buf, "kind=%s\n", b64url(req.Kind))
	fmt.Fprintf(&buf, "resource=%s\n", b64url(req.Resource))
	fmt.Fprintf(&buf, "message=%s\n", b64url(req.Message))
	return buf.Bytes()
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
