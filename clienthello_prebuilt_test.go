// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func testPrebuiltHello(t *testing.T, tp []byte, sessionID []byte, alpn []string, shares []keyShare) []byte {
	t.Helper()
	hello := &clientHelloMsg{
		vers:                         VersionTLS12,
		random:                       bytes.Repeat([]byte{0x42}, 32),
		sessionId:                    sessionID,
		cipherSuites:                 []uint16{TLS_AES_128_GCM_SHA256},
		compressionMethods:           []uint8{compressionNone},
		serverName:                   "example.com",
		supportedCurves:              []CurveID{X25519},
		supportedVersions:            []uint16{VersionTLS13},
		alpnProtocols:                alpn,
		keyShares:                    shares,
		quicTransportParameters:      tp,
		supportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256},
	}
	raw, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testX25519Share(t *testing.T) (*ecdh.PrivateKey, keyShare) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, keyShare{group: X25519, data: priv.PublicKey().Bytes()}
}

func testPrebuiltConn(t *testing.T, raw *RawClientHello, tp []byte, nextProtos []string) *Conn {
	t.Helper()
	return &Conn{
		config: &Config{
			NextProtos: nextProtos,
			JLSConfig: &JLSConfig{
				Enable: true,
				User:   JLSUser{Username: "user", Password: "password"},
			},
		},
		quic: &quicState{transportParams: tp, clientHello: raw},
	}
}

func TestPrebuiltClientHello(t *testing.T) {
	tp := []byte{0x04, 0x03, 0x02, 0x01}
	priv, share := testX25519Share(t)
	raw := testPrebuiltHello(t, tp, nil, []string{"h3"}, []keyShare{share})

	c := testPrebuiltConn(t, &RawClientHello{Raw: raw, ECDHE: priv}, tp, []string{"h3"})
	hello, keys, ech, err := c.makeRawClientHello(c.quic.clientHello)
	if err != nil {
		t.Fatal(err)
	}
	if ech != nil {
		t.Fatal("prebuilt ClientHello unexpectedly returned ECH context")
	}
	if keys.ecdhe != priv {
		t.Fatal("ECDHE private key was not adopted")
	}
	if len(hello.original) != len(raw) || !bytes.Equal(hello.original, raw) {
		t.Fatal("raw ClientHello was not preserved")
	}
	if got, err := hello.marshal(); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("marshal() = %x, %v; want original raw bytes", got, err)
	}
}

func TestPrebuiltClientHelloJLS(t *testing.T) {
	tp := []byte{0x04, 0x03, 0x02, 0x01}
	priv, share := testX25519Share(t)
	raw := testPrebuiltHello(t, tp, nil, []string{"h3"}, []keyShare{share})
	c := testPrebuiltConn(t, &RawClientHello{Raw: raw, ECDHE: priv}, tp, []string{"h3"})

	hello, _, _, err := c.makeRawClientHello(c.quic.clientHello)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.applyJLSClientHelloRandom(hello); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello.original[jlsHelloRandomOffset:jlsHelloRandomOffset+jlsHelloRandomLen], hello.random) {
		t.Fatal("sealed random was not written back to the raw ClientHello")
	}
	authData, err := jlsClientHelloWireAuthData(hello)
	if err != nil {
		t.Fatal(err)
	}
	if !jlsCheckFakeRandom(c.config.JLSConfig.User, hello.random, authData) {
		t.Fatal("client-side sealed random failed server-side verification")
	}

	server := &Conn{config: &Config{JLSConfig: &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{{Username: "user", Password: "password"}},
		ServerName: "example.com",
	}}}
	if err := server.authenticateJLSClientHello(hello); err != nil {
		t.Fatal(err)
	}
	if server.jlsState != jlsStateAuthSuccess {
		t.Fatalf("server JLS state = %d, want authenticated", server.jlsState)
	}
}

func TestPrebuiltClientHelloValidation(t *testing.T) {
	tp := []byte{0x04, 0x03, 0x02, 0x01}
	priv, share := testX25519Share(t)
	raw := testPrebuiltHello(t, tp, nil, []string{"h3"}, []keyShare{share})

	badLen := append([]byte(nil), raw...)
	badLen[3]++
	badType := append([]byte(nil), raw...)
	badType[0] = 2
	badSession := testPrebuiltHello(t, tp, bytes.Repeat([]byte{1}, 32), []string{"h3"}, []keyShare{share})
	badALPN := testPrebuiltHello(t, tp, nil, nil, []keyShare{share})

	otherTP := []byte{0x05, 0x03, 0x02, 0x01}
	badTP := testPrebuiltHello(t, otherTP, nil, []string{"h3"}, []keyShare{share})

	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badGroup := testPrebuiltHello(t, tp, nil, []string{"h3"}, []keyShare{{group: CurveP256, data: p256.PublicKey().Bytes()}})

	hybrid := make([]byte, 1216)
	hybridRaw := testPrebuiltHello(t, tp, nil, []string{"h3"}, []keyShare{{group: X25519MLKEM768, data: hybrid}})

	tests := []struct {
		name string
		raw  []byte
		keys *RawClientHello
		tp   []byte
		alpn []string
		want string
	}{
		{"nil", nil, &RawClientHello{}, tp, []string{"h3"}, "empty"},
		{"short", raw[:10], &RawClientHello{Raw: raw[:10], ECDHE: priv}, tp, []string{"h3"}, "invalid length"},
		{"length", badLen, &RawClientHello{Raw: badLen, ECDHE: priv}, tp, []string{"h3"}, "invalid length"},
		{"type", badType, &RawClientHello{Raw: badType, ECDHE: priv}, tp, []string{"h3"}, "handshake type"},
		{"session id", badSession, &RawClientHello{Raw: badSession, ECDHE: priv}, tp, []string{"h3"}, "empty session_id"},
		{"alpn empty", badALPN, &RawClientHello{Raw: badALPN, ECDHE: priv}, tp, []string{"h3"}, "no ALPN"},
		{"alpn mismatch", raw, &RawClientHello{Raw: raw, ECDHE: priv}, tp, []string{"h2"}, "ALPN"},
		{"tp mismatch", badTP, &RawClientHello{Raw: badTP, ECDHE: priv}, tp, []string{"h3"}, "transport_parameters"},
		{"group", badGroup, &RawClientHello{Raw: badGroup, ECDHE: priv}, tp, []string{"h3"}, "unsupported key share"},
		{"hybrid no seed", hybridRaw, &RawClientHello{Raw: hybridRaw, ECDHE: priv}, tp, []string{"h3"}, "ML-KEM seed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testPrebuiltConn(t, tt.keys, tt.tp, tt.alpn)
			if tt.raw == nil {
				c.quic.clientHello = &RawClientHello{}
			} else {
				c.quic.clientHello.Raw = tt.raw
			}
			_, _, _, err := c.makeRawClientHello(c.quic.clientHello)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tt.want)) {
				t.Fatalf("error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestPrebuiltClientHelloRejectsNonQUIC(t *testing.T) {
	c := &Conn{config: &Config{NextProtos: []string{"h3"}}}
	if _, _, _, err := c.makeRawClientHello(&RawClientHello{Raw: []byte{1, 0, 0, 0}}); err == nil {
		t.Fatal("expected error for non-QUIC connection")
	}
}

func TestPrebuiltClientHelloRejectsHRR(t *testing.T) {
	hs := &clientHandshakeStateTLS13{
		c:     &Conn{quic: &quicState{clientHello: &RawClientHello{}}},
		hello: &clientHelloMsg{},
	}
	if err := hs.processHelloRetryRequest(); err == nil {
		t.Fatal("expected HelloRetryRequest error for prebuilt ClientHello")
	}
}

func TestNilPrebuiltClientHelloDoesNotChangeQUICConfig(t *testing.T) {
	q := QUICClient(&QUICConfig{TLSConfig: &Config{}})
	if q.conn.quic.clientHello != nil {
		t.Fatal("nil QUICConfig.ClientHello should leave quic.clientHello nil")
	}
}

func TestHybridClientSharedSecretUsesMlkemEcdhe(t *testing.T) {
	keIface, err := keyExchangeForCurveID(X25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	keys, _, err := keIface.keyShares(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hybridEcdhe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys.mlkemEcdhe = hybridEcdhe

	clientShare := append(keys.mlkem.Encapsulator().Bytes(), hybridEcdhe.PublicKey().Bytes()...)
	serverSecret, serverShare, err := keIface.serverSharedSecret(rand.Reader, clientShare)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret, err := keIface.clientSharedSecret(keys, serverShare.data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientSecret, serverSecret) {
		t.Fatal("hybrid shared secret mismatch: client did not use mlkemEcdhe")
	}

	// The plain X25519 path must keep using ecdhe, not mlkemEcdhe.
	plainKE, err := keyExchangeForCurveID(X25519)
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want, err := serverPriv.ECDH(keys.ecdhe.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	got, err := plainKE.clientSharedSecret(keys, serverPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("plain X25519 shared secret mismatch: ecdhe was not used")
	}
}
