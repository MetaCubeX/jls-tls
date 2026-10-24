// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/metacubex/mlkem"
)

// makeRawClientHello validates and adopts a caller-supplied ClientHello for a
// QUIC connection. The raw bytes are authoritative: they are used for the
// transcript and, when JLS is enabled, for the JLS associated data.
func (c *Conn) makeRawClientHello(ch *RawClientHello) (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error) {
	if c.quic == nil {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello is only supported for QUIC connections")
	}
	if c.config.EncryptedClientHelloConfigList != nil {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello cannot be used with encrypted client hello")
	}
	if ch == nil || len(ch.Raw) < 4 {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello is empty")
	}
	if ch.Raw[0] != typeClientHello {
		return nil, nil, nil, fmt.Errorf("tls: prebuilt ClientHello has handshake type %d, want %d", ch.Raw[0], typeClientHello)
	}
	msgLen := int(ch.Raw[1])<<16 | int(ch.Raw[2])<<8 | int(ch.Raw[3])
	if msgLen != len(ch.Raw)-4 {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello has invalid length")
	}
	if msgLen > maxHandshake {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello is too large")
	}

	// Keep our own copy: the caller may reuse or mutate Raw, while hello.random
	// aliases this buffer and JLS rewrites the random in place.
	raw := append([]byte(nil), ch.Raw...)
	var hello clientHelloMsg
	if !hello.unmarshal(raw) {
		return nil, nil, nil, errors.New("tls: failed to unmarshal prebuilt ClientHello")
	}
	if len(hello.sessionId) != 0 {
		return nil, nil, nil, errors.New("tls: prebuilt QUIC ClientHello must have an empty session_id")
	}
	if len(hello.random) != 32 {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello has invalid random")
	}
	if !slicesContains(hello.supportedVersions, VersionTLS13) {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello does not support TLS 1.3")
	}
	if len(hello.alpnProtocols) == 0 {
		return nil, nil, nil, errors.New("tls: prebuilt QUIC ClientHello has no ALPN")
	}
	if !slicesEqual(hello.alpnProtocols, c.config.NextProtos) {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello ALPN does not match Config.NextProtos")
	}
	if len(hello.pskIdentities) != 0 || len(hello.pskBinders) != 0 {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello with a PSK is not supported")
	}
	if c.quic.transportParams == nil {
		return nil, nil, nil, errors.New("tls: transport parameters must be set before using a prebuilt ClientHello")
	}
	if !bytes.Equal(hello.quicTransportParameters, c.quic.transportParams) {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello quic_transport_parameters do not match SetTransportParameters")
	}

	keys := &keySharePrivateKeys{
		ecdhe:      ch.ECDHE,
		mlkemEcdhe: ch.HybridECDHE,
	}
	if len(ch.MLKEMSeed) != 0 {
		key, err := mlkem.NewDecapsulationKey768(ch.MLKEMSeed)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tls: invalid ML-KEM seed: %w", err)
		}
		keys.mlkem = key
	}
	if keys.ecdhe == nil {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello requires an ECDHE private key")
	}

	var sawX25519, sawHybrid bool
	for _, share := range hello.keyShares {
		switch share.group {
		case X25519:
			sawX25519 = true
		case X25519MLKEM768:
			sawHybrid = true
			if keys.mlkem == nil {
				return nil, nil, nil, errors.New("tls: prebuilt hybrid key share requires an ML-KEM seed")
			}
			if keys.mlkemEcdhe == nil {
				return nil, nil, nil, errors.New("tls: prebuilt hybrid key share requires HybridECDHE")
			}
		default:
			return nil, nil, nil, fmt.Errorf("tls: prebuilt ClientHello has unsupported key share group %#x", uint16(share.group))
		}
	}
	if !sawX25519 && !sawHybrid {
		return nil, nil, nil, errors.New("tls: prebuilt ClientHello has no supported key share")
	}
	if sawX25519 && keys.ecdhe == nil {
		return nil, nil, nil, errors.New("tls: prebuilt X25519 key share requires ECDHE")
	}
	if sawHybrid && keys.mlkem == nil {
		return nil, nil, nil, errors.New("tls: prebuilt hybrid key share requires an ML-KEM seed")
	}

	return &hello, keys, nil, nil
}
