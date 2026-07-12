package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// JLS BEGIN: ShadowQUIC JLS authentication and camouflage support.

// JLSUser is a ShadowQUIC JLS user. Username maps to rustls-jls user_iv,
// and Password maps to rustls-jls user_pwd.
type JLSUser struct {
	Username string
	Password string
}

// JLSConfig enables ShadowQUIC JLS authentication and camouflage.
type JLSConfig struct {
	Enable bool

	// Client-side field.
	User JLSUser

	// Server-side fields.
	Users      []JLSUser
	ServerName string
}

// JLSState reports ShadowQUIC JLS authentication state for a connection.
type JLSState struct {
	Authenticated bool
	User          string
}

type jlsState uint8

const (
	jlsStateDisabled jlsState = iota
	jlsStateNotAuthed
	jlsStateAuthSuccess
	jlsStateAuthFailed
)

const (
	jlsHandshakeHeaderLen    = 4 // uint8 message type and uint24 message length
	jlsHelloLegacyVersionLen = 2
	jlsHelloRandomLen        = 32
	jlsHelloRandomOffset     = jlsHandshakeHeaderLen + jlsHelloLegacyVersionLen
	jlsRandomSeedLen         = jlsHelloRandomLen / 2
)

// ErrJLSAuthFailed is returned when ShadowQUIC JLS authentication fails.
var ErrJLSAuthFailed = errors.New("tls: jls authentication failed")

var errJLSAuthFailed = ErrJLSAuthFailed

func (c *Config) jlsClientConfig() *JLSConfig {
	if c == nil || c.JLSConfig == nil || !c.JLSConfig.Enable {
		return nil
	}
	return c.JLSConfig
}

func (c *Config) jlsServerConfig() *JLSConfig {
	if c == nil || c.JLSConfig == nil || !c.JLSConfig.Enable {
		return nil
	}
	return c.JLSConfig
}

func (c *Conn) jlsAuthenticated() bool {
	return c.jlsState == jlsStateAuthSuccess
}

func (c *Conn) suppressJLSUnauthenticatedAlerts() bool {
	cfg := c.config.jlsServerConfig()
	return !c.isClient && c.quic == nil && cfg != nil && !c.jlsAuthenticated()
}

func jlsBuildFakeRandom(user JLSUser, random16, authData []byte) ([]byte, error) {
	if len(random16) != jlsRandomSeedLen {
		return nil, errors.New("tls: jls random seed must be 16 bytes")
	}
	nonceHash := sha256.New()
	nonceHash.Write([]byte(user.Username))
	nonceHash.Write(authData)
	nonce := nonceHash.Sum(nil)

	keyHash := sha256.New()
	keyHash.Write([]byte(user.Password))
	keyHash.Write(authData)
	key := keyHash.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, sha256.Size)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, random16, nil), nil
}

func jlsCheckFakeRandom(user JLSUser, fakeRandom, authData []byte) bool {
	if len(fakeRandom) != jlsHelloRandomLen {
		return false
	}
	nonceHash := sha256.New()
	nonceHash.Write([]byte(user.Username))
	nonceHash.Write(authData)
	nonce := nonceHash.Sum(nil)

	keyHash := sha256.New()
	keyHash.Write([]byte(user.Password))
	keyHash.Write(authData)
	key := keyHash.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	aead, err := cipher.NewGCMWithNonceSize(block, sha256.Size)
	if err != nil {
		return false
	}
	plain, err := aead.Open(nil, nonce, fakeRandom, nil)
	return err == nil && len(plain) == jlsRandomSeedLen
}

func (c *Conn) applyJLSClientHello(hello *clientHelloMsg, session *SessionState, binderKey []byte) error {
	if err := c.applyJLSClientHelloRandom(hello); err != nil {
		return err
	}
	if c.config.jlsClientConfig() == nil {
		return nil
	}

	if session != nil && binderKey != nil {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		if suite == nil {
			return errors.New("tls: jls failed to find tls13 cipher suite for psk binder")
		}
		transcript := suite.hash.New()
		if err := computeAndUpdatePSK(hello, binderKey, transcript, suite.finishedHash); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) applyJLSClientHelloRandom(hello *clientHelloMsg) error {
	cfg := c.config.jlsClientConfig()
	if cfg == nil {
		c.jlsState = jlsStateDisabled
		return nil
	}
	if c.config.EncryptedClientHelloConfigList != nil {
		return errors.New("tls: jls cannot be used with encrypted client hello")
	}
	if len(hello.random) != jlsHelloRandomLen {
		return errors.New("tls: jls client hello random is invalid")
	}
	c.jlsState = jlsStateNotAuthed

	authData, err := jlsClientHelloAuthData(hello)
	if err != nil {
		return err
	}
	fakeRandom, err := jlsBuildFakeRandom(cfg.User, hello.random[:jlsRandomSeedLen], authData)
	if err != nil {
		return err
	}
	hello.random = fakeRandom
	return nil
}

func jlsClientHelloAuthData(hello *clientHelloMsg) ([]byte, error) {
	clone := hello.clone()
	clone.original = nil
	clone.random = make([]byte, jlsHelloRandomLen)
	for i := range clone.pskBinders {
		clone.pskBinders[i] = make([]byte, len(clone.pskBinders[i]))
	}
	return clone.marshal()
}

func (c *Conn) authenticateJLSServerHello(serverHello *serverHelloMsg) error {
	cfg := c.config.jlsClientConfig()
	if cfg == nil {
		c.jlsState = jlsStateDisabled
		return nil
	}
	authData, err := jlsServerHelloAuthData(serverHello)
	if err != nil {
		return err
	}
	if !jlsCheckFakeRandom(cfg.User, serverHello.random, authData) {
		c.jlsState = jlsStateAuthFailed
		return nil
	}
	c.jlsState = jlsStateAuthSuccess
	c.jlsUser = cfg.User
	return nil
}

// marshalForJLS returns the canonical ServerHello encoding used as JLS
// authentication data. TLS does not assign meaning to the order of extensions,
// but JLS authenticates the serialized message (with random zeroed by the
// caller), so both peers must produce byte-for-byte identical encodings.
//
// rustls decodes a received ServerHello and re-encodes ServerExtensions in its
// struct declaration order: key_share, pre_shared_key, supported_versions. Go
// normally marshals those fields as supported_versions, key_share,
// pre_shared_key. Authenticating Go's normal encoding directly would therefore
// break both Go-to-rustls and rustls-to-Go JLS handshakes.
//
// Go-to-Go remains compatible because authentication encoding is separate from
// wire encoding:
//   - the Go server canonicalizes its ServerHello fields here, zeros random in
//     jlsServerHelloAuthData, and uses those bytes to build the fake random;
//   - it then sends the ServerHello with the normal Go marshal order;
//   - the Go client parses those wire bytes into serverHelloMsg fields, calls
//     this method to recreate the same canonical bytes, zeros random, and
//     verifies the fake random.
//
// The server and client therefore authenticate identical canonical bytes even
// though the wire uses Go's normal order. The TLS transcript is also unchanged:
// the server hashes its normal marshal output, while the client hashes the
// stored original wire bytes, which are the exact bytes sent by the server.
//
// This conversion is deliberately isolated from serverHelloMsg.marshal. The
// normal marshal order and the original wire bytes must remain unchanged for
// TLS transcript hashing and non-JLS handshakes. Starting with the normal
// encoding here also preserves every non-JLS field and extension payload.
func (m *serverHelloMsg) marshalForJLS() ([]byte, error) {
	msg, err := m.marshal()
	if err != nil {
		return nil, err
	}

	// Parse the complete ServerHello structure instead of relying on fixed byte
	// offsets. The extension slices below continue to reference msg.
	s := cryptobyte.String(msg)
	var messageType, compressionMethod uint8
	var legacyVersion, cipherSuite uint16
	var body, sessionID, extensions cryptobyte.String
	var random []byte
	if !s.ReadUint8(&messageType) ||
		messageType != typeServerHello ||
		!s.ReadUint24LengthPrefixed(&body) ||
		!s.Empty() ||
		!body.ReadUint16(&legacyVersion) ||
		!body.ReadBytes(&random, jlsHelloRandomLen) ||
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16(&cipherSuite) ||
		!body.ReadUint8(&compressionMethod) ||
		!body.ReadUint16LengthPrefixed(&extensions) ||
		!body.Empty() {
		return nil, errors.New("tls: invalid JLS server hello")
	}

	type extension struct {
		typeID uint16
		wire   []byte
	}
	extensionBytes := extensions
	parsed := make([]extension, 0, 3)
	for len(extensions) > 0 {
		remaining := extensions
		var typeID uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typeID) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("tls: invalid JLS server hello extensions")
		}
		wireLen := len(remaining) - len(extensions)
		parsed = append(parsed, extension{typeID: typeID, wire: remaining[:wireLen]})
	}

	// These are the only extensions whose relative order differs between the
	// valid TLS 1.3 JLS ServerHello encodings produced by Go and rustls.
	canonicalTypes := [...]uint16{
		extensionKeyShare,
		extensionPreSharedKey,
		extensionSupportedVersions,
	}
	canonical := make(map[uint16][]byte, len(canonicalTypes))
	for _, ext := range parsed {
		for _, typeID := range canonicalTypes {
			if ext.typeID == typeID {
				canonical[typeID] = ext.wire
				break
			}
		}
	}

	// Replace the canonical extensions at their first original position. Every
	// extension frame is reused verbatim and the total size is unchanged, so the
	// existing handshake and extension length prefixes remain valid. Unrelated
	// extensions retain their original relative order.
	extensionOffset := len(msg) - len(extensionBytes)
	result := append([]byte(nil), msg[:extensionOffset]...)
	canonicalWritten := false
	for _, ext := range parsed {
		if _, ok := canonical[ext.typeID]; ok {
			if !canonicalWritten {
				for _, typeID := range canonicalTypes {
					result = append(result, canonical[typeID]...)
				}
				canonicalWritten = true
			}
			continue
		}
		result = append(result, ext.wire...)
	}
	return result, nil
}

func jlsServerHelloAuthData(hello *serverHelloMsg) ([]byte, error) {
	msg, err := hello.marshalForJLS()
	if err != nil {
		return nil, err
	}
	if len(msg) < jlsHelloRandomOffset+jlsHelloRandomLen {
		return nil, errors.New("tls: jls server hello too short")
	}
	jlsZero(msg[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	return msg, nil
}

func (c *Conn) authenticateJLSClientHello(hello *clientHelloMsg) error {
	cfg := c.config.jlsServerConfig()
	if cfg == nil {
		c.jlsState = jlsStateDisabled
		return nil
	}
	c.jlsState = jlsStateNotAuthed
	authData, err := jlsClientHelloWireAuthData(hello)
	if err != nil {
		c.jlsState = jlsStateAuthFailed
		return err
	}
	if !cfg.checkServerName(hello.serverName) {
		c.jlsState = jlsStateAuthFailed
		return errJLSAuthFailed
	}
	for _, user := range cfg.Users {
		if jlsCheckFakeRandom(user, hello.random, authData) {
			c.jlsState = jlsStateAuthSuccess
			c.jlsUser = user
			return nil
		}
	}
	c.jlsState = jlsStateAuthFailed
	return errJLSAuthFailed
}

func jlsClientHelloWireAuthData(hello *clientHelloMsg) ([]byte, error) {
	var msg []byte
	if hello.original != nil {
		msg = append([]byte(nil), hello.original...)
	} else {
		var err error
		msg, err = jlsClientHelloAuthData(hello)
		if err != nil {
			return nil, err
		}
		return msg, nil
	}
	if len(msg) < jlsHelloRandomOffset+jlsHelloRandomLen {
		return nil, errors.New("tls: jls client hello too short")
	}
	jlsZero(msg[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	return jlsZeroPSKBinders(msg, hello.pskBinders)
}

func jlsZeroPSKBinders(msg []byte, binders [][]byte) ([]byte, error) {
	if len(binders) == 0 {
		return msg, nil
	}
	bindersLen := 2
	for _, binder := range binders {
		if len(binder) > 0xff {
			return nil, errors.New("tls: jls psk binder too large")
		}
		bindersLen += 1 + len(binder)
	}
	if bindersLen > len(msg) || bindersLen-2 > 0xffff {
		return nil, errors.New("tls: jls malformed psk binders")
	}
	off := len(msg) - bindersLen
	binary.BigEndian.PutUint16(msg[off:off+2], uint16(bindersLen-2))
	off += 2
	for _, binder := range binders {
		msg[off] = byte(len(binder))
		off++
		jlsZero(msg[off : off+len(binder)])
		off += len(binder)
	}
	return msg, nil
}

func jlsZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (cfg *JLSConfig) checkServerName(serverName string) bool {
	if cfg == nil || cfg.ServerName == "" {
		return true
	}
	return serverName == cfg.ServerName
}

// JLS END
