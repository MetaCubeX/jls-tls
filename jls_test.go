package tls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestJLSServerHelloAuthDataUsesWireEncoding(t *testing.T) {
	hello := testJLSServerHello()
	for i := range hello.random {
		hello.random[i] = byte(i + 1)
	}
	wire, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	wire = swapFirstTwoServerHelloExtensions(t, wire)

	received := new(serverHelloMsg)
	if !received.unmarshal(wire) {
		t.Fatal("failed to unmarshal test ServerHello")
	}
	original := append([]byte(nil), wire...)

	got, err := jlsServerHelloAuthData(received)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), wire...)
	jlsZero(want[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	if !bytes.Equal(got, want) {
		t.Fatal("JLS ServerHello authentication data did not preserve wire encoding")
	}
	if !bytes.Equal(received.original, original) {
		t.Fatal("JLS ServerHello authentication modified original wire encoding")
	}
}

func testJLSServerHello() *serverHelloMsg {
	return &serverHelloMsg{
		vers:                    VersionTLS12,
		random:                  make([]byte, jlsHelloRandomLen),
		cipherSuite:             TLS_AES_128_GCM_SHA256,
		compressionMethod:       compressionNone,
		serverShare:             keyShare{group: X25519, data: []byte{1}},
		selectedIdentityPresent: true,
		selectedIdentity:        0,
		supportedVersion:        VersionTLS13,
	}
}

func swapFirstTwoServerHelloExtensions(t *testing.T, message []byte) []byte {
	t.Helper()
	offset := jlsHelloRandomOffset + jlsHelloRandomLen
	if len(message) <= offset {
		t.Fatal("test ServerHello is too short")
	}
	sessionIDLen := int(message[offset])
	offset += 1 + sessionIDLen + 2 + 1
	if len(message) < offset+2 {
		t.Fatal("test ServerHello has no extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(message[offset : offset+2]))
	offset += 2
	end := offset + extensionsLen
	if end > len(message) || offset+4 > end {
		t.Fatal("test ServerHello has malformed extensions")
	}
	firstEnd := offset + 4 + int(binary.BigEndian.Uint16(message[offset+2:offset+4]))
	if firstEnd+4 > end {
		t.Fatal("test ServerHello has fewer than two extensions")
	}
	secondEnd := firstEnd + 4 + int(binary.BigEndian.Uint16(message[firstEnd+2:firstEnd+4]))
	if secondEnd > end {
		t.Fatal("test ServerHello has malformed second extension")
	}

	result := append([]byte(nil), message[:offset]...)
	result = append(result, message[firstEnd:secondEnd]...)
	result = append(result, message[offset:firstEnd]...)
	result = append(result, message[secondEnd:]...)
	return result
}

func TestJLSHandshake(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := testConfig.Clone()
	clientConfig.ServerName = "camouflage.example"
	clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}

	serverConfig := testConfig.Clone()
	serverConfig.JLSConfig = &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{{Username: "other", Password: "other-password"}, user},
		ServerName: clientConfig.ServerName,
	}

	serverState, clientState, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	if serverState.Version != VersionTLS13 || clientState.Version != VersionTLS13 {
		t.Fatalf("JLS negotiated versions: server=%#x client=%#x", serverState.Version, clientState.Version)
	}
	for side, state := range map[string]ConnectionState{"server": serverState, "client": clientState} {
		if state.JLS.Status != JLSAuthenticated || state.JLS.User != user.Username {
			t.Fatalf("%s JLS state = %+v, want authenticated user %q", side, state.JLS, user.Username)
		}
	}
}

func TestJLSAuthenticationFailure(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	for _, test := range []struct {
		name       string
		clientUser JLSUser
		serverName string
	}{
		{name: "wrong password", clientUser: JLSUser{Username: user.Username, Password: "wrong-password"}, serverName: "camouflage.example"},
		{name: "wrong server name", clientUser: user, serverName: "other.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
			clientConfig.TLSConfig.MinVersion = VersionTLS13
			clientConfig.TLSConfig.ServerName = test.serverName
			clientConfig.TLSConfig.JLSConfig = &JLSConfig{Enable: true, User: test.clientUser}

			serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
			serverConfig.TLSConfig.MinVersion = VersionTLS13
			serverConfig.TLSConfig.JLSConfig = &JLSConfig{
				Enable:     true,
				Users:      []JLSUser{user},
				ServerName: "camouflage.example",
			}

			client := newTestQUICClient(t, clientConfig)
			client.conn.SetTransportParameters(nil)
			server := newTestQUICServer(t, serverConfig)
			server.conn.SetTransportParameters(nil)

			err := runTestQUICConnection(context.Background(), client, server, nil)
			if !errors.Is(err, ErrJLSAuthFailed) {
				t.Fatalf("JLS authentication error = %v, want %v", err, ErrJLSAuthFailed)
			}
			if client.complete || server.complete {
				t.Fatal("JLS authentication failure completed the QUIC handshake")
			}
		})
	}
}

func TestJLSClientFallsBackToTLS(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := testConfig.Clone()
	clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}
	verifierCalled := false
	clientConfig.VerifyConnection = func(state ConnectionState) error {
		verifierCalled = true
		if state.JLS.Status == JLSAuthenticated {
			return errors.New("ordinary TLS server reported authenticated JLS state")
		}
		return nil
	}

	serverState, clientState, err := testHandshake(t, clientConfig, testConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	if !verifierCalled {
		t.Fatal("ordinary TLS fallback skipped VerifyConnection")
	}
	if serverState.JLS.Status != JLSDisabled {
		t.Fatalf("ordinary TLS server reported JLS state: %+v", serverState.JLS)
	}
	if clientState.JLS.Status != JLSUnauthenticated {
		t.Fatalf("ordinary TLS fallback reported JLS authentication: server=%+v client=%+v", serverState.JLS, clientState.JLS)
	}
}

func TestJLSTCPServerSuppressesUnauthenticatedAlerts(t *testing.T) {
	for _, test := range []struct {
		name       string
		enableJLS  bool
		wantWrites bool
	}{
		{name: "ordinary TLS", wantWrites: true},
		{name: "JLS TCP server", enableJLS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := localPipe(t)
			serverWriteCounter := &writeCountingConn{Conn: serverConn}

			clientConfig := testConfig.Clone()
			clientConfig.MaxVersion = VersionTLS12
			clientDone := make(chan error, 1)
			go func() {
				clientDone <- Client(clientConn, clientConfig).Handshake()
			}()

			serverConfig := testConfig.Clone()
			serverConfig.MinVersion = VersionTLS13
			if test.enableJLS {
				serverConfig.JLSConfig = &JLSConfig{
					Enable: true,
					Users:  []JLSUser{{Username: "user", Password: "password"}},
				}
			}
			serverErr := Server(serverWriteCounter, serverConfig).Handshake()
			_ = serverConn.Close()
			clientErr := <-clientDone
			_ = clientConn.Close()

			if serverErr == nil || clientErr == nil {
				t.Fatalf("handshake errors: server=%v client=%v", serverErr, clientErr)
			}
			if gotWrites := serverWriteCounter.numWrites > 0; gotWrites != test.wantWrites {
				t.Fatalf("server wrote during rejected handshake = %v, want %v", gotWrites, test.wantWrites)
			}
		})
	}
}

func TestJLSTCPServerDiscardsAuthenticatedPreWriteFailure(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	for _, test := range []struct {
		name      string
		configure func(*Config)
	}{
		{
			name: "alert before server flight",
			configure: func(config *Config) {
				config.Certificates = nil
			},
		},
		{
			name: "error with buffered server flight",
			configure: func(config *Config) {
				config.KeyLogWriter = jlsFailingWriter{}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := localPipe(t)
			serverWriteCounter := &writeCountingConn{Conn: serverConn}

			clientConfig := testConfig.Clone()
			clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}
			clientDone := make(chan error, 1)
			go func() {
				clientDone <- Client(clientConn, clientConfig).Handshake()
			}()

			serverConfig := testConfig.Clone()
			serverConfig.JLSConfig = &JLSConfig{Enable: true, Users: []JLSUser{user}}
			test.configure(serverConfig)
			server := Server(serverWriteCounter, serverConfig)
			serverErr := server.Handshake()
			serverState := server.ConnectionState()
			_ = serverConn.Close()
			clientErr := <-clientDone
			_ = clientConn.Close()

			if serverErr == nil || clientErr == nil {
				t.Fatalf("handshake errors: server=%v client=%v", serverErr, clientErr)
			}
			if serverWriteCounter.numWrites != 0 {
				t.Fatalf("JLS server wrote %d records before fallback", serverWriteCounter.numWrites)
			}
			if serverState.JLS.Status != JLSAuthenticated {
				t.Fatalf("server JLS state = %+v, want authenticated", serverState.JLS)
			}
		})
	}
}

type jlsFailingWriter struct{}

func (jlsFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("jls test writer failed")
}

func TestJLSAuthenticatedHandshakeSkipsCertificateVerification(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := testConfig.Clone()
	clientConfig.InsecureSkipVerify = false
	clientConfig.ServerName = "camouflage.example"
	clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}
	verifierCalled := false
	clientConfig.VerifyConnection = func(ConnectionState) error {
		verifierCalled = true
		return errors.New("JLS-authenticated handshake called VerifyConnection")
	}

	serverConfig := testConfig.Clone()
	serverConfig.JLSConfig = &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{user},
		ServerName: clientConfig.ServerName,
	}

	serverState, clientState, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	if verifierCalled {
		t.Fatal("JLS-authenticated handshake called VerifyConnection")
	}
	if serverState.JLS.Status != JLSAuthenticated || clientState.JLS.Status != JLSAuthenticated {
		t.Fatalf("JLS authentication state: server=%+v client=%+v", serverState.JLS, clientState.JLS)
	}
}

func TestJLSHelloRetryRequest(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	t.Run("ordinary TLS fallback", func(t *testing.T) {
		clientConfig := testConfig.Clone()
		clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}
		verifierCalled := false
		clientConfig.VerifyConnection = func(state ConnectionState) error {
			verifierCalled = true
			if state.JLS.Status != JLSUnauthenticated {
				return errors.New("HelloRetryRequest fallback reported authenticated JLS state")
			}
			return nil
		}

		serverConfig := testConfig.Clone()
		serverConfig.CurvePreferences = []CurveID{CurveP256}

		serverState, clientState, err := testHandshake(t, clientConfig, serverConfig)
		if err != nil {
			t.Fatal(err)
		}
		if !serverState.HelloRetryRequest || !clientState.HelloRetryRequest {
			t.Fatal("ordinary TLS fallback did not exercise HelloRetryRequest")
		}
		if !verifierCalled {
			t.Fatal("HelloRetryRequest fallback skipped certificate verification")
		}
		if clientState.JLS.Status != JLSUnauthenticated {
			t.Fatalf("client JLS state = %+v, want unauthenticated", clientState.JLS)
		}
	})

	t.Run("JLS server", func(t *testing.T) {
		clientConn, serverConn := localPipe(t)
		serverWriteCounter := &writeCountingConn{Conn: serverConn}

		clientConfig := testConfig.Clone()
		clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}
		clientDone := make(chan error, 1)
		go func() {
			clientDone <- Client(clientConn, clientConfig).Handshake()
		}()

		serverConfig := testConfig.Clone()
		serverConfig.CurvePreferences = []CurveID{CurveP256}
		serverConfig.JLSConfig = &JLSConfig{Enable: true, Users: []JLSUser{user}}
		server := Server(serverWriteCounter, serverConfig)
		serverErr := server.Handshake()
		serverState := server.ConnectionState()
		_ = serverConn.Close()
		clientErr := <-clientDone
		_ = clientConn.Close()

		if !errors.Is(serverErr, ErrJLSAuthFailed) || clientErr == nil {
			t.Fatalf("handshake errors: server=%v client=%v", serverErr, clientErr)
		}
		if serverWriteCounter.numWrites != 0 {
			t.Fatalf("JLS server wrote %d records before rejecting HelloRetryRequest", serverWriteCounter.numWrites)
		}
		if serverState.HelloRetryRequest {
			t.Fatal("JLS server reported HelloRetryRequest")
		}
		if serverState.JLS.Status != JLSUnauthenticated {
			t.Fatalf("server JLS state = %+v, want unauthenticated", serverState.JLS)
		}
	})
}
