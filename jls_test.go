package tls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestJLSForbiddenRandomSuffix(t *testing.T) {
	for _, suffix := range [][]byte{
		[]byte(downgradeCanaryTLS12),
		[]byte(downgradeCanaryTLS11),
		helloRetryRequestRandom[len(helloRetryRequestRandom)-len(downgradeCanaryTLS12):],
	} {
		random := append(make([]byte, jlsHelloRandomLen-len(suffix)), suffix...)
		if !jlsHasForbiddenRandomSuffix(random) {
			t.Fatalf("JLS accepted forbidden random suffix %x", suffix)
		}
	}
	if jlsHasForbiddenRandomSuffix(make([]byte, jlsHelloRandomLen)) {
		t.Fatal("JLS rejected an ordinary random suffix")
	}
}

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

func TestJLSQUICEarlyDataResumption(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	clientConfig.TLSConfig.MinVersion = VersionTLS13
	clientConfig.TLSConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.TLSConfig.ServerName = "camouflage.example"
	clientConfig.TLSConfig.NextProtos = []string{"h3"}
	clientConfig.TLSConfig.InsecureSkipVerify = false
	clientConfig.TLSConfig.JLSConfig = &JLSConfig{Enable: true, User: user}

	serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	serverConfig.TLSConfig.MinVersion = VersionTLS13
	serverConfig.TLSConfig.NextProtos = []string{"h3"}
	serverConfig.TLSConfig.JLSConfig = &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{user},
		ServerName: clientConfig.TLSConfig.ServerName,
	}

	client := newTestQUICClient(t, clientConfig)
	client.conn.SetTransportParameters(nil)
	server := newTestQUICServer(t, serverConfig)
	server.conn.SetTransportParameters(nil)
	server.ticketOpts.EarlyData = true
	if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
		t.Fatalf("first JLS handshake failed: %v", err)
	}

	cache := clientConfig.TLSConfig.ClientSessionCache.(*lruSessionCache)
	session := cache.q.Front().Value.(*lruSessionCacheEntry).state.session
	if len(session.verifiedChains) != 0 {
		t.Fatal("JLS camouflage certificate unexpectedly produced a verified chain")
	}
	if !client.conn.conn.canResumeJLSAuthenticatedSession(session) {
		t.Fatal("authenticated JLS session was not marked for resumption")
	}
	otherServerConfig := clientConfig.TLSConfig.Clone()
	otherServerConfig.ServerName = "other.example"
	if (&Conn{config: otherServerConfig}).canResumeJLSAuthenticatedSession(session) {
		t.Fatal("authenticated JLS session was accepted under a different cache key")
	}
	tls12Session := *session
	tls12Session.version = VersionTLS12
	if client.conn.conn.canResumeJLSAuthenticatedSession(&tls12Session) {
		t.Fatal("authenticated JLS marker was accepted for a TLS 1.2 session")
	}
	serverSession := *session
	serverSession.isClient = false
	if client.conn.conn.canResumeJLSAuthenticatedSession(&serverSession) {
		t.Fatal("authenticated JLS marker was accepted for a server session")
	}

	client = newTestQUICClient(t, clientConfig)
	client.conn.SetTransportParameters(nil)
	server = newTestQUICServer(t, serverConfig)
	server.conn.SetTransportParameters(nil)
	if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
		t.Fatalf("resumed JLS handshake failed: %v", err)
	}
	if state := client.conn.ConnectionState(); !state.DidResume || state.JLS.Status != JLSAuthenticated {
		t.Fatalf("resumed client state = %+v, want authenticated JLS resumption", state)
	}
	if client.writeSecret[QUICEncryptionLevelEarly].secret == nil {
		t.Fatal("resumed JLS client did not receive an early data write secret")
	}
	if server.readSecret[QUICEncryptionLevelEarly].secret == nil {
		t.Fatal("resumed JLS server did not receive an early data read secret")
	}

	otherUser := JLSUser{Username: "other", Password: "other-password"}
	clientConfig.TLSConfig.JLSConfig.User = otherUser
	serverConfig.TLSConfig.JLSConfig.Users = append(serverConfig.TLSConfig.JLSConfig.Users, otherUser)
	client = newTestQUICClient(t, clientConfig)
	client.conn.SetTransportParameters(nil)
	server = newTestQUICServer(t, serverConfig)
	server.conn.SetTransportParameters(nil)
	if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
		t.Fatalf("JLS handshake after changing credentials failed: %v", err)
	}
	if state := client.conn.ConnectionState(); state.DidResume || state.JLS.User != otherUser.Username {
		t.Fatalf("client state = %+v, want a full JLS handshake as %q", state, otherUser.Username)
	}
}

func TestJLSTCPResumption(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := testConfig.Clone()
	clientConfig.MinVersion = VersionTLS13
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.ServerName = "camouflage.example"
	clientConfig.InsecureSkipVerify = false
	clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}

	serverConfig := testConfig.Clone()
	serverConfig.MinVersion = VersionTLS13
	serverConfig.JLSConfig = &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{user},
		ServerName: clientConfig.ServerName,
	}

	_, clientState, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("first JLS TCP handshake failed: %v", err)
	}
	if clientState.DidResume {
		t.Fatal("first JLS TCP handshake unexpectedly resumed")
	}

	cache := clientConfig.ClientSessionCache.(*lruSessionCache)
	session := cache.q.Front().Value.(*lruSessionCacheEntry).state.session
	if len(session.verifiedChains) != 0 {
		t.Fatal("JLS TCP camouflage certificate unexpectedly produced a verified chain")
	}
	if !(&Conn{config: clientConfig}).canResumeJLSAuthenticatedSession(session) {
		t.Fatal("authenticated JLS TCP session was not marked for resumption")
	}

	_, clientState, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("resumed JLS TCP handshake failed: %v", err)
	}
	if !clientState.DidResume || clientState.JLS.Status != JLSAuthenticated {
		t.Fatalf("resumed client state = %+v, want authenticated JLS TCP resumption", clientState)
	}
}

func TestJLSTLS12FallbackSessionIsUnmarked(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := testConfig.Clone()
	clientConfig.MinVersion = VersionTLS12
	clientConfig.MaxVersion = VersionTLS12
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.ServerName = "camouflage.example"
	clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}

	serverConfig := testConfig.Clone()
	serverConfig.MinVersion = VersionTLS12
	serverConfig.MaxVersion = VersionTLS12
	serverConfig.JLSConfig = &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{user},
		ServerName: clientConfig.ServerName,
	}

	_, clientState, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("first TLS 1.2 fallback handshake failed: %v", err)
	}
	if clientState.DidResume || clientState.JLS.Status != JLSUnauthenticated {
		t.Fatalf("first client state = %+v, want unresumed TLS 1.2 fallback", clientState)
	}

	cache := clientConfig.ClientSessionCache.(*lruSessionCache)
	session := cache.q.Front().Value.(*lruSessionCacheEntry).state.session
	if (&Conn{config: clientConfig}).canResumeJLSAuthenticatedSession(session) {
		t.Fatal("TLS 1.2 fallback session was marked as JLS-authenticated")
	}

	_, clientState, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("resumed TLS 1.2 fallback handshake failed: %v", err)
	}
	if !clientState.DidResume || clientState.JLS.Status != JLSUnauthenticated {
		t.Fatalf("resumed client state = %+v, want ordinary TLS 1.2 fallback resumption", clientState)
	}
}

func TestJLSDoesNotTrustUnmarkedSession(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	clientConfig.TLSConfig.MinVersion = VersionTLS13
	clientConfig.TLSConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.TLSConfig.ServerName = "example.go.dev"
	clientConfig.TLSConfig.NextProtos = []string{"h3"}
	clientConfig.TLSConfig.InsecureSkipVerify = true

	serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	serverConfig.TLSConfig.MinVersion = VersionTLS13
	serverConfig.TLSConfig.NextProtos = []string{"h3"}

	client := newTestQUICClient(t, clientConfig)
	client.conn.SetTransportParameters(nil)
	server := newTestQUICServer(t, serverConfig)
	server.conn.SetTransportParameters(nil)
	server.ticketOpts.EarlyData = true
	if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
		t.Fatalf("ordinary TLS handshake failed: %v", err)
	}

	cache := clientConfig.TLSConfig.ClientSessionCache.(*lruSessionCache)
	session := cache.q.Front().Value.(*lruSessionCacheEntry).state.session
	if len(session.verifiedChains) != 0 {
		t.Fatal("insecure ordinary TLS session unexpectedly produced a verified chain")
	}
	if client.conn.conn.canResumeJLSAuthenticatedSession(session) {
		t.Fatal("ordinary TLS session was marked as JLS-authenticated")
	}

	clientConfig.TLSConfig.InsecureSkipVerify = false
	clientConfig.TLSConfig.JLSConfig = &JLSConfig{Enable: true, User: user}
	serverConfig.TLSConfig.JLSConfig = &JLSConfig{
		Enable:     true,
		Users:      []JLSUser{user},
		ServerName: clientConfig.TLSConfig.ServerName,
	}

	client = newTestQUICClient(t, clientConfig)
	client.conn.SetTransportParameters(nil)
	server = newTestQUICServer(t, serverConfig)
	server.conn.SetTransportParameters(nil)
	if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
		t.Fatalf("JLS handshake after ordinary TLS session failed: %v", err)
	}
	if state := client.conn.ConnectionState(); state.DidResume || state.JLS.Status != JLSAuthenticated {
		t.Fatalf("client state = %+v, want a full authenticated JLS handshake", state)
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
