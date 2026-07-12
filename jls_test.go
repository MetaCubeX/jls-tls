package tls

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestJLSServerHelloExtensionOrderMatchesRustls(t *testing.T) {
	message, err := testJLSServerHello().marshalForJLS()
	if err != nil {
		t.Fatal(err)
	}
	checkServerHelloExtensionOrder(t, message, []uint16{
		extensionKeyShare,
		extensionPreSharedKey,
		extensionSupportedVersions,
	})
}

func TestServerHelloMarshalKeepsStandardExtensionOrder(t *testing.T) {
	message, err := testJLSServerHello().marshal()
	if err != nil {
		t.Fatal(err)
	}
	checkServerHelloExtensionOrder(t, message, []uint16{
		extensionSupportedVersions,
		extensionKeyShare,
		extensionPreSharedKey,
	})
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

func checkServerHelloExtensionOrder(t *testing.T, message []byte, want []uint16) {
	t.Helper()
	offset := jlsHelloRandomOffset + jlsHelloRandomLen
	sessionIDLen := int(message[offset])
	offset += 1 + sessionIDLen + 2 + 1
	extensionsLen := int(binary.BigEndian.Uint16(message[offset : offset+2]))
	offset += 2
	end := offset + extensionsLen

	var got []uint16
	for offset < end {
		got = append(got, binary.BigEndian.Uint16(message[offset:offset+2]))
		extensionLen := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		offset += 4 + extensionLen
	}
	if len(got) != len(want) {
		t.Fatalf("ServerHello extensions = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ServerHello extensions = %#v, want %#v", got, want)
		}
	}
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
		if !state.JLS.Authenticated || state.JLS.User != user.Username {
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
		if state.JLS.Authenticated {
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
	if serverState.JLS.Authenticated || clientState.JLS.Authenticated {
		t.Fatalf("ordinary TLS fallback reported JLS authentication: server=%+v client=%+v", serverState.JLS, clientState.JLS)
	}
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
	if !serverState.JLS.Authenticated || !clientState.JLS.Authenticated {
		t.Fatalf("JLS authentication state: server=%+v client=%+v", serverState.JLS, clientState.JLS)
	}
}

func TestJLSHelloRetryRequest(t *testing.T) {
	user := JLSUser{Username: "user", Password: "password"}
	t.Run("full handshake", func(t *testing.T) {
		clientConfig := testConfig.Clone()
		clientConfig.JLSConfig = &JLSConfig{Enable: true, User: user}

		serverConfig := testConfig.Clone()
		serverConfig.CurvePreferences = []CurveID{CurveP256}
		serverConfig.JLSConfig = &JLSConfig{Enable: true, Users: []JLSUser{user}}

		serverState, clientState, err := testHandshake(t, clientConfig, serverConfig)
		if err != nil {
			t.Fatal(err)
		}
		if !serverState.HelloRetryRequest || !clientState.HelloRetryRequest {
			t.Fatal("JLS handshake did not exercise HelloRetryRequest")
		}
		if !serverState.JLS.Authenticated || serverState.JLS.User != user.Username {
			t.Fatalf("server JLS state = %+v, want authenticated user %q", serverState.JLS, user.Username)
		}
		if !clientState.JLS.Authenticated || clientState.JLS.User != user.Username {
			t.Fatalf("client JLS state = %+v, want authenticated user %q", clientState.JLS, user.Username)
		}
	})

	t.Run("QUIC session resumption", func(t *testing.T) {
		clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
		clientConfig.TLSConfig.MinVersion = VersionTLS13
		clientConfig.TLSConfig.ClientSessionCache = NewLRUClientSessionCache(1)
		clientConfig.TLSConfig.ServerName = "example.go.dev"
		clientConfig.TLSConfig.JLSConfig = &JLSConfig{Enable: true, User: user}

		serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
		serverConfig.TLSConfig.MinVersion = VersionTLS13
		serverConfig.TLSConfig.JLSConfig = &JLSConfig{Enable: true, Users: []JLSUser{user}}

		run := func() (*testQUICConn, *testQUICConn) {
			client := newTestQUICClient(t, clientConfig)
			client.conn.SetTransportParameters(nil)
			server := newTestQUICServer(t, serverConfig)
			server.conn.SetTransportParameters(nil)
			if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
				t.Fatal(err)
			}
			return client, server
		}

		firstClient, _ := run()
		if firstClient.conn.ConnectionState().DidResume {
			t.Fatal("first JLS QUIC connection unexpectedly resumed")
		}

		serverConfig.TLSConfig.CurvePreferences = []CurveID{CurveP256}
		secondClient, secondServer := run()
		clientState := secondClient.conn.ConnectionState()
		serverState := secondServer.conn.ConnectionState()
		if !clientState.DidResume || !clientState.HelloRetryRequest || !serverState.HelloRetryRequest {
			t.Fatalf("resumed HRR state: client=%+v server=%+v", clientState, serverState)
		}
		if !clientState.JLS.Authenticated || !serverState.JLS.Authenticated {
			t.Fatalf("JLS authentication state: client=%+v server=%+v", clientState.JLS, serverState.JLS)
		}
	})
}
