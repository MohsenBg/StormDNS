package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stormdns-go/internal/config"
	DnsParser "stormdns-go/internal/dnsparser"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/security"
	"stormdns-go/internal/udpserver"
)

func startAutoRealServer(t *testing.T, upstreamPort int) *net.UDPAddr {
	t.Helper()
	reserved, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.LocalAddr().(*net.UDPAddr)
	reserved.Close()
	path := filepath.Join(t.TempDir(), "server.toml")
	body := fmt.Sprintf("DOMAIN = [\"v.example.com\"]\nUDP_HOST = \"127.0.0.1\"\nUDP_PORT = %d\nUDP_READERS = 1\nDNS_REQUEST_WORKERS = 2\nSUPPORTED_UPLOAD_COMPRESSION_TYPES = [0]\nSUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0]\n", addr.Port)
	body += fmt.Sprintf("USE_EXTERNAL_SOCKS5 = true\nFORWARD_IP = \"127.0.0.1\"\nFORWARD_PORT = %d\n", upstreamPort)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewCodec(1, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	server := udpserver.New(cfg, logger.New("auto-e2e-server", "error"), codec)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	probe, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	query, _ := DnsParser.BuildTXTQuestionPacket("v.example.com", 16, 0)
	buffer := make([]byte, 1024)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		probe.SetDeadline(time.Now().Add(30 * time.Millisecond))
		probe.Write(query)
		if _, err := probe.Read(buffer); err == nil {
			return addr
		}
	}
	t.Fatal("local server did not become ready")
	return nil
}

func startAutoEchoSOCKS(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		hello := make([]byte, 3)
		if _, err := io.ReadFull(conn, hello); err != nil {
			return
		}
		if !bytes.Equal(hello, []byte{5, 1, 0}) {
			return
		}
		conn.Write([]byte{5, 0})
		request := make([]byte, 10)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		if !bytes.Equal(request, []byte{5, 1, 0, 1, 8, 8, 8, 8, 1, 187}) {
			return
		}
		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		io.Copy(conn, conn)
	}()
	t.Cleanup(func() { cancel(); listener.Close(); <-done })
	return listener.Addr().(*net.TCPAddr).Port
}

// A local DNS forwarding path whose permitted record type can change while
// streams are active. All tunnel processing is done by the real UDP server.
func startAutoFilteringResolver(t *testing.T, backend *net.UDPAddr, allowed *atomic.Uint32) *net.UDPAddr {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var relays sync.WaitGroup
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := front.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			query := append([]byte(nil), buffer[:n]...)
			parsed, err := DnsParser.ParsePacketLite(query)
			if err != nil || !parsed.HasQuestion || uint32(parsed.FirstQuestion.Type) != allowed.Load() {
				continue
			}
			relays.Add(1)
			go func() {
				defer relays.Done()
				up, err := net.DialUDP("udp", nil, backend)
				if err != nil {
					return
				}
				defer up.Close()
				stop := context.AfterFunc(ctx, func() { up.Close() })
				defer stop()
				up.SetDeadline(time.Now().Add(time.Second))
				if _, err := up.Write(query); err != nil {
					return
				}
				reply := make([]byte, 65535)
				n, err := up.Read(reply)
				if err == nil {
					front.WriteToUDP(reply[:n], peer)
				}
			}()
		}
	}()
	t.Cleanup(func() { cancel(); front.Close(); <-done; relays.Wait() })
	return front.LocalAddr().(*net.UDPAddr)
}

func TestAutoRealTunnelSurvivesRecordTypeSwitch(t *testing.T) {
	// The real server intentionally forbids direct loopback targets. Route the
	// public target through a configured local SOCKS echo server instead; no
	// network traffic leaves loopback and the production policy stays intact.
	backend := startAutoRealServer(t, startAutoEchoSOCKS(t))
	var allowed atomic.Uint32
	allowed.Store(33)
	resolver := startAutoFilteringResolver(t, backend, &allowed)
	c := newAutoTestClient(t, &autoTestResolver{addr: resolver})
	c.cfg.ListenPort = 0
	c.cfg.UploadCompressionType = 0
	c.cfg.DownloadCompressionType = 0
	c.uploadCompression = 0
	c.downloadCompression = 0
	c.cfg.PingAggressiveIntervalSeconds = 0.02
	c.cfg.PingLazyIntervalSeconds = 0.05
	c.tunnelPacketTimeout = 500 * time.Millisecond
	c.pingManager = newPingManager(c)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatal(err)
	}
	c.successMTUChecks = true
	if c.connections[0].TunnelQueryType != 33 {
		t.Fatal("SRV-only path was not selected")
	}
	pathKey := c.connections[0].Key
	if err := c.InitializeSession(3); err != nil {
		t.Fatal(err)
	}
	sessionID := c.sessionID
	if err := c.StartAsyncRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.StopAsyncRuntime)
	c.InitVirtualStream0()
	c.pingManager.Start(ctx)

	proxy, err := net.DialTimeout("tcp", c.tcpListener.listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxy.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := proxy.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(proxy, hello); err != nil || !bytes.Equal(hello, []byte{5, 0}) {
		t.Fatalf("SOCKS greeting failed: %v %v", hello, err)
	}
	connect := []byte{5, 1, 0, 1, 8, 8, 8, 8, 0, 0}
	binary.BigEndian.PutUint16(connect[8:10], 443)
	if _, err := proxy.Write(connect); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(proxy, response); err != nil || response[1] != 0 {
		t.Fatalf("SOCKS connect failed: %v %v", response, err)
	}
	transfer := func(label string) {
		payload := bytes.Repeat([]byte(label), 32)
		if _, err := proxy.Write(payload); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(proxy, received); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if !bytes.Equal(payload, received) {
			t.Fatalf("%s: tunnel corrupted payload", label)
		}
	}
	transfer("SRV")
	allowed.Store(16)
	// Traffic now fails on SRV. The real timeout/health loop must discover TXT
	// on its own while ARQ preserves this already-connected TCP stream.
	transfer("TXT")
	after, _ := c.GetConnectionByKey(pathKey)
	if after.TunnelQueryType != 16 || c.sessionID != sessionID || c.runtimeResetPending.Load() {
		t.Fatal("failed to switch to TXT without restarting the real session")
	}
}
