package libv2ray

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/outbound"
)

func TestPrefixOutboundTags(t *testing.T) {
	content, tag, err := prefixOutboundTags(`{
		// Xray's own loader accepts comments too
		"outbounds": [
			{
				"tag": "proxy",
				"protocol": "vless",
				"streamSettings": {
					"sockopt": {"dialerProxy": "hop", "mark": 4294967295},
					"tlsSettings": {"echSockopt": {"dialerProxy": "ech"}},
					"xhttpSettings": {"extra": {"downloadSettings": {"sockopt": {"DialerProxy": "hop"}}}}
				}
			},
			{"Tag": "hop", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "elsewhere"}}},
			{"tag": "ech", "protocol": "freedom"},
			{"protocol": "blackhole"}
		]
	}`, "delay-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "delay-test-1/proxy" {
		t.Error("the measurement dials through ", tag)
	}
	want := `{
		"outbounds": [
			{
				"tag": "delay-test-1/proxy",
				"protocol": "vless",
				"streamSettings": {
					"sockopt": {"dialerProxy": "delay-test-1/hop", "mark": 4294967295},
					"tlsSettings": {"echSockopt": {"dialerProxy": "delay-test-1/ech"}},
					"xhttpSettings": {"extra": {"downloadSettings": {"sockopt": {"DialerProxy": "delay-test-1/hop"}}}}
				}
			},
			{"Tag": "delay-test-1/hop", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "elsewhere"}}},
			{"tag": "delay-test-1/ech", "protocol": "freedom"},
			{"tag": "delay-test-1#3", "protocol": "blackhole"}
		]
	}`
	if got, want := decodeJSON(t, content), decodeJSON(t, want); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMeasureOutboundDelayKeepsConfigurationsApart(t *testing.T) {
	// Configurations with the same tags, measured at the same time. Each dials through a dialerProxy
	// "hop" of its own: that of the working one reaches a server that answers, that of the broken one a
	// closed port. With an instance per measurement, a dialerProxy was looked up in the instance created
	// last, so either could go through the hop of the other.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := listener.Addr().String()
	listener.Close()

	config := func(hopTarget string) string {
		return fmt.Sprintf(`{
			"log": {"loglevel": "none"},
			"outbounds": [
				{"tag": "proxy", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
				{"tag": "hop", "protocol": "freedom", "settings": {"redirect": %q}}
			]
		}`, hopTarget)
	}
	working, broken := config(server.Listener.Addr().String()), config(closedAddress)
	const url = "http://delay.test/generate_204"

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := MeasureOutboundDelay(working, url); err != nil {
				t.Error("the working configuration failed: ", err)
			}
		}()
		go func() {
			defer wg.Done()
			if delay, err := MeasureOutboundDelay(broken, url); err == nil {
				t.Error("the broken configuration was measured at ", delay, " ms")
			}
		}()
	}
	wg.Wait()

	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the measurements")
	}
}

func TestMeasureOutboundDelayQueriesECHThroughOwnOutbound(t *testing.T) {
	// Configurations with an ECH outbound under one tag, as PattNG appends it, measured at the same
	// time. The ECH config query of each goes through the ECH outbound of its own configuration, which
	// sends it to the DNS server of that configuration. No VLESS server answers, so every measurement
	// fails after its query.
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	config := func(name string, dnsServer string) string {
		return fmt.Sprintf(`{
			"log": {"loglevel": "none"},
			"outbounds": [
				{
					"tag": "proxy",
					"protocol": "vless",
					"settings": {"address": "127.0.0.1", "port": %d, "id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"},
					"streamSettings": {
						"security": "tls",
						"tlsSettings": {
							"serverName": "%s.example",
							"echConfigList": "%s.example+udp://127.0.0.1:9",
							"echSockopt": {"dialerProxy": "ech-out"}
						}
					}
				},
				{"tag": "ech-out", "protocol": "freedom", "settings": {"redirect": %q}}
			]
		}`, server.Addr().(*net.TCPAddr).Port, name, name, dnsServer)
	}
	var queriesA, queriesB dnsQueries
	configA, configB := config("a", startDNSServer(t, &queriesA)), config("b", startDNSServer(t, &queriesB))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			MeasureOutboundDelay(configA, "http://delay.test/generate_204")
		}()
		go func() {
			defer wg.Done()
			MeasureOutboundDelay(configB, "http://delay.test/generate_204")
		}()
	}
	wg.Wait()

	for _, c := range []struct {
		name    string
		queries *dnsQueries
	}{{"a.example", &queriesA}, {"b.example", &queriesB}} {
		names := c.queries.get()
		if len(names) == 0 {
			t.Error("the ECH outbound for ", c.name, " sent no query")
		}
		for _, name := range names {
			if name != c.name {
				t.Error("the ECH outbound for ", c.name, " sent the query for ", name)
			}
		}
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the measurements")
	}
}

func TestMeasureOutboundDelayCleansUpAfterAnError(t *testing.T) {
	// The second outbound cannot be added under the tag of the first. The first is removed again, and
	// the shared instance closes with the measurement.
	_, err := MeasureOutboundDelay(`{
		"log": {"loglevel": "none"},
		"outbounds": [
			{"tag": "proxy", "protocol": "freedom"},
			{"tag": "proxy", "protocol": "freedom"}
		]
	}`, "http://delay.test/generate_204")
	if err == nil {
		t.Error("two outbounds with one tag were measured")
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the failed measurement")
	}
}

func TestCancelOutboundDelaysEndsItsBatchAtOnce(t *testing.T) {
	// A SOCKS server that never answers keeps each measurement waiting for its 12-second timeout.
	server := startStallingServer(t)
	config := stallingConfig(server)
	a, b := newBatchName("cancel-a"), newBatchName("cancel-b")
	type result struct {
		batch string
		delay int64
		err   error
	}
	results := make(chan result, 6)
	for _, batch := range []string{a, a, a, a, b, b} {
		go func() {
			delay, err := MeasureOutboundDelayInBatch(batch, config, "http://delay.test/generate_204")
			results <- result{batch, delay, err}
		}()
	}
	server.awaitConnections(t, 6)

	CancelOutboundDelays(a)
	for range 4 {
		select {
		case r := <-results:
			if r.batch != a || r.delay != -1 || r.err != nil {
				t.Errorf("after batch %s was cancelled, a measurement returned %+v", a, r)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a measurement of the cancelled batch still runs")
		}
	}
	select {
	case r := <-results:
		t.Fatalf("a measurement of the other batch returned %+v", r)
	case <-time.After(500 * time.Millisecond):
	}

	CancelOutboundDelays(b)
	for range 2 {
		select {
		case r := <-results:
			if r.delay != -1 || r.err != nil {
				t.Errorf("after batch %s was cancelled, a measurement returned %+v", b, r)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a measurement of the second batch still runs after it was cancelled")
		}
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after its measurements were cancelled")
	}
}

func TestMeasureOutboundDelayInACancelledBatchReturnsAtOnce(t *testing.T) {
	// The caller may have passed its last check when its test stopped
	server := startStallingServer(t)
	batch := newBatchName("cancel-c")
	CancelOutboundDelays(batch)

	start := time.Now()
	delay, err := MeasureOutboundDelayInBatch(batch, stallingConfig(server), "http://delay.test/generate_204")
	if delay != -1 || err != nil {
		t.Errorf("a measurement of a cancelled batch returned %d, %v", delay, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a measurement of a cancelled batch took %v", elapsed)
	}
	if n := server.accepted.Load(); n != 0 {
		t.Errorf("a measurement of a cancelled batch connected %d times", n)
	}
	if delayInstanceRunning() {
		t.Error("a measurement of a cancelled batch started the shared instance")
	}
}

func TestMeasureOutboundDelayInBatchForgetsAFinishedBatch(t *testing.T) {
	batch := newBatchName("finished")
	_, err := MeasureOutboundDelayInBatch(batch, `{
		"log": {"loglevel": "none"},
		"outbounds": [{"protocol": "blackhole"}]
	}`, "http://delay.test/generate_204")
	if err == nil {
		t.Error("a measurement through a blackhole succeeded")
	}
	delayBatches.Lock()
	_, kept := delayBatches.batches[batch]
	delayBatches.Unlock()
	if kept {
		t.Error("a batch is kept after its measurements finished")
	}
}

func TestOpenExitSwapsTheExitNodeBehindOneInbound(t *testing.T) {
	// Two servers stand for where two exit-nodes lead, and an HTTP client with the exit as its SOCKS proxy
	// for a core that dials out through it. A measurement keeps the shared instance running, as the
	// other profiles of a test do: the second core finds the inbound of the first, and only the exit-node
	// has changed.
	serverOf := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(name))
		}))
	}
	a, b := serverOf("a"), serverOf("b")
	defer a.Close()
	defer b.Close()
	exitNode := func(server *httptest.Server) string {
		return fmt.Sprintf(`{"outbounds": [{"tag": "exit-node", "protocol": "freedom", "settings": {"redirect": %q}}]}`, server.Listener.Addr().String())
	}
	through := func(port int64) (string, error) {
		transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
		defer transport.CloseIdleConnections()
		resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Get("http://exit.test/")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	stalling := startStallingServer(t)
	batch := newBatchName("swap")
	stalled := make(chan struct{})
	go func() {
		MeasureOutboundDelayInBatch(batch, stallingConfig(stalling), "http://delay.test/generate_204")
		close(stalled)
	}()
	stalling.awaitConnections(t, 1)

	portA, err := OpenExit(exitNode(a))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := through(portA); err != nil || got != "a" {
		t.Errorf("the first exit-node reached %q (%v)", got, err)
	}
	CloseExit()

	portB, err := OpenExit(exitNode(b))
	if err != nil {
		t.Fatal(err)
	}
	if portB != portA {
		t.Errorf("the second core got the inbound on %d, the first on %d", portB, portA)
	}
	if got, err := through(portB); err != nil || got != "b" {
		t.Errorf("the second exit-node reached %q (%v)", got, err)
	}
	CloseExit()

	CancelOutboundDelays(batch)
	select {
	case <-stalled:
	case <-time.After(3 * time.Second):
		t.Fatal("the stalled measurement still runs after its batch was cancelled")
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the exits and the measurement")
	}
	// The inbound went with the instance, and the next instance gets one of its own.
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portA), time.Second); err == nil {
		conn.Close()
		t.Error("the inbound of the exit still listens after the shared instance closed")
	}
	portC, err := OpenExit(exitNode(a))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := through(portC); err != nil || got != "a" {
		t.Errorf("the exit of a new instance reached %q (%v)", got, err)
	}
	CloseExit()
	// Letting go once more lets go of nothing.
	CloseExit()
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the last exit closed")
	}
}

// plainExit is the configuration of a plain exit-node, as a profile without finalMask and dialMode has it.
const plainExit = `{"outbounds": [{"tag": "exit-node", "protocol": "freedom"}]}`

func TestOpenExitServesOneCoreAtATime(t *testing.T) {
	if _, err := OpenExit(plainExit); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExit(plainExit); err == nil {
		t.Error("a second core got the exit before the first let go of it")
	}
	CloseExit()
	if _, err := OpenExit(plainExit); err != nil {
		t.Error("the exit stayed taken after the first core let go of it: ", err)
	}
	CloseExit()
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the exit closed")
	}
}

func TestOpenExitDialsByTheSockoptOfItsOutbound(t *testing.T) {
	// The exit-node of a profile carries the profile's dialMode in its sockopt, and the exit dials by it:
	// a mode this Xray does not know refuses every dial.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	port, err := OpenExit(fmt.Sprintf(`{"outbounds": [{
		"tag": "exit-node",
		"protocol": "freedom",
		"settings": {"redirect": %q},
		"streamSettings": {"sockopt": {"dialMode": "no-such-dial-mode"}}
	}]}`, server.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseExit()
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
	defer transport.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Get("http://exit.test/"); err == nil {
		resp.Body.Close()
		t.Error("the exit dialled by a dialMode this Xray does not know")
	}
}

func TestOpenExitRefusesAConfigurationWithoutAUsableExitNode(t *testing.T) {
	for _, config := range []string{
		"not json", "[]", "null", "{}",
		`{"outbounds": [{"protocol": "freedom"}]}`,
		`{"outbounds": [{"tag": "proxy", "protocol": "freedom"}]}`,
		`{"outbounds": [{"tag": "exit-node", "protocol": "no-such-protocol"}]}`,
	} {
		if _, err := OpenExit(config); err == nil {
			CloseExit()
			t.Errorf("an exit opened with the configuration %s", config)
		}
	}
	if delayInstanceRunning() {
		t.Error("the shared instance runs after the refused exits")
	}
}

func TestOpenExitLeavesTheMeasurementsTheirDialer(t *testing.T) {
	// A measurement keeps the shared instance running while the exit opens. An exit of an instance of its
	// own would set the dialer of the process, where the dialerProxy of a later measurement would then
	// not be found; the exit is part of the shared instance instead.
	stalling := startStallingServer(t)
	batch := newBatchName("exit")
	stalled := make(chan struct{})
	go func() {
		MeasureOutboundDelayInBatch(batch, stallingConfig(stalling), "http://delay.test/generate_204")
		close(stalled)
	}()
	stalling.awaitConnections(t, 1)

	if _, err := OpenExit(plainExit); err != nil {
		t.Fatal(err)
	}
	delayExit.Lock()
	exitInstance := delayExit.inst
	delayExit.Unlock()
	delayInstance.Lock()
	shared := exitInstance != nil && exitInstance == delayInstance.instance
	delayInstance.Unlock()
	if !shared {
		t.Error("the exit runs in an instance of its own")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	chain := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"outbounds": [
			{"tag": "proxy", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
			{"tag": "hop", "protocol": "freedom", "settings": {"redirect": %q}}
		]
	}`, server.Listener.Addr().String())
	if _, err := MeasureOutboundDelay(chain, "http://delay.test/generate_204"); err != nil {
		t.Error("a measurement through a dialerProxy failed beside the exit: ", err)
	}

	CloseExit()
	CancelOutboundDelays(batch)
	select {
	case <-stalled:
	case <-time.After(3 * time.Second):
		t.Fatal("the stalled measurement still runs after its batch was cancelled")
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the exit and the measurements")
	}
}

func TestExitOutboundsBringAlongWhatTheExitNodeDialsThrough(t *testing.T) {
	// The configuration of a chain whose Aether hop dials out through the two hops after it: the
	// exit-node dials through hop, which dials through the exit-node's own ECH outbound in turn. The
	// outbound to the core and an outbound nothing of the exit-node dials through stay out.
	content := `{
		"inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
		"outbounds": [
			{"tag": "proxy", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 10819}},
			{"tag": "exit-node", "protocol": "vless", "streamSettings": {
				"sockopt": {"dialerProxy": "hop"},
				"tlsSettings": {"echSockopt": {"dialerProxy": "ech"}}
			}},
			{"tag": "hop", "protocol": "trojan", "streamSettings": {"sockopt": {"dialerProxy": "exit-node"}}},
			{"tag": "ech", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "elsewhere"}}},
			{"tag": "other", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
			{"tag": "hop", "protocol": "shadowsocks"}
		]
	}`

	exit, err := exitOutbounds(content)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := map[string]map[string]any{}
	for _, element := range decodeJSON(t, exit).(map[string]any)["outbounds"].([]any) {
		outbound := element.(map[string]any)
		outbounds[outbound["tag"].(string)] = outbound
	}
	if len(outbounds) != 3 || outbounds["exit-node"] == nil || outbounds["exit-node/hop"] == nil || outbounds["exit-node/ech"] == nil {
		t.Fatalf("the exit brings along %v", exit)
	}
	dialerProxyOf := func(outbound map[string]any, path ...string) any {
		var value any = outbound
		for _, key := range path {
			value = value.(map[string]any)[key]
		}
		return value
	}
	if got := dialerProxyOf(outbounds["exit-node"], "streamSettings", "sockopt", "dialerProxy"); got != "exit-node/hop" {
		t.Errorf("the exit-node dials through %v", got)
	}
	if got := dialerProxyOf(outbounds["exit-node"], "streamSettings", "tlsSettings", "echSockopt", "dialerProxy"); got != "exit-node/ech" {
		t.Errorf("the exit-node queries ECH through %v", got)
	}
	// The first outbound with a tag is the one, and a loop back to the exit-node ends there.
	if got := outbounds["exit-node/hop"]["protocol"]; got != "trojan" {
		t.Errorf("the hop brought along is the %v outbound", got)
	}
	if got := dialerProxyOf(outbounds["exit-node/hop"], "streamSettings", "sockopt", "dialerProxy"); got != "exit-node" {
		t.Errorf("the hop dials through %v", got)
	}
	// A dialerProxy that names nothing of the configuration is left as written.
	if got := dialerProxyOf(outbounds["exit-node/ech"], "streamSettings", "sockopt", "dialerProxy"); got != "elsewhere" {
		t.Errorf("the ECH outbound dials through %v", got)
	}
}

func TestOpenExitDialsThroughTheHopsOfItsExitNode(t *testing.T) {
	// A proxy chain's hop as the exit-node, which dials through the hop after it: the request leaves by
	// the last hop, which leads to the server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hop"))
	}))
	defer server.Close()
	stalling := startStallingServer(t)
	batch := newBatchName("hops")
	stalled := make(chan struct{})
	go func() {
		MeasureOutboundDelayInBatch(batch, stallingConfig(stalling), "http://delay.test/generate_204")
		close(stalled)
	}()
	stalling.awaitConnections(t, 1)

	port, err := OpenExit(fmt.Sprintf(`{"outbounds": [
		{"tag": "proxy", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 9}},
		{"tag": "exit-node", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
		{"tag": "hop", "protocol": "freedom", "settings": {"redirect": %q}}
	]}`, server.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	handlers := func() outbound.Manager {
		delayInstance.Lock()
		defer delayInstance.Unlock()
		return delayInstance.instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	}
	if handlers().GetHandler("exit-node/hop") == nil || handlers().GetHandler("exit-node/proxy") != nil {
		t.Error("the exit holds other outbounds than its exit-node and the hop it dials through")
	}
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Get("http://exit.test/")
	if err != nil {
		t.Fatal("no answer through the hops of the exit-node: ", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "hop" {
		t.Errorf("the exit reached %q (%v)", body, err)
	}

	CloseExit()
	if handlers().GetHandler("exit-node") != nil || handlers().GetHandler("exit-node/hop") != nil {
		t.Error("the exit-node or its hop is left after the exit closed")
	}
	CancelOutboundDelays(batch)
	select {
	case <-stalled:
	case <-time.After(3 * time.Second):
		t.Fatal("the stalled measurement still runs after its batch was cancelled")
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the exit and the measurement")
	}
}

// batchNames numbers the batches of the tests. A cancelled batch stays cancelled, so each test names its
// batches anew, as PattNG does for each of its tests.
var batchNames atomic.Uint64

func newBatchName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, batchNames.Add(1))
}

// stallingServer accepts connections and never answers, like a proxy server whose far end is gone.
type stallingServer struct {
	port     int
	accepted atomic.Int32
}

func startStallingServer(t *testing.T) *stallingServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &stallingServer{port: listener.Addr().(*net.TCPAddr).Port}
	var conns sync.Map
	t.Cleanup(func() {
		listener.Close()
		conns.Range(func(conn, _ any) bool {
			conn.(net.Conn).Close()
			return true
		})
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns.Store(conn, nil)
			server.accepted.Add(1)
		}
	}()
	return server
}

// awaitConnections waits until n measurements connected to the server.
func (s *stallingServer) awaitConnections(t *testing.T, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.accepted.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d measurements connected", s.accepted.Load(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stallingConfig is a configuration whose outbound is a SOCKS proxy at server.
func stallingConfig(server *stallingServer) string {
	return fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"outbounds": [{"protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": %d}]}}]
	}`, server.port)
}

// dnsQueries records the names that a DNS server of a test was asked for.
type dnsQueries struct {
	sync.Mutex
	names []string
}

func (q *dnsQueries) add(name string) {
	q.Lock()
	defer q.Unlock()
	q.names = append(q.names, name)
}

func (q *dnsQueries) get() []string {
	q.Lock()
	defer q.Unlock()
	return append([]string(nil), q.names...)
}

// startDNSServer starts a UDP DNS server that records the name of each query in queries and answers
// NXDOMAIN, and returns its address.
func startDNSServer(t *testing.T, queries *dnsQueries) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			name, ok := dnsQuestionName(buffer[:n])
			if !ok {
				continue
			}
			queries.add(name)
			response := append([]byte(nil), buffer[:n]...)
			response[2] |= 0x80                   // QR: a response
			response[3] = response[3]&0xf0 | 0x03 // RCODE: NXDOMAIN
			conn.WriteTo(response, addr)
		}
	}()
	return conn.LocalAddr().String()
}

// dnsQuestionName returns the name in the question of a DNS message.
func dnsQuestionName(message []byte) (string, bool) {
	var labels []string
	for offset := 12; offset < len(message); {
		length := int(message[offset])
		if length == 0 {
			return strings.Join(labels, "."), true
		}
		offset++
		if offset+length > len(message) {
			return "", false
		}
		labels = append(labels, string(message[offset:offset+length]))
		offset += length
	}
	return "", false
}

func delayInstanceRunning() bool {
	delayInstance.Lock()
	defer delayInstance.Unlock()
	return delayInstance.instance != nil || delayInstance.users != 0
}

func decodeJSON(t *testing.T, content string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
