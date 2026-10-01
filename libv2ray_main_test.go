package libv2ray

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// quietCallbacks is a CoreCallbackHandler that ignores what the core reports.
type quietCallbacks struct{}

func (quietCallbacks) Startup() int                 { return 0 }
func (quietCallbacks) Shutdown() int                { return 0 }
func (quietCallbacks) OnEmitStatus(int, string) int { return 0 }

func TestStartLoopClosesWhatAFailedStartStarted(t *testing.T) {
	// The inbounds have no tag, so they start in order: the first listens, and the second fails, since
	// 192.0.2.1 (TEST-NET-1) is no address of this machine. The first went on listening beside the next
	// instance when the failed one was left open.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	first := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	inbound := fmt.Sprintf(`{"port": %d, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}}`, first)
	failing := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [%s, {"port": %d, "listen": "192.0.2.1", "protocol": "socks", "settings": {"auth": "noauth"}}],
		"outbounds": [{"protocol": "freedom"}]
	}`, inbound, first)

	controller := NewCoreController(quietCallbacks{})
	if err := controller.StartLoop(failing, 0); err == nil {
		controller.StopLoop()
		t.Fatal("a start with an inbound on an address of no interface succeeded")
	}
	if controller.IsRunning || controller.coreInstance != nil || controller.statsManager != nil {
		t.Error("the failed start left its instance with the controller")
	}
	address := fmt.Sprintf("127.0.0.1:%d", first)
	if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		conn.Close()
		t.Error("the first inbound of the failed start still listens")
	}

	// The next start takes the port the failed one had.
	working := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [%s],
		"outbounds": [{"protocol": "freedom"}]
	}`, inbound)
	if err := controller.StartLoop(working, 0); err != nil {
		t.Fatal("the start after the failed one failed: ", err)
	}
	if conn, err := net.DialTimeout("tcp", address, time.Second); err != nil {
		t.Error("the start after the failed one does not listen: ", err)
	} else {
		conn.Close()
	}
	controller.StopLoop()
	if controller.IsRunning {
		t.Error("the controller still runs after StopLoop")
	}
}
