package libv2ray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	json_reader "github.com/xtls/xray-core/infra/conf/json"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/blackhole"
)

// Xray runs at most one instance per process (core/xray.go: "At any time, there must be at most one
// Server instance running"): the instance created last sets the outbound manager and the DNS client
// that every dialerProxy and domainStrategy of the process resolves with. MeasureOutboundDelay
// therefore measures every configuration in one shared instance, which runs while any measurement
// does. A measurement adds the outbounds of its configuration under tags of its own, dials through the
// first of them and removes them again, so measurements that run at the same time never use each
// other's outbounds. The exits that OpenExit opens are part of the same instance, for the same reason.

// delayDefaultTag is the tag of the shared instance's own outbound, a blackhole that is its default
// handler, so that no measured outbound becomes the default. Measured tags start with it and a number.
const delayDefaultTag = "delay-test"

var delayInstance struct {
	sync.Mutex
	instance *core.Instance
	users    int
}

// delayMeasurements numbers the measurements for the tags of their outbounds.
var delayMeasurements atomic.Uint64

// delayBatches holds the batches of measurements that run or were cancelled. PattNG measures the configurations
// of a test as one batch, and ends it with CancelOutboundDelays when the test stops: it cannot interrupt a
// measurement, which blocks a Java thread in Go.
var delayBatches = struct {
	sync.Mutex
	batches map[string]*delayBatch
}{batches: map[string]*delayBatch{}}

type delayBatch struct {
	ctx    context.Context
	cancel context.CancelFunc
	users  int
	// cancelled is set by CancelOutboundDelays. The batch is then kept for the life of the process, so that a
	// measurement that starts later returns at once as well: its caller may have passed its last check already.
	// PattNG names the batch of each test anew and cancels it at most once.
	cancelled bool
}

// delayBatchOf returns the batch with name, which it adds when there is none. The caller holds delayBatches.
func delayBatchOf(name string) *delayBatch {
	batch := delayBatches.batches[name]
	if batch == nil {
		ctx, cancel := context.WithCancel(context.Background())
		batch = &delayBatch{ctx: ctx, cancel: cancel}
		delayBatches.batches[name] = batch
	}
	return batch
}

// acquireDelayBatch returns the context of the measurements of the batch with name. Each call must be followed
// by releaseDelayBatch.
func acquireDelayBatch(name string) context.Context {
	delayBatches.Lock()
	defer delayBatches.Unlock()

	batch := delayBatchOf(name)
	batch.users++
	return batch.ctx
}

// releaseDelayBatch forgets the batch with name once none of its measurements runs, unless it was cancelled.
func releaseDelayBatch(name string) {
	delayBatches.Lock()
	defer delayBatches.Unlock()

	batch := delayBatches.batches[name]
	batch.users--
	if batch.users == 0 && !batch.cancelled {
		batch.cancel()
		delete(delayBatches.batches, name)
	}
}

// CancelOutboundDelays ends the measurements of the batch with name at once: the running ones return -1, and so
// do those that start later. The measurements of other batches go on.
func CancelOutboundDelays(name string) {
	delayBatches.Lock()
	defer delayBatches.Unlock()

	batch := delayBatchOf(name)
	batch.cancelled = true
	batch.cancel()
}

// acquireDelayInstance returns the shared instance. When neither a measurement nor an exit uses it, it
// starts one with the apps of config that they need, and a router for the rules of the exits. Each
// successful call must be followed by releaseDelayInstance.
func acquireDelayInstance(config *core.Config) (*core.Instance, error) {
	delayInstance.Lock()
	defer delayInstance.Unlock()

	if delayInstance.instance == nil {
		var apps []*serial.TypedMessage
		for _, app := range config.App {
			if app.Type == "xray.app.proxyman.OutboundConfig" ||
				app.Type == "xray.app.proxyman.InboundConfig" ||
				app.Type == "xray.app.dispatcher.Config" ||
				app.Type == "xray.app.log.Config" {
				apps = append(apps, app)
			}
		}
		apps = append(apps, serial.ToTypedMessage(&router.Config{}))
		inst, err := core.New(&core.Config{
			App: apps,
			Outbound: []*core.OutboundHandlerConfig{{
				Tag:           delayDefaultTag,
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			}},
		})
		if err != nil {
			return nil, err
		}
		if err := inst.Start(); err != nil {
			inst.Close()
			return nil, err
		}
		delayInstance.instance = inst
	}
	delayInstance.users++
	return delayInstance.instance, nil
}

// releaseDelayInstance closes the shared instance once neither a measurement nor an exit uses it.
func releaseDelayInstance() {
	delayInstance.Lock()
	defer delayInstance.Unlock()

	delayInstance.users--
	if delayInstance.users == 0 {
		delayInstance.instance.Close()
		delayInstance.instance = nil
	}
}

// addDelayOutbounds adds the outbounds of a measurement to the shared instance. The returned function
// removes and closes those it added, also after an error.
func addDelayOutbounds(inst *core.Instance, configs []*core.OutboundHandlerConfig) (func(), error) {
	outbounds := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	remove := func() {
		for _, config := range configs {
			if handler := outbounds.GetHandler(config.Tag); handler != nil {
				outbounds.RemoveHandler(context.Background(), config.Tag)
				handler.Close()
			}
		}
	}
	for _, config := range configs {
		if err := core.AddOutboundHandler(inst, config); err != nil {
			return remove, err
		}
	}
	return remove, nil
}

// The cores that PattNG runs on their own, for scans, key renewals and latency tests, dial out through
// the exit of the shared instance of their process, as the core of a session dials out through an
// inbound of the session's configuration: what comes in on the mixed inbound exitInboundTag, on the
// loopback address, leaves by the outbound exitOutboundTag, the exit-node of the core: a plain one of
// its profile, or, in a proxy chain, the hop the core dials out through. PattNG runs one such core at a
// time in a process, so the inbound and its routing rule stay while the shared instance runs, and only
// the exit-node changes from one core to the next. A measurement names its outbound, which routing then
// has no say in.
const (
	exitInboundTag  = "secondary-socks"
	exitOutboundTag = "exit-node"
	exitRuleTag     = "exit"
)

var delayExit struct {
	sync.Mutex
	// inst is the instance that holds the inbound and the rule of the exit, the inbound on port. A later
	// instance holds neither until an exit opens in it.
	inst *core.Instance
	port int
	// remove takes the exit-node out again, with the outbounds it dials through; it is set while a core
	// dials out through the exit.
	remove func()
}

// OpenExit sets the outbound of config tagged exitOutboundTag as the exit-node of the exit, and returns
// the port of the exit's inbound. Of config, the JSON of an Xray configuration, only the outbounds are
// read: the exit-node, and every outbound it dials through by dialerProxy, which come along under tags
// of the exit, see exitOutbounds. The first exit of a shared instance adds the inbound and its rule, on
// a free port, and they stay while the instance runs. One core at a time dials out through the exit:
// until CloseExit, a second OpenExit fails. The shared instance runs while the exit is open.
func OpenExit(config string) (int64, error) {
	delayExit.Lock()
	defer delayExit.Unlock()

	if delayExit.remove != nil {
		return -1, errors.New("the exit is open for another core")
	}
	outbounds, err := exitOutbounds(config)
	if err != nil {
		return -1, fmt.Errorf("outbound load error: %w", err)
	}
	loaded, err := coreserial.LoadJSONConfig(strings.NewReader(outbounds))
	if err != nil {
		return -1, fmt.Errorf("config load error: %w", err)
	}

	inst, err := acquireDelayInstance(loaded)
	if err != nil {
		return -1, fmt.Errorf("instance creation failed: %w", err)
	}
	if delayExit.inst != inst {
		if err := addExitInbound(inst); err != nil {
			releaseDelayInstance()
			return -1, fmt.Errorf("exit creation failed: %w", err)
		}
	}
	remove, err := addDelayOutbounds(inst, loaded.Outbound)
	if err != nil {
		remove()
		releaseDelayInstance()
		return -1, fmt.Errorf("exit creation failed: %w", err)
	}
	delayExit.remove = remove
	return int64(delayExit.port), nil
}

// addExitInbound adds the inbound of the exit, on a free port of the loopback address, and the rule that
// sends what comes in on it out by the exit-node to inst. The caller holds delayExit.
func addExitInbound(inst *core.Instance) error {
	port, err := freeLoopbackPort()
	if err != nil {
		return err
	}
	config, err := coreserial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(`{
		"inbounds": [{"tag": %q, "port": %d, "listen": "127.0.0.1", "protocol": "mixed", "settings": {"udp": true}}],
		"routing": {"rules": [{"ruleTag": %q, "inboundTag": [%q], "outboundTag": %q}]}
	}`, exitInboundTag, port, exitRuleTag, exitInboundTag, exitOutboundTag)))
	if err != nil {
		return err
	}
	rules := appOf(config, "xray.app.router.Config")
	if rules == nil {
		return errors.New("the exit has no routing")
	}
	routes := inst.GetFeature(routing.RouterType()).(routing.Router)
	if err := routes.AddRule(rules, true); err != nil {
		return err
	}
	if err := core.AddInboundHandler(inst, config.Inbound[0]); err != nil {
		routes.RemoveRule(exitRuleTag)
		return err
	}
	delayExit.inst, delayExit.port = inst, port
	return nil
}

// CloseExit takes out the exit-node that OpenExit set, with the outbounds it dials through, and lets go
// of the shared instance, which closes, with the inbound and the rule of the exit, unless a measurement
// runs. Without an open exit it does nothing.
func CloseExit() {
	delayExit.Lock()
	defer delayExit.Unlock()

	if delayExit.remove == nil {
		return
	}
	delayExit.remove()
	delayExit.remove = nil
	releaseDelayInstance()
}

// exitOutbounds returns, as the JSON of a configuration with outbounds alone, the outbound of the
// configuration content tagged exitOutboundTag and every outbound of content that it dials through by
// dialerProxy, at any depth. Those come along under tags of the exit, exitOutboundTag followed by "/" and
// their own tag, so that they never meet the outbounds of a measurement, and every dialerProxy among
// them follows its outbound to the new tag. A dialerProxy that names no outbound of content is left as
// it is: it names no outbound of the exit either way. When several outbounds have a tag, the first
// counts, as it does for Xray.
func exitOutbounds(content string) (string, error) {
	decoder := json.NewDecoder(&json_reader.Reader{Reader: strings.NewReader(content)})
	decoder.UseNumber()
	var config map[string]any
	if err := decoder.Decode(&config); err != nil {
		return "", err
	}
	all, _ := config[jsonKey(config, "outbounds")].([]any)
	byTag := map[string]map[string]any{}
	for _, element := range all {
		outbound, ok := element.(map[string]any)
		if !ok {
			continue
		}
		if tag, _ := outbound[jsonKey(outbound, "tag")].(string); tag != "" && byTag[tag] == nil {
			byTag[tag] = outbound
		}
	}
	if byTag[exitOutboundTag] == nil {
		return "", errors.New("the configuration has no exit-node")
	}

	tags := map[string]string{exitOutboundTag: exitOutboundTag}
	order := []string{exitOutboundTag}
	for i := 0; i < len(order); i++ {
		for _, tag := range dialerProxiesOf(byTag[order[i]]) {
			if _, taken := tags[tag]; taken || byTag[tag] == nil {
				continue
			}
			tags[tag] = exitOutboundTag + "/" + tag
			order = append(order, tag)
		}
	}
	outbounds := make([]any, 0, len(order))
	for _, tag := range order {
		outbound := byTag[tag]
		outbound[jsonKey(outbound, "tag")] = tags[tag]
		relinkDialerProxies(outbound, tags)
		outbounds = append(outbounds, outbound)
	}

	exit, err := json.Marshal(map[string]any{"outbounds": outbounds})
	if err != nil {
		return "", err
	}
	return string(exit), nil
}

// dialerProxiesOf returns every dialerProxy in value, in the order they are found.
func dialerProxiesOf(value any) []string {
	var found []string
	var walk func(value any)
	walk = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, element := range value {
				if tag, ok := element.(string); ok && strings.EqualFold(key, "dialerProxy") {
					found = append(found, tag)
					continue
				}
				walk(element)
			}
		case []any:
			for _, element := range value {
				walk(element)
			}
		}
	}
	walk(value)
	return found
}

// appOf returns the app of config whose type is name, or nil when it has none.
func appOf(config *core.Config, name string) *serial.TypedMessage {
	for _, app := range config.App {
		if app.Type == name {
			return app
		}
	}
	return nil
}

// freeLoopbackPort returns a port of the loopback address that nothing listens on.
func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// prefixOutboundTags gives every outbound of the configuration content a tag of the measurement:
// prefix followed by "/" and its own tag, or by "#" and its index when it has none. Every dialerProxy
// that names an outbound of the configuration follows it to its new tag. It returns the new content and
// the tag of the first outbound, which the measurement dials through.
func prefixOutboundTags(content string, prefix string) (string, string, error) {
	decoder := json.NewDecoder(&json_reader.Reader{Reader: strings.NewReader(content)})
	decoder.UseNumber()
	var config map[string]any
	if err := decoder.Decode(&config); err != nil {
		return "", "", err
	}
	outbounds, _ := config[jsonKey(config, "outbounds")].([]any)
	if len(outbounds) == 0 {
		return "", "", errors.New("the configuration has no outbound")
	}

	tags := make(map[string]string, len(outbounds))
	var firstTag string
	for i, element := range outbounds {
		outbound, ok := element.(map[string]any)
		if !ok {
			return "", "", fmt.Errorf("outbound %d is not an object", i)
		}
		key := jsonKey(outbound, "tag")
		newTag := prefix + "#" + strconv.Itoa(i)
		if tag, _ := outbound[key].(string); tag != "" {
			newTag = prefix + "/" + tag
			tags[tag] = newTag
		}
		outbound[key] = newTag
		if i == 0 {
			firstTag = newTag
		}
	}
	for _, element := range outbounds {
		relinkDialerProxies(element, tags)
	}

	newContent, err := json.Marshal(config)
	if err != nil {
		return "", "", err
	}
	return string(newContent), firstTag, nil
}

// relinkDialerProxies points every dialerProxy in value that names an outbound of the configuration at
// that outbound's new tag. Any other dialerProxy names no outbound of the measurement either way.
func relinkDialerProxies(value any, tags map[string]string) {
	switch value := value.(type) {
	case map[string]any:
		for key, element := range value {
			if tag, ok := element.(string); ok && strings.EqualFold(key, "dialerProxy") {
				if newTag, ok := tags[tag]; ok {
					value[key] = newTag
				}
				continue
			}
			relinkDialerProxies(element, tags)
		}
	case []any:
		for _, element := range value {
			relinkDialerProxies(element, tags)
		}
	}
}

// jsonKey returns the key of object that Xray reads as name: Go matches JSON keys to fields without
// regard to case, preferring an exact match. It returns name when object has no such key.
func jsonKey(object map[string]any, name string) string {
	if _, ok := object[name]; ok {
		return name
	}
	for key := range object {
		if strings.EqualFold(key, name) {
			return key
		}
	}
	return name
}
