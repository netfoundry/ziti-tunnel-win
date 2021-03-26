/*
 * Copyright NetFoundry, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cziti

/*
#cgo LDFLAGS: -l ziti-tunnel-sdk-c -l lwipcore -l lwipwin32arch -l ziti-tunnel-sdk-c -l ziti-tunnel-cbs-c

#include <ziti/netif_driver.h>
#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_tunnel_cbs.h>
#include <ziti/ziti_log.h>
#include <uv.h>

int netifClose(netif_handle dev);
ssize_t netifRead(netif_handle dev, void *buf, size_t buf_len);
ssize_t netifWrite(netif_handle dev, void *buf, size_t len);
int netifSetup(netif_handle dev, uv_loop_t *loop, packet_cb packetCb, void* ctx);

int netifAddRoute(netif_handle dev, char* dest);


typedef struct netif_handle_s {
   const char* id;
   packet_cb on_packet_cb;
   void *packet_cb_ctx;
} netif_handle_t;

void readAsync(struct uv_async_s *a);
void readIdle(uv_prepare_t *idler);

void call_on_packet(void *packet, ssize_t len, packet_cb cb, void *ctx);
void remove_intercepts(uv_async_t *handle);
void free_async(uv_handle_t* timer);

dns_manager* get_dns_mgr_from_c();
dns_manager* dns_mgr_c;
int netifAddRoute(netif_handle dev, char* dest);
int netifRemoveRoute(netif_handle dev, char* dest);


*/
import "C"
import (
	"golang.zx2c4.com/wireguard/tun"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"unsafe"
)

type Tunnel interface {
	AddIntercept(svcId string, service string, hostname string, port int, ctx unsafe.Pointer)
}

type tunnel struct {
	dev    tun.Device
	driver C.netif_driver
	writeQ chan []byte
	readQ  chan []byte

	idleR       *C.uv_prepare_t
	read        *C.uv_async_t
	loop        *C.uv_loop_t
	onPacket    C.packet_cb
	onPacketCtx unsafe.Pointer

	tunCtx C.tunneler_context
}

//var devMap = make(map[string]*tunnel)
var theTun *tunnel

func HookupTun(dev tun.Device /*, dns []net.IP*/) error {
	log.Debug("in HookupTun ")
	defer log.Debug("exiting HookupTun")
	name, err := dev.Name()
	if err != nil {
		log.Error(err)
		return err
	}
	drv := makeDriver(name)

	log.Debug("in HookupTun2")

	t := &tunnel{
		dev:    dev,
		driver: drv,
		writeQ: make(chan []byte, 64),
		readQ:  make(chan []byte, 64),
	}

	theTun = t

	opts := (*C.tunneler_sdk_options)(C.calloc(1, C.sizeof_tunneler_sdk_options))
	opts.netif_driver = drv
	opts.ziti_dial = C.ziti_sdk_dial_cb(C.ziti_sdk_c_dial)
	opts.ziti_close = C.ziti_sdk_close_cb(C.ziti_sdk_c_close)
	opts.ziti_close_write = C.ziti_sdk_close_cb(C.ziti_sdk_c_close_write)
	opts.ziti_write = C.ziti_sdk_write_cb(C.ziti_sdk_c_write)
	opts.ziti_host = C.ziti_sdk_host_cb(C.ziti_sdk_c_host)

	t.tunCtx = C.ziti_tunneler_init(opts, _impl.libuvCtx.l)
	C.ziti_tunneler_set_dns(t.tunCtx, C.get_dns_mgr_from_c())
	return nil
}

func makeDriver(name string) C.netif_driver {
	driver := &C.netif_driver_t{}
	driver.handle = &C.netif_handle_t{}
	driver.handle.id = C.CString(name)
	driver.close = C.netif_close_cb(C.netifClose)
	driver.setup = C.setup_packet_cb(C.netifSetup)
	driver.write = C.netif_write_cb(C.netifWrite)
	driver.add_route = C.add_route_cb(C.netifAddRoute)
	driver.delete_route = C.delete_route_cb(C.netifRemoveRoute)
	return driver
}

//export netifWrite
func netifWrite(_ C.netif_handle, buf unsafe.Pointer, length C.size_t) C.ssize_t {
	b := C.GoBytes(buf, C.int(length))

	theTun.writeQ <- b

	return C.ssize_t(len(b))
}

//export netifClose
func netifClose(_ C.netif_handle) C.int {
	log.Debug("in netifClose")
	return C.int(0)
}

//export netifSetup
func netifSetup(h C.netif_handle, l *C.uv_loop_t, packetCb C.packet_cb, ctx unsafe.Pointer) C.int {

	theTun.read = (*C.uv_async_t)(C.calloc(1, C.sizeof_uv_async_t))
	C.uv_async_init(l, theTun.read, C.uv_async_cb(C.readAsync))
	theTun.read.data = unsafe.Pointer(h)
	log.Debugf("in netifSetup netif[%s] handle[%p] before", C.GoString(h.id), h)

	theTun.idleR = (*C.uv_prepare_t)(C.calloc(1, C.sizeof_uv_prepare_t))
	C.uv_prepare_init(l, theTun.idleR)
	theTun.idleR.data = unsafe.Pointer(h)
	C.uv_prepare_start(theTun.idleR, C.uv_prepare_cb(C.readIdle))
	log.Debugf("in netifSetup netif[%s] handle[%p] after", C.GoString(h.id), h)

	theTun.onPacket = packetCb
	theTun.onPacketCtx = ctx
	theTun.loop = l

	go theTun.runWriteLoop()
	go theTun.runReadLoop()

	return C.int(0)
}

func (t *tunnel) runReadLoop() {
	mtu, err := t.dev.MTU()
	if err != nil {
		log.Panicf("An unexpected and unrecoverable error has occurred while %s: %v", "getting the MTU", err)
	}
	log.Debugf("starting tun read loop mtu=%d", mtu)
	defer log.Debug("tun read loop is done")
	mtuBuf := make([]byte, mtu)
	for {
		nr, err := t.dev.Read(mtuBuf, 0)
		if err != nil {
			if err == io.EOF || err == os.ErrClosed {
				//that's fine...
				return
			}
			log.Panicf("An unexpected and unrecoverable error has occurred while %s: %v", "reading from the tun device", err)
		}

		if len(t.readQ) == cap(t.readQ) {
			log.Debug("read loop is about to block")
		}

		buf := make([]byte, nr)
		copy(buf, mtuBuf[:nr])
		t.readQ <- buf
		C.uv_async_send((*C.uv_async_t)(unsafe.Pointer(t.read)))
	}
}

//export readIdle
func readIdle(_ *C.uv_prepare_t) {
	np := len(theTun.readQ)
	for i := np; i > 0; i-- {
		b := <-theTun.readQ
		buf := C.CBytes(b)

		C.call_on_packet(buf, C.ssize_t(len(b)), theTun.onPacket, theTun.onPacketCtx)
		C.free(buf)
	}
}

//export readAsync
func readAsync(_ *C.uv_async_t) {
	// nothing to do: only needed to trigger loop into action
}

func (t *tunnel) runWriteLoop() {
	log.Debug("starting Write Loop")
	defer log.Debug("write loop finished")
	for {
		select {
		case p := <-t.writeQ:
			if p == nil {
				return
			}

			n, err := t.dev.Write(p, 0)
			if err != nil {
				log.Panicf("An unexpected and unrecoverable error has occurred while %s: %v", "writing to tun device", err)
			}

			if n < len(p) {
				log.Debug("Error short write")
			}
		}
	}
}

type RemoveWG struct {
	Wg    *sync.WaitGroup
	Czsvc *ZService
}

func RemoveIntercept(rwg *RemoveWG) {
	async := (*C.uv_async_t)(C.malloc(C.sizeof_uv_async_t))
	async.data = unsafe.Pointer(rwg)
	C.uv_async_init(_impl.libuvCtx.l, async, C.uv_async_cb(C.remove_intercepts))
	C.uv_async_send((*C.uv_async_t)(unsafe.Pointer(async)))
}

//export remove_intercepts
func remove_intercepts(async *C.uv_async_t) {
	rwg := (*RemoveWG)(async.data)
	cSvcName := C.CString(rwg.Czsvc.Name)
	defer C.free(unsafe.Pointer(cSvcName))
	C.ziti_tunneler_stop_intercepting(theTun.tunCtx, unsafe.Pointer(rwg.Czsvc.Czctx), cSvcName)
	C.uv_close((*C.uv_handle_t)(unsafe.Pointer(async)), C.uv_close_cb(C.free_async))
	rwg.Wg.Done()
}

//export apply_dns_go
func apply_dns_go(_ /*dns*/ *C.dns_manager, hostname *C.char, ip *C.char) C.int {
	ghostname := C.GoString(hostname)
	gip := C.GoString(ip)
	log.Tracef("apply_dns_go callback hostname: %s, ip: %s", ghostname, gip)
	DNSMgr.ApplyDNS(ghostname, gip)
	return 0
}

//export netifAddRoute
func netifAddRoute(_ C.netif_handle, dest *C.char) C.int {
	routeAsString := C.GoString(dest)
	if strings.Contains(routeAsString, "/") {
		log.Debugf("route appears to be in CIDR format: %s", routeAsString)
		_, cidr, e := net.ParseCIDR(routeAsString)
		if e != nil {
			log.Errorf("The provided route does not appear to follow CIDR formatting? %s", routeAsString)
			return 1
		}
		if cidr == nil {
			log.Errorf("An error occurred while parsing CIDR: %s", routeAsString)
			return 1
		}

		_ = goapi.AddRoute(*cidr, dnsip, 1)

	} else {
		log.Debugf("route appears to be an IP (not CIDR): %s", routeAsString)
		ip := net.ParseIP(routeAsString)
		if ip == nil {
			log.Errorf("An error occurred while parsing IP: %s", routeAsString)
			return 1
		}
		_ = goapi.AddRoute(net.IPNet{IP: ip, Mask: net.IPMask{255, 255, 255, 255}}, dnsip, 1)
	}
	return 0
}

//export netifRemoveRoute
func netifRemoveRoute(_ C.netif_handle, dest *C.char) C.int {
	log.Infof("i am inside netifRemoveRoute: %s", C.GoString(dest))
	return 0
}
