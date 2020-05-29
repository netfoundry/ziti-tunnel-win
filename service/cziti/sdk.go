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
#cgo windows LDFLAGS: -l libziti.imp -luv -lws2_32 -lpsapi

#include <ziti/ziti.h>

#include "sdk.h"
extern void initCB(ziti_context nf, int status, void *ctx);
extern void serviceCB(ziti_context nf, ziti_service*, int status, void *ctx);

*/
import "C"
import (
	"encoding/json"
	"errors"
	"github.com/michaelquigley/pfxlog"
	"os"
	"unsafe"
)

const (
	ADDED = "added"
	REMOVED = "removed"
)

var ServiceChanges = make(chan ServiceChange)
var log = pfxlog.Logger()

type sdk struct {
	libuvCtx *C.libuv_ctx
}
type ServiceChange struct {
	Operation string
	Servicename string
	Host string
	Port int
	NFContext *CZitiCtx
}

var _impl sdk

func init() {
	_impl.libuvCtx = (*C.libuv_ctx)(C.calloc(1, C.sizeof_libuv_ctx))
	C.libuv_init(_impl.libuvCtx)
}

func SetLog(f *os.File) {
	C.setLogOut(C.intptr_t(f.Fd()))
}

func SetLogLevel(level int) {
	C.setLogLevel(C.int(level))
}

func Start() {

	v := C.ziti_get_version()
	log.Infof("starting ziti-sdk-c %s(%s)[%s]", C.GoString(v.version), C.GoString(v.revision), C.GoString(v.build_date))

	_impl.run()
}

func (inst *sdk) run() {
	C.libuv_run(inst.libuvCtx)
}

func Stop() {
	C.libuv_stop(_impl.libuvCtx)
}

type Service struct {
	Name          string
	Id            string
	InterceptHost string
	InterceptPort int
}

type CZitiCtx struct {
	options   C.ziti_options
	nf        C.ziti_context
	status    int
	statusErr error

	Services *map[string]Service
}

func (c *CZitiCtx) Status() (int, error) {
	return c.status, c.statusErr
}

func (c *CZitiCtx) Name() string {
	if c.nf != nil {
		id := C.ziti_get_identity(c.nf)
		if id != nil {
			return C.GoString(id.name)
		}
	}
	return "<unknown>"
}

func (c *CZitiCtx) Controller() string {
	if c.nf != nil {
		return C.GoString(C.ziti_get_controller(c.nf))
	}
	return C.GoString(c.options.controller)
}

var tunCfgName = C.CString("ziti-tunneler-client.v1")

//export serviceCB
func serviceCB(nf C.ziti_context, service *C.ziti_service, status C.int, data unsafe.Pointer) {
	ctx := (*CZitiCtx)(data)

	if ctx.Services == nil {
		m := make(map[string]Service)
		ctx.Services = &m
	}

	name := C.GoString(service.name)
	log.Debugf("============ INSIDE serviceCB - status: %s - %v, %v, %v ============", name, status, C.ZITI_SERVICE_UNAVAILABLE, C.ZITI_OK)
	if status == C.ZITI_SERVICE_UNAVAILABLE {
		DNS.DeregisterService(ctx, name)
		delete(*ctx.Services, name)
		ServiceChanges <- ServiceChange{
			Operation:   REMOVED,
			Servicename: name,
			NFContext: ctx,
		}
	} else if status == C.ZITI_OK {
		cfg := C.ziti_service_get_raw_config(service, tunCfgName)

		host := ""
		port := -1
		if cfg != nil {
			var c map[string]interface{}

			if err := json.Unmarshal([]byte(C.GoString(cfg)), &c); err == nil {
				host = c["hostname"].(string)
				port = int(c["port"].(float64))
			}
		}
		(*ctx.Services)[name] = Service{
			Name:          name,
			Id:            C.GoString(service.id),
			InterceptHost: host,
			InterceptPort: port,
		}
		if host != "" && port != -1 {
			ip, err := DNS.RegisterService(host, uint16(port), ctx, name)
			if err != nil {
				log.Error(err)
			} else {
				log.Infof("service[%s] is mapped to <%s:%d>", name, ip.String(), port)
				for _, t := range devMap {
					t.AddIntercept(name, ip.String(), port, unsafe.Pointer(ctx.nf))
				}
				ServiceChanges <- ServiceChange{
					Operation:   ADDED,
					Servicename: name,
					Host: ip.String(),
					Port: port,
					NFContext: ctx,
				}
			}
		}
	}
}

//export initCB
func initCB(nf C.ziti_context, status C.int, data unsafe.Pointer) {
	ctx := (*CZitiCtx)(data)

	ctx.nf = nf
	ctx.options.ctx = data
	ctx.status = int(status)
	ctx.statusErr = zitiError(status)

	cfg := C.GoString(ctx.options.config)
	if ch, ok := initMap[cfg]; ok {
		ch <- ctx
	} else {
		log.Warn("response channel not found")
	}
}

var initMap = make(map[string]chan *CZitiCtx)

func zitiError(code C.int) error {
	if int(code) != 0 {
		return errors.New(C.GoString(C.ziti_errorstr(code)))
	}
	return nil
}

func LoadZiti(cfg string) *CZitiCtx {
	ctx := &CZitiCtx{}
	ctx.options.config = C.CString(cfg)
	ctx.options.init_cb = C.ziti_init_cb(C.initCB)
	ctx.options.service_cb = C.ziti_service_cb(C.serviceCB)
	//TODO don't commit this - ctx.options.refresh_interval = C.long(600)
	ctx.options.refresh_interval = C.long(15)
	ctx.options.config_types = C.all_configs
	//ctx.options.ctx = unsafe.Pointer(&ctx)

	ch := make(chan *CZitiCtx)
	initMap[cfg] = ch
	rc := C.ziti_init_opts(&ctx.options, _impl.libuvCtx.l, unsafe.Pointer(ctx))
	if rc != C.ZITI_OK {
		ctx.status, ctx.statusErr = int(rc), zitiError(rc)
		go func() {
			ch <- ctx
		}()
	}

	res := <-ch
	delete(initMap, cfg)

	return res
}

func GetTransferRates(ctx *CZitiCtx) (int64, int64, bool) { //extern void NF_get_transfer_rates(ziti_context nf, double* up, double* down);
	if ctx == nil {
		return 0, 0, false
	}
	var up, down C.double
	C.ziti_get_transfer_rates(ctx.nf, &up, &down)

	return int64(up), int64(down), true
}