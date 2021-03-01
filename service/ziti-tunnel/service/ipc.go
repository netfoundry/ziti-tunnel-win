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

package service

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/openziti/desktop-edge-win/service/cziti"
	"github.com/openziti/desktop-edge-win/service/windns"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/config"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/constants"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/dto"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/util/logging"
	"github.com/openziti/foundation/identity/identity"
	idcfg "github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"golang.org/x/sys/windows/svc"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

type Pipes struct {
	ipc    net.Listener
	logs   net.Listener
	events net.Listener
}

func (p *Pipes) Close() {
	_ = p.ipc.Close()
	_ = p.logs.Close()
	_ = p.events.Close()
}

var shutdown = make(chan bool, 8) //a channel informing go routines to exit

func SubMain(ops chan string, changes chan<- svc.Status) error {
	log.Info("============================== service begins ==============================")
	windns.RemoveAllNrptRules()

	rts.LoadConfig()
	l := rts.state.LogLevel
	parsedLevel, cLogLevel := logging.ParseLevel(l)

	rts.state.LogLevel = parsedLevel.String()
	logging.InitLogger(parsedLevel)

	_ = logging.Elog.Info(InformationEvent, SvcName+" starting. log file located at "+config.LogFile())

	// create a channel for notifying any connections that they are to be interrupted
	interrupt = make(chan struct{}, 8)

	// a channel to signal the handleEvents that initialization is complete
	initialized := make(chan struct{})

	// initialize the network interface
	err := initialize(cLogLevel)
	if err != nil {
		log.Panicf("unexpected err from initialize: %v", err)
		return err
	}

	setTunnelState(true)

	go handleEvents(initialized)

	//listen for services that show up
	go acceptServices()

	// open the pipe for business
	pipes, err := openPipes()
	if err != nil {
		return err
	}
	defer pipes.Close()

	// notify the service is running
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	_ = logging.Elog.Info(InformationEvent, SvcName+" status set to running")
	log.Info(SvcName + " status set to running. starting cancel loop")

	rts.SaveState() //if we get this far it means things seem to be working. backup the config

	//indicate the metrics handler can begin
	initialized <- struct{}{}

	waitForStopRequest(ops)

	log.Debug("shutting down. start a ZitiDump")
	for _, id := range rts.ids {
		if id.CId != nil {
			sb := strings.Builder{}
			cziti.ZitiDumpOnShutdown(id.CId, &sb)
			log.Infof("working around the c sdk's limitation of embedding newlines on calling ziti_shutdown\n %s", sb.String())
		}
	}
	log.Debug("shutting down. ZitiDump complete")

	requestShutdown("service shutdown")

	// signal to any connected consumers that the service is shutting down normally
	events.broadcast <- dto.StatusEvent{
		Op: "shutdown",
	}

	// wait 1 second for the shutdown to send to clients
	shutdownDelay := make(chan bool)
	go func() {
		time.Sleep(1 * time.Second)
		shutdownDelay <- true
	}()
	<-shutdownDelay

	log.Infof("shutting down connections...")
	pipes.shutdownConnections()

	log.Infof("shutting down events...")
	events.shutdown()

	windns.RemoveAllNrptRules()

	log.Infof("Removing existing interface: %s", TunName)
	wt, err := tun.WintunPool.OpenAdapter(TunName)
	if err == nil {
		// If so, we delete it, in case it has weird residual configuration.
		_, err = wt.Delete(true)
		if err != nil {
			log.Errorf("Error deleting already existing interface: %v", err)
		}
	} else {
		log.Errorf("INTERFACE %s was nil? %v", TunName, err)
	}

	rts.Close()

	log.Info("==============================  service ends  ==============================")

	ops <- "done"
	return nil
}

func requestShutdown(requester string) {
	log.Infof("shutdown requested by %v", requester)
	shutdown <- true // stops the metrics ticker
	shutdown <- true // stops the service change listener
}

func waitForStopRequest(ops <-chan string) {
	sig := make(chan os.Signal)
	signal.Notify(sig)
loop:
	for {
		select {
		case c := <-ops:
			log.Infof("request for control received: %v", c)
			if c == "stop" {
				break loop
			} else {
				log.Debug("unexpected operation: " + c)
			}
		case s := <-sig:
			log.Warnf("signal received! %v", s)
		}
	}
	log.Debugf("wait loop is exiting")
}

func openPipes() (*Pipes, error) {
	// create the ACE string representing the following groups have access to the pipes created
	grps := []string{InteractivelyLoggedInUser, System, BuiltinAdmins, LocalService}
	auth := "D:" + strings.Join(grps, "")

	// create the pipes
	pc := winio.PipeConfig{
		SecurityDescriptor: auth,
		MessageMode:        false,
		InputBufferSize:    1024,
		OutputBufferSize:   1024,
	}
	logs, err := winio.ListenPipe(logsPipeName(), &pc)
	if err != nil {
		return nil, err
	}
	ipc, err := winio.ListenPipe(IpcPipeName(), &pc)
	if err != nil {
		return nil, err
	}
	events, err := winio.ListenPipe(eventsPipeName(), &pc)
	if err != nil {
		return nil, err
	}

	// listen for log requests
	go accept(logs, serveLogs, "  logs")
	log.Debugf("log listener ready. pipe: %s", logsPipeName())

	// listen for ipc messages
	go accept(ipc, serveIpc, "   ipc")
	log.Debugf("ipc listener ready pipe: %s", IpcPipeName())

	// listen for events messages
	go accept(events, serveEvents, "events")
	log.Debugf("events listener ready pipe: %s", eventsPipeName())

	return &Pipes{
		ipc:    ipc,
		logs:   logs,
		events: events,
	}, nil
}

func (p *Pipes) shutdownConnections() {
	log.Info("waiting for all connections to close...")
	p.Close()

	for i := 0; i < ipcConnections; i++ {
		log.Debug("cancelling ipc read loop...")
		interrupt <- struct{}{}
	}
	log.Info("waiting for all ipc connections to close...")
	ipcWg.Wait()
	log.Info("all ipc connections closed")

	for i := 0; i < eventsConnections; i++ {
		log.Debug("cancelling events read loop...")
		interrupt <- struct{}{}
	}
	log.Info("waiting for all events connections to close...")
	eventsWg.Wait()
	log.Info("all events connections closed")
}

func initialize(cLogLevel int) error {
	assignedIp, t, err := rts.CreateTun(rts.state.TunIpv4, rts.state.TunIpv4Mask)
	if err != nil {
		return err
	}

	cziti.DnsInit(rts, rts.state.TunIpv4, rts.state.TunIpv4Mask)
	cziti.Start(cLogLevel)
	err = cziti.HookupTun(*t)
	if err != nil {
		log.Panicf("An unrecoverable error has occurred! %v", err)
	}

	setTunInfo(rts.state)

	rts.state.Active = true
	for _, id := range rts.state.Identities {
		if id != nil {
			i := &Id{
				Identity: *id,
				CId:      nil,
			}
			rts.ids[id.FingerPrint] = i
		} else {
			log.Warnf("identity was nil?")
		}
	}
	dnsReady := make(chan bool)
	go cziti.RunDNSserver([]net.IP{assignedIp}, dnsReady)
	<-dnsReady
	log.Debugf("initial state loaded from configuration file")
	return nil
}

func setTunInfo(s *dto.TunnelStatus) {
	ipv4 := rts.state.TunIpv4
	ipv4mask := rts.state.TunIpv4Mask

	if strings.TrimSpace(ipv4) == "" {
		ipv4 = constants.Ipv4ip
		log.Infof("ip not provided using default: %v", ipv4)
		rts.UpdateIpv4(ipv4)
	}
	if ipv4mask < constants.Ipv4MaxMask || ipv4mask > constants.Ipv4MinMask {
		log.Warnf("provided mask is invalid: %d. using default value: %d", ipv4mask, constants.Ipv4DefaultMask)
		ipv4mask = constants.Ipv4DefaultMask
		rts.UpdateIpv4Mask(ipv4mask)
	}
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipv4, ipv4mask))
	if err != nil {
		log.Errorf("error parsing CIDR block: (%v)", err)
		return
	}

	t := *rts.tun
	mtu, err := t.MTU()
	if err != nil {
		log.Errorf("error reading MTU - using 0 for MTU: (%v)", err)
		mtu = 0
	}
	umtu := uint16(mtu)
	//set the tun info into the state
	s.IpInfo = &dto.TunIpInfo{
		Ip:     ipv4,
		DNS:    ipv4,
		MTU:    umtu,
		Subnet: ipv4MaskString(ipnet.Mask),
	}
}

func ipv4MaskString(m []byte) string {
	if len(m) != 4 {
		log.Panicf("An unexpected and unrecoverable error has occurred. ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func closeConn(conn net.Conn) {
	err := conn.Close()
	if err != nil {
		log.Warnf("abnormal error while closing connection. %v", err)
	}
}

func accept(p net.Listener, serveFunction func(net.Conn), debug string) {
	for {
		c, err := p.Accept()
		if err != nil {
			if err != winio.ErrPipeListenerClosed {
				log.Errorf("%v unexpected error while accepting a connection. exiting loop. %v", debug, err)
			}
			return
		}

		go serveFunction(c)
	}
}

func serveIpc(conn net.Conn) {
	log.Debug("beginning ipc receive loop")
	defer log.Info("a connected IPC client has disconnected")
	defer closeConn(conn) //close the connection after this function invoked as go routine exits

	done := make(chan struct{}, 8)
	defer close(done) // ensure that goroutine exits

	ipcWg.Add(1)
	ipcConnections++
	defer func() {
		log.Debugf("serveIpc is exiting. total connection count now: %d", ipcConnections)
		ipcWg.Done()
		ipcConnections--
		log.Debugf("serveIpc is exiting. total connection count now: %d", ipcConnections)
	}() // count down whenever the function exits
	log.Debugf("accepting a new client for serveIpc. total connection count: %d", ipcConnections)

	go func() {
		select {
		case <-interrupt:
			log.Info("request to interrupt read loop received")
			_ = conn.Close()
			log.Info("read loop interrupted")
		case <-done:
			log.Debug("loop finished normally")
		}
	}()

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)
	rw := bufio.NewReadWriter(reader, writer)
	enc := json.NewEncoder(writer)

	for {
		log.Debug("ipc read begins")
		msg, err := reader.ReadString('\n')
		log.Debug("ipc read ends")
		if err != nil {
			if err != winio.ErrFileClosed {
				if err == io.EOF {
					log.Debug("pipe closed. client likely disconnected")
				} else {
					log.Errorf("unexpected error while reading line. %v", err)

					//try to respond... likely won't work but try...
					respondWithError(enc, "could not read line properly! exiting loop!", UNKNOWN_ERROR, err)
				}
			}
			log.Debugf("connection closed due to shutdown request for ipc: %v", err)
			return
		}

		log.Debugf("msg received: %s", msg)

		if strings.TrimSpace(msg) == "" {
			// empty message. ignore it and read again
			log.Debug("empty line received. ignoring")
			continue
		}

		dec := json.NewDecoder(strings.NewReader(msg))
		var cmd dto.CommandMsg
		if err := dec.Decode(&cmd); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		switch cmd.Function {
		case "AddIdentity":
			addIdMsg, err := reader.ReadString('\n')
			if err != nil {
				respondWithError(enc, "could not read string properly", UNKNOWN_ERROR, err)
				return
			}
			log.Debugf("msg received: %s", addIdMsg)
			addIdDec := json.NewDecoder(strings.NewReader(addIdMsg))

			var newId dto.AddIdentity
			if err := addIdDec.Decode(&newId); err == io.EOF {
				break
			} else if err != nil {
				log.Fatal(err)
			}
			newIdentity(newId, enc)
		case "RemoveIdentity":
			log.Debugf("Request received to remove an identity")
			removeIdentity(enc, cmd.Payload["Fingerprint"].(string))
		case "Status":
			reportStatus(enc)
		case "TunnelState":
			onOff := cmd.Payload["OnOff"].(bool)
			tunnelState(onOff, enc)
		case "IdentityOnOff":
			onOff := cmd.Payload["OnOff"].(bool)
			fingerprint := cmd.Payload["Fingerprint"].(string)
			toggleIdentity(enc, fingerprint, onOff)
		case "SetLogLevel":
			setLogLevel(enc, cmd.Payload["Level"].(string))
		case "ZitiDump":
			log.Debug("request to ZitiDump received")
			for _, id := range rts.ids {
				if id.CId != nil {
					cziti.ZitiDump(id.CId, fmt.Sprintf(`%s\%s.ziti.txt`, config.LogsPath(), id.Name))
				}
			}
			log.Debug("request to ZitiDump complete")
			respond(enc, dto.Response{Message: "ZitiDump complete", Code: SUCCESS, Error: "", Payload: nil})
		case "Debug":
			dbg()
			respond(enc, dto.Response{
				Code:    0,
				Message: "debug",
				Error:   "debug",
				Payload: nil,
			})
		default:
			log.Warnf("Unknown operation: %s. Returning error on pipe", cmd.Function)
			respondWithError(enc, "Something unexpected has happened", UNKNOWN_ERROR, nil)
		}

		//save the state
		rts.SaveState()

		_ = rw.Flush()
	}
}

func setLogLevel(out *json.Encoder, level string) {
	goLevel, cLevel := logging.ParseLevel(level)
	log.Infof("Setting logger levels to %s", goLevel)
	logging.SetLoggingLevel(goLevel)
	cziti.SetLogLevel(cLevel)
	rts.state.LogLevel = goLevel.String()
	respond(out, dto.Response{Message: "log level set", Code: SUCCESS, Error: "", Payload: nil})
}

func serveLogs(conn net.Conn) {
	log.Debug("accepted a logs connection, writing logs to pipe")
	w := bufio.NewWriter(conn)

	file, err := os.OpenFile(config.LogFile(), os.O_RDONLY, 0644)
	if err != nil {
		log.Errorf("could not open log file at %s", config.LogFile())
		_, _ = w.WriteString("an unexpected error occurred while retrieving logs. look at the actual log file.")
		return
	}
	writeLogToStream(file, w)

	err = conn.Close()
	if err != nil {
		log.Error("error closing connection", err)
	}
}

func writeLogToStream(file *os.File, writer *bufio.Writer) {
	r := bufio.NewReader(file)
	wrote, err := io.Copy(writer, r)
	if err != nil {
		log.Errorf("problem responding with log data for: %v", file)
	}
	_, err = writer.Write([]byte("end of logs\n"))
	if err != nil {
		log.Errorf("unexpected error writing log response: %v", err)
	}

	err = writer.Flush()
	if err != nil {
		log.Errorf("unexpected error flushing log response: %v", err)
	}
	log.Debugf("wrote %d bytes to client from logs", wrote)

	err = file.Close()
	if err != nil {
		log.Error("error closing log file", err)
	}
}

func serveEvents(conn net.Conn) {
	randomInt := rand.Int()
	log.Debug("accepted an events connection, writing events to pipe")
	defer closeConn(conn) //close the connection after this function invoked as go routine exits

	eventsWg.Add(1)
	eventsConnections++
	defer func() {
		log.Debugf("serveEvents is exiting. total connection count now: %d", eventsConnections)
		eventsWg.Done()
		eventsConnections--
		log.Debugf("serveEvents is exiting. total connection count now: %d", eventsConnections)
	}() // count down whenever the function exits
	log.Debugf("accepting a new client for serveEvents. total connection count: %d", eventsConnections)

	consumer := make(chan interface{}, 8)
	events.register(randomInt, consumer)
	defer events.unregister(randomInt)

	w := bufio.NewWriter(conn)
	o := json.NewEncoder(w)

	log.Info("new event client connected - sending current status")
	err := o.Encode(dto.TunnelStatusEvent{
		StatusEvent: dto.StatusEvent{Op: "status"},
		Status:      rts.ToStatus(true),
		ApiVersion:  API_VERSION,
	})

	if err != nil {
		log.Errorf("could not send status to event client: %v", err)
	} else {
		log.Info("status sent. listening for new events")
	}

loop:
	for {
		select {
		case msg := <-consumer:
			err := o.Encode(msg)
			if err != nil {
				log.Debugf("exiting from serveEvents - %v", err)
				break loop
			}
			_ = w.Flush()
		case <-interrupt:
			break loop
		}
	}
	log.Info("a connected event client has disconnected")
}

func reportStatus(out *json.Encoder) {
	s := rts.ToStatus(true)
	respond(out, dto.ZitiTunnelStatus{
		Status:  &s,
		Metrics: nil,
	})
	log.Debugf("request for status responded to")
}

func tunnelState(onOff bool, out *json.Encoder) {
	log.Debugf("toggle ziti on/off: %t", onOff)
	state := rts.state
	if onOff == state.Active {
		log.Debugf("nothing to do. the state of the tunnel already matches the requested state: %t", onOff)
		respond(out, dto.Response{Message: fmt.Sprintf("noop: tunnel state already set to %t", onOff), Code: SUCCESS, Error: "", Payload: nil})
		return
	}
	setTunnelState(onOff)
	state.Active = onOff

	respond(out, dto.Response{Message: "tunnel state updated successfully", Code: SUCCESS, Error: "", Payload: nil})
	log.Debugf("toggle ziti on/off: %t responded to", onOff)
}

func setTunnelState(onOff bool) {
	if onOff {
		TunStarted = time.Now()

		for _, id := range rts.ids {
			connectIdentity(id)
		}
	} else {
		// state.Close()
	}
}

func toggleIdentity(out *json.Encoder, fingerprint string, onOff bool) {
	log.Debugf("toggle ziti on/off for %s: %t", fingerprint, onOff)

	id := rts.Find(fingerprint)

	if id == nil {
		msg := fmt.Sprintf("identity with fingerprint %s not found", fingerprint)
		log.Warn(msg)
		respond(out, dto.Response{
			Code:    SUCCESS,
			Message: fmt.Sprintf("no update performed. %s", msg),
			Error:   "",
			Payload: nil,
		})
	} else if id.Active == onOff {
		log.Debugf("nothing to do - the provided identity %s is already set to active=%t", id.Name, id.Active)
		//nothing to do...
		respond(out, dto.Response{
			Code:    SUCCESS,
			Message: fmt.Sprintf("no update performed. identity is already set to active=%t", onOff),
			Error:   "",
			Payload: nil,
		})
	} else {
		if onOff {
			connectIdentity(id)
		} else {
			err := disconnectIdentity(id)
			if err != nil {
				log.Warnf("could not disconnect identity: %v", err)
			}
		}
		id.Active = onOff
		rts.SaveState()
		respond(out, dto.Response{Message: "identity toggled", Code: SUCCESS, Error: "", Payload: Clean(id)})
	}

	log.Debugf("toggle ziti on/off for %s: %t responded to", fingerprint, onOff)
}

func removeTempFile(file os.File) {
	err := os.Remove(file.Name()) // clean up
	if err != nil {
		log.Warnf("could not remove temp file: %s", file.Name())
	}
	err = file.Close()
	if err != nil {
		log.Warnf("could not close the temp file: %s", file.Name())
	}
}

func newIdentity(newId dto.AddIdentity, out *json.Encoder) {
	log.Debugf("new identity for %s: %s", newId.Id.Name, newId.EnrollmentFlags.JwtString)

	tokenStr := newId.EnrollmentFlags.JwtString
	log.Debugf("jwt to parse: %s", tokenStr)
	tkn, _, err := enroll.ParseToken(tokenStr)

	if err != nil {
		respondWithError(out, "failed to parse JWT: %s", COULD_NOT_ENROLL, err)
		return
	}
	var certPath = ""
	var keyPath = ""
	var caOverride = ""

	flags := enroll.EnrollmentFlags{
		CertFile:      certPath,
		KeyFile:       keyPath,
		KeyAlg:        "EC",
		Token:         tkn,
		IDName:        newId.Id.Name,
		AdditionalCAs: caOverride,
	}

	//enroll identity using the file and go sdk
	conf, err := enroll.Enroll(flags)
	if err != nil {
		respondWithError(out, "failed to enroll", COULD_NOT_ENROLL, err)
		return
	}

	enrolled, err := ioutil.TempFile("" /*temp dir*/, "ziti-enrollment-*")
	if err != nil {
		respondWithError(out, "Could not create temporary file in local storage. This is abnormal. "+
			"Check the process has access to the temporary folder", COULD_NOT_WRITE_FILE, err)
		return
	}

	enc := json.NewEncoder(enrolled)
	enc.SetEscapeHTML(false)
	encErr := enc.Encode(&conf)

	outpath := enrolled.Name()
	if encErr != nil {
		respondWithError(out, fmt.Sprintf("enrollment successful but the identity file was not able to be written to: %s [%s]", outpath, encErr), COULD_NOT_ENROLL, err)
		return
	}

	sdkId, err := identity.LoadIdentity(conf.ID)
	if err != nil {
		respondWithError(out, "unable to load identity which was just created. this is abnormal", COULD_NOT_ENROLL, err)
		return
	}

	//map fields onto new identity
	newId.Id.Config.ZtAPI = conf.ZtAPI
	newId.Id.Config.ID = conf.ID
	newId.Id.FingerPrint = fmt.Sprintf("%x", sha1.Sum(sdkId.Cert().Leaf.Raw)) //generate fingerprint
	if newId.Id.Name == "" {
		newId.Id.Name = newId.Id.FingerPrint
	}
	newId.Id.Status = STATUS_ENROLLED

	err = enrolled.Close()
	if err != nil {
		log.Panicf("An unexpected and unrecoverable error has occurred while %s: %v", "enrolling an identity", err)
	}
	newPath := newId.Id.Path()

	//move the temp file to its final home after enrollment
	err = os.Rename(enrolled.Name(), newPath)
	if err != nil {
		log.Errorf("unexpected issue renaming the enrollment! attempting to remove the temporary file at: %s", enrolled.Name())
		removeTempFile(*enrolled)
		respondWithError(out, "a problem occurred while writing the identity file.", COULD_NOT_ENROLL, err)
	}

	//newId.Id.Active = false //set to false by default - enable the id after persisting
	log.Infof("enrolled successfully. identity file written to: %s", newPath)

	id := &Id{
		Identity: dto.Identity{
			FingerPrint: newId.Id.FingerPrint,
		},
	}

	rts.ids[id.FingerPrint] = id

	connectIdentity(id)

	state := rts.state
	//if successful parse the output and add the config to the identity
	state.Identities = append(state.Identities, &newId.Id)

	//return successful message
	resp := dto.Response{Message: "success", Code: SUCCESS, Error: "", Payload: Clean(id)}

	respond(out, resp)
	log.Debugf("new identity for %s responded to", newId.Id.Name)
}

func respondWithError(out *json.Encoder, msg string, code int, err error) {
	if err != nil {
		respond(out, dto.Response{Message: msg, Code: code, Error: err.Error()})
	} else {
		respond(out, dto.Response{Message: msg, Code: code, Error: ""})
	}
	log.Debugf("responded with error: %s, %d, %v", msg, code, err)
}

func connectIdentity(id *Id) {
	log.Infof("connecting identity: %s[%s]", id.Name, id.FingerPrint)

	if id.CId == nil || !id.CId.Loaded {
		rts.LoadIdentity(id, DEFAULT_REFRESH_INTERVAL)
	} else {
		log.Debugf("%s[%s] is already loaded", id.Name, id.FingerPrint)

		id.CId.Services.Range(func(key interface{}, value interface{}) bool {
			id.Services = append(id.Services, nil)
			return true
		})

		events.broadcast <- dto.IdentityEvent{
			ActionEvent: IDENTITY_ADDED,
			Id:          id.Identity,
		}
		log.Infof("connecting identity completed: %s[%s]", id.Name, id.FingerPrint)
	}
}

func disconnectIdentity(id *Id) error {
	log.Infof("disconnecting identity: %s", id.Name)

	if id.Active {
		if id.CId == nil {
			return fmt.Errorf("identity has not been initialized properly. please consult the logs for details")
		} else {
			log.Debugf("ranging over services all services to remove intercept and deregister the service")

			id.CId.Services.Range(func(key interface{}, value interface{}) bool {
				val := value.(*cziti.ZService)
				var wg sync.WaitGroup
				wg.Add(1)
				rwg := &cziti.RemoveWG{
					Wg:    &wg,
					Czsvc: val,
				}
				cziti.RemoveIntercept(rwg)
				wg.Wait()
				return true
			})
			log.Infof("disconnecting identity complete: %s", id.Name)
		}
	} else {
		log.Debugf("id: %s is already disconnected - not attempting to disconnected again fingerprint:%s", id.Name, id.FingerPrint)
	}

	id.Active = false
	return nil
}

func removeIdentity(out *json.Encoder, fingerprint string) {
	log.Infof("request to remove identity by fingerprint: %s", fingerprint)
	id := rts.Find(fingerprint)
	if id == nil {
		respondWithError(out, fmt.Sprintf("Could not find identity by fingerprint: %s", fingerprint), IDENTITY_NOT_FOUND, nil)
		return
	}

	anyErrs := ""
	err := disconnectIdentity(id)
	if err != nil {
		anyErrs = err.Error()
		log.Errorf("error when disconnecting identity: %s, %v", fingerprint, err)
	}

	rts.RemoveByFingerprint(fingerprint)

	//remove the file from the filesystem - first verify it's the proper file
	log.Debugf("removing identity file for fingerprint %s at %s", id.FingerPrint, id.Path())
	err = os.Remove(id.Path())
	if err != nil {
		log.Warnf("could not remove file: %s", id.Path())
	} else {
		log.Debugf("identity file removed: %s", id.Path())
	}

	resp := dto.Response{Message: "success", Code: SUCCESS, Error: anyErrs, Payload: nil}
	respond(out, resp)
	// call shutdown some day id.CId.Shutdown()
	log.Infof("request to remove identity by fingerprint: %s responded to", fingerprint)
}

func respond(out *json.Encoder, thing interface{}) {
	//leave for debugging j := json.NewEncoder(os.Stdout)
	//leave for debugging j.Encode(thing)
	_ = out.Encode(thing)
}

func pipeName(path string) string {
	if !Debug {
		return pipeBase + path
	} else {
		return pipeBase /*+ `debug\`*/ + path
	}
}

func IpcPipeName() string {
	return pipeName("ipc")
}

func logsPipeName() string {
	return pipeName("logs")
}

func eventsPipeName() string {
	return pipeName("events")
}

func acceptServices() {
	for {
		select {
		case <-shutdown:
			return
		case serviceChange := <-cziti.ServiceChanges:
			log.Debugf("processing service change event. id:%s name:%s", serviceChange.Service.Id, serviceChange.Service.Name)
			change := dto.ServiceEvent(serviceChange)
			events.broadcast <- change
			log.Debugf("dispatched %s service change event", serviceChange.Op)
		}
	}
}

func handleEvents(isInitialized chan struct{}) {
	events.run()
	d := 5 * time.Second
	every5s := time.NewTicker(d)

	defer log.Debugf("exiting handleEvents. loops were set for %v", d)
	<-isInitialized
	log.Info("beginning metric collection")
	for {
		select {
		case <-shutdown:
			return
		case <-every5s.C:
			s := rts.ToMetrics()

			events.broadcast <- dto.MetricsEvent{
				StatusEvent: dto.StatusEvent{Op: "metrics"},
				Identities:  s.Identities,
			}
		}
	}
}

//Removes the Config from the provided identity and returns a 'cleaned' id
func Clean(src *Id) dto.Identity {
	log.Tracef("cleaning identity: %s", src.Name)
	AddMetrics(src)
	nid := dto.Identity{
		Name:              src.Name,
		FingerPrint:       src.FingerPrint,
		Active:            src.Active,
		Config:            idcfg.Config{},
		ControllerVersion: src.ControllerVersion,
		Status:            "",
		Services:          make([]*dto.Service, 0),
		Metrics:           src.Metrics,
		Tags:              nil,
	}

	if src.CId != nil {
		src.CId.Services.Range(func(key interface{}, value interface{}) bool {
			//string, ZService
			val := value.(*cziti.ZService)
			nid.Services = append(nid.Services, /*svcToDto(val)*/val.Service)
			return true
		})
	}

	nid.Config.ZtAPI = src.Config.ZtAPI
	log.Tracef("Up: %v Down %v", nid.Metrics.Up, nid.Metrics.Down)
	return nid
}

func AddMetrics(id *Id) {
	if id == nil || id.CId == nil {
		return
	}
	id.Metrics = &dto.Metrics{}
	up, down, _ := id.CId.GetMetrics()

	id.Metrics.Up = up
	id.Metrics.Down = down
}

func svcToDto(src cziti.ZService) *dto.Service {
	dest := &dto.Service{
		Name:          src.Name,
		Id:            src.Id,
		OwnsIntercept: false,
	}
	if src.Service != nil {
		dest.Protocols = src.Service.Protocols
		dest.Addresses = src.Service.Addresses
		dest.Ports = src.Service.Ports
	}
	return dest
}
