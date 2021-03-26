// +build windows

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
	"fmt"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/config"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/util/logging"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/util/recovery"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

type zitiService struct{}

func (m *zitiService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}
	err := config.EnsureConfigFolder()
	if err != nil {
		log.Panic("config folder not found and was not created by process!")
	}
	err = config.EnsureLogsFolder()
	if err != nil {
		log.Panic("log folder not found and was not created by process!")
	}
	control := make(chan string)
	mainLoop := make(chan struct{})
	go func() {
		defer recovery.TunnelPanic()
		err := SubMain(control, changes)
		if err != nil {
			log.Errorf("the main loop exited with an unexpected error: %v", err)
		}
		mainLoop <- struct{}{}
		requestShutdown("mainloop")
	}()
loop:
	for {
		select {
		case <-mainLoop:
			log.Debug("the main loop exited. stop listening for control commands")
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				_ = logging.Elog.Info(InterrogateEvent, "interrogate request received")
				changes <- c.CurrentStatus
			case svc.Stop:
				_ = logging.Elog.Info(StopEvent, "issuing stop")
				control <- "stop"
				_ = logging.Elog.Info(StopEvent, "stop issued")
				break loop
			case svc.Shutdown:
				_ = logging.Elog.Info(ShutdownEvent, "issuing shutdown")
				control <- "stop"
				_ = logging.Elog.Info(ShutdownEvent, "shutdown issued")
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				_ = logging.Elog.Info(PauseEvent, "request to pause service received. todo - unimplemented")
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				_ = logging.Elog.Info(ContinueEvent, "request to continue service received. todo - unimplemented")
			default:
				_ = logging.Elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}

	log.Debug("main loop exiting")
	changes <- svc.Status{State: svc.StopPending}

	log.Infof("waiting for shutdown to complete")
	<- control
	log.Infof("normal shutdown complete")
	return
}

func RunService(isDebug bool) {
	_ = logging.Elog.Info(InformationEvent, fmt.Sprintf("starting %s service", SvcStartName))
	run := svc.Run
	if isDebug {
		log.Info("debug specified. using debug.run")
		run = debug.Run
	}
	err := run(SvcStartName, &zitiService{})

	if err != nil {
		_ = logging.Elog.Error(ErrorEvent, fmt.Sprintf("%s service failed: %v", SvcStartName, err))
		return
	}
	_ = logging.Elog.Info(StopEvent, fmt.Sprintf("%s service stopped", SvcStartName))
}
