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

package globals

import (
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/michaelquigley/pfxlog"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"io"
	"os"
	"strings"
	"time"

	"github.com/netfoundry/ziti-tunnel-win/service/ziti-tunnel/config"
)

var Elog debug.Log
var logger *logrus.Entry

func Logger() *logrus.Entry {
	if logger == nil {
		logger = pfxlog.Logger()
	}
	return logger
}

func InitLogger(logLevel logrus.Level) {
	logrus.SetLevel(logLevel)

	rl, _ := rotatelogs.New(config.LogFile() + ".%Y%m%d%H%M",
		rotatelogs.WithRotationTime(24 * time.Hour),
		rotatelogs.WithRotationCount(7),
		rotatelogs.WithLinkName(config.LogFile()))

	multiWriter := io.MultiWriter(rl, os.Stdout)

	logrus.SetOutput(multiWriter)
	logrus.SetFormatter(pfxlog.NewFormatter())
	logger.Infof("Logger initialized. Log file located at: %s", config.LogFile())
}

func ParseLevel(lvl string) (logrus.Level, int) {
	switch strings.ToLower(lvl) {
	case "panic":
		return logrus.PanicLevel, 0
	case "fatal":
		return logrus.FatalLevel, 1
	case "error":
		return logrus.ErrorLevel, 2
	case "warn", "warning":
		return logrus.WarnLevel, 3
	case "info":
		return logrus.InfoLevel, 4
	case "debug":
		return logrus.DebugLevel, 5
	case "trace":
		return logrus.TraceLevel, 6
	default:
		logrus.Warnf("level not recognized: %s. Using Info", lvl)
		return logrus.InfoLevel, 4
	}
}

func InitEventLog(svcName string, interactive bool) {
	var err error
	if !interactive {
		Elog = debug.New(svcName)
	} else {
		Elog, err = eventlog.Open(svcName)
		if err != nil {
			return
		}
	}
}
