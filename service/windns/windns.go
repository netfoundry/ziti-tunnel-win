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

package windns

import (
	"bytes"
	"fmt"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/util/logging"
	"net"
	"os"
	"os/exec"
	"strings"
)

var log = logging.Logger()

func GetConnectionSpecificDomains() []string {
	script := `Get-DnsClient | Select-Object ConnectionSpecificSuffix -Unique | ForEach-Object { $_.ConnectionSpecificSuffix }; (Get-DnsClientGlobalSetting).SuffixSearchList`

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stdout
	output := new(bytes.Buffer)
	cmd.Stdout = output

	log.Tracef("running powershell command to get ConnectionSpecificSuffixes: %s", script)
	err := cmd.Run()

	if err != nil {
		log.Panicf("An unexpected and unrecoverable error has occurred while running the command: %s %v", script, err)
	}

	var names []string
	for {
		domain, err := output.ReadString('\n')
		if err != nil {
			break
		}
		domain = strings.TrimSpace(domain)
		if "" != domain {
			if !strings.HasSuffix(domain, ".") {
				names = append(names, domain+".")
			}
		}
	}
	return names
}

func GetUpstreamDNS() []string {
	script := `Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses } | Sort-Object | Get-Unique`

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stdout
	output := new(bytes.Buffer)
	cmd.Stdout = output

	err := cmd.Run()

	if err != nil {
		log.Panicf("An unexpected and unrecoverable error has occurred while running the command: %s %v", script, err)
	}

	var names []string
	for {
		l, err := output.ReadString('\n')
		if err != nil {
			break
		}
		addr := net.ParseIP(strings.TrimSpace(l))
		if !addr.IsLoopback() {
			names = append(names, addr.String())
		}
	}
	return names
}

func FlushDNS() {
	log.Info("flushing DNS cache using ipconfig /flushdns")
	script := `ipconfig /flushdns`

	cmd := exec.Command("cmd", "-Command", script)
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		log.Errorf("ERROR flushing DNS: %v", err)
	}
}

func RemoveAllNrptRules() {
	script := fmt.Sprintf(`Get-DnsClientNrptRule | Where { $_.Comment.StartsWith("Added by ziti-tunnel") } | Remove-DnsClientNrptRule -ErrorAction SilentlyContinue -Force`)
	log.Debugf("removing all nrpt rules with: %s", script)

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		log.Errorf("ERROR removing all nrpt rules: %v", err)
	}
}

func AddNrptRules(domainsToMap map[string]bool, dnsServer string) {
	if len(domainsToMap) == 0 {
		log.Debug("no domains to map specified to AddNrptRules. exiting early")
		return
	}
	sb := strings.Builder{}
	sb.WriteString(`$Rules = @(
`)

	for hostname := range domainsToMap {
		sb.WriteString(fmt.Sprintf(`@{ Namespace ="%s"; NameServers = @("%s"); Comment = "Added by ziti-tunnel"; DisplayName = "ziti-tunnel:%s"; }%s`, hostname, dnsServer, hostname, "\n"))
	}

	sb.WriteString(fmt.Sprintf(`)

ForEach ($Rule in $Rules) {
	Add-DnsClientNrptRule @Rule
}`))

	script := sb.String()
	log.Debugf("Executing NRPT script:\n%s", script)

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		log.Errorf("ERROR adding nrpt rules: %v", err)
	}
}

func RemoveNrptRules(domainsToMap map[string]bool) {
	if len(domainsToMap) == 0 {
		log.Debug("no domains to map specified to RemoveNrptRules. exiting early")
		return
	}

	sb := strings.Builder{}
	sb.WriteString(`$toRemove = @(
`)

	for hostname := range domainsToMap {
		sb.WriteString(fmt.Sprintf(`"%s"%s`, hostname, "\n"))
	}

	sb.WriteString(fmt.Sprintf(`)

Get-DnsClientNrptRule | Where { $toRemove -contains $_.DisplayName } | Remove-DnsClientNrptRule -ErrorAction SilentlyContinue -Force
`))

	script := sb.String()
	log.Debugf("Executing NRPT script:\n%s", script)

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		log.Errorf("ERROR removing nrpt rules: %v", err)
	}
}
