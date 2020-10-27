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

import (
	"bytes"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"net"
	"os"
	"os/exec"
	"strings"
)

var log = pfxlog.Logger()

func ResetDNS() {
	log.Info("resetting dns to original-ish state")

	script := `Get-NetIPInterface | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }`

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		log.Errorf("ERROR resetting DNS: %v", err)
	}
}

func GetConnectionSpecificDomains() []string {
	script := `Get-DnsClient | Select-Object ConnectionSpecificSuffix -Unique | ForEach-Object { $_.ConnectionSpecificSuffix }`

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


func ReplaceDNS(ips []net.IP) {
	ipsStrArr := make([]string, len(ips))
	for i, ip := range ips {
		ipsStrArr[i] = fmt.Sprintf("'%s'", ip.String())
	}
	ipsAsString := strings.Join(ipsStrArr, ",")

	script := fmt.Sprintf(`$dnsinfo=Get-DnsClientServerAddress
$dnsIps=@(%s)

# see https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.addressfamily
$IPv4=2
$IPv6=23

$dnsPerInterface = @{}

foreach ($dns in $dnsinfo)
{
    if($dnsPerInterface[$dns.InterfaceIndex] -eq $null) { $dnsPerInterface[$dns.InterfaceIndex]=[System.Collections.ArrayList]@() }
    
    $dnsServers=$dns.ServerAddresses
    $ArrList=[System.Collections.ArrayList]@($dnsServers)
    foreach ($dnsIp in $dnsIps)
    {
        if(($dnsServers -ne $null) -and ($ArrList.Contains($dnsIp)) ) {
            # uncomment when debugging echo ($dns.InterfaceAlias + " IPv4 already contains ${dnsIp}")
        } else {
            $ArrList.Insert(0, $dnsIp)
        }
    }
    $dnsPerInterface[$dns.InterfaceIndex].AddRange($ArrList)
}

foreach ($key in $dnsPerInterface.Keys)
{
    $dnsServers=$dnsPerInterface[$key]
    Set-DnsClientServerAddress -InterfaceIndex $key -ServerAddresses ($dnsServers)
}`, ipsAsString)

	cmd := exec.Command("powershell", "-Command", script)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	if err := cmd.Run(); err != nil {
		log.Errorf("ERROR resetting DNS (%v)", err)
	}
}
