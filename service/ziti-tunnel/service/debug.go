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
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/dto"
	idcfg "github.com/openziti/sdk-golang/ziti/config"
)

func dbg() {

	r := rts.ToStatus(true)
	rts.BroadcastEvent(dto.TunnelStatusEvent{
		StatusEvent: dto.StatusEvent{Op: "status"},
		Status:      r,
		ApiVersion:  API_VERSION,
	})

	svcs := make([]*dto.Service, 2)
	svcs[0] = &dto.Service{
		Name: "FakeService1",
	}
	svcs[1] = &dto.Service{
		Name: "Second Fake Service",
	}

	rts.BroadcastEvent(dto.IdentityEvent{
		ActionEvent: dto.IDENTITY_ADDED,
		Id: dto.Identity{
			Name:        "NewIdentity",
			FingerPrint: "new_id_fingerprint",
			Active:      true,
			Config: idcfg.Config{
				ZtAPI: "http://new_id.com:2123",
			},
			Status:   STATUS_ENROLLED,
			Services: svcs,
			Metrics:  nil,
		},
	})

	rts.BroadcastEvent(dto.IdentityEvent{
		ActionEvent: dto.IDENTITY_REMOVED,
		Id: dto.Identity{
			Name:        "",
			FingerPrint: "new_id_fingerprint",
			Active:      false,
			Config:      idcfg.Config{},
			Status:      "",
			Services:    nil,
			Metrics:     nil,
		},
	})
}
