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

#include "sdk.h"
#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_log.h>

void ziti_mfa_auth_request(ziti_ar_mfa_cb response_cb, ziti_context ztx, void *mfa_ctx, char *code, ziti_ar_mfa_status_cb auth_response, char *fingerprint) {
    response_cb(ztx, mfa_ctx, code, auth_response, fingerprint);
}