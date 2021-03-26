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

#include <stdlib.h>
#include <ziti/ziti.h>
#include <ziti/ziti_events.h>
#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_tunnel_cbs.h>
#include "ziti/ziti_log.h"
#include "sdk.h"

*/
import "C"
import (
	"fmt"
	"github.com/openziti/desktop-edge-win/service/ziti-tunnel/dto"
	"strings"
	"time"
	"unsafe"
)

type mfaCodes struct {
	codes       []string
	fingerprint string
	err         error
}

var emptyCodes []string
var mfaAuthResults = make(chan string)

//export ziti_aq_mfa_cb_go
func ziti_aq_mfa_cb_go(ztx C.ziti_context, mfa_ctx unsafe.Pointer, aq_mfa *C.ziti_auth_query_mfa, response_cb C.ziti_ar_mfa_cb) {
	appCtx := C.ziti_app_ctx(ztx)
	if appCtx != C.NULL {
		log.Debugf("mfa requested for ziti context %p.", ztx)
		zid := (*ZIdentity)(appCtx)
		mfa := &Mfa{
			mfaContext: mfa_ctx,
			authQuery:  aq_mfa,
			responseCb: response_cb,
		}
		zid.mfa = mfa
		zid.MfaNeeded = true
		zid.MfaEnabled = true
		log.Debugf("mfa enabled/needed set to true for ziti context [%p]. Identity name:%s [fingerprint: %s]", zid, zid.Name, zid.Fingerprint)
	} else {
		log.Debugf("mfa requested for ziti context/mfa context [%p, %p] but the context was NOT found in the map. This is unexpected. Please report.", ztx, mfa_ctx)
	}
}

func EnableMFA(id *ZIdentity) {
	C.ziti_mfa_enroll(id.czctx, C.ziti_mfa_cb(C.ziti_mfa_enroll_cb_go), unsafe.Pointer(C.CString(id.Fingerprint)))
}

//export ziti_mfa_enroll_cb_go
func ziti_mfa_enroll_cb_go(_ C.ziti_context, status C.int, enrollment *C.ziti_mfa_enrollment, cFingerprint *C.char) {
	defer C.free(unsafe.Pointer(cFingerprint))
	fp := C.GoString(cFingerprint)
	if unsafe.Pointer(enrollment) == C.NULL {
		log.Warnf("'enrollment' is null in mfa enroll cb for %s", fp)
		return
	}
	isVerified := bool(enrollment.is_verified)
	url := C.GoString(enrollment.provisioning_url)

	var m = dto.MfaEvent{
		ActionEvent:     dto.MFAEnrollmentChallengeEvent,
		Fingerprint:     fp,
		Successful:      isVerified,
		ProvisioningUrl: url,
		RecoveryCodes:   populateStringSlice(enrollment.recovery_codes),
	}
	if status != C.ZITI_OK {
		e := C.ziti_errorstr(status)
		ego := C.GoString(e)
		log.Errorf("Error encounted when enrolling mfa: %v", ego)
	} else {
		log.Infof("mfa enrollment begins for fingerprint: %s", fp)
		goapi.BroadcastEvent(m)
	}
}

func VerifyMFA(id *ZIdentity, code string) {
	ccode := C.CString(code)
	defer C.free(unsafe.Pointer(ccode))

	log.Tracef("verifying MFA for fingerprint: %s using code: %s", id.Fingerprint, code)
	C.ziti_mfa_verify(id.czctx, ccode, C.ziti_mfa_cb(C.ziti_mfa_cb_verify_go), unsafe.Pointer(C.CString(id.Fingerprint)))
}

//export ziti_mfa_cb_verify_go
func ziti_mfa_cb_verify_go(_ C.ziti_context, status C.int, cFingerprint *C.char) {
	defer C.free(unsafe.Pointer(cFingerprint))
	fp := C.GoString(cFingerprint)
	log.Debugf("ziti_mfa_cb_verify_go called for %s. status: %d for ", fp, int(status))
	var m = dto.MfaEvent{
		ActionEvent: dto.MFAEnrollmentVerificationEvent,
		Fingerprint: fp,
		Successful:  false,
		RecoveryCodes: nil,
	}

	if status != C.ZITI_OK {
		e := C.ziti_errorstr(status)
		ego := C.GoString(e)
		log.Errorf("Error encounted when verifying mfa: %v", ego)
		m.Error = ego
	} else {
		log.Infof("mfa successfully verified for fingerprint: %s", fp)
		goapi.UpdateMfa(fp, false, true)
		m.Successful = true
	}

	log.Debugf("mfa verify callback. sending ziti_mfa_verify response back to UI for %s. verified: %t. error: %s", fp, m.Successful, m.Error)
	goapi.BroadcastEvent(m)
}

var rtnCodes = make(chan mfaCodes)
func ReturnMfaCodes(id *ZIdentity, code string) ([]string, error) {
	ccode := C.CString(code)
	defer C.free(unsafe.Pointer(ccode))
	cfp := C.CString(id.Fingerprint)
	defer C.free(unsafe.Pointer(cfp))
	log.Debugf("asking for ReturnMfaCodes for fingerprint: %s with code: %s", id.Fingerprint, code)
	C.ziti_mfa_get_recovery_codes(id.czctx, ccode, C.ziti_mfa_recovery_codes_cb(C.ziti_mfa_recovery_codes_cb_return), unsafe.Pointer(cfp))

	select {
	case rtn := <-rtnCodes:
		log.Debugf("mfa codes returned ReturnMfaCodes: %s", id.Fingerprint)
		if id.Fingerprint != rtn.fingerprint {
			log.Warnf("unexpected condition correlating mfa codes returned! %s != %s", id.Fingerprint, rtn.fingerprint)
			return emptyCodes, rtn.err
		}
		return rtn.codes, rtn.err
	case <-time.After(10 * time.Second):
		return emptyCodes, fmt.Errorf("returning mfa codes has timed out")
	}
}

//export ziti_mfa_recovery_codes_cb_return
func ziti_mfa_recovery_codes_cb_return(_ C.ziti_context, status C.int, recoveryCodes **C.char, cFingerprint *C.char) {
	fp := C.GoString(cFingerprint)
	log.Debugf("ziti_mfa_recovery_codes_cb_return called with status and fingerprint: %s with status: %v", fp, status)
	var ego error
	var theCodes []string
	if status != C.ZITI_OK {
		e := C.ziti_errorstr(status)
		ego = fmt.Errorf("%s", C.GoString(e))
		log.Errorf("Error encounted when returning mfa recovery codes: %v", ego)
	} else {
		theCodes = populateStringSlice(recoveryCodes)
		ego = nil
	}
	rtnCodes <- mfaCodes{
		codes:       theCodes,
		fingerprint: fp,
		err:         ego,
	}
	log.Infof("recovery codes have been returned for fingerprint: %s", fp)
}

var genCodes = make(chan mfaCodes)
func GenerateMfaCodes(id *ZIdentity, code string) ([]string, error) {
	ccode := C.CString(code)
	defer C.free(unsafe.Pointer(ccode))
	cfp := C.CString(id.Fingerprint)
	defer C.free(unsafe.Pointer(cfp))
	log.Debugf("GenerateMfaCodes called for fingerprint: %s with code: %s", id.Fingerprint, code)
	C.ziti_mfa_new_recovery_codes(id.czctx, ccode, C.ziti_mfa_recovery_codes_cb(C.ziti_mfa_recovery_codes_cb_generate), unsafe.Pointer(cfp))
	select {
	case rtn := <-genCodes:
		log.Debugf("GenerateMfaCodes complete for fingerprint: %s", id.Fingerprint)
		if id.Fingerprint != rtn.fingerprint {
			log.Warnf("unexpected condition correlating mfa codes when regenerating! %s != %s", id.Fingerprint, rtn.fingerprint)
			return emptyCodes, rtn.err
		}
		return rtn.codes, rtn.err
	case <-time.After(10 * time.Second):
		return emptyCodes, fmt.Errorf("generating mfa codes has timed out for fingerprint: %s", id.Fingerprint)
	}
}

//export ziti_mfa_recovery_codes_cb_generate
func ziti_mfa_recovery_codes_cb_generate(_ C.ziti_context, status C.int, recoveryCodes **C.char, cFingerprint *C.char) {
	fp := C.GoString(cFingerprint)
	log.Debugf("csdk has called back for GenerateMfaCodes for fingerprint: %s with status: %v", fp, status)
	var theCodes []string
	var ego error
	if status != C.ZITI_OK {
		e := C.ziti_errorstr(status)
		ego = fmt.Errorf("%s", C.GoString(e))
		log.Errorf("Error when generating mfa recovery codes: %v", ego)
	} else {
		theCodes = populateStringSlice(recoveryCodes)
		ego = nil
	}
	genCodes <- mfaCodes{
		codes:       theCodes,
		fingerprint: fp,
		err:         ego,
	}
	log.Infof("recovery codes have been regenerated for fingerprint: %s", fp)
}

func populateStringSlice(c_char_array **C.char) []string {
	var strs []string
	i := 0
	for {
		var cstr = C.ziti_char_array_get(c_char_array, C.int(i))
		if cstr == nil {
			break
		}
		strs = append(strs, C.GoString(cstr))
		i++
	}
	return strs
}

func AuthMFA(id *ZIdentity, code string) error {
	if id.mfa == nil {
		log.Warnf("AuthMFA called but mfa is nil. This usually is because AuthMFA is called from an unenrolled MFA endpoint or the endpoint has already been auth'ed")
		return fmt.Errorf("identity has not authenticated yet")
	}
	if id.mfa.responseCb == nil {
		log.Warnf("AuthMFA called but response cb is nil. This usually is because the session is already validiated. returning true from AuthMFA")
		return nil
	}

	ccode := C.CString(code)
	defer C.free(unsafe.Pointer(ccode))

	cfp := C.CString(id.Fingerprint)
	defer C.free(unsafe.Pointer(cfp))
	log.Debugf("beginning authentication for fingerprint %s with code %s", id.Fingerprint, code)
	C.ziti_mfa_auth_request(id.mfa.responseCb, id.czctx, id.mfa.mfaContext, ccode, C.ziti_ar_mfa_status_cb(C.ziti_ar_mfa_status_cb_go), cfp)
	authResult := strings.TrimSpace(<-mfaAuthResults)

	if authResult == "" {
		id.mfa.responseCb = nil
		id.MfaNeeded = false
		return nil
	}
	return fmt.Errorf("error in authMFA: %v", authResult)
}

//export ziti_ar_mfa_status_cb_go
func ziti_ar_mfa_status_cb_go(ztx C.ziti_context, mfa_ctx unsafe.Pointer, status C.int, cFingerprint *C.char) {
	fp := C.GoString(cFingerprint)
	log.Debugf("ziti_ar_mfa_status_cb_go called for fingerprint: %s with status %v", fp, status)
	if status == C.ZITI_OK {
		log.Infof("mfa authentication succeeded for fingerprint: %s", fp)
		mfaAuthResults <- ""
	} else {
		log.Warnf("mfa authentication failed for fingerprint: %s", fp)
		e := C.ziti_errorstr(status)
		ego := C.GoString(e)
		mfaAuthResults <- ego
	}
}

func RemoveMFA(id *ZIdentity, code string) {
	ccode := C.CString(code)
	defer C.free(unsafe.Pointer(ccode))

	log.Tracef("removing MFA for fingerprint: %s using code: %s", id.Fingerprint, code)
	C.ziti_mfa_remove(id.czctx, ccode, C.ziti_mfa_cb(C.ziti_mfa_cb_remove_go), unsafe.Pointer(C.CString(id.Fingerprint))) //c string freed in callback
}

//export ziti_mfa_cb_remove_go
func ziti_mfa_cb_remove_go(_ C.ziti_context, status C.int, cFingerprint *C.char) {
	defer C.free(unsafe.Pointer(cFingerprint))
	fp := C.GoString(cFingerprint)

	log.Debugf("ziti_mfa_cb_remove_go called for %s. status: %d for ", fp, int(status))
	var m = dto.MfaEvent{
		ActionEvent: dto.MFAEnrollmentRemovedEvent,
		Fingerprint: fp,
		Successful:  false,
		RecoveryCodes: nil,
	}

	if status != C.ZITI_OK {
		e := C.ziti_errorstr(status)
		ego := C.GoString(e)
		log.Errorf("Error encounted when removing mfa: %v", ego)
		m.Error = ego
	} else {
		log.Infof("Identity with fingerprint %s has successfully removed MFA", fp)
		m.Successful = true
		goapi.UpdateMfa(fp, false, false)
	}

	log.Debugf("sending ziti_mfa_verify response back to UI for %s. verified: %t. error: %s", fp, m.Successful, m.Error)
	goapi.BroadcastEvent(m)
}