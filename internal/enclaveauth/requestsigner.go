// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package enclaveauth

import "net/http"

// RequestSigner attaches attested enclave auth to a control-plane request.
// Clients take this interface so they can be built without a signer (a fleet
// mid-migration, or a test) and simply send the bearer instead.
type RequestSigner interface {
	Sign(req *http.Request, body []byte) error
}
