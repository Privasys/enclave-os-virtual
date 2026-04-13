package ratls

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"

	"github.com/google/go-tdx-guest/client"
	"go.uber.org/zap"
)

func init() {
	RegisterAttester("tdx", func() Attester { return new(TDXAttester) })
}

// oidTDXQuote is the X.509 extension OID for an Intel SGX/TDX attestation
// quote: 1.2.840.113741.1.5.5.1.6
var oidTDXQuote = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 5, 5, 1, 6}

// tsmReportPath is the Linux configfs-tsm report directory. Its presence
// indicates that the kernel's TSM (Trusted Security Module) subsystem is
// loaded and TDX attestation is available.
const tsmReportPath = "/sys/kernel/config/tsm/report"

// TDXAttester implements Attester for Intel TDX Confidential VMs using the
// Linux configfs-tsm interface.
type TDXAttester struct {
	quoteProvider *client.LinuxConfigFsQuoteProvider
}

// Name returns "tdx".
func (a *TDXAttester) Name() string { return "tdx" }

// Provision checks for /sys/kernel/config/tsm/report, initialises the
// configfs-tsm quote provider, and verifies that it is supported.
func (a *TDXAttester) Provision(logger *zap.Logger) error {
	if _, err := os.Stat(tsmReportPath); err != nil {
		return fmt.Errorf("configfs-tsm report path %q is not accessible: %w "+
			"— ensure this host is a TDX Confidential VM with TSM support", tsmReportPath, err)
	}

	qp, err := client.GetQuoteProvider()
	if err != nil {
		return fmt.Errorf("failed to initialise configfs-tsm quote provider: %w", err)
	}
	if err := qp.IsSupported(); err != nil {
		return fmt.Errorf("configfs-tsm quote provider reports unsupported: %w", err)
	}
	a.quoteProvider = qp

	logger.Info("TDX attester provisioned",
		zap.String("tsm_report_path", tsmReportPath))
	return nil
}

// Quote obtains a TDX attestation quote via configfs-tsm for the given
// 64-byte report data.
func (a *TDXAttester) Quote(reportData [64]byte) ([]byte, error) {
	rawQuote, err := a.quoteProvider.GetRawQuote(reportData)
	if err != nil {
		return nil, fmt.Errorf("TDX quote generation failed: %w", err)
	}
	return rawQuote, nil
}

// CertExtension returns a non-critical X.509 extension with the TDX quote
// under OID 1.2.840.113741.1.5.5.1.6.
func (a *TDXAttester) CertExtension(quote []byte) pkix.Extension {
	return pkix.Extension{
		Id:       oidTDXQuote,
		Critical: false,
		Value:    quote,
	}
}

// Interface guard.
var _ Attester = (*TDXAttester)(nil)
