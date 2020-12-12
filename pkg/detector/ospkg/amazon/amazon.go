package amazon

import (
	"strings"

	version "github.com/knqyf263/go-deb-version"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
	"github.com/AlaskaAirlines/trivy/pkg/log"
	"github.com/AlaskaAirlines/trivy/pkg/scanner/utils"
	"github.com/AlaskaAirlines/trivy/pkg/types"
)

// Scanner to scan amazon vulnerabilities
type Scanner struct {
	l  *zap.SugaredLogger
	ac dbTypes.VulnSrc
}

// NewScanner is the factory method to return Amazon scanner
func NewScanner() *Scanner {
	return &Scanner{
		l:  log.Logger,
		ac: amazon.NewVulnSrc(),
	}
}

// Detect scans the packages using amazon scanner
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Amazon Linux vulnerabilities...")

	osVer = strings.Fields(osVer)[0]
	if osVer != "2" {
		osVer = "1"
	}
	log.Logger.Debugf("amazon: os version: %s", osVer)
	log.Logger.Debugf("amazon: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.ac.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get amazon advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		if installed == "" {
			continue
		}

		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Amazon Linux installed package version: %s", err)
			continue
		}

		for _, adv := range advisories {
			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Amazon Linux package version: %s", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
					Layer:            pkg.Layer,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks if os can be scanned using amazon scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	return true
}
