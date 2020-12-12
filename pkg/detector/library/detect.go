package library

import (
	"path/filepath"
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/AlaskaAirlines/trivy/pkg/log"
	"github.com/AlaskaAirlines/trivy/pkg/types"
)

// SuperSet binds the dependencies for library scan
var SuperSet = wire.NewSet(
	wire.Struct(new(DriverFactory)),
	wire.Bind(new(Factory), new(DriverFactory)),
	NewDetector,
	wire.Bind(new(Operation), new(Detector)),
)

// Operation defines library scan operations
type Operation interface {
	Detect(imageName string, filePath string, created time.Time, pkgs []ftypes.LibraryInfo) (vulns []types.DetectedVulnerability, err error)
}

// Detector implements driverFactory
type Detector struct {
	driverFactory Factory
}

// NewDetector is the factory method for detector
func NewDetector(factory Factory) Detector {
	return Detector{driverFactory: factory}
}

// Detect scans and returns vulnerabilities of library
func (d Detector) Detect(_, filePath string, _ time.Time, pkgs []ftypes.LibraryInfo) ([]types.DetectedVulnerability, error) {
	log.Logger.Debugf("Detecting library vulnerabilities, path: %s", filePath)
	driver, err := d.driverFactory.NewDriver(filepath.Base(filePath))
	if err != nil {
		return nil, xerrors.Errorf("failed to new driver: %w", err)
	}

	vulns, err := detect(driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(driver Driver, libs []ftypes.LibraryInfo) ([]types.DetectedVulnerability, error) {
	log.Logger.Infof("Detecting %s vulnerabilities...", driver.Type())
	var vulnerabilities []types.DetectedVulnerability
	for _, lib := range libs {
		vulns, err := driver.Detect(lib.Library.Name, lib.Library.Version)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}

		for i := range vulns {
			vulns[i].Layer = lib.Layer
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
