package artifact

import (
	"context"
	l "log"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/AlaskaAirlines/trivy/internal/artifact/config"
	"github.com/AlaskaAirlines/trivy/internal/operation"
	"github.com/AlaskaAirlines/trivy/pkg/log"
	"github.com/AlaskaAirlines/trivy/pkg/report"
	"github.com/AlaskaAirlines/trivy/pkg/scanner"
	"github.com/AlaskaAirlines/trivy/pkg/types"
	"github.com/AlaskaAirlines/trivy/pkg/utils"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
)

// InitializeScanner type to define initialize function signature
type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration) (
	scanner.Scanner, func(), error)

// nolint: gocyclo
// TODO: refactror and fix cyclometic complexity
func run(c config.Config, initializeScanner InitializeScanner) error {
	if err := log.InitLogger(c.Debug, c.Quiet); err != nil {
		l.Fatal(err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	cacheClient, err := cache.NewFSCache(c.CacheDir)
	if err != nil {
		return xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	defer cacheClient.Close()

	cacheOperation := operation.NewCache(cacheClient)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		return cacheOperation.Reset()
	}
	if c.ClearCache {
		return cacheOperation.ClearImages()
	}

	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return nil
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	defer db.Close()

	target := c.Target
	if c.Input != "" {
		target = c.Input
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	scanner, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, c.Timeout)
	if err != nil {
		return xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs, // this is valid only for image subcommand
		ListAllPackages:     c.ListAllPkgs,
		SkipFiles:           c.SkipFiles,
		SkipDirectories:     c.SkipDirectories,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, err := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile, c.IgnorePolicy)
		if err != nil {
			return xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
	}

	if err = report.WriteResults(c.Format, c.Output, c.Severities, results, c.Template, c.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
	return nil
}
