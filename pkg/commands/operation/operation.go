package operation

import (
	"context"
	"slices"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
)

var mu sync.Mutex

// DownloadDB downloads the DB
func DownloadDB(ctx context.Context, appVersion, cacheDir string, dbRepositories []name.Reference, quiet, skipUpdate bool,
	opt ftypes.RegistryOptions) error {
	mu.Lock()
	defer mu.Unlock()

	ctx = log.WithContextPrefix(ctx, log.PrefixVulnerabilityDB)
	dbDir := db.Dir(cacheDir)
	client := db.NewClient(dbDir, quiet, db.WithDBRepository(dbRepositories))
	needsUpdate, err := client.NeedsUpdate(ctx, appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update DB")
		if err = client.Download(ctx, dbDir, opt); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	// for debug
	if err = client.ShowInfo(); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func DownloadVEXRepositories(ctx context.Context, opts flag.Options) error {
	ctx = log.WithContextPrefix(ctx, "vex")
	if opts.SkipVEXRepoUpdate {
		log.InfoContext(ctx, "Skipping VEX repository update")
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	// Download VEX repositories only if `--vex repo` is passed.
	_, enabled := lo.Find(opts.VEXSources, func(src vex.Source) bool {
		return src.Type == vex.TypeRepository
	})
	if !enabled {
		return nil
	}

	err := repo.NewManager(opts.CacheDir).DownloadRepositories(ctx, nil, repo.Options{
		Insecure: opts.Insecure,
	})
	if err != nil {
		return xerrors.Errorf("failed to download vex repositories: %w", err)
	}

	return nil

}

// InitBuiltinChecks downloads the built-in policies and loads them
func InitBuiltinChecks(ctx context.Context, client *policy.Client, skipUpdate bool, registryOpts ftypes.RegistryOptions) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	ctx = log.WithContextPrefix(ctx, "checks-client")

	var err error

	if skipUpdate {
		log.InfoContext(ctx, "No downloadable checks were loaded as --skip-check-update is enabled, loading from existing cache...")

		path := client.BuiltinChecksPath()
		_, _, err := misconf.CheckPathExists(path)
		if err != nil {
			return "", xerrors.Errorf("failed to check cache: %w", err)
		}
		return path, nil
	}

	needsUpdate, err := client.NeedsUpdate(ctx, registryOpts)
	if err != nil {
		return "", xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update the checks bundle")
		log.InfoContext(ctx, "Downloading the checks bundle...")
		if err = client.DownloadBuiltinChecks(ctx, registryOpts); err != nil {
			return "", xerrors.Errorf("failed to download checks bundle: %w", err)
		}
	} else {
		log.InfoContext(ctx,
			"Using existing checks from cache",
			log.String("path", client.BuiltinChecksPath()),
		)
	}

	return client.BuiltinChecksPath(), nil
}

func Exit(opts flag.Options, failedResults bool, m types.Metadata) error {
	if opts.ExitOnEOL != 0 && m.OS != nil && m.OS.Eosl {
		log.Error("Detected EOL OS", log.String("family", string(m.OS.Family)),
			log.String("version", m.OS.Name))
		return &types.ExitError{Code: opts.ExitOnEOL}
	}

	if opts.ExitCode != 0 && failedResults {
		return &types.ExitError{Code: opts.ExitCode}
	}
	return nil
}

// ExitFailure determines whether the report contains findings that should
// trigger the exit code specified by --exit-code according to --exit-on-severity.
//
// The report is filtered on a copy with the exit-on severities (expanded to a
// threshold, e.g. HIGH also matches CRITICAL) so that suppressions
// (.trivyignore, VEX, ignore policies) are honored, while the original report
// is left intact for output filtering by --severity.
// It must be called before the report is filtered for output.
func ExitFailure(ctx context.Context, opts flag.Options, report types.Report) (bool, error) {
	filterOpts := opts.FilterOpts()
	filterOpts.Severities = thresholdSeverities(opts.ExitOnSeverities)

	// Filter a copy of the report so the original stays intact for output.
	// Note that result.Filter only reassigns fields on the results,
	// so a shallow copy of the results slice is sufficient here.
	r := report
	r.Results = slices.Clone(report.Results)
	if err := result.Filter(ctx, r, filterOpts); err != nil {
		return false, xerrors.Errorf("exit-on-severity filtering error: %w", err)
	}
	return r.Results.Failed(), nil
}

// thresholdSeverities expands the given severities into all severities equal
// to or higher than the lowest one, e.g. HIGH => [HIGH, CRITICAL].
func thresholdSeverities(severities []dbTypes.Severity) []dbTypes.Severity {
	if len(severities) == 0 {
		return nil
	}
	minSev := slices.Min(severities)
	var expanded []dbTypes.Severity
	for s := minSev; s <= dbTypes.SeverityCritical; s++ {
		expanded = append(expanded, s)
	}
	return expanded
}
