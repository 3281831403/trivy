package operation

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

var exitOnSeverityPkg = ftypes.Package{
	ID:      "werkzeug@0.11.1",
	Name:    "werkzeug",
	Version: "0.11.1",
	Identifier: ftypes.PkgIdentifier{
		UID: "01",
		PURL: &packageurl.PackageURL{
			Type:    packageurl.TypePyPi,
			Name:    "werkzeug",
			Version: "0.11.1",
		},
	},
}

func exitOnSeverityReport() types.Report {
	return types.Report{
		ArtifactName: "test",
		ArtifactType: ftypes.TypeFilesystem,
		Results: types.Results{
			{
				Target:   "requirements.txt",
				Class:    types.ClassLangPkg,
				Type:     ftypes.Pip,
				Packages: []ftypes.Package{exitOnSeverityPkg},
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2019-14806",
						PkgName:          "werkzeug",
						InstalledVersion: "0.11.1",
						PkgIdentifier:    exitOnSeverityPkg.Identifier,
						Vulnerability: dbTypes.Vulnerability{
							Severity: "HIGH",
						},
					},
				},
			},
		},
	}
}

func TestExitFailure(t *testing.T) {
	const openVEXDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "test",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2019-14806"},
      "products": [{"@id": "pkg:pypi/werkzeug@0.11.1"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}`

	tests := []struct {
		name    string
		opts    flag.Options
		setup   func(t *testing.T, dir string) flag.Options
		want    bool
		wantErr string
	}{
		{
			name: "HIGH finding matches --exit-on-severity HIGH",
			opts: flag.Options{
				ReportOptions: flag.ReportOptions{
					ExitOnSeverities: []dbTypes.Severity{dbTypes.SeverityHigh},
				},
			},
			want: true,
		},
		{
			name: "HIGH finding does not match --exit-on-severity CRITICAL",
			opts: flag.Options{
				ReportOptions: flag.ReportOptions{
					ExitOnSeverities: []dbTypes.Severity{dbTypes.SeverityCritical},
				},
			},
			want: false,
		},
		{
			name: "threshold: HIGH finding matches --exit-on-severity MEDIUM",
			opts: flag.Options{
				ReportOptions: flag.ReportOptions{
					ExitOnSeverities: []dbTypes.Severity{dbTypes.SeverityMedium},
				},
			},
			want: true,
		},
		{
			name: "finding suppressed by .trivyignore does not fail",
			setup: func(t *testing.T, dir string) flag.Options {
				ignoreFile := filepath.Join(dir, ".trivyignore")
				require.NoError(t, os.WriteFile(ignoreFile, []byte("CVE-2019-14806\n"), 0o644))
				return flag.Options{
					ReportOptions: flag.ReportOptions{
						ExitOnSeverities: []dbTypes.Severity{dbTypes.SeverityHigh},
						IgnoreFile:       ignoreFile,
					},
				}
			},
			want: false,
		},
		{
			name: "finding suppressed by VEX does not fail",
			setup: func(t *testing.T, dir string) flag.Options {
				vexFile := filepath.Join(dir, "openvex.json")
				require.NoError(t, os.WriteFile(vexFile, []byte(openVEXDoc), 0o644))
				return flag.Options{
					ReportOptions: flag.ReportOptions{
						ExitOnSeverities: []dbTypes.Severity{dbTypes.SeverityHigh},
					},
					VulnerabilityOptions: flag.VulnerabilityOptions{
						VEXSources: []vex.Source{{Type: vex.TypeFile, FilePath: vexFile}},
					},
				}
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			if tt.setup != nil {
				opts = tt.setup(t, t.TempDir())
			}

			report := exitOnSeverityReport()
			got, err := ExitFailure(context.Background(), opts, report)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// The original report must stay unfiltered for output.
			require.Len(t, report.Results, 1)
			assert.Len(t, report.Results[0].Vulnerabilities, 1)
		})
	}
}

func TestThresholdSeverities(t *testing.T) {
	tests := []struct {
		name       string
		severities []dbTypes.Severity
		want       []dbTypes.Severity
	}{
		{
			name:       "nil",
			severities: nil,
			want:       nil,
		},
		{
			name:       "HIGH expands to HIGH and CRITICAL",
			severities: []dbTypes.Severity{dbTypes.SeverityHigh},
			want:       []dbTypes.Severity{dbTypes.SeverityHigh, dbTypes.SeverityCritical},
		},
		{
			name:       "CRITICAL stays CRITICAL",
			severities: []dbTypes.Severity{dbTypes.SeverityCritical},
			want:       []dbTypes.Severity{dbTypes.SeverityCritical},
		},
		{
			name:       "lowest severity wins",
			severities: []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityMedium},
			want:       []dbTypes.Severity{dbTypes.SeverityMedium, dbTypes.SeverityHigh, dbTypes.SeverityCritical},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, thresholdSeverities(tt.severities))
		})
	}
}
