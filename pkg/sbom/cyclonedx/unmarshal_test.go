package cyclonedx_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestUnmarshaler_Unmarshal(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      types.SBOM
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
					},
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "musl@1.2.3-r0",
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.3-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.16.0",
											},
										},
									},
									BOMRef: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
								},
							},
						},
					},
				},
				Applications: []ftypes.Application{
					{
						Type:     ftypes.Composer,
						FilePath: "app/composer/composer.lock",
						Packages: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type:     ftypes.GoBinary,
						FilePath: "app/gobinary/gobinary",
						Packages: ftypes.Packages{
							{
								ID:      "github.com/package-url/packageurl-go@v0.1.1-0.20220203205134-d70459300c8a",
								Name:    "github.com/package-url/packageurl-go",
								Version: "v0.1.1-0.20220203205134-d70459300c8a",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/package-url",
										Name:      "packageurl-go",
										Version:   "v0.1.1-0.20220203205134-d70459300c8a",
									},
									BOMRef: "pkg:golang/github.com/package-url/packageurl-go@v0.1.1-0.20220203205134-d70459300c8a",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type:     ftypes.Gradle,
						FilePath: "app/gradle/target/gradle.lockfile",
						Packages: ftypes.Packages{
							{
								ID:   "com.example:example:0.0.1",
								Name: "com.example:example",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.example",
										Name:      "example",
										Version:   "0.0.1",
									},
									BOMRef: "pkg:maven/com.example/example@0.0.1",
								},
								Version: "0.0.1",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type: ftypes.Jar,
						Packages: ftypes.Packages{
							{
								ID:   "org.codehaus.mojo:child-project:1.0",
								Name: "org.codehaus.mojo:child-project",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.codehaus.mojo",
										Name:      "child-project",
										Version:   "1.0",
									},
									BOMRef: "pkg:maven/org.codehaus.mojo/child-project@1.0?file_path=app%2Fmaven%2Ftarget%2Fchild-project-1.0.jar",
								},
								Version: "1.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
								FilePath: "app/maven/target/child-project-1.0.jar",
							},
						},
					},
					{
						Type:     ftypes.NodePkg,
						FilePath: "",
						Packages: ftypes.Packages{
							{
								ID:      "@example/bootstrap@5.0.2",
								Name:    "@example/bootstrap",
								Version: "5.0.2",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "@example",
										Name:      "bootstrap",
										Version:   "5.0.2",
									},
									BOMRef: "pkg:npm/@example/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
								},
								Licenses: []string{"MIT"},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
								FilePath: "app/app/package.json",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path KBOM",
			inputFile: "testdata/happy/kbom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "ubuntu",
						Name:   "22.04.2",
					},
				},
				Applications: []ftypes.Application{
					{
						Type: ftypes.GoBinary,
						Packages: ftypes.Packages{
							{
								ID:      "docker@v24.0.4",
								Name:    "docker",
								Version: "24.0.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGolang,
										Name:    "docker",
										Version: "24.0.4",
									},
									BOMRef: "pkg:golang/docker@24.0.4",
								},
							},
						},
					},
					{
						Type: ftypes.K8sUpstream,
						Packages: ftypes.Packages{
							{
								ID:      "k8s.io/apiserver@1.27.4",
								Name:    "k8s.io/apiserver",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/apiserver",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fapiserver@1.27.4",
								},
							},
							{
								ID:      "k8s.io/controller-manager@1.27.4",
								Name:    "k8s.io/controller-manager",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/controller-manager",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fcontroller-manager@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kube-proxy@1.27.4",
								Name:    "k8s.io/kube-proxy",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kube-proxy",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkube-proxy@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kube-scheduler@1.27.4",
								Name:    "k8s.io/kube-scheduler",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kube-scheduler",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkube-scheduler@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kubelet@1.27.4",
								Name:    "k8s.io/kubelet",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kubelet",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkubelet@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kubernetes@1.27.4",
								Name:    "k8s.io/kubernetes",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kubernetes",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkubernetes@1.27.4",
								},
								DependsOn: []string{
									"k8s.io/apiserver@1.27.4",
									"k8s.io/controller-manager@1.27.4",
									"k8s.io/kube-proxy@1.27.4",
									"k8s.io/kube-scheduler@1.27.4",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path with infinity loop",
			inputFile: "testdata/happy/infinite-loop-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:08d22c0ceb150ddeb2237c5fa3129c0183f3cc6f5eeb2e7aa4016da3ad02140a",
					DiffIDs: []string{
						"sha256:b93c1bd012ab8fda60f5b4f5906bf244586e0e3292d84571d3abb56472248466",
					},
					RepoTags: []string{
						"ubuntu:latest",
					},
					RepoDigests: []string{
						"ubuntu@sha256:67211c14fa74f070d27cc59d69a7fa9aeff8e28ea118ef3babc295a0428a6d21",
					},
					OS: &ftypes.OS{
						Family: "ubuntu",
						Name:   "22.04",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "libc6@2.35-0ubuntu3.1",
								Name:       "libc6",
								Version:    "2.35-0ubuntu3.1",
								SrcName:    "glibc",
								SrcVersion: "2.35",
								SrcRelease: "0ubuntu3.1",
								Licenses: []string{
									"LGPL-2.1",
									"GPL-2.0",
									"GFDL-1.3",
								},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "ubuntu",
										Name:      "libc6",
										Version:   "2.35-0ubuntu3.1",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "ubuntu-22.04",
											},
										},
									},
									BOMRef: "pkg:deb/ubuntu/libc6@2.35-0ubuntu3.1?distro=ubuntu-22.04",
								},
								DependsOn: []string{
									"libcrypt1@1:4.4.27-1",
								},
								Layer: ftypes.Layer{
									Digest: "sha256:74ac377868f863e123f24c409f79709f7563fa464557c36a09cf6f85c8b92b7f",
									DiffID: "sha256:b93c1bd012ab8fda60f5b4f5906bf244586e0e3292d84571d3abb56472248466",
								},
							},
							{
								ID:         "libcrypt1@1:4.4.27-1",
								Name:       "libcrypt1",
								Version:    "4.4.27-1",
								Epoch:      1,
								SrcName:    "libxcrypt",
								SrcVersion: "4.4.27",
								SrcRelease: "1",
								SrcEpoch:   1,
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "ubuntu",
										Name:      "libcrypt1",
										Version:   "4.4.27-1",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "ubuntu-22.04",
											},
											{
												Key:   "epoch",
												Value: "1",
											},
										},
									},
									BOMRef: "pkg:deb/ubuntu/libcrypt1@4.4.27-1?epoch=1&distro=ubuntu-22.04",
								},
								DependsOn: []string{
									"libc6@2.35-0ubuntu3.1",
								},
								Layer: ftypes.Layer{
									Digest: "sha256:74ac377868f863e123f24c409f79709f7563fa464557c36a09cf6f85c8b92b7f",
									DiffID: "sha256:b93c1bd012ab8fda60f5b4f5906bf244586e0e3292d84571d3abb56472248466",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for third party sbom",
			inputFile: "testdata/happy/third-party-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "musl@1.2.3-r0",
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.3-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.16.0",
											},
										},
									},
									BOMRef: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
								},
							},
						},
					},
				},
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Packages: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for third party sbom, no operation-system component",
			inputFile: "testdata/happy/third-party-bom-no-os.json",
			want: types.SBOM{
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "musl@1.2.3-r0",
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.3-r0",
										Qualifiers: packageurl.Qualifiers{
											{Key: "distro", Value: "3.16.0"},
										},
									},
									BOMRef: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
								},
							},
						},
					},
				},
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Packages: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for unrelated bom",
			inputFile: "testdata/happy/unrelated-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Packages: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for independent library bom",
			inputFile: "testdata/happy/independent-library-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Packages: ftypes.Packages{
							{
								ID:      "pear/core@1.13.1",
								Name:    "pear/core",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "core",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/core@1.13.1",
								},
								DependsOn: []string{
									"pear/log@1.13.1",
									"pear/pear_exception@v1.0.0",
								},
							},
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for jar where name is GroupID and ArtifactID",
			inputFile: "testdata/happy/group-in-name.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: "jar",
						Packages: ftypes.Packages{
							{
								ID:      "org.springframework:spring-web:5.3.22",
								Name:    "org.springframework:spring-web",
								Version: "5.3.22",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.springframework",
										Name:      "spring-web",
										Version:   "5.3.22",
									},
									BOMRef: "pkg:maven/org.springframework/spring-web@5.3.22?file_path=spring-web-5.3.22.jar",
								},
								FilePath: "spring-web-5.3.22.jar",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for BOM with nested packages",
			inputFile: "testdata/happy/nested-packages-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "gobinary",
						FilePath: "foo/bar/test.elf",
						Packages: ftypes.Packages{
							{
								ID:   "github.com/aquasecurity/test",
								Name: "github.com/aquasecurity/test",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/aquasecurity",
										Name:      "test",
									},
									BOMRef: "pkg:golang/github.com/aquasecurity/test",
								},
								DependsOn: []string{
									"github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
									"github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
									"stdlib@v1.15.2",
								},
							},
							{
								ID:      "github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
								Name:    "github.com/aquasecurity/go-pep440-version",
								Version: "v0.0.0-20210121094942-22b2f8951d46",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/aquasecurity",
										Name:      "go-pep440-version",
										Version:   "v0.0.0-20210121094942-22b2f8951d46",
									},
									BOMRef: "pkg:golang/github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
								},
							},
							{
								ID:      "github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
								Name:    "github.com/aquasecurity/go-version",
								Version: "v0.0.0-20210121072130-637058cfe492",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/aquasecurity",
										Name:      "go-version",
										Version:   "v0.0.0-20210121072130-637058cfe492",
									},
									BOMRef: "pkg:golang/github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
								},
							},
							{
								ID:      "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:    "golang.org/x/xerrors",
								Version: "v0.0.0-20200804184101-5ec99f83aff1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "golang.org/x",
										Name:      "xerrors",
										Version:   "v0.0.0-20200804184101-5ec99f83aff1",
									},
									BOMRef: "pkg:golang/golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								},
							},
							{
								ID:      "stdlib@v1.15.2",
								Name:    "stdlib",
								Version: "v1.15.2",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGolang,
										Name:    "stdlib",
										Version: "v1.15.2",
									},
									BOMRef: "pkg:golang/stdlib@v1.15.2",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for BOM with nested components",
			inputFile: "testdata/happy/nested-components-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.GoBinary,
						FilePath: "app1/package-lock.json",
						Packages: ftypes.Packages{
							{
								ID:      "example/root-pkg@1.0.0",
								Name:    "example/root-pkg",
								Version: "1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "example",
										Name:      "root-pkg",
										Version:   "1.0.0",
									},
									BOMRef: "pkg:npm/example/root-pkg@1.0.0",
								},
								DependsOn: []string{
									"example/shared-pkg@2.0.0",
								},
							},
							{
								ID:      "example/shared-pkg@2.0.0",
								Name:    "example/shared-pkg",
								Version: "2.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "example",
										Name:      "shared-pkg",
										Version:   "2.0.0",
									},
									BOMRef: "pkg:npm/example/shared-pkg@2.0.0",
								},
								DependsOn: []string{
									"example/deep-pkg@3.0.0",
								},
							},
							{
								ID:      "example/deep-pkg@3.0.0",
								Name:    "example/deep-pkg",
								Version: "3.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "example",
										Name:      "deep-pkg",
										Version:   "3.0.0",
									},
									BOMRef: "pkg:npm/example/deep-pkg@3.0.0",
								},
							},
						},
					},
					{
						Type:     ftypes.GoBinary,
						FilePath: "app2/package-lock.json",
						Packages: ftypes.Packages{
							{
								ID:      "example/other-pkg@4.0.0",
								Name:    "example/other-pkg",
								Version: "4.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "example",
										Name:      "other-pkg",
										Version:   "4.0.0",
									},
									BOMRef: "pkg:npm/example/other-pkg@4.0.0",
								},
								DependsOn: []string{
									"example/shared-pkg@2.0.0",
								},
							},
							// The shared package is reachable from both applications, even though
							// it is a single component with a single BOM-Ref. Its own dependencies
							// are reachable from both applications as well.
							{
								ID:      "example/shared-pkg@2.0.0",
								Name:    "example/shared-pkg",
								Version: "2.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "example",
										Name:      "shared-pkg",
										Version:   "2.0.0",
									},
									BOMRef: "pkg:npm/example/shared-pkg@2.0.0",
								},
								DependsOn: []string{
									"example/deep-pkg@3.0.0",
								},
							},
							{
								ID:      "example/deep-pkg@3.0.0",
								Name:    "example/deep-pkg",
								Version: "3.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "example",
										Name:      "deep-pkg",
										Version:   "3.0.0",
									},
									BOMRef: "pkg:npm/example/deep-pkg@3.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for nested OS packages",
			inputFile: "testdata/happy/nested-os-packages-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.20.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "busybox@1.36.1-r0",
								Name:       "busybox",
								Version:    "1.36.1-r0",
								SrcName:    "busybox",
								SrcVersion: "1.36.1-r0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "busybox",
										Version:   "1.36.1-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.20.0",
											},
										},
									},
									BOMRef: "pkg:apk/alpine/busybox@1.36.1-r0?distro=3.20.0",
								},
								DependsOn: []string{
									"musl@1.2.5-r0",
								},
							},
							{
								ID:         "musl@1.2.5-r0",
								Name:       "musl",
								Version:    "1.2.5-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.5-r0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.5-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.20.0",
											},
										},
									},
									BOMRef: "pkg:apk/alpine/musl@1.2.5-r0?distro=3.20.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path only os component",
			inputFile: "testdata/happy/os-only-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
					},
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
			},
		},
		{
			name:      "happy path empty component",
			inputFile: "testdata/happy/empty-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
					},
				},
			},
		},
		{
			name:      "happy path empty metadata component",
			inputFile: "testdata/happy/empty-metadata-component-bom.json",
			want:      types.SBOM{},
		},
		{
			name:      "invalid purl",
			inputFile: "testdata/happy/invalid-purl.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.Composer,
						Packages: ftypes.Packages{
							{
								ID:      "pear/core@1.13.1",
								Name:    "pear/core",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "core",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/core@1.13.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "SHA-512",
			inputFile: "testdata/happy/package-hashes.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.NodePkg,
						Packages: ftypes.Packages{
							{
								ID:      "@angular/animations@19.2.10",
								Name:    "@angular/animations",
								Version: "19.2.10",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "@angular",
										Name:      "animations",
										Version:   "19.2.10",
									},
									BOMRef: "@angular/animations@19.2.10",
								},
								// The legacy field carries the first hash of the component.
								Digest: "sha512:2e51fa9add03f3e308d0b57c40dc7dfeba8b2efd1609f60f4bfe625d21a92327ec7e52e83b97511a1b52e297506eee60aa69cb75ff62eebe257512637fbc1bfa",
								// A recorded source is restored, and a recorded digest whose value is not among the
								// hashes is ignored. A hash without a recorded source falls back to the SBOM source.
								Digests: []digest.SourcedDigest{
									{
										Digest: "sha512:2e51fa9add03f3e308d0b57c40dc7dfeba8b2efd1609f60f4bfe625d21a92327ec7e52e83b97511a1b52e297506eee60aa69cb75ff62eebe257512637fbc1bfa",
										Source: digest.SourceFileContent,
									},
									{
										Digest: "sha1:76d1e0e3a5e0f8b9e4d3c2b1a0987654321fedcb",
										Source: digest.SourceSBOM,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path - third-party SBOM scan of `file` root component",
			inputFile: "testdata/happy/third-party-scan-file-component.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "jar",
						FilePath: "",
						Packages: ftypes.Packages{
							ftypes.Package{
								ID:   "commons-io:commons-io:2.13.0",
								Name: "commons-io:commons-io",
								Identifier: ftypes.PkgIdentifier{
									UID: "",
									PURL: &packageurl.PackageURL{
										Type:       "maven",
										Namespace:  "commons-io",
										Name:       "commons-io",
										Version:    "2.13.0",
										Qualifiers: nil,
										Subpath:    "",
									},
									BOMRef: "pkg:maven/commons-io/commons-io@2.13.0?package-id=6033c6b2f2d3cf10",
								},
								Version:            "2.13.0",
								Release:            "",
								Epoch:              0,
								Arch:               "",
								Dev:                false,
								SrcName:            "",
								SrcVersion:         "",
								SrcRelease:         "",
								SrcEpoch:           0,
								Licenses:           []string{"Apache-2.0"},
								Maintainer:         "",
								ExternalReferences: nil,
								Modularitylabel:    "",
								BuildInfo:          nil,
								Indirect:           false,
								Relationship:       0,
								DependsOn:          nil,
								Layer: ftypes.Layer{
									Size:      0,
									Digest:    "",
									DiffID:    "",
									CreatedBy: "",
								},
								FilePath:       "",
								Digest:         "",
								Locations:      nil,
								InstalledFiles: nil,
							},
						},
					},
				},
			},
		},
		{
			name:      "invalid serial",
			inputFile: "testdata/sad/invalid-serial.json",
			wantErr:   "CycloneDX decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			var cdx cyclonedx.BOM
			err = json.NewDecoder(f).Decode(&cdx)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			var got types.SBOM
			err = sbomio.NewDecoder(cdx.BOM).Decode(t.Context(), &got)
			require.NoError(t, err)

			got.BOM = nil
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestUnmarshaler_NestedComponentsRoundTrip makes sure a third-party CycloneDX document using
// nested components survives a conversion back to CycloneDX and a second read: every nested
// package stays in the inventory, a shared package keeps a single BOM-Ref while remaining
// reachable from every target, and the package count and dependency edges stay unchanged.
func TestUnmarshaler_NestedComponentsRoundTrip(t *testing.T) {
	decode := func(t *testing.T, r io.Reader) types.SBOM {
		var bom cyclonedx.BOM
		require.NoError(t, json.NewDecoder(r).Decode(&bom))

		var sbom types.SBOM
		require.NoError(t, sbomio.NewDecoder(bom.BOM).Decode(t.Context(), &sbom))
		sbom.BOM = nil
		return sbom
	}

	f, err := os.Open("testdata/happy/nested-components-bom.json")
	require.NoError(t, err)
	defer f.Close()
	first := decode(t, f)

	// Re-marshal the parsed BOM the way `trivy --format cyclonedx` does, then read it back.
	var parsed cyclonedx.BOM
	f2, err := os.Open("testdata/happy/nested-components-bom.json")
	require.NoError(t, err)
	defer f2.Close()
	require.NoError(t, json.NewDecoder(f2).Decode(&parsed))

	marshaler := cyclonedx.NewMarshaler("dev")
	doc, err := marshaler.Marshal(t.Context(), parsed.BOM)
	require.NoError(t, err)

	data, err := json.Marshal(doc)
	require.NoError(t, err)
	second := decode(t, bytes.NewReader(data))

	assert.Equal(t, countPackages(first), countPackages(second))
	assert.Equal(t, dependencyEdges(first), dependencyEdges(second))

	// The shared package is represented by a single component, hence a single BOM-Ref.
	var refs []string
	for _, c := range *doc.Components {
		refs = append(refs, c.BOMRef)
	}
	assert.ElementsMatch(t, refs, lo.Uniq(refs))

	// Dependency edges must not be duplicated either.
	var edges [][2]string
	for _, d := range *doc.Dependencies {
		for _, dep := range lo.FromPtr(d.Dependencies) {
			edges = append(edges, [2]string{d.Ref, dep})
		}
	}
	assert.ElementsMatch(t, edges, lo.Uniq(edges))
}

func countPackages(sbom types.SBOM) int {
	var n int
	for _, app := range sbom.Applications {
		n += len(app.Packages)
	}
	for _, pi := range sbom.Packages {
		n += len(pi.Packages)
	}
	return n
}

func dependencyEdges(sbom types.SBOM) [][2]string {
	var edges [][2]string
	for _, app := range sbom.Applications {
		for _, p := range app.Packages {
			for _, dep := range p.DependsOn {
				edges = append(edges, [2]string{p.ID, dep})
			}
		}
	}
	for _, pi := range sbom.Packages {
		for _, p := range pi.Packages {
			for _, dep := range p.DependsOn {
				edges = append(edges, [2]string{p.ID, dep})
			}
		}
	}
	return edges
}

// Trivy writes cryptographic assets into a CycloneDX document and drops them when reading
// one back.
func TestUnmarshaler_CryptographicAssets(t *testing.T) {
	report := cryptoReport([]ftypes.CryptoAsset{
		cryptotest.CertificateAsset(),
		cryptotest.AlgorithmAsset(),
	})

	marshaler := cyclonedx.NewMarshaler("dev")
	doc, err := marshaler.MarshalReport(t.Context(), report)
	require.NoError(t, err)

	var written int
	for _, component := range *doc.Components {
		if component.CryptoProperties != nil {
			written++
		}
	}
	require.Equal(t, 2, written)

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	var bom cyclonedx.BOM
	require.NoError(t, json.Unmarshal(data, &bom))

	var got types.SBOM
	require.NoError(t, sbomio.NewDecoder(bom.BOM).Decode(t.Context(), &got))

	assert.Empty(t, got.Packages)
	assert.Empty(t, got.Applications)
}
