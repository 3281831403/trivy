package cyclonedx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

var (
	ErrUnsupportedType = errors.New("unsupported type")
)

type BOM struct {
	*core.BOM
}

func DecodeJSON(r io.Reader) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, xerrors.Errorf("CycloneDX decode error: %w", err)
	}
	return bom, nil
}

func (b *BOM) UnmarshalJSON(data []byte) error {
	log.Debug("Unmarshalling CycloneDX JSON...")
	if b.BOM == nil {
		b.BOM = core.NewBOM(core.Options{GenerateBOMRef: true})
	}

	cdxBOM, err := DecodeJSON(bytes.NewReader(data))
	if err != nil {
		return xerrors.Errorf("CycloneDX decode error: %w", err)
	}

	if !IsTrivySBOM(cdxBOM) {
		log.Warn("Third-party SBOM may lead to inaccurate vulnerability detection")
		log.Warn("Recommend using Trivy to generate SBOMs")
	}

	if err = b.parseBOM(cdxBOM); err != nil {
		return xerrors.Errorf("failed to parse sbom: %w", err)
	}

	// Store the original metadata
	b.BOM.SerialNumber = cdxBOM.SerialNumber
	b.BOM.Version = cdxBOM.Version

	return nil
}

func (b *BOM) parseBOM(bom *cdx.BOM) error {
	// Flatten the component tree, including components nested at any depth. Third-party SBOMs
	// can represent the inventory as nested `components` instead of a flat list, and the
	// dependency graph may cover only the top-level entries.
	//
	// Components sharing the same package URL describe the same package. Such a component is
	// added only once, while every place it appears at (each target that contains it) keeps an
	// edge to it, so the package shows up under each of its owners.
	components := b.parseComponents(bom.Components)

	// Convert the metadata component into Trivy component
	mComponent, err := b.parseMetadataComponent(bom)
	if err != nil {
		return xerrors.Errorf("failed to parse root component: %w", err)
	} else if mComponent != nil {
		components[mComponent.PkgIdentifier.BOMRef] = mComponent
	}

	// Parse dependencies and build relationships
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		ref, ok := components[dep.Ref]
		if !ok {
			continue
		}

		dependencies := lo.FromPtr(dep.Dependencies)
		if len(dependencies) == 0 {
			// Empty dependsOn array - create empty relationship to preserve this information
			b.BOM.AddRelationship(ref, nil, core.RelationshipDependsOn)
		} else {
			// Process actual dependencies
			for _, depRef := range dependencies {
				dependency, ok := components[depRef]
				if !ok {
					continue
				}
				b.BOM.AddRelationship(ref, dependency, core.RelationshipDependsOn)
			}
		}
	}

	if refs := b.parseExternalReferences(bom); refs != nil {
		b.BOM.AddExternalReferences(refs)
	}

	return nil
}

func (b *BOM) parseMetadataComponent(bom *cdx.BOM) (*core.Component, error) {
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil, nil
	}
	root, err := b.parseComponent(*bom.Metadata.Component)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse metadata component: %w", err)
	}
	root.Root = true
	b.BOM.AddComponent(root)
	return root, nil
}

func (b *BOM) parseExternalReferences(bom *cdx.BOM) []core.ExternalReference {
	if bom.ExternalReferences == nil {
		return nil
	}
	var refs = make([]core.ExternalReference, 0)

	for _, ref := range *bom.ExternalReferences {
		t, err := b.unmarshalReferenceType(ref.Type)
		if err != nil {
			continue
		}

		externalReference := core.ExternalReference{
			Type: t,
			URL:  ref.URL,
		}

		refs = append(refs, externalReference)
	}
	return refs
}

func (b *BOM) unmarshalReferenceType(t cdx.ExternalReferenceType) (core.ExternalReferenceType, error) {
	var referenceType core.ExternalReferenceType
	switch t {
	case cdx.ERTypeExploitabilityStatement:
		referenceType = core.ExternalReferenceVEX
	default:
		return "", fmt.Errorf("unsupported external reference type: %s", t)
	}
	return referenceType, nil
}

// parseComponents walks the CycloneDX component tree, including components nested at any
// depth, and converts it into a flat map of BOM-Refs to Trivy components.
//
// A package URL uniquely identifies a package: components carrying the same purl are merged
// into the first one, so the package is added once and gets a single BOM-Ref. Every nesting
// site still records an edge from its parent, hence a shared package appears under each target
// that contains it.
func (b *BOM) parseComponents(cdxComponents *[]cdx.Component) map[string]*core.Component {
	components := make(map[string]*core.Component)
	// purls maps a package URL to the component that owns it, so components repeated with the
	// same purl resolve to a single package.
	purls := make(map[string]*core.Component)
	for _, component := range lo.FromPtr(cdxComponents) {
		b.parseNestedComponents(component, nil, components, purls)
	}
	return components
}

// parseNestedComponents converts a CycloneDX component and, recursively, all of its nested
// components. parent is the component the current one is nested into, or nil at the top level.
func (b *BOM) parseNestedComponents(component cdx.Component, parent *core.Component,
	components map[string]*core.Component, purls map[string]*core.Component,
) {
	// Trivy writes cryptographic assets but does not read them back yet.
	if component.Type == cdx.ComponentTypeCryptographicAsset {
		return
	}

	c, err := b.parseComponent(component)
	if errors.Is(err, ErrUnsupportedType) {
		log.Info("Skipping the component with the unsupported type",
			log.String("bom-ref", component.BOMRef), log.String("type", string(component.Type)))
	} else if err != nil {
		log.Warn("Failed to parse component", log.Err(err))
	} else {
		// Merge components that describe the same package, identified by its package URL. The
		// first occurrence wins: a package is added once and keeps a single BOM-Ref.
		var purl string
		if c.PkgIdentifier.PURL != nil {
			purl = c.PkgIdentifier.PURL.String()
		}
		if existing, ok := purls[purl]; ok && purl != "" {
			c = existing
		} else {
			b.BOM.AddComponent(c)
			if purl != "" {
				purls[purl] = c
			}
		}

		// A BOM-Ref may be reused by several nested occurrences of the same package; all of them
		// resolve to the same component.
		components[component.BOMRef] = c

		// Record the nesting. Without an edge the flattened children would be disconnected from
		// their target, and a package shared by several applications would be reachable from only
		// one of them.
		if parent != nil {
			b.addNestingRelationship(parent, c)
		}
		parent = c
	}

	// Walk nested components even when the current one was skipped, so a failed component does
	// not hide the whole subtree underneath it.
	for _, child := range lo.FromPtr(component.Components) {
		b.parseNestedComponents(child, parent, components, purls)
	}
}

// addNestingRelationship turns the CycloneDX component nesting into a Trivy relationship.
// Applications, operating systems and other targets contain their packages; a nested package
// is treated as a dependency of its parent package, so parent packages see their subpackages.
func (b *BOM) addNestingRelationship(parent, child *core.Component) {
	switch parent.Type {
	case core.TypeLibrary:
		b.BOM.AddRelationship(parent, child, core.RelationshipDependsOn)
	default:
		b.BOM.AddRelationship(parent, child, core.RelationshipContains)
	}
}

func (b *BOM) parseComponent(c cdx.Component) (*core.Component, error) {
	componentType, err := b.unmarshalType(c.Type)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal component type: %w", err)
	}

	identifier := ftypes.PkgIdentifier{
		BOMRef: c.BOMRef,
	}

	// Parse PURL
	if c.PackageURL != "" {
		purl, err := packageurl.FromString(c.PackageURL)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse PURL: %w", err)
		}
		identifier.PURL = &purl
	}

	component := &core.Component{
		Type:     componentType,
		Name:     c.Name,
		Group:    c.Group,
		Version:  c.Version,
		Licenses: b.unmarshalLicenses(c.Licenses),
		Files: []core.File{
			{
				Digests: b.unmarshalHashes(c.Hashes),
			},
		},
		PkgIdentifier: identifier,
		Supplier:      b.unmarshalSupplier(c.Supplier),
		Properties:    b.unmarshalProperties(c.Properties),
	}

	return component, nil
}

func (b *BOM) unmarshalType(t cdx.ComponentType) (core.ComponentType, error) {
	var ctype core.ComponentType
	switch t {
	case cdx.ComponentTypeContainer:
		ctype = core.TypeContainerImage
	case cdx.ComponentTypeApplication:
		ctype = core.TypeApplication
	// There are not many differences between a `library` and a `framework` components, and sometimes it is difficult to choose the right type.
	// That is why some users choose `framework` type.
	// So we should parse and scan `framework` components as libraries.
	case cdx.ComponentTypeLibrary, cdx.ComponentTypeFramework:
		ctype = core.TypeLibrary
	case cdx.ComponentTypeOS:
		ctype = core.TypeOS
	case cdx.ComponentTypePlatform:
		ctype = core.TypePlatform
	case cdx.ComponentTypeFile:
		ctype = core.TypeFilesystem
	default:
		return "", ErrUnsupportedType
	}
	return ctype, nil
}

// parsePackageLicenses checks all supported license fields and returns a list of licenses.
// https://cyclonedx.org/docs/1.5/json/#components_items_licenses
func (b *BOM) unmarshalLicenses(l *cdx.Licenses) []string {
	var licenses []string
	for _, license := range lo.FromPtr(l) {
		if license.License != nil {
			// Trivy uses `Name` field to marshal licenses
			if license.License.Name != "" {
				licenses = append(licenses, license.License.Name)
				continue
			}

			if license.License.ID != "" {
				licenses = append(licenses, license.License.ID)
				continue
			}
		}

		if license.Expression != "" {
			licenses = append(licenses, license.Expression)
			continue
		}

	}
	return licenses
}

func (b *BOM) unmarshalHashes(hashes *[]cdx.Hash) []digest.SourcedDigest {
	var digests []digest.SourcedDigest
	for _, h := range lo.FromPtr(hashes) {
		var alg digest.Algorithm
		switch h.Algorithm {
		case cdx.HashAlgoSHA1:
			alg = digest.SHA1
		case cdx.HashAlgoSHA256:
			alg = digest.SHA256
		case cdx.HashAlgoSHA512:
			alg = digest.SHA512
		case cdx.HashAlgoMD5:
			alg = digest.MD5
		default:
			log.Warn("Unsupported hash algorithm", log.String("algorithm", string(h.Algorithm)))
			continue
		}
		digests = append(digests, digest.SourcedDigest{
			Digest: digest.NewDigestFromString(alg, h.Value),
			Source: digest.SourceSBOM,
		})
	}
	return digests
}

func (b *BOM) unmarshalSupplier(supplier *cdx.OrganizationalEntity) string {
	if supplier == nil {
		return ""
	}
	return supplier.Name
}

func (b *BOM) unmarshalProperties(properties *[]cdx.Property) []core.Property {
	var props []core.Property
	for _, p := range lo.FromPtr(properties) {
		prop := core.Property{
			Value: p.Value,
		}

		// If the property has the Trivy namespace prefix, it's a Trivy property
		if name, found := strings.CutPrefix(p.Name, Namespace); found {
			prop.Name = name
			prop.External = false // Trivy property (default)
		} else {
			// External property - preserve the original name and mark as external
			prop.Name = p.Name
			prop.External = true
		}

		props = append(props, prop)
	}
	return props
}

func IsTrivySBOM(c *cdx.BOM) bool {
	if c == nil || c.Metadata == nil || c.Metadata.Tools == nil {
		return false
	}

	for _, component := range lo.FromPtr(c.Metadata.Tools.Components) {
		if component.Group == ToolVendor && component.Name == ToolName {
			return true
		}
	}

	// Metadata.Tools array is deprecated (as of CycloneDX v1.5). We check this field for backward compatibility.
	// cf. https://github.com/CycloneDX/cyclonedx-go/blob/b9654ae9b4705645152d20eb9872b5f3d73eac49/cyclonedx.go#L988
	for _, tool := range lo.FromPtr(c.Metadata.Tools.Tools) {
		if tool.Vendor == ToolVendor && tool.Name == ToolName {
			return true
		}
	}
	return false
}
