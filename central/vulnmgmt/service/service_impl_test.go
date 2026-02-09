package service

import (
	"testing"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stretchr/testify/assert"
)

func TestTransformVulnerabilityToResponse(t *testing.T) {
	t.Run("with valid CVE", func(t *testing.T) {
		vuln := &storage.EmbeddedVulnerability{
			Cve:                   "CVE-2021-1234",
			FirstSystemOccurrence: protocompat.TimestampNow(),
			FirstImageOccurrence:  protocompat.TimestampNow(),
		}

		result := transformVulnerabilityToResponse(vuln)

		assert.NotNil(t, result)
		assert.Equal(t, "CVE-2021-1234", result.Id)
		assert.NotNil(t, result.FirstSystemOccurrence)
		assert.NotNil(t, result.FirstImageOccurrence)
		assert.Nil(t, result.Suppression)
	})

	t.Run("with suppression", func(t *testing.T) {
		vuln := &storage.EmbeddedVulnerability{
			Cve:                "CVE-2021-1234",
			Suppressed:         true,
			SuppressActivation: protocompat.TimestampNow(),
			SuppressExpiry:     protocompat.TimestampNow(),
		}

		result := transformVulnerabilityToResponse(vuln)

		assert.NotNil(t, result)
		assert.Equal(t, "CVE-2021-1234", result.Id)
		assert.NotNil(t, result.Suppression)
		assert.NotNil(t, result.Suppression.SuppressActivation)
		assert.NotNil(t, result.Suppression.SuppressExpiry)
	})

	t.Run("without CVE returns nil", func(t *testing.T) {
		vuln := &storage.EmbeddedVulnerability{
			Cve:                   "",
			FirstSystemOccurrence: protocompat.TimestampNow(),
		}

		result := transformVulnerabilityToResponse(vuln)

		assert.Nil(t, result)
	})
}

func TestExtractLayerSha(t *testing.T) {
	layerShas := []string{"sha256:layer1", "sha256:layer2", "sha256:layer3"}

	t.Run("valid layer index", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			HasLayerIndex: &storage.EmbeddedImageScanComponent_LayerIndex{
				LayerIndex: 1,
			},
		}

		result := extractLayerSha(comp, layerShas)

		assert.Equal(t, "sha256:layer2", result)
	})

	t.Run("layer index out of bounds", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			HasLayerIndex: &storage.EmbeddedImageScanComponent_LayerIndex{
				LayerIndex: 10,
			},
		}

		result := extractLayerSha(comp, layerShas)

		assert.Equal(t, "", result)
	})

	t.Run("no layer index", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{}

		result := extractLayerSha(comp, layerShas)

		assert.Equal(t, "", result)
	})

	t.Run("empty layer shas", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			HasLayerIndex: &storage.EmbeddedImageScanComponent_LayerIndex{
				LayerIndex: 0,
			},
		}

		result := extractLayerSha(comp, []string{})

		assert.Equal(t, "", result)
	})
}

func TestTransformComponentToResponse(t *testing.T) {
	layerShas := []string{"sha256:layer1", "sha256:layer2"}

	t.Run("with vulnerabilities", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			Name:    "openssl",
			Version: "1.0.0",
			Location: "/usr/lib",
			HasLayerIndex: &storage.EmbeddedImageScanComponent_LayerIndex{
				LayerIndex: 0,
			},
			Vulns: []*storage.EmbeddedVulnerability{
				{
					Cve:                   "CVE-2021-1234",
					FirstSystemOccurrence: protocompat.TimestampNow(),
					FirstImageOccurrence:  protocompat.TimestampNow(),
				},
				{
					Cve:                   "CVE-2021-5678",
					FirstSystemOccurrence: protocompat.TimestampNow(),
				},
			},
		}

		result := transformComponentToResponse(comp, layerShas)

		assert.NotNil(t, result)
		assert.Equal(t, "openssl", result.Name)
		assert.Equal(t, "1.0.0", result.Version)
		assert.Equal(t, "/usr/lib", result.Location)
		assert.Equal(t, "sha256:layer1", result.LayerSha)
		assert.Len(t, result.Vulnerabilities, 2)
		assert.Equal(t, "CVE-2021-1234", result.Vulnerabilities[0].Id)
		assert.Equal(t, "CVE-2021-5678", result.Vulnerabilities[1].Id)
	})

	t.Run("no vulnerabilities returns nil", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			Name:    "openssl",
			Version: "1.0.0",
			Vulns:   []*storage.EmbeddedVulnerability{},
		}

		result := transformComponentToResponse(comp, layerShas)

		assert.Nil(t, result)
	})

	t.Run("only vulnerabilities without CVE returns nil", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			Name:    "openssl",
			Version: "1.0.0",
			Vulns: []*storage.EmbeddedVulnerability{
				{
					Cve:                   "",
					FirstSystemOccurrence: protocompat.TimestampNow(),
				},
			},
		}

		result := transformComponentToResponse(comp, layerShas)

		assert.Nil(t, result)
	})

	t.Run("mixed valid and invalid CVEs", func(t *testing.T) {
		comp := &storage.EmbeddedImageScanComponent{
			Name:    "openssl",
			Version: "1.0.0",
			Vulns: []*storage.EmbeddedVulnerability{
				{
					Cve: "",
				},
				{
					Cve: "CVE-2021-1234",
				},
				{
					Cve: "",
				},
			},
		}

		result := transformComponentToResponse(comp, layerShas)

		assert.NotNil(t, result)
		assert.Len(t, result.Vulnerabilities, 1)
		assert.Equal(t, "CVE-2021-1234", result.Vulnerabilities[0].Id)
	})
}

func TestTransformImageToResponse_Integration(t *testing.T) {
	t.Run("filters components without vulnerabilities", func(t *testing.T) {
		components := []*storage.EmbeddedImageScanComponent{
			{
				Name:    "no-vulns",
				Version: "1.0.0",
				Vulns:   []*storage.EmbeddedVulnerability{},
			},
			{
				Name:    "with-vulns",
				Version: "2.0.0",
				Vulns: []*storage.EmbeddedVulnerability{
					{Cve: "CVE-2021-1234"},
				},
			},
		}

		layerShas := []string{"sha256:layer1"}
		result := []*v1.ImageVulnerabilitiesResponse_Image_Component{}

		for _, comp := range components {
			if responseComp := transformComponentToResponse(comp, layerShas); responseComp != nil {
				result = append(result, responseComp)
			}
		}

		assert.Len(t, result, 1)
		assert.Equal(t, "with-vulns", result[0].Name)
	})
}
