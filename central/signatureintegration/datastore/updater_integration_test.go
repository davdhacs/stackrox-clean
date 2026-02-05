//go:build sql_integration

package datastore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stackrox/rox/central/signatureintegration/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/protoassert"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/signatures"
	"github.com/stretchr/testify/suite"
)

// validTestPublicKey is a valid PEM-encoded public key for testing.
const validTestPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO
3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX
7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS
j+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd
OrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ
5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl
FQIDAQAB
-----END PUBLIC KEY-----`

func TestUpdaterIntegration(t *testing.T) {
	suite.Run(t, new(updaterIntegrationTestSuite))
}

type updaterIntegrationTestSuite struct {
	suite.Suite

	ctx     context.Context
	db      *pgtest.TestPostgres
	storage postgres.Store
}

func (s *updaterIntegrationTestSuite) SetupTest() {
	s.ctx = sac.WithGlobalAccessScopeChecker(context.Background(),
		sac.AllowFixedScopes(
			sac.AccessModeScopeKeys(storage.Access_READ_ACCESS, storage.Access_READ_WRITE_ACCESS),
			sac.ResourceScopeKeys(resources.Integration)))

	s.db = pgtest.ForT(s.T())
	s.storage = postgres.New(s.db)

	// Initialize siStore for the updater to use
	siStore = s.storage
}

// verifyStoredIntegration checks that the stored integration matches the expected one.
func (s *updaterIntegrationTestSuite) verifyStoredIntegration(expected *storage.SignatureIntegration) {
	s.T().Helper()
	stored, exists, err := s.storage.Get(s.ctx, expected.GetId())
	s.Require().NoError(err)
	s.Require().True(exists, "integration should exist in storage")
	protoassert.Equal(s.T(), expected, stored)
}

// verifyStoredKey checks that the stored integration has the expected public key.
func (s *updaterIntegrationTestSuite) verifyStoredKey(integrationID, expectedKey string) {
	s.T().Helper()
	stored, exists, err := s.storage.Get(s.ctx, integrationID)
	s.Require().NoError(err)
	s.Require().True(exists, "integration should exist in storage")
	s.Equal(expectedKey, stored.GetCosign().GetPublicKeys()[0].GetPublicKeyPemEnc())
}

func (s *updaterIntegrationTestSuite) TestStoredIntegrationUnchangedOnFailure() {
	// Store the default integration
	originalIntegration := signatures.DefaultRedHatSignatureIntegration
	err := upsertDefaultRedHatSignatureIntegration(s.storage, originalIntegration)
	s.Require().NoError(err)

	// Verify it's stored correctly
	s.verifyStoredIntegration(originalIntegration)

	s.Run("integration unchanged when HTTP fetch fails", func() {
		u := &updater{
			client: &http.Client{
				Timeout: 1 * time.Second,
			},
			interval:    time.Second,
			stopSig:     concurrency.NewSignal(),
			url:         "http://localhost:0", // will fail to connect
			previousKey: "different-key",      // force update attempt
		}

		err := u.update()
		s.Error(err)

		s.verifyStoredIntegration(originalIntegration)
	})

	s.Run("integration unchanged when key validation fails", func() {
		invalidKey := "not-a-valid-pem-key"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(invalidKey))
		}))
		defer server.Close()

		u := &updater{
			client: &http.Client{
				Timeout: 5 * time.Second,
			},
			interval:    time.Second,
			stopSig:     concurrency.NewSignal(),
			url:         server.URL,
			previousKey: "different-key", // force update attempt
		}

		err := u.update()
		s.Error(err)
		s.Contains(err.Error(), "validating public key")

		s.verifyStoredIntegration(originalIntegration)
	})

	s.Run("integration unchanged when server returns non-200", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		u := &updater{
			client: &http.Client{
				Timeout: 5 * time.Second,
			},
			interval:    time.Second,
			stopSig:     concurrency.NewSignal(),
			url:         server.URL,
			previousKey: "different-key",
		}

		err := u.update()
		s.Error(err)

		s.verifyStoredIntegration(originalIntegration)
	})
}

func (s *updaterIntegrationTestSuite) TestStoredIntegrationUpdatedOnSuccess() {
	// Store the default integration
	originalIntegration := signatures.DefaultRedHatSignatureIntegration
	originalKey := originalIntegration.GetCosign().GetPublicKeys()[0].GetPublicKeyPemEnc()
	err := upsertDefaultRedHatSignatureIntegration(s.storage, originalIntegration)
	s.Require().NoError(err)

	// Verify initial state
	s.verifyStoredIntegration(originalIntegration)

	// Serve a valid new key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validTestPublicKey))
	}))
	defer server.Close()

	u := &updater{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		interval:    time.Second,
		stopSig:     concurrency.NewSignal(),
		url:         server.URL,
		previousKey: originalKey,
	}

	// Update should succeed
	err = u.update()
	s.NoError(err)

	// previousKey should be updated
	s.Equal(validTestPublicKey, u.previousKey)

	// Stored integration should have the new key
	s.verifyStoredKey(originalIntegration.GetId(), validTestPublicKey)
}
