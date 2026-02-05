package datastore

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stretchr/testify/suite"
)

func TestUpdater(t *testing.T) {
	suite.Run(t, new(updaterTestSuite))
}

type updaterTestSuite struct {
	suite.Suite
}

func (s *updaterTestSuite) TestFetchPublicKey() {
	s.Run("returns key from HTTP response", func() {
		expectedKey := "-----BEGIN PUBLIC KEY-----\ntest-key-content\n-----END PUBLIC KEY-----"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.Equal(http.MethodGet, r.Method)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(expectedKey))
		}))
		defer server.Close()

		u := newTestUpdater(server.URL, time.Second)
		key, err := u.fetchPublicKey()

		s.NoError(err)
		s.Equal(expectedKey, key)
	})

	s.Run("returns error on non-200 status", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		u := newTestUpdater(server.URL, time.Second)
		key, err := u.fetchPublicKey()

		s.Error(err)
		s.Contains(err.Error(), "500")
		s.Empty(key)
	})

	s.Run("returns error on request failure", func() {
		// Use a URL that will fail to connect
		u := newTestUpdater("http://localhost:0", time.Second)
		key, err := u.fetchPublicKey()

		s.Error(err)
		s.Empty(key)
	})
}

func (s *updaterTestSuite) TestUpdate() {
	s.Run("skips update when key unchanged", func() {
		existingKey := "-----BEGIN PUBLIC KEY-----\nexisting-key\n-----END PUBLIC KEY-----"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(existingKey))
		}))
		defer server.Close()

		u := newTestUpdater(server.URL, time.Second)
		u.previousKey = existingKey

		err := u.update()

		s.NoError(err)
		s.Equal(existingKey, u.previousKey) // unchanged
	})

	s.Run("returns error on fetch failure", func() {
		u := newTestUpdater("http://localhost:0", time.Second)
		originalKey := u.previousKey

		err := u.update()

		s.Error(err)
		s.Equal(originalKey, u.previousKey) // previousKey unchanged on failure
	})

	s.Run("rejects invalid PEM key", func() {
		invalidKey := "not-a-valid-pem-key"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(invalidKey))
		}))
		defer server.Close()

		u := newTestUpdater(server.URL, time.Second)
		u.previousKey = "some-other-key" // different so update is attempted

		err := u.update()

		s.Error(err)
		s.Contains(err.Error(), "validating public key")
		s.Equal("some-other-key", u.previousKey) // previousKey unchanged on validation failure
	})

	s.Run("rejects malformed PEM key", func() {
		// Valid PEM structure but invalid content
		malformedKey := "-----BEGIN PUBLIC KEY-----\nnotbase64content!!!\n-----END PUBLIC KEY-----"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(malformedKey))
		}))
		defer server.Close()

		u := newTestUpdater(server.URL, time.Second)
		u.previousKey = "some-other-key"

		err := u.update()

		s.Error(err)
		s.Contains(err.Error(), "validating public key")
		s.Equal("some-other-key", u.previousKey) // previousKey unchanged
	})

	s.Run("rejects empty key", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(""))
		}))
		defer server.Close()

		u := newTestUpdater(server.URL, time.Second)
		u.previousKey = "some-other-key"

		err := u.update()

		s.Error(err)
		s.Equal("some-other-key", u.previousKey) // previousKey unchanged
	})
}

// newTestUpdater creates an updater configured for testing.
func newTestUpdater(serverURL string, interval time.Duration) *updater {
	return &updater{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		interval: interval,
		stopSig:  concurrency.NewSignal(),
		url:      serverURL,
	}
}
