package datastore

import (
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/signatures"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	minUpdateInterval = 1 * time.Hour
)

type updater struct {
	client      *http.Client
	interval    time.Duration
	once        sync.Once
	previousKey string
	stopSig     concurrency.Signal
	url         string
}

func newUpdater() *updater {
	interval := env.RedHatSigningKeyUpdateInterval.DurationSetting()
	if interval < minUpdateInterval {
		log.Warnf("ROX_REDHAT_SIGNING_KEY_UPDATE_INTERVAL is too short, setting to the minimum duration (%v)", minUpdateInterval)
		interval = minUpdateInterval
	}

	return &updater{
		client: &http.Client{
			Transport: proxy.RoundTripper(),
			Timeout:   5 * time.Minute,
		},
		interval:    interval,
		previousKey: signatures.ReleaseKey3PublicKey,
		stopSig:     concurrency.NewSignal(),
		url:         env.RedHatSigningKeyBucketURL.Setting(),
	}
}

func (u *updater) Stop() {
	u.stopSig.Signal()
}

func (u *updater) Start() {
	u.once.Do(func() {
		go u.runForever()
	})
}

func (u *updater) runForever() {
	log.Infof("Starting to update the default Red Hat signature integration every %v", u.interval)

	// Run an initial update, to handle cases where the key was rotated but the backed-in key (pkg/signatures/release-key-3.pub.txt)
	// is still the old one. Without this, the default Red Hat signature integration would have an outdated key during
	// the first `u.interval`.
	u.doUpdate()

	t := time.NewTimer(u.interval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			u.doUpdate()
			t.Reset(u.interval)
		case <-u.stopSig.Done():
			return
		}
	}
}

func (u *updater) doUpdate() {
	if err := u.update(); err != nil {
		log.Errorf("Failed to update the default Red Hat signature integration: %v", err)
	}
}

func (u *updater) update() error {
	key, err := u.fetchPublicKey()
	if err != nil {
		return err
	}

	if key == u.previousKey {
		log.Infof("Skipping update of default Red Hat signature integration because the key has not changed")
		return nil
	}

	if err = validatePublicKey(key); err != nil {
		return errors.Wrapf(err, "validating public key from %s", u.url)
	}

	if err = u.updateKeyInSignatureIntegration(key); err != nil {
		return err
	}

	u.previousKey = key

	return nil
}

func (u *updater) fetchPublicKey() (string, error) {
	req, err := http.NewRequest(http.MethodGet, u.url, nil)
	if err != nil {
		return "", errors.Wrap(err, "constructing request")
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "executing request")
	}
	defer utils.IgnoreError(resp.Body.Close)

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("HTTP response code was %d", resp.StatusCode)
	}

	keyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "reading response body")
	}

	return string(keyBytes), nil
}

func (u *updater) updateKeyInSignatureIntegration(key string) error {
	log.Debugf("Updating Red Hat signing key in the default Red Hat signature integration")

	integration := signatures.DefaultRedHatSignatureIntegration.CloneVT()
	integration.Cosign.PublicKeys[0].PublicKeyPemEnc = key

	return upsertDefaultRedHatSignatureIntegration(siStore, integration)
}

func validatePublicKey(key string) error {
	keyBlock, rest := pem.Decode([]byte(key))
	if !signatures.IsValidPublicKeyPEMBlock(keyBlock, rest) {
		return errors.New("failed to decode PEM block containing public key")
	}
	return nil
}
