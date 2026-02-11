package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeCentralDefaultsIntoSpec(t *testing.T) {
	tests := map[string]struct {
		before *Central
		after  *Central
	}{
		"empty": {
			before: &Central{},
			after:  &Central{},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			central := tt.before.DeepCopy()
			require.NoError(t, MergeCentralDefaultsIntoSpec(central))
			require.Equal(t, tt.after, central)
		})
	}
}
