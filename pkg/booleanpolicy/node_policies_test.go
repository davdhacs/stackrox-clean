package booleanpolicy

import (
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy/fieldnames"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stretchr/testify/suite"
)

type NodeDetectionTestSuite struct {
	suite.Suite
}

func TestNodeDetection(t *testing.T) {
	suite.Run(t, new(NodeDetectionTestSuite))
}

func (s *NodeDetectionTestSuite) TestNodeFileAccess() {
	node := &storage.Node{
		Name: "test-node-1",
		Id:   "test-node-1",
	}

	type eventWrapper struct {
		access      *storage.FileAccess
		expectAlert bool
	}

	for _, tc := range []struct {
		description string
		policy      *storage.Policy
		events      []eventWrapper
	}{
		{
			description: "Node file open policy with matching event",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN}, false,
				"/etc/passwd",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file open policy with mismatching event (UNLINK)",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN}, false,
				"/etc/passwd",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_UNLINK),
					expectAlert: false,
				},
			},
		},
		{
			description: "Node file open policy with mismatching event (/tmp/foo)",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN}, false,
				"/etc/passwd",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/tmp/foo", storage.FileAccess_OPEN),
					expectAlert: false,
				},
			},
		},
		{
			description: "Node file policy with negated file operation",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN}, true,
				"/etc/passwd",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: false, // open is the only event we should ignore
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_UNLINK),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_CREATE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OWNERSHIP_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_PERMISSION_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_RENAME),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file policy with multiple operations",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN, storage.FileAccess_CREATE}, false,
				"/etc/passwd",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_CREATE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_RENAME),
					expectAlert: false,
				},
			},
		},
		{
			description: "Node file policy with multiple negated operations",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN, storage.FileAccess_CREATE}, true,
				"/etc/passwd",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: false,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_CREATE),
					expectAlert: false,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OWNERSHIP_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_PERMISSION_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_UNLINK),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_RENAME),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file policy with multiple files and single operation",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN}, false,
				"/etc/passwd", "/etc/shadow",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/shadow", storage.FileAccess_OPEN),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file policy with multiple files and multiple operations",
			policy: s.getNodeFileAccessPolicyWithOperations(
				fieldnames.ActualPath,
				[]storage.FileAccess_Operation{storage.FileAccess_OPEN, storage.FileAccess_CREATE}, false,
				"/etc/passwd", "/etc/shadow",
			),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_CREATE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/shadow", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/shadow", storage.FileAccess_CREATE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/tmp/foo", storage.FileAccess_CREATE),
					expectAlert: false,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/tmp/foo", storage.FileAccess_OPEN),
					expectAlert: false,
				},
			},
		},
		{
			description: "Node file policy actual path with no operations",
			policy:      s.getNodeFileAccessPolicyActualPath("/etc/passwd"),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_CREATE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OWNERSHIP_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_PERMISSION_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_UNLINK),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_RENAME),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file policy actual path with all allowed files",
			policy:      s.getNodeFileAccessPolicyActualPath("/etc/passwd", "/etc/ssh/sshd_config", "/etc/shadow", "/etc/sudoers"),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/shadow", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/ssh/sshd_config", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.ActualPath, "/etc/sudoers", storage.FileAccess_OPEN),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file policy effective path with all allowed files",
			policy:      s.getNodeFileAccessPolicyEffectivePath("/etc/passwd", "/etc/ssh/sshd_config", "/etc/shadow", "/etc/sudoers"),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/shadow", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/ssh/sshd_config", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/sudoers", storage.FileAccess_OPEN),
					expectAlert: true,
				},
			},
		},
		{
			description: "Node file policy effective path with no operations",
			policy:      s.getNodeFileAccessPolicyEffectivePath("/etc/passwd"),
			events: []eventWrapper{
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_OPEN),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_CREATE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_OWNERSHIP_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_PERMISSION_CHANGE),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_UNLINK),
					expectAlert: true,
				},
				{
					access:      s.getNodeFileAccessEvent(fieldnames.EffectivePath, "/etc/passwd", storage.FileAccess_RENAME),
					expectAlert: true,
				},
			},
		},
	} {
		testutils.MustUpdateFeature(s.T(), features.SensitiveFileActivity, true)
		defer testutils.MustUpdateFeature(s.T(), features.SensitiveFileActivity, false)
		ResetFieldMetadataSingleton(s.T())
		defer ResetFieldMetadataSingleton(s.T())

		s.Run(tc.description, func() {
			matcher, err := BuildNodeEventMatcher(tc.policy)
			s.Require().NoError(err)

			for _, event := range tc.events {
				var cache CacheReceptacle
				violations, err := matcher.MatchNodeWithFileAccess(&cache, node, event.access)
				s.Require().NoError(err)

				if event.expectAlert {
					s.Require().Len(violations.AlertViolations, 1, "expected one file access violation in alert")
					s.Require().Equal(storage.Alert_Violation_FILE_ACCESS, violations.AlertViolations[0].GetType(), "expected FILE_ACCESS type")

					fileAccess := violations.AlertViolations[0].GetFileAccess()
					s.Require().NotNil(fileAccess, "expected file access info")

					// Verify the file access details match
					s.Require().Equal(event.access.GetFile().GetEffectivePath(), fileAccess.GetFile().GetEffectivePath())
					s.Require().Equal(event.access.GetFile().GetActualPath(), fileAccess.GetFile().GetActualPath())
					s.Require().Equal(event.access.GetOperation(), fileAccess.GetOperation())
				} else {
					s.Require().Empty(violations.AlertViolations, "expected no alerts")
				}
			}
		})
	}
}

func (s *NodeDetectionTestSuite) getNodeFileAccessEvent(field string, path string, operation storage.FileAccess_Operation) *storage.FileAccess {

	file := &storage.FileAccess_File{}
	switch field {
	case fieldnames.ActualPath:
		file.ActualPath = path
	case fieldnames.EffectivePath:
		file.EffectivePath = path
	default:
		panic("invalid field name")
	}

	return &storage.FileAccess{
		File:      file,
		Operation: operation,
	}
}

func (s *NodeDetectionTestSuite) getNodeFileAccessPolicyWithOperations(pathField string, operations []storage.FileAccess_Operation, negate bool, paths ...string) *storage.Policy {
	policy := s.getNodeFileAccessPolicyForPathType(pathField, paths...)

	var operationValues []*storage.PolicyValue
	for _, op := range operations {
		operationValues = append(operationValues, &storage.PolicyValue{
			Value: op.String(),
		})
	}

	groups := policy.GetPolicySections()[0].GetPolicyGroups()
	groups = append(groups, &storage.PolicyGroup{
		FieldName: fieldnames.FileOperation,
		Values:    operationValues,
		Negate:    negate,
	})

	policy.GetPolicySections()[0].PolicyGroups = groups

	return policy
}

func (s *NodeDetectionTestSuite) getNodeFileAccessPolicyActualPath(paths ...string) *storage.Policy {
	return s.getNodeFileAccessPolicyForPathType(fieldnames.ActualPath, paths...)
}

func (s *NodeDetectionTestSuite) getNodeFileAccessPolicyEffectivePath(paths ...string) *storage.Policy {
	return s.getNodeFileAccessPolicyForPathType(fieldnames.EffectivePath, paths...)
}

func (s *NodeDetectionTestSuite) getNodeFileAccessPolicyForPathType(fieldname string, paths ...string) *storage.Policy {
	var policyValues []*storage.PolicyValue
	for _, path := range paths {
		policyValues = append(policyValues, &storage.PolicyValue{
			Value: path,
		})
	}

	return &storage.Policy{
		Id:            uuid.NewV4().String(),
		PolicyVersion: "1.1",
		Name:          "Sensitive File Access on Node",
		Severity:      storage.Severity_HIGH_SEVERITY,
		Categories:    []string{"File System"},
		PolicySections: []*storage.PolicySection{
			{
				SectionName: "section 1",
				PolicyGroups: []*storage.PolicyGroup{
					{
						FieldName: fieldname,
						Values:    policyValues,
					},
				},
			},
		},
		LifecycleStages: []storage.LifecycleStage{storage.LifecycleStage_RUNTIME},
		EventSource:     storage.EventSource_NODE_EVENT,
	}
}
