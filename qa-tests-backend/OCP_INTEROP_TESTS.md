# OpenShift Interop Test Suite

Tests for StackRox integration with OpenShift-specific features and operators.

## Quick Start

```bash
# From root directory
make ocp-interop-test

# Or from qa-tests-backend/
./gradlew testOCPInterop
```

## What's Tested

- **Compliance Operator** (6 tests) - Compliance scans, machine configs, tailored profiles
- **OpenShift Routes** (2 tests) - Route detection and policy enforcement
- **Network Flow** (2 tests) - Network graph with orchestrator components
- **RBAC** (1 test) - Service account validation
- **Deployments** (1 test) - Orchestrator component identification

**Total: 12 tests across 6 files**

## Prerequisites

- OpenShift 4.x cluster with StackRox deployed
- Environment variables configured (see CLAUDE.md)
- **Optional**: Compliance Operator (tests auto-skip if not installed)

## Test Details

### Compliance Tests (6 tests)
- Static compliance checks (TLS, network visibility, risk assessment)
- Compliance result aggregation across standards
- Error state validation
- **Compliance Operator Integration** (auto-skips if not installed):
  - Machine config compliance (ocp4-cis-node, rhcos4-moderate, rhcos4-moderate-modified)
  - Tailored profile validation
  - Cluster-level compliance (ocp4-cis)

### Network & Routes (4 tests)
- Network graph filtering with orchestrator components
- Network flow detection between deployments
- Route detection and tracking
- Route exposure policy enforcement

### Platform Integration (2 tests)
- Service account scraping and validation
- Orchestrator component identification (apiserver, console)

## Key Features

- **Auto-skip on non-OpenShift**: Tests use `Assume.assumeTrue(ClusterService.isOpenShift4())`
- **Graceful Compliance Operator handling**: Tests skip with clear logging if CO not installed
- **Dual-tagged**: Tests have both `@Tag("OCPInterop")` and original tags (e.g., `@Tag("BAT")`)

## Recent Fixes

- **ROX-12461**: Compliance Operator tests now handle missing CO gracefully (auto-skip with logging)
- Tests work reliably with or without Compliance Operator installed

## Future Expansion

Additional OpenShift operator integrations to consider:
- Monitoring Operator (Prometheus/Grafana)
- Logging Operator
- Service Mesh Operator
- Cert Manager
- GitOps/Pipelines operators
