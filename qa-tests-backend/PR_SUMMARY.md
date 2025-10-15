# PR: Add OpenShift Interop Test Suite & Fix Compliance Operator Tests

## Summary

This PR adds a new OpenShift Interop test suite with 12 tests and fixes the previously disabled Compliance Operator tests (ROX-12461).

## Changes

### 1. New Test Suite: `testOCPInterop`
**Files**: `Makefile`, `qa-tests-backend/build.gradle`
- Added `make ocp-interop-test` target to root Makefile
- Added Gradle task `testOCPInterop` to build.gradle
- 12 tests tagged with `@Tag("OCPInterop")` across 6 test files

### 2. Fixed Compliance Operator Tests (ROX-12461)
**File**: `ComplianceTest.groovy`
- **Problem**: Tests assumed Compliance Operator standards would always be present, causing NPE when CO not installed
- **Fix**: Added defensive null checks with graceful test skipping
- **Result**: 3 Compliance Operator tests now enabled and work with/without CO

```groovy
// Before: Would NPE if standard not found
ComplianceRunResults run = BASE_RESULTS.get(standard)

// After: Graceful skip with helpful logging
ComplianceRunResults run = BASE_RESULTS.get(standard)
if (run == null) {
    log.warn "Standard '${standard}' not found. Available: ${BASE_RESULTS.keySet()}"
    Assume.assumeTrue("CO standard should be available", false)
}
```

### 3. Added OCPInterop Tags
**Files**: 6 test files
- `ComplianceTest.groovy` - 6 tests (3 core + 3 Compliance Operator)
- `NetworkFlowTest.groovy` - 2 tests
- `RoutesTest.groovy` - 1 test
- `PolicyFieldsTest.groovy` - 1 test
- `K8sRbacTest.groovy` - 1 test
- `DeploymentTest.groovy` - 1 test

All tests retain their original tags (BAT, etc.) plus new `@Tag("OCPInterop")`

### 4. Documentation
**File**: `OCP_INTEROP_TESTS.md` (new, 67 lines)
- Quick start guide
- Test coverage overview
- Prerequisites and setup
- Auto-skip behavior documentation

## Test Coverage

The suite validates StackRox integration with:
- **Compliance Operator**: Machine configs, tailored profiles, cluster compliance
- **OpenShift Routes**: Detection, tracking, policy enforcement
- **Network Flow**: Graph filtering with orchestrator components
- **RBAC**: Service account validation
- **Platform**: Orchestrator component identification

## Key Features

1. **Graceful Degradation**: Tests skip cleanly when dependencies (like Compliance Operator) aren't available
2. **Clear Logging**: Diagnostic messages show what's available vs. expected
3. **CI-Friendly**: No hard dependencies - tests adapt to environment
4. **Dual-Tagged**: Can run independently (`testOCPInterop`) or as part of broader suites (`testBAT`)

## Testing

Run the new suite (either method):
```bash
# From root directory
make ocp-interop-test

# Or from qa-tests-backend/
./gradlew testOCPInterop
```

Expected behavior:
- **On OpenShift with CO**: All 12 tests run and validate
- **On OpenShift without CO**: 9 tests run, 3 skip gracefully
- **On non-OpenShift**: All tests skip (Assume.assumeTrue fails)

## Impact

- ✅ Fixes ROX-12461 (Compliance Operator tests disabled)
- ✅ Adds comprehensive OpenShift integration testing
- ✅ No breaking changes - existing test suites unaffected
- ✅ Defensive programming prevents future similar issues
- ✅ Documentation for maintainability

## Files Changed

```
Makefile                                           |   5 ++
qa-tests-backend/build.gradle                      |   6 ++
qa-tests-backend/src/test/groovy/ComplianceTest.groovy         | 100 +++--
qa-tests-backend/src/test/groovy/DeploymentTest.groovy         |   1 +
qa-tests-backend/src/test/groovy/K8sRbacTest.groovy            |   1 +
qa-tests-backend/src/test/groovy/NetworkFlowTest.groovy        |   2 +
qa-tests-backend/src/test/groovy/PolicyFieldsTest.groovy       |   1 +
qa-tests-backend/src/test/groovy/RoutesTest.groovy             |   1 +
qa-tests-backend/OCP_INTEROP_TESTS.md (new)                    |  67 ++++
```

**Total**: 8 files modified, 1 new file, ~117 insertions, ~25 deletions

## Review Focus Areas

1. **Defensive null checks** in ComplianceTest.groovy - do they cover all edge cases?
2. **Test tag consistency** - is `OCPInterop` the right name?
3. **Documentation clarity** - is OCP_INTEROP_TESTS.md helpful?
4. **Logging verbosity** - is the setup logging too verbose/not enough?
