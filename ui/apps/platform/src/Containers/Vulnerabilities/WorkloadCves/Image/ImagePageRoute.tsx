import useFeatureFlags from 'hooks/useFeatureFlags';

import ImagePage from './ImagePage';
import useVulnerabilityState from '../hooks/useVulnerabilityState';

function ImagePageRoute() {
    const vulnerabilityState = useVulnerabilityState();
    const { isFeatureFlagEnabled } = useFeatureFlags();
    const isBaseImageDetectionEnabled = isFeatureFlagEnabled('ROX_BASE_IMAGE_DETECTION');

    return (
        <ImagePage
            showVulnerabilityStateTabs
            vulnerabilityState={vulnerabilityState}
            deploymentResourceColumnOverrides={{}}
            isBaseImageDetectionEnabled={isBaseImageDetectionEnabled}
        />
    );
}

export default ImagePageRoute;
