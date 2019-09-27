package jenkins.security;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import hudson.model.DirectoryBrowserSupport;

@Extension
public class ResourceDomainRecommendation extends AdministrativeMonitor {
    @Override
    public boolean isActivated() {
        boolean isResourceRootUrlSet = ResourceDomainConfiguration.get().getResourceRootUrl() != null;
        boolean isOverriddenCSP = System.getProperty(DirectoryBrowserSupport.class + ".CSP") != null;
        return isOverriddenCSP && isResourceRootUrlSet;
    }
}
