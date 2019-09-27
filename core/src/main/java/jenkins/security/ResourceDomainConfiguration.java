package jenkins.security;

import hudson.Extension;
import hudson.ExtensionList;
import hudson.Util;
import hudson.util.FormValidation;
import jenkins.diagnostics.RootUrlNotSetMonitor;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.util.UrlHelper;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

/**
 * Configure the resource root URL, an alternative root URL to serve resources from to not need Content-Security-Policy
 * headers, which mess with desired complex output.
 *
 * @since TODO
 */
@Extension
@Restricted(NoExternalUse.class)
public class ResourceDomainConfiguration extends GlobalConfiguration {

    private String resourceRootUrl;

    public ResourceDomainConfiguration() {
        load();
    }

    @Nonnull
    @Override
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        save();
        return true;
    }

    public FormValidation doCheckResourceRootUrl(@QueryParameter String resourceRootUrl) {
        if (ExtensionList.lookupSingleton(RootUrlNotSetMonitor.class).isActivated()) {
            // TODO is this really a prerequisite?
            return FormValidation.warning("Can only set resource root URL if regular root URL is set."); // TODO i18n
        }

        resourceRootUrl = Util.fixEmptyAndTrim(resourceRootUrl);
        if (resourceRootUrl == null) {
            return FormValidation.ok("Without a resource root URL, resources will be served from the main domain with Content-Security-Policy set."); // TODO i18n
        }

        if (!UrlHelper.isValidRootUrl(resourceRootUrl)) {
            return FormValidation.warning("Not a valid URL"); // TODO i18n
        }
        return FormValidation.ok();
    }

    public String getResourceRootUrl() {
        return resourceRootUrl;
    }

    public void setResourceRootUrl(String resourceRootUrl) {
        if (doCheckResourceRootUrl(resourceRootUrl).kind == FormValidation.Kind.OK) {
            // only accept valid configurations
            this.resourceRootUrl = resourceRootUrl;
            // TODO clear existing cached URLs when clearing the second domain?
        }
    }

    public static boolean isResourceRequest(HttpServletRequest req) {
        return isResourceDomainConfigured() && get().getResourceRootUrl().contains(req.getHeader("Host")); // TODO implement a proper check
    }

    public static boolean isResourceDomainConfigured() {
        String resourceRootUrl = get().getResourceRootUrl();
        return resourceRootUrl != null && !resourceRootUrl.isEmpty();
    }

    public static ResourceDomainConfiguration get() {
        return ExtensionList.lookupSingleton(ResourceDomainConfiguration.class);
    }
}
