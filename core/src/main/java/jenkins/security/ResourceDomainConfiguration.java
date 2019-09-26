package jenkins.security;

import hudson.Extension;
import hudson.ExtensionList;
import hudson.util.FormValidation;
import jenkins.diagnostics.RootUrlNotSetMonitor;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.util.UrlHelper;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
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

    public String getResourceRootUrl() {
        return resourceRootUrl;
    }

    public void setResourceRootUrl(String resourceRootUrl) {
        if (doCheckResourceRootUrl(resourceRootUrl).kind == FormValidation.Kind.OK) {
            this.resourceRootUrl = resourceRootUrl;
        }
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

    public static boolean isResourceRequest(HttpServletRequest req) {
        return get().getResourceRootUrl().contains(req.getHeader("Host")); // TODO implement a proper check
    }

    public static ResourceDomainConfiguration get() {
        return ExtensionList.lookupSingleton(ResourceDomainConfiguration.class);
    }

    public FormValidation doCheckResourceRootUrl(String resourceRootUrl) {
        if (ExtensionList.lookupSingleton(RootUrlNotSetMonitor.class).isActivated()) {
            return FormValidation.warning("Can only set resource root URL if regular root URL is set");
        }
        if (!UrlHelper.isValidRootUrl(resourceRootUrl)) {
            FormValidation.warning("Not a valid URL");
        }
        return FormValidation.ok();
    }

}
