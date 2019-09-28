package jenkins.security;

import hudson.Extension;
import hudson.Util;
import hudson.model.DirectoryBrowserSupport;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessControlled;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.apache.commons.codec.binary.Base64;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.*;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Root action serving {@link DirectoryBrowserSupport} instances on random URLs to support resource URLs (second domain).
 *
 * @see ResourceDomainFilter
 * @see ResourceDomainConfiguration
 *
 * @since TODO
 */
@Extension
@Restricted(NoExternalUse.class)
public class ResourceDomainRootAction implements UnprotectedRootAction {

    private static final Logger LOGGER = Logger.getLogger(ResourceDomainRootAction.class.getName());

    @CheckForNull
    @Override
    public String getIconFileName() {
        return null;
    }

    @CheckForNull
    @Override
    public String getDisplayName() {
        return null;
    }

    @CheckForNull
    @Override
    public String getUrlName() {
        return "static-files";
    }

    public void doIndex(StaplerRequest req, StaplerResponse rsp) throws IOException {
        if (!ResourceDomainConfiguration.isResourceRequest(req)) {
            rsp.sendError(404, "Cannot handle requests to this URL unless on Jenkins resource URL.");
        } else {
            rsp.sendError(404, "Jenkins serves only static files on this domain.");
        }
    }

    public Object getDynamic(String id, StaplerRequest req, StaplerResponse rsp) throws Exception {
        if (!ResourceDomainConfiguration.isResourceRequest(req)) {
            rsp.sendError(404, "Cannot handle requests to this URL unless on Jenkins resource URL.");
            return null;
        }

        String metadata = decrypt(id);
        if (metadata == null) {
            rsp.sendError(404, "Jenkins serves only static files on this domain.");
            return null;
        }

        String authenticationName = Util.fixEmpty(metadata.split(":", 2)[0]);
        String browserUrl = metadata.split(":", 2)[1];

        return new ReferenceHolder(browserUrl, authenticationName);
    }

    public String getRedirectUrl(String key, String restOfPath) {
        String rootUrl = getResourceRootUrl();
        if (!rootUrl.endsWith("/")) {
            rootUrl += "/";
        }
        return rootUrl + (getUrlName() + "/" + key + "/" + restOfPath).replace("//", "/"); // TODO clean up lazy concatenation
    }

    private static String getResourceRootUrl() {
        return ResourceDomainConfiguration.get().getResourceRootUrl();
    }

    public String register(DirectoryBrowserSupport dbs, StaplerRequest req) {
        String dbsFile = req.getRestOfPath();

        String completeUrl = req.getAncestors().get(0).getRestOfUrl();
        completeUrl = completeUrl.substring(0, completeUrl.length() - dbsFile.length());

        Authentication authentication = Jenkins.getAuthentication();
        String authenticationName = authentication == Jenkins.ANONYMOUS ? "" : authentication.getName();

        String value = authenticationName + ":" + completeUrl;
        String encrypted = encrypt(value);
        return encrypted;
    }

    /**
     * Implements the browsing support for a specific {@link DirectoryBrowserSupport} like permission check.
     */
    private static class ReferenceHolder {
        private final String authenticationName;
        private final String browserUrl;

        ReferenceHolder(@Nonnull String browserUrl, String authenticationName) {
            this.browserUrl = browserUrl;
            this.authenticationName = authenticationName;
        }

        public void doDynamic(StaplerRequest req, StaplerResponse rsp) throws IOException {
            String restOfPath = req.getRestOfPath();

            // TODO do I want something like this?
            if (restOfPath.isEmpty()) {
                String url = Jenkins.get().getRootUrl() + browserUrl;
                rsp.sendRedirect(302, url);
                return;
            }

            AccessControlled requestRoot = Jenkins.get();
            String requestUrlSuffix = this.browserUrl;

            LOGGER.log(Level.INFO, "Performing a request as authentication: " + authenticationName + " to object: " + requestRoot + " and restOfUrl: " + requestUrlSuffix + " and restOfPath: " + restOfPath);

            Authentication auth = Jenkins.ANONYMOUS;
            if (authenticationName != null) {
                User user = User.getById(authenticationName, false);
                if (user != null) {
                    auth = user.impersonate();
                }
            }

            try (ACLContext ignored = ACL.as(auth)) {
                Stapler.getCurrent().invoke(req, rsp, requestRoot, requestUrlSuffix + restOfPath);
            } catch (AccessDeniedException ade) {
                LOGGER.log(Level.INFO, "Failed permission check", ade);
                rsp.sendError(403, "Failed permission check: " + ade.getMessage());
            } catch (Exception e) {
                LOGGER.log(Level.INFO, "Something else failed", e);
                rsp.sendError(404, "Failed: " + e.getMessage());
            }
        }

        @Override
        public String toString() {
            return "[" + super.toString() + ", authentication=" + authenticationName + "; key=" + browserUrl + "]";
        }
    }

    private String encrypt(String value) {
        String encrypted = Secret.fromString(value).getEncryptedValue();
        return Base64.encodeBase64String(encrypted.getBytes());
    }

    private String decrypt(String value) {
        Secret secret = Secret.decrypt(new String(Base64.decodeBase64(value), StandardCharsets.UTF_8)); // TODO FIXME there is no confirmation that the secret is specifically from this feature
        if (secret == null) {
            return null;
        }
        return secret.getPlainText();
    }
}
