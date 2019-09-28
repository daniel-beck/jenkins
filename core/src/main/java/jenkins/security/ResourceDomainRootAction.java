package jenkins.security;

import hudson.Extension;
import hudson.Util;
import hudson.model.DirectoryBrowserSupport;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessControlled;
import jenkins.model.Jenkins;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.*;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.TimeUnit;
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

        String authenticationName = Util.fixEmpty(metadata.split(":", 3)[0]);
        String epoch = Util.fixEmpty(metadata.split(":", 3)[1]);
        String browserUrl = metadata.split(":", 3)[2];

        long creationDate = Long.parseLong(epoch);
        long age = new Date().getTime() - creationDate; // TODO check for negative age?

        if (age < TimeUnit.MINUTES.toMillis(2)) { // TODO Use HOURS, minutes is only for testing
            return new ReferenceHolder(browserUrl, authenticationName);
        }

        // too old, so redirect to the real file first
        return new Redirection(browserUrl);
    }

    private static class Redirection {
        private final String url;

        public Redirection(String url) {
            this.url = url;
        }

        public void doDynamic(StaplerRequest req, StaplerResponse rsp) throws IOException {
            String restOfPath = req.getRestOfPath();

            String url = Jenkins.get().getRootUrl() + this.url + restOfPath;
            rsp.sendRedirect(302, url);
        }
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

        Date date = new Date();

        String value = authenticationName + ":" + date.getTime() + ":" + completeUrl;
        try {
            return encrypt(value);
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, "Failed to encrypt " + value, ex);
        }
        return null;
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

    private String encrypt(String value) throws Exception {
        byte[] iv = KEY.newIv();
        Cipher cipher = KEY.encrypt(iv);
        byte[] bytes = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));

        return Util.toHexString(iv) + "_" + Util.toHexString(bytes);
    }

    private String decrypt(String value) {
        try {
            byte[] iv = Util.fromHexString(value.substring(0, value.indexOf("_")));
            byte[] encrypted = Util.fromHexString(value.substring(value.indexOf("_") + 1));
            Cipher cipher = KEY.decrypt(iv);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            LOGGER.log(Level.FINE, "Failure decrypting", ex);
            return null;
        }
    }

    private static CryptoConfidentialKey KEY = new CryptoConfidentialKey(ResourceDomainRootAction.class, "key");
}
