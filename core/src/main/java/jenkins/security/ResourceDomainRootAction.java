package jenkins.security;

import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.DirectoryBrowserSupport;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessControlled;
import hudson.util.HttpResponses;
import jenkins.model.Jenkins;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.*;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
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

    private GlobalTable globalTable = new GlobalTable();

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

        UUID uuid;
        try {
            uuid = UUID.fromString(id);
        } catch (IllegalArgumentException ex) {
            // not a UUID
            rsp.sendError(404, "Jenkins serves only static files on this domain.");
            return null;
        }

        ReferenceHolder holder = globalTable.lookup(uuid);
        if (holder != null) {
            return holder;
        }

        rsp.sendRedirect(302, getResourceRootUrl());
        return null;
    }

    public String getRedirectUrl(String key, String restOfPath) {
        String rootUrl = getResourceRootUrl();
        if (!rootUrl.endsWith("/")) {
            rootUrl += "/";
        }
        String fullUrl = rootUrl + (getUrlName() + "/" + key + "/" + restOfPath).replace("//", "/"); // TODO clean up lazy concatenation
        return fullUrl;
    }

    private static String getResourceRootUrl() {
        return ResourceDomainConfiguration.get().getResourceRootUrl();
    }

    public String register(DirectoryBrowserSupport dbs, StaplerRequest req) {
        String restOfPath  = req.getRestOfPath();
        String dbsFile = req.getRestOfPath();
        String url = req.getAncestors().get(0).getRestOfUrl();
        List<Ancestor> ancestors = req.getAncestors();
        Object root = ancestors.get(0).getObject();
        AccessControlled ac = null;

        // find nearest ancestor that's AccessControlled
        for (Ancestor ancestor : ancestors) {
            Object o = ancestor.getObject();
            if (o instanceof AccessControlled) {
                ac = (AccessControlled)o;
                restOfPath = ancestor.getRestOfUrl();
            }
        }


        Authentication authentication = Jenkins.getAuthentication();
        ReferenceHolder holder = new ReferenceHolder(url, authentication, url, ac, restOfPath, root, dbsFile);
        UUID uuid = getUrlMappingTableForCurrentSession().register(url, holder);
        globalTable.register(uuid, holder); // TODO this needs to be done in the SessionTable to not get out of sync
        LOGGER.log(Level.INFO, "Registering " + dbs + " for key: " + url + " authentication: " + authentication.getName() + " and got UUID: " + uuid.toString());

        return uuid.toString();
    }

    /**
     * Implements the browsing support for a specific {@link DirectoryBrowserSupport} like permission check.
     */
    private static class ReferenceHolder {
        private final String authenticationName;
        private final String browserUrl;
        private final String restOfUrl;
        private final String pathInfo;
        private final WeakReference<AccessControlled> ac;
        private final Object root;

        ReferenceHolder(@Nonnull String browserUrl, @Nonnull Authentication authenticationName, String path, AccessControlled ac, String restOfUrl, Object root, String dbsFile) {
            this.browserUrl = browserUrl.substring(0, restOfUrl.length() - dbsFile.length());
            if (authenticationName == Jenkins.ANONYMOUS) {
                this.authenticationName = null;
            } else {
                this.authenticationName = authenticationName.getName();
            }
            this.pathInfo = path;
            this.ac = new WeakReference<>(ac);
            this.restOfUrl = restOfUrl.substring(0, restOfUrl.length() - dbsFile.length());
            this.root = root;
        }

        public void doDynamic(StaplerRequest req, StaplerResponse rsp) throws IOException {
            AccessControlled ac = this.ac.get();

            if (ac == null) {
                // TODO redirect to 'browserUrl'
                rsp.sendError(404, "Resource expired");
            }

            String restOfPath = req.getRestOfPath();

            // TODO do I want something like this?
            if (restOfPath.isEmpty()) {
                String url = Jenkins.get().getRootUrl() + browserUrl;
                LOGGER.log(Level.INFO, "Forwarding a request as authentication: " + authenticationName + " to object: " + ac + " and restOfUrl: " + restOfUrl + " and restOfPath: " + restOfPath + " to url: " + url);
                rsp.sendRedirect(302, url);
                return;
            }

            LOGGER.log(Level.INFO, "Performing a request as authentication: " + authenticationName + " to object: " + ac + " and restOfUrl: " + restOfUrl + " and restOfPath: " + restOfPath);

            Authentication auth = Jenkins.ANONYMOUS;
            if (authenticationName != null) {
                User user = User.getById(authenticationName, false);
                if (user != null) {
                    auth = user.impersonate();
                }
            }

            try (ACLContext unused = ACL.as(auth)) {
                Stapler.getCurrent().invoke(req, rsp, ac, restOfUrl + restOfPath);
            } catch (AccessDeniedException ade) {
                LOGGER.log(Level.INFO, "Failed permission check", ade);
                rsp.sendError(403, "Failed permission check: " + ade.getMessage());
                return;
            } catch (Exception e) {
                LOGGER.log(Level.INFO, "Something else failed", e);
                rsp.sendError(404, "Failed: " + e.getMessage());
                return;
            }
        }

        @Override
        public String toString() {
            return "[" + super.toString() + ", authentication=" + authenticationName + "; key=" + browserUrl + "]";
        }
    }


    /**
     * URL Mapping for the current HTTP session
     *
     * @return
     */
    private static SessionTable getUrlMappingTableForCurrentSession() {
        HttpSession session = Stapler.getCurrentRequest().getSession(true);

        synchronized (session) {
            SessionTable table = (SessionTable) session.getAttribute(SessionTable.class.getName());
            if (table == null) {
                SessionTable sessionTable = new SessionTable();
                session.setAttribute(SessionTable.class.getName(), table = sessionTable);
                LOGGER.log(Level.INFO, "Setting a new SessionTable for " + session + ": " + sessionTable);
            }
            return table;
        }
    }

    /**
     * Inspired by {@link org.kohsuke.stapler.bind.BoundObjectTable}.
     */
    private static class SessionTable {
        private final Map<String, UUID> keyToUuid = new TreeMap<>();
        private final Map<UUID, ReferenceHolder> uuidToHolder = new TreeMap<>();

        public UUID register(@Nonnull String key, @Nonnull ReferenceHolder holder) {
            { // logging
                LOGGER.log(Level.INFO, "keyToUuid contained for key: " + key + " the UUID: " + keyToUuid.get(key));
            }
            // TODO better determine whether a holder needs to be updated for a given key, e.g. after project renames
            keyToUuid.putIfAbsent(key, UUID.randomUUID());
            UUID uuid = keyToUuid.get(key);
            { // logging
                LOGGER.log(Level.INFO, "keyToUuid contains now for key: " + key + " the UUID: " + uuid + " (" + keyToUuid.size() + " total elements)");
            }

            { // logging
                LOGGER.log(Level.INFO, "uuidToHolder contained for UUID: " + uuid + " the holder: " + uuidToHolder.get(uuid));
            }
            ReferenceHolder oldHolder = uuidToHolder.putIfAbsent(uuid, holder);
            ReferenceHolder newHolder = uuidToHolder.get(uuid);
            { // logging
                LOGGER.log(Level.INFO, "uuidToHolder contains now for UUID: " + uuid + " the holder: " + holder + " (" + uuidToHolder.size() + " total elements)");
            }

            return uuid;
        }
    }

    /**
     * Utility class to keep a map from UUID to {@link ReferenceHolder} through weak references.
     * Strong references are handled by the per-session {@link SessionTable} and therefore evicted when sessions are.
     */
    private static class GlobalTable {
        private final HashMap<UUID, WeakReference<ReferenceHolder>> uuidToHolder = new HashMap<>();

        public void register(@Nonnull UUID uuid, @Nonnull ReferenceHolder holder) {
            if (uuidToHolder.containsKey(uuid)) {
                // TODO leave this in or remove?
                ReferenceHolder h = uuidToHolder.get(uuid).get();
                if (h == null) {
                    LOGGER.log(Level.INFO, "Re-registering for UUID " + uuid + " which was expired");
                } else {
                    LOGGER.log(Level.WARNING, "Re-registering for UUID " + uuid + " which was NOT expired and pointed to " + h);
                }
            } else {
                LOGGER.log(Level.INFO, "Registering for UUID " + uuid + " which was unknown before");
            }
            uuidToHolder.putIfAbsent(uuid, new WeakReference<>(holder));
            LOGGER.log(Level.INFO, "Global table now contains " + uuidToHolder.size() + " entries");
        }

        public @CheckForNull
        ReferenceHolder lookup(@Nonnull UUID uuid) {
            WeakReference<ReferenceHolder> reference = uuidToHolder.get(uuid);
            if (reference == null) {
                return null;
            }
            return reference.get();
        }
    }
}
