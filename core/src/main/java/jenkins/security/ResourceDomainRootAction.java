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
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;
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

    public HttpResponse doIndex() {
        return HttpResponses.redirectTo(302, ExtensionList.lookupSingleton(ResourceDomainConfiguration.class).getResourceRootUrl());
    }

    public Object getDynamic(String id, StaplerResponse rsp) throws Exception {
        UUID uuid = UUID.fromString(id);
        if (ResourceDomainConfiguration.isResourceRequest(Stapler.getCurrentRequest())) {
            DirectoryBrowserSupportHolder holder = globalTable.lookup(uuid);
            if (holder != null) {
                return holder;
            }
        }
        rsp.sendRedirect(302, ExtensionList.lookupSingleton(ResourceDomainConfiguration.class).getResourceRootUrl());
        return null;
    }

    public static final ThreadLocal<Boolean> NOT_A_REAL_REQUEST = new ThreadLocal<>();


    /**
     *
     * @param dbs
     * @param key
     * @param permissionCheck
     * @return an identifier that can be passed as first argument into {@link #getRedirectUrl(String, String)}.
     */
    public String register(DirectoryBrowserSupport dbs, String key, Runnable permissionCheck) {
        Authentication authentication = Jenkins.getAuthentication();
        { // make sure the current user passes the permission check to begin with (detect bugs)
            try (ACLContext unused = ACL.as(authentication)) {
                permissionCheck.run();
                LOGGER.info("Passed permission check for key: " + key + " dbs: " + dbs + " as: " + authentication);
            } catch (Exception e) {
                throw new RuntimeException("Unexpected exception when testing whether the current user passes the permission check.", e);
            }
        }
        DirectoryBrowserSupportHolder holder = new DirectoryBrowserSupportHolder(key, dbs, permissionCheck, authentication, null, null, null, null);
        UUID uuid = getUrlMappingTableForCurrentSession().register(key, holder);
        globalTable.register(uuid, holder); // TODO this needs to be done in the SessionTable to not get out of sync
        LOGGER.log(Level.INFO, "Registering " + dbs + " for key: " + key + " authentication: " + authentication.getName() + " and got UUID: " + uuid.toString());
        return uuid.toString();
    }

    public String getRedirectUrl(String key, String restOfPath) {
        String rootUrl = ExtensionList.lookupSingleton(ResourceDomainConfiguration.class).getResourceRootUrl();
        if (!rootUrl.endsWith("/")) {
            rootUrl += "/";
        }
        String fullUrl = rootUrl + (getUrlName() + "/" + key + "/" + restOfPath).replace("//", "/");
        return fullUrl;
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

    public void register(DirectoryBrowserSupport dbs, StaplerRequest req) {
        String restOfPath  = req.getRestOfPath();
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
        DirectoryBrowserSupportHolder holder = new DirectoryBrowserSupportHolder(url, dbs, () -> {}, authentication, url, ac, restOfPath, root);
        UUID uuid = getUrlMappingTableForCurrentSession().register(url, holder);
        globalTable.register(uuid, holder); // TODO this needs to be done in the SessionTable to not get out of sync
        LOGGER.log(Level.INFO, "Registering " + dbs + " for key: " + url + " authentication: " + authentication.getName() + " and got UUID: " + uuid.toString());
    }

    /**
     * Implements the browsing support for a specific {@link DirectoryBrowserSupport} like permission check.
     */
    private static class DirectoryBrowserSupportHolder implements StaplerProxy, Comparable<DirectoryBrowserSupportHolder> {
        private final Runnable permissionCheck;
        private final DirectoryBrowserSupport dbs;
        private final String authentication;
        private final String key;
        private final String restOfUrl;
        private final String pathInfo;
        private final AccessControlled ac;
        private final Object root;

        /**
         *
         * @param key identifies this {@link DirectoryBrowserSupport} among others, e.g. "userContent" of "job x ws", or "job x build 5 artifacts"
         * @param dbs the {@link DirectoryBrowserSupport}
         * @param permissionCheck implements a permission check, as these URLs will bypass any other permission checks usually encountered through URLs like /job/foo/job/bar/ws.
         */
        DirectoryBrowserSupportHolder(@Nonnull String key, @Nonnull DirectoryBrowserSupport dbs, @Nonnull Runnable permissionCheck, @Nonnull Authentication authentication, String path, AccessControlled ac, String restOfUrl, Object root) {
            this.key = key;
            this.dbs = dbs;
            this.permissionCheck = permissionCheck;
            this.authentication = authentication.getName();
            this.pathInfo = path;
            this.ac = ac;
            this.restOfUrl = restOfUrl;
            this.root = root;
        }

        public HttpResponse doDynamic() {
            return this.dbs;
        }

        @Override
        public Object getTarget() {
            try (ACLContext unused = ACL.as(User.getById(authentication, false))) {
                permissionCheck.run();
            } catch (AccessDeniedException ade) {
                throw ade;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            if (ac != null) {
                NOT_A_REAL_REQUEST.set(true);
                try (ACLContext unused = ACL.as(User.getById(authentication, true))) {
                    Stapler.getCurrent().invoke(Stapler.getCurrentRequest(), Stapler.getCurrentResponse(), ac, restOfUrl);
                } catch (AccessDeniedException ade) {
                    LOGGER.log(Level.INFO, "Failed permission check", ade);
                } catch (Exception e) {
                    LOGGER.log(Level.INFO, "Something else failed", e);
                } finally {
                    NOT_A_REAL_REQUEST.set(false);
                }
            }

            return this;
        }

        @Override
        public int compareTo(DirectoryBrowserSupportHolder directoryBrowserSupportHolder) {
            return this.key.compareTo(directoryBrowserSupportHolder.key);
        }

        @Override
        public String toString() {
            return "[" + super.toString() + ", authentication=" + authentication + "; key=" + key + "; dbs=" + dbs + "; permissionCheck=" + permissionCheck + "]";
        }
    }

    /**
     * Inspired by {@link org.kohsuke.stapler.bind.BoundObjectTable}.
     */
    private static class SessionTable {
        private final Map<String, UUID> keyToUuid = new TreeMap<>();
        private final Map<UUID, DirectoryBrowserSupportHolder> uuidToHolder = new TreeMap<>();

        public UUID register(@Nonnull String key, @Nonnull  DirectoryBrowserSupportHolder holder) {
            { // logging
                LOGGER.log(Level.INFO, "keyToUuid contained for key: " + key + " the UUID: " + keyToUuid.get(key));
            }
            UUID oldUuid = keyToUuid.put(key, UUID.randomUUID());
            UUID uuid = (UUID)keyToUuid.get(key);
            { // logging
                LOGGER.log(Level.INFO, "keyToUuid contains now for key: " + key + " the UUID: " + uuid + " (" + keyToUuid.size() + " total elements)");
            }

            { // logging
                LOGGER.log(Level.INFO, "uuidToHolder contained for UUID: " + uuid + " the holder: " + uuidToHolder.get(uuid));
            }
            DirectoryBrowserSupportHolder oldHolder = uuidToHolder.putIfAbsent(uuid, holder);
            DirectoryBrowserSupportHolder newHolder = uuidToHolder.get(uuid);
            { // logging
                LOGGER.log(Level.INFO, "uuidToHolder contains now for UUID: " + uuid + " the holder: " + holder + " (" + uuidToHolder.size() + " total elements)");
            }

            if (newHolder != oldHolder) {
            }

            return uuid;
        }
    }

    /**
     * Utility class to keep a map from UUID to {@link DirectoryBrowserSupportHolder} through weak references.
     * Strong references are handled by the per-session {@link SessionTable} and therefore evicted when sessions are.
     */
    private static class GlobalTable {
        private final HashMap<UUID, WeakReference<DirectoryBrowserSupportHolder>> uuidToHolder = new HashMap<>();

        public void register(@Nonnull UUID uuid, @Nonnull DirectoryBrowserSupportHolder holder) {
            if (uuidToHolder.containsKey(uuid)) {
                // TODO leave this in or remove?
                DirectoryBrowserSupportHolder h = uuidToHolder.get(uuid).get();
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

        public @CheckForNull DirectoryBrowserSupportHolder lookup(@Nonnull UUID uuid) {
            WeakReference<DirectoryBrowserSupportHolder> reference = uuidToHolder.get(uuid);
            if (reference == null) {
                return null;
            }
            return (DirectoryBrowserSupportHolder) reference.get();
        }
    }
}
