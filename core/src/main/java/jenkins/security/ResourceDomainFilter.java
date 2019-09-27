package jenkins.security;

import hudson.init.Initializer;
import hudson.util.PluginServletFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Prohibit requests to Jenkins coming through a resource domain URL configured with {@link ResourceDomainConfiguration},
 * except anything going to {@link ResourceDomainRootAction}.
 *
 * @since TODO
 */
public class ResourceDomainFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(ResourceDomainFilter.class.getName());

    @Initializer
    public static void init() throws ServletException {
        PluginServletFilter.addFilter(new ResourceDomainFilter());
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (servletRequest instanceof HttpServletRequest) {
            HttpServletRequest httpServletRequest = (HttpServletRequest)servletRequest;
            HttpServletResponse httpServletResponse = (HttpServletResponse)servletResponse;
            String path = httpServletRequest.getPathInfo();
            if (ResourceDomainConfiguration.isResourceRequest(httpServletRequest) && !path.startsWith("/static-files/") && !path.equals("/static-files")) {
                LOGGER.log(Level.FINE, "Rejecting request to " + httpServletRequest.getRequestURL() + " from " + httpServletRequest.getRemoteAddr() + " on resource domain");
                httpServletResponse.sendError(404, "Jenkins serves only static files on this domain.");
                return;
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void destroy() {

    }
}
