/*
 * The MIT License
 *
 * Copyright (c) 2026, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package jenkins.core;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.servlet.ServletContext;
import java.io.File;
import java.io.FilenameFilter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * ClassLoader for internal Jenkins libraries that should be isolated from plugin classpaths.
 *
 * <p>This classloader loads JARs from {@code WEB-INF/core-lib/}.
 */
@Restricted(NoExternalUse.class)
public class CoreLibClassLoader extends URLClassLoader {

    private static final Logger LOGGER = Logger.getLogger(CoreLibClassLoader.class.getName());
    private static final FilenameFilter JAR_FILTER = (dir, name) -> name.endsWith(".jar");

    /**
     * Creates a new CoreLibClassLoader.
     *
     * @param urls URLs to load
     * @param parent parent classloader
     */
    private CoreLibClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, parent);
        LOGGER.log(Level.CONFIG, "CoreLibClassLoader initialized with {0} JARs", urls.length);
        for (URL url : urls) {
            LOGGER.log(Level.CONFIG, "  - {0}", url);
        }
    }

    /**
     * Initializes the CoreLibClassLoader for internal libraries isolated from plugins.
     *
     * @param context the servlet context
     * @param parent the parent classloader
     * @return the CoreLibClassLoader
     * @throws java.lang.IllegalStateException when the {@code WEB-INF/core-lib} dir is not found or empty
     * @since TODO
     */
    @NonNull
    @SuppressFBWarnings(value = "PATH_TRAVERSAL_IN", justification = "WEB-INF is not attacker-controlled")
    public static CoreLibClassLoader initialize(ServletContext context, ClassLoader parent) {
        String realPath = context.getRealPath("/WEB-INF/core-lib");
        if (realPath == null) {
            throw new IllegalStateException("Could not look up real path for WEB-INF/core-lib, failed to initialize CoreLibClassLoader");
        }

        File coreLibDir =  new File(realPath);
        if (!coreLibDir.isDirectory()) {
            throw new IllegalStateException("WEB-INF/core-lib is not a directory, failed to initialize CoreLibClassLoader: " + coreLibDir.getAbsolutePath());
        }

        List<URL> urls = new ArrayList<>();
        File[] jars = coreLibDir.listFiles(JAR_FILTER);
        if (jars == null || jars.length == 0) {
            throw new IllegalStateException("WEB-INF/core-lib empty, failed to initialize CoreLibClassLoader: " + coreLibDir.getAbsolutePath());
        }
        for (File jar : Arrays.stream(jars).sorted().toList()) {
            try {
                urls.add(jar.toURI().toURL());
            } catch (MalformedURLException e) {
                LOGGER.log(Level.WARNING, "Failed to add core-lib JAR: " + jar, e);
            }
        }

        LOGGER.log(Level.CONFIG, "CoreLibClassLoader initialized from {0}", coreLibDir);
        return new CoreLibClassLoader(urls.toArray(new URL[0]), parent);
    }
}
