package jenkins.diagnostics;

import hudson.Main;
import org.apache.commons.jelly.Script;
import org.apache.commons.jelly.impl.ExpressionScript;
import org.apache.commons.jelly.impl.ScriptBlock;
import org.apache.commons.jelly.impl.TagScript;
import org.kohsuke.stapler.jelly.ReallyStaticTagLibrary;

import java.util.logging.Level;
import java.util.logging.Logger;

public class StaticJellyListener implements ReallyStaticTagLibrary.Listener {
    private static final Logger LOGGER = Logger.getLogger(StaticJellyListener.class.getName());

    @Override
    public void onRun(final TagScript tagScript) {
        if (ENABLE_LOGGING == Boolean.FALSE) {
            return;
        }
        final Script tagBody = tagScript.getTagBody();
        if (!tagScript.getLocalName().equals("script") || !(tagBody instanceof ScriptBlock)) {
            return;
        }
        final String safe = tagScript.getSaxAttributes().getValue("data-evaluated-xss-safe");
        if (safe != null && safe.equals("true")) {
            return;
        }
        ScriptBlock block = (ScriptBlock) tagBody;
        for (Object o : block.getScriptList()) {
            if (!(o instanceof ExpressionScript)) {
                // this isn't an expression
                continue;
            }
            final String fileName = tagScript.getFileName();
            if (ENABLE_LOGGING == Boolean.TRUE || fileName.startsWith("file:")) {
                final String needle = "src/main/resources";
                String shortFileName = fileName.contains(needle) ? fileName.substring(fileName.indexOf(needle) + needle.length()) : fileName;
                // file: is a component being debugged, jar:file: would be elsewhere
                LOGGER.log(Level.INFO, () -> "Script tag in file: " + fileName + " on line: " + tagScript.getLineNumber() + " contains an expression that is a potential XSS vulnerability: " + ((ExpressionScript) o).getExpression().getExpressionText());
            }
        }
    }


    /**
     * Tri-state: Boolean true and false enable and disable logging respectively, while {@code null} (the default during development) logs only "file" resources.
     */
    private static /* non-final for Groovy */ Boolean ENABLE_LOGGING = Main.isDevelopmentMode ? null : false;
}
