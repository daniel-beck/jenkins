package jenkins.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.console.ExpandableDetailsNote;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import jenkins.tasks.SimpleBuildStep;
import org.htmlunit.html.HtmlPage;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

public class Security3245Test {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Issue("SECURITY-3245")
    @Test
    public void captionCannotAttributeEscape() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject("p");
        p.getBuildersList().add(new ExpandableDetailsNoteTestAction("' onclick=alert(1) foo='bar", "<h1></h1>"));
        FreeStyleBuild build = j.buildAndAssertSuccess(p);

        AtomicBoolean alerts = new AtomicBoolean();
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            wc.setAlertHandler((pr, s) -> alerts.set(true));
            final HtmlPage page = wc.goTo(build.getUrl() + "console");
            String content = page.getWebResponse().getContentAsString();
            assertThat(content, containsString("<input type=button value='&#39; onclick=alert(1) foo=&#39;bar' class='reveal-expandable-detail'>"));

            // Execute JavaScript code to simulate click event
            String jsCode = "document.querySelector('.reveal-expandable-detail').dispatchEvent(new MouseEvent('click'));";
            page.executeJavaScript(jsCode);

            Assert.assertFalse("Alert not expected", alerts.get());
        }
    }

    static class ExpandableDetailsNoteTestAction extends Builder implements SimpleBuildStep {

        final String caption;
        final String html;

        ExpandableDetailsNoteTestAction(String caption, String html) {
            this.caption = caption;
            this.html = html;
        }

        @Override
        public void perform(@NonNull Run<?, ?> run, @NonNull FilePath workspace, @NonNull EnvVars env, @NonNull Launcher launcher, @NonNull TaskListener listener) throws IOException {
            listener.annotate(new ExpandableDetailsNote(caption, html));
        }
    }
}
