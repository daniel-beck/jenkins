package jenkins.bugs;

import jenkins.util.io.FileBoolean;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsSessionRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertTrue;

public class LocalDataJenkinsSessionRuleTest {
    @Rule
    public JenkinsSessionRule session = new JenkinsSessionRule();

    @Test
    @LocalData
    public void testWeird() throws Throwable {
        final String name = "a";
        session.then(j -> {
            assertTrue(getFileBoolean(name).isOn());
            getFileBoolean(name).off();
            assertTrue(getFileBoolean(name).isOff());
        });
        session.then(j -> assertTrue(getFileBoolean(name).isOff()));
    }

    private FileBoolean getFileBoolean(String name) {
        return new FileBoolean(LocalDataJenkinsSessionRuleTest.class, name);
    }
}
