/*
 * The MIT License
 *
 * Copyright (c) Red Hat, Inc.
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
package org.jenkinsci.plugins.permissivescriptsecurity;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import hudson.util.RingBufferLogHandler;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.GroovySandbox;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PermissiveWhitelistTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void logUnsafeSignature() throws Exception {
        for (Handler handler: PermissiveWhitelist.LOGGER.getHandlers()) {
            PermissiveWhitelist.LOGGER.removeHandler(handler);
        }
        RingBufferLogHandler handler = new RingBufferLogHandler();
        PermissiveWhitelist.LOGGER.addHandler(handler);

        assertTrue(PermissiveWhitelist.enabled);
        runUnsafeScript();

        List<LogRecord> logs = handler.getView();
        assertEquals(1, logs.size());
        assertEquals("Unsecure signature found: staticMethod jenkins.model.Jenkins getInstance", logs.get(0).getMessage());

        PermissiveWhitelist.enabled = false;
        try {
            runUnsafeScript();
            fail();
        } catch (RejectedAccessException _) {
            // Expected
        }
        logs = handler.getView();
        assertEquals(1, logs.size());
    }

    private void runUnsafeScript() {
        GroovyShell shell = new GroovyShell(GroovySandbox.createSecureCompilerConfiguration());
        Script script = shell.parse("jenkins.model.Jenkins.getInstance()");
        Object ret = GroovySandbox.run(script, Whitelist.all());
        assertTrue(ret instanceof Jenkins);
    }
}
