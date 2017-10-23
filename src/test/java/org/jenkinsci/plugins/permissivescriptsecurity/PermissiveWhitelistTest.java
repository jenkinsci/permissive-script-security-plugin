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

import groovy.lang.Binding;
import hudson.util.RingBufferLogHandler;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.permissivescriptsecurity.PermissiveWhitelist.Mode;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.jenkinsci.plugins.scriptsecurity.scripts.ApprovalContext;
import org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PermissiveWhitelistTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void logUnsafeSignatureInPermissiveMode() throws Exception {
        RingBufferLogHandler handler = injectLogHandler();
        assertEquals("Permissive whitelisting should be disabled by default", Mode.DISABLED, PermissiveWhitelist.MODE);

        try {
            runScript("System.exit(42)");
            fail();
        } catch (RejectedAccessException _) {
            // Expected
        }

        Set<ScriptApproval.PendingSignature> pendingSignatures = ScriptApproval.get().getPendingSignatures();
        assertEquals(pendingSignatures.toString(), 1, pendingSignatures.size());

        List<LogRecord> logs = handler.getView();
        assertEquals(0, logs.size());

        PermissiveWhitelist.MODE = Mode.ENABLED;
        try {
            Object ret = runScript("jenkins.model.Jenkins.getInstance()");
            assertTrue(ret instanceof Jenkins);

            logs = handler.getView();
            assertEquals(1, logs.size());
            assertEquals("Unsecure signature found: staticMethod jenkins.model.Jenkins getInstance", logs.get(0).getMessage());

            pendingSignatures = ScriptApproval.get().getPendingSignatures();
            assertEquals(pendingSignatures.toString(), 2, pendingSignatures.size());
        } finally {
            PermissiveWhitelist.MODE = Mode.DISABLED;
        }

        handler.clear();
        logs = handler.getView();
        assertEquals(0, logs.size());

        PermissiveWhitelist.MODE = Mode.NO_SECURITY;
        try {
            Object ret = runScript("new File('/')");
            assertTrue(ret instanceof java.io.File);

            logs = handler.getView();
            assertEquals(logs.toString(), 0, logs.size());

            pendingSignatures = ScriptApproval.get().getPendingSignatures();
            for (ScriptApproval.PendingSignature pendingSignature : pendingSignatures) {
                System.out.println(pendingSignature.signature);
            }
            assertEquals(pendingSignatures.toString(), 2, pendingSignatures.size());
        } finally {
            PermissiveWhitelist.MODE = Mode.DISABLED;
        }
    }

    @Test
    public void ignoreSafeSignature() throws Exception {
        PermissiveWhitelist.MODE = Mode.ENABLED;
        try {
            RingBufferLogHandler handler = injectLogHandler();

            Object ret = runScript("this.equals(this)");
            assertTrue((Boolean) ret);
            assertEquals(handler.getView().toString(), 0, handler.getView().size());
        } finally {
            PermissiveWhitelist.MODE = Mode.DISABLED;
        }

        PermissiveWhitelist.MODE = Mode.NO_SECURITY;
        try {
            RingBufferLogHandler handler = injectLogHandler();

            Object ret = runScript("this.equals(this)");
            assertTrue((Boolean) ret);
            assertEquals(handler.getView().toString(), 0, handler.getView().size());
        } finally {
            PermissiveWhitelist.MODE = Mode.DISABLED;
        }
    }
    
    @Test
    public void getConfigured() throws Exception {
        assertEquals(Mode.ENABLED, Mode.getConfigured("true"));
        assertEquals(Mode.DISABLED, Mode.getConfigured("false"));
        assertEquals(Mode.NO_SECURITY, Mode.getConfigured("no_security"));
        assertEquals(Mode.DISABLED, Mode.getConfigured("This looks like a nice plugin!"));
    }

    private RingBufferLogHandler injectLogHandler() {
        for (Handler handler: PermissiveWhitelist.LOGGER.getHandlers()) {
            PermissiveWhitelist.LOGGER.removeHandler(handler);
        }
        RingBufferLogHandler handler = new RingBufferLogHandler();
        PermissiveWhitelist.LOGGER.addHandler(handler);
        return handler;
    }

    private Object runScript(String text) throws Exception {
        SecureGroovyScript script = new SecureGroovyScript(text, true, Collections.<ClasspathEntry>emptyList());
        script.configuring(ApprovalContext.create());
        return script.evaluate(getClass().getClassLoader(), new Binding());
    }
}
