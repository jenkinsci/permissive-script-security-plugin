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

import hudson.model.Result;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertEquals;

public class PipelineIntegrationTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    @Before
    public void before() {
        l.capture(100);
        l.record(PermissiveWhitelist.class, Level.INFO);
    }

    @Test
    public void dangerousSignaturesNotReportedWhenNoSecurity() throws Exception {
        PermissiveWhitelist.MODE = PermissiveWhitelist.Mode.NO_SECURITY;
        WorkflowJob p = newJob("new File('/etc/shadow/')");
        j.buildAndAssertSuccess(p);

        assertPendingSignatures(Collections.emptyList());
        assertThat(l.getMessages(), emptyIterable());
    }

    @Test
    public void dangerousSignaturesRejectedWhenDisabled() throws Exception {
        PermissiveWhitelist.MODE = PermissiveWhitelist.Mode.DISABLED;
        WorkflowJob p = newJob("new File('/etc/shadow/')");
        WorkflowRun r = j.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        assertThat(r.getLog(), containsString("Scripts not permitted to use new java.io.File java.lang.String"));

        assertPendingSignatures(Collections.singletonList("new java.io.File java.lang.String"));
        assertThat(l.getMessages(), emptyIterable());
    }

    @Test
    public void dangerousSignaturesReportedWhenEnabled() throws Exception {
        PermissiveWhitelist.MODE = PermissiveWhitelist.Mode.ENABLED;
        WorkflowJob p = newJob("new File('/etc/shadow/')");
        WorkflowRun r = j.buildAndAssertSuccess(p);

        assertPendingSignatures(Collections.singletonList("new java.io.File java.lang.String"));
        assertThat(l.getMessages(), iterableWithSize(1));
    }

    @Test
    public void noSignaturesWhenDisabled() throws Exception {
        PermissiveWhitelist.MODE = PermissiveWhitelist.Mode.DISABLED;
        _noSignaturesForSafeScript();
    }

    @Test
    public void noSignaturesWhenEnabled() throws Exception {
        PermissiveWhitelist.MODE = PermissiveWhitelist.Mode.ENABLED;
        _noSignaturesForSafeScript();
    }

    @Test
    public void noSignaturesWhenNoSecurity() throws Exception {
        PermissiveWhitelist.MODE = PermissiveWhitelist.Mode.NO_SECURITY;
        _noSignaturesForSafeScript();
    }

    private void _noSignaturesForSafeScript() throws Exception {
        WorkflowJob job = newJob("echo 'Hello World'");
        j.buildAndAssertSuccess(job);

        assertPendingSignatures(Collections.emptyList());
        assertThat(l.getMessages(), emptyIterable());
    }

    private WorkflowJob newJob(String script) throws IOException {
        WorkflowJob job = j.createProject(WorkflowJob.class);
        job.setDefinition(new CpsFlowDefinition(script, true));
        return job;
    }

    private void assertPendingSignatures(List<String> expected) throws IOException {
        Set<ScriptApproval.PendingSignature> ps = ScriptApproval.get().getPendingSignatures();
        List<String> sigs = ps.stream().map(s -> s.signature).collect(Collectors.toList());
        try {
            if (ps.isEmpty()) return;
            assertEquals(expected, sigs);
        } finally {
            // Clean for next tests
            for (String sig : sigs) {
                ScriptApproval.get().denySignature(sig);
            }
        }
    }
}
