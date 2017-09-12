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

import hudson.Extension;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.jenkinsci.plugins.scriptsecurity.scripts.ApprovalContext;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Permit every access not permitted by other {@link Whitelist}s but log the details.
 *
 * @author ogondza.
 */
@Restricted(NoExternalUse.class)
@Extension(ordinal = Double.MIN_VALUE) // Run if no other whitelist permitted the signature.
public class PermissiveWhitelist extends Whitelist {
    /*package*/ static @Nonnull Mode MODE = Mode.getConfigured(
            System.getProperty("permissive-script-security.enabled", "false")
    );

    /*package*/ static final Logger LOGGER = Logger.getLogger(PermissiveWhitelist.class.getName());

    public enum Mode {
        DISABLED() {
            public boolean act(RejectedAccessException ex) {
                return false; // Reject was not permitted by others
            }
        },
        ENABLED() {
            public boolean act(RejectedAccessException ex) {
                LOGGER.log(Level.INFO, "Unsecure signature found: " + ex.getSignature(), ex);
                ScriptApproval.get().accessRejected(ex, ApprovalContext.create().withCurrentUser());
                return true;
            }
        },
        NO_SECURITY() {
            public boolean act(RejectedAccessException ex) {
                return true; // You have been warned
            }
        };

        public abstract boolean act(RejectedAccessException ex);

        public static Mode getConfigured(String config) {
            if ("true".equals(config)) {
                return ENABLED;
            } else if ("no_security".equals(config)) {
                return NO_SECURITY;
            } else {
                return DISABLED;
            }
        }
    }

    public boolean permitsMethod(@Nonnull Method method, @Nonnull Object receiver, @Nonnull Object[] args) {
        return MODE.act(StaticWhitelist.rejectMethod(method));
    }

    public boolean permitsConstructor(@Nonnull Constructor<?> constructor, @Nonnull Object[] args) {
        return MODE.act(StaticWhitelist.rejectNew(constructor));
    }

    public boolean permitsStaticMethod(@Nonnull Method method, @Nonnull Object[] args) {
        return MODE.act(StaticWhitelist.rejectStaticMethod(method));
    }

    public boolean permitsFieldGet(@Nonnull Field field, @Nonnull Object receiver) {
        return MODE.act(StaticWhitelist.rejectField(field));
    }

    public boolean permitsFieldSet(@Nonnull Field field, @Nonnull Object receiver, @CheckForNull Object value) {
        return MODE.act(StaticWhitelist.rejectField(field));
    }

    public boolean permitsStaticFieldGet(@Nonnull Field field) {
        return MODE.act(StaticWhitelist.rejectStaticField(field));
    }

    public boolean permitsStaticFieldSet(@Nonnull Field field, @CheckForNull Object value) {
        return MODE.act(StaticWhitelist.rejectStaticField(field));
    }
}
