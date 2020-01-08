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
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Supplier;
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
            @Override
            public boolean act(Function<Whitelist, Boolean> check, Supplier<RejectedAccessException> reject) {
                return false;
            }
        },
        ENABLED() {
            // There does not seem to be a reliable way to make sure this is the latest Whitelist to consult (so we cannot
            // assume noone has whitelisted the signature when we are called), so as a second best thing, let's rerun all
            // the whitelists to see whether the signature needs to be logged. The lock is here to prevent this to cause
            // infinite recursion by aborting when the thread is about to reenter.
            private final ReentrantLock rl = new ReentrantLock();
            @Override
            public boolean act(Function<Whitelist, Boolean> check, Supplier<RejectedAccessException> reject) {
                // Break the recursion _not_ whitelisting the signature - we need to know what would happen without this whitelist
                if (rl.isHeldByCurrentThread()) return false;

                rl.lock();
                try {
                    Boolean otherwiseWhitelisted = check.apply(Whitelist.all());
                    if (!otherwiseWhitelisted) {
                        RejectedAccessException raj = reject.get();
                        LOGGER.log(Level.INFO, "Unsecure signature found: " + raj.getSignature(), raj);
                    }
                    return true;
                } finally {
                    rl.unlock();
                }
            }
        },
        NO_SECURITY() {
            @Override
            public boolean act(Function<Whitelist, Boolean> check, Supplier<RejectedAccessException> reject) {
                return true;
            }
        };

        public abstract boolean act(Function<Whitelist, Boolean> check, Supplier<RejectedAccessException> reject);

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
        return MODE.act(
                w -> w.permitsMethod(method, receiver, args),
                () -> StaticWhitelist.rejectMethod(method)
        );
    }

    public boolean permitsConstructor(@Nonnull Constructor<?> constructor, @Nonnull Object[] args) {
        return MODE.act(
                w -> w.permitsConstructor(constructor, args),
                () -> StaticWhitelist.rejectNew(constructor)
        );
    }

    public boolean permitsStaticMethod(@Nonnull Method method, @Nonnull Object[] args) {
        return MODE.act(
                w -> w.permitsStaticMethod(method, args),
                () -> StaticWhitelist.rejectStaticMethod(method)
        );
    }

    public boolean permitsFieldGet(@Nonnull Field field, @Nonnull Object receiver) {
        return MODE.act(
                w -> w.permitsFieldGet(field, receiver),
                () -> StaticWhitelist.rejectField(field)
        );
    }

    public boolean permitsFieldSet(@Nonnull Field field, @Nonnull Object receiver, @CheckForNull Object value) {
        return MODE.act(
                w -> w.permitsFieldSet(field, receiver, value),
                () -> StaticWhitelist.rejectField(field)
        );
    }

    public boolean permitsStaticFieldGet(@Nonnull Field field) {
        return MODE.act(
                w -> w.permitsStaticFieldGet(field),
                () -> StaticWhitelist.rejectStaticField(field)
        );
    }

    public boolean permitsStaticFieldSet(@Nonnull Field field, @CheckForNull Object value) {
        return MODE.act(
                w -> w.permitsStaticFieldSet(field, value),
                () -> StaticWhitelist.rejectStaticField(field)
        );
    }
}
