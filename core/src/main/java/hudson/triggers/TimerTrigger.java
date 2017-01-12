/*
 * The MIT License
 * 
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi, Jean-Baptiste Quenot, Martin Eigenbrodt
 *               2015 Kanstantsin Shautsou
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
package hudson.triggers;

import antlr.ANTLRException;
import hudson.Extension;
import static hudson.Util.fixNull;

import hudson.RestrictedSince;
import hudson.model.BuildableItem;
import hudson.model.Cause;
import hudson.model.Item;
import hudson.scheduler.CronTabList;
import hudson.scheduler.Hash;
import hudson.util.FormValidation;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;

import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;

/**
 * {@link Trigger} that runs a job periodically.
 *
 * @author Kohsuke Kawaguchi
 */
public class TimerTrigger extends Trigger<BuildableItem> {

    @DataBoundConstructor
    public TimerTrigger(@Nonnull String spec) throws ANTLRException {
        super(spec);
    }

    @Override
    public void run() {
        if (job == null) {
            return;
        }

        job.scheduleBuild(0, new TimerTriggerCause());
    }

    @Extension @Symbol("cron")
    public static class DescriptorImpl extends TriggerDescriptor {
        public boolean isApplicable(Item item) {
            return item instanceof BuildableItem;
        }

        public String getDisplayName() {
            return Messages.TimerTrigger_DisplayName();
        }

        // backward compatibility
        @RestrictedSince("since TODO 2.4x") @Restricted(NoExternalUse.class) // For Stapler only
        public FormValidation doCheck(@QueryParameter String value, @AncestorInPath Item item) {
            return doCheckSpec(value, item);
        }
        
        /**
         * Performs syntax check.
         */
        @RestrictedSince("since TODO 2.4x") @Restricted(NoExternalUse.class) // For Stapler only
        public FormValidation doCheckSpec(@QueryParameter String value, @AncestorInPath Item item) {
            try {
                CronTabList ctl = CronTabList.create(fixNull(value), item != null ? Hash.from(item.getFullName()) : null);
                Collection<FormValidation> validations = new ArrayList<>();
                updateValidationsForSanity(validations, ctl);
                updateValidationsForNextRun(validations, ctl);
                return FormValidation.aggregate(validations);
            } catch (ANTLRException e) {
                if (value.trim().indexOf('\n')==-1 && value.contains("**"))
                    return FormValidation.error(Messages.TimerTrigger_MissingWhitespace());
                return FormValidation.error(e.getMessage());
            }
        }

        private void updateValidationsForSanity(Collection<FormValidation> validations, CronTabList ctl) {
            String msg = ctl.checkSanity();
            if(msg!=null)  validations.add(FormValidation.warning(msg));
        }

        private void updateValidationsForNextRun(Collection<FormValidation> validations, CronTabList ctl) {
            Calendar prev = ctl.previous();
            Calendar next = ctl.next();
            if (prev != null && next != null) {
                DateFormat fmt = DateFormat.getDateTimeInstance(DateFormat.FULL, DateFormat.FULL);
                validations.add(FormValidation.ok(Messages.TimerTrigger_would_last_have_run_at_would_next_run_at(fmt.format(prev.getTime()), fmt.format(next.getTime()))));
            } else {
                validations.add(FormValidation.warning(Messages.TimerTrigger_no_schedules_so_will_never_run()));
            }
        }
    }
    
    public static class TimerTriggerCause extends Cause {
        @Override
        public String getShortDescription() {
            return Messages.TimerTrigger_TimerTriggerCause_ShortDescription();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof TimerTriggerCause;
        }

        @Override
        public int hashCode() {
            return 5;
        }
    }
}
