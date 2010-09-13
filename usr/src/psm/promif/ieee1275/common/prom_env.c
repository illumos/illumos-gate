/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * The functions in this file are used to control the pre- and post-processing
 * functions that bracket calls to the OBP CIF handler.  One set, promif_preprom
 * and promif_postprom, are provided for general kernel use.  The other set,
 * promif_preout and promif_postout, are used by the power management subsystem
 * to ensure that the framebuffer is active when PROM functions that interact
 * with the console are invoked.
 *
 * In some cases, the operation of these functions must be suppressed.  As such,
 * this file provides the ability to suspend and resume use of both sets
 * simultaneously.  Complicating matters is the fact that both current uses of
 * the pre- and post-processor suspension and resume facilities, kmdb and CPR
 * may be used simultaneously.  We therefore support normal operation and two
 * levels of suspension.  The pre- and post-processing functions are only
 * called during normal operation.  With each suspension request, this
 * subsystem enters the first suspension level, or passes to the second
 * suspension level, as appropriate.  Resume calls decrement the suspension
 * level.  Only two nested suspensions are supported.
 *
 * As indicated above, the two current users are CPR and kmdb.  CPR must prevent
 * kernel accesses outside of the nucleus page during the late stages of system
 * suspension and during the early stages of system resumption.  As such, the
 * PM-related processing must not occur during these times.
 *
 * The platform-specific portions of kmdb live in the platmods, and thus execute
 * in the linker environment of the platmods.  That is, any promif calls they
 * may make are executed by the kernel copies of those functions, rather than
 * the versions included with kmdb.  The only difference between the two copies
 * being the nonuse of the pre- and post-processing functions in the kmdb
 * versions, we must ensure that these functions are not used when the kmdb
 * platmod code executes.  Accordingly, kmdb disables the pre- and post-
 * processing functions via the KDI prior to passing control to the platmod
 * debugger code.
 */

static int promif_suspendlevel;

static promif_preprom_f *promif_preprom_fn;
static promif_postprom_f *promif_postprom_fn;

/*
 * When this is set, the PROM output functions attempt to
 * redirect output to the kernel terminal emulator.
 */
promif_redir_t promif_redirect;
promif_redir_arg_t promif_redirect_arg;

/*
 * Sets new callback and argument, returns previous callback.
 */
void
prom_set_stdout_redirect(promif_redir_t new_fn, promif_redir_arg_t opaque_arg)
{
	promif_redirect_arg = opaque_arg;
	promif_redirect = new_fn;
}

void
prom_set_preprom(promif_preprom_f *new)
{
	promif_preprom_fn = new;
}

void
prom_set_postprom(promif_postprom_f *new)
{
	promif_postprom_fn = new;
}

void
promif_preprom(void)
{
	if (promif_suspendlevel == 0 && promif_preprom_fn != NULL)
		promif_preprom_fn();
}

void
promif_postprom(void)
{
	if (promif_suspendlevel == 0 && promif_postprom_fn != NULL)
		promif_postprom_fn();
}

/*
 * The reader will note that the layout and calling conventions of the
 * prom_preout and prom_postout functions differ from the prom_preprom and
 * prom_postprom functions, above.  At the time the preout and postout
 * functions are initialized, kernel startup is well underway.  There exists
 * a race condition whereby a PROM call may begin before preout has been
 * initialized, and may end after postout has been initialized.  In such
 * cases, there will be a call to postout without a corresponding preout
 * call.  The preprom and postprom calls above are initialized early enough
 * that this race condition does not occur.
 *
 * To avoid the race condition, the preout/postout functions are designed
 * such that the initialization is atomic.  Further, the preout call returns
 * a data structure that includes a pointer to the postout function that
 * corresponds to the invoked preout function.  This ensures that the preout
 * and postout functions will only be used as a matched set.
 */

static void
null_outfunc(void)
{
}

static promif_owrap_t nullwrapper =
{
	null_outfunc,
	null_outfunc
};

static promif_owrap_t *wrapper = &nullwrapper;
static promif_owrap_t pmwrapper;

promif_owrap_t
*promif_preout(void)
{
	promif_owrap_t *ow;

	if (promif_suspendlevel > 0)
		return (&nullwrapper);

	ow = wrapper;
	if (ow->preout != NULL)
		(ow->preout)();
	return (ow);
}

void
promif_postout(promif_owrap_t *ow)
{
	if (ow->postout != NULL)
		(ow->postout)();
}

void
prom_set_outfuncs(void (*pref)(void), void (*postf)(void))
{
	pmwrapper.preout = pref;
	pmwrapper.postout = postf;
	wrapper = &pmwrapper;
}

void
prom_suspend_prepost(void)
{
	ASSERT(promif_suspendlevel < 2);

	promif_suspendlevel++;
}

void
prom_resume_prepost(void)
{
	ASSERT(promif_suspendlevel >= 0);

	promif_suspendlevel--;
}
