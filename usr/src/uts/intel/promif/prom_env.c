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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This function is installed for both pre and post output during cpr to keep
 * the early stages of the resuming kernel from accessing outside the nucleus
 * mapping; we assert that the console is all powered up before it is installed
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
static promif_owrap_t *saved_wrapper;

promif_owrap_t
*promif_preout(void)
{
	promif_owrap_t *ow = wrapper;
	(ow->preout)();
	return (ow);
}

void
promif_postout(promif_owrap_t *ow)
{
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
	saved_wrapper = wrapper;
	wrapper = &nullwrapper;
}

void
prom_resume_prepost(void)
{
	wrapper = saved_wrapper;
	saved_wrapper = NULL;
}
