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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mem.h>
#include <fm/fmd_fmri.h>

/*
 * We do not yet support DIMM enumeration in the x86 mem scheme because our
 * diagnosis is using the new libtopo functionality and hopefully won't need
 * this before we eventually replace scheme plug-ins entirely w/ libtopo.
 */
int
mem_discover(void)
{
	return (0);
}

/*
 * The following two routines are stubs for corresponding SPARC-only code.
 */

/*ARGSUSED*/
int
mem_get_serids_by_unum(const char *unum, char ***seridsp, size_t *nseridsp)
{
	errno = ENOTSUP;
	return (-1);
}

/*ARGSUSED*/
void
mem_expand_opt(nvlist_t *nvl, char *unum, char **serids)
{
}
