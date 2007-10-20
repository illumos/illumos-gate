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

/*
 * cpr functions for supported sparc platforms
 */
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpr.h>
#include <sys/kmem.h>
#include <sys/errno.h>

/*
 * setup the original and new sets of property names/values
 * Not relevant to S3, which is all we support for now.
 */
/*ARGSUSED*/
int
cpr_default_setup(int alloc)
{
	return (0);
}

void
cpr_send_notice(void)
{
	static char cstr[] = "\014" "\033[1P" "\033[18;21H";

	prom_printf(cstr);
	prom_printf("Saving System State. Please Wait... ");
}

void
cpr_spinning_bar(void)
{
	static char *spin_strings[] = { "|\b", "/\b", "-\b", "\\\b" };
	static int idx;

	prom_printf(spin_strings[idx]);
	if (++idx == 4)
		idx = 0;
}

void
cpr_resume_notice(void)
{
	static char cstr[] = "\014" "\033[1P" "\033[18;21H";

	prom_printf(cstr);
	prom_printf("Restoring System State. Please Wait... ");
}
