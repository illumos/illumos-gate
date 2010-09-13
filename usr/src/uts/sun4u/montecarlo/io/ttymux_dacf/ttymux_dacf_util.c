/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>

#include "ttymux_dacf.h"

int ttymux_errlevel = DPRINT_L3;

/*
 * ttymux_dprintf
 * 	Print string to the console.
 */
void
ttymux_dprintf(int l, const char *fmt, ...)
{
	va_list ap;

#ifndef DEBUG
	if (!l) {
		return;
	}
#endif
	if ((l) < ttymux_errlevel) {

		return;
	}

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}
