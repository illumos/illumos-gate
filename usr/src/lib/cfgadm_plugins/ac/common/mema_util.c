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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <locale.h>
#include <sys/param.h>
#include <config_admin.h>
#include "mema_util.h"

/*
 * The libmemadm routines can return arbitrary error strings.  As the
 * calling program does not know how long these errors might be,
 * the library routines must allocate the required space and the
 * calling program must deallocate it.
 *
 * This routine povides a printf-like interface for creating the
 * error strings.
 */

#define	FMT_STR_SLOP		(16)

void
__fmt_errstring(
	char **errstring,
	size_t extra_length_hint,
	const char *fmt,
	...)
{
	char *ebuf;
	size_t elen;
	va_list ap;

	/*
	 * If no errors required or error already set, return.
	 */
	if ((errstring == NULL) || (*errstring != NULL))
		return;

	elen = strlen(fmt) + extra_length_hint + FMT_STR_SLOP;

	if ((ebuf = (char *)malloc(elen + 1)) == NULL)
		return;

	va_start(ap, fmt);
	(void) vsprintf(ebuf, fmt, ap);
	va_end(ap);

	if (strlen(ebuf) > elen)
		abort();

	*errstring = ebuf;
}
