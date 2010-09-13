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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: m_wcsdup.c 1.5 1994/08/17 15:32:51 jeffhe Exp $";
#endif
#endif

#include <mks.h>
#include <string.h>
#include <stdlib.h>

/*f
 * Return a wide copy of the wide string `s', or NULL
 */
LDEFN wchar_t *
m_wcsdup(s)
const wchar_t *s;
{
	wchar_t *cp;
	int len;
	extern char *_cmdname;

	cp = (wchar_t *)malloc(len = (wcslen(s) + 1) * sizeof(wchar_t));
	if (cp == (wchar_t *)NULL) {
		return((wchar_t *)0);
	}
	return ((wchar_t *)memcpy((char *)cp, s, len));
}
