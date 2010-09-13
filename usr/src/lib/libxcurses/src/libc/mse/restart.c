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
static char rcsID[] = "$Header: /rd/src/libc/mse/RCS/restart.c,v 1.1 1992/12/15 10:59:56 alex Exp alex $";
#endif /*lint*/
#endif /*M_RCSID*/

#include <mks.h>
#include <stdlib.h>
#include <wchar.h>

/*f
 * Restartable multibyte routines, for a system without state.
 */
int
mbrtowc(wchar_t *wc, const char *mb, size_t n, mbstate_t *ps)
{
	return mbtowc(wc, mb, n);
}

int
wcrtomb(char *s, wchar_t wc, mbstate_t *ps)
{
	return wctomb(s, wc);
}
