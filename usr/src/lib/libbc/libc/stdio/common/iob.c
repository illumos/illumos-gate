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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from Sun */

#include <stdio.h>
#include "iob.h"

FILE _iob[NSTATIC] = {
#if pdp11
	{ NULL, 0, NULL, 0, _IOREAD,			0 },	/* stdin */
	{ NULL, 0, NULL, 0, _IOWRT,			1 },	/* stdout */
	{ NULL, 0, NULL, 0, _IOWRT|_IONBF,		2 },	/* stderr */
#else
#if u370
	{ NULL, 0, NULL, 0, _IOREAD,			0 },	/* stdin */
	{ NULL, 0, NULL, 0, _IOWRT,			1 },	/* stdout */
	{ NULL, 0, NULL, 0, _IOWRT|_IONBF,		2 },	/* stderr */
#else	/* just about every other UNIX system in existence */
	{ 0, NULL, NULL, 0, _IOREAD,			0 },	/* stdin */
	{ 0, NULL, NULL, 0, _IOWRT,			1 },	/* stdout */
	{ 0, NULL, NULL, 0, _IOWRT|_IONBF,		2 },	/* stderr */
#endif
#endif
};
