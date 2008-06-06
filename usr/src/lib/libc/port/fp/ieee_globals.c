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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * contains definitions for variables for IEEE floating-point arithmetic
 * modes; IEEE floating-point arithmetic exception handling;
 */

#include "lint.h"
#include <thread.h>
#include <synch.h>
#include <mtlib.h>
#include "tsd.h"

int __inf_read, __inf_written, __nan_read, __nan_written;

/*
 * Per-thread instances (thread-specific data) of the above globals.
 */
typedef struct {
	int	__inf_read;
	int	__inf_written;
	int	__nan_read;
	int	__nan_written;
} fpvars_t;

#define	fpvars	((fpvars_t *)tsdalloc(_T_FP_GET, sizeof (fpvars_t), NULL))

int *
_thrp_get_nan_written()
{
	return (thr_main() ? &__nan_written : &fpvars->__nan_written);
}

int *
_thrp_get_nan_read()
{
	return (thr_main() ? &__nan_read : &fpvars->__nan_read);
}

int *
_thrp_get_inf_written()
{
	return (thr_main() ? &__inf_written : &fpvars->__inf_written);
}

int *
_thrp_get_inf_read()
{
	return (thr_main() ? &__inf_read : &fpvars->__inf_read);
}
