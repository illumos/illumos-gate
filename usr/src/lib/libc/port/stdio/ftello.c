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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Return file offset.
 * Coordinates with buffering.
 */

#include <sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak _ftello64 = ftello64
#endif
#pragma weak _ftello = ftello

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stddef.h>
#include "stdiom.h"

#if !defined(_LP64)

off64_t
ftello64(FILE *iop)
{
	return (ftell_common(iop));
}

#endif	/* _LP64 */

off_t
ftello(FILE *iop)
{
	return ((off_t)ftell(iop));
}
