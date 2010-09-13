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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * return offset in file.
 */

#include <sys/feature_tests.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#pragma weak _tell64 = tell64
#else
#pragma weak _tell = tell
#endif

#include "lint.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64

off64_t
tell64(int f)
{
	return (lseek64(f, 0, SEEK_CUR));
}

#else

off_t
tell(int f)
{
	return (lseek(f, 0, SEEK_CUR));
}

#endif  /* _FILE_OFFSET_BITS == 64 */
