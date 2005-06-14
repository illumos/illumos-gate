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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

/*
 * Interface to mmap introduced in 4.0.  Incorporates flag telling
 * system to use 4.0 interface to mmap.
 */

#include "SYS.h"
#include <sys/mman.h>

#define	FLAGS	%o3

ENTRY(mmap)
	sethi	%hi(_MAP_NEW), %g1
	or	%g1, FLAGS, FLAGS
	mov	SYS_mmap, %g1
	t	8
	CERROR(o5)
	RET

SET_SIZE(mmap)
