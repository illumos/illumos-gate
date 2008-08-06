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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"creat.s"

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)
/* C library -- creat						*/
/* int __creat(char *path, mode_t mode)				*/

	SYSCALL2_RVAL1(__creat,creat)
	RET
	SET_SIZE(__creat)

#else
/* C library -- creat64						*/
/* int __creat64(char *path, mode_t mode)			*/

	SYSCALL2_RVAL1(__creat64,creat64)
	RET
	SET_SIZE(__creat64)

#endif
