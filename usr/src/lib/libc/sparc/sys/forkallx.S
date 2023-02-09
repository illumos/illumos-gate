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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"forkallx.s"

#include "SYS.h"

/*
 * pid = __forkallx(flags);
 *
 * syscall trap: forksys(1, flags)
 *
 * From the syscall:
 * %o1 == 0 in parent process, %o1 == 1 in child process.
 * %o0 == pid of child in parent, %o0 == pid of parent in child.
 *
 * The child gets a zero return value.
 * The parent gets the pid of the child.
 */

	ENTRY(__forkallx)
	mov	%o0, %o1
	mov	1, %o0
	SYSTRAP_2RVALS(forksys)
	SYSCERROR
	movrnz	%o1, 0, %o0
	RET
	SET_SIZE(__forkallx)
