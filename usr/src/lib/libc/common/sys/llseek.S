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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"llseek.s"

/*
 * C library -- llseek
 * offset_t llseek(int fildes, offset_t offset, int whence);
 */

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(llseek,function)

#include "SYS.h"

#if CLONGSIZE == 8	/* from sys/asm_linkage.h */
	/*
	 * For _LP64, llseek() is the same as lseek().
	 */
	SYSCALL2_RVAL1(llseek,lseek)
#else
	SYSCALL64(llseek)
#endif
	RET
	SET_SIZE(llseek)
