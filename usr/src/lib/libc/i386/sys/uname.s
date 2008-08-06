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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"uname.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(uname,function)

#include "SYS.h"

	.set	UNAME, 0

	ENTRY(uname)
	pushl	$UNAME		/ type
	pushl	$0		/ mv flag
	pushl	12(%esp)	/ utsname address (retaddr+$UNAME+0)
	subl	$4, %esp	/ where return address would be.
	SYSTRAP_RVAL1(utssys)
	jae	1f
	addl	$16, %esp
	jmp	__cerror
1:
	addl	$16, %esp
	ret
	SET_SIZE(uname)
