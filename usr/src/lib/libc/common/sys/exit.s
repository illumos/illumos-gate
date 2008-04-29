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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

/* C library -- _exit
 *
 * void _exit(int status)
 * void _Exit(int status)   -- added for SUSv3 standard
 *
 * code is return in r0 to system
 * Same as plain exit, for user who want to define their own exit.
 *
 * _Exit() has been implemented as a weak symbol of _exit().
 * This is the cheapest way to get a duplicate symbol of _exit()
 * which is all that is required.  To the dynamic linker there
 * is no difference between a strong and weak symbol.
 */

#include "SYS.h"

	ANSI_PRAGMA_WEAK2(_Exit,_exit,function)
	ENTRY(_exit)
	SYSTRAP_RVAL1(exit)
	SET_SIZE(_exit)
