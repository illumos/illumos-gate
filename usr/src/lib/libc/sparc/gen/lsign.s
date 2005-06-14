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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*       Copyright (c) 1989 by Sun Microsystems, Inc.		*/

.ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Determine the sign of a double-long number.
 * Ported from m32 version to sparc.
 *
 *	int
 *	lsign (op)
 *		dl_t	op;
 */

	.file	"lsign.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(lsign,function)

#include "synonyms.h"

	ENTRY(lsign)

	ld	[%o0],%o0		! fetch op (high word only)
	jmp	%o7+8			! return
	srl	%o0,31,%o0		! shift letf logical to isolate sign

	SET_SIZE(lsign)
