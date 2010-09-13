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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

#define	NOP_4		nop;nop;nop;nop
#define	NOP_16		NOP_4;NOP_4;NOP_4;NOP_4
#define	NOP_64		NOP_16;NOP_16;NOP_16;NOP_16
#define	NOP_256		NOP_64;NOP_64;NOP_64;NOP_64
#define	NOP_1K		NOP_256;NOP_256;NOP_256;NOP_256
#define	NOP_4K		NOP_1K;NOP_1K;NOP_1K;NOP_1K
#define	NOP_16K		NOP_4K;NOP_4K;NOP_4K;NOP_4K

/* flushes the icache using a series of nops */

#ifdef __lint

void
iflush(void)
{
}

#else

ENTRY(iflush)
	NOP_4K
	NOP_4K
	retl
	nop
SET_SIZE(iflush)

#endif
