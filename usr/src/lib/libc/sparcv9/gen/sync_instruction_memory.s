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
 * Copyright (c) 1995-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

	.file	"sync_instruction_memory.s"

#include <sys/asm_linkage.h>

/*
 * void sync_instruction_memory(caddr_t addr, int len)
 *
 * Make the memory at {addr, addr+len} valid for instruction execution.
 */

#ifdef lint
#define	nop
void
sync_instruction_memory(caddr_t addr, size_t len)
{
	caddr_t end = addr + len;
	caddr_t start = addr & ~7;
	for (; start < end; start += 8)
		flush(start);
	nop; nop; nop; nop; nop;
	return;
}
#else
	ENTRY(sync_instruction_memory)
	add	%o0, %o1, %o2
	andn	%o0, 7, %o0

	cmp	%o0, %o2
	bgeu,pn	%xcc, 2f
	nop
	flush	%o0
1:
	add	%o0, 8, %o0
	cmp	%o0, %o2
	blu,a,pt %xcc, 1b
	flush	%o0
2:
	retl
	clr	%o0
	SET_SIZE(sync_instruction_memory)

	ENTRY(nop)
	retl
	nop
	SET_SIZE(nop)
#endif
