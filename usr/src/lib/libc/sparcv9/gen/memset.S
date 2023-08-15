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

	.file	"memset.s"

/*
 * memset(sp, c, n)
 *
 * Set an array of n chars starting at sp to the character c.
 * Return sp.
 *
 * Fast assembler language version of the following C-program for memset
 * which represents the `standard' for the C-library.
 *
 *	void *
 *	memset(void *sp1, int c, size_t n)
 *	{
 *	    if (n != 0) {
 *		char *sp = sp1;
 *		do {
 *		    *sp++ = (char)c;
 *		} while (--n != 0);
 *	    }
 *	    return (sp1);
 *	}
 *
 *
 *
 * Algorithm used:
 *	For small stores (6 or fewer bytes), bytes will be stored one at a time.
 *
 *	When setting 15 or more bytes, there will be at least 8 bytes aligned
 *	on an 8-byte boundary.  So, leading bytes will be set, then as many
 *	8-byte aligned chunks as possible will be set, followed by any trailing
 *	bytes.
 *
 *	For between 8 and 14 bytes (inclusive), leading odd bytes will be
 *	set, followed by 4-byte chunks, followed by trailing bytes.
 *
 * Inputs:
 *	o0:  pointer to start of area to be set to a given value
 *	o1:  character used to set memory at location in i0
 *	o2:  number of bytes to be set
 *
 * Outputs:
 *	o0:  pointer to start of area set (same as input value in o0)
 *
 */

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memset,function)

	ENTRY(memset)
	mov	%o0, %o5		! need to return this value
	cmp	%o2, 7
	blu,pn	%xcc, .wrchar		! small count:  just set bytes
	and	%o1, 0xff, %o1

	sll	%o1, 8, %o4		! generate 4 bytes filled with char
	or 	%o1, %o4, %o1
	sll	%o1, 16, %o4
	cmp	%o2, 15
	blu,pn	%xcc, .walign		! not enough to guarantee 8-byte align
	or	%o1, %o4, %o1

	sllx	%o1, 32, %o4		! now fill the other 4 bytes with char
	or 	%o1, %o4, %o1

.dalign:			! Set bytes until 8-byte aligned
	btst	7, %o5			! 8-byte aligned?
	bz,a,pn	%icc, .wrdbl
	andn	%o2, 7, %o3		! o3 has 8-byte multiple

	dec	%o2
	stb	%o1, [%o5]		! clear a byte
	b	.dalign			! go see if aligned yet
	inc	%o5

	.align	32
.wrdbl:
	stx	%o1, [%o5]		! write aligned 8 bytes
	subcc	%o3, 8, %o3
	bnz,pt	%xcc, .wrdbl
	inc	8, %o5

	b	.wrchar			! write the remaining bytes
	and	%o2, 7, %o2		! leftover count, if any

.walign:			! Set bytes until 4-byte aligned
	btst	3, %o5			! if bigger, align to 4 bytes
	bz,pn	%icc, .wrword
	andn	%o2, 3, %o3		! create word sized count in %o3

	dec	%o2			! decrement count
	stb	%o1, [%o5]		! clear a byte
	b	.walign
	inc	%o5			! next byte

.wrword:
	st	%o1, [%o5]		! 4-byte writing loop
	subcc	%o3, 4, %o3
	bnz,pn	%xcc, .wrword
	inc	4, %o5

	and	%o2, 3, %o2		! leftover count, if any

.wrchar:
	deccc	%o2			! byte clearing loop
	inc	%o5
	bgeu,a,pt %xcc, .wrchar
	stb	%o1, [%o5 + -1]		! we've already incremented the address

	retl
	sub	%o0, %g0, %o0

	SET_SIZE(memset)
