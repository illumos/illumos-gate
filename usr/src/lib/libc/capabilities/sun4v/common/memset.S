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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"memset.s"

/*
 * char *memset(sp, c, n)
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
 * Flow :
 *
 *	For small 6 or fewer bytes stores, bytes will be stored.
 *
 *	For less than 32 bytes stores, align the address on 4 byte boundary.
 *	Then store as many 4-byte chunks, followed by trailing bytes.
 *
 *	For sizes greater than 32 bytes, align the address on 8 byte boundary.
 *	if (count > 64) {
 *		store as many 8-bytes chunks to block align the address
 *		store using ASI_BLK_INIT_ST_QUAD_LDD_P
 *	}
 *	Store as many 8-byte chunks, followed by trialing bytes.
 *
 */

#include <sys/asm_linkage.h>
#include <sys/niagaraasi.h>
#include <sys/asi.h>

	ANSI_PRAGMA_WEAK(memset,function)

	.section        ".text"
	.align 32

	ENTRY(memset)

	mov	%o0, %o5		! copy sp1 before using it
	cmp	%o2, 7			! if small counts, just write bytes
	blu,pn	%ncc, .wrchar
	and	%o1, 0xff, %o1		! o1 is (char)c

	sll	%o1, 8, %o3
	or	%o1, %o3, %o1		! now o1 has 2 bytes of c
	sll	%o1, 16, %o3

	cmp	%o2, 0x20
	blu,pn	%ncc, .wdalign
	or	%o1, %o3, %o1		! now o1 has 4 bytes of c

	sllx	%o1, 32, %o3
	or	%o1, %o3, %o1		! now o1 has 8 bytes of c

.dbalign:
	andcc	%o5, 7, %o3		! is sp1 aligned on a 8 byte bound
	bz,pt	%ncc, .blkalign		! already double aligned
	sub	%o3, 8, %o3		! -(bytes till double aligned)
	add	%o2, %o3, %o2		! update o2 with new count

	! Set -(%o3) bytes till sp1 double aligned
1:	stb	%o1, [%o5]		! there is at least 1 byte to set
	inccc	%o3			! byte clearing loop
	bl,pt	%ncc, 1b
	inc	%o5

	! Now sp1 is double aligned (sp1 is found in %o5)
.blkalign:
	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi

	cmp	%o2, 0x40		! check if there are 64 bytes to set
	blu,pn	%ncc, 5f
	mov	%o2, %o3

	andcc	%o5, 63, %o3		! is sp1 block aligned?
	bz,pt	%ncc, .blkwr		! now block aligned
	sub	%o3, 64, %o3		! o3 is -(bytes till block aligned)
	add	%o2, %o3, %o2		! o2 is the remainder

	! Store -(%o3) bytes till dst is block (64 byte) aligned.
	! Use double word stores.
	! Recall that dst is already double word aligned
1:
	stx	%o1, [%o5]
	addcc	%o3, 8, %o3
	bl,pt	%ncc, 1b
	add	%o5, 8, %o5

	! Now sp1 is block aligned
.blkwr:
	and	%o2, 63, %o3		! calc bytes left after blk store.
	andn	%o2, 63, %o4		! calc size of blocks in bytes

	cmp	%o4, 0x100		! check if there are 256 bytes to set
	blu,pn	%ncc, 3f
	nop
2:
	stxa	%o1, [%o5+0x0]%asi
	stxa	%o1, [%o5+0x40]%asi
	stxa	%o1, [%o5+0x80]%asi
	stxa	%o1, [%o5+0xc0]%asi

	stxa	%o1, [%o5+0x8]%asi
	stxa	%o1, [%o5+0x10]%asi
	stxa	%o1, [%o5+0x18]%asi
	stxa	%o1, [%o5+0x20]%asi
	stxa	%o1, [%o5+0x28]%asi
	stxa	%o1, [%o5+0x30]%asi
	stxa	%o1, [%o5+0x38]%asi

	stxa	%o1, [%o5+0x48]%asi
	stxa	%o1, [%o5+0x50]%asi
	stxa	%o1, [%o5+0x58]%asi
	stxa	%o1, [%o5+0x60]%asi
	stxa	%o1, [%o5+0x68]%asi
	stxa	%o1, [%o5+0x70]%asi
	stxa	%o1, [%o5+0x78]%asi

	stxa	%o1, [%o5+0x88]%asi
	stxa	%o1, [%o5+0x90]%asi
	stxa	%o1, [%o5+0x98]%asi
	stxa	%o1, [%o5+0xa0]%asi
	stxa	%o1, [%o5+0xa8]%asi
	stxa	%o1, [%o5+0xb0]%asi
	stxa	%o1, [%o5+0xb8]%asi

	stxa	%o1, [%o5+0xc8]%asi
	stxa	%o1, [%o5+0xd0]%asi
	stxa	%o1, [%o5+0xd8]%asi
	stxa	%o1, [%o5+0xe0]%asi
	stxa	%o1, [%o5+0xe8]%asi
	stxa	%o1, [%o5+0xf0]%asi
	stxa	%o1, [%o5+0xf8]%asi

	sub	%o4, 0x100, %o4
	cmp	%o4, 0x100
	bgu,pt	%ncc, 2b
	add	%o5, 0x100, %o5

3:
	cmp	%o4, 0x40		! check if 64 bytes to set
	blu	%ncc, 5f
	nop
4:
	stxa	%o1, [%o5+0x0]%asi
	stxa	%o1, [%o5+0x8]%asi
	stxa	%o1, [%o5+0x10]%asi
	stxa	%o1, [%o5+0x18]%asi
	stxa	%o1, [%o5+0x20]%asi
	stxa	%o1, [%o5+0x28]%asi
	stxa	%o1, [%o5+0x30]%asi
	stxa	%o1, [%o5+0x38]%asi

	subcc	%o4, 0x40, %o4
	bgu,pt	%ncc, 4b
	add	%o5, 0x40, %o5

5:
	! Set the remaining doubles
	membar	#Sync
	mov	ASI_PNF, %asi		! restore %asi to default
					! ASI_PRIMARY_NOFAULT value
	subcc	%o3, 8, %o3		! Can we store any doubles?
	blu,pn	%ncc, .wrchar
	and	%o2, 7, %o2		! calc bytes left after doubles

6:
	stx	%o1, [%o5]		! store the doubles
	subcc	%o3, 8, %o3
	bgeu,pt	%ncc, 6b
	add	%o5, 8, %o5

	ba	.wrchar
	nop

.wdalign:
	andcc	%o5, 3, %o3		! is sp1 aligned on a word boundary
	bz,pn	%ncc, .wrword
	andn	%o2, 3, %o3		! create word sized count in %o3

	dec	%o2			! decrement count
	stb	%o1, [%o5]		! clear a byte
	b	.wdalign
	inc	%o5			! next byte

.wrword:
	st	%o1, [%o5]		! 4-byte writing loop
	subcc	%o3, 4, %o3
	bnz,pt	%ncc, .wrword
	inc	4, %o5

	and	%o2, 3, %o2		! leftover count, if any

.wrchar:
	! Set the remaining bytes, if any
	cmp	%o2, 0
	be	%ncc, .exit
	nop

7:
	deccc	%o2
	stb	%o1, [%o5]
	bgu,pt	%ncc, 7b
	inc	%o5

.exit:
	retl				! %o0 was preserved
	nop

	SET_SIZE(memset)
