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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"memcpy.s"
/*
 * memcpy(s1, s2, len)
 *
 * Copy s2 to s1, always copy n bytes.
 * Note: this does not work for overlapped copies, bcopy() does
 *
 * Fast assembler language version of the following C-program for memcpy
 * which represents the `standard' for the C-library.
 *
 *	void * 
 *	memcpy(void *s, const void *s0, size_t n)
 *	{
 *		if (n != 0) {
 *	   	    char *s1 = s;
 *		    const char *s2 = s0;
 *		    do {
 *			*s1++ = *s2++;
 *		    } while (--n != 0);
 *		}
 *		return ( s );
 *	}
 *
 * Flow :
 *
 * if (count < 17) {
 *	Do the byte copy
 *	Return destination address
 * }
 * if (count < 128) {
 *	Is source aligned on word boundary
 *	If no then align source on word boundary then goto .ald
 *	If yes goto .ald
 *	.ald:
 *		Is destination aligned on word boundary
 *		Depending on destination offset (last 2 bits of destination)
 *		copy data by shifting and merging.
 *		Copy residue bytes as byte copy
 *		Return destination address
 * } else {
 *	Align destination on block boundary
 *	Depending on the source offset (last 4 bits of source address) align
 *	the data and store to destination. Both the load and store are done
 *	using ASI_BLK_INIT_ST_QUAD_LDD_P.
 *	For remaining count copy as much data in 8-byte chunk from source to
 *	destination.
 *	Followed by trailing copy using byte copy.
 *	Return saved destination address
 * }
 *
 */

#include <sys/asm_linkage.h>
#include <sys/niagaraasi.h>
#include <sys/asi.h>
#include <sys/trap.h>

/*
 * This define is to align data for the unaligned source cases.
 * The data1, data2 and data3 is merged into data1 and data2.
 * The data3 is preserved for next merge.
 */
#define	ALIGN_DATA(data1, data2, data3, lshift, rshift, tmp)	\
	sllx	data1, lshift, data1				;\
	srlx	data2, rshift, tmp				;\
	or	data1, tmp, data1				;\
	sllx	data2, lshift, data2				;\
	srlx	data3, rshift, tmp				;\
	or	data2, tmp, data2
/*
 * Align the data. Merge the data1 and data2 into data1.
 */
#define	ALIGN_DATA_EW(data1, data2, lshift, rshift, tmp)	\
	sllx	data1, lshift, data1				;\
	srlx	data2, rshift, tmp				;\
	or	data1, tmp, data1
/*
 * Align the data in case of backward copy.
 */
#define	ALIGN_DATA_BC(data1, data2, rshift, lshift, tmp)	\
	srlx	data1, rshift, data1				;\
	sllx	data2, lshift, tmp				;\
	or	data1, tmp, data1

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

#include "synonyms.h"

	ENTRY(memmove)
	cmp	%o1, %o0	! if from address is >= to use forward copy
	bgeu	%ncc, forcpy	! else use backward if ...
	sub	%o0, %o1, %o4	! get difference of two addresses
	cmp	%o2, %o4	! compare size and difference of addresses
	bleu	%ncc, forcpy	! if size is bigger, do overlapped copy
	nop

        !
        ! an overlapped copy that must be done "backwards"
        !
.ovbc:  
	mov	%o0, %o5		! save des address for return val	
	add     %o1, %o2, %o1           ! get to end of source space
        add     %o0, %o2, %o0           ! get to end of destination space

.chksize:
	cmp	%o2, 0x20
	bgu,pn	%ncc, .dbalign
	nop

.bytecp:
	tst	%o2
	bleu,a,pn %ncc, exitovbc
	nop

1:
	dec	%o0			! decrement to address
	dec	%o1			! decrement from address
	ldub	[%o1], %o4
	deccc	%o2
	bgu,pt	%ncc, 1b
	stb	%o4, [%o0]
exitovbc:
	retl
	mov	%o5, %o0

.dbalign:
	andcc	%o0, 7, %o3
	bz	%ncc, .dbbck
	nop
					! %o3 has bytes till dst 8 bytes aligned
	sub	%o2, %o3, %o2		! update o2 with new count
2:
	dec	%o1
	dec	%o0
	ldub	[%o1], %o4
	deccc	%o3
	bgu,pt	%ncc, 2b
	stb	%o4, [%o0]

	! Now Destination is 8 byte aligned
.dbbck:
	save	%sp, -SA(MINFRAME), %sp

	andn	%i2, 0x7, %i3		! %i3 count is multiple of 8 bytes size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	andcc	%i1, 7, %g1		! is src aligned on 8 bytes
					! %g1 has src offset
	bz	%ncc, .dbcopybc
	nop

	sll	%g1, 3, %o1		! left shift
	mov	0x40, %g5
	sub	%g5, %o1, %g5		! right shift = (64 - left shift)

.cpy_dbwdbc:
	sub	%i1, %g1, %i1		! align the src at 8 bytes.
	ldx	[%i1], %o2
2:
	sub	%i0, 0x8, %i0
	ldx	[%i1-0x8], %o4		! we are at the end
	ALIGN_DATA_BC(%o2, %o4, %g5, %o1, %o3)
	stx	%o2, [%i0]
	mov	%o4, %o2
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, 2b
	sub	%i1, 0x8, %i1
	ba	.bytebc
	add	%i1, %g1, %i1

.dbcopybc:
	sub	%i1, 8, %i1
	sub	%i0, 8, %i0		! we are at the end
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .dbcopybc
	nop

.bytebc:
	tst	%i2
	bleu,a,pn %ncc, exitbc
	nop

1:
	dec	%i0			! decrement to address
	dec	%i1			! decrement from address
	ldub	[%i1], %i4
	deccc	%i2
	bgu,pt	%ncc, 1b
	stb	%i4, [%i0]
exitbc:
	ret
	restore	%i5, %g0, %o0
 
	SET_SIZE(memmove)


	ENTRY(memcpy)
	ENTRY(__align_cpy_1)
forcpy:
	mov	%o0, %g5		! save des address for return val
	cmp	%o2, 17			! for small counts copy bytes
	bleu,pt	%ncc, .dbytecp
	nop
	cmp	%o2, 0x80		! For lengths less than 128 bytes
	bgu,pn	%ncc, .blkalgndst	! no block st/quad ld
	andcc	%o1, 3, %o5		! is src word aligned
	bz,pn	%ncc, .aldst
	cmp	%o5, 2			! is src half-word aligned
	be,pt	%ncc, .s2algn
	cmp	%o5, 3			! src is byte aligned
.s1algn:ldub	[%o1], %o3		! move 1 or 3 bytes to align it
	inc	1, %o1
	stb	%o3, [%g5]		! move a byte to align src
	inc	1, %g5
	bne,pt	%ncc, .s2algn
	dec	%o2
	b	.ald			! now go align dest
	andcc	%g5, 3, %o5

.s2algn:lduh	[%o1], %o3		! know src is 2 byte alinged
	inc	2, %o1
	srl	%o3, 8, %o4
	stb	%o4, [%g5]		! have to do bytes,
	stb	%o3, [%g5 + 1]		! don't know dst alingment
	inc	2, %g5
	dec	2, %o2

.aldst:	andcc	%g5, 3, %o5		! align the destination address
.ald:	bz,pn	%ncc, .w4cp
	cmp	%o5, 2
	bz,pn	%ncc, .w2cp
	cmp	%o5, 3
.w3cp:	lduw	[%o1], %o4
	inc	4, %o1
	srl	%o4, 24, %o5
	stb	%o5, [%g5]
	bne,pt	%ncc, .w1cp
	inc	%g5
	dec	1, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %g5, %o1		! o1 gets the difference

1:	sll	%o4, 8, %g1		! save residual bytes
	lduw	[%o1+%g5], %o4
	deccc	4, %o3
	srl	%o4, 24, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%g5]
	bnz,pt	%ncc, 1b
	inc	4, %g5
	sub	%o1, 3, %o1		! used one byte of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w1cp:	srl	%o4, 8, %o5
	sth	%o5, [%g5]
	inc	2, %g5
	dec	3, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %g5, %o1		! o1 gets the difference

2:	sll	%o4, 24, %g1		! save residual bytes
	lduw	[%o1+%g5], %o4
	deccc	4, %o3
	srl	%o4, 8, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%g5]
	bnz,pt	%ncc, 2b
	inc	4, %g5
	sub	%o1, 1, %o1		! used three bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w2cp:	lduw	[%o1], %o4
	inc	4, %o1
	srl	%o4, 16, %o5
	sth	%o5, [%g5]
	inc	2, %g5
	dec	2, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %g5, %o1		! o1 gets the difference
	
3:	sll	%o4, 16, %g1		! save residual bytes
	lduw	[%o1+%g5], %o4
	deccc	4, %o3
	srl	%o4, 16, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%g5]
	bnz,pt	%ncc, 3b
	inc	4, %g5
	sub	%o1, 2, %o1		! used two bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w4cp:	andn	%o2, 3, %o3		! o3 is aligned word count
	sub	%o1, %g5, %o1		! o1 gets the difference

1:	lduw	[%o1+%g5], %o4		! read from address
	deccc	4, %o3			! decrement count
	st	%o4, [%g5]		! write at destination address
	bgu,pt	%ncc, 1b
	inc	4, %g5			! increment to address
	b	7f
	and	%o2, 3, %o2		! number of leftover bytes, if any

	!
	! differenced byte copy, works with any alignment
	!
.dbytecp:
	b	7f
	sub	%o1, %g5, %o1		! o1 gets the difference

4:	stb	%o4, [%g5]		! write to address
	inc	%g5			! inc to address
7:	deccc	%o2			! decrement count
	bgeu,a,pt %ncc,4b		! loop till done
	ldub	[%o1+%g5], %o4		! read from address
	retl				! %o0 was preserved
	nop

.blkalgndst:
	save	%sp, -SA(MINFRAME), %sp
	
	! Block (64 bytes) align the destination.
	! Do not know the alignement of src at this time.
	! Therefore using byte copy.

	andcc	%i0, 0x3f, %i3		! is dst block aligned
	bz	%ncc, .chksrc		! dst already block aligned
	sub	%i3, 0x40, %i3
	neg	%i3			! bytes till dst 64 bytes aligned
	sub	%i2, %i3, %i2		! update i2 with new count

1:	ldub	[%i1], %i4
	stb	%i4, [%i0]
	inc	%i1
	deccc	%i3
	bgu,pt	%ncc, 1b
	inc	%i0

	! Now Destination is block (64 bytes) aligned
.chksrc:
	andn	%i2, 0x3f, %i3		! %i3 count is multiple of block size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi

	andcc	%i1, 0xf, %l1		! is src quadword aligned
	bz,pn	%ncc, .blkcpy		! src offset in %l1
	nop
	cmp	%l1, 0x8
	bgu	%ncc, .cpy_upper_double
	nop
	blu	%ncc, .cpy_lower_double
	nop

	! Falls through when source offset is equal to 8 i.e.
	! source is double word aligned.
	! In this case no shift/merge of data is required
	sub	%i1, %l1, %i1		! align the src at 16 bytes.
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %o2
loop0:
	ldda	[%i1+0x10]%asi, %o4
	prefetch [%o0+0x40], #one_read

	stxa	%o3, [%i0+0x0]%asi
	stxa	%o4, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %o2
	stxa	%o5, [%i0+0x10]%asi
	stxa	%o2, [%i0+0x18]%asi

	ldda	[%i1+0x30]%asi, %o4
	stxa	%o3, [%i0+0x20]%asi
	stxa	%o4, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %o2
	stxa	%o5, [%i0+0x30]%asi
	stxa	%o2, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, loop0
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %l1, %i1		! increment the source by src offset

.cpy_lower_double:
	sub	%i1, %l1, %i1		! align the src at 16 bytes.
	sll	%l1, 3, %l2		! %l2 left shift
	mov	0x40, %l3
	sub	%l3, %l2, %l3		! %l3 right shift = (64 - left shift)
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %o2	! partial data in %o2 and %o3 has
					! complete data
loop1:
	ldda	[%i1+0x10]%asi, %o4	! %o4 has partial data for this read.
	ALIGN_DATA(%o2, %o3, %o4, %l2, %l3, %g1)	! merge %o2, %o3 and %o4
							! into %o2 and %o3
	prefetch [%o0+0x40], #one_read
	stxa	%o2, [%i0+0x0]%asi
	stxa	%o3, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %o2
	ALIGN_DATA(%o4, %o5, %o2, %l2, %l3, %g1)	! merge %o2 with %o5 and
	stxa	%o4, [%i0+0x10]%asi			! %o4 from previous read
	stxa	%o5, [%i0+0x18]%asi			! into %o4 and %o5

	! Repeat the same for next 32 bytes.

	ldda	[%i1+0x30]%asi, %o4
	ALIGN_DATA(%o2, %o3, %o4, %l2, %l3, %g1)
	stxa	%o2, [%i0+0x20]%asi
	stxa	%o3, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %o2
	ALIGN_DATA(%o4, %o5, %o2, %l2, %l3, %g1)
	stxa	%o4, [%i0+0x30]%asi
	stxa	%o5, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, loop1
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %l1, %i1		! increment the source by src offset

.cpy_upper_double:
	sub	%i1, %l1, %i1		! align the src at 16 bytes.
	mov	0x8, %l2
	sub	%l1, %l2, %l2
	sll	%l2, 3, %l2		! %l2 left shift
	mov	0x40, %l3
	sub	%l3, %l2, %l3		! %l3 right shift = (64 - left shift)
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %o2	! partial data in %o3 for this read and
					! no data in %o2
loop2:
	ldda	[%i1+0x10]%asi, %o4	! %o4 has complete data and %o5 has
					! partial
	ALIGN_DATA(%o3, %o4, %o5, %l2, %l3, %g1)	! merge %o3, %o4 and %o5
							! into %o3 and %o4
	prefetch [%o0+0x40], #one_read
	stxa	%o3, [%i0+0x0]%asi
	stxa	%o4, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %o2
	ALIGN_DATA(%o5, %o2, %o3, %l2, %l3, %g1)	! merge %o2 and %o3 with
	stxa	%o5, [%i0+0x10]%asi			! %o5 from previous read
	stxa	%o2, [%i0+0x18]%asi			! into %o5 and %o2

	! Repeat the same for next 32 bytes.

	ldda	[%i1+0x30]%asi, %o4
	ALIGN_DATA(%o3, %o4, %o5, %l2, %l3, %g1)
	stxa	%o3, [%i0+0x20]%asi
	stxa	%o4, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %o2
	ALIGN_DATA(%o5, %o2, %o3, %l2, %l3, %g1)
	stxa	%o5, [%i0+0x30]%asi
	stxa	%o2, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, loop2
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %l1, %i1		! increment the source by src offset


	! Do fast copy using ASI_BLK_INIT_ST_QUAD_LDD_P
.blkcpy:
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
1:
	prefetch [%o0+0x40], #one_read

	ldda	[%i1+0x0]%asi, %o2
	ldda	[%i1+0x10]%asi, %o4

	stxa	%o2, [%i0+0x0]%asi
	stxa	%o3, [%i0+0x8]%asi
	stxa	%o4, [%i0+0x10]%asi
	stxa	%o5, [%i0+0x18]%asi

	ldda	[%i1+0x20]%asi, %o2
	ldda	[%i1+0x30]%asi, %o4

	stxa	%o2, [%i0+0x20]%asi
	stxa	%o3, [%i0+0x28]%asi
	stxa	%o4, [%i0+0x30]%asi
	stxa	%o5, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, 1b
	add	%i0, 0x40, %i0

.blkdone:
	membar	#Sync
	mov	ASI_PNF, %asi		! restore %asi to default
					! ASI_PRIMARY_NOFAULT value

	! Copy as much rest of the data as double word copy.
.cpy_wd:
	cmp	%i2, 0x8
	blu	%ncc, .dbdone		! Not enough bytes to copy as double
	nop

	andn	%i2, 0x7, %i3		! %i3 count is multiple of 8 bytes size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	andcc	%i1, 7, %l1		! is src aligned on a 8 bytes
	bz	%ncc, .dbcopy
	nop

	sll	%l1, 3, %l2		! left shift
	mov	0x40, %l3
	sub	%l3, %l2, %l3		! right shift = (64 - left shift)

.copy_wd:
	sub	%i1, %l1, %i1		! align the src at 8 bytes.
	ldx	[%i1], %o2
2:
	ldx	[%i1+8], %o4
	ALIGN_DATA_EW(%o2, %o4, %l2, %l3, %o3)
	stx	%o2, [%i0]
	mov	%o4, %o2
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, 2b
	add	%i0, 0x8, %i0
	ba	.dbdone
	add	%i1, %l1, %i1

.dbcopy:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .dbcopy
	add	%i0, 0x8, %i0

.dbdone:
	tst	%i2
	bz,pt	%ncc, .blkexit
	nop

.residue:
	ldub	[%i1], %i4
	stb	%i4, [%i0]
	inc	%i1
	deccc	%i2
	bgu,pt	%ncc, .residue
	inc	%i0

.blkexit:
	ret
	restore	%g5, %g0, %o0
	SET_SIZE(memcpy)
	SET_SIZE(__align_cpy_1)
