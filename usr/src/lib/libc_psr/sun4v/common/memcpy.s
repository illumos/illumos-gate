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

	.file	"%M%"

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

#ifdef	NIAGARA2_IMPL
#include <sys/sun4asi.h>

#define	ALIGN_OFF_1_7			\
	faligndata %d0, %d2, %d48	;\
	faligndata %d2, %d4, %d50	;\
	faligndata %d4, %d6, %d52	;\
	faligndata %d6, %d8, %d54	;\
	faligndata %d8, %d10, %d56	;\
	faligndata %d10, %d12, %d58	;\
	faligndata %d12, %d14, %d60	;\
	faligndata %d14, %d16, %d62

#define	ALIGN_OFF_8_15			\
	faligndata %d2, %d4, %d48	;\
	faligndata %d4, %d6, %d50	;\
	faligndata %d6, %d8, %d52	;\
	faligndata %d8, %d10, %d54	;\
	faligndata %d10, %d12, %d56	;\
	faligndata %d12, %d14, %d58	;\
	faligndata %d14, %d16, %d60	;\
	faligndata %d16, %d18, %d62

#define	ALIGN_OFF_16_23			\
	faligndata %d4, %d6, %d48	;\
	faligndata %d6, %d8, %d50	;\
	faligndata %d8, %d10, %d52	;\
	faligndata %d10, %d12, %d54	;\
	faligndata %d12, %d14, %d56	;\
	faligndata %d14, %d16, %d58	;\
	faligndata %d16, %d18, %d60	;\
	faligndata %d18, %d20, %d62

#define	ALIGN_OFF_24_31			\
	faligndata %d6, %d8, %d48	;\
	faligndata %d8, %d10, %d50	;\
	faligndata %d10, %d12, %d52	;\
	faligndata %d12, %d14, %d54	;\
	faligndata %d14, %d16, %d56	;\
	faligndata %d16, %d18, %d58	;\
	faligndata %d18, %d20, %d60	;\
	faligndata %d20, %d22, %d62

#define	ALIGN_OFF_32_39			\
	faligndata %d8, %d10, %d48	;\
	faligndata %d10, %d12, %d50	;\
	faligndata %d12, %d14, %d52	;\
	faligndata %d14, %d16, %d54	;\
	faligndata %d16, %d18, %d56	;\
	faligndata %d18, %d20, %d58	;\
	faligndata %d20, %d22, %d60	;\
	faligndata %d22, %d24, %d62

#define	ALIGN_OFF_40_47			\
	faligndata %d10, %d12, %d48	;\
	faligndata %d12, %d14, %d50	;\
	faligndata %d14, %d16, %d52	;\
	faligndata %d16, %d18, %d54	;\
	faligndata %d18, %d20, %d56	;\
	faligndata %d20, %d22, %d58	;\
	faligndata %d22, %d24, %d60	;\
	faligndata %d24, %d26, %d62

#define	ALIGN_OFF_48_55			\
	faligndata %d12, %d14, %d48	;\
	faligndata %d14, %d16, %d50	;\
	faligndata %d16, %d18, %d52	;\
	faligndata %d18, %d20, %d54	;\
	faligndata %d20, %d22, %d56	;\
	faligndata %d22, %d24, %d58	;\
	faligndata %d24, %d26, %d60	;\
	faligndata %d26, %d28, %d62

#define	ALIGN_OFF_56_63			\
	faligndata %d14, %d16, %d48	;\
	faligndata %d16, %d18, %d50	;\
	faligndata %d18, %d20, %d52	;\
	faligndata %d20, %d22, %d54	;\
	faligndata %d22, %d24, %d56	;\
	faligndata %d24, %d26, %d58	;\
	faligndata %d26, %d28, %d60	;\
	faligndata %d28, %d30, %d62

#else	/* NIAGARA2_IMPL */
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
#endif	/* NIAGARA2_IMPL */

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

	ENTRY(memmove)
	cmp	%o1, %o0	! if from address is >= to use forward copy
	bgeu,pn	%ncc, forcpy	! else use backward if ...
	sub	%o0, %o1, %o4	! get difference of two addresses
	cmp	%o2, %o4	! compare size and difference of addresses
	bleu,pn	%ncc, forcpy	! if size is bigger, do overlapped copy
	add     %o1, %o2, %o5	! get to end of source space

        !
        ! an overlapped copy that must be done "backwards"
        !
.chksize:
	cmp	%o2, 8			! less than 8 byte do byte copy
	blu,pt %ncc, 2f			! else continue

	! Now size is bigger than 8
.dbalign:
	add     %o0, %o2, %g1           ! get to end of dest space
	andcc	%g1, 7, %o3		! %o3 has bytes till dst 8 bytes aligned
	bz,a,pn	%ncc, .dbbck		! if dst is not 8 byte aligned: align it
	andn	%o2, 7, %o3		! %o3 count is multiple of 8 bytes size
	sub	%o2, %o3, %o2		! update o2 with new count

1:	dec	%o5			! decrement source
	ldub	[%o5], %g1		! load one byte
	deccc	%o3			! decrement count
	bgu,pt	%ncc, 1b		! if not done keep copying
	stb	%g1, [%o5+%o4]		! store one byte into dest
	andncc	%o2, 7, %o3		! %o3 count is multiple of 8 bytes size
	bz,pn	%ncc, 2f		! if size < 8, move to byte copy

	! Now Destination is 8 byte aligned
.dbbck:
	andcc	%o5, 7, %o0		! %o0 has src offset
	bz,a,pn	%ncc, .dbcopybc		! if src is aligned to fast mem move
	sub	%o2, %o3, %o2		! Residue bytes in %o2

.cpy_dbwdbc:				! alignment of src is needed
 	sub	%o2, 8, %o2             ! set size one loop ahead
	sll	%o0, 3, %g1		! %g1 is left shift
	mov	64, %g5			! init %g5 to be 64
	sub	%g5, %g1, %g5		! %g5 right shift = (64 - left shift)
	sub	%o5, %o0, %o5		! align the src at 8 bytes.
	add	%o4, %o0, %o4		! increase difference between src & dst
	ldx	[%o5], %o1		! load first 8 bytes
	srlx	%o1, %g5, %o1
1:	sub	%o5, 8, %o5		! subtract 8 from src
	ldx	[%o5], %o0		! load 8 byte
	sllx	%o0, %g1, %o3		! shift loaded 8 bytes left into tmp reg
	or	%o1, %o3, %o3		! align data
	stx	%o3, [%o5+%o4]		! store 8 byte
	subcc	%o2, 8, %o2		! subtract 8 byte from size
	bg,pt	%ncc, 1b		! if size > 0 continue
	srlx	%o0, %g5, %o1		! move extra byte for the next use

	srl	%g1, 3, %o0		! retsote %o0 value for alignment
	add	%o5, %o0, %o5		! restore src alignment
	sub	%o4, %o0, %o4		! restore difference between src & dest

 	ba	2f			! branch to the trailing byte copy
 	add	%o2, 8, %o2             ! restore size value

.dbcopybc:				! alignment of src is not needed
1:	sub	%o5, 8, %o5		! subtract from src
	ldx	[%o5], %g1		! load 8 bytes
	subcc	%o3, 8, %o3		! subtract from size
	bgu,pt	%ncc, 1b		! if size is bigger 0 continue
	stx	%g1, [%o5+%o4]		! store 8 bytes to destination

	ba	2f
	nop

.bcbyte:
1:	ldub	[%o5], %g1		! load one byte
	stb	%g1, [%o5+%o4]		! store one byte
2:	deccc	%o2			! decrement size
	bgeu,a,pt %ncc, 1b		! if size is >=0 continue
	dec	%o5			! decrement from address

.exitbc:				! exit from backward copy
	retl
	add	%o5, %o4, %o0		! restore dest addr
	SET_SIZE(memmove)

	ENTRY(memcpy)
	ENTRY(__align_cpy_1)
forcpy:
	mov	%o0, %g5		! save des address for return val
	cmp	%o2, 17			! for small counts copy bytes
	bleu,pt	%ncc, .dbytecp
	nop

	cmp	%o2, 0x80		! For lengths less than 128 bytes no
	bleu,pn	%ncc, .no_blkcpy	! copy using ASI_BLK_INIT_ST_QUAD_LDD_P

	/*
	 * Make sure that source and destination buffers are 64 bytes apart.
	 * If they are not, do not use ASI_BLK_INIT_ST_QUAD_LDD_P asi to copy
	 * the data.
	 */
	subcc	%o1, %o0, %o3
	blu	%ncc, .blkalgndst
	cmp	%o3, 0x40		! if src - dst >= 0x40
	bgeu,pt	%ncc, .blkalgndst	! then use ASI_BLK_INIT_ST_QUAD_LDD_P
.no_blkcpy:
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
	
#ifdef	NIAGARA2_IMPL
	rd	 %fprs, %l7		! save orig %fprs into %l7
         
        ! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
        ! So set it anyway, without checking.
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1
#endif	/* NIAGARA2_IMPL */

	! Block (64 bytes) align the destination.
	andcc	%i0, 0x3f, %i3		! is dst block aligned
	bz	%ncc, .chksrc		! dst already block aligned
	sub	%i3, 0x40, %i3
	neg	%i3			! bytes till dst 64 bytes aligned
	sub	%i2, %i3, %i2		! update i2 with new count

	! Based on source and destination alignment do
	! either 8 bytes, 4 bytes, 2 bytes or byte copy.

	! Is dst & src 8B aligned
	or	%i0, %i1, %o2
	andcc	%o2, 0x7, %g0
	bz	%ncc, .alewdcp
	nop

	! Is dst & src 4B aligned
	andcc	%o2, 0x3, %g0
	bz	%ncc, .alwdcp
	nop

	! Is dst & src 2B aligned
	andcc	%o2, 0x1, %g0
	bz	%ncc, .alhlfwdcp
	nop

	! 1B aligned
1:	ldub	[%i1], %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i3
	bgu,pt	%ncc, 1b
	inc	%i0

	ba	.chksrc
	nop

	! dst & src 4B aligned
.alwdcp:
	ld	[%i1], %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	subcc	%i3, 0x4, %i3
	bgu,pt	%ncc, .alwdcp
	add	%i0, 0x4, %i0

	ba	.chksrc
	nop

	! dst & src 2B aligned
.alhlfwdcp:
	lduh	[%i1], %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	subcc	%i3, 0x2, %i3
	bgu,pt	%ncc, .alhlfwdcp
	add	%i0, 0x2, %i0

	ba	.chksrc
	nop

	! dst & src 8B aligned
.alewdcp:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .alewdcp
	add	%i0, 0x8, %i0

	! Now Destination is block (64 bytes) aligned
.chksrc:
	andn	%i2, 0x3f, %i3		! %i3 count is multiple of block size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi

#ifdef	NIAGARA2_IMPL
	andn	%i1, 0x3f, %l0		! %l0 has block aligned src address
	prefetch [%l0+0x0], #one_read
	andcc	%i1, 0x3f, %g0		! is src 64B aligned
	bz,pn	%ncc, .blkcpy
	nop

	! handle misaligned source cases
	alignaddr %i1, %g0, %g0		! generate %gsr

	srl	%i1, 0x3, %l1		! src add bits 3, 4, 5 are now least
					! significant in %l1
	andcc	%l1, 0x7, %l2		! mask everything except bits 1, 2, 3
	add	%i1, %i3, %i1

	! switch statement to get to right 8 byte block within
	! 64 byte block
	cmp	 %l2, 0x4
	bgeu,a	 hlf
	cmp	 %l2, 0x6
	cmp	 %l2, 0x2
	bgeu,a	 sqtr
	nop
	cmp	 %l2, 0x1
	be,a	 off15
	nop
	ba	 off7
	nop
sqtr:
	be,a	 off23
	nop
	ba,a	 off31
	nop

hlf:
	bgeu,a	 fqtr
	nop	 
	cmp	 %l2, 0x5
	be,a	 off47
	nop
	ba	 off39
	nop
fqtr:
	be,a	 off55
	nop

	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
7:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_56_63
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 7b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off7:
	ldda	[%l0]ASI_BLK_P, %d0
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
0:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_1_7
	fmovd	%d16, %d0
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 0b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off15:
	ldd	[%l0+0x8], %d2
	ldd	[%l0+0x10], %d4
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
1:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_8_15
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 1b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off23:
	ldd	[%l0+0x10], %d4
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
2:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_16_23
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 2b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off31:
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
3:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_24_31
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 3b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off39:
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
4:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_32_39
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 4b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off47:
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
5:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_40_47
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 5b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

off55:
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
6:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_48_55
	fmovd	%d28, %d12
	fmovd	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 6b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

.blkcpy:
	prefetch [%i1+0x40], #one_read
	prefetch [%i1+0x80], #one_read
8:
	stxa	%g0, [%i0]%asi		! initialize the cache line
	ldda	[%i1]ASI_BLK_P, %d0
	stda	%d0, [%i0]ASI_BLK_P

	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 8b
	prefetch [%i1+0x80], #one_read
	membar	#Sync

.blkdone:
#else	/* NIAGARA2_IMPL */
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
#endif	/* NIAGARA2_IMPL */

	mov	ASI_PNF, %asi		! restore %asi to default
					! ASI_PRIMARY_NOFAULT value
	tst	%i2
	bz,pt	%ncc, .blkexit
	nop

	! Handle trailing bytes
	cmp	%i2, 0x8
	blu,pt	%ncc, .residue
	nop

	! Can we do some 8B ops
	or	%i1, %i0, %o2
	andcc	%o2, 0x7, %g0
	bnz	%ncc, .last4
	nop

	! Do 8byte ops as long as possible
.last8:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	sub	%i2, 0x8, %i2
	cmp	%i2, 0x8
	bgu,pt	%ncc, .last8
	add	%i0, 0x8, %i0

	tst	%i2
	bz,pt	%ncc, .blkexit
	nop

	ba	.residue
	nop

.last4:
	! Can we do 4B ops
	andcc	%o2, 0x3, %g0
	bnz	%ncc, .last2
	nop
1:
	ld	[%i1], %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	sub	%i2, 0x4, %i2
	cmp	%i2, 0x4
	bgu,pt	%ncc, 1b
	add	%i0, 0x4, %i0

	cmp	%i2, 0
	bz,pt	%ncc, .blkexit
	nop

	ba	.residue
	nop

.last2:
	! Can we do 2B ops
	andcc	%o2, 0x1, %g0
	bnz	%ncc, .residue
	nop

1:
	lduh	[%i1], %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	sub	%i2, 0x2, %i2
	cmp	%i2, 0x2
	bgu,pt	%ncc, 1b
	add	%i0, 0x2, %i0

	cmp	%i2, 0
	bz,pt	%ncc, .blkexit
	nop

.residue:
	ldub	[%i1], %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i2
	bgu,pt	%ncc, .residue
	inc	%i0

.blkexit:
#ifdef	NIAGARA2_IMPL
	and	%l7, 0x4, %l7		! fprs.du = fprs.dl = 0
	wr	%l7, %g0, %fprs		! fprs = %l7 - restore fprs.fef
#endif	/* NIAGARA2_IMPL */
	ret
	restore	%g5, %g0, %o0
	SET_SIZE(memcpy)
	SET_SIZE(__align_cpy_1)
