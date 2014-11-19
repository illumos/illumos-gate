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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/
/ In-line functions for amd64 kernels.
/

/
/ return current thread pointer
/
/ NOTE: the "0x18" should be replaced by the computed value of the
/	offset of "cpu_thread" from the beginning of the struct cpu.
/	Including "assym.h" does not work, however, since that stuff
/	is PSM-specific and is only visible to the 'unix' build anyway.
/	Same with current cpu pointer, where "0xc" should be replaced
/	by the computed value of the offset of "cpu_self".
/	Ugh -- what a disaster.
/
	.inline	threadp,0
	movq	%gs:0x18, %rax
	.end

/
/ return current cpu pointer
/
	.inline	curcpup,0
	movq	%gs:0x10, %rax
	.end

/
/ return caller
/
	.inline caller,0
	movq	8(%rbp), %rax
	.end

/
/ convert ipl to spl.  This is the identity function for i86
/
	.inline	ipltospl,0
	movq	%rdi, %rax
	.end

/
/ Networking byte order functions (too bad, Intel has the wrong byte order)
/

	.inline	htonll,4
	movq	%rdi, %rax
	bswapq	%rax
	.end

	.inline	ntohll,4
	movq	%rdi, %rax
	bswapq	%rax
	.end

	.inline	htonl,4
	movl	%edi, %eax
	bswap	%eax
	.end

	.inline	ntohl,4
	movl	%edi, %eax
	bswap	%eax
	.end

	.inline	htons,4
	movl	%edi, %eax
	bswap	%eax
	shrl	$16, %eax
	.end

	.inline	ntohs,4
	movl	%edi, %eax
	bswap	%eax
	shrl	$16, %eax
	.end

/*
 * multiply two long numbers and yield a u_lonlong_t result
 * Provided to manipulate hrtime_t values.
 */
	/* XX64 These don't work correctly with SOS9 build 13.0 yet
	.inline mul32, 8
	xorl	%edx, %edx
	movl	%edi, %eax
	mull	%esi
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	.end
	*/
/*
 * Unlock hres_lock and increment the count value. (See clock.h)
 */
	.inline unlock_hres_lock, 0
	lock
	incl	hres_lock
	.end

	.inline	atomic_orb,8
	movl	%esi, %eax
	lock
	orb	%al,(%rdi)
	.end

	.inline	atomic_andb,8
	movl	%esi, %eax
	lock
	andb	%al,(%rdi)
	.end

/*
 * atomic inc/dec operations.
 *	void atomic_inc16(uint16_t *addr) { ++*addr; }
 *	void atomic_dec16(uint16_t *addr) { --*addr; }
 */
	.inline	atomic_inc16,4
	lock
	incw	(%rdi)
	.end

	.inline	atomic_dec16,4
	lock
	decw	(%rdi)
	.end

/*
 * atomic bit clear
 */
	.inline atomic_btr32,8
	lock
	btrl %esi, (%rdi)
	setc %al
	.end

/*
 * Call the pause instruction.  To the Pentium 4 Xeon processor, it acts as
 * a hint that the code sequence is a busy spin-wait loop.  Without a pause
 * instruction in these loops, the P4 Xeon processor may suffer a severe
 * penalty when exiting the loop because the processor detects a possible
 * memory violation.  Inserting the pause instruction significantly reduces
 * the likelihood of a memory order violation, improving performance.
 * The pause instruction is a NOP on all other IA-32 processors.
 */
	.inline ht_pause, 0
	pause
	.end

/*
 * inlines for update_sregs().
 */
        .inline __set_ds, 0
        movw    %di, %ds
        .end

        .inline __set_es, 0
        movw    %di, %es
        .end

        .inline __set_fs, 0
        movw    %di, %fs
        .end

        .inline __set_gs, 0
        movw    %di, %gs
        .end

	/*
	 * OPTERON_ERRATUM_88 requires mfence
	 */
        .inline __swapgs, 0
        mfence
        swapgs
	.end

/*
 * prefetch 64 bytes
 */

 	.inline	prefetch_read_many,8
	prefetcht0	(%rdi)
	prefetcht0	32(%rdi)
	.end

 	.inline	prefetch_read_once,8
	prefetchnta	(%rdi)
	prefetchnta	32(%rdi)
	.end

 	.inline	prefetch_write_many,8
	prefetcht0	(%rdi)
	prefetcht0	32(%rdi)
	.end

 	.inline	prefetch_write_once,8
	prefetcht0	(%rdi)
	prefetcht0	32(%rdi)
	.end
