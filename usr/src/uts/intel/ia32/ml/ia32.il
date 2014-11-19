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
/ Inline functions for i386 kernels.
/	Shared between all x86 platform variants.
/

/
/ return current thread pointer
/
/ NOTE: the "0x10" should be replaced by the computed value of the
/	offset of "cpu_thread" from the beginning of the struct cpu.
/	Including "assym.h" does not work, however, since that stuff
/	is PSM-specific and is only visible to the 'unix' build anyway.
/	Same with current cpu pointer, where "0xc" should be replaced
/	by the computed value of the offset of "cpu_self".
/	Ugh -- what a disaster.
/
	.inline	threadp,0
	movl	%gs:0x10, %eax
	.end

/
/ return current cpu pointer
/
	.inline	curcpup,0
	movl	%gs:0xc, %eax
	.end

/
/ return caller
/
	.inline caller,0
	movl	4(%ebp), %eax
	.end

/
/ convert ipl to spl.  This is the identity function for i86
/
	.inline	ipltospl,0
	movl	(%esp), %eax
	.end

/
/ Networking byte order functions (too bad, Intel has the wrong byte order)
/
	.inline	htonll,4
	movl	(%esp), %edx
	movl	4(%esp), %eax
	bswap	%edx
	bswap	%eax
	.end

	.inline	ntohll,4
	movl	(%esp), %edx
	movl	4(%esp), %eax
	bswap	%edx
	bswap	%eax
	.end

	.inline	htonl,4
	movl	(%esp), %eax
	bswap	%eax
	.end

	.inline	ntohl,4
	movl	(%esp), %eax
	bswap	%eax
	.end

	.inline	htons,4
	movl	(%esp), %eax
	bswap	%eax
	shrl	$16, %eax
	.end

	.inline	ntohs,4
	movl	(%esp), %eax
	bswap	%eax
	shrl	$16, %eax
	.end

/*
 * multiply two long numbers and yield a u_longlong_t result
 * Provided to manipulate hrtime_t values.
 */
	.inline mul32, 8
	movl	4(%esp), %eax
	movl	(%esp), %ecx
	mull	%ecx
	.end

/*
 * Unlock hres_lock and increment the count value. (See clock.h)
 */
	.inline unlock_hres_lock, 0
	lock
	incl	hres_lock
	.end

	.inline	atomic_orb,8
	movl	(%esp), %eax
	movl    4(%esp), %edx
	lock
	orb	%dl,(%eax)
	.end

	.inline	atomic_andb,8
	movl	(%esp), %eax
	movl    4(%esp), %edx
	lock
	andb	%dl,(%eax)
	.end

/*
 * atomic inc/dec operations.
 *	void atomic_inc16(uint16_t *addr) { ++*addr; }
 *	void atomic_dec16(uint16_t *addr) { --*addr; }
 */
	.inline	atomic_inc16,4
	movl	(%esp), %eax
	lock
	incw	(%eax)
	.end

	.inline	atomic_dec16,4
	movl	(%esp), %eax
	lock
	decw	(%eax)
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
	rep			/ our compiler doesn't support "pause" yet,
	nop			/ so we're using "F3 90" opcode directly
	.end

/*
 * prefetch 64 bytes
 *
 * prefetch is an SSE extension which is not supported on older 32-bit processors
 * so define this as a no-op for now
 */

 	.inline	prefetch_read_many,4
/	movl		(%esp), %eax
/	prefetcht0	(%eax)
/	prefetcht0	32(%eax)
	.end

 	.inline	prefetch_read_once,4
/	movl		(%esp), %eax
/	prefetchnta	(%eax)
/	prefetchnta	32(%eax)
	.end

 	.inline	prefetch_write_many,4
/	movl		(%esp), %eax
/	prefetcht0	(%eax)
/	prefetcht0	32(%eax)
	.end

 	.inline	prefetch_write_once,4
/	movl		(%esp), %eax
/	prefetcht0	(%eax)
/	prefetcht0	32(%eax)
	.end

