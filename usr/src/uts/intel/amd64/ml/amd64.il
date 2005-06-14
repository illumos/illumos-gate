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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
/ return value of cr3 register
/
	.inline	getcr3,0
	movq	%cr3, %rax
	.end

/
/ reload cr3 register with its current value
/
	.inline	reload_cr3,0
	movq	%cr3, %rdi
	movq	%rdi, %cr3
	.end

/
/ return value of cr8 register
/
	.inline	getcr8,0
	movq	%cr8, %rax
	.end

/
/ set cr8 register
/
	.inline	setcr8,0
	movq	%rdi, %cr8
	.end

/
/ convert ipl to spl.  This is the identity function for i86
/
	.inline	ipltospl,0
	movq	%rdi, %rax
	.end

/
/ enable interrupts
/
	.inline	sti,0
	sti
	.end

/
/ disable interrupts
/
	.inline cli,0
	cli
	.end

/
/ find the low order bit in a word
/
	.inline lowbit,4
	movq	$-1, %rax
	bsfq	%rdi, %rax
	incq	%rax
	.end

/
/ disable interrupts and return value describing if interrupts were enabled
/
	/* XX64 These don't work correctly with SOS9 build 13.0 yet
	.inline	clear_int_flag,0
	pushfq
	cli
	popq	%rax
	.end

	.inline	intr_clear,0
	pushfq
	cli
	popq	%rax
	.end
	*/

/
/ restore interrupt enable flag to value returned from 'clear_int_flag' above
/
	/* XX64 These don't work correctly with SOS9 build 13.0 yet
	.inline restore_int_flag,4
	pushq	%rdi
	popfq
	.end

	.inline intr_restore,4
	pushq	%rdi
	popfq
	.end
	*/

/
/ in and out
/
	.inline	inb,4
	movq	%rdi, %rdx
	xorq    %rax, %rax
	inb	(%dx)
	.end

	.inline	inw,4
	movq	%rdi, %rdx
	xorq    %rax, %rax
	inw	(%dx)
	.end

	.inline	inl,4
	movq	%rdi, %rdx
	xorq    %rax, %rax
	inl	(%dx)
	.end

	.inline	outb,8
	movq	%rdi, %rdx
	movq	%rsi, %rax
	outb	(%dx)
	.end

	.inline	outw,8
	movq	%rdi, %rdx
	movq	%rsi, %rax
	outw	(%dx)
	.end

	.inline	outl,8
	movq	%rdi, %rdx
	movq	%rsi, %rax
	outl	(%dx)
	.end

/
/ Networking byte order functions (too bad, Intel has the wrong byte order)
/

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
 * Read Time Stamp Counter
 * uint64_t tsc_read();
 *
 * usage:
 * uint64_t cycles = tsc_read();
 *
 * PPro & PII take no less than 34 cycles to execute rdtsc + stores.
 * Pentium takes about 16 cycles.
 */
	.inline	tsc_read, 0
	rdtsc				/ %edx:%eax = RDTSC
	shlq	$32, %rdx
	orq	%rdx, %rax
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
 * Call the halt instruction. This will put the CPU to sleep until
 * it is again awoken via an interrupt.
 * This function should be called with interrupts already disabled
 * for the CPU.
 * Note that "sti" will only enable interrupts at the end of the
 * subsequent instruction...in this case: "hlt".
 */
	.inline i86_halt,0
	sti
	hlt
	.end
