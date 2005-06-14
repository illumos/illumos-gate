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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/
/ In-line functions for i86 kernels.
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
/ return value of cr3 register
/
	.inline	getcr3,0
	movl	%cr3, %eax
	.end

/
/ reload cr3 register with its current value
/
	.inline	reload_cr3,0
	movl	%cr3, %eax
	movl	%eax, %cr3
	.end

/*
 * Put a new value into cr3 (page table base register
 *	void setcr3(void *value)
 */
	.inline	setcr3,4
	movl	(%esp), %eax
	movl	%eax, %cr3
	.end

/
/ invalidate and flush cache.
/
	.inline	cache_bug,0
	wbinvd
	.end

/
/ convert ipl to spl.  This is the identity function for i86
/
	.inline	ipltospl,0
	movl	(%esp), %eax
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
	movl	$-1, %eax
	bsfl	(%esp), %eax
	incl	%eax
	.end
/
/ find the high order bit in a word
/
	.inline highbit,4
	movl	$-1, %eax
	bsrl	(%esp), %eax
	incl	%eax
	.end

/
/ disable interrupts and return value describing if interrupts were enabled
/
	.inline	clear_int_flag,0
	pushfl
	cli
	popl	%eax
	.end

	.inline	intr_clear,0
	pushfl
	cli
	popl	%eax
	.end

/
/ restore interrupt enable flag to value returned from 'clear_int_flag' above
/
	.inline restore_int_flag,4
	pushl	(%esp)
	popfl
	.end

	.inline intr_restore,4
	pushl	(%esp)
	popfl
	.end

/
/ in and out
/
	.inline	inb,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inb	(%dx)
	.end

	.inline	inw,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inw	(%dx)
	.end

	.inline	inl,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inl	(%dx)
	.end

	.inline	outb,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outb	(%dx)
	.end

	.inline	outw,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outw	(%dx)
	.end

	.inline	outl,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outl	(%dx)
	.end

/
/ Networking byte order functions (too bad, Intel has the wrong byte order)
/

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
 * multiply two long numbers and yield a u_lonlong_t result
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
 * Invalidate TLB translation to 1 page.
 *	void mmu_tlbflush_entry(void *addr)
 */
	.inline	mmu_tlbflush_entry,4
	movl	(%esp), %eax
	invlpg	(%eax)
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
	.end

/*
 * void tsc_clear(register)
 * Clear the local Time Stamp Counter via write-MSR instruction.
 * Note that while this is a 64-bit write, the top 32-bits are
 * ignored, so it isn't massively useful to write anything other
 * than zero.
 */
	.inline  tsc_reset, 4
	movl	(%esp), %ecx
	xorl	%eax, %eax
	movl	%eax, %edx
	wrmsr
	ret
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
