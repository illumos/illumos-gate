/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>

/*
 * This ASM file contains various routines that are designed to flush
 * microarchitectural buffer state as part of dealing with the
 * microarchitectural data sampling (MDS) vulnerabilities.
 *
 * These are called from various points in the system ranging from interrupts,
 * before going idle, to returning from system calls. This means the following
 * is true about the state of the system:
 *
 *  o All register state is precious, we must not change register state upon
 *    entry or return from these functions.
 *
 *  o %ds is valid.
 *
 *  o %gs is arbitrary, it may be kernel or user. You cannot rely on it.
 *
 *  o Interrupts should be disabled by the caller.
 *
 *  o %cr3 is on the kernel-side and therefore we still have access to kernel
 *    text. In other words, we haven't switched back to the user page table.
 *
 *  o It is up to the caller to insure that a sufficient serializing instruction
 *    has been executed after this to make sure any pending speculations are
 *    captured. In general, this should be handled by the fact that callers of
 *    this are either going to change privilege levels or halt, which makes
 *    these operations safer.
 */

	/*
	 * By default, x86_md_clear is disabled until the system determines that
	 * it both needs MDS related mitigations and we have microcode that
	 * provides the needed functionality.
	 *
	 * The VERW instruction clobbers flags which is why it's important that
	 * we save and restore them here.
	 */
	ENTRY_NP(x86_md_clear)
	ret
	pushfq
	subq	$8, %rsp
	mov	%ds, (%rsp)
	verw	(%rsp)
	addq	$8, %rsp
	popfq
	ret
	SET_SIZE(x86_md_clear)
