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
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/asm_linkage.h>

ENTRY(outb)
	movw    %di, %dx
	movb    %sil, %al
	outb    (%dx)
	ret
SET_SIZE(outb)

ENTRY(outw)
	movw    %di, %dx
	movw    %si, %ax
	outw    (%dx)
	ret
SET_SIZE(outb)

ENTRY(outl)
	movw    %di, %dx
	movl    %esi, %eax
	outl    (%dx)
	ret
SET_SIZE(outl)

ENTRY(inb)
	movw    %di, %dx
	inb    (%dx)
	ret
SET_SIZE(inb)

ENTRY(inw)
	movw    %di, %dx
	inw    (%dx)
	ret
SET_SIZE(inw)

ENTRY(inl)
	movw    %di, %dx
	inl    (%dx)
	ret
SET_SIZE(inl)

ENTRY(rdmsr)
	movl    %edi, %ecx
	rdmsr
	shlq    $32, %rdx
	orq     %rdx, %rax
	ret
SET_SIZE(rdmsr)

ENTRY(wrmsr)
	movq    %rsi, %rdx
	shrq    $32, %rdx
	movl    %esi, %eax
	movl    %edi, %ecx
	wrmsr
	ret
SET_SIZE(wrmsr)
