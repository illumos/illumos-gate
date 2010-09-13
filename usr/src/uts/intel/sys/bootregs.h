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

#ifndef	_SYS_BOOTREGS_H
#define	_SYS_BOOTREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_KERNEL) || defined(_BOOT)

/*
 *  This structure is used by bootops to save/restore registers when
 *  transferring between protected and realmode code.
 *
 *  NOTE: The following macros require an ANSI compiler!
 */

#define	i8080reg(r) union {  /* 8080-like "general purpose" registers */\
	uint32_t e ## r ## x;					\
	struct { uint16_t r ## x; } word;				\
	struct { uint8_t  r ## l, r ## h; } byte;			\
}

#define	i8086reg(r) union { /* 16/32-bit "special purpose" registers  */\
	uint32_t e ## r;						\
	struct { uint16_t r; } word;				\
}

struct bop_regs {
	/*
	 *  Machine state structure for realmode <-> protected mode callout
	 *  operations:
	 */

	i8080reg(a) eax;	/* The so-called "general purpose" registers */
	i8080reg(d) edx;
	i8080reg(c) ecx;
	i8080reg(b) ebx;

	i8086reg(bp) ebp;	/* 16/32-bit "pointer" registers */
	i8086reg(si) esi;
	i8086reg(di) edi;

	uint16_t ds;	/* Segment registers */
	uint16_t es;
	uint16_t fs;
	uint16_t gs;

	uint32_t eflags;
};

#undef	i8080reg
#undef	i8086reg
#endif	/* _KERNEL || _BOOT */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BOOTREGS_H */
