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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64_CPU
#define	_AMD64_CPU

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

extern void amd64_flush_tlb(void);
extern void amd64_flush_tlbentry(caddr_t);

extern ulong_t amd64_get_cr2(void);
extern ulong_t amd64_get_cr0(void);
extern ulong_t amd64_get_cr3(void);
extern ulong_t amd64_get_cr4(void);

extern ulong_t amd64_get_eflags(void);

struct amd64_cpuid_regs {
	uint32_t r_eax;
	uint32_t r_ebx;
	uint32_t r_ecx;
	uint32_t r_edx;
};

#define	AMD64_Auth	0x68747541
#define	AMD64_enti	0x69746e65
#define	AMD64_cAMD	0x444d4163

extern uint32_t amd64_cpuid_supported(void);
extern void amd64_cpuid_insn(uint32_t, struct amd64_cpuid_regs *);
extern uint32_t amd64_special_hw(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_CPU */
