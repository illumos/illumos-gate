/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64_CPU
#define	_AMD64_CPU

#ifdef	__cplusplus
extern "C" {
#endif

#include <shared.h>

typedef unsigned int    uint_t;
typedef unsigned long ulong_t;

#define BITX(u, h, l)   (((u) >> (l)) & ((1lu << ((h) - (l) + 1lu)) - 1lu))

#include <controlregs.h>

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
extern void amd64_rdmsr(uint32_t, uint64_t *);
extern void amd64_wrmsr(uint32_t, const uint64_t *);
extern int get_target_operating_mode(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_CPU */
