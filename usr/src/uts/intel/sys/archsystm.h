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

#ifndef _SYS_ARCHSYSTM_H
#define	_SYS_ARCHSYSTM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * A selection of ISA-dependent interfaces
 */

#include <vm/seg_enum.h>
#include <vm/page.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern greg_t getfp(void);
extern int getpil(void);

extern ulong_t getcr0(void);
extern void setcr0(ulong_t);
extern ulong_t getcr2(void);

#if defined(__i386)
extern uint16_t getgs(void);
extern void setgs(uint16_t);
#endif

extern void sti(void);

extern void tenmicrosec(void);

extern void restore_int_flag(int);
extern int clear_int_flag(void);

extern void int3(void);
extern void int18(void);
extern void int20(void);

#if defined(__amd64)
extern void sys_syscall();
extern void sys_syscall32();
extern void sys_lcall32();
extern void sys_syscall_int();
extern void brand_sys_syscall();
extern void brand_sys_syscall32();
extern void brand_sys_syscall_int();
#elif defined(__i386)
extern void sys_call();
extern void brand_sys_call();
#endif
extern void sys_sysenter();
extern void _sys_sysenter_post_swapgs();
extern void brand_sys_sysenter();
extern void _brand_sys_sysenter_post_swapgs();

extern void dosyscall(void);

extern void bind_hwcap(void);

extern uint8_t inb(int port);
extern uint16_t inw(int port);
extern uint32_t inl(int port);
extern void outb(int port, uint8_t value);
extern void outw(int port, uint16_t value);
extern void outl(int port, uint32_t value);

extern void pc_reset(void) __NORETURN;
extern void reset(void) __NORETURN;
extern int goany(void);

extern void setgregs(klwp_t *, gregset_t);
extern void getgregs(klwp_t *, gregset_t);
extern void setfpregs(klwp_t *, fpregset_t *);
extern void getfpregs(klwp_t *, fpregset_t *);

#if defined(_SYSCALL32_IMPL)
extern void getgregs32(klwp_t *, gregset32_t);
extern void setfpregs32(klwp_t *, fpregset32_t *);
extern void getfpregs32(klwp_t *, fpregset32_t *);
#endif

struct fpu_ctx;

extern void fp_free(struct fpu_ctx *, int);
extern void fp_save(struct fpu_ctx *);
extern void fp_restore(struct fpu_ctx *);

extern int fpu_pentium_fdivbug;

extern void sep_save(void *);
extern void sep_restore(void *);

extern void brand_interpositioning_enable(void);
extern void brand_interpositioning_disable(void);

struct regs;

extern int instr_size(struct regs *, caddr_t *, enum seg_rw);

extern void realsigprof(int, int);

extern int enable_cbcp; /* patchable in /etc/system */

extern uint_t cpu_hwcap_flags;
extern uint_t cpu_freq;
extern uint64_t cpu_freq_hz;

extern caddr_t i86devmap(pfn_t, pgcnt_t, uint_t);
extern page_t *page_numtopp_alloc(pfn_t pfnum);

extern void hwblkclr(void *, size_t);
extern void hwblkpagecopy(const void *, void *);

extern void (*kcpc_hw_enable_cpc_intr)(void);

extern void setup_mca(void);
extern void setup_mtrr(void);
extern void patch_tsc(void);

extern user_desc_t *cpu_get_gdt(void);

/*
 * Warning: these routines do -not- use normal calling conventions!
 */
extern void setup_121_andcall(void (*)(ulong_t), ulong_t);
extern void enable_big_page_support(ulong_t);
extern void enable_pae(ulong_t);

extern hrtime_t (*gethrtimef)(void);
extern hrtime_t (*gethrtimeunscaledf)(void);
extern void (*scalehrtimef)(hrtime_t *);
extern void (*gethrestimef)(timestruc_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ARCHSYSTM_H */
