/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1992 Terrence R. Lambert.
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)machdep.c	7.4 (Berkeley) 6/3/91
 */

#include <sys/types.h>
#include <sys/tss.h>
#include <sys/segments.h>
#include <sys/trap.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/kobj.h>
#include <sys/cmn_err.h>
#include <sys/reboot.h>
#include <sys/kdi.h>

extern void syscall_int(void);

/*
 * cpu0 and default tables and structures.
 */
#pragma	align	16(gdt0)
user_desc_t	gdt0[NGDT];		/* global descriptor table */
desctbr_t	gdt0_default_r;

#pragma	align	16(ldt0_default)
user_desc_t	ldt0_default[MINNLDT];	/* default local descriptor table */
system_desc_t	ldt0_default_desc;	/* seg descriptor for ldt0_default */

#if defined(__amd64)
#pragma align	16(ltd0_default64)
user_desc_t	ldt0_default64[MINNLDT]; /* default LDT for 64-bit apps */
system_desc_t	ldt0_default64_desc;	/* seg descriptor for ldt0_default64 */
#endif	/* __amd64 */

#pragma	align	16(idt0)
gate_desc_t	idt0[NIDT]; 		/* interrupt descriptor table */
desctbr_t	idt0_default_r;		/* describes idt0 in IDTR format */

#pragma align	16(ktss0)
struct tss	ktss0;			/* kernel task state structure */

#if defined(__i386)
#pragma align	16(dftss0)
struct tss	dftss0;			/* #DF double-fault exception */
#endif	/* __i386 */

user_desc_t	zero_udesc;		/* base zero user desc native procs */

#if defined(__amd64)
user_desc_t	zero_u32desc;		/* 32-bit compatibility procs */
#endif	/* __amd64 */

#pragma	align	16(dblfault_stack0)
char		dblfault_stack0[DEFAULTSTKSZ];

extern void	fast_null(void);
extern hrtime_t	get_hrtime(void);
extern hrtime_t	gethrvtime(void);
extern hrtime_t	get_hrestime(void);
extern uint64_t	getlgrp(void);

void (*(fasttable[]))(void) = {
	fast_null,			/* T_FNULL routine */
	fast_null,			/* T_FGETFP routine (initially null) */
	fast_null,			/* T_FSETFP routine (initially null) */
	(void (*)())get_hrtime,		/* T_GETHRTIME */
	(void (*)())gethrvtime,		/* T_GETHRVTIME */
	(void (*)())get_hrestime,	/* T_GETHRESTIME */
	(void (*)())getlgrp		/* T_GETLGRP */
};

/*
 * software prototypes for default local descriptor table
 */

/*
 * Routines for loading segment descriptors in format the hardware
 * can understand.
 */

#if defined(__amd64)

/*
 * In long mode we have the new L or long mode attribute bit
 * for code segments. Only the conforming bit in type is used along
 * with descriptor priority and present bits. Default operand size must
 * be zero when in long mode. In 32-bit compatibility mode all fields
 * are treated as in legacy mode. For data segments while in long mode
 * only the present bit is loaded.
 */
void
set_usegd(user_desc_t *dp, uint_t lmode, void *base, size_t size,
    uint_t type, uint_t dpl, uint_t gran, uint_t defopsz)
{
	ASSERT(lmode == SDP_SHORT || lmode == SDP_LONG);

	/*
	 * 64-bit long mode.
	 */
	if (lmode == SDP_LONG)
		dp->usd_def32 = 0;		/* 32-bit operands only */
	else
		/*
		 * 32-bit compatibility mode.
		 */
		dp->usd_def32 = defopsz;	/* 0 = 16, 1 = 32-bit ops */

	dp->usd_long = lmode;	/* 64-bit mode */
	dp->usd_type = type;
	dp->usd_dpl = dpl;
	dp->usd_p = 1;
	dp->usd_gran = gran;		/* 0 = bytes, 1 = pages */

	dp->usd_lobase = (uintptr_t)base;
	dp->usd_midbase = (uintptr_t)base >> 16;
	dp->usd_hibase = (uintptr_t)base >> (16 + 8);
	dp->usd_lolimit = size;
	dp->usd_hilimit = (uintptr_t)size >> 16;
}

#elif defined(__i386)

/*
 * Install user segment descriptor for code and data.
 */
void
set_usegd(user_desc_t *dp, void *base, size_t size, uint_t type,
    uint_t dpl, uint_t gran, uint_t defopsz)
{
	dp->usd_lolimit = size;
	dp->usd_hilimit = (uintptr_t)size >> 16;

	dp->usd_lobase = (uintptr_t)base;
	dp->usd_midbase = (uintptr_t)base >> 16;
	dp->usd_hibase = (uintptr_t)base >> (16 + 8);

	dp->usd_type = type;
	dp->usd_dpl = dpl;
	dp->usd_p = 1;
	dp->usd_def32 = defopsz;	/* 0 = 16, 1 = 32 bit operands */
	dp->usd_gran = gran;		/* 0 = bytes, 1 = pages */
}

#endif	/* __i386 */

/*
 * Install system segment descriptor for LDT and TSS segments.
 */

#if defined(__amd64)

void
set_syssegd(system_desc_t *dp, void *base, size_t size, uint_t type,
    uint_t dpl)
{
	dp->ssd_lolimit = size;
	dp->ssd_hilimit = (uintptr_t)size >> 16;

	dp->ssd_lobase = (uintptr_t)base;
	dp->ssd_midbase = (uintptr_t)base >> 16;
	dp->ssd_hibase = (uintptr_t)base >> (16 + 8);
	dp->ssd_hi64base = (uintptr_t)base >> (16 + 8 + 8);

	dp->ssd_type = type;
	dp->ssd_zero1 = 0;	/* must be zero */
	dp->ssd_zero2 = 0;
	dp->ssd_dpl = dpl;
	dp->ssd_p = 1;
	dp->ssd_gran = 0;	/* force byte units */
}

#elif defined(__i386)

void
set_syssegd(system_desc_t *dp, void *base, size_t size, uint_t type,
    uint_t dpl)
{
	dp->ssd_lolimit = size;
	dp->ssd_hilimit = (uintptr_t)size >> 16;

	dp->ssd_lobase = (uintptr_t)base;
	dp->ssd_midbase = (uintptr_t)base >> 16;
	dp->ssd_hibase = (uintptr_t)base >> (16 + 8);

	dp->ssd_type = type;
	dp->ssd_zero = 0;	/* must be zero */
	dp->ssd_dpl = dpl;
	dp->ssd_p = 1;
	dp->ssd_gran = 0;	/* force byte units */
}

#endif	/* __i386 */

/*
 * Install gate segment descriptor for interrupt, trap, call and task gates.
 */

#if defined(__amd64)

/*
 * Note stkcpy is replaced with ist. Read the PRM for details on this.
 */
void
set_gatesegd(gate_desc_t *dp, void (*func)(void), selector_t sel, uint_t ist,
    uint_t type, uint_t dpl)
{
	dp->sgd_looffset = (uintptr_t)func;
	dp->sgd_hioffset = (uintptr_t)func >> 16;
	dp->sgd_hi64offset = (uintptr_t)func >> (16 + 16);

	dp->sgd_selector =  (uint16_t)sel;
	dp->sgd_ist = ist;
	dp->sgd_type = type;
	dp->sgd_dpl = dpl;
	dp->sgd_p = 1;
}

#elif defined(__i386)

void
set_gatesegd(gate_desc_t *dp, void (*func)(void), selector_t sel,
    uint_t wcount, uint_t type, uint_t dpl)
{
	dp->sgd_looffset = (uintptr_t)func;
	dp->sgd_hioffset = (uintptr_t)func >> 16;

	dp->sgd_selector =  (uint16_t)sel;
	dp->sgd_stkcpy = wcount;
	dp->sgd_type = type;
	dp->sgd_dpl = dpl;
	dp->sgd_p = 1;
}

#endif /* __i386 */

/*
 * Build kernel GDT.
 */

#if defined(__amd64)

static void
init_gdt(void)
{
	desctbr_t	r_bgdt, r_gdt;
	user_desc_t	*bgdt;
	size_t		alen = 0xfffff;	/* entire 32-bit address space */

	/*
	 * Copy in from boot's gdt to our gdt entries 1 - 4.
	 * Entry 0 is the null descriptor by definition.
	 */
	rd_gdtr(&r_bgdt);
	bgdt = (user_desc_t *)r_bgdt.dtr_base;
	if (bgdt == NULL)
		panic("null boot gdt");

	gdt0[GDT_B32DATA] = bgdt[GDT_B32DATA];
	gdt0[GDT_B32CODE] = bgdt[GDT_B32CODE];
	gdt0[GDT_B64DATA] = bgdt[GDT_B64DATA];
	gdt0[GDT_B64CODE] = bgdt[GDT_B64CODE];

	/*
	 * 64-bit kernel code segment.
	 */
	set_usegd(&gdt0[GDT_KCODE], SDP_LONG, NULL, 0, SDT_MEMERA, SEL_KPL,
	    SDP_PAGES, SDP_OP32);

	/*
	 * 64-bit kernel data segment. The limit attribute is ignored in 64-bit
	 * mode, but we set it here to 0xFFFF so that we can use the SYSRET
	 * instruction to return from system calls back to 32-bit applications.
	 * SYSRET doesn't update the base, limit, or attributes of %ss or %ds
	 * descriptors. We therefore must ensure that the kernel uses something,
	 * though it will be ignored by hardware, that is compatible with 32-bit
	 * apps. For the same reason we must set the default op size of this
	 * descriptor to 32-bit operands.
	 */
	set_usegd(&gdt0[GDT_KDATA], SDP_LONG, NULL, alen, SDT_MEMRWA,
	    SEL_KPL, SDP_PAGES, SDP_OP32);
	gdt0[GDT_KDATA].usd_def32 = 1;

	/*
	 * 64-bit user code segment.
	 */
	set_usegd(&gdt0[GDT_UCODE], SDP_LONG, NULL, 0, SDT_MEMERA, SEL_UPL,
	    SDP_PAGES, SDP_OP32);

	/*
	 * 32-bit user code segment.
	 */
	set_usegd(&gdt0[GDT_U32CODE], SDP_SHORT, NULL, alen, SDT_MEMERA,
	    SEL_UPL, SDP_PAGES, SDP_OP32);

	/*
	 * 32 and 64 bit data segments can actually share the same descriptor.
	 * In long mode only the present bit is checked but all other fields
	 * are loaded. But in compatibility mode all fields are interpreted
	 * as in legacy mode so they must be set correctly for a 32-bit data
	 * segment.
	 */
	set_usegd(&gdt0[GDT_UDATA], SDP_SHORT, NULL, alen, SDT_MEMRWA, SEL_UPL,
	    SDP_PAGES, SDP_OP32);

	/*
	 * LDT descriptor for 64-bit processes
	 */
	set_syssegd((system_desc_t *)&gdt0[GDT_LDT], ldt0_default64,
	    sizeof (ldt0_default64) - 1, SDT_SYSLDT, SEL_KPL);
	ldt0_default64_desc = *((system_desc_t *)&gdt0[GDT_LDT]);

	/*
	 * LDT descriptor for 32-bit processes
	 */
	set_syssegd((system_desc_t *)&gdt0[GDT_LDT], ldt0_default,
	    sizeof (ldt0_default) - 1, SDT_SYSLDT, SEL_KPL);
	ldt0_default_desc = *((system_desc_t *)&gdt0[GDT_LDT]);

	/*
	 * Kernel TSS
	 */
	set_syssegd((system_desc_t *)&gdt0[GDT_KTSS], &ktss0,
	    sizeof (ktss0) - 1, SDT_SYSTSS, SEL_KPL);

	/*
	 * Initialize fs and gs descriptors for 32 bit processes.
	 * Only attributes and limits are initialized, the effective
	 * base address is programmed via fsbase/gsbase.
	 */
	set_usegd(&gdt0[GDT_LWPFS], SDP_SHORT, NULL, alen, SDT_MEMRWA,
	    SEL_UPL, SDP_PAGES, SDP_OP32);
	set_usegd(&gdt0[GDT_LWPGS], SDP_SHORT, NULL, alen, SDT_MEMRWA,
	    SEL_UPL, SDP_PAGES, SDP_OP32);

	/*
	 * Install our new GDT
	 */
	r_gdt.dtr_limit = sizeof (gdt0) - 1;
	r_gdt.dtr_base = (uintptr_t)gdt0;
	wr_gdtr(&r_gdt);

	/*
	 * Initialize convenient zero base user descriptors for clearing
	 * lwp private %fs and %gs descriptors in GDT. See setregs() for
	 * an example.
	 */
	set_usegd(&zero_udesc, SDP_LONG, 0, 0, SDT_MEMRWA, SEL_UPL,
	    SDP_BYTES, SDP_OP32);
	set_usegd(&zero_u32desc, SDP_SHORT, 0, -1, SDT_MEMRWA, SEL_UPL,
	    SDP_PAGES, SDP_OP32);
}

#elif defined(__i386)

static void
init_gdt(void)
{
	desctbr_t	r_bgdt, r_gdt;
	user_desc_t	*bgdt;

	/*
	 * Copy in from boot's gdt to our gdt entries 1 - 4.
	 * Entry 0 is null descriptor by definition.
	 */
	rd_gdtr(&r_bgdt);
	bgdt = (user_desc_t *)r_bgdt.dtr_base;
	if (bgdt == NULL)
		panic("null boot gdt");

	gdt0[GDT_BOOTFLAT] = bgdt[GDT_BOOTFLAT];
	gdt0[GDT_BOOTCODE] = bgdt[GDT_BOOTCODE];
	gdt0[GDT_BOOTCODE16] = bgdt[GDT_BOOTCODE16];
	gdt0[GDT_BOOTDATA] = bgdt[GDT_BOOTDATA];

	/*
	 * Text and data for both kernel and user span entire 32 bit
	 * address space.
	 */

	/*
	 * kernel code segment.
	 */
	set_usegd(&gdt0[GDT_KCODE], NULL, -1, SDT_MEMERA, SEL_KPL, SDP_PAGES,
	    SDP_OP32);

	/*
	 * kernel data segment.
	 */
	set_usegd(&gdt0[GDT_KDATA], NULL, -1, SDT_MEMRWA, SEL_KPL, SDP_PAGES,
	    SDP_OP32);

	/*
	 * user code segment.
	 */
	set_usegd(&gdt0[GDT_UCODE], NULL, -1, SDT_MEMERA, SEL_UPL, SDP_PAGES,
	    SDP_OP32);

	/*
	 * user data segment.
	 */
	set_usegd(&gdt0[GDT_UDATA], NULL, -1, SDT_MEMRWA, SEL_UPL, SDP_PAGES,
	    SDP_OP32);

	/*
	 * LDT for current process
	 */
	set_syssegd((system_desc_t *)&gdt0[GDT_LDT], ldt0_default,
	    sizeof (ldt0_default) - 1, SDT_SYSLDT, SEL_KPL);

	ldt0_default_desc = *((system_desc_t *)&gdt0[GDT_LDT]);

	/*
	 * TSS for T_DBLFLT (double fault) handler
	 */
	set_syssegd((system_desc_t *)&gdt0[GDT_DBFLT], &dftss0,
	    sizeof (dftss0) - 1, SDT_SYSTSS, SEL_KPL);

	/*
	 * TSS for kernel
	 */
	set_syssegd((system_desc_t *)&gdt0[GDT_KTSS], &ktss0,
	    sizeof (ktss0) - 1, SDT_SYSTSS, SEL_KPL);

	/*
	 * %gs selector for kernel
	 */
	set_usegd(&gdt0[GDT_GS], &cpus[0], sizeof (struct cpu) -1, SDT_MEMRWA,
	    SEL_KPL, SDP_BYTES, SDP_OP32);

	/*
	 * Initialize lwp private descriptors.
	 * Only attributes and limits are initialized, the effective
	 * base address is programmed via fsbase/gsbase.
	 */
	set_usegd(&gdt0[GDT_LWPFS], NULL, (size_t)-1, SDT_MEMRWA, SEL_UPL,
	    SDP_PAGES, SDP_OP32);
	set_usegd(&gdt0[GDT_LWPGS], NULL, (size_t)-1, SDT_MEMRWA, SEL_UPL,
	    SDP_PAGES, SDP_OP32);

	/*
	 * Install our new GDT
	 */
	r_gdt.dtr_limit = sizeof (gdt0) - 1;
	r_gdt.dtr_base = (uintptr_t)gdt0;
	wr_gdtr(&r_gdt);

	/*
	 * Initialize convenient zero base user descriptors for clearing
	 * lwp private %fs and %gs descriptors in GDT. See setregs() for
	 * an example.
	 */
	set_usegd(&zero_udesc, 0, -1, SDT_MEMRWA, SEL_UPL, SDP_PAGES, SDP_OP32);
}

#endif	/* __i386 */

#if defined(__amd64)

/*
 * Build kernel IDT.
 *
 * Note that we pretty much require every gate to be an interrupt gate;
 * that's because of our dependency on using 'swapgs' every time we come
 * into the kernel to find the cpu structure - if we get interrupted just
 * before doing that, so that %cs is in kernel mode (so that the trap prolog
 * doesn't do a swapgs), but %gsbase is really still pointing at something
 * in userland, bad things ensue.
 *
 * Perhaps they should have invented a trap gate that does an atomic swapgs?
 *
 * XX64	We do need to think further about the follow-on impact of this.
 *	Most of the kernel handlers re-enable interrupts as soon as they've
 *	saved register state and done the swapgs, but there may be something
 *	more subtle going on.
 */
static void
init_idt(void)
{
	char	ivctname[80];
	void	(*ivctptr)(void);
	int	i;

	/*
	 * Initialize entire table with 'reserved' trap and then overwrite
	 * specific entries. T_EXTOVRFLT (9) is unsupported and reserved
	 * since it can only be generated on a 386 processor. 15 is also
	 * unsupported and reserved.
	 */
	for (i = 0; i < NIDT; i++)
		set_gatesegd(&idt0[i], &resvtrap, KCS_SEL, 0, SDT_SYSIGT,
		    SEL_KPL);

	set_gatesegd(&idt0[T_ZERODIV], &div0trap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_SGLSTP], &dbgtrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_NMIFLT], &nmiint, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_BPTFLT], &brktrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_UPL);
	set_gatesegd(&idt0[T_OVFLW], &ovflotrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_UPL);
	set_gatesegd(&idt0[T_BOUNDFLT], &boundstrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_ILLINST], &invoptrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_NOEXTFLT], &ndptrap,  KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);

	/*
	 * double fault handler.
	 */
	set_gatesegd(&idt0[T_DBLFLT], &syserrtrap, KCS_SEL, 1, SDT_SYSIGT,
	    SEL_KPL);

	/*
	 * T_EXTOVRFLT coprocessor-segment-overrun not supported.
	 */

	set_gatesegd(&idt0[T_TSSFLT], &invtsstrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_SEGFLT], &segnptrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_STKFLT], &stktrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_GPFLT], &gptrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_PGFLT], &pftrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);

	/*
	 * 15 reserved.
	 */
	set_gatesegd(&idt0[15], &resvtrap, KCS_SEL, 0, SDT_SYSIGT, SEL_KPL);

	set_gatesegd(&idt0[T_EXTERRFLT], &ndperr, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_ALIGNMENT], &achktrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_MCE], &mcetrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_SIMDFPE], &xmtrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);

	/*
	 * 20-31 reserved
	 */
	for (i = 20; i < 32; i++)
		set_gatesegd(&idt0[i], &invaltrap, KCS_SEL, 0, SDT_SYSIGT,
		    SEL_KPL);

	/*
	 * interrupts 32 - 255
	 */
	for (i = 32; i < 256; i++) {
		(void) snprintf(ivctname, sizeof (ivctname), "ivct%d", i);
		ivctptr = (void (*)(void))kobj_getsymvalue(ivctname, 0);
		if (ivctptr == NULL)
			panic("kobj_getsymvalue(%s) failed", ivctname);

		set_gatesegd(&idt0[i], ivctptr, KCS_SEL, 0, SDT_SYSIGT,
		    SEL_KPL);
	}

	/*
	 * install fast trap handler at 210.
	 */
	set_gatesegd(&idt0[T_FASTTRAP], &fasttrap, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);

	/*
	 * System call handler.
	 */
	set_gatesegd(&idt0[T_SYSCALLINT], &sys_syscall_int, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);

	/*
	 * Install the DTrace interrupt handlers for the fasttrap provider.
	 */
	set_gatesegd(&idt0[T_DTRACE_PROBE], &dtrace_fasttrap, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);
	set_gatesegd(&idt0[T_DTRACE_RET], &dtrace_ret, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);

	if (boothowto & RB_DEBUG)
		kdi_dvec_idt_sync(idt0);

	/*
	 * We must maintain a description of idt0 in convenient IDTR format
	 * for use by T_NMIFLT and T_PGFLT (nmiint() and pentium_pftrap())
	 * handlers.
	 */
	idt0_default_r.dtr_limit = sizeof (idt0) - 1;
	idt0_default_r.dtr_base = (uintptr_t)idt0;
	wr_idtr(&idt0_default_r);
}

#elif defined(__i386)

/*
 * Build kernel IDT.
 */
static void
init_idt(void)
{
	char	ivctname[80];
	void	(*ivctptr)(void);
	int	i;

	/*
	 * Initialize entire table with 'reserved' trap and then overwrite
	 * specific entries. T_EXTOVRFLT (9) is unsupported and reserved
	 * since it can only be generated on a 386 processor. 15 is also
	 * unsupported and reserved.
	 */
	for (i = 0; i < NIDT; i++)
		set_gatesegd(&idt0[i], &resvtrap, KCS_SEL, 0, SDT_SYSTGT,
		    SEL_KPL);

	set_gatesegd(&idt0[T_ZERODIV], &div0trap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_SGLSTP], &dbgtrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_NMIFLT], &nmiint, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_BPTFLT], &brktrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_UPL);
	set_gatesegd(&idt0[T_OVFLW], &ovflotrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_UPL);
	set_gatesegd(&idt0[T_BOUNDFLT], &boundstrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_ILLINST], &invoptrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_NOEXTFLT], &ndptrap,  KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);

	/*
	 * Install TSS for T_DBLFLT handler.
	 */
	set_gatesegd(&idt0[T_DBLFLT], NULL, DFTSS_SEL, 0, SDT_SYSTASKGT,
	    SEL_KPL);

	/*
	 * T_EXTOVRFLT coprocessor-segment-overrun not supported.
	 */

	set_gatesegd(&idt0[T_TSSFLT], &invtsstrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_SEGFLT], &segnptrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_STKFLT], &stktrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_GPFLT], &gptrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_PGFLT], &pftrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);

	/*
	 * 15 reserved.
	 */
	set_gatesegd(&idt0[15], &resvtrap, KCS_SEL, 0, SDT_SYSTGT, SEL_KPL);

	set_gatesegd(&idt0[T_EXTERRFLT], &ndperr, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_ALIGNMENT], &achktrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_MCE], &mcetrap, KCS_SEL, 0, SDT_SYSIGT,
	    SEL_KPL);
	set_gatesegd(&idt0[T_SIMDFPE], &xmtrap, KCS_SEL, 0, SDT_SYSTGT,
	    SEL_KPL);

	/*
	 * 20-31 reserved
	 */
	for (i = 20; i < 32; i++)
		set_gatesegd(&idt0[i], &invaltrap, KCS_SEL, 0, SDT_SYSTGT,
		    SEL_KPL);

	/*
	 * interrupts 32 - 255
	 */
	for (i = 32; i < 256; i++) {
		(void) snprintf(ivctname, sizeof (ivctname), "ivct%d", i);
		ivctptr = (void (*)(void))kobj_getsymvalue(ivctname, 0);
		if (ivctptr == NULL)
			panic("kobj_getsymvalue(%s) failed", ivctname);

		set_gatesegd(&idt0[i], ivctptr, KCS_SEL, 0, SDT_SYSIGT,
		    SEL_KPL);
	}

	/*
	 * install fast trap handler at 210.
	 */
	set_gatesegd(&idt0[T_FASTTRAP], &fasttrap, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);

	/*
	 * System call handler. Note that we don't use the hardware's parameter
	 * copying mechanism here; see the comment above sys_call() for details.
	 */
	set_gatesegd(&idt0[T_SYSCALLINT], &sys_call, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);

	/*
	 * Install the DTrace interrupt handlers for the fasttrap provider.
	 */
	set_gatesegd(&idt0[T_DTRACE_PROBE], &dtrace_fasttrap, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);
	set_gatesegd(&idt0[T_DTRACE_RET], &dtrace_ret, KCS_SEL, 0,
	    SDT_SYSIGT, SEL_UPL);

	if (boothowto & RB_DEBUG)
		kdi_dvec_idt_sync(idt0);

	/*
	 * We must maintain a description of idt0 in convenient IDTR format
	 * for use by T_NMIFLT and T_PGFLT (nmiint() and pentium_pftrap())
	 * handlers.
	 */
	idt0_default_r.dtr_limit = sizeof (idt0) - 1;
	idt0_default_r.dtr_base = (uintptr_t)idt0;
	wr_idtr(&idt0_default_r);
}

#endif	/* __i386 */

#if defined(__amd64)

static void
init_ldt(void)
{
	/*
	 * System calls using call gates from libc.a and libc.so.1
	 * must cause a #NP fault and be processed in trap().
	 * Therefore clear the "present" bit in the gate descriptor.
	 */

	/*
	 * call gate for libc.a (obsolete)
	 */
	set_gatesegd((gate_desc_t *)&ldt0_default[LDT_SYSCALL],
	    (void (*)(void))&sys_lcall32, KCS_SEL, 1, SDT_SYSCGT, SEL_UPL);
	((gate_desc_t *)&ldt0_default[LDT_SYSCALL])->sgd_p = 0;

	/*
	 * i386 call gate for system calls from libc.
	 */
	set_gatesegd((gate_desc_t *)&ldt0_default[LDT_ALTSYSCALL],
	    (void (*)(void))&sys_lcall32, KCS_SEL, 1, SDT_SYSCGT, SEL_UPL);
	((gate_desc_t *)&ldt0_default[LDT_ALTSYSCALL])->sgd_p = 0;

	wr_ldtr(ULDT_SEL);
}

#elif defined(__i386)

/*
 * Note that the call gates for system calls ask the hardware to copy exactly
 * one parameter onto the kernel stack for us; the parameter itself is not used.
 * The real reason this is done is to make room for a snapshot of EFLAGS. See
 * comment above sys_call() for details.
 */
static void
init_ldt(void)
{
	/*
	 * call gate for libc.a (obsolete)
	 */
	set_gatesegd((gate_desc_t *)&ldt0_default[LDT_SYSCALL],
	    (void (*)(void))&sys_call, KCS_SEL, 1, SDT_SYSCGT, SEL_UPL);

	/*
	 * i386 call gate for system calls from libc.
	 */
	set_gatesegd((gate_desc_t *)&ldt0_default[LDT_ALTSYSCALL],
	    (void (*)(void))&sys_call, KCS_SEL, 1, SDT_SYSCGT, SEL_UPL);

	wr_ldtr(ULDT_SEL);
}

#endif	/* __i386 */

#if defined(__amd64)

static void
init_tss(void)
{
	/*
	 * tss_rsp0 is dynamically filled in by resume() on each context switch.
	 * All exceptions but #DF will run on the thread stack.
	 * Set up the double fault stack here.
	 */
	ktss0.tss_ist1 =
	    (uint64_t)&dblfault_stack0[sizeof (dblfault_stack0)];

	/*
	 * Set I/O bit map offset equal to size of TSS segment limit
	 * for no I/O permission map. This will force all user I/O
	 * instructions to generate #gp fault.
	 */
	ktss0.tss_bitmapbase = sizeof (ktss0);

	/*
	 * Point %tr to descriptor for ktss0 in gdt.
	 */
	wr_tsr(KTSS_SEL);
}

#elif defined(__i386)

static void
init_tss(void)
{
	/*
	 * ktss0.tss_esp dynamically filled in by resume() on each
	 * context switch.
	 */
	ktss0.tss_ss0	= KDS_SEL;
	ktss0.tss_eip	= (uint32_t)_start;
	ktss0.tss_ds	= ktss0.tss_es = ktss0.tss_ss = KDS_SEL;
	ktss0.tss_cs	= KCS_SEL;
	ktss0.tss_fs	= KFS_SEL;
	ktss0.tss_gs	= KGS_SEL;
	ktss0.tss_ldt	= ULDT_SEL;

	/*
	 * Initialize double fault tss.
	 */
	dftss0.tss_esp0	= (uint32_t)&dblfault_stack0[sizeof (dblfault_stack0)];
	dftss0.tss_ss0	= KDS_SEL;

	/*
	 * tss_cr3 will get initialized in hat_kern_setup() once our page
	 * tables have been setup.
	 */
	dftss0.tss_eip	= (uint32_t)syserrtrap;
	dftss0.tss_esp	= (uint32_t)&dblfault_stack0[sizeof (dblfault_stack0)];
	dftss0.tss_cs	= KCS_SEL;
	dftss0.tss_ds	= KDS_SEL;
	dftss0.tss_es	= KDS_SEL;
	dftss0.tss_ss	= KDS_SEL;
	dftss0.tss_fs	= KFS_SEL;
	dftss0.tss_gs	= KGS_SEL;

	/*
	 * Set I/O bit map offset equal to size of TSS segment limit
	 * for no I/O permission map. This will force all user I/O
	 * instructions to generate #gp fault.
	 */
	ktss0.tss_bitmapbase = sizeof (ktss0);

	/*
	 * Point %tr to descriptor for ktss0 in gdt.
	 */
	wr_tsr(KTSS_SEL);
}

#endif	/* __i386 */

void
init_tables(void)
{
	init_gdt();
	init_tss();
	init_idt();
	init_ldt();
}
