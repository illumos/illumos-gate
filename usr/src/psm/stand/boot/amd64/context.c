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

#include <sys/types.h>
#include <sys/trap.h>
#include <sys/controlregs.h>
#include <sys/sysmacros.h>
#include <sys/link.h>

#include <amd64/types.h>
#include <amd64/amd64.h>
#include <amd64/cpu.h>
#include <amd64/machregs.h>
#include <amd64/tss.h>
#include <amd64/segments.h>
#include <amd64/debug.h>
#include <amd64/bootops64.h>
#include <amd64/bootsvcs64.h>
#include <amd64/amd64_page.h>

/*
 * This save area is initialized by amd64_exitto(), and used to
 * restore the state of the machine before invoking various
 * bootops.
 *
 * However, it needs to be mapped 1:1 so that we can reference it
 * while paging is disabled.  This is achieved via mapfile trickery;
 * we glom the entire program into one contiguous segment.
 */
struct i386_machregs exitto_i386_machregs;

/*CSTYLED*/
#pragma	align 16 (amd64_stack)
static uint8_t amd64_stack[1024*16];

/*CSTYLED*/
#pragma	align 16 (amd64_dblfault_stack)
static uint8_t amd64_dblfault_stack[1024*16];

/*CSTYLED*/
#pragma	align 16 (amd64_exception_stack)
static uint8_t amd64_exception_stack[1024*16];

static const selector_t	cs64sel = SEL_GDT(GDT_CODE64, SEL_KPL);
static const selector_t	ds64sel = SEL_GDT(GDT_DATA64, SEL_KPL);

static user_desc64_t	gdt64[NGDT];	/* long mode gdt */
static amd64tss_t	tss64;		/* long mode tss */

static void
make_gdt(desctbr64_t *rgdt)
{
	/*
	 * TSS
	 */
	bzero(&tss64, sizeof (tss64));

	/*
	 * All exceptions but #DF will run on the exception stack.
	 */
	tss64.tss_ist1 = (uint64_t)(uintptr_t)
		&amd64_exception_stack[sizeof (amd64_exception_stack)];

	/*
	 * #DF (double fault) gets its own private stack.
	 */
	tss64.tss_ist2 = (uint64_t)(uintptr_t)
		&amd64_dblfault_stack[sizeof (amd64_dblfault_stack)];

	/*
	 * GDT
	 */
	bzero(gdt64, sizeof (gdt64));

	/*
	 * 32-bit legacy or compatibility mode for data.
	 * Maps entire 4G address space.
	 */
	set_usegd64(&gdt64[GDT_DATA32], SHORT, NULL, 0xfffff, SDT_MEMRW,
	    SEL_KPL, PAGES, OP32);

	/*
	 * 32-bit legacy or compatibility mode for code.
	 * Maps entire 4G address space.
	 */
	set_usegd64(&gdt64[GDT_CODE32], SHORT, NULL, 0xfffff, SDT_MEMERC,
	    SEL_KPL, PAGES, OP32);

	/*
	 * 64-bit long mode for data.  XXX don't really need this.
	 * Maps entire 64-bit address space by definition.
	 */
	set_usegd64(&gdt64[GDT_DATA64], LONG, NULL, 0, SDT_MEMRW,
	    SEL_KPL, PAGES, OP32);

	/*
	 * 64-bit long mode for code.
	 * Maps entire 64-bit address space by definition.
	 */
	set_usegd64(&gdt64[GDT_CODE64], LONG, NULL, 0, SDT_MEMERC,
	    SEL_KPL, PAGES, OP32);

	/*
	 * 64-bit long mode TSS.
	 */
	set_syssegd64((system_desc64_t *)&gdt64[GDT_TSS64], &tss64,
	    sizeof (tss64), SDT_SYSTSS, SEL_KPL);

	rgdt->dtr_limit = sizeof (gdt64) - 1;
	rgdt->dtr_base = (uint64_t)(uintptr_t)gdt64;
}

static gate_desc64_t	idt64[NIDT];	/* long mode idt */

static void
make_idt(desctbr64_t *ridt)
{
	int i;

	/*
	 * IDT
	 *
	 * First initialize all entries to reserve trap then overwrite
	 * the important ones with specific handlers.
	 *
	 * XXX how big does this idt really need to be ? I suspect
	 * only large enough to hold kmdb's soft int?
	 *
	 * XX64 fbsd only uses interrupt gates for all. Perhaps
	 * This is good for amd64 since we want to block maskable
	 * interrupts once we take an exception?
	 */
	bzero(idt64, sizeof (idt64));	/* FIXME */

	for (i = 0; i < NIDT; i++)
		set_gatesegd64(&idt64[i], &amd64_resvtrap, cs64sel, 1,
		    SDT_SYSIGT, SEL_KPL);

	set_gatesegd64(&idt64[T_ZERODIV], &amd64_div0trap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_SGLSTP], &amd64_dbgtrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_NMIFLT], &amd64_nmiint, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_BPTFLT], &amd64_brktrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_UPL);
	set_gatesegd64(&idt64[T_OVFLW], &amd64_ovflotrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_UPL);
	set_gatesegd64(&idt64[T_BOUNDFLT], &amd64_boundstrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_ILLINST], &amd64_invoptrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_NOEXTFLT], &amd64_ndptrap,  cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);

	/*
	 * double fault handler gets its own private stack (tss.ist2).
	 */
	set_gatesegd64(&idt64[T_DBLFLT], &amd64_doublefault, cs64sel, 2,
	    SDT_SYSIGT, SEL_KPL);

	/*
	 * T_EXTOVRFLT coprocessor-segment-overrun not supported.
	 */

	set_gatesegd64(&idt64[T_TSSFLT], &amd64_invtsstrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_SEGFLT], &amd64_segnptrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_STKFLT], &amd64_stktrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_GPFLT], &amd64_gptrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_PGFLT], &amd64_pftrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);

	/*
	 * 15 reserved.
	 */
	set_gatesegd64(&idt64[15], &amd64_resvtrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);

	set_gatesegd64(&idt64[T_EXTERRFLT], &amd64_ndperr, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_ALIGNMENT], &amd64_achktrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_MCE], &amd64_mcetrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);
	set_gatesegd64(&idt64[T_SIMDFPE], &amd64_xmtrap, cs64sel, 1,
	    SDT_SYSIGT, SEL_KPL);

	/*
	 * 20-31 reserved
	 */
	for (i = 20; i < 32; i++)
	    set_gatesegd64(&idt64[i], &amd64_invaltrap, cs64sel, 1,
		SDT_SYSIGT, SEL_KPL);

	/*
	 * XX64 -- why not resvtrap in initial programming??
	 * either way, move this to the top so that the defaults
	 * are set together.
	 */
	ridt->dtr_limit = sizeof (idt64) - 1;
	ridt->dtr_base = (uint64_t)(uintptr_t)idt64;
}

/*
 * Note that when rsp is being pushed, like the processor, we must
 * ensure that the value of the stack pointer at the beginning of the
 * instruction is the one that is pushed, NOT the value after.
 */
#define	PUSHQ(rsp, value)			\
	rsp[-1] = ((uint64_t)(value)); rsp--

#define	SUBQ(rsp, value)			\
	rsp -= ((value) / sizeof (*rsp))

struct amd64_machregs *
amd64_makectx64(uint64_t entry)
{
	extern struct bootops *bop;
	extern struct boot_syscalls *sysp;
	extern Elf64_Boot *elfbootvecELF64;

	struct boot_syscalls64	*sysp64;
	struct bootops64	*bop64;
	uint64_t		*rsp;

	bzero(amd64_stack, sizeof (amd64_stack));

	rsp = (void *)&amd64_stack[sizeof (amd64_stack)];

	PUSHQ(rsp, entry);

	/*
	 * terminate stack walks with a null RBP value.
	 */
	PUSHQ(rsp, 0);

	/*
	 * push in amd64_machregs order.
	 */
	PUSHQ(rsp, ds64sel);	/* ss */
	PUSHQ(rsp, (uintptr_t)rsp);	/* rsp */
	PUSHQ(rsp, amd64_get_eflags());	/* rfl */
	PUSHQ(rsp, cs64sel);	/* cs */
	PUSHQ(rsp, 0);		/* %rip - because we didn't go thru a stub */
	PUSHQ(rsp, 0);		/* err */
	PUSHQ(rsp, 0);		/* trapno */
	PUSHQ(rsp, ds64sel);	/* es */
	PUSHQ(rsp, ds64sel);	/* ds */
	PUSHQ(rsp, 0);		/* fs */
	PUSHQ(rsp, 0);		/* gs */

	SUBQ(rsp, 11 * 8);	/* r8 thru r15 are zero */

	bop64 = init_bootops64(bop);
	sysp64 = init_boot_syscalls64(sysp);

	PUSHQ(rsp, (uintptr_t)elfbootvecELF64);	/* rcx */
	PUSHQ(rsp, (uintptr_t)bop64);		/* rdx */
	PUSHQ(rsp, 0);				/* rsi - null dvec */
	PUSHQ(rsp, (uintptr_t)sysp64);		/* rdi */

	PUSHQ(rsp, SEL_GDT(GDT_TSS64, SEL_KPL));	/* tr */

	SUBQ(rsp, 1 * 8);				/* null ldt */

	PUSHQ(rsp, 0);					/* idt */
	PUSHQ(rsp, 0);
	make_idt((desctbr64_t *)rsp);

	PUSHQ(rsp, 0);					/* gdt */
	PUSHQ(rsp, 0);
	make_gdt((desctbr64_t *)rsp);

	PUSHQ(rsp, 0);					/* cr8 */

	/*
	 * XX64:  Note that boot enables CR4_PGE (global pages)
	 *	  and Joe has discovered errata that warns against
	 *	  mixing this.  Need to investigate.
	 */
	PUSHQ(rsp, CR4_PGE | CR4_PAE | amd64_get_cr4());	/* cr4 */
	PUSHQ(rsp, amd64_init_longpt(amd64_get_cr3()));		/* cr3 */
	PUSHQ(rsp, amd64_get_cr2());				/* cr2 */

	/*
	 * XX64 - CR0_PG already set?
	 */
	PUSHQ(rsp, CR0_PG | amd64_get_cr0());		/* cr0 */

	SUBQ(rsp, 3 * 8);		/* kgsbase, gsbase, fsbase */

	return ((struct amd64_machregs *)rsp);
}
