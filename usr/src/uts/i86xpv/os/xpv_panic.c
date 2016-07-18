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
 * Copyright (c) 2012 Gary Mills
 * Copyright 2016 PALO, Richard.
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/clock.h>
#include <sys/psm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/compress.h>
#include <sys/modctl.h>
#include <sys/trap.h>
#include <sys/panic.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/kobj.h>
#include <sys/apic.h>
#include <sys/apic_timer.h>
#include <sys/dumphdr.h>
#include <sys/mem.h>
#include <sys/x86_archext.h>
#include <sys/xpv_panic.h>
#include <sys/boot_console.h>
#include <sys/bootsvcs.h>
#include <sys/consdev.h>
#include <vm/hat_pte.h>
#include <vm/hat_i86.h>

/* XXX: need to add a PAE version too, if we ever support both PAE and non */
#if defined(__i386)
#define	XPV_FILENAME	"/boot/xen-syms"
#else
#define	XPV_FILENAME	"/boot/amd64/xen-syms"
#endif
#define	XPV_MODNAME	"xpv"

int xpv_panicking = 0;

struct module *xpv_module;
struct modctl *xpv_modctl;

#define	ALIGN(x, a)	((a) == 0 ? (uintptr_t)(x) : \
	(((uintptr_t)(x) + (uintptr_t)(a) - 1l) & ~((uintptr_t)(a) - 1l)))

/* Pointer to the xpv_panic_info structure handed to us by Xen.  */
static struct panic_info *xpv_panic_info = NULL;

/* Timer support */
#define	NSEC_SHIFT 5
#define	T_XPV_TIMER	0xd1
#define	XPV_TIMER_INTERVAL	1000	/* 1000 microseconds */
static uint32_t *xpv_apicadr = NULL;
static uint_t	nsec_scale;

/* IDT support */
#pragma	align	16(xpv_panic_idt)
static gate_desc_t	xpv_panic_idt[NIDT];	/* interrupt descriptor table */

/* Xen pagetables mapped into our HAT's ptable windows */
static pfn_t ptable_pfn[MAX_NUM_LEVEL];

/* Number of MMU_PAGESIZE pages we're adding to the Solaris dump */
static int xpv_dump_pages;

/*
 * There are up to two large swathes of RAM that we don't want to include
 * in the dump: those that comprise the Xen version of segkpm.  On 32-bit
 * systems there is no such region of memory.  On 64-bit systems, there
 * should be just a single contiguous region that corresponds to all of
 * physical memory.  The tricky bit is that Xen's heap sometimes lives in
 * the middle of their segkpm, and is mapped using only kpm-like addresses.
 * In that case, we need to skip the swathes before and after Xen's heap.
 */
uintptr_t kpm1_low = 0;
uintptr_t kpm1_high = 0;
uintptr_t kpm2_low = 0;
uintptr_t kpm2_high = 0;

/*
 * Some commonly used values that we don't want to recompute over and over.
 */
static int xpv_panic_nptes[MAX_NUM_LEVEL];
static ulong_t xpv_panic_cr3;
static uintptr_t xpv_end;

static void xpv_panic_console_print(const char *fmt, ...);
static void (*xpv_panic_printf)(const char *, ...) = xpv_panic_console_print;

#define	CONSOLE_BUF_SIZE	256
static char console_buffer[CONSOLE_BUF_SIZE];
static boolean_t use_polledio;

/*
 * Pointers to machine check panic info (if any).
 */
xpv_mca_panic_data_t *xpv_mca_panic_data = NULL;

static void
xpv_panic_putc(int m)
{
	struct cons_polledio *c = cons_polledio;

	/* This really shouldn't happen */
	if (boot_console_type(NULL) == CONS_HYPERVISOR)
		return;

	if (use_polledio == B_TRUE)
		c->cons_polledio_putchar(c->cons_polledio_argument, m);
	else
		bcons_putchar(m);
}

static void
xpv_panic_puts(char *msg)
{
	char *m;

	dump_timeleft = dump_timeout;
	for (m = msg; *m; m++)
		xpv_panic_putc((int)*m);
}

static void
xpv_panic_console_print(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(console_buffer, sizeof (console_buffer), fmt, ap);
	va_end(ap);

	xpv_panic_puts(console_buffer);
}

static void
xpv_panic_map(int level, pfn_t pfn)
{
	x86pte_t pte, *pteptr;

	/*
	 * The provided pfn represents a level 'level' page table.  Map it
	 * into the 'level' slot in the list of page table windows.
	 */
	pteptr = (x86pte_t *)PWIN_PTE_VA(level);
	pte = pfn_to_pa(pfn) | PT_VALID;

	XPV_ALLOW_PAGETABLE_UPDATES();
	if (mmu.pae_hat)
		*pteptr = pte;
	else
		*(x86pte32_t *)pteptr = pte;
	XPV_DISALLOW_PAGETABLE_UPDATES();

	mmu_tlbflush_entry(PWIN_VA(level));
}

/*
 * Walk the page tables to find the pfn mapped by the given va.
 */
static pfn_t
xpv_va_walk(uintptr_t *vaddr)
{
	int l, idx;
	pfn_t pfn;
	x86pte_t pte;
	x86pte_t *ptep;
	uintptr_t va = *vaddr;
	uintptr_t scan_va;
	caddr_t ptable_window;
	static pfn_t toplevel_pfn;
	static uintptr_t lastva;

	/*
	 * If we do anything other than a simple scan through memory, don't
	 * trust the mapped page tables.
	 */
	if (va != lastva + MMU_PAGESIZE)
		for (l = mmu.max_level; l >= 0; l--)
			ptable_pfn[l] = PFN_INVALID;

	toplevel_pfn = mmu_btop(xpv_panic_cr3);

	while (va < xpv_end && va >= *vaddr) {
		/* Find the lowest table with any entry for va */
		pfn = toplevel_pfn;
		for (l = mmu.max_level; l >= 0; l--) {
			if (ptable_pfn[l] != pfn) {
				xpv_panic_map(l, pfn);
				ptable_pfn[l] = pfn;
			}

			/*
			 * Search this pagetable for any mapping to an
			 * address >= va.
			 */
			ptable_window = PWIN_VA(l);
			if (l == mmu.max_level && mmu.pae_hat)
				ptable_window +=
				    (xpv_panic_cr3 & MMU_PAGEOFFSET);

			idx = (va >> LEVEL_SHIFT(l)) & (xpv_panic_nptes[l] - 1);
			scan_va = va;
			while (idx < xpv_panic_nptes[l] && scan_va < xpv_end &&
			    scan_va >= *vaddr) {
				ptep = (x86pte_t *)(ptable_window +
				    (idx << mmu.pte_size_shift));
				pte = GET_PTE(ptep);
				if (pte & PTE_VALID)
					break;
				idx++;
				scan_va += mmu.level_size[l];
			}

			/*
			 * If there are no valid mappings in this table, we
			 * can skip to the end of the VA range it covers.
			 */
			if (idx == xpv_panic_nptes[l]) {
				va = NEXT_ENTRY_VA(va, l + 1);
				break;
			}

			va = scan_va;
			/*
			 * See if we've hit the end of the range.
			 */
			if (va >= xpv_end || va < *vaddr)
				break;

			/*
			 * If this mapping is for a pagetable, we drop down
			 * to the next level in the hierarchy and look for
			 * a mapping in it.
			 */
			pfn = PTE2MFN(pte, l);
			if (!PTE_ISPAGE(pte, l))
				continue;

			/*
			 * The APIC page is magic.  Nothing to see here;
			 * move along.
			 */
			if (((uintptr_t)xpv_apicadr & MMU_PAGEMASK) ==
			    (va & MMU_PAGEMASK)) {
				va += MMU_PAGESIZE;
				break;
			}

			/*
			 * See if the address is within one of the two
			 * kpm-like regions we want to skip.
			 */
			if (va >= kpm1_low && va < kpm1_high) {
				va = kpm1_high;
				break;
			}
			if (va >= kpm2_low && va < kpm2_high) {
				va = kpm2_high;
				break;
			}

			/*
			 * The Xen panic code only handles small pages.  If
			 * this mapping is for a large page, we need to
			 * identify the consituent page that covers the
			 * specific VA we were looking for.
			 */
			if (l > 0) {
				if (l > 1)
					panic("Xen panic can't cope with "
					    "giant pages.");
				idx = (va >> LEVEL_SHIFT(0)) &
				    (xpv_panic_nptes[0] - 1);
				pfn += idx;
			}

			*vaddr = va;
			lastva = va;
			return (pfn | PFN_IS_FOREIGN_MFN);
		}
	}
	return (PFN_INVALID);
}

/*
 * Walk through the Xen VA space, finding pages that are mapped in.
 *
 * These pages all have MFNs rather than PFNs, meaning they may be outside
 * the physical address space the kernel knows about, or they may collide
 * with PFNs the kernel is using.
 *
 * The obvious trick of just adding the PFN_IS_FOREIGN_MFN bit to the MFNs
 * to avoid collisions doesn't work.  The pages need to be written to disk
 * in PFN-order or savecore gets confused.  We can't allocate memory to
 * contruct a sorted pfn->VA reverse mapping, so we have to write the pages
 * to disk in VA order.
 *
 * To square this circle, we simply make up PFNs for each of Xen's pages.
 * We assign each mapped page a fake PFN in ascending order.  These fake
 * PFNs each have the FOREIGN bit set, ensuring that they fall outside the
 * range of Solaris PFNs written by the kernel.
 */
int
dump_xpv_addr()
{
	uintptr_t va;
	mem_vtop_t mem_vtop;

	xpv_dump_pages = 0;
	va = xen_virt_start;

	while (xpv_va_walk(&va) != PFN_INVALID) {
		mem_vtop.m_as = &kas;
		mem_vtop.m_va = (void *)va;
		mem_vtop.m_pfn = (pfn_t)xpv_dump_pages | PFN_IS_FOREIGN_MFN;

		dumpvp_write(&mem_vtop, sizeof (mem_vtop_t));
		xpv_dump_pages++;

		va += MMU_PAGESIZE;
	}

	/*
	 * Add the shared_info page.  This page actually ends up in the
	 * dump twice: once for the Xen va and once for the Solaris va.
	 * This isn't ideal, but we don't know the address Xen is using for
	 * the page, so we can't share it.
	 */
	mem_vtop.m_as = &kas;
	mem_vtop.m_va = HYPERVISOR_shared_info;
	mem_vtop.m_pfn = (pfn_t)xpv_dump_pages | PFN_IS_FOREIGN_MFN;
	dumpvp_write(&mem_vtop, sizeof (mem_vtop_t));
	xpv_dump_pages++;

	return (xpv_dump_pages);
}

void
dump_xpv_pfn()
{
	pfn_t pfn;
	int cnt;

	for (cnt = 0; cnt < xpv_dump_pages; cnt++) {
		pfn = (pfn_t)cnt | PFN_IS_FOREIGN_MFN;
		dumpvp_write(&pfn, sizeof (pfn));
	}
}

int
dump_xpv_data(void *dump_cbuf)
{
	uintptr_t va;
	uint32_t csize;
	int cnt = 0;

	/*
	 * XXX: we should probably run this data through a UE check.  The
	 * catch is that the UE code relies on on_trap() and getpfnum()
	 * working.
	 */
	va = xen_virt_start;

	while (xpv_va_walk(&va) != PFN_INVALID) {
		csize = (uint32_t)compress((void *)va, dump_cbuf, PAGESIZE);
		dumpvp_write(&csize, sizeof (uint32_t));
		dumpvp_write(dump_cbuf, csize);
		if (dump_ioerr) {
			dumphdr->dump_flags &= ~DF_COMPLETE;
			return (cnt);
		}
		cnt++;
		va += MMU_PAGESIZE;
	}

	/*
	 * Finally, dump the shared_info page
	 */
	csize = (uint32_t)compress((void *)HYPERVISOR_shared_info, dump_cbuf,
	    PAGESIZE);
	dumpvp_write(&csize, sizeof (uint32_t));
	dumpvp_write(dump_cbuf, csize);
	if (dump_ioerr)
		dumphdr->dump_flags &= ~DF_COMPLETE;
	cnt++;

	return (cnt);
}

static void *
showstack(void *fpreg, int xpv_only)
{
	struct frame *fpp;
	ulong_t off;
	char *sym;
	uintptr_t pc, fp, lastfp;
	uintptr_t minaddr = min(KERNELBASE, xen_virt_start);

	fp = (uintptr_t)fpreg;
	if (fp < minaddr) {
		xpv_panic_printf("Bad frame ptr: 0x%p\n", fpreg);
		return (fpreg);
	}

	do {
		fpp = (struct frame *)fp;
		pc = fpp->fr_savpc;

		if ((xpv_only != 0) &&
		    (fp > xpv_end || fp < xen_virt_start))
			break;
		if ((sym = kobj_getsymname(pc, &off)) != NULL)
			xpv_panic_printf("%08lx %s:%s+%lx\n", fp,
			    mod_containing_pc((caddr_t)pc), sym, off);
		else if ((pc >= xen_virt_start) && (pc <= xpv_end))
			xpv_panic_printf("%08lx 0x%lx (in Xen)\n", fp, pc);
		else
			xpv_panic_printf("%08lx %lx\n", fp, pc);

		lastfp = fp;
		fp = fpp->fr_savfp;

		/*
		 * Xen marks an exception frame by inverting the frame
		 * pointer.
		 */
		if (fp < lastfp) {
			if ((~fp > minaddr) && ((~fp) ^ lastfp) < 0xfff)
				fp = ~fp;
		}
	} while (fp > lastfp);
	return ((void *)fp);
}

void *
xpv_traceback(void *fpreg)
{
	return (showstack(fpreg, 1));
}

#if defined(__amd64)
static void
xpv_panic_hypercall(ulong_t call)
{
	panic("Illegally issued hypercall %d during panic!\n", (int)call);
}
#endif

void
xpv_die(struct regs *rp)
{
	struct panic_trap_info ti;
	struct cregs creg;

	ti.trap_regs = rp;
	ti.trap_type = rp->r_trapno;

	curthread->t_panic_trap = &ti;
	if (ti.trap_type == T_PGFLT) {
		getcregs(&creg);
		ti.trap_addr = (caddr_t)creg.cr_cr2;
		panic("Fatal pagefault at 0x%lx.  fault addr=0x%p  rp=0x%p",
		    rp->r_pc, (void *)ti.trap_addr, (void *)rp);
	} else {
		ti.trap_addr = (caddr_t)rp->r_pc;
		panic("Fatal trap %ld at 0x%lx.  rp=0x%p", rp->r_trapno,
		    rp->r_pc, (void *)rp);
	}
}

/*
 * Build IDT to handle a Xen panic
 */
static void
switch_to_xpv_panic_idt()
{
	int i;
	desctbr_t idtr;
	gate_desc_t *idt = xpv_panic_idt;
	selector_t cs = get_cs_register();

	for (i = 0; i < 32; i++)
		set_gatesegd(&idt[i], &xpv_invaltrap, cs, SDT_SYSIGT, TRP_XPL,
		    0);

	set_gatesegd(&idt[T_ZERODIV], &xpv_div0trap, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_SGLSTP], &xpv_dbgtrap, cs, SDT_SYSIGT, TRP_XPL, 0);
	set_gatesegd(&idt[T_NMIFLT], &xpv_nmiint, cs, SDT_SYSIGT, TRP_XPL, 0);
	set_gatesegd(&idt[T_BOUNDFLT], &xpv_boundstrap, cs, SDT_SYSIGT,
	    TRP_XPL, 0);
	set_gatesegd(&idt[T_ILLINST], &xpv_invoptrap, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_NOEXTFLT], &xpv_ndptrap, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_TSSFLT], &xpv_invtsstrap, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_SEGFLT], &xpv_segnptrap, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_STKFLT], &xpv_stktrap, cs, SDT_SYSIGT, TRP_XPL, 0);
	set_gatesegd(&idt[T_GPFLT], &xpv_gptrap, cs, SDT_SYSIGT, TRP_XPL, 0);
	set_gatesegd(&idt[T_PGFLT], &xpv_pftrap, cs, SDT_SYSIGT, TRP_XPL, 0);
	set_gatesegd(&idt[T_EXTERRFLT], &xpv_ndperr, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_ALIGNMENT], &xpv_achktrap, cs, SDT_SYSIGT, TRP_XPL,
	    0);
	set_gatesegd(&idt[T_MCE], &xpv_mcetrap, cs, SDT_SYSIGT, TRP_XPL, 0);
	set_gatesegd(&idt[T_SIMDFPE], &xpv_xmtrap, cs, SDT_SYSIGT, TRP_XPL, 0);

	/*
	 * We have no double fault handler.  Any single fault represents a
	 * catastrophic failure for us, so there is no attempt to handle
	 * them cleanly: we just print a message and reboot.  If we
	 * encounter a second fault while doing that, there is nothing
	 * else we can do.
	 */

	/*
	 * Be prepared to absorb any stray device interrupts received
	 * while writing the core to disk.
	 */
	for (i = 33; i < NIDT; i++)
		set_gatesegd(&idt[i], &xpv_surprise_intr, cs, SDT_SYSIGT,
		    TRP_XPL, 0);

	/* The one interrupt we expect to get is from the APIC timer.  */
	set_gatesegd(&idt[T_XPV_TIMER], &xpv_timer_trap, cs, SDT_SYSIGT,
	    TRP_XPL, 0);

	idtr.dtr_base = (uintptr_t)xpv_panic_idt;
	idtr.dtr_limit = sizeof (xpv_panic_idt) - 1;
	wr_idtr(&idtr);

#if defined(__amd64)
	/* Catch any hypercalls. */
	wrmsr(MSR_AMD_LSTAR, (uintptr_t)xpv_panic_hypercall);
	wrmsr(MSR_AMD_CSTAR, (uintptr_t)xpv_panic_hypercall);
#endif
}

static void
xpv_apic_clkinit()
{
	uint_t		apic_ticks = 0;

	/*
	 * Measure how many APIC ticks there are within a fixed time
	 * period.  We're going to be fairly coarse here.  This timer is
	 * just being used to detect a stalled panic, so as long as we have
	 * the right order of magnitude, everything should be fine.
	 */
	xpv_apicadr[APIC_SPUR_INT_REG] = AV_UNIT_ENABLE | APIC_SPUR_INTR;
	xpv_apicadr[APIC_LOCAL_TIMER] = AV_MASK;
	xpv_apicadr[APIC_INT_VECT0] = AV_MASK;	/* local intr reg 0 */

	xpv_apicadr[APIC_DIVIDE_REG] = 0;
	xpv_apicadr[APIC_INIT_COUNT] = APIC_MAXVAL;
	drv_usecwait(XPV_TIMER_INTERVAL);
	apic_ticks = APIC_MAXVAL - xpv_apicadr[APIC_CURR_COUNT];

	/*
	 * apic_ticks now represents roughly how many apic ticks comprise
	 * one timeout interval.  Program the timer to send us an interrupt
	 * every time that interval expires.
	 */
	xpv_apicadr[APIC_LOCAL_TIMER] = T_XPV_TIMER | AV_PERIODIC;
	xpv_apicadr[APIC_INIT_COUNT] = apic_ticks;
	xpv_apicadr[APIC_EOI_REG] = 0;
}

void
xpv_timer_tick(void)
{
	static int ticks = 0;

	if (ticks++ >= MICROSEC / XPV_TIMER_INTERVAL) {
		ticks = 0;
		if (dump_timeleft && (--dump_timeleft == 0))
			panic("Xen panic timeout\n");
	}
	xpv_apicadr[APIC_EOI_REG] = 0;
}

void
xpv_interrupt(void)
{
#ifdef	DEBUG
	static int cnt = 0;

	if (cnt++ < 10)
		xpv_panic_printf("Unexpected interrupt received.\n");
	if ((cnt < 1000) && ((cnt % 100) == 0))
		xpv_panic_printf("%d unexpected interrupts received.\n", cnt);
#endif

	xpv_apicadr[APIC_EOI_REG] = 0;
}

/*
 * Managing time in panic context is trivial.  We only have a single CPU,
 * we never get rescheduled, we never get suspended.  We just need to
 * convert clock ticks into nanoseconds.
 */
static hrtime_t
xpv_panic_gethrtime(void)
{
	hrtime_t tsc, hrt;
	unsigned int *l = (unsigned int *)&(tsc);

	tsc = __rdtsc_insn();
	hrt = (mul32(l[1], nsec_scale) << NSEC_SHIFT) +
	    (mul32(l[0], nsec_scale) >> (32 - NSEC_SHIFT));

	return (hrt);
}

static void
xpv_panic_time_init()
{
	nsec_scale =
	    CPU->cpu_m.mcpu_vcpu_info->time.tsc_to_system_mul >> NSEC_SHIFT;

	gethrtimef = xpv_panic_gethrtime;
}

static void
xpv_panicsys(struct regs *rp, char *fmt, ...)
{
	extern void panicsys(const char *, va_list, struct regs *, int);
	va_list alist;

	va_start(alist, fmt);
	panicsys(fmt, alist, rp, 1);
	va_end(alist);
}

void
xpv_do_panic(void *arg)
{
	struct panic_info *pip = (struct panic_info *)arg;
	int l;
	struct cregs creg;
#if defined(__amd64)
	extern uintptr_t postbootkernelbase;
#endif

	if (xpv_panicking++ > 0)
		panic("multiple calls to xpv_do_panic()");

	/*
	 * Indicate to the underlying panic framework that a panic has been
	 * initiated.  This is ordinarily done as part of vpanic().  Since
	 * we already have all the register state saved by the hypervisor,
	 * we skip that and jump straight into the panic processing code.
	 *
	 * XXX If another thread grabs and wins the panic_quiesce trigger
	 * then we'll have two threads in panicsys believing they are in
	 * charge of the panic attempt!
	 */
	(void) panic_trigger(&panic_quiesce);

#if defined(__amd64)
	/*
	 * bzero() and bcopy() get unhappy when asked to operate on
	 * addresses outside of the kernel.  At this point Xen is really a
	 * part of the kernel, so we update the routines' notion of where
	 * the kernel starts.
	 */
	postbootkernelbase = xen_virt_start;
#endif

#if defined(HYPERVISOR_VIRT_END)
	xpv_end = HYPERVISOR_VIRT_END;
#else
	xpv_end = (uintptr_t)UINTPTR_MAX - sizeof (uintptr_t);
#endif

	/*
	 * If we were redirecting console output to the hypervisor, we have
	 * to stop.
	 */
	use_polledio = B_FALSE;
	if (boot_console_type(NULL) == CONS_HYPERVISOR) {
		bcons_device_change(CONS_HYPERVISOR);
	} else if (cons_polledio != NULL &&
	    cons_polledio->cons_polledio_putchar != NULL)  {
		if (cons_polledio->cons_polledio_enter != NULL)
			cons_polledio->cons_polledio_enter(
			    cons_polledio->cons_polledio_argument);
		use_polledio = 1;
	}

	/* Make sure we handle all console output from here on. */
	sysp->bsvc_putchar = xpv_panic_putc;

	/*
	 * If we find an unsupported panic_info structure, there's not much
	 * we can do other than complain, plow on, and hope for the best.
	 */
	if (pip->pi_version != PANIC_INFO_VERSION)
		xpv_panic_printf("Warning: Xen is using an unsupported "
		    "version of the panic_info structure.\n");

	xpv_panic_info = pip;

#if defined(__amd64)
	kpm1_low = (uintptr_t)xpv_panic_info->pi_ram_start;
	if (xpv_panic_info->pi_xen_start == NULL) {
		kpm1_high = (uintptr_t)xpv_panic_info->pi_ram_end;
	} else {
		kpm1_high = (uintptr_t)xpv_panic_info->pi_xen_start;
		kpm2_low = (uintptr_t)xpv_panic_info->pi_xen_end;
		kpm2_high = (uintptr_t)xpv_panic_info->pi_ram_end;
	}
#endif

	/*
	 * Make sure we are running on the Solaris %gs.  The Xen panic code
	 * should already have set up the GDT properly.
	 */
	xpv_panic_resetgs();
#if defined(__amd64)
	wrmsr(MSR_AMD_GSBASE, (uint64_t)&cpus[0]);
#endif

	xpv_panic_time_init();

	/*
	 * Switch to our own IDT, avoiding any accidental returns to Xen
	 * world.
	 */
	switch_to_xpv_panic_idt();

	/*
	 * Initialize the APIC timer, which is used to detect a hung dump
	 * attempt.
	 */
	xpv_apicadr = pip->pi_apic;
	xpv_apic_clkinit();

	/*
	 * Set up a few values that we'll need repeatedly.
	 */
	getcregs(&creg);
	xpv_panic_cr3 = creg.cr_cr3;
	for (l = mmu.max_level; l >= 0; l--)
		xpv_panic_nptes[l] = mmu.ptes_per_table;
#ifdef __i386
	if (mmu.pae_hat)
		xpv_panic_nptes[mmu.max_level] = 4;
#endif

	/* Add the fake Xen module to the module list */
	if (xpv_module != NULL) {
		extern int last_module_id;

		xpv_modctl->mod_id = last_module_id++;
		xpv_modctl->mod_next = &modules;
		xpv_modctl->mod_prev = modules.mod_prev;
		modules.mod_prev->mod_next = xpv_modctl;
		modules.mod_prev = xpv_modctl;
	}

	if (pip->pi_mca.mpd_magic == MCA_PANICDATA_MAGIC)
		xpv_mca_panic_data = &pip->pi_mca;

	xpv_panic_printf = printf;
	xpv_panicsys((struct regs *)pip->pi_regs, pip->pi_panicstr);
	xpv_panic_printf("Failed to reboot following panic.\n");
	for (;;)
		;
}

/*
 * Set up the necessary data structures to pretend that the Xen hypervisor
 * is a loadable module, allowing mdb to find the Xen symbols in a crash
 * dump.  Since these symbols all map to VA space Solaris doesn't normally
 * have access to, we don't link these structures into the kernel's lists
 * until/unless we hit a Xen panic.
 *
 * The observant reader will note a striking amount of overlap between this
 * code and that found in krtld.  While it would be handy if we could just
 * ask krtld to do this work for us, it's not that simple.  Among the
 * complications: we're not actually loading the text here (grub did it at
 * boot), the .text section is writable, there are no relocations to do,
 * none of the module text/data is in readable memory, etc.  Training krtld
 * to deal with this weird module is as complicated, and more risky, than
 * reimplementing the necessary subset of it here.
 */
static void
init_xen_module()
{
	struct _buf *file = NULL;
	struct module *mp;
	struct modctl *mcp;
	int i, shn;
	Shdr *shp, *ctf_shp;
	char *names = NULL;
	size_t n, namesize, text_align, data_align;
#if defined(__amd64)
	const char machine = EM_AMD64;
#else
	const char machine = EM_386;
#endif

	/* Allocate and init the module structure */
	mp = kmem_zalloc(sizeof (*mp), KM_SLEEP);
	mp->filename = kobj_zalloc(strlen(XPV_FILENAME) + 1, KM_SLEEP);
	(void) strcpy(mp->filename, XPV_FILENAME);

	/* Allocate and init the modctl structure */
	mcp = kmem_zalloc(sizeof (*mcp), KM_SLEEP);
	mcp->mod_modname = kobj_zalloc(strlen(XPV_MODNAME) + 1, KM_SLEEP);
	(void) strcpy(mcp->mod_modname, XPV_MODNAME);
	mcp->mod_filename = kobj_zalloc(strlen(XPV_FILENAME) + 1, KM_SLEEP);
	(void) strcpy(mcp->mod_filename, XPV_FILENAME);
	mcp->mod_inprogress_thread = (kthread_id_t)-1;
	mcp->mod_ref = 1;
	mcp->mod_loaded = 1;
	mcp->mod_loadcnt = 1;
	mcp->mod_mp = mp;

	/*
	 * Try to open a Xen image that hasn't had its symbol and CTF
	 * information stripped off.
	 */
	file = kobj_open_file(XPV_FILENAME);
	if (file == (struct _buf *)-1) {
		file = NULL;
		goto err;
	}

	/*
	 * Read the header and ensure that this is an ELF file for the
	 * proper ISA.  If it's not, somebody has done something very
	 * stupid.  Why bother?  See Mencken.
	 */
	if (kobj_read_file(file, (char *)&mp->hdr, sizeof (mp->hdr), 0) < 0)
		goto err;
	for (i = 0; i < SELFMAG; i++)
		if (mp->hdr.e_ident[i] != ELFMAG[i])
			goto err;
	if ((mp->hdr.e_ident[EI_DATA] != ELFDATA2LSB) ||
	    (mp->hdr.e_machine != machine))
		goto err;

	/* Read in the section headers */
	n = mp->hdr.e_shentsize * mp->hdr.e_shnum;
	mp->shdrs = kmem_zalloc(n, KM_SLEEP);
	if (kobj_read_file(file, mp->shdrs, n, mp->hdr.e_shoff) < 0)
		goto err;

	/* Read the section names */
	shp = (Shdr *)(mp->shdrs + mp->hdr.e_shstrndx * mp->hdr.e_shentsize);
	namesize = shp->sh_size;
	names = kmem_zalloc(shp->sh_size, KM_SLEEP);
	if (kobj_read_file(file, names, shp->sh_size, shp->sh_offset) < 0)
		goto err;

	/*
	 * Fill in the text and data size fields.
	 */
	ctf_shp = NULL;
	text_align = data_align = 0;
	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		shp = (Shdr *)(mp->shdrs + shn * mp->hdr.e_shentsize);

		/* Sanity check the offset of the section name */
		if (shp->sh_name >= namesize)
			continue;

		/* If we find the symtab section, remember it for later. */
		if (shp->sh_type == SHT_SYMTAB) {
			mp->symtbl_section = shn;
			mp->symhdr = shp;
			continue;
		}

		/* If we find the CTF section, remember it for later. */
		if ((shp->sh_size != 0) &&
		    (strcmp(names + shp->sh_name, ".SUNW_ctf") == 0)) {
			ctf_shp = shp;
			continue;
		}

		if (!(shp->sh_flags & SHF_ALLOC))
			continue;

		/*
		 * Xen marks its text section as writable, so we need to
		 * look for the name - not just the flag.
		 */
		if ((strcmp(&names[shp->sh_name], ".text") != 0) &&
		    (shp->sh_flags & SHF_WRITE) != 0) {
			if (shp->sh_addralign > data_align)
				data_align = shp->sh_addralign;
			mp->data_size = ALIGN(mp->data_size, data_align);
			mp->data_size += ALIGN(shp->sh_size, 8);
			if (mp->data == NULL || mp->data > (char *)shp->sh_addr)
				mp->data = (char *)shp->sh_addr;
		} else {
			if (shp->sh_addralign > text_align)
				text_align = shp->sh_addralign;
			mp->text_size = ALIGN(mp->text_size, text_align);
			mp->text_size += ALIGN(shp->sh_size, 8);
			if (mp->text == NULL || mp->text > (char *)shp->sh_addr)
				mp->text = (char *)shp->sh_addr;
		}
	}
	kmem_free(names, namesize);
	names = NULL;
	shp = NULL;
	mcp->mod_text = mp->text;
	mcp->mod_text_size = mp->text_size;

	/*
	 * If we have symbol table and string table sections, read them in
	 * now.  If we don't, we just plow on.  We'll still get a valid
	 * core dump, but finding anything useful will be just a bit
	 * harder.
	 *
	 * Note: we don't bother with a hash table.  We'll never do a
	 * symbol lookup unless we crash, and then mdb creates its own.  We
	 * also don't try to perform any relocations.  Xen should be loaded
	 * exactly where the ELF file indicates, and the symbol information
	 * in the file should be complete and correct already.  Static
	 * linking ain't all bad.
	 */
	if ((mp->symhdr != NULL) && (mp->symhdr->sh_link < mp->hdr.e_shnum)) {
		mp->strhdr = (Shdr *)
		    (mp->shdrs + mp->symhdr->sh_link * mp->hdr.e_shentsize);
		mp->nsyms = mp->symhdr->sh_size / mp->symhdr->sh_entsize;

		/* Allocate space for the symbol table and strings.  */
		mp->symsize = mp->symhdr->sh_size +
		    mp->nsyms * sizeof (symid_t) + mp->strhdr->sh_size;
		mp->symspace = kmem_zalloc(mp->symsize, KM_SLEEP);
		mp->symtbl = mp->symspace;
		mp->strings = (char *)(mp->symtbl + mp->symhdr->sh_size);

		if ((kobj_read_file(file, mp->symtbl,
		    mp->symhdr->sh_size, mp->symhdr->sh_offset) < 0) ||
		    (kobj_read_file(file, mp->strings,
		    mp->strhdr->sh_size, mp->strhdr->sh_offset) < 0))
			goto err;
	}

	/*
	 * Read in the CTF section
	 */
	if ((ctf_shp != NULL) && ((moddebug & MODDEBUG_NOCTF) == 0)) {
		mp->ctfdata = kmem_zalloc(ctf_shp->sh_size, KM_SLEEP);
		mp->ctfsize = ctf_shp->sh_size;
		if (kobj_read_file(file, mp->ctfdata, mp->ctfsize,
		    ctf_shp->sh_offset) < 0)
			goto err;
	}

	kobj_close_file(file);

	xpv_module = mp;
	xpv_modctl = mcp;
	return;

err:
	cmn_err(CE_WARN, "Failed to initialize xpv module.");
	if (file != NULL)
		kobj_close_file(file);

	kmem_free(mp->filename, strlen(XPV_FILENAME) + 1);
	if (mp->shdrs != NULL)
		kmem_free(mp->shdrs, mp->hdr.e_shentsize * mp->hdr.e_shnum);
	if (mp->symspace != NULL)
		kmem_free(mp->symspace, mp->symsize);
	if (mp->ctfdata != NULL)
		kmem_free(mp->ctfdata, mp->ctfsize);
	kmem_free(mp, sizeof (*mp));
	kmem_free(mcp->mod_filename, strlen(XPV_FILENAME) + 1);
	kmem_free(mcp->mod_modname, strlen(XPV_MODNAME) + 1);
	kmem_free(mcp, sizeof (*mcp));
	if (names != NULL)
		kmem_free(names, namesize);
}

void
xpv_panic_init()
{
	xen_platform_op_t op;
	int i;

	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	for (i = 0; i < mmu.num_level; i++)
		ptable_pfn[i] = PFN_INVALID;

	/* Let Xen know where to jump if/when it panics. */
	op.cmd = XENPF_panic_init;
	op.interface_version = XENPF_INTERFACE_VERSION;
	op.u.panic_init.panic_addr = (unsigned long)xpv_panic_hdlr;

	(void) HYPERVISOR_platform_op(&op);

	init_xen_module();
}
