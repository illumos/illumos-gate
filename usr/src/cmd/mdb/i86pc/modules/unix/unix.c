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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/traptrace.h>
#include <sys/x_call.h>
#include <sys/xc_levels.h>
#include <sys/avintr.h>
#include <sys/systm.h>
#include <sys/trap.h>
#include <sys/mutex.h>
#include <sys/mutex_impl.h>
#include "i86mmu.h"
#include "unix_sup.h"
#include <sys/apix.h>
#include <sys/x86_archext.h>
#include <sys/bitmap.h>
#include <sys/controlregs.h>

#define	TT_HDLR_WIDTH	17


/* apix only */
static apix_impl_t *d_apixs[NCPU];
static int use_apix = 0;

static int
ttrace_ttr_size_check(void)
{
	mdb_ctf_id_t ttrtid;
	ssize_t ttr_size;

	if (mdb_ctf_lookup_by_name("trap_trace_rec_t", &ttrtid) != 0 ||
	    mdb_ctf_type_resolve(ttrtid, &ttrtid) != 0) {
		mdb_warn("failed to determine size of trap_trace_rec_t; "
		    "non-TRAPTRACE kernel?\n");
		return (0);
	}

	if ((ttr_size = mdb_ctf_type_size(ttrtid)) !=
	    sizeof (trap_trace_rec_t)) {
		/*
		 * On Intel machines, this will happen when TTR_STACK_DEPTH
		 * is changed.  This code could be smarter, and could
		 * dynamically adapt to different depths, but not until a
		 * need for such adaptation is demonstrated.
		 */
		mdb_warn("size of trap_trace_rec_t (%d bytes) doesn't "
		    "match expected %d\n", ttr_size, sizeof (trap_trace_rec_t));
		return (0);
	}

	return (1);
}

int
ttrace_walk_init(mdb_walk_state_t *wsp)
{
	trap_trace_ctl_t *ttcp;
	size_t ttc_size = sizeof (trap_trace_ctl_t) * NCPU;
	int i;

	if (!ttrace_ttr_size_check())
		return (WALK_ERR);

	ttcp = mdb_zalloc(ttc_size, UM_SLEEP);

	if (wsp->walk_addr != NULL) {
		mdb_warn("ttrace only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readsym(ttcp, ttc_size, "trap_trace_ctl") == -1) {
		mdb_warn("symbol 'trap_trace_ctl' not found; "
		    "non-TRAPTRACE kernel?\n");
		mdb_free(ttcp, ttc_size);
		return (WALK_ERR);
	}

	/*
	 * We'll poach the ttc_current pointer (which isn't used for
	 * anything) to store a pointer to our current TRAPTRACE record.
	 * This allows us to only keep the array of trap_trace_ctl structures
	 * as our walker state (ttc_current may be the only kernel data
	 * structure member added exclusively to make writing the mdb walker
	 * a little easier).
	 */
	for (i = 0; i < NCPU; i++) {
		trap_trace_ctl_t *ttc = &ttcp[i];

		if (ttc->ttc_first == NULL)
			continue;

		/*
		 * Assign ttc_current to be the last completed record.
		 * Note that the error checking (i.e. in the ttc_next ==
		 * ttc_first case) is performed in the step function.
		 */
		ttc->ttc_current = ttc->ttc_next - sizeof (trap_trace_rec_t);
	}

	wsp->walk_data = ttcp;
	return (WALK_NEXT);
}

int
ttrace_walk_step(mdb_walk_state_t *wsp)
{
	trap_trace_ctl_t *ttcp = wsp->walk_data, *ttc, *latest_ttc;
	trap_trace_rec_t rec;
	int rval, i, recsize = sizeof (trap_trace_rec_t);
	hrtime_t latest = 0;

	/*
	 * Loop through the CPUs, looking for the latest trap trace record
	 * (we want to walk through the trap trace records in reverse
	 * chronological order).
	 */
	for (i = 0; i < NCPU; i++) {
		ttc = &ttcp[i];

		if (ttc->ttc_current == NULL)
			continue;

		if (ttc->ttc_current < ttc->ttc_first)
			ttc->ttc_current = ttc->ttc_limit - recsize;

		if (mdb_vread(&rec, sizeof (rec), ttc->ttc_current) == -1) {
			mdb_warn("couldn't read rec at %p", ttc->ttc_current);
			return (WALK_ERR);
		}

		if (rec.ttr_stamp > latest) {
			latest = rec.ttr_stamp;
			latest_ttc = ttc;
		}
	}

	if (latest == 0)
		return (WALK_DONE);

	ttc = latest_ttc;

	if (mdb_vread(&rec, sizeof (rec), ttc->ttc_current) == -1) {
		mdb_warn("couldn't read rec at %p", ttc->ttc_current);
		return (WALK_ERR);
	}

	rval = wsp->walk_callback(ttc->ttc_current, &rec, wsp->walk_cbdata);

	if (ttc->ttc_current == ttc->ttc_next)
		ttc->ttc_current = NULL;
	else
		ttc->ttc_current -= sizeof (trap_trace_rec_t);

	return (rval);
}

void
ttrace_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (trap_trace_ctl_t) * NCPU);
}

static int
ttrace_syscall(trap_trace_rec_t *rec)
{
	GElf_Sym sym;
	int sysnum = rec->ttr_sysnum;
	uintptr_t addr;
	struct sysent sys;

	mdb_printf("%-3x", sysnum);

	if (rec->ttr_sysnum > NSYSCALL) {
		mdb_printf(" %-*d", TT_HDLR_WIDTH, rec->ttr_sysnum);
		return (0);
	}

	if (mdb_lookup_by_name("sysent", &sym) == -1) {
		mdb_warn("\ncouldn't find 'sysent'");
		return (-1);
	}

	addr = (uintptr_t)sym.st_value + sysnum * sizeof (struct sysent);

	if (addr >= (uintptr_t)sym.st_value + sym.st_size) {
		mdb_warn("\nsysnum %d out-of-range\n", sysnum);
		return (-1);
	}

	if (mdb_vread(&sys, sizeof (sys), addr) == -1) {
		mdb_warn("\nfailed to read sysent at %p", addr);
		return (-1);
	}

	mdb_printf(" %-*a", TT_HDLR_WIDTH, sys.sy_callc);

	return (0);
}

static int
ttrace_interrupt(trap_trace_rec_t *rec)
{
	GElf_Sym sym;
	uintptr_t addr;
	struct av_head hd;
	struct autovec av;

	switch (rec->ttr_regs.r_trapno) {
	case T_SOFTINT:
		mdb_printf("%-3s %-*s", "-", TT_HDLR_WIDTH, "(fakesoftint)");
		return (0);
	default:
		break;
	}

	mdb_printf("%-3x ", rec->ttr_vector);

	if (mdb_lookup_by_name("autovect", &sym) == -1) {
		mdb_warn("\ncouldn't find 'autovect'");
		return (-1);
	}

	addr = (uintptr_t)sym.st_value +
	    rec->ttr_vector * sizeof (struct av_head);

	if (addr >= (uintptr_t)sym.st_value + sym.st_size) {
		mdb_warn("\nav_head for vec %x is corrupt\n", rec->ttr_vector);
		return (-1);
	}

	if (mdb_vread(&hd, sizeof (hd), addr) == -1) {
		mdb_warn("\ncouldn't read av_head for vec %x", rec->ttr_vector);
		return (-1);
	}

	if (hd.avh_link == NULL) {
		if (rec->ttr_ipl == XC_CPUPOKE_PIL)
			mdb_printf("%-*s", TT_HDLR_WIDTH, "(cpupoke)");
		else
			mdb_printf("%-*s", TT_HDLR_WIDTH, "(spurious)");
	} else {
		if (mdb_vread(&av, sizeof (av), (uintptr_t)hd.avh_link) == -1) {
			mdb_warn("couldn't read autovec at %p",
			    (uintptr_t)hd.avh_link);
		}

		mdb_printf("%-*a", TT_HDLR_WIDTH, av.av_vector);
	}

	return (0);
}

static int
ttrace_apix_interrupt(trap_trace_rec_t *rec)
{
	struct autovec av;
	apix_impl_t apix;
	apix_vector_t apix_vector;

	switch (rec->ttr_regs.r_trapno) {
	case T_SOFTINT:
		mdb_printf("%-3s %-*s", "-", TT_HDLR_WIDTH, "(fakesoftint)");
		return (0);
	default:
		break;
	}

	mdb_printf("%-3x ", rec->ttr_vector);

	/* Read the per CPU apix entry */
	if (mdb_vread(&apix, sizeof (apix_impl_t),
	    (uintptr_t)d_apixs[rec->ttr_cpuid]) == -1) {
		mdb_warn("\ncouldn't read apix[%d]", rec->ttr_cpuid);
		return (-1);
	}
	if (mdb_vread(&apix_vector, sizeof (apix_vector_t),
	    (uintptr_t)apix.x_vectbl[rec->ttr_vector]) == -1) {
		mdb_warn("\ncouldn't read apix_vector_t[%d]", rec->ttr_vector);
		return (-1);
	}
	if (apix_vector.v_share == 0) {
		if (rec->ttr_ipl == XC_CPUPOKE_PIL)
			mdb_printf("%-*s", TT_HDLR_WIDTH, "(cpupoke)");
		else
			mdb_printf("%-*s", TT_HDLR_WIDTH, "(spurious)");
	} else {
		if (mdb_vread(&av, sizeof (struct autovec),
		    (uintptr_t)(apix_vector.v_autovect)) == -1) {
			mdb_warn("couldn't read autovec at %p",
			    (uintptr_t)apix_vector.v_autovect);
		}

		mdb_printf("%-*a", TT_HDLR_WIDTH, av.av_vector);
	}

	return (0);
}


static struct {
	int tt_trapno;
	char *tt_name;
} ttrace_traps[] = {
	{ T_ZERODIV,	"divide-error" },
	{ T_SGLSTP,	"debug-exception" },
	{ T_NMIFLT,	"nmi-interrupt" },
	{ T_BPTFLT,	"breakpoint" },
	{ T_OVFLW,	"into-overflow" },
	{ T_BOUNDFLT,	"bound-exceeded" },
	{ T_ILLINST,	"invalid-opcode" },
	{ T_NOEXTFLT,	"device-not-avail" },
	{ T_DBLFLT,	"double-fault" },
	{ T_EXTOVRFLT,	"segment-overrun" },
	{ T_TSSFLT,	"invalid-tss" },
	{ T_SEGFLT,	"segment-not-pres" },
	{ T_STKFLT,	"stack-fault" },
	{ T_GPFLT,	"general-protectn" },
	{ T_PGFLT,	"page-fault" },
	{ T_EXTERRFLT,	"error-fault" },
	{ T_ALIGNMENT,	"alignment-check" },
	{ T_MCE,	"machine-check" },
	{ T_SIMDFPE,	"sse-exception" },

	{ T_DBGENTR,	"debug-enter" },
	{ T_FASTTRAP,	"fasttrap-0xd2" },
	{ T_SYSCALLINT,	"syscall-0x91" },
	{ T_DTRACE_RET,	"dtrace-ret" },
	{ T_SOFTINT,	"softint" },
	{ T_INTERRUPT,	"interrupt" },
	{ T_FAULT,	"fault" },
	{ T_AST,	"ast" },
	{ T_SYSCALL,	"syscall" },

	{ 0,		NULL }
};

static int
ttrace_trap(trap_trace_rec_t *rec)
{
	int i;

	if (rec->ttr_regs.r_trapno == T_AST)
		mdb_printf("%-3s ", "-");
	else
		mdb_printf("%-3x ", rec->ttr_regs.r_trapno);

	for (i = 0; ttrace_traps[i].tt_name != NULL; i++) {
		if (rec->ttr_regs.r_trapno == ttrace_traps[i].tt_trapno)
			break;
	}

	if (ttrace_traps[i].tt_name == NULL)
		mdb_printf("%-*s", TT_HDLR_WIDTH, "(unknown)");
	else
		mdb_printf("%-*s", TT_HDLR_WIDTH, ttrace_traps[i].tt_name);

	return (0);
}

static void
ttrace_intr_detail(trap_trace_rec_t *rec)
{
	mdb_printf("\tirq %x ipl %d oldpri %d basepri %d\n", rec->ttr_vector,
	    rec->ttr_ipl, rec->ttr_pri, rec->ttr_spl);
}

static struct {
	uchar_t t_marker;
	char *t_name;
	int (*t_hdlr)(trap_trace_rec_t *);
} ttrace_hdlr[] = {
	{ TT_SYSCALL, "sysc", ttrace_syscall },
	{ TT_SYSENTER, "syse", ttrace_syscall },
	{ TT_SYSC, "asys", ttrace_syscall },
	{ TT_SYSC64, "sc64", ttrace_syscall },
	{ TT_INTERRUPT, "intr", ttrace_interrupt },
	{ TT_TRAP, "trap", ttrace_trap },
	{ TT_EVENT, "evnt", ttrace_trap },
	{ 0, NULL, NULL }
};

typedef struct ttrace_dcmd {
	processorid_t ttd_cpu;
	uint_t ttd_extended;
	uintptr_t ttd_kthread;
	trap_trace_ctl_t ttd_ttc[NCPU];
} ttrace_dcmd_t;

#if defined(__amd64)

#define	DUMP(reg) #reg, regs->r_##reg
#define	THREEREGS	"         %3s: %16lx %3s: %16lx %3s: %16lx\n"

static void
ttrace_dumpregs(trap_trace_rec_t *rec)
{
	struct regs *regs = &rec->ttr_regs;

	mdb_printf(THREEREGS, DUMP(rdi), DUMP(rsi), DUMP(rdx));
	mdb_printf(THREEREGS, DUMP(rcx), DUMP(r8), DUMP(r9));
	mdb_printf(THREEREGS, DUMP(rax), DUMP(rbx), DUMP(rbp));
	mdb_printf(THREEREGS, DUMP(r10), DUMP(r11), DUMP(r12));
	mdb_printf(THREEREGS, DUMP(r13), DUMP(r14), DUMP(r15));
	mdb_printf(THREEREGS, DUMP(ds), DUMP(es), DUMP(fs));
	mdb_printf(THREEREGS, DUMP(gs), "trp", regs->r_trapno, DUMP(err));
	mdb_printf(THREEREGS, DUMP(rip), DUMP(cs), DUMP(rfl));
	mdb_printf(THREEREGS, DUMP(rsp), DUMP(ss), "cr2", rec->ttr_cr2);
	mdb_printf("\n");
}

#else

#define	DUMP(reg) #reg, regs->r_##reg
#define	FOURREGS	"         %3s: %08x %3s: %08x %3s: %08x %3s: %08x\n"

static void
ttrace_dumpregs(trap_trace_rec_t *rec)
{
	struct regs *regs = &rec->ttr_regs;

	mdb_printf(FOURREGS, DUMP(gs), DUMP(fs), DUMP(es), DUMP(ds));
	mdb_printf(FOURREGS, DUMP(edi), DUMP(esi), DUMP(ebp), DUMP(esp));
	mdb_printf(FOURREGS, DUMP(ebx), DUMP(edx), DUMP(ecx), DUMP(eax));
	mdb_printf(FOURREGS, "trp", regs->r_trapno, DUMP(err),
	    DUMP(pc), DUMP(cs));
	mdb_printf(FOURREGS, DUMP(efl), "usp", regs->r_uesp, DUMP(ss),
	    "cr2", rec->ttr_cr2);
	mdb_printf("\n");
}

#endif	/* __amd64 */

int
ttrace_walk(uintptr_t addr, trap_trace_rec_t *rec, ttrace_dcmd_t *dcmd)
{
	struct regs *regs = &rec->ttr_regs;
	processorid_t cpu = -1, i;

	for (i = 0; i < NCPU; i++) {
		if (addr >= dcmd->ttd_ttc[i].ttc_first &&
		    addr < dcmd->ttd_ttc[i].ttc_limit) {
			cpu = i;
			break;
		}
	}

	if (cpu == -1) {
		mdb_warn("couldn't find %p in any trap trace ctl\n", addr);
		return (WALK_ERR);
	}

	if (dcmd->ttd_cpu != -1 && cpu != dcmd->ttd_cpu)
		return (WALK_NEXT);

	if (dcmd->ttd_kthread != 0 &&
	    dcmd->ttd_kthread != rec->ttr_curthread)
		return (WALK_NEXT);

	mdb_printf("%3d %15llx ", cpu, rec->ttr_stamp);

	for (i = 0; ttrace_hdlr[i].t_hdlr != NULL; i++) {
		if (rec->ttr_marker != ttrace_hdlr[i].t_marker)
			continue;
		mdb_printf("%4s ", ttrace_hdlr[i].t_name);
		if (ttrace_hdlr[i].t_hdlr(rec) == -1)
			return (WALK_ERR);
	}

	mdb_printf(" %a\n", regs->r_pc);

	if (dcmd->ttd_extended == FALSE)
		return (WALK_NEXT);

	if (rec->ttr_marker == TT_INTERRUPT)
		ttrace_intr_detail(rec);
	else
		ttrace_dumpregs(rec);

	if (rec->ttr_sdepth > 0) {
		for (i = 0; i < rec->ttr_sdepth; i++) {
			if (i >= TTR_STACK_DEPTH) {
				mdb_printf("%17s*** invalid ttr_sdepth (is %d, "
				    "should be <= %d)\n", " ", rec->ttr_sdepth,
				    TTR_STACK_DEPTH);
				break;
			}

			mdb_printf("%17s %a()\n", " ", rec->ttr_stack[i]);
		}
		mdb_printf("\n");
	}

	return (WALK_NEXT);
}

int
ttrace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ttrace_dcmd_t dcmd;
	trap_trace_ctl_t *ttc = dcmd.ttd_ttc;
	trap_trace_rec_t rec;
	size_t ttc_size = sizeof (trap_trace_ctl_t) * NCPU;

	if (!ttrace_ttr_size_check())
		return (WALK_ERR);

	bzero(&dcmd, sizeof (dcmd));
	dcmd.ttd_cpu = -1;
	dcmd.ttd_extended = FALSE;

	if (mdb_readsym(ttc, ttc_size, "trap_trace_ctl") == -1) {
		mdb_warn("symbol 'trap_trace_ctl' not found; "
		    "non-TRAPTRACE kernel?\n");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'x', MDB_OPT_SETBITS, TRUE, &dcmd.ttd_extended,
	    't', MDB_OPT_UINTPTR, &dcmd.ttd_kthread, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%3s %15s %4s %2s %-*s%s\n", "CPU",
		    "TIMESTAMP", "TYPE", "Vec", TT_HDLR_WIDTH, "HANDLER",
		    " EIP");
	}

	if (flags & DCMD_ADDRSPEC) {
		if (addr >= NCPU) {
			if (mdb_vread(&rec, sizeof (rec), addr) == -1) {
				mdb_warn("couldn't read trap trace record "
				    "at %p", addr);
				return (DCMD_ERR);
			}

			if (ttrace_walk(addr, &rec, &dcmd) == WALK_ERR)
				return (DCMD_ERR);

			return (DCMD_OK);
		}
		dcmd.ttd_cpu = addr;
	}

	if (mdb_readvar(&use_apix, "apix_enable") == -1) {
		mdb_warn("failed to read apix_enable");
		use_apix = 0;
	}

	if (use_apix) {
		if (mdb_readvar(&d_apixs, "apixs") == -1) {
			mdb_warn("\nfailed to read apixs.");
			return (DCMD_ERR);
		}
		/* change to apix ttrace interrupt handler */
		ttrace_hdlr[4].t_hdlr = ttrace_apix_interrupt;
	}

	if (mdb_walk("ttrace", (mdb_walk_cb_t)ttrace_walk, &dcmd) == -1) {
		mdb_warn("couldn't walk 'ttrace'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
mutex_owner_init(mdb_walk_state_t *wsp)
{
	return (WALK_NEXT);
}

int
mutex_owner_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mutex_impl_t mtx;
	uintptr_t owner;
	kthread_t thr;

	if (mdb_vread(&mtx, sizeof (mtx), addr) == -1)
		return (WALK_ERR);

	if (!MUTEX_TYPE_ADAPTIVE(&mtx))
		return (WALK_DONE);

	if ((owner = (uintptr_t)MUTEX_OWNER(&mtx)) == NULL)
		return (WALK_DONE);

	if (mdb_vread(&thr, sizeof (thr), owner) != -1)
		(void) wsp->walk_callback(owner, &thr, wsp->walk_cbdata);

	return (WALK_DONE);
}

static void
gate_desc_dump(gate_desc_t *gate, const char *label, int header)
{
	const char *lastnm;
	uint_t lastval;
	char type[4];

	switch (gate->sgd_type) {
	case SDT_SYSIGT:
		strcpy(type, "int");
		break;
	case SDT_SYSTGT:
		strcpy(type, "trp");
		break;
	case SDT_SYSTASKGT:
		strcpy(type, "tsk");
		break;
	default:
		(void) mdb_snprintf(type, sizeof (type), "%3x", gate->sgd_type);
	}

#if defined(__amd64)
	lastnm = "IST";
	lastval = gate->sgd_ist;
#else
	lastnm = "STK";
	lastval = gate->sgd_stkcpy;
#endif

	if (header) {
		mdb_printf("%*s%<u>%-30s%</u> %<u>%-4s%</u> %<u>%3s%</u> "
		    "%<u>%1s%</u> %<u>%3s%</u> %<u>%3s%</u>\n", strlen(label),
		    "", "HANDLER", "SEL", "DPL", "P", "TYP", lastnm);
	}

	mdb_printf("%s", label);

	if (gate->sgd_type == SDT_SYSTASKGT)
		mdb_printf("%-30s ", "-");
	else
		mdb_printf("%-30a ", GATESEG_GETOFFSET(gate));

	mdb_printf("%4x  %d  %c %3s %2x\n", gate->sgd_selector,
	    gate->sgd_dpl, (gate->sgd_p ? '+' : ' '), type, lastval);
}

/*ARGSUSED*/
static int
gate_desc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	gate_desc_t gate;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&gate, sizeof (gate_desc_t), addr) !=
	    sizeof (gate_desc_t)) {
		mdb_warn("failed to read gate descriptor at %p\n", addr);
		return (DCMD_ERR);
	}

	gate_desc_dump(&gate, "", DCMD_HDRSPEC(flags));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
idt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;

	if (!(flags & DCMD_ADDRSPEC)) {
		GElf_Sym idt0_va;
		gate_desc_t *idt0;

		if (mdb_lookup_by_name("idt0", &idt0_va) < 0) {
			mdb_warn("failed to find VA of idt0");
			return (DCMD_ERR);
		}

		addr = idt0_va.st_value;
		if (mdb_vread(&idt0, sizeof (idt0), addr) != sizeof (idt0)) {
			mdb_warn("failed to read idt0 at %p\n", addr);
			return (DCMD_ERR);
		}

		addr = (uintptr_t)idt0;
	}

	for (i = 0; i < NIDT; i++, addr += sizeof (gate_desc_t)) {
		gate_desc_t gate;
		char label[6];

		if (mdb_vread(&gate, sizeof (gate_desc_t), addr) !=
		    sizeof (gate_desc_t)) {
			mdb_warn("failed to read gate descriptor at %p\n",
			    addr);
			return (DCMD_ERR);
		}

		(void) mdb_snprintf(label, sizeof (label), "%3d: ", i);
		gate_desc_dump(&gate, label, i == 0);
	}

	return (DCMD_OK);
}

static void
htables_help(void)
{
	mdb_printf(
	    "Given a (hat_t *), generates the list of all (htable_t *)s\n"
	    "that correspond to that address space\n");
}

static void
report_maps_help(void)
{
	mdb_printf(
	    "Given a PFN, report HAT structures that map the page, or use\n"
	    "the page as a pagetable.\n"
	    "\n"
	    "-m Interpret the PFN as an MFN (machine frame number)\n");
}

static void
ptable_help(void)
{
	mdb_printf(
	    "Given a PFN holding a page table, print its contents, and\n"
	    "the address of the corresponding htable structure.\n"
	    "\n"
	    "-m Interpret the PFN as an MFN (machine frame number)\n");
}

/*
 * NSEC_SHIFT is replicated here (it is not defined in a header file),
 * but for amusement, the reader is directed to the comment that explains
 * the rationale for this particular value on x86.  Spoiler:  the value is
 * selected to accommodate 60 MHz Pentiums!  (And a confession:  if the voice
 * in that comment sounds too familiar, it's because your author also wrote
 * that code -- some fifteen years prior to this writing in 2011...)
 */
#define	NSEC_SHIFT 5

/*ARGSUSED*/
static int
scalehrtime_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint32_t nsec_scale;
	hrtime_t tsc = addr, hrt;
	unsigned int *tscp = (unsigned int *)&tsc;
	uintptr_t scalehrtimef;
	uint64_t scale;
	GElf_Sym sym;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (argc != 1)
			return (DCMD_USAGE);

		switch (argv[0].a_type) {
		case MDB_TYPE_STRING:
			tsc = mdb_strtoull(argv[0].a_un.a_str);
			break;
		case MDB_TYPE_IMMEDIATE:
			tsc = argv[0].a_un.a_val;
			break;
		default:
			return (DCMD_USAGE);
		}
	}

	if (mdb_readsym(&scalehrtimef,
	    sizeof (scalehrtimef), "scalehrtimef") == -1) {
		mdb_warn("couldn't read 'scalehrtimef'");
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("tsc_scalehrtime", &sym) == -1) {
		mdb_warn("couldn't find 'tsc_scalehrtime'");
		return (DCMD_ERR);
	}

	if (sym.st_value != scalehrtimef) {
		mdb_warn("::scalehrtime requires that scalehrtimef "
		    "be set to tsc_scalehrtime\n");
		return (DCMD_ERR);
	}

	if (mdb_readsym(&nsec_scale, sizeof (nsec_scale), "nsec_scale") == -1) {
		mdb_warn("couldn't read 'nsec_scale'");
		return (DCMD_ERR);
	}

	scale = (uint64_t)nsec_scale;

	hrt = ((uint64_t)tscp[1] * scale) << NSEC_SHIFT;
	hrt += ((uint64_t)tscp[0] * scale) >> (32 - NSEC_SHIFT);

	mdb_printf("0x%llx\n", hrt);

	return (DCMD_OK);
}

/*
 * The x86 feature set is implemented as a bitmap array. That bitmap array is
 * stored across a number of uchars based on the BT_SIZEOFMAP(NUM_X86_FEATURES)
 * macro. We have the names for each of these features in unix's text segment
 * so we do not have to duplicate them and instead just look them up.
 */
/*ARGSUSED*/
static int
x86_featureset_cmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	void *fset;
	GElf_Sym sym;
	uintptr_t nptr;
	char name[128];
	int ii;

	size_t sz = sizeof (uchar_t) * BT_SIZEOFMAP(NUM_X86_FEATURES);

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_lookup_by_name("x86_feature_names", &sym) == -1) {
		mdb_warn("couldn't find x86_feature_names");
		return (DCMD_ERR);
	}

	fset = mdb_zalloc(sz, UM_NOSLEEP);
	if (fset == NULL) {
		mdb_warn("failed to allocate memory for x86_featureset");
		return (DCMD_ERR);
	}

	if (mdb_readvar(fset, "x86_featureset") != sz) {
		mdb_warn("failed to read x86_featureset");
		mdb_free(fset, sz);
		return (DCMD_ERR);
	}

	for (ii = 0; ii < NUM_X86_FEATURES; ii++) {
		if (!BT_TEST((ulong_t *)fset, ii))
			continue;

		if (mdb_vread(&nptr, sizeof (char *), sym.st_value +
		    sizeof (void *) * ii) != sizeof (char *)) {
			mdb_warn("failed to read feature array %d", ii);
			mdb_free(fset, sz);
			return (DCMD_ERR);
		}

		if (mdb_readstr(name, sizeof (name), nptr) == -1) {
			mdb_warn("failed to read feature %d", ii);
			mdb_free(fset, sz);
			return (DCMD_ERR);
		}
		mdb_printf("%s\n", name);
	}

	mdb_free(fset, sz);
	return (DCMD_OK);
}

#ifdef _KMDB
/* ARGSUSED */
static int
crregs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ulong_t cr0, cr2, cr3, cr4;
	static const mdb_bitmask_t cr0_flag_bits[] = {
		{ "PE",		CR0_PE,		CR0_PE },
		{ "MP",		CR0_MP,		CR0_MP },
		{ "EM",		CR0_EM,		CR0_EM },
		{ "TS",		CR0_TS,		CR0_TS },
		{ "ET",		CR0_ET,		CR0_ET },
		{ "NE",		CR0_NE,		CR0_NE },
		{ "WP",		CR0_WP,		CR0_WP },
		{ "AM",		CR0_AM,		CR0_AM },
		{ "NW",		CR0_NW,		CR0_NW },
		{ "CD",		CR0_CD,		CR0_CD },
		{ "PG",		CR0_PG,		CR0_PG },
		{ NULL,		0,		0 }
	};

	static const mdb_bitmask_t cr3_flag_bits[] = {
		{ "PCD",	CR3_PCD,	CR3_PCD },
		{ "PWT",	CR3_PWT,	CR3_PWT },
		{ NULL,		0,		0, }
	};

	static const mdb_bitmask_t cr4_flag_bits[] = {
		{ "VME",	CR4_VME,	CR4_VME },
		{ "PVI",	CR4_PVI,	CR4_PVI },
		{ "TSD",	CR4_TSD,	CR4_TSD },
		{ "DE",		CR4_DE,		CR4_DE },
		{ "PSE",	CR4_PSE,	CR4_PSE },
		{ "PAE",	CR4_PAE,	CR4_PAE },
		{ "MCE",	CR4_MCE,	CR4_MCE },
		{ "PGE",	CR4_PGE,	CR4_PGE },
		{ "PCE",	CR4_PCE,	CR4_PCE },
		{ "OSFXSR",	CR4_OSFXSR,	CR4_OSFXSR },
		{ "OSXMMEXCPT",	CR4_OSXMMEXCPT,	CR4_OSXMMEXCPT },
		{ "VMXE",	CR4_VMXE,	CR4_VMXE },
		{ "SMXE",	CR4_SMXE,	CR4_SMXE },
		{ "PCIDE",	CR4_PCIDE,	CR4_PCIDE },
		{ "OSXSAVE",	CR4_OSXSAVE,	CR4_OSXSAVE },
		{ "SMEP",	CR4_SMEP,	CR4_SMEP },
		{ "SMAP",	CR4_SMAP,	CR4_SMAP },
		{ NULL,		0,		0 }
	};

	cr0 = kmdb_unix_getcr0();
	cr2 = kmdb_unix_getcr2();
	cr3 = kmdb_unix_getcr3();
	cr4 = kmdb_unix_getcr4();
	mdb_printf("%%cr0 = 0x%08x <%b>\n", cr0, cr0, cr0_flag_bits);
	mdb_printf("%%cr2 = 0x%08x <%a>\n", cr2, cr2);

	if ((cr4 & CR4_PCIDE)) {
		mdb_printf("%%cr3 = 0x%08x <pfn:%lu pcid:%u>\n",
		    cr3 >> MMU_PAGESHIFT, cr3 & MMU_PAGEOFFSET);
	} else {
		mdb_printf("%%cr3 = 0x%08x <pfn:%lu flags:%b>\n", cr3,
		    cr3 >> MMU_PAGESHIFT, cr3, cr3_flag_bits);
	}

	mdb_printf("%%cr4 = 0x%08x <%b>\n", cr4, cr4, cr4_flag_bits);

	return (DCMD_OK);
}
#endif

static const mdb_dcmd_t dcmds[] = {
	{ "gate_desc", ":", "dump a gate descriptor", gate_desc },
	{ "idt", ":[-v]", "dump an IDT", idt },
	{ "ttrace", "[-x] [-t kthread]", "dump trap trace buffers", ttrace },
	{ "vatopfn", ":[-a as]", "translate address to physical page",
	    va2pfn_dcmd },
	{ "report_maps", ":[-m]",
	    "Given PFN, report mappings / page table usage",
	    report_maps_dcmd, report_maps_help },
	{ "htables", "", "Given hat_t *, lists all its htable_t * values",
	    htables_dcmd, htables_help },
	{ "ptable", ":[-m]", "Given PFN, dump contents of a page table",
	    ptable_dcmd, ptable_help },
	{ "pte", ":[-p XXXXX] [-l N]", "print human readable page table entry",
	    pte_dcmd },
	{ "pfntomfn", ":", "convert physical page to hypervisor machine page",
	    pfntomfn_dcmd },
	{ "mfntopfn", ":", "convert hypervisor machine page to physical page",
	    mfntopfn_dcmd },
	{ "memseg_list", ":", "show memseg list", memseg_list },
	{ "scalehrtime", ":",
	    "scale an unscaled high-res time", scalehrtime_cmd },
	{ "x86_featureset", NULL, "dump the x86_featureset vector",
		x86_featureset_cmd },
#ifdef _KMDB
	{ "crregs", NULL, "dump control registers", crregs_dcmd },
#endif
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ttrace", "walks trap trace buffers in reverse chronological order",
		ttrace_walk_init, ttrace_walk_step, ttrace_walk_fini },
	{ "mutex_owner", "walks the owner of a mutex",
		mutex_owner_init, mutex_owner_step },
	{ "memseg", "walk the memseg structures",
		memseg_walk_init, memseg_walk_step, memseg_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

void
_mdb_fini(void)
{
	free_mmu();
}
