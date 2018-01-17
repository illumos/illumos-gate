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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * isa-dependent portions of the kmdb target
 */

#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_v9util.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_umem.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kvm.h>
#include <mdb/mdb.h>

#include <sys/types.h>
#include <sys/stack.h>
#include <sys/regset.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/machtrap.h>
#include <sys/trap.h>

/* Higher than the highest trap number for which we have a specific specifier */
#define	KMT_MAXTRAPNO	0x1ff

#define	OP(x)		((x) >> 30)
#define	OP3(x)		(((x) >> 19) & 0x3f)
#define	RD(x)		(((x) >> 25) & 0x1f)
#define	RS1(x)		(((x) >> 14) & 0x1f)
#define	RS2(x)		((x) & 0x1f)

#define	OP_ARITH	0x2

#define	OP3_OR		0x02
#define	OP3_SAVE	0x3c
#define	OP3_RESTORE	0x3d

static int
kmt_stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gsp,
    mdb_tgt_stack_f *func, void *arg, int cpuid)
{
	const mdb_tgt_gregset_t *grp;
	mdb_tgt_gregset_t gregs;
	kreg_t *kregs = &gregs.kregs[0];
	long nwin, stopwin, canrestore, wp, i, sp;
	long argv[6];

	/*
	 * If gsp isn't null, we were asked to dump a trace from a
	 * specific location.  The normal iterator can handle that.
	 */
	if (gsp != NULL) {
		if (cpuid != DPI_MASTER_CPUID)
			warn("register set provided - ignoring cpu argument\n");
		return (mdb_kvm_v9stack_iter(t, gsp, func, arg));
	}

	if (kmdb_dpi_get_cpu_state(cpuid) < 0) {
		warn("failed to iterate through stack for cpu %u", cpuid);
		return (DCMD_ERR);
	}

	/*
	 * We're being asked to dump the trace for the current CPU.
	 * To do that, we need to iterate first through the saved
	 * register windors.  If there's more to the trace than that,
	 * we'll hand off to the normal iterator.
	 */
	if ((grp = kmdb_dpi_get_gregs(cpuid)) == NULL) {
		warn("failed to retrieve registers for cpu %d", cpuid);
		return (DCMD_ERR);
	}

	bcopy(grp, &gregs, sizeof (mdb_tgt_gregset_t));

	wp = kregs[KREG_CWP];
	canrestore = kregs[KREG_CANRESTORE];
	nwin = kmdb_dpi_get_nwin(cpuid);
	stopwin = ((wp + nwin) - canrestore - 1) % nwin;

	mdb_dprintf(MDB_DBG_KMOD, "dumping cwp = %lu, canrestore = %lu, "
	    "stopwin = %lu\n", wp, canrestore, stopwin);

	for (;;) {
		struct rwindow rwin;

		for (i = 0; i < 6; i++)
			argv[i] = kregs[KREG_I0 + i];

		if (kregs[KREG_PC] != 0 &&
		    func(arg, kregs[KREG_PC], 6, argv, &gregs) != 0)
			return (0);

		kregs[KREG_PC] = kregs[KREG_I7];
		kregs[KREG_NPC] = kregs[KREG_PC] + 4;

		if ((sp = kregs[KREG_FP] + STACK_BIAS) == STACK_BIAS || sp == 0)
			return (0); /* Stop if we're at the end of stack */

		if (sp & (STACK_ALIGN - 1))
			return (set_errno(EMDB_STKALIGN));

		wp = (wp + nwin - 1) % nwin;

		if (wp == stopwin)
			break;

		bcopy(&kregs[KREG_I0], &kregs[KREG_O0], 8 * sizeof (kreg_t));

		if (kmdb_dpi_get_rwin(cpuid, wp, &rwin) < 0) {
			warn("unable to get registers from window %ld\n", wp);
			return (-1);
		}

		for (i = 0; i < 8; i++)
			kregs[KREG_L0 + i] = (uintptr_t)rwin.rw_local[i];
		for (i = 0; i < 8; i++)
			kregs[KREG_I0 + i] = (uintptr_t)rwin.rw_in[i];
	}

	mdb_dprintf(MDB_DBG_KMOD, "dumping wp %ld and beyond normally\n", wp);

	/*
	 * hack - if we null out pc here, iterator won't print the frame
	 * that corresponds to the current set of registers.  That's what we
	 * want because we just printed them above.
	 */
	kregs[KREG_PC] = 0;
	return (mdb_kvm_v9stack_iter(t, &gregs, func, arg));
}

void
kmt_printregs(const mdb_tgt_gregset_t *gregs)
{
	mdb_v9printregs(gregs);
}

static int
kmt_stack_common(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int cpuid, mdb_tgt_stack_f *func, kreg_t saved_pc)
{
	mdb_tgt_gregset_t *grp = NULL;
	mdb_tgt_gregset_t gregs;
	void *arg = (void *)(uintptr_t)mdb.m_nargs;

	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.kregs[KREG_FP] = addr;
		gregs.kregs[KREG_I7] = saved_pc;
		grp = &gregs;
	}

	if (argc != 0) {
		if (argv->a_type == MDB_TYPE_CHAR || argc > 1)
			return (DCMD_USAGE);

		if (argv->a_type == MDB_TYPE_STRING)
			arg = (void *)(uintptr_t)(uint_t)
			    mdb_strtoull(argv->a_un.a_str);
		else
			arg = (void *)(uintptr_t)(uint_t)argv->a_un.a_val;
	}

	(void) kmt_stack_iter(mdb.m_target, grp, func, arg, cpuid);

	return (DCMD_OK);
}

int
kmt_cpustack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int cpuid, int verbose)
{
	return (kmt_stack_common(addr, flags, argc, argv, cpuid,
	    (verbose ? mdb_kvm_v9framev : mdb_kvm_v9frame), 0));
}

int
kmt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    mdb_kvm_v9frame, 0));
}

int
kmt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    mdb_kvm_v9framev, 0));
}

int
kmt_stackr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	/*
	 * Force printing of the first register window by setting the saved
	 * pc (%i7) to PC_FAKE.
	 */
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    mdb_kvm_v9framer, PC_FAKE));
}

ssize_t
kmt_write_page(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	jmp_buf *oldpcb = NULL;
	jmp_buf pcb;
	physaddr_t pa;

	/*
	 * Can we write to this page?
	 */
	if (!(t->t_flags & MDB_TGT_F_ALLOWIO) &&
	    (nbytes = kmdb_kdi_range_is_nontoxic(addr, nbytes, 1)) == 0)
		return (set_errno(EMDB_NOMAP));

	/*
	 * The OBP va>pa call returns a protection value that's right only some
	 * of the time.  We can, however, tell if we failed a write due to a
	 * protection violation.  If we get such an error, we'll retry the
	 * write using pwrite.
	 */
	if (setjmp(pcb) != 0) {
		/* We failed the write */
		kmdb_dpi_restore_fault_hdlr(oldpcb);

		if (errno == EACCES && kmdb_prom_vtop(addr, &pa) == 0)
			return (kmt_pwrite(t, buf, nbytes, pa));
		return (-1); /* errno is set for us */
	}

	mdb_dprintf(MDB_DBG_KMOD, "copying %lu bytes from %p to %p\n", nbytes,
	    buf, (void *)addr);

	oldpcb = kmdb_dpi_set_fault_hdlr(&pcb);
	(void) kmt_writer((void *)buf, nbytes, addr);
	kmdb_dpi_restore_fault_hdlr(oldpcb);

	return (nbytes);
}

/*ARGSUSED*/
ssize_t
kmt_write(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	size_t ntowrite, nwritten, n;
	int rc;

	kmdb_prom_check_interrupt();

	if (nbytes == 0)
		return (0);

	/*
	 * Break the writes up into page-sized chunks.  First, the leading page
	 * fragment (if any), then the subsequent pages.
	 */

	if ((n = (addr & (mdb.m_pagesize - 1))) != 0) {
		ntowrite = MIN(mdb.m_pagesize - n, nbytes);

		if ((rc = kmt_write_page(t, buf, ntowrite, addr)) != ntowrite)
			return (rc);

		addr = roundup(addr, mdb.m_pagesize);
		nbytes -= ntowrite;
		nwritten = ntowrite;
		buf = ((caddr_t)buf + ntowrite);
	}

	while (nbytes > 0) {
		ntowrite = MIN(mdb.m_pagesize, nbytes);

		if ((rc = kmt_write_page(t, buf, ntowrite, addr)) != ntowrite)
			return (rc < 0 ? rc : rc + nwritten);

		addr += mdb.m_pagesize;
		nbytes -= ntowrite;
		nwritten += ntowrite;
		buf = ((caddr_t)buf + ntowrite);
	}

	return (rc);
}

/*ARGSUSED*/
ssize_t
kmt_ioread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	return (set_errno(EMDB_TGTHWNOTSUP));
}

/*ARGSUSED*/
ssize_t
kmt_iowrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (set_errno(EMDB_TGTHWNOTSUP));
}

const char *
kmt_def_dismode(void)
{
#ifdef __sparcv9
	return ("v9plus");
#else
	return ("v8");
#endif
}

/*
 * If we are stopped on a save instruction or at the first instruction of a
 * known function, return %o7 as the step-out address; otherwise return the
 * current frame's return address (%i7).  Significantly better handling of
 * step out in leaf routines could be accomplished by implementing more
 * complex decoding of the current function and our current state.
 */
int
kmt_step_out(mdb_tgt_t *t, uintptr_t *p)
{
	kreg_t pc, i7, o7;
	GElf_Sym func;

	(void) kmdb_dpi_get_register("pc", &pc);
	(void) kmdb_dpi_get_register("i7", &i7);
	(void) kmdb_dpi_get_register("o7", &o7);

	if (mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY, NULL, 0,
	    &func, NULL) == 0 && func.st_value == pc)
		*p = o7 + 2 * sizeof (mdb_instr_t);
	else {
		mdb_instr_t instr;

		if (mdb_tgt_vread(t, &instr, sizeof (instr), pc) !=
		    sizeof (instr)) {
			warn("failed to read instruction at %p for step out",
			    (void *)pc);
			return (-1);
		}

		if (OP(instr) == OP_ARITH && OP3(instr) == OP3_SAVE)
			*p = o7 + 2 * sizeof (mdb_instr_t);
		else
			*p = i7 + 2 * sizeof (mdb_instr_t);
	}

	return (0);
}

static const char *
regno2name(int idx)
{
	const mdb_tgt_regdesc_t *rd;

	for (rd = mdb_sparcv9_kregs; rd->rd_name != NULL; rd++) {
		if (idx == rd->rd_num)
			return (rd->rd_name);
	}

	ASSERT(rd->rd_name != NULL);

	return ("unknown");
}

/*
 * Step over call and jmpl by returning the address of the position where a
 * temporary breakpoint can be set to catch return from the control transfer.
 * This function does not currently provide advanced decoding of DCTI couples
 * or any other complex special case; we just fall back to single-step.
 */
int
kmt_next(mdb_tgt_t *t, uintptr_t *p)
{
	kreg_t pc, npc;
	GElf_Sym func;

	(void) kmdb_dpi_get_register("pc", &pc);
	(void) kmdb_dpi_get_register("npc", &npc);

	if (mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY, NULL, 0,
	    &func, NULL) != 0)
		return (-1);

	if (npc < func.st_value || func.st_value + func.st_size <= npc) {
		mdb_instr_t instr;
		kreg_t reg;

		/*
		 * We're about to transfer control outside this function, so we
		 * want to stop when control returns from the other function.
		 * Normally the return address will be in %o7, tail-calls being
		 * the exception.  We try to discover if this is a tail-call and
		 * compute the return address in that case.
		 */
		if (mdb_tgt_vread(t, &instr, sizeof (instr), pc) !=
		    sizeof (instr)) {
			warn("failed to read instruction at %p for next",
			    (void *)pc);
			return (-1);
		}

		if (OP(instr) == OP_ARITH && OP3(instr) == OP3_RESTORE) {
			(void) kmdb_dpi_get_register("i7", &reg);
		} else if (OP(instr) == OP_ARITH && OP3(instr) == OP3_OR &&
		    RD(instr) == KREG_O7) {
			if (RS1(instr) == KREG_G0)
				return (set_errno(EAGAIN));

			(void) kmdb_dpi_get_register(regno2name(RS2(instr)),
			    &reg);
		} else
			(void) kmdb_dpi_get_register("o7", &reg);

		*p = reg + 2 * sizeof (mdb_instr_t);

		return (0);
	}

	return (set_errno(EAGAIN));
}

const char *
kmt_trapname(int trapnum)
{
	static char trapname[11];

	switch (trapnum) {
	case T_INSTR_EXCEPTION:
		return ("instruction access error trap");
	case T_ALIGNMENT:
		return ("improper alignment trap");
	case T_UNIMP_INSTR:
		return ("illegal instruction trap");
	case T_IDIV0:
		return ("division by zero trap");
	case T_FAST_INSTR_MMU_MISS:
		return ("instruction access MMU miss trap");
	case T_FAST_DATA_MMU_MISS:
		return ("data access MMU miss trap");
	case ST_KMDB_TRAP|T_SOFTWARE_TRAP:
		return ("debugger entry trap");
	case ST_KMDB_BREAKPOINT|T_SOFTWARE_TRAP:
		return ("breakpoint trap");
	default:
		(void) mdb_snprintf(trapname, sizeof (trapname), "trap %#x",
		    trapnum);
		return (trapname);
	}
}

void
kmt_init_isadep(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;

	kmt->kmt_rds = mdb_sparcv9_kregs;

	kmt->kmt_trapmax = KMT_MAXTRAPNO;
	kmt->kmt_trapmap = mdb_zalloc(BT_SIZEOFMAP(kmt->kmt_trapmax), UM_SLEEP);

	/* Traps for which we want to provide an explicit message */
	(void) mdb_tgt_add_fault(t, T_INSTR_EXCEPTION, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_ALIGNMENT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_UNIMP_INSTR, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_IDIV0, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_FAST_INSTR_MMU_MISS,
	    MDB_TGT_SPEC_INTERNAL, no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_FAST_DATA_MMU_MISS, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);

	/*
	 * Traps which will be handled elsewhere, and which therefore don't
	 * need the trap-based message.
	 */
	BT_SET(kmt->kmt_trapmap, ST_KMDB_TRAP|T_SOFTWARE_TRAP);
	BT_SET(kmt->kmt_trapmap, ST_KMDB_BREAKPOINT|T_SOFTWARE_TRAP);
	BT_SET(kmt->kmt_trapmap, T_PA_WATCHPOINT);
	BT_SET(kmt->kmt_trapmap, T_VA_WATCHPOINT);

	/* Catch-all for traps not explicitly listed here */
	(void) mdb_tgt_add_fault(t, KMT_TRAP_NOTENUM, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
}

/*ARGSUSED*/
void
kmt_startup_isadep(mdb_tgt_t *t)
{
}
