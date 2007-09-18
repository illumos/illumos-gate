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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/machsystm.h>
#include <sys/cpu_module.h>
#include <sys/panic.h>
#include <sys/uadmin.h>
#include <sys/kobj.h>
#include <sys/contract/process_impl.h>
#include <vm/hat_sfmmu.h>
#include <sys/reboot.h>

#ifdef  TRAPTRACE
#include <sys/traptrace.h>
#endif

void showregs(unsigned, struct regs *, caddr_t, uint_t);

extern int tudebug;

void
mmu_print_sfsr(uint_t sfsr)
{
	printf("MMU sfsr=%x:", sfsr);
	switch (X_FAULT_TYPE(sfsr)) {
	case FT_NONE:
		printf(" No error");
		break;
	case FT_PRIV:
		printf(" Privilege violation");
		break;
	case FT_SPEC_LD:
		printf(" Speculative load on E-bit page");
		break;
	case FT_ATOMIC_NC:
		printf(" Atomic to uncacheable page");
		break;
	case FT_ILL_ALT:
		printf(" Illegal lda or sta");
		break;
	case FT_NFO:
		printf(" Normal access to NFO page");
		break;
	case FT_RANGE:
		printf(" Data or instruction address out of range");
		break;
	default:
		printf(" Unknown error");
		break;
	}

	printf(" context 0x%x", X_FAULT_CTX(sfsr));
	printf("\n");
}


/*
 * Handle an asynchronous hardware error, i.e. an E-$ parity error.
 * The policy is currently to send a hardware error contract event to
 * the process's process contract and to kill the process.  Eventually
 * we may want to instead send a special signal whose default
 * disposition is to generate the contract event.
 */
void
trap_async_hwerr(void)
{
	k_siginfo_t si;
	proc_t *p = ttoproc(curthread);

	errorq_drain(ue_queue); /* flush pending async error messages */

	contract_process_hwerr(p->p_ct_process, p);

	bzero(&si, sizeof (k_siginfo_t));
	si.si_signo = SIGKILL;
	si.si_code = SI_NOINFO;
	trapsig(&si, 1);
}

/*
 * Handle bus error and bus timeout for a user process by sending SIGBUS
 * The type is either ASYNC_BERR or ASYNC_BTO.
 */
void
trap_async_berr_bto(int type, struct regs *rp)
{
	k_siginfo_t si;

	errorq_drain(ue_queue); /* flush pending async error messages */
	bzero(&si, sizeof (k_siginfo_t));

	si.si_signo = SIGBUS;
	si.si_code = (type == ASYNC_BERR ? BUS_OBJERR : BUS_ADRERR);
	si.si_addr = (caddr_t)rp->r_pc; /* AFAR unavailable - future RFE */
	si.si_errno = ENXIO;

	trapsig(&si, 1);
}

/*
 * Print out debugging info.
 */
/*ARGSUSED*/
void
showregs(uint_t type, struct regs *rp, caddr_t addr, uint_t mmu_fsr)
{
	int s;

	s = spl7();
	type &= ~T_USER;
	printf("%s: ", PTOU(curproc)->u_comm);

	switch (type) {
	case T_SYS_RTT_ALIGN:
	case T_ALIGNMENT:
		printf("alignment error:\n");
		break;
	case T_INSTR_EXCEPTION:
		printf("text access exception:\n");
		break;
	case T_DATA_EXCEPTION:
		printf("data access exception:\n");
		break;
	case T_PRIV_INSTR:
		printf("privileged instruction fault:\n");
		break;
	case T_UNIMP_INSTR:
		printf("illegal instruction fault:\n");
		break;
	case T_IDIV0:
		printf("integer divide zero trap:\n");
		break;
	case T_DIV0:
		printf("zero divide trap:\n");
		break;
	case T_INT_OVERFLOW:
		printf("integer overflow:\n");
		break;
	case T_BREAKPOINT:
		printf("breakpoint trap:\n");
		break;
	case T_TAG_OVERFLOW:
		printf("tag overflow:\n");
		break;
	default:
		if (type >= T_SOFTWARE_TRAP && type <= T_ESOFTWARE_TRAP)
			printf("software trap 0x%x\n", type - T_SOFTWARE_TRAP);
		else
			printf("trap type = 0x%x\n", type);
		break;
	}
	if (type == T_DATA_EXCEPTION || type == T_INSTR_EXCEPTION) {
		mmu_print_sfsr(mmu_fsr);
	} else if (addr) {
		printf("addr=0x%p\n", (void *)addr);
	}

	printf("pid=%d, pc=0x%lx, sp=0x%llx, tstate=0x%llx, context=0x%x\n",
	    (ttoproc(curthread) && ttoproc(curthread)->p_pidp) ?
	    (ttoproc(curthread)->p_pid) : 0, rp->r_pc, rp->r_sp,
	    rp->r_tstate, sfmmu_getctx_sec());
	if (USERMODE(rp->r_tstate)) {
		printf("o0-o7: %llx, %llx, %llx, %llx, %llx, %llx, "
		    "%llx, %llx\n", rp->r_o0, rp->r_o1, rp->r_o2, rp->r_o3,
		    rp->r_o4, rp->r_o5, rp->r_o6, rp->r_o7);
	}
	printf("g1-g7: %llx, %llx, %llx, %llx, %llx, %llx, %llx\n",
	    rp->r_g1, rp->r_g2, rp->r_g3,
	    rp->r_g4, rp->r_g5, rp->r_g6, rp->r_g7);

	if (tudebug > 1 && (boothowto & RB_DEBUG)) {
		debug_enter((char *)NULL);
	}
	splx(s);
}

static void
ptl1_showtrap(ptl1_state_t *pstate)
{
	ptl1_regs_t *rp = &pstate->ptl1_regs;
	short i, j, maxtl = rp->ptl1_trap_regs[0].ptl1_tl;
	short curgl = rp->ptl1_gregs[0].ptl1_gl;

	printf("%%tl %%tpc              %%tnpc             %%tstate"
	    "           %%tt\n");

	for (i = maxtl - 1; i >= 0; i--) {
		ptl1_trapregs_t *ptp = &rp->ptl1_trap_regs[i];
		uint64_t tstate = ptp->ptl1_tstate;
		uint32_t gl, ccr, asi, cwp, pstate;

		cwp = (tstate >> TSTATE_CWP_SHIFT) & TSTATE_CWP_MASK;
		pstate = (tstate >> TSTATE_PSTATE_SHIFT) & TSTATE_PSTATE_MASK;
		asi = (tstate >> TSTATE_ASI_SHIFT) & TSTATE_ASI_MASK;
		ccr = (tstate >> TSTATE_CCR_SHIFT) & TSTATE_CCR_MASK;
		gl = (tstate >> TSTATE_GL_SHIFT) & TSTATE_GL_MASK;

		printf(" %d  %016" PRIx64 "  %016" PRIx64 "  %010" PRIx64
		    "        %03x\n", ptp->ptl1_tl, ptp->ptl1_tpc,
		    ptp->ptl1_tnpc, tstate, ptp->ptl1_tt);
		printf("    %%gl: %02x  %%ccr: %02x  %%asi: %02x  %%cwp: %x  "
		    "%%pstate: %b\n", gl, ccr, asi, cwp, pstate, PSTATE_BITS);
	}

	/*
	 * ptl1_gregs[] array holds global registers for GL 0 through
	 * current GL. Note that the current GL global registers are
	 * always stored at index 0 in the ptl1_gregs[] array.
	 */
	for (i = 0; i <= curgl; i++) {
		ptl1_gregs_t *pgp = &rp->ptl1_gregs[i];

		printf("    %%gl: %02" PRIx64 "\n", pgp->ptl1_gl);
		printf("%%g0-3: %016x %016" PRIx64 " %016" PRIx64 " %016"
		    PRIx64 "\n", 0, pgp->ptl1_g1, pgp->ptl1_g2, pgp->ptl1_g3);
		printf("%%g4-7: %016" PRIx64 " %016" PRIx64 " %016"
		    PRIx64 " %016" PRIx64 "\n", pgp->ptl1_g4, pgp->ptl1_g5,
		    pgp->ptl1_g6, pgp->ptl1_g7);
	}

	i = rp->ptl1_cwp;
	j = rp->ptl1_canrestore;
	for (; j >= 0; i--, j--) {
		struct rwindow *wp;
		ulong_t off;
		char *sym;

		if (i < 0)
			i += MAXWIN;

		wp = &rp->ptl1_rwindow[i];

		if ((sym = kobj_getsymname(wp->rw_in[7], &off)) != NULL) {
			printf("Register window %d, caller %s+%lx\n",
			    i, sym, off);
		} else {
			printf("Register window %d, caller %lx\n",
			    i, wp->rw_in[7]);
		}

		if (i == rp->ptl1_cwp) {
			struct rwindow *nwp;

			if (i == MAXWIN - 1)
				nwp = &rp->ptl1_rwindow[0];
			else
				nwp = &rp->ptl1_rwindow[i+1];
			printf("%%o0-3: %016lx %016lx %016lx %016lx\n"
			    "%%o4-7: %016lx %016lx %016lx %016lx\n",
			    nwp->rw_in[0], nwp->rw_in[1], nwp->rw_in[2],
			    nwp->rw_in[3], nwp->rw_in[4], nwp->rw_in[5],
			    nwp->rw_in[6], nwp->rw_in[7]);
		}
		printf("%%l0-3: %016lx %016lx %016lx %016lx\n"
		    "%%l4-7: %016lx %016lx %016lx %016lx\n",
		    wp->rw_local[0], wp->rw_local[1], wp->rw_local[2],
		    wp->rw_local[3], wp->rw_local[4], wp->rw_local[5],
		    wp->rw_local[6], wp->rw_local[7]);

		printf("%%i0-3: %016lx %016lx %016lx %016lx\n"
		    "%%i4-7: %016lx %016lx %016lx %016lx\n",
		    wp->rw_in[0], wp->rw_in[1], wp->rw_in[2], wp->rw_in[3],
		    wp->rw_in[4], wp->rw_in[5], wp->rw_in[6], wp->rw_in[7]);
	}
}

void
panic_showtrap(struct panic_trap_info *tip)
{
	ptl1_state_t *pstate = &CPU->cpu_m.ptl1_state;
	/*
	 * If ptl1_panic() was called, print out the information
	 * saved in the ptl1_state struture.
	 */
	if (pstate->ptl1_entry_count) {
		ptl1_showtrap(pstate);
		return;
	}

	showregs(tip->trap_type, tip->trap_regs, tip->trap_addr,
	    tip->trap_mmu_fsr);
}

static void
ptl1_savetrap(panic_data_t *pdp, ptl1_state_t *pstate)
{
	ptl1_regs_t *rp = &pstate->ptl1_regs;
	short i, maxtl = rp->ptl1_trap_regs[0].ptl1_tl;
	panic_nv_t *pnv = PANICNVGET(pdp);
	char name[PANICNVNAMELEN];

	for (i = maxtl - 1; i >= 0; i--) {
		ptl1_trapregs_t *ptp = &rp->ptl1_trap_regs[i];

		(void) snprintf(name, sizeof (name), "tl[%d]", i);
		PANICNVADD(pnv, name, ptp->ptl1_tl);
		(void) snprintf(name, sizeof (name), "tt[%d]", i);
		PANICNVADD(pnv, name, ptp->ptl1_tt);
		(void) snprintf(name, sizeof (name), "tpc[%d]", i);
		PANICNVADD(pnv, name, ptp->ptl1_tpc);
		(void) snprintf(name, sizeof (name), "tnpc[%d]", i);
		PANICNVADD(pnv, name, ptp->ptl1_tnpc);
		(void) snprintf(name, sizeof (name), "tstate[%d]", i);
		PANICNVADD(pnv, name, ptp->ptl1_tstate);
	}

	PANICNVSET(pdp, pnv);
}

void
panic_savetrap(panic_data_t *pdp, struct panic_trap_info *tip)
{
	panic_nv_t *pnv;
	ptl1_state_t *pstate = &CPU->cpu_m.ptl1_state;
	/*
	 * If ptl1_panic() was called, save the trap registers
	 * stored in the ptl1_state struture.
	 */
	if (pstate->ptl1_entry_count) {
		ptl1_savetrap(pdp, pstate);
		return;
	}

	panic_saveregs(pdp, tip->trap_regs);
	pnv = PANICNVGET(pdp);

	PANICNVADD(pnv, "sfsr", tip->trap_mmu_fsr);
	PANICNVADD(pnv, "sfar", tip->trap_addr);
	PANICNVADD(pnv, "tt", tip->trap_type);

	PANICNVSET(pdp, pnv);
}
