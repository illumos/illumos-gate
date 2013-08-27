/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_gcore.h>
#include <mdb/mdb_debug.h>

#include <sys/psw.h>
#include <sys/privregs.h>

uintptr_t
gcore_prgetstackbase(mdb_proc_t *p)
{
	return (p->p_usrstack - p->p_stksize);
}

int
gcore_prfetchinstr(mdb_klwp_t *lwp, ulong_t *ip)
{
	*ip = (ulong_t)(instr_t)lwp->lwp_pcb.pcb_instr;
	return (lwp->lwp_pcb.pcb_flags & INSTR_VALID);
}

int
gcore_prisstep(mdb_klwp_t *lwp)
{
	return ((lwp->lwp_pcb.pcb_flags &
	    (NORMAL_STEP|WATCH_STEP|DEBUG_PENDING)) != 0);
}

void
gcore_getgregs(mdb_klwp_t *lwp, gregset_t grp)
{
	struct regs rgs;
	struct regs *rp;

	if (mdb_vread(&rgs, sizeof (rgs), lwp->lwp_regs) != sizeof (rgs)) {
		mdb_warn("Failed to read regs from %p\n", lwp->lwp_regs);
		return;
	}
	rp = &rgs;

#if defined(__amd64)
	struct pcb *pcb = &lwp->lwp_pcb;

	grp[REG_RDI] = rp->r_rdi;
	grp[REG_RSI] = rp->r_rsi;
	grp[REG_RDX] = rp->r_rdx;
	grp[REG_RCX] = rp->r_rcx;
	grp[REG_R8] = rp->r_r8;
	grp[REG_R9] = rp->r_r9;
	grp[REG_RAX] = rp->r_rax;
	grp[REG_RBX] = rp->r_rbx;
	grp[REG_RBP] = rp->r_rbp;
	grp[REG_R10] = rp->r_r10;
	grp[REG_R11] = rp->r_r11;
	grp[REG_R12] = rp->r_r12;
	grp[REG_R13] = rp->r_r13;
	grp[REG_R14] = rp->r_r14;
	grp[REG_R15] = rp->r_r15;
	grp[REG_FSBASE] = pcb->pcb_fsbase;
	grp[REG_GSBASE] = pcb->pcb_gsbase;
	if (pcb->pcb_rupdate == 1) {
		grp[REG_DS] = pcb->pcb_ds;
		grp[REG_ES] = pcb->pcb_es;
		grp[REG_FS] = pcb->pcb_fs;
		grp[REG_GS] = pcb->pcb_gs;
	} else {
		grp[REG_DS] = rp->r_ds;
		grp[REG_ES] = rp->r_es;
		grp[REG_FS] = rp->r_fs;
		grp[REG_GS] = rp->r_gs;
	}
	grp[REG_TRAPNO] = rp->r_trapno;
	grp[REG_ERR] = rp->r_err;
	grp[REG_RIP] = rp->r_rip;
	grp[REG_CS] = rp->r_cs;
	grp[REG_SS] = rp->r_ss;
	grp[REG_RFL] = rp->r_rfl;
	grp[REG_RSP] = rp->r_rsp;
#else
	bcopy(&rp->r_gs, grp, sizeof (gregset_t));
#endif
}

int
gcore_prgetrvals(mdb_klwp_t *lwp, long *rval1, long *rval2)
{
	struct regs *r = lwptoregs(lwp);

	if (r->r_ps & PS_C)
		return (r->r_r0);
	if (lwp->lwp_eosys == JUSTRETURN) {
		*rval1 = 0;
		*rval2 = 0;
	} else {
		*rval1 = r->r_r0;
		*rval2 = r->r_r1;
	}
	return (0);
}
