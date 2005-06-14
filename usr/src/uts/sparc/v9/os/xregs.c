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
 * Copyright 1994-1998,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/klwp.h>
#include <sys/ucontext.h>
#include <sys/procfs.h>
#include <sys/privregs.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/fpu/fpusystm.h>

/*
 * Association of extra register state with a struct ucontext is
 * done by placing an xrs_t within the uc_mcontext filler area.
 *
 * The following routines provide an interface for this association.
 */

/*
 * clear the struct ucontext extra register state pointer
 */
/* ARGSUSED */
void
xregs_clrptr(klwp_id_t lwp, ucontext_t *uc)
{
	uc->uc_mcontext.xrs.xrs_id = 0;
	uc->uc_mcontext.xrs.xrs_ptr = NULL;
}

/*
 * indicate whether or not an extra register state
 * pointer is associated with a struct ucontext
 */
/* ARGSUSED */
int
xregs_hasptr(klwp_id_t lwp, ucontext_t *uc)
{
	return (uc->uc_mcontext.xrs.xrs_id == XRS_ID);
}

/*
 * get the struct ucontext extra register state pointer field
 */
/* ARGSUSED */
caddr_t
xregs_getptr(klwp_id_t lwp, ucontext_t *uc)
{
	if (uc->uc_mcontext.xrs.xrs_id == XRS_ID)
		return (uc->uc_mcontext.xrs.xrs_ptr);
	return (NULL);
}

/*
 * set the struct ucontext extra register state pointer field
 */
/* ARGSUSED */
void
xregs_setptr(klwp_id_t lwp, ucontext_t *uc, caddr_t xrp)
{
	uc->uc_mcontext.xrs.xrs_id = XRS_ID;
	uc->uc_mcontext.xrs.xrs_ptr = xrp;
}

#ifdef _SYSCALL32_IMPL

/* ARGSUSED */
void
xregs_clrptr32(klwp_id_t lwp, ucontext32_t *uc)
{
	uc->uc_mcontext.xrs.xrs_id = 0;
	uc->uc_mcontext.xrs.xrs_ptr = 0;
}

/* ARGSUSED */
int
xregs_hasptr32(klwp_id_t lwp, ucontext32_t *uc)
{
	return (uc->uc_mcontext.xrs.xrs_id == XRS_ID);
}

/* ARGSUSED */
caddr32_t
xregs_getptr32(klwp_id_t lwp, ucontext32_t *uc)
{
	if (uc->uc_mcontext.xrs.xrs_id == XRS_ID)
		return (uc->uc_mcontext.xrs.xrs_ptr);
	return (0);
}

/* ARGSUSED */
void
xregs_setptr32(klwp_id_t lwp, ucontext32_t *uc, caddr32_t xrp)
{
	uc->uc_mcontext.xrs.xrs_id = XRS_ID;
	uc->uc_mcontext.xrs.xrs_ptr = xrp;
}

#endif /* _SYSCALL32_IMPL */

/*
 * Extra register state manipulation routines.
 * NOTE:  'lwp' might not correspond to 'curthread' in any of the
 * functions below since they are called from code in /proc to get
 * or set the extra registers of another lwp.
 */

int xregs_exists = 1;

#define	GET_UPPER_32(all)		(uint32_t)((uint64_t)(all) >> 32)
#define	SET_ALL_64(upper, lower)	\
		(((uint64_t)(upper) << 32) | (uint32_t)(lower))


/*
 * fill in the extra register state area specified with the
 * specified lwp's non-floating-point extra register state
 * information
 */
void
xregs_getgregs(klwp_id_t lwp, caddr_t xrp)
{
	prxregset_t *xregs = (prxregset_t *)xrp;
	struct regs *rp = lwptoregs(lwp);

	if (xregs == NULL)
		return;

	xregs->pr_type = XR_TYPE_V8P;

	xregs->pr_un.pr_v8p.pr_xg[XR_G0] = 0;
	xregs->pr_un.pr_v8p.pr_xg[XR_G1] = GET_UPPER_32(rp->r_g1);
	xregs->pr_un.pr_v8p.pr_xg[XR_G2] = GET_UPPER_32(rp->r_g2);
	xregs->pr_un.pr_v8p.pr_xg[XR_G3] = GET_UPPER_32(rp->r_g3);
	xregs->pr_un.pr_v8p.pr_xg[XR_G4] = GET_UPPER_32(rp->r_g4);
	xregs->pr_un.pr_v8p.pr_xg[XR_G5] = GET_UPPER_32(rp->r_g5);
	xregs->pr_un.pr_v8p.pr_xg[XR_G6] = GET_UPPER_32(rp->r_g6);
	xregs->pr_un.pr_v8p.pr_xg[XR_G7] = GET_UPPER_32(rp->r_g7);

	xregs->pr_un.pr_v8p.pr_xo[XR_O0] = GET_UPPER_32(rp->r_o0);
	xregs->pr_un.pr_v8p.pr_xo[XR_O1] = GET_UPPER_32(rp->r_o1);
	xregs->pr_un.pr_v8p.pr_xo[XR_O2] = GET_UPPER_32(rp->r_o2);
	xregs->pr_un.pr_v8p.pr_xo[XR_O3] = GET_UPPER_32(rp->r_o3);
	xregs->pr_un.pr_v8p.pr_xo[XR_O4] = GET_UPPER_32(rp->r_o4);
	xregs->pr_un.pr_v8p.pr_xo[XR_O5] = GET_UPPER_32(rp->r_o5);
	xregs->pr_un.pr_v8p.pr_xo[XR_O6] = GET_UPPER_32(rp->r_o6);
	xregs->pr_un.pr_v8p.pr_xo[XR_O7] = GET_UPPER_32(rp->r_o7);

	xregs->pr_un.pr_v8p.pr_tstate = rp->r_tstate;

	xregs_getgfiller(lwp, xrp);
}

/*
 * fill in the extra register state area specified with the
 * specified lwp's floating-point extra register state information
 */
void
xregs_getfpregs(klwp_id_t lwp, caddr_t xrp)
{
	prxregset_t *xregs = (prxregset_t *)xrp;
	kfpu_t *fp = lwptofpu(lwp);

	if (xregs == NULL)
		return;

	kpreempt_disable();

	xregs->pr_type = XR_TYPE_V8P;

	if (ttolwp(curthread) == lwp)
		fp->fpu_fprs = _fp_read_fprs();
	if ((fp->fpu_en) || (fp->fpu_fprs & FPRS_FEF)) {
		/*
		 * If we have an fpu and the current thread owns the fp
		 * context, flush fp registers into the pcb.
		 */
		if (fpu_exists && (ttolwp(curthread) == lwp)) {
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);

				_fp_write_fprs(fprs);
				fp->fpu_fprs = fprs;
#ifdef DEBUG
				if (fpdispr) {
					cmn_err(CE_NOTE, "xregs_getfpregs "
					    "with fp disabled!");
				}
#endif /* DEBUG */
			}
			fp_v8p_fksave(fp);
		}
		(void) kcopy(&fp->fpu_fr.fpu_dregs[16],
		    &xregs->pr_un.pr_v8p.pr_xfr,
		    sizeof (xregs->pr_un.pr_v8p.pr_xfr));
		xregs->pr_un.pr_v8p.pr_xfsr = GET_UPPER_32(fp->fpu_fsr);
		xregs->pr_un.pr_v8p.pr_fprs = fp->fpu_fprs;

		xregs_getfpfiller(lwp, xrp);
	} else {
		int i;
		for (i = 0; i < 32; i++)			/* Nan */
			xregs->pr_un.pr_v8p.pr_xfr.pr_regs[i] = (uint32_t)-1;
	}

	kpreempt_enable();
}

/*
 * fill in the extra register state area specified with
 * the specified lwp's extra register state information
 */
void
xregs_get(klwp_id_t lwp, caddr_t xrp)
{
	if (xrp != NULL) {
		bzero(xrp, sizeof (prxregset_t));
		xregs_getgregs(lwp, xrp);
		xregs_getfpregs(lwp, xrp);
	}
}

/*
 * set the specified lwp's non-floating-point extra
 * register state based on the specified input
 */
void
xregs_setgregs(klwp_id_t lwp, caddr_t xrp)
{
	prxregset_t *xregs = (prxregset_t *)xrp;
	struct regs *rp = lwptoregs(lwp);
	int current = (lwp == curthread->t_lwp);

	if (xregs == NULL)
		return;

#ifdef DEBUG
	if (xregs->pr_type != XR_TYPE_V8P) {
		cmn_err(CE_WARN,
		    "xregs_setgregs: pr_type is %d and should be %d",
		    xregs->pr_type, XR_TYPE_V8P);
	}
#endif /* DEBUG */

	if (current) {
		/*
		 * copy the args from the regs first
		 */
		(void) save_syscall_args();
	}

	rp->r_g1 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G1], rp->r_g1);
	rp->r_g2 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G2], rp->r_g2);
	rp->r_g3 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G3], rp->r_g3);
	rp->r_g4 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G4], rp->r_g4);
	rp->r_g5 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G5], rp->r_g5);
	rp->r_g6 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G6], rp->r_g6);
	rp->r_g7 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xg[XR_G7], rp->r_g7);

	rp->r_o0 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O0], rp->r_o0);
	rp->r_o1 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O1], rp->r_o1);
	rp->r_o2 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O2], rp->r_o2);
	rp->r_o3 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O3], rp->r_o3);
	rp->r_o4 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O4], rp->r_o4);
	rp->r_o5 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O5], rp->r_o5);
	rp->r_o6 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O6], rp->r_o6);
	rp->r_o7 = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xo[XR_O7], rp->r_o7);

	rp->r_tstate &= ~((uint64_t)CCR_XCC << TSTATE_CCR_SHIFT);
	rp->r_tstate |= xregs->pr_un.pr_v8p.pr_tstate &
	    ((uint64_t)CCR_XCC << TSTATE_CCR_SHIFT);
	rp->r_tstate &= ~((uint64_t)TSTATE_ASI_MASK << TSTATE_ASI_SHIFT);
	rp->r_tstate |= xregs->pr_un.pr_v8p.pr_tstate &
	    ((uint64_t)TSTATE_ASI_MASK << TSTATE_ASI_SHIFT);

	xregs_setgfiller(lwp, xrp);

	if (current) {
		/*
		 * This was called from a system call, but we
		 * do not want to return via the shared window;
		 * restoring the CPU context changes everything.
		 */
		lwp->lwp_eosys = JUSTRETURN;
		curthread->t_post_sys = 1;
	}
}

/*
 * set the specified lwp's floating-point extra
 * register state based on the specified input
 */
void
xregs_setfpregs(klwp_id_t lwp, caddr_t xrp)
{
	prxregset_t *xregs = (prxregset_t *)xrp;
	kfpu_t *fp = lwptofpu(lwp);

	if (xregs == NULL)
		return;

#ifdef DEBUG
	if (xregs->pr_type != XR_TYPE_V8P) {
		cmn_err(CE_WARN,
		    "xregs_setfpregs: pr_type is %d and should be %d",
		    xregs->pr_type, XR_TYPE_V8P);
	}
#endif /* DEBUG */
	if ((fp->fpu_en) || (xregs->pr_un.pr_v8p.pr_fprs & FPRS_FEF)) {
		kpreempt_disable();
		(void) kcopy(&xregs->pr_un.pr_v8p.pr_xfr,
		    &fp->fpu_fr.fpu_dregs[16],
		    sizeof (xregs->pr_un.pr_v8p.pr_xfr));
		fp->fpu_fprs = xregs->pr_un.pr_v8p.pr_fprs;
		fp->fpu_fsr = SET_ALL_64(xregs->pr_un.pr_v8p.pr_xfsr,
		    fp->fpu_fsr);

		xregs_setfpfiller(lwp, xrp);

		/*
		 * If not the current lwp then resume() will handle it
		 */
		if (lwp != ttolwp(curthread)) {
			/* force resume to reload fp regs */
			kpreempt_enable();
			return;
		}

		if (fpu_exists) {
			fp->fpu_fprs = _fp_read_fprs();
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);

				_fp_write_fprs(fprs);
				fp->fpu_fprs = (V9_FPU_FPRS_TYPE)fprs;
#ifdef DEBUG
				if (fpdispr) {
					cmn_err(CE_NOTE, "xregs_setfpregs "
					    "with fp disabled!");
				}
#endif /* DEBUG */
			}
			fp_v8p_load(fp);
		}

		kpreempt_enable();
	}
}

/*
 * set the specified lwp's extra register
 * state based on the specified input
 */
void
xregs_set(klwp_id_t lwp, caddr_t xrp)
{
	if (xrp != NULL) {
		xregs_setgregs(lwp, xrp);
		xregs_setfpregs(lwp, xrp);
	}
}

/*
 * return the size of the extra register state
 */
int
xregs_getsize(proc_t *p)
{
	if (!xregs_exists || p->p_model == DATAMODEL_LP64)
		return (0);
	return (sizeof (prxregset_t));
}
