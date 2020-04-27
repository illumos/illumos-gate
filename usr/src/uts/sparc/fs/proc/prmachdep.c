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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pcb.h>
#include <sys/buf.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/cpuvar.h>
#include <sys/copyops.h>
#include <sys/watchpoint.h>

#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/archsystm.h>
#include <sys/cmn_err.h>
#include <sys/stack.h>
#include <sys/machpcb.h>
#include <sys/simulate.h>
#include <sys/fpu/fpusystm.h>

#include <sys/pte.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vmparam.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <vm/page.h>

#include <fs/proc/prdata.h>
#include <v9/sys/psr_compat.h>

int	prnwatch = 10000;	/* maximum number of watched areas */

/*
 * Force a thread into the kernel if it is not already there.
 * This is a no-op on uniprocessors.
 */
/* ARGSUSED */
void
prpokethread(kthread_t *t)
{
	if (t->t_state == TS_ONPROC && t->t_cpu != CPU)
		poke_cpu(t->t_cpu->cpu_id);
}

/*
 * Return general registers.
 */
void
prgetprregs(klwp_t *lwp, prgregset_t prp)
{
	gregset_t gr;

	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	getgregs(lwp, gr);
	bzero(prp, sizeof (prp));

	/*
	 * Can't copy since prgregset_t and gregset_t
	 * use different defines.
	 */
	prp[R_G1] = gr[REG_G1];
	prp[R_G2] = gr[REG_G2];
	prp[R_G3] = gr[REG_G3];
	prp[R_G4] = gr[REG_G4];
	prp[R_G5] = gr[REG_G5];
	prp[R_G6] = gr[REG_G6];
	prp[R_G7] = gr[REG_G7];

	prp[R_O0] = gr[REG_O0];
	prp[R_O1] = gr[REG_O1];
	prp[R_O2] = gr[REG_O2];
	prp[R_O3] = gr[REG_O3];
	prp[R_O4] = gr[REG_O4];
	prp[R_O5] = gr[REG_O5];
	prp[R_O6] = gr[REG_O6];
	prp[R_O7] = gr[REG_O7];

	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE) {
		prp[R_L0] = lwp->lwp_pcb.pcb_xregs.rw_local[0];
		prp[R_L1] = lwp->lwp_pcb.pcb_xregs.rw_local[1];
		prp[R_L2] = lwp->lwp_pcb.pcb_xregs.rw_local[2];
		prp[R_L3] = lwp->lwp_pcb.pcb_xregs.rw_local[3];
		prp[R_L4] = lwp->lwp_pcb.pcb_xregs.rw_local[4];
		prp[R_L5] = lwp->lwp_pcb.pcb_xregs.rw_local[5];
		prp[R_L6] = lwp->lwp_pcb.pcb_xregs.rw_local[6];
		prp[R_L7] = lwp->lwp_pcb.pcb_xregs.rw_local[7];

		prp[R_I0] = lwp->lwp_pcb.pcb_xregs.rw_in[0];
		prp[R_I1] = lwp->lwp_pcb.pcb_xregs.rw_in[1];
		prp[R_I2] = lwp->lwp_pcb.pcb_xregs.rw_in[2];
		prp[R_I3] = lwp->lwp_pcb.pcb_xregs.rw_in[3];
		prp[R_I4] = lwp->lwp_pcb.pcb_xregs.rw_in[4];
		prp[R_I5] = lwp->lwp_pcb.pcb_xregs.rw_in[5];
		prp[R_I6] = lwp->lwp_pcb.pcb_xregs.rw_in[6];
		prp[R_I7] = lwp->lwp_pcb.pcb_xregs.rw_in[7];
	}

	prp[R_CCR] = gr[REG_CCR];
	prp[R_ASI] = gr[REG_ASI];
	prp[R_FPRS] = gr[REG_FPRS];
	prp[R_PC]  = gr[REG_PC];
	prp[R_nPC] = gr[REG_nPC];
	prp[R_Y]   = gr[REG_Y];
}

/*
 * Set general registers.
 */
void
prsetprregs(klwp_t *lwp, prgregset_t prp, int initial)
{
	gregset_t gr;

	gr[REG_G1] = prp[R_G1];
	gr[REG_G2] = prp[R_G2];
	gr[REG_G3] = prp[R_G3];
	gr[REG_G4] = prp[R_G4];
	gr[REG_G5] = prp[R_G5];
	gr[REG_G6] = prp[R_G6];
	gr[REG_G7] = prp[R_G7];

	gr[REG_O0] = prp[R_O0];
	gr[REG_O1] = prp[R_O1];
	gr[REG_O2] = prp[R_O2];
	gr[REG_O3] = prp[R_O3];
	gr[REG_O4] = prp[R_O4];
	gr[REG_O5] = prp[R_O5];
	gr[REG_O6] = prp[R_O6];
	gr[REG_O7] = prp[R_O7];

	lwp->lwp_pcb.pcb_xregs.rw_local[0] = prp[R_L0];
	lwp->lwp_pcb.pcb_xregs.rw_local[1] = prp[R_L1];
	lwp->lwp_pcb.pcb_xregs.rw_local[2] = prp[R_L2];
	lwp->lwp_pcb.pcb_xregs.rw_local[3] = prp[R_L3];
	lwp->lwp_pcb.pcb_xregs.rw_local[4] = prp[R_L4];
	lwp->lwp_pcb.pcb_xregs.rw_local[5] = prp[R_L5];
	lwp->lwp_pcb.pcb_xregs.rw_local[6] = prp[R_L6];
	lwp->lwp_pcb.pcb_xregs.rw_local[7] = prp[R_L7];

	lwp->lwp_pcb.pcb_xregs.rw_in[0] = prp[R_I0];
	lwp->lwp_pcb.pcb_xregs.rw_in[1] = prp[R_I1];
	lwp->lwp_pcb.pcb_xregs.rw_in[2] = prp[R_I2];
	lwp->lwp_pcb.pcb_xregs.rw_in[3] = prp[R_I3];
	lwp->lwp_pcb.pcb_xregs.rw_in[4] = prp[R_I4];
	lwp->lwp_pcb.pcb_xregs.rw_in[5] = prp[R_I5];
	lwp->lwp_pcb.pcb_xregs.rw_in[6] = prp[R_I6];
	lwp->lwp_pcb.pcb_xregs.rw_in[7] = prp[R_I7];

	lwp->lwp_pcb.pcb_xregstat = XREGMODIFIED;
	lwptot(lwp)->t_post_sys = 1;

	/*
	 * setgregs will only allow the condition codes to be set.
	 */
	gr[REG_CCR] = prp[R_CCR];
	gr[REG_ASI] = prp[R_ASI];
	gr[REG_FPRS] = prp[R_FPRS];
	gr[REG_PC]  = prp[R_PC];
	gr[REG_nPC] = prp[R_nPC];
	gr[REG_Y]   = prp[R_Y];

	if (initial) {		/* set initial values */
		if (lwptoproc(lwp)->p_model == DATAMODEL_LP64)
			lwptoregs(lwp)->r_tstate = TSTATE_USER64|TSTATE_MM_TSO;
		else
			lwptoregs(lwp)->r_tstate = TSTATE_USER32|TSTATE_MM_TSO;
		if (!fpu_exists)
			lwptoregs(lwp)->r_tstate &= ~TSTATE_PEF;
	}

	setgregs(lwp, gr);
}

#ifdef _SYSCALL32_IMPL

/*
 * modify the lower 32bits of a uint64_t
 */
#define	SET_LOWER_32(all, lower)	\
	(((uint64_t)(all) & 0xffffffff00000000) | (uint32_t)(lower))

/*
 * Convert prgregset32 to native prgregset.
 */
void
prgregset_32ton(klwp_t *lwp, prgregset32_t src, prgregset_t dest)
{
	struct regs *r = lwptoregs(lwp);

	dest[R_G0] = SET_LOWER_32(0, src[R_G0]);
	dest[R_G1] = SET_LOWER_32(r->r_g1, src[R_G1]);
	dest[R_G2] = SET_LOWER_32(r->r_g2, src[R_G2]);
	dest[R_G3] = SET_LOWER_32(r->r_g3, src[R_G3]);
	dest[R_G4] = SET_LOWER_32(r->r_g4, src[R_G4]);
	dest[R_G5] = SET_LOWER_32(r->r_g5, src[R_G5]);
	dest[R_G6] = SET_LOWER_32(r->r_g6, src[R_G6]);
	dest[R_G7] = SET_LOWER_32(r->r_g7, src[R_G7]);

	dest[R_O0] = SET_LOWER_32(r->r_o0, src[R_O0]);
	dest[R_O1] = SET_LOWER_32(r->r_o1, src[R_O1]);
	dest[R_O2] = SET_LOWER_32(r->r_o2, src[R_O2]);
	dest[R_O3] = SET_LOWER_32(r->r_o3, src[R_O3]);
	dest[R_O4] = SET_LOWER_32(r->r_o4, src[R_O4]);
	dest[R_O5] = SET_LOWER_32(r->r_o5, src[R_O5]);
	dest[R_O6] = SET_LOWER_32(r->r_o6, src[R_O6]);
	dest[R_O7] = SET_LOWER_32(r->r_o7, src[R_O7]);

	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE) {
		struct rwindow *rw = &lwp->lwp_pcb.pcb_xregs;

		dest[R_L0] = SET_LOWER_32(rw->rw_local[0], src[R_L0]);
		dest[R_L1] = SET_LOWER_32(rw->rw_local[1], src[R_L1]);
		dest[R_L2] = SET_LOWER_32(rw->rw_local[2], src[R_L2]);
		dest[R_L3] = SET_LOWER_32(rw->rw_local[3], src[R_L3]);
		dest[R_L4] = SET_LOWER_32(rw->rw_local[4], src[R_L4]);
		dest[R_L5] = SET_LOWER_32(rw->rw_local[5], src[R_L5]);
		dest[R_L6] = SET_LOWER_32(rw->rw_local[6], src[R_L6]);
		dest[R_L7] = SET_LOWER_32(rw->rw_local[7], src[R_L7]);

		dest[R_I0] = SET_LOWER_32(rw->rw_in[0], src[R_I0]);
		dest[R_I1] = SET_LOWER_32(rw->rw_in[1], src[R_I1]);
		dest[R_I2] = SET_LOWER_32(rw->rw_in[2], src[R_I2]);
		dest[R_I3] = SET_LOWER_32(rw->rw_in[3], src[R_I3]);
		dest[R_I4] = SET_LOWER_32(rw->rw_in[4], src[R_I4]);
		dest[R_I5] = SET_LOWER_32(rw->rw_in[5], src[R_I5]);
		dest[R_I6] = SET_LOWER_32(rw->rw_in[6], src[R_I6]);
		dest[R_I7] = SET_LOWER_32(rw->rw_in[7], src[R_I7]);
	} else {
		dest[R_L0] = (uint32_t)src[R_L0];
		dest[R_L1] = (uint32_t)src[R_L1];
		dest[R_L2] = (uint32_t)src[R_L2];
		dest[R_L3] = (uint32_t)src[R_L3];
		dest[R_L4] = (uint32_t)src[R_L4];
		dest[R_L5] = (uint32_t)src[R_L5];
		dest[R_L6] = (uint32_t)src[R_L6];
		dest[R_L7] = (uint32_t)src[R_L7];

		dest[R_I0] = (uint32_t)src[R_I0];
		dest[R_I1] = (uint32_t)src[R_I1];
		dest[R_I2] = (uint32_t)src[R_I2];
		dest[R_I3] = (uint32_t)src[R_I3];
		dest[R_I4] = (uint32_t)src[R_I4];
		dest[R_I5] = (uint32_t)src[R_I5];
		dest[R_I6] = (uint32_t)src[R_I6];
		dest[R_I7] = (uint32_t)src[R_I7];
	}

	dest[R_CCR] = ((r->r_tstate >> TSTATE_CCR_SHIFT) & CCR_XCC) |
	    ((src[R_PSR] >> (TSTATE_CCR_SHIFT-PSR_TSTATE_CC_SHIFT)) & CCR_ICC);

	dest[R_PC] = SET_LOWER_32(r->r_pc, src[R_PC]);
	dest[R_nPC] = SET_LOWER_32(r->r_npc, src[R_nPC]);
	dest[R_Y] = (uint32_t)src[R_Y];

	dest[R_ASI] = (r->r_tstate >> TSTATE_ASI_SHIFT) & TSTATE_ASI_MASK;
	dest[R_FPRS] = lwptofpu(lwp)->fpu_fprs;
}

/*
 * Return 32-bit general registers.
 */

/* conversion from 64-bit register to 32-bit register */
#define	R32(r)	(prgreg32_t)(uint32_t)(r)

void
prgetprregs32(klwp_t *lwp, prgregset32_t prp)
{
	gregset32_t gr;

	extern void getgregs32(klwp_t *, gregset32_t);

	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	getgregs32(lwp, gr);
	bzero(prp, sizeof (prp));

	/*
	 * Can't copy since prgregset_t and gregset_t
	 * use different defines.
	 */
	prp[R_G1] = gr[REG_G1];
	prp[R_G2] = gr[REG_G2];
	prp[R_G3] = gr[REG_G3];
	prp[R_G4] = gr[REG_G4];
	prp[R_G5] = gr[REG_G5];
	prp[R_G6] = gr[REG_G6];
	prp[R_G7] = gr[REG_G7];

	prp[R_O0] = gr[REG_O0];
	prp[R_O1] = gr[REG_O1];
	prp[R_O2] = gr[REG_O2];
	prp[R_O3] = gr[REG_O3];
	prp[R_O4] = gr[REG_O4];
	prp[R_O5] = gr[REG_O5];
	prp[R_O6] = gr[REG_O6];
	prp[R_O7] = gr[REG_O7];

	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE) {
		prp[R_L0] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[0]);
		prp[R_L1] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[1]);
		prp[R_L2] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[2]);
		prp[R_L3] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[3]);
		prp[R_L4] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[4]);
		prp[R_L5] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[5]);
		prp[R_L6] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[6]);
		prp[R_L7] = R32(lwp->lwp_pcb.pcb_xregs.rw_local[7]);

		prp[R_I0] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[0]);
		prp[R_I1] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[1]);
		prp[R_I2] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[2]);
		prp[R_I3] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[3]);
		prp[R_I4] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[4]);
		prp[R_I5] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[5]);
		prp[R_I6] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[6]);
		prp[R_I7] = R32(lwp->lwp_pcb.pcb_xregs.rw_in[7]);
	}

	prp[R_PSR] = gr[REG_PSR];
	prp[R_PC]  = gr[REG_PC];
	prp[R_nPC] = gr[REG_nPC];
	prp[R_Y]   = gr[REG_Y];
}

#endif	/* _SYSCALL32_IMPL */

/*
 * Get the syscall return values for the lwp.
 */
int
prgetrvals(klwp_t *lwp, long *rval1, long *rval2)
{
	struct regs *r = lwptoregs(lwp);

	if (r->r_tstate & TSTATE_IC)
		return ((int)r->r_o0);
	if (lwp->lwp_eosys == JUSTRETURN) {
		*rval1 = 0;
		*rval2 = 0;
	} else if (lwptoproc(lwp)->p_model == DATAMODEL_ILP32) {
		*rval1 = r->r_o0 & (uint32_t)0xffffffffU;
		*rval2 = r->r_o1 & (uint32_t)0xffffffffU;
	} else {
		*rval1 = r->r_o0;
		*rval2 = r->r_o1;
	}
	return (0);
}

/*
 * Does the system support floating-point, either through hardware
 * or by trapping and emulating floating-point machine instructions?
 */
int
prhasfp(void)
{
	/*
	 * SunOS5.0 emulates floating-point if FP hardware is not present.
	 */
	return (1);
}

/*
 * Get floating-point registers.
 */
void
prgetprfpregs(klwp_t *lwp, prfpregset_t *pfp)
{
	bzero(pfp, sizeof (*pfp));
	/*
	 * This works only because prfpregset_t is intentionally
	 * constructed to be identical to fpregset_t, with additional
	 * space for the floating-point queue at the end.
	 */
	getfpregs(lwp, (fpregset_t *)pfp);
	/*
	 * This is supposed to be a pointer to the floating point queue.
	 * We can't provide such a thing through the /proc interface.
	 */
	pfp->pr_filler = 0;
	/*
	 * XXX: to be done: fetch the FP queue if it is non-empty.
	 */
}

#ifdef	_SYSCALL32_IMPL
void
prgetprfpregs32(klwp_t *lwp, prfpregset32_t *pfp)
{
	bzero(pfp, sizeof (*pfp));
	/*
	 * This works only because prfpregset32_t is intentionally
	 * constructed to be identical to fpregset32_t, with additional
	 * space for the floating-point queue at the end.
	 */
	getfpregs32(lwp, (fpregset32_t *)pfp);
	/*
	 * This is supposed to be a pointer to the floating point queue.
	 * We can't provide such a thing through the /proc interface.
	 */
	pfp->pr_filler = 0;
	/*
	 * XXX: to be done: fetch the FP queue if it is non-empty.
	 */
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Set floating-point registers.
 */
void
prsetprfpregs(klwp_t *lwp, prfpregset_t *pfp)
{
	/*
	 * XXX: to be done: store the FP queue if it is non-empty.
	 */
	pfp->pr_qcnt = 0;
	/*
	 * We set fpu_en before calling setfpregs() in order to
	 * retain the semantics of this operation from older
	 * versions of the system.  SunOS 5.4 and prior never
	 * queried fpu_en; they just set the registers.  The
	 * proper operation if fpu_en is zero is to disable
	 * floating point in the target process, but this can
	 * only change after a proper end-of-life period for
	 * the old semantics.
	 */
	pfp->pr_en = 1;
	/*
	 * This works only because prfpregset_t is intentionally
	 * constructed to be identical to fpregset_t, with additional
	 * space for the floating-point queue at the end.
	 */
	setfpregs(lwp, (fpregset_t *)pfp);
}

#ifdef	_SYSCALL32_IMPL
void
prsetprfpregs32(klwp_t *lwp, prfpregset32_t *pfp)
{
	/*
	 * XXX: to be done: store the FP queue if it is non-empty.
	 */
	pfp->pr_qcnt = 0;
	/*
	 * We set fpu_en before calling setfpregs() in order to
	 * retain the semantics of this operation from older
	 * versions of the system.  SunOS 5.4 and prior never
	 * queried fpu_en; they just set the registers.  The
	 * proper operation if fpu_en is zero is to disable
	 * floating point in the target process, but this can
	 * only change after a proper end-of-life period for
	 * the old semantics.
	 */
	pfp->pr_en = 1;
	/*
	 * This works only because prfpregset32_t is intentionally
	 * constructed to be identical to fpregset32_t, with additional
	 * space for the floating-point queue at the end.
	 */
	setfpregs32(lwp, (fpregset32_t *)pfp);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Does the system support extra register state?
 * In a kernel that supports both an _LP64 and an _ILP32 data model,
 * the answer depends on the data model of the process.
 * An _LP64 process does not have extra registers.
 */
int
prhasx(proc_t *p)
{
	extern int xregs_exists;

	if (p->p_model == DATAMODEL_LP64)
		return (0);
	else
		return (xregs_exists);
}

/*
 * Get the size of the extra registers.
 */
int
prgetprxregsize(proc_t *p)
{
	return (xregs_getsize(p));
}

/*
 * Get extra registers.
 */
void
prgetprxregs(klwp_t *lwp, caddr_t prx)
{
	extern void xregs_get(struct _klwp *, caddr_t);

	(void) xregs_get(lwp, prx);
}

/*
 * Set extra registers.
 */
void
prsetprxregs(klwp_t *lwp, caddr_t prx)
{
	extern void xregs_set(struct _klwp *, caddr_t);

	(void) xregs_set(lwp, prx);
}

/*
 * Get the ancillary state registers.
 */
void
prgetasregs(klwp_t *lwp, asrset_t asrset)
{
	bzero(asrset, sizeof (asrset_t));
	getasrs(lwp, asrset);
	getfpasrs(lwp, asrset);
}

/*
 * Set the ancillary state registers.
 */
void
prsetasregs(klwp_t *lwp, asrset_t asrset)
{
	setasrs(lwp, asrset);
	setfpasrs(lwp, asrset);
}

/*
 * Return the base (lower limit) of the process stack.
 */
caddr_t
prgetstackbase(proc_t *p)
{
	return (p->p_usrstack - p->p_stksize);
}

/*
 * Return the "addr" field for pr_addr in prpsinfo_t.
 * This is a vestige of the past, so whatever we return is OK.
 */
caddr_t
prgetpsaddr(proc_t *p)
{
	return ((caddr_t)p);
}

/*
 * Arrange to single-step the lwp.
 */
void
prstep(klwp_t *lwp, int watchstep)
{
	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	lwp->lwp_pcb.pcb_step = STEP_REQUESTED;
	lwp->lwp_pcb.pcb_tracepc = NULL;
	if (watchstep)
		lwp->lwp_pcb.pcb_flags |= WATCH_STEP;
	else
		lwp->lwp_pcb.pcb_flags |= NORMAL_STEP;
}

/*
 * Undo prstep().
 */
void
prnostep(klwp_t *lwp)
{
	ASSERT(ttolwp(curthread) == lwp ||
	    MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	lwp->lwp_pcb.pcb_step = STEP_NONE;
	lwp->lwp_pcb.pcb_tracepc = NULL;
	lwp->lwp_pcb.pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
}

/*
 * Return non-zero if a single-step is in effect.
 */
int
prisstep(klwp_t *lwp)
{
	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	return (lwp->lwp_pcb.pcb_step != STEP_NONE);
}

/*
 * Set the PC to the specified virtual address.
 */
void
prsvaddr(klwp_t *lwp, caddr_t vaddr)
{
	struct regs *r = lwptoregs(lwp);

	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	/*
	 * pc and npc must be word aligned on sparc.
	 * We silently make it so to avoid a watchdog reset.
	 */
	r->r_pc = (uintptr_t)vaddr & ~03L;
	r->r_npc = r->r_pc + 4;
}

/*
 * Map address "addr" in address space "as" into a kernel virtual address.
 * The memory is guaranteed to be resident and locked down.
 */
caddr_t
prmapin(struct as *as, caddr_t addr, int writing)
{
	page_t *pp;
	caddr_t kaddr;
	pfn_t pfnum;

	/*
	 * XXX - Because of past mistakes, we have bits being returned
	 * by getpfnum that are actually the page type bits of the pte.
	 * When the object we are trying to map is a memory page with
	 * a page structure everything is ok and we can use the optimal
	 * method, ppmapin.  Otherwise, we have to do something special.
	 */
	pfnum = hat_getpfnum(as->a_hat, addr);
	if (pf_is_memory(pfnum)) {
		pp = page_numtopp_nolock(pfnum);
		if (pp != NULL) {
			ASSERT(PAGE_LOCKED(pp));
			kaddr = ppmapin(pp, writing ?
			    (PROT_READ | PROT_WRITE) : PROT_READ,
			    (caddr_t)-1);
			return (kaddr + ((uintptr_t)addr & PAGEOFFSET));
		}
	}

	/*
	 * Oh well, we didn't have a page struct for the object we were
	 * trying to map in; ppmapin doesn't handle devices, but allocating a
	 * heap address allows ppmapout to free virutal space when done.
	 */
	kaddr = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	hat_devload(kas.a_hat, kaddr, PAGESIZE, pfnum,
	    writing ? (PROT_READ | PROT_WRITE) : PROT_READ, HAT_LOAD_LOCK);

	return (kaddr + ((uintptr_t)addr & PAGEOFFSET));
}

/*
 * Unmap address "addr" in address space "as"; inverse of prmapin().
 */
/* ARGSUSED */
void
prmapout(struct as *as, caddr_t addr, caddr_t vaddr, int writing)
{
	extern void ppmapout(caddr_t);

	vaddr = (caddr_t)((uintptr_t)vaddr & PAGEMASK);
	ppmapout(vaddr);
}


#define	BAMASK22 0xffc00000	/* for masking out disp22 from ba,a */
#define	BAA	0x30800000	/* ba,a without disp22 */
#define	FBAA	0x31800000	/* fba,a without disp22 */
#define	CBAA	0x31c00000	/* cba,a without disp22 */

#define	BAMASK19 0xfff80000	/* for masking out disp19 from ba,a %[ix]cc */
#define	BAA_icc	0x30480000	/* ba,a %icc without disp19 */
#define	BAA_xcc	0x30680000	/* ba,a %xcc without disp19 */


/*
 * Prepare to single-step the lwp if requested.
 * This is called by the lwp itself just before returning to user level.
 */
void
prdostep(void)
{
	klwp_t *lwp = ttolwp(curthread);
	struct regs *r = lwptoregs(lwp);
	proc_t *p = lwptoproc(lwp);
	struct as *as = p->p_as;
	caddr_t pc;
	caddr_t npc;

	ASSERT(lwp != NULL);
	ASSERT(r != NULL);

	if (lwp->lwp_pcb.pcb_step == STEP_NONE ||
	    lwp->lwp_pcb.pcb_step == STEP_ACTIVE)
		return;

	if (p->p_model == DATAMODEL_ILP32) {
		pc = (caddr_t)(uintptr_t)(caddr32_t)r->r_pc;
		npc = (caddr_t)(uintptr_t)(caddr32_t)r->r_npc;
	} else {
		pc = (caddr_t)r->r_pc;
		npc = (caddr_t)r->r_npc;
	}

	if (lwp->lwp_pcb.pcb_step == STEP_WASACTIVE) {
		if (npc == (caddr_t)lwp->lwp_pcb.pcb_tracepc)
			r->r_npc = (greg_t)as->a_userlimit;
		else {
			lwp->lwp_pcb.pcb_tracepc = (void *)pc;
			r->r_pc = (greg_t)as->a_userlimit;
		}
	} else {
		/*
		 * Single-stepping on sparc is effected by setting nPC
		 * to an invalid address and expecting FLTBOUNDS to
		 * occur after the instruction at PC is executed.
		 * This is not the whole story, however; we must
		 * deal with branch-always instructions with the
		 * annul bit set as a special case here.
		 *
		 * fuword() returns -1 on error and we can't distinguish
		 * this from a legitimate instruction of all 1's.
		 * However 0xffffffff is not one of the branch-always
		 * instructions we are interested in.  No problem.
		 */
		int32_t instr;
		int32_t i;

		if (fuword32_nowatch((void *)pc, (uint32_t *)&instr) != 0)
			instr = -1;
		if ((i = instr & BAMASK22) == BAA || i == FBAA || i == CBAA) {
			/*
			 * For ba,a and relatives, compute the
			 * new PC from the instruction.
			 */
			i = (instr << 10) >> 8;
			lwp->lwp_pcb.pcb_tracepc = (void *)(pc + i);
			r->r_pc = (greg_t)as->a_userlimit;
			r->r_npc = r->r_pc + 4;
		} else if ((i = instr & BAMASK19) == BAA_icc || i == BAA_xcc) {
			/*
			 * For ba,a %icc and ba,a %xcc, compute the
			 * new PC from the instruction.
			 */
			i = (instr << 13) >> 11;
			lwp->lwp_pcb.pcb_tracepc = (void *)(pc + i);
			r->r_pc = (greg_t)as->a_userlimit;
			r->r_npc = r->r_pc + 4;
		} else {
			lwp->lwp_pcb.pcb_tracepc = (void *)npc;
			r->r_npc = (greg_t)as->a_userlimit;
		}
	}

	lwp->lwp_pcb.pcb_step = STEP_ACTIVE;
}

/*
 * Wrap up single stepping of the lwp.
 * This is called by the lwp itself just after it has taken
 * the FLTBOUNDS trap.  We fix up the PC and nPC to have their
 * proper values after the step.  We return 1 to indicate that
 * this fault really is the one we are expecting, else 0.
 *
 * This is also called from syscall() and stop() to reset PC
 * and nPC to their proper values for debugger visibility.
 */
int
prundostep(void)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = ttoproc(curthread);
	struct as *as = p->p_as;
	int rc = 0;
	caddr_t pc;
	caddr_t npc;

	ASSERT(lwp != NULL);

	if (lwp->lwp_pcb.pcb_step == STEP_ACTIVE) {
		struct regs *r = lwptoregs(lwp);

		ASSERT(r != NULL);

		if (p->p_model == DATAMODEL_ILP32) {
			pc = (caddr_t)(uintptr_t)(caddr32_t)r->r_pc;
			npc = (caddr_t)(uintptr_t)(caddr32_t)r->r_npc;
		} else {
			pc = (caddr_t)r->r_pc;
			npc = (caddr_t)r->r_npc;
		}

		if (pc == (caddr_t)as->a_userlimit ||
		    pc == (caddr_t)as->a_userlimit + 4) {
			if (pc == (caddr_t)as->a_userlimit) {
				r->r_pc = (greg_t)lwp->lwp_pcb.pcb_tracepc;
				if (npc == (caddr_t)as->a_userlimit + 4)
					r->r_npc = r->r_pc + 4;
			} else {
				r->r_pc = (greg_t)lwp->lwp_pcb.pcb_tracepc + 4;
				r->r_npc = r->r_pc + 4;
			}
			rc = 1;
		} else {
			r->r_npc = (greg_t)lwp->lwp_pcb.pcb_tracepc;
		}
		lwp->lwp_pcb.pcb_step = STEP_WASACTIVE;
	}

	return (rc);
}

/*
 * Make sure the lwp is in an orderly state
 * for inspection by a debugger through /proc.
 *
 * This needs to be called only once while the current thread remains in the
 * kernel and needs to be called while holding no resources (mutex locks, etc).
 *
 * As a hedge against these conditions, if prstop() is called repeatedly
 * before prunstop() is called, it does nothing and just returns.
 *
 * prunstop() must be called before the thread returns to user level.
 */
/* ARGSUSED */
void
prstop(int why, int what)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	struct regs *r = lwptoregs(lwp);
	kfpu_t *pfp = lwptofpu(lwp);
	caddr_t sp;
	caddr_t pc;
	int watched;
	extern void fp_prsave(kfpu_t *);

	if (lwp->lwp_pcb.pcb_flags & PRSTOP_CALLED)
		return;

	/*
	 * Make sure we don't deadlock on a recursive call
	 * to prstop().  stop() tests the lwp_nostop flag.
	 */
	ASSERT(lwp->lwp_nostop == 0);
	lwp->lwp_nostop = 1;
	(void) flush_user_windows_to_stack(NULL);
	if (lwp->lwp_pcb.pcb_step != STEP_NONE)
		(void) prundostep();

	if (lwp->lwp_pcb.pcb_xregstat == XREGNONE) {
		/*
		 * Attempt to fetch the last register window from the stack.
		 * If that fails, look for it in the pcb.
		 * If that fails, give up.
		 */
		struct machpcb *mpcb = lwptompcb(lwp);
		struct rwindow32 rwindow32;
		size_t rw_size;
		caddr_t rwp;
		int is64;

		if (mpcb->mpcb_wstate == WSTATE_USER32) {
			rw_size = sizeof (struct rwindow32);
			sp = (caddr_t)(uintptr_t)(caddr32_t)r->r_sp;
			rwp = sp;
			is64 = 0;
		} else {
			rw_size = sizeof (struct rwindow);
			sp = (caddr_t)r->r_sp;
			rwp = sp + V9BIAS64;
			is64 = 1;
		}

		watched = watch_disable_addr(rwp, rw_size, S_READ);
		if (is64 &&
		    copyin(rwp, &lwp->lwp_pcb.pcb_xregs, rw_size) == 0)
			lwp->lwp_pcb.pcb_xregstat = XREGPRESENT;
		else if (!is64 &&
		    copyin(rwp, &rwindow32, rw_size) == 0) {
			rwindow_32ton(&rwindow32, &lwp->lwp_pcb.pcb_xregs);
			lwp->lwp_pcb.pcb_xregstat = XREGPRESENT;
		} else {
			int i;

			for (i = 0; i < mpcb->mpcb_wbcnt; i++) {
				if (sp == mpcb->mpcb_spbuf[i]) {
					if (is64) {
						bcopy(mpcb->mpcb_wbuf +
						    (i * rw_size),
						    &lwp->lwp_pcb.pcb_xregs,
						    rw_size);
					} else {
						struct rwindow32 *rw32 =
						    (struct rwindow32 *)
						    (mpcb->mpcb_wbuf +
						    (i * rw_size));
						rwindow_32ton(rw32,
						    &lwp->lwp_pcb.pcb_xregs);
					}
					lwp->lwp_pcb.pcb_xregstat = XREGPRESENT;
					break;
				}
			}
		}
		if (watched)
			watch_enable_addr(rwp, rw_size, S_READ);
	}

	/*
	 * Make sure the floating point state is saved.
	 */
	fp_prsave(pfp);

	if (p->p_model == DATAMODEL_ILP32)
		pc = (caddr_t)(uintptr_t)(caddr32_t)r->r_pc;
	else
		pc = (caddr_t)r->r_pc;

	if (copyin_nowatch(pc, &lwp->lwp_pcb.pcb_instr,
	    sizeof (lwp->lwp_pcb.pcb_instr)) == 0)
		lwp->lwp_pcb.pcb_flags |= INSTR_VALID;
	else {
		lwp->lwp_pcb.pcb_flags &= ~INSTR_VALID;
		lwp->lwp_pcb.pcb_instr = 0;
	}

	(void) save_syscall_args();
	ASSERT(lwp->lwp_nostop == 1);
	lwp->lwp_nostop = 0;

	lwp->lwp_pcb.pcb_flags |= PRSTOP_CALLED;
	aston(curthread);	/* so prunstop() will be called */
}

/*
 * Inform prstop() that it should do its work again
 * the next time it is called.
 */
void
prunstop(void)
{
	ttolwp(curthread)->lwp_pcb.pcb_flags &= ~PRSTOP_CALLED;
}

/*
 * Fetch the user-level instruction on which the lwp is stopped.
 * It was saved by the lwp itself, in prstop().
 * Return non-zero if the instruction is valid.
 */
int
prfetchinstr(klwp_t *lwp, ulong_t *ip)
{
	*ip = (ulong_t)(instr_t)lwp->lwp_pcb.pcb_instr;
	return (lwp->lwp_pcb.pcb_flags & INSTR_VALID);
}

int
prnwindows(klwp_t *lwp)
{
	struct machpcb *mpcb = lwptompcb(lwp);

	return (mpcb->mpcb_wbcnt);
}

void
prgetwindows(klwp_t *lwp, gwindows_t *gwp)
{
	getgwins(lwp, gwp);
}

#ifdef	_SYSCALL32_IMPL
void
prgetwindows32(klwp_t *lwp, gwindows32_t *gwp)
{
	getgwins32(lwp, gwp);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Called from trap() when a load or store instruction
 * falls in a watched page but is not a watchpoint.
 * We emulate the instruction in the kernel.
 */
int
pr_watch_emul(struct regs *rp, caddr_t addr, enum seg_rw rw)
{
	char *badaddr = (caddr_t)(-1);
	int res;
	int watched;

	/* prevent recursive calls to pr_watch_emul() */
	ASSERT(!(curthread->t_flag & T_WATCHPT));
	curthread->t_flag |= T_WATCHPT;

	watched = watch_disable_addr(addr, 16, rw);
	res = do_unaligned(rp, &badaddr);
	if (watched)
		watch_enable_addr(addr, 16, rw);

	curthread->t_flag &= ~T_WATCHPT;
	if (res == SIMU_SUCCESS) {
		rp->r_pc = rp->r_npc;
		rp->r_npc += 4;
		return (1);
	}
	return (0);
}
