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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * This implements the hypervisor multiplexor FPU API. Its purpose is to make it
 * easy to switch between the host and guest hypervisor while hiding all the
 * details about CR0.TS and how to save the host's state as required.
 */

#include <sys/pcb.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/hma.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>

struct hma_fpu {
	fpu_ctx_t	hf_guest_fpu;
	kthread_t	*hf_curthread;
	boolean_t	hf_inguest;
};

int
hma_fpu_init(hma_fpu_t *fpu)
{
	struct xsave_state *xs;

	ASSERT0(fpu->hf_inguest);

	switch (fp_save_mech) {
	case FP_FXSAVE:
		bcopy(&sse_initial, fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_fx,
		    sizeof (struct fxsave_state));
		fpu->hf_guest_fpu.fpu_xsave_mask = 0;
		break;
	case FP_XSAVE:
		/*
		 * Zero everything in the xsave case as we may have data in
		 * the structure that's not part of the initial value (which
		 * only really deals with a small portion of the xsave state).
		 */
		xs = fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_xs;
		bzero(xs, cpuid_get_xsave_size());
		bcopy(&avx_initial, xs, sizeof (*xs));
		xs->xs_xstate_bv = XFEATURE_LEGACY_FP | XFEATURE_SSE;
		fpu->hf_guest_fpu.fpu_xsave_mask = XFEATURE_FP_ALL;
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	fpu->hf_guest_fpu.fpu_flags = FPU_EN | FPU_VALID;

	return (0);
}

void
hma_fpu_free(hma_fpu_t *fpu)
{
	if (fpu == NULL)
		return;

	ASSERT3P(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic, !=, NULL);
	kmem_cache_free(fpsave_cachep,
	    fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic);
	kmem_free(fpu, sizeof (*fpu));
}

hma_fpu_t *
hma_fpu_alloc(int kmflag)
{
	hma_fpu_t *fpu;

	fpu = kmem_zalloc(sizeof (hma_fpu_t), kmflag);
	if (fpu == NULL)
		return (NULL);

	fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic =
	    kmem_cache_alloc(fpsave_cachep, kmflag);
	if (fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic == NULL) {
		kmem_free(fpu, sizeof (hma_fpu_t));
		return (NULL);
	}
	fpu->hf_inguest = B_FALSE;

	/*
	 * Make sure the entire structure is zero.
	 */
	switch (fp_save_mech) {
	case FP_FXSAVE:
		bzero(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic,
		    sizeof (struct fxsave_state));
		break;
	case FP_XSAVE:
		bzero(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic,
		    cpuid_get_xsave_size());
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	return (fpu);
}

void
hma_fpu_start_guest(hma_fpu_t *fpu)
{
	/*
	 * Note, we don't check / assert whether or not t_prempt is true because
	 * there are contexts where this is safe to call (from a context op)
	 * where t_preempt may not be set.
	 */
	ASSERT3S(fpu->hf_inguest, ==, B_FALSE);
	ASSERT3P(fpu->hf_curthread, ==, NULL);
	ASSERT3P(curthread->t_lwp, !=, NULL);
	ASSERT3U(fpu->hf_guest_fpu.fpu_flags & FPU_EN, !=, 0);
	ASSERT3U(fpu->hf_guest_fpu.fpu_flags & FPU_VALID, !=, 0);

	fpu->hf_inguest = B_TRUE;
	fpu->hf_curthread = curthread;


	fp_save(&curthread->t_lwp->lwp_pcb.pcb_fpu);
	fp_restore(&fpu->hf_guest_fpu);
	fpu->hf_guest_fpu.fpu_flags &= ~FPU_VALID;
}

void
hma_fpu_stop_guest(hma_fpu_t *fpu)
{
	ASSERT3S(fpu->hf_inguest, ==, B_TRUE);
	ASSERT3P(fpu->hf_curthread, ==, curthread);
	ASSERT3U(fpu->hf_guest_fpu.fpu_flags & FPU_EN, !=, 0);
	ASSERT3U(fpu->hf_guest_fpu.fpu_flags & FPU_VALID, ==, 0);

	/*
	 * Note, we can't use fp_save because it assumes that we're saving to
	 * the thread's PCB and not somewhere else. Because this is a different
	 * FPU context, we instead have to do this ourselves.
	 */
	switch (fp_save_mech) {
	case FP_FXSAVE:
		fpxsave(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_fx);
		break;
	case FP_XSAVE:
		xsavep(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_xs,
		    fpu->hf_guest_fpu.fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
	fpu->hf_guest_fpu.fpu_flags |= FPU_VALID;

	fp_restore(&curthread->t_lwp->lwp_pcb.pcb_fpu);

	fpu->hf_inguest = B_FALSE;
	fpu->hf_curthread = NULL;
}

void
hma_fpu_get_fxsave_state(const hma_fpu_t *fpu, struct fxsave_state *fx)
{
	const struct fxsave_state *guest;

	ASSERT3S(fpu->hf_inguest, ==, B_FALSE);

	guest = fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_fx;
	bcopy(guest, fx, sizeof (*fx));
}

int
hma_fpu_set_fxsave_state(hma_fpu_t *fpu, const struct fxsave_state *fx)
{
	struct fxsave_state *gfx;
	struct xsave_state *gxs;

	ASSERT3S(fpu->hf_inguest, ==, B_FALSE);

	/*
	 * If reserved bits are set in fx_mxcsr, then we will take a #GP when
	 * we restore them. Reject this outright.
	 *
	 * We do not need to check if we are dealing with state that has pending
	 * exceptions. This was only the case with the original FPU save and
	 * restore mechanisms (fsave/frstor). When using fxsave/fxrstor and
	 * xsave/xrstor they will be deferred to the user using the FPU, which
	 * is what we'd want here (they'd be used in guest context).
	 */
	if ((fx->fx_mxcsr & ~sse_mxcsr_mask) != 0)
		return (EINVAL);

	switch (fp_save_mech) {
	case FP_FXSAVE:
		gfx = fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_fx;
		bcopy(fx, gfx, sizeof (*fx));
		break;
	case FP_XSAVE:
		gxs = fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_xs;
		bzero(gxs, cpuid_get_xsave_size());
		bcopy(fx, &gxs->xs_fxsave, sizeof (*fx));
		gxs->xs_xstate_bv = XFEATURE_LEGACY_FP | XFEATURE_SSE;
		break;
	default:
		panic("Invalid fp_save_mech");
		/* NOTREACHED */
	}

	return (0);
}
