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
 * Copyright 2022 Oxide Computer Company
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
#include <sys/controlregs.h>
#include <sys/sysmacros.h>
#include <sys/stdbool.h>
#include <sys/ontrap.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>

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
		xs->xs_header.xsh_xstate_bv = XFEATURE_LEGACY_FP | XFEATURE_SSE;
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

/*
 * Since fp_save() assumes a thread-centric view of the FPU usage -- it will
 * assert if attempting to save elsewhere than the thread PCB, and will elide
 * action if the FPU is not enabled -- we cannot use it for the manual saving of
 * FPU contents.  To work around that, we call the save mechanism directly.
 */
static void
do_fp_save(fpu_ctx_t *fpu)
{
	/*
	 * For our manual saving, we expect that the thread PCB never be the
	 * landing zone for the data.
	 */
	ASSERT(curthread->t_lwp == NULL ||
	    fpu != &curthread->t_lwp->lwp_pcb.pcb_fpu);

	switch (fp_save_mech) {
	case FP_FXSAVE:
		fpxsave(fpu->fpu_regs.kfpu_u.kfpu_fx);
		break;
	case FP_XSAVE:
		xsavep(fpu->fpu_regs.kfpu_u.kfpu_xs, fpu->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
	}
	fpu->fpu_flags |= FPU_VALID;
}


void
hma_fpu_stop_guest(hma_fpu_t *fpu)
{
	ASSERT3S(fpu->hf_inguest, ==, B_TRUE);
	ASSERT3P(fpu->hf_curthread, ==, curthread);
	ASSERT3U(fpu->hf_guest_fpu.fpu_flags & FPU_EN, !=, 0);
	ASSERT3U(fpu->hf_guest_fpu.fpu_flags & FPU_VALID, ==, 0);

	do_fp_save(&fpu->hf_guest_fpu);

	fp_restore(&curthread->t_lwp->lwp_pcb.pcb_fpu);

	fpu->hf_inguest = B_FALSE;
	fpu->hf_curthread = NULL;
}

/*
 * Will output up to `ndesc` records into `descp`.  The required size for an
 * XSAVE area containing all of the data fields supported by the host will be
 * placed in `req_sizep` (if non-NULL).  Returns the number of feature bits
 * supported by the host.
 */
uint_t
hma_fpu_describe_xsave_state(hma_xsave_state_desc_t *descp, uint_t ndesc,
    size_t *req_sizep)
{
	uint64_t features;

	switch (fp_save_mech) {
	case FP_FXSAVE:
		/*
		 * Even without xsave support, the FPU will have legacy x87
		 * float and SSE state contained within.
		 */
		features = XFEATURE_LEGACY_FP | XFEATURE_SSE;
		break;
	case FP_XSAVE:
		features = get_xcr(XFEATURE_ENABLED_MASK);
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	uint_t count, pos;
	uint_t max_size = MIN_XSAVE_SIZE;
	for (count = 0, pos = 0; pos <= 63; pos++) {
		const uint64_t bit = (1 << pos);
		uint32_t size, off;

		if ((features & bit) == 0) {
			continue;
		}

		if (bit == XFEATURE_LEGACY_FP || bit == XFEATURE_SSE) {
			size = sizeof (struct fxsave_state);
			off = 0;
		} else {
			/*
			 * Size and position of data types within the XSAVE area
			 * is described in leaf 0xD in the subfunction
			 * corresponding to the bit position (for pos > 1).
			 */
			struct cpuid_regs regs = {
				.cp_eax = 0xD,
				.cp_ecx = pos,
			};

			ASSERT3U(pos, >, 1);

			(void) __cpuid_insn(&regs);
			size = regs.cp_eax;
			off = regs.cp_ebx;
		}
		max_size = MAX(max_size, off + size);

		if (count < ndesc) {
			hma_xsave_state_desc_t *desc = &descp[count];

			desc->hxsd_bit = bit;
			desc->hxsd_size = size;
			desc->hxsd_off = off;
		}
		count++;
	}
	if (req_sizep != NULL) {
		*req_sizep = max_size;
	}
	return (count);
}

hma_fpu_xsave_result_t
hma_fpu_get_xsave_state(const hma_fpu_t *fpu, void *buf, size_t len)
{
	ASSERT(!fpu->hf_inguest);

	size_t valid_len;
	switch (fp_save_mech) {
	case FP_FXSAVE: {
		if (len < MIN_XSAVE_SIZE) {
			return (HFXR_NO_SPACE);
		}
		bcopy(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic, buf,
		    sizeof (struct fxsave_state));

		struct xsave_header hdr = {
			.xsh_xstate_bv = XFEATURE_LEGACY_FP | XFEATURE_SSE,
		};
		bcopy(&hdr, buf + sizeof (struct fxsave_state), sizeof (hdr));

		break;
	}
	case FP_XSAVE:
		(void) hma_fpu_describe_xsave_state(NULL,  0, &valid_len);
		if (len < valid_len) {
			return (HFXR_NO_SPACE);
		}
		bcopy(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_generic, buf,
		    valid_len);
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	return (HFXR_OK);
}

hma_fpu_xsave_result_t
hma_fpu_set_xsave_state(hma_fpu_t *fpu, void *buf, size_t len)
{
	ASSERT(!fpu->hf_inguest);

	if (len < MIN_XSAVE_SIZE) {
		return (HFXR_NO_SPACE);
	}
	/* 64-byte alignment is demanded of the FPU-related operations */
	if (((uintptr_t)buf & 63) != 0) {
		return (HFXR_BAD_ALIGN);
	}

	struct xsave_header *hdr = buf + sizeof (struct fxsave_state);
	if (hdr->xsh_xcomp_bv != 0) {
		/* XSAVEC formatting not supported at this time */
		return (HFXR_UNSUP_FMT);
	}

	uint64_t allowed_bits;
	size_t save_area_size;
	switch (fp_save_mech) {
	case FP_FXSAVE:
		allowed_bits = XFEATURE_LEGACY_FP | XFEATURE_SSE;
		save_area_size = sizeof (struct fxsave_state);
		break;
	case FP_XSAVE:
		allowed_bits = get_xcr(XFEATURE_ENABLED_MASK);
		save_area_size = cpuid_get_xsave_size();
		break;
	default:
		panic("Invalid fp_save_mech");
	}
	if ((hdr->xsh_xstate_bv & ~(allowed_bits)) != 0) {
		return (HFXR_UNSUP_FEAT);
	}

	/*
	 * We validate the incoming state with the FPU itself prior to saving it
	 * into the guest FPU context area.  In order to preserve any state
	 * currently housed in the FPU, we save it to a temporarily allocated
	 * FPU context. It is important to note that we are not following the
	 * normal rules around state management detailed in uts/intel/os/fpu.c.
	 * This saving is unconditional, uncaring about the state in the FPU or
	 * the value of CR0_TS, simplifying our process before returning to the
	 * caller (without needing to chcek of an lwp, etc).  To prevent
	 * interrupting threads from encountering this unusual FPU state, we
	 * keep interrupts disabled for the duration.
	 */
	fpu_ctx_t temp_ctx = {
		.fpu_xsave_mask = XFEATURE_FP_ALL,
	};
	temp_ctx.fpu_regs.kfpu_u.kfpu_generic =
	    kmem_cache_alloc(fpsave_cachep, KM_SLEEP);
	bzero(temp_ctx.fpu_regs.kfpu_u.kfpu_generic, save_area_size);

	ulong_t iflag;
	iflag = intr_clear();
	bool disable_when_done = (getcr0() & CR0_TS) != 0;
	do_fp_save(&temp_ctx);

	/*
	 * If the provided data is invalid, it will cause a #GP when we attempt
	 * to load it into the FPU, so protect against that with on_trap().
	 * Should the data load successfully, we can then be confident that its
	 * later use in via hma_fpu_start_guest() will be safe.
	 */
	on_trap_data_t otd;
	volatile hma_fpu_xsave_result_t res = HFXR_OK;
	if (on_trap(&otd, OT_DATA_EC) != 0) {
		res = HFXR_INVALID_DATA;
		goto done;
	}

	switch (fp_save_mech) {
	case FP_FXSAVE:
		if (hdr->xsh_xstate_bv == 0) {
			/*
			 * An empty xstate_bv means we can simply load the
			 * legacy FP/SSE area with their initial state.
			 */
			bcopy(&sse_initial,
			    fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_fx,
			    sizeof (sse_initial));
		} else {
			fpxrestore(buf);
			fpxsave(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_fx);
		}
		break;
	case FP_XSAVE:
		xrestore(buf, XFEATURE_FP_ALL);
		xsavep(fpu->hf_guest_fpu.fpu_regs.kfpu_u.kfpu_xs,
		    fpu->hf_guest_fpu.fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
	}

done:
	no_trap();
	fp_restore(&temp_ctx);
	if (disable_when_done) {
		fpdisable();
	}
	intr_restore(iflag);
	kmem_cache_free(fpsave_cachep, temp_ctx.fpu_regs.kfpu_u.kfpu_generic);

	return (res);
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
		gxs->xs_header.xsh_xstate_bv =
		    XFEATURE_LEGACY_FP | XFEATURE_SSE;
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	return (0);
}
