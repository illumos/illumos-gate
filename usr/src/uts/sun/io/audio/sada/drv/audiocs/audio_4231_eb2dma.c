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

/*
 * Platform specifc code for the EB2 DMA controller. The EB2 is a PCI bus
 * IC that includes play and record DMA engines and an interface for
 * the CS4231.
 */

#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_src.h>
#include <sys/audio/audio_trace.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/am_src1.h>
#include <sys/audio/impl/audio_4231_impl.h>
#include <sys/audio/audio_4231.h>

/*
 * Attribute structure for the APC, used to create DMA handles.
 */
static ddi_dma_attr_t eb2_attr = {
	DMA_ATTR_V0,			/* version */
	0x0000000000000000LL,		/* dlim_addr_lo */
	0x00000000ffffffffLL,		/* dlim_addr_hi */
	0x0000000000ffffffLL,		/* DMA counter register */
	0x0000000000000001LL,		/* DMA address alignment */
	0x00000074,			/* 4 and 16 byte burst sizes */
	0x00000001,			/* min effective DMA size */
	0x000000000000ffffLL,		/* maximum transfer size, 8k */
	0x000000000000ffffLL,		/* segment boundary, 32k */
	0x00000001,			/* s/g list length, no s/g */
	0x00000001,			/* granularity of device, don't care */
	0				/* DMA flags */
};

static ddi_device_acc_attr_t acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Local routines
 */
static uint_t eb2_rec_intr(caddr_t);
static uint_t eb2_play_intr(caddr_t);
static int eb2_program_play(CS_state_t *, int);

/*
 * DMA ops vector functions
 */
static int eb2_map_regs(dev_info_t *, CS_state_t *, size_t, size_t);
static void eb2_unmap_regs(CS_state_t *);
static void eb2_reset(CS_state_t *);
static int eb2_add_intr(CS_state_t *);
static void eb2_rem_intr(dev_info_t *);
static int eb2_p_start(CS_state_t *);
static void eb2_p_pause(CS_state_t *);
static void eb2_p_restart(CS_state_t *);
static void eb2_p_stop(CS_state_t *);
static int eb2_r_start(CS_state_t *);
static void eb2_r_stop(CS_state_t *);
static void eb2_power(CS_state_t *, int);

cs4231_dma_ops_t cs4231_eb2dma_ops = {
	"EB2 DMA controller",
	eb2_map_regs,
	eb2_unmap_regs,
	eb2_reset,
	eb2_add_intr,
	eb2_rem_intr,
	eb2_p_start,
	eb2_p_pause,
	eb2_p_restart,
	eb2_p_stop,
	eb2_r_start,
	eb2_r_stop,
	eb2_power
};

/* File name for the cs4231_put8() and cs4231_reg_select() routines */
static char *thisfile = __FILE__;

/*
 * eb2_map_regs()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use. It then binds each of the buffers to its
 *	respective handle, getting a DMA cookie. Finally, the registers
 *	are mapped in.
 *
 *	NOTE: All of the ddi_dma_... routines sleep if they cannot get
 *		memory. This means these calls will almost always succeed.
 *
 * Arguments:
 *	dev_info_t	*dip		Pointer to the device's devinfo
 *	CS_state_t	*state		The device's state
 *	int		pbuf_size	The size of the play DMA buffers to
 *					allocate, we need two
 *	int		cbuf_size	The size of the capture DMA buffers to
 *					allocate, we need two
 *
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
eb2_map_regs(dev_info_t *dip, CS_state_t *state, size_t pbuf_size,
	size_t cbuf_size)
{
	uint_t		dma_cookie_count;
	int		rc;

	ATRACE("in eb2_map_regs()", state);

	/* allocate two handles for play and two for record */
	if ((rc = ddi_dma_alloc_handle(dip, &eb2_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ph[0])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_alloc_handle(0) failed: %d", rc);
		goto error;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &eb2_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ph[1])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_alloc_handle(1) failed: %d", rc);
		goto error_ph0;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &eb2_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ch[0])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_alloc_handle(2) failed: %d", rc);
		goto error_ph1;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &eb2_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ch[1])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_alloc_handle(3) failed: %d", rc);
		goto error_rh0;
	}

	/* allocate the four DMA buffers, two for play and two for record */
	if (ddi_dma_mem_alloc(state->cs_ph[0], pbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_pb[0], &state->cs_pml[0],
	    &state->cs_pmh[0]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_mem_alloc(0) failed");
		goto error_rh1;
	}
	if (ddi_dma_mem_alloc(state->cs_ph[1], pbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_pb[1], &state->cs_pml[1],
	    &state->cs_pmh[1]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_mem_alloc(1) failed");
		goto error_pb0;
	}
	if (ddi_dma_mem_alloc(state->cs_ch[0], cbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_cb[0], &state->cs_cml[0],
	    &state->cs_cmh[0]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_mem_alloc(2) failed");
		goto error_pb1;
	}
	if (ddi_dma_mem_alloc(state->cs_ch[1], cbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_cb[1], &state->cs_cml[1],
	    &state->cs_cmh[1]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_mem_alloc(3) failed");
		goto error_rb0;
	}

	/* bind each of the buffers to a DMA handle */
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ph[0], (struct as *)0,
	    state->cs_pb[0], pbuf_size, DDI_DMA_WRITE, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_pc[0], &dma_cookie_count)) !=
	    DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_addr_bind_handle(0) failed: %d",
		    rc);
		goto error_rb1;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ph[1], (struct as *)0,
	    state->cs_pb[1], pbuf_size, DDI_DMA_WRITE, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_pc[1], &dma_cookie_count)) !=
	    DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_addr_bind_handle(1) failed: %d",
		    rc);
		goto error_pc0;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ch[0], (struct as *)0,
	    state->cs_cb[0], cbuf_size, DDI_DMA_READ, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_cc[0], &dma_cookie_count)) !=
	    DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_addr_bind_handle(2) failed: %d",
		    rc);
		goto error_pc1;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ch[1], (struct as *)0,
	    state->cs_cb[1], cbuf_size, DDI_DMA_READ, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_cc[1], &dma_cookie_count)) !=
	    DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_dma_addr_bind_handle(3) failed: %d",
		    rc);
		goto error_rc0;
	}
	ASSERT(dma_cookie_count == 1);

	/* now, map the codec */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&state->cs_regs, 0,
	    sizeof (cs4231_pioregs_t), &acc_attr,
	    &EB2_CODEC_HNDL) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_regs_map_setup() codec failed: %d",
		    rc);
		goto error_rc1;
	}

	/* next the play registers */
	acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	if (ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&state->cs_eb2_regs.play, 0,
	    sizeof (cs4231_eb2regs_t), &acc_attr,
		&EB2_PLAY_HNDL) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_regs_map_setup() play registers "
		    "failed: %d", rc);
		goto error_dev1;
	}

	ASSERT(acc_attr.devacc_attr_endian_flags == DDI_STRUCTURE_LE_ACC);

	/* now the capture registers */
	if (ddi_regs_map_setup(dip, 2,
	    (caddr_t *)&state->cs_eb2_regs.record, 0,
	    sizeof (cs4231_eb2regs_t), &acc_attr,
	    &EB2_REC_HNDL) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_regs_map_setup() record registers "
		    "failed: %d", rc);
		goto error_dev2;
	}

	/* finally the auxio register */
	if (ddi_regs_map_setup(dip, 3,
	    (caddr_t *)&state->cs_eb2_regs.auxio, 0,
	    sizeof (uint_t), &acc_attr,
	    &EB2_AUXIO_HNDL) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_map_regs() ddi_regs_map_setup() audio register "
		    "failed: %d", rc);
		goto error_dev2;
	}

	/* disable play and record interrupts */
	ddi_put32(EB2_PLAY_HNDL, &EB2_PLAY_CSR, EB2_PCLEAR_RESET_VALUE);
	ddi_put32(EB2_REC_HNDL, &EB2_PLAY_CSR, EB2_RCLEAR_RESET_VALUE);

	/* let the state structure know about the attributes */
	state->cs_dma_attr = &eb2_attr;

	/* we start with play and record buffers 0 */
	state->cs_pbuf_toggle = 0;
	state->cs_cbuf_toggle = 0;

	ATRACE("eb2_map_regs() returning success", state);

	return (AUDIO_SUCCESS);

error_dev2:
	ddi_regs_map_free(&EB2_REC_HNDL);
error_dev1:
	ddi_regs_map_free(&EB2_PLAY_HNDL);
error_dev0:
	ddi_regs_map_free(&EB2_CODEC_HNDL);
error_rc1:
	(void) ddi_dma_unbind_handle(state->cs_ch[1]);
error_rc0:
	(void) ddi_dma_unbind_handle(state->cs_ch[0]);
error_pc1:
	(void) ddi_dma_unbind_handle(state->cs_ph[1]);
error_pc0:
	(void) ddi_dma_unbind_handle(state->cs_ph[0]);
error_rb1:
	ddi_dma_mem_free(&state->cs_cmh[1]);
error_rb0:
	ddi_dma_mem_free(&state->cs_cmh[0]);
error_pb1:
	ddi_dma_mem_free(&state->cs_pmh[1]);
error_pb0:
	ddi_dma_mem_free(&state->cs_pmh[0]);
error_rh1:
	ddi_dma_free_handle(&state->cs_ch[1]);
error_rh0:
	ddi_dma_free_handle(&state->cs_ch[0]);
error_ph1:
	ddi_dma_free_handle(&state->cs_ph[1]);
error_ph0:
	ddi_dma_free_handle(&state->cs_ph[0]);
error:
	ATRACE("eb2_map_regs() returning failure", state);

	return (AUDIO_FAILURE);

}	/* eb2_map_regs() */

/*
 * eb2_unmap_regs()
 *
 * Description:
 *	This routine unbinds the DMA cookies, frees the DMA buffers,
 *	deallocated the DAM handles, and finally unmaps the Codec's and
 *	DMA engine's registers.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state
 *
 * Returns:
 *	void
 */
static void
eb2_unmap_regs(CS_state_t *state)
{
	ATRACE("in eb2_unmap_regs()", state);

	(void) ddi_dma_unbind_handle(state->cs_ph[0]);
	(void) ddi_dma_unbind_handle(state->cs_ph[1]);
	(void) ddi_dma_unbind_handle(state->cs_ch[0]);
	(void) ddi_dma_unbind_handle(state->cs_ch[1]);

	ddi_dma_mem_free(&state->cs_pmh[0]);
	ddi_dma_mem_free(&state->cs_pmh[1]);
	ddi_dma_mem_free(&state->cs_cmh[0]);
	ddi_dma_mem_free(&state->cs_cmh[1]);

	ddi_dma_free_handle(&state->cs_ph[0]);
	ddi_dma_free_handle(&state->cs_ph[1]);
	ddi_dma_free_handle(&state->cs_ch[0]);
	ddi_dma_free_handle(&state->cs_ch[1]);

	ddi_regs_map_free(&EB2_CODEC_HNDL);
	ddi_regs_map_free(&EB2_PLAY_HNDL);
	ddi_regs_map_free(&EB2_REC_HNDL);
	ddi_regs_map_free(&EB2_AUXIO_HNDL);

	ATRACE("eb2_unmap_regs() returning", state);

}	/* eb2_unmap_regs() */

/*
 * eb2_reset()
 *
 * Description:
 *	Reset both the play and record DMA engines. The engines are left
 *	with interrupts and the DMA engine disabled.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's devinfo structure
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
eb2_reset(CS_state_t *state)
{
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;
	ddi_acc_handle_t	rhandle = EB2_REC_HNDL;
	uint_t			reg;
	int			x;

	ATRACE("in eb2_reset()", state);

	/* start with the play side */
	ddi_put32(phandle, &EB2_PLAY_CSR, EB2_RESET);
	/* wait for play data to drain */
	reg = ddi_get32(phandle, &EB2_PLAY_CSR);
	for (x = 0; !(reg & EB2_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on the bus */
		reg = ddi_get32(phandle, &EB2_PLAY_CSR);
	}
	/* clear the reset bit and program for chaining */
	ddi_put32(phandle, &EB2_PLAY_CSR, EB2_PCLEAR_RESET_VALUE);

	/* now do the record side and program for chaining */
	ddi_put32(rhandle, &EB2_REC_CSR, EB2_RESET);
	/* wait for record data to drain */
	reg = ddi_get32(rhandle, &EB2_REC_CSR);
	for (x = 0; !(reg & EB2_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on the bus */
		reg = ddi_get32(rhandle, &EB2_REC_CSR);
	}
	/* clear the reset bit */
	ddi_put32(rhandle, &EB2_REC_CSR, EB2_RCLEAR_RESET_VALUE);

	ATRACE("eb2_reset() returning", state);

}	/* eb2_reset() */

/*
 * eb2_add_intr()
 *
 * Description:
 *	Register the EB2 interrupts with the kernel.
 *
 *	NOTE: This does NOT turn on interrupts.
 *
 *	CAUTION: While the interrupts are added, the Codec interrupts are
 *		not enabled.
 *
 * Arguments:
 *	CS_state_t	*state	Pointer to the device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
eb2_add_intr(CS_state_t *state)
{
	dev_info_t	*dip = state->cs_dip;

	ATRACE("in eb2_add_intr()", state);

	/* first we make sure these aren't high level interrupts */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_add_intr() unsupported high level interrupt 0");
		return (AUDIO_FAILURE);
	}
	if (ddi_intr_hilevel(dip, 1) != 0) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_add_intr() unsupported high level interrupt 1");
		return (AUDIO_FAILURE);
	}

	/* okay to register the interrupts */
	if (ddi_add_intr(dip, 0, (ddi_iblock_cookie_t *)0,
	    (ddi_idevice_cookie_t *)0, eb2_rec_intr,
	    (caddr_t)state) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_add_intr() bad record interrupt specification");
		return (AUDIO_FAILURE);
	}

	if (ddi_add_intr(dip, 1, (ddi_iblock_cookie_t *)0,
	    (ddi_idevice_cookie_t *)0, eb2_play_intr,
	    (caddr_t)state) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!eb2_add_intr() bad play interrupt specification");
		ddi_remove_intr(dip, 0, NULL);
		return (AUDIO_FAILURE);
	}

	ATRACE("eb2_add_intr() returning successful", state);

	return (AUDIO_SUCCESS);

}	/* eb2_add_intr() */

/*
 * eb2_rem_intr()
 *
 * Description:
 *	Unregister the EB2 interrupts from the kernel.
 *
 *	CAUTION: While the interrupts are removed, the Codec interrupts are
 *		not disabled, but then, they never should have been on in
 *		the first place.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's devinfo
 *
 * Returns:
 *	void
 */
static void
eb2_rem_intr(dev_info_t *dip)
{
	ATRACE("in eb2_rem_intr()", dip);

	ddi_remove_intr(dip, 0, NULL);
	ddi_remove_intr(dip, 1, NULL);

	ATRACE("eb2_rem_intr() returning", dip);

}	/* eb2_rem_intr() */

/*
 * eb2_p_start()
 *
 * Description:
 *	This routine starts the play DMA engine. This includes "hard" starts
 *	where the DMA engine's registers need to be loaded as well as starting
 *	after a pause;
 *
 *	For hard starts the DMA engine is started by programming the Play Next
 *	Byte Register and the Play Next Address Register twice, and finally
 *	enabling the DMA play engine.
 *
 *	Starting after a pause is much eaiser, we just turn on the EN_DMA bit.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 *	CAUTION: This routine doesn't start the Codec because the first
 *		interrupt causes a recursive mutex_enter.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Successfully started
 *	AUDIO_FAILURE		Start failed
 */
static int
eb2_p_start(CS_state_t *state)
{
	ddi_acc_handle_t	handle = EB2_CODEC_HNDL;
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;
	int			i;
	int			samples;

	ATRACE("in eb2_p_start()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* figure out the number of samples we want */
	samples = state->cs_play_sr * state->cs_play_ch /
	    state->cs_ad_info.ad_play.ad_int_rate;
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples % state->cs_play_ch) == 1) {
		ATRACE("eb2_p_start() samples not mod", samples);
		/* need to adjust */
		samples++;
	}
	ATRACE("eb2_p_start() samples per interrupt", samples);

	/* try to load 2 buffers worth to get things started */
	for (i = 0; i < 2; i++) {
		ATRACE_32("eb2_p_start() calling eb2_program_play()", samples);
		PLAY_COUNT = samples *
		    (state->cs_play_prec >> AUDIO_PRECISION_SHIFT);
		if (eb2_program_play(state, samples) <= 0) {
			ATRACE("eb2_p_start() "
			    "eb2_program_play() returns no samples", state);
			break;
		}

		if (i == 0) {
			/* start playing before we load the next address */
			ATRACE("eb2_p_start() turn on play DMA engine", state);
			OR_SET_WORD(phandle, &EB2_PLAY_CSR, EB2_PLAY_ENABLE);
		}
	}

	/*
	 * If there wasn't anything to get then we aren't active. This can
	 * happen if an AUDIO_DRAIN was issued with no audio in the stream.
	 */
	if (i == 0) {
		ATRACE("eb2_p_start() nothing to do", state);
		return (AUDIO_FAILURE);
	}

	/*
	 * Even with just one DMA buffer loaded we can still play some audio.
	 * Read the Codec Status Register so that we clear the Error and
	 * Initialization register, Index 11, so we'll know when we get
	 * a play underrun in the ISR. Then enable the play DMA engine,
	 * including interrupts.
	 */
#ifdef DEBUG
	ATRACE_8("eb2_p_start() Read the Codec status reg, clearing Index 11",
	    ddi_get8(handle, &CS4231_STATUS));
#else
	(void) ddi_get8(handle, &CS4231_STATUS); /* we only need a read */
#endif

	state->cs_flags |= PDMA_ENGINE_INITIALIZED;

	ATRACE("eb2_p_start() returning", state);

	return (AUDIO_SUCCESS);

}	/* eb2_p_start() */

/*
 * eb2_pause()
 *
 * Description:
 *	This routine pauses the play DMA engine. Buffers, FIFO, etc. are NOT
 *	lost.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
eb2_p_pause(CS_state_t *state)
{
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;
	int			x;
	uint8_t			creg;

	ATRACE("in eb2_p_pause()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* clear the EN_DMA bit, pausing the engine */
	AND_SET_WORD(phandle, &EB2_PLAY_CSR, ~EB2_EN_DMA);

	/* we wait for the Codec FIFO to underrun */
	cs4231_reg_select(state->cs_ahandle, phandle, &CS4231_IAR, ESI_REG,
	    __LINE__, thisfile);
	creg = ddi_get8(phandle, &CS4231_IDR);
	for (x = 0; !(creg & ESI_PUR) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		creg = ddi_get8(phandle, &CS4231_IDR);
	}

	/* stop the Codec */
	cs4231_reg_select(state->cs_ahandle, phandle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(phandle, &CS4231_IDR, ~INTC_PEN, INTC_VALID_MASK);

	ATRACE("eb2_p_pause() returning", state);

}	/* eb2_p_pause() */

/*
 * eb2_p_restart()
 *
 * Description:
 *	This routine restarts the play DMA engine after pausing. Buffers,
 *	FIFO, etc. MUST be programmed and valid.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
eb2_p_restart(CS_state_t *state)
{
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;

	ATRACE("in eb2_p_restart()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* start the Codec */
	cs4231_reg_select(state->cs_ahandle, phandle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	OR_SET_BYTE(phandle, &CS4231_IDR, INTC_PEN, INTC_VALID_MASK);

	/* set the EN_DMA bit, restarting the engine */
	OR_SET_WORD(phandle, &EB2_PLAY_CSR, EB2_EN_DMA);

	ATRACE("eb2_p_restart() returning", state);

}	/* eb2_p_restart() */

/*
 * eb2_p_stop()
 *
 * Description:
 *	This routine stops the play DMA engine.
 *
 *	The DMA engine is stopped by using the play RESET bit.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
eb2_p_stop(CS_state_t *state)
{
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;
	uint_t			reg;
	int			x;
	uint8_t			creg;

	ATRACE("in eb2_p_stop()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* clear the play interrupts so the ISR doesn't get involved */
	AND_SET_WORD(phandle, &EB2_PLAY_CSR, ~EB2_PINTR_MASK);

	/* set the play RESET bit to stop playing audio */
	OR_SET_WORD(phandle, &EB2_PLAY_CSR, EB2_RESET);

	/* wait for the FIFO to drain */
	reg = ddi_get32(phandle, &EB2_PLAY_CSR);
	for (x = 0; (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on the bus */
		reg = ddi_get32(phandle, &EB2_PLAY_CSR);
	}
#ifdef DEBUG
	if (x >= CS4231_TIMEOUT) {
		ATRACE("eb2_p_stop() timeout", state);
	}
#endif

	/* now clear the RESET and EN_DMA bits */
	AND_SET_WORD(phandle, &EB2_PLAY_CSR, ~(EB2_RESET|EB2_EN_DMA));

	/* we wait for the Codec FIFO to underrun */
	cs4231_reg_select(state->cs_ahandle, phandle, &CS4231_IAR, ESI_REG,
	    __LINE__, thisfile);
	creg = ddi_get8(phandle, &CS4231_IDR);
	for (x = 0; !(creg & ESI_PUR) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		creg = ddi_get8(phandle, &CS4231_IDR);
	}

	/* stop the Codec */
	cs4231_reg_select(state->cs_ahandle, phandle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(phandle, &CS4231_IDR, ~INTC_PEN, INTC_VALID_MASK);

	state->cs_flags &= ~PDMA_ENGINE_INITIALIZED;

	ATRACE("eb2_p_stop() returning", state);

}	/* eb2_p_stop() */

/*
 * eb2_r_start()
 *
 * Description:
 *	This routine starts the record DMA engine. The DMA engine is never
 *	paused for record, so a puse is equivalent to a stop. Thus all starts
 *	are hard starts.
 *
 *	For hard starts the DMA engine is started by programming the Record
 *	NExt Byte Register and then the Record Next Address Register twice,
 *	and finally enabling the record DMA engine.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 *	CAUTION: This routine doesn't start the Codec because the first
 *		interrupt causes a recursive mutex_enter.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		The capture DMA was started
 *	AUDIO_FAILURE		The capture DMA was not started
 */
static int
eb2_r_start(CS_state_t *state)
{
	ddi_acc_handle_t	rhandle = EB2_REC_HNDL;
	uint_t			csr;
	int			bytes;
	int			i;
	int			samples;
	int			x;

	ATRACE("in eb2_r_start()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* figure out the number of samples to capture */
	samples = state->cs_record_sr * state->cs_record_ch /
	    state->cs_ad_info.ad_record.ad_int_rate;
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples % state->cs_record_ch) == 1) {
		ATRACE("eb2_r_start() samples not mod", samples);
		/* need to adjust */
		samples++;
	}
	ATRACE("eb2_r_start() samples per interrupt", samples);

	/* now convert the number of samples to the "size" in bytes */
	ASSERT(state->cs_record_prec == AUDIO_PRECISION_8 ||
	    state->cs_record_prec == AUDIO_PRECISION_16);
	bytes = samples * (state->cs_record_prec >> AUDIO_PRECISION_SHIFT);
	ATRACE("eb2_r_start() DMA count", bytes);

	/* reset the DMA engine so we have a good starting place */
	OR_SET_WORD(rhandle, &EB2_REC_CSR, EB2_RESET);

	/* wait for the FIFO to drain, it should be empty */
	csr = ddi_get32(rhandle, &EB2_REC_CSR);
	for (x = 0; (csr & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* no reason to beat on the bus */
		csr = ddi_get32(rhandle, &EB2_REC_CSR);
	}
	if (x >= CS4231_TIMEOUT) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_r_start() timeout waiting for Codec, record not "
		    "started!");
		return (AUDIO_FAILURE);
	}

	/* now clear the RESET and EN_DMA bits */
	AND_SET_WORD(rhandle, &EB2_REC_CSR, ~(EB2_RESET|EB2_EN_DMA));

	/* put into chaining mode */
	OR_SET_WORD(rhandle, &EB2_REC_CSR, EB2_RCLEAR_RESET_VALUE);

	/*
	 * Program the DMA engine with both buffers. We MUST do both buffers
	 * otherwise CAP_COUNT isn't going to set both byte counts.
	 */
	for (i = 0; i < 2; i++) {
		/* sync the DMA buffer before it is going to be used */
		ATRACE("eb2_r_start() dma buffer sync", state);
		if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0,
		    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
			audio_sup_log(state->cs_ahandle, CE_NOTE,
			    "!eb2_r_start() ddi_dma_sync() failed, recording "
			    "stopped");

			/* reset the DMA engine */
			OR_SET_WORD(rhandle, &EB2_REC_CSR, EB2_RESET);

			/* wait for the FIFO to drain, it should be empty */
			csr = ddi_get32(rhandle, &EB2_REC_CSR);
			for (x = 0;
			    (csr & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
				drv_usecwait(1);	/* don't beat on bus */
				csr = ddi_get32(rhandle, &EB2_REC_CSR);
			}

			/* now clear the RESET and EN_DMA bits */
			AND_SET_WORD(rhandle, &EB2_REC_CSR,
			    ~(EB2_RESET|EB2_EN_DMA));

			return (AUDIO_FAILURE);
		}

		/* for eb2 we first program the Next Byte Count Register */
		ATRACE_32("eb2_r_start() next count", (uint_t)bytes);
		ddi_put32(rhandle, &EB2_REC_BCR, (uint_t)bytes);
		CAP_COUNT = bytes;
		ATRACE_32("eb2_r_start() samples to send", samples);

		/* now program the Next Address Register - starts state mach */
		ATRACE_32("eb2_r_start() next address",
		    (uint_t)CAP_DMA_COOKIE.dmac_address);
		ddi_put32(rhandle, &EB2_REC_ACR,
		    (uint_t)CAP_DMA_COOKIE.dmac_address);

		if (i == 0) {
			/* start the DMA engine before loading the next addr */
			ATRACE("eb2_r_start() turn on rec DMA engine", state);
			OR_SET_WORD(rhandle, &EB2_REC_CSR, EB2_REC_ENABLE);
		}

		/* get ready for the next DMA buffer */
		AUDIO_TOGGLE(state->cs_cbuf_toggle);
		ATRACE_32("eb2_r_start() new toggle", state->cs_cbuf_toggle);
	}

	state->cs_flags |= RDMA_ENGINE_INITIALIZED;

	ATRACE("eb2_r_start() returning", state);

	return (AUDIO_SUCCESS);

}	/* eb2_r_start() */

/*
 * eb2_r_stop()
 *
 * Description:
 *	This routine stops the record DMA engine. It then sends any collected
 *	data to the audio mixer.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
eb2_r_stop(CS_state_t *state)
{
	ddi_acc_handle_t	handle = EB2_CODEC_HNDL;
	ddi_acc_handle_t	rhandle = EB2_REC_HNDL;
	uint_t			reg;
	uint_t			csr;
	int			samples;
	int			x;

	ATRACE("in eb2_r_stop()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* stop the Codec */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_CEN, INTC_VALID_MASK);

	csr = ddi_get32(rhandle, &EB2_REC_CSR);
	for (x = 0; (csr & EB2_CYC_PENDING) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);
		csr = ddi_get32(rhandle, &EB2_REC_CSR);
	}

	csr = ddi_get32(rhandle, &EB2_REC_CSR);
	if (csr & EB2_INT_PEND) {
		state->cs_flags |= REC_INTR_PENDING;
	}

	/* set the record RESET bit to stop recording audio */
	OR_SET_WORD(rhandle, &EB2_REC_CSR, EB2_RESET);

	/* wait for the FIFO to drain */
	reg = ddi_get32(rhandle, &EB2_REC_CSR);
	for (x = 0; (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);		/* don't beat on the bus */
		reg = ddi_get32(rhandle, &EB2_REC_CSR);
	}

#ifdef DEBUG
	if (x >= CS4231_TIMEOUT) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "audiocs: eb2_r_stop() timeout, record buffer flushed");
	}
#endif

	/* clear the RESET and EN_DMA bits */
	AND_SET_WORD(rhandle, &EB2_REC_CSR, ~(EB2_RESET|EB2_EN_DMA));

	/* figure how many samples were recorded */
	samples = (CAP_COUNT - ddi_get32(rhandle, &EB2_REC_BCR)) /
	    (state->cs_record_prec >> AUDIO_PRECISION_SHIFT);

	samples -= samples % state->cs_record_ch;

	/* send the captured audio to the mixer */
	if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0, DDI_DMA_SYNC_FORCPU) ==
	    DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_r_stop() ddi_dma_sync() failed, recorded audio lost");
	} else {
		mutex_exit(&state->cs_lock);
		am_send_audio(state->cs_ahandle, CAP_DMA_BUF,
		    AUDIO_NO_CHANNEL, samples);
		mutex_enter(&state->cs_lock);
	}

	state->cs_flags &= ~RDMA_ENGINE_INITIALIZED;

	ATRACE("eb2_r_stop() returning", state);

}	/* eb2_r_stop() */

/*
 * eb2_power()
 *
 * Description:
 *	This routine turns the Codec on or off using the auxio register
 *	in the eb2 device (cheerio or rio). Fortunately we don't need
 *	to delay like we do with the APC.
 *
 *	NOTE: The state structure must be locked when this routine is called.
 *
 * Arguments:
 *	CS_state_t	*state		Ptr to the device's state structure
 *	int		level		Power level to set
 *
 * Returns:
 *	void
 */
static void
eb2_power(CS_state_t *state, int level)
{
	ddi_acc_handle_t	xhandle = EB2_AUXIO_HNDL;

	ATRACE("in eb2_power()", state);
	ATRACE_32("eb2_power() level", level);

	ASSERT(mutex_owned(&state->cs_lock));

	if (level == CS4231_PWR_ON) {	/* turn power on */
		AND_SET_WORD(xhandle, EB2_AUXIO_REG, ~EB2_AUXIO_COD_PDWN);
		state->cs_powered = CS4231_PWR_ON;
	} else {	/* turn power off */
		OR_SET_WORD(xhandle, EB2_AUXIO_REG, EB2_AUXIO_COD_PDWN);
		state->cs_powered = CS4231_PWR_OFF;
	}

	ATRACE_32("eb2_power() done", ddi_get32(xhandle, EB2_AUXIO_REG));

}	/* eb2_power() */


/* *******  Local Routines ************************************************** */

/*
 * eb2_rec_intr()
 *
 * Description:
 *	EB2 record interrupt serivce routine. First we find out why there was
 *	an interrupt, then we take the appropriate action
 *
 * Arguments:
 *	caddr_t		T	Pointer to the interrupting device's state
 *				structure
 *
 * Returns:
 *	DDI_INTR_CLAIMED	Interrupt claimed and processed
 *	DDI_INTR_UNCLAIMED	Interrupt not claimed, and thus ignored
 */
static uint_t
eb2_rec_intr(caddr_t T)
{
	CS_state_t		*state = (CS_state_t *)T;
	ddi_acc_handle_t	rhandle = EB2_REC_HNDL;
	uint_t			csr;
	uint_t			reg;
	int			rc = DDI_INTR_UNCLAIMED;
	int			samples;
	int			x;

	ATRACE("in eb2_rec_intr()", state);

	/* the state must be protected */
	mutex_enter(&state->cs_lock);

	/* get the EB2 record CSR */
	csr = ddi_get32(rhandle, &EB2_REC_CSR);
	ATRACE_32("eb2_rec_intr() intrrupt CSR", csr);

	/* make sure this device sent the interrupt */
	if (!(csr & EB2_INT_PEND)) {
		/* Interrupt that's still being serviced */
		if (state->cs_flags & REC_INTR_PENDING) {
			rc = DDI_INTR_CLAIMED;
			goto done;
		}

		/* nope, this isn't our interrupt */
		ATRACE_32("eb2_rec_intr() device didn't send interrupt", csr);
		if (state->cs_ksp) {
			KIOP(state)->intrs[KSTAT_INTR_SPURIOUS]++;
		}
		mutex_exit(&state->cs_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear all interrupts we captured at this time */
	ddi_put32(rhandle, &EB2_REC_CSR, (csr|EB2_TC));
	ATRACE_32("eb2_rec_intr() csr after clear",
	    ddi_get32(rhandle, &EB2_REC_CSR));

	if (csr & EB2_TC) {
		ATRACE("eb2_rec_intr() record interrupt", state);

		/* sync DMA memory before sending it to the audio mixer */
		if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0,
		    DDI_DMA_SYNC_FORCPU) == DDI_FAILURE) {
			audio_sup_log(state->cs_ahandle, CE_NOTE,
			    "!eb2_rec_intr() ddi_dma_sync(#1) failed, recorded "
			    "audio lost");
		} else {
			/* figure how many samples were recorded */
			samples = CAP_COUNT /
			    (state->cs_record_prec >> AUDIO_PRECISION_SHIFT);

			/* send the captured audio to the mixer */
			mutex_exit(&state->cs_lock);
			am_send_audio(state->cs_ahandle, CAP_DMA_BUF,
			    AUDIO_NO_CHANNEL, samples);
			mutex_enter(&state->cs_lock);
		}

		/* sync the DMA buffer before it is going to be reused */
		ATRACE("eb2_rec_intr() dma buffer sync", state);
		if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0,
		    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
			audio_sup_log(state->cs_ahandle, CE_NOTE,
			    "!eb2_rec_intr() ddi_dma_sync(#2) failed, recording"
			    " disabled");

			/* reset the DMA engine */
			OR_SET_WORD(rhandle, &EB2_REC_CSR, EB2_RESET);

			/* wait for the FIFO to drain, it should be empty */
			reg = ddi_get32(rhandle, &EB2_REC_CSR);
			for (x = 0;
			    (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
				drv_usecwait(1);	/* don't beat on bus */
				reg = ddi_get32(rhandle, &EB2_REC_CSR);
			}

			/* now clear the RESET and EN_DMA bits */
			AND_SET_WORD(rhandle, &EB2_REC_CSR,
			    ~(EB2_RESET|EB2_EN_DMA));
		} else {
			ATRACE_32("eb2_rec_intr() next address",
			    (uint_t)CAP_DMA_COOKIE.dmac_address);

			/* first program the Next Byte Count Register */
			ATRACE_32("eb2_rec_intr() next count",
			    (uint_t)CAP_COUNT);
			ddi_put32(rhandle, &EB2_REC_BCR, (uint_t)CAP_COUNT);

			/* now program the Next Add. Reg. - starts state mach */
			ATRACE_32("eb2_rec_intr() next address",
			    (uint_t)CAP_DMA_COOKIE.dmac_address);
			ddi_put32(rhandle, &EB2_REC_ACR,
			    (uint_t)CAP_DMA_COOKIE.dmac_address);

			/* get ready for the next DMA buffer */
			AUDIO_TOGGLE(state->cs_cbuf_toggle);
			ATRACE_32("eb2_rec_intr() new toggle",
			    state->cs_cbuf_toggle);
		}

		/* we always claim the interrupt, even if DMA sync failed */
		rc = DDI_INTR_CLAIMED;
	} else if (csr & EB2_ERR_PEND) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_rec_intr() error interrupt: 0x%x", csr);
		rc = DDI_INTR_CLAIMED;
	} else {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_rec_intr() unknown interrupt: 0x%x", csr);
		rc = DDI_INTR_CLAIMED;
	}

done:
	state->cs_flags &= ~REC_INTR_PENDING;

	/* update the kernel interrupt statistics */
	if (state->cs_ksp) {
		if (rc == DDI_INTR_CLAIMED) {
			KIOP(state)->intrs[KSTAT_INTR_HARD]++;
		} else {
			KIOP(state)->intrs[KSTAT_INTR_SPURIOUS]++;
		}
	}

	mutex_exit(&state->cs_lock);

	ATRACE_32("eb2_rec_intr() returning", rc);

	return (rc);

}	/* eb2_rec_intr() */

/*
 * eb2_play_intr()
 *
 * Description:
 *	EB2 play interrupt serivce routine. First we find out why there was an
 *	interrupt, then we take the appropriate action.
 *
 * Arguments:
 *	caddr_t		T	Pointer to the interrupting device's state
 *				structure
 *
 * Returns:
 *	DDI_INTR_CLAIMED	Interrupt claimed and processed
 *	DDI_INTR_UNCLAIMED	Interrupt not claimed, and thus ignored
 */
static uint_t
eb2_play_intr(caddr_t T)
{
	CS_state_t		*state = (CS_state_t *)T;
	ddi_acc_handle_t	handle = EB2_CODEC_HNDL;
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;
	uint_t			csr;
	uint_t			reg;
	int			rc = DDI_INTR_UNCLAIMED;
	int			samples;
	int			x;
	uint8_t			creg;

	ATRACE("in eb2_play_intr()", state);

	/* the state must be protected */
	mutex_enter(&state->cs_lock);

	/* get the EB2 play CSR */
	csr = ddi_get32(phandle, &EB2_PLAY_CSR);
	ATRACE_32("eb2_play_intr() interrupt CSR", csr);

	/* make sure this device sent the interrupt */
	if (!(csr & EB2_INT_PEND)) {
		mutex_exit(&state->cs_lock);
		/* nope, this isn't our interrupt */
		ATRACE_32("eb2_play_intr() device didn't send interrupt", csr);
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear all interrupts we captured at this time */
	ddi_put32(phandle, &EB2_PLAY_CSR, (csr|EB2_TC));
	ATRACE_32("eb2_play_intr() csr after clear",
	    ddi_get32(phandle, &EB2_PLAY_CSR));

	if (csr & EB2_TC) {
		samples = PLAY_COUNT /
		    (state->cs_play_prec >> AUDIO_PRECISION_SHIFT);
		ATRACE_32("eb2_play_intr() samples to get", samples);

		/* try to load the next audio buffer */
		samples = eb2_program_play(state, samples);
		ATRACE_32("eb2_play_intr() samples eb2_program_play() returned",
		    samples);

		if (samples <= 0 && !(csr & EB2_A_LOADED)) {
			/*
			 * There isn't any more data to play, so wait for
			 * the the Codec FIFO to empty. Then turn off the
			 * play DMA engine by reseting it. Also, we should
			 * note that a play interrupt with an ADDRESS loaded
			 * but no samples is ignored, but acknowledged. We
			 * wait for the ADDRESS to not be loaded before we
			 * declare the DMA engine empty.
			 */
			ATRACE_32("eb2_play_intr() no more data, wait for "
			    "FIFO", samples);

			/*
			 * We wait for the Codec FIFO to underrun. Unlike the
			 * APC, we wouldn't be here if the pipe wasn't already
			 * empty.
			 */
			cs4231_reg_select(state->cs_ahandle, handle,
			    &CS4231_IAR, ESI_REG, __LINE__, thisfile);
			creg = ddi_get8(handle, &CS4231_IDR);
			for (x = 0; !(creg & ESI_PUR) && x < CS4231_TIMEOUT;
			    x++) {
				drv_usecwait(1);	/* don't beat on bus */
				creg = ddi_get8(handle, &CS4231_IDR);
			}

			/*
			 * Clear the flag so if audio is restarted while in
			 * am_play_shutdown() we can detect it and not mess
			 * things up.
			 */
			state->cs_flags &= ~PDMA_ENGINE_INITIALIZED;

			/* now shutdown the play stream */
			ATRACE("eb2_intr() shutdown play stream", state);
			mutex_exit(&state->cs_lock);
			am_play_shutdown(state->cs_ahandle, NULL);
			mutex_enter(&state->cs_lock);

			/* make sure playing wasn't restarted when lock lost */
			if (state->cs_flags & PDMA_ENGINE_INITIALIZED) {
				/* yes, it was, so we're done */
				ATRACE("eb2_intr() restart after shutdown", 0);
				rc = DDI_INTR_CLAIMED;
				goto done;
			}

			/*
			 * Nope, play was not restarted so reset the
			 * DMA eng, putting it into a known state
			 */
			OR_SET_WORD(phandle, &EB2_PLAY_CSR, EB2_RESET);

			/* wait for the FIFO to drain, which it should be */
			reg = ddi_get32(phandle, &EB2_PLAY_CSR);
			for (x = 0;
			    (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
				drv_usecwait(1); /* don't beat on the bus */
				reg = ddi_get32(phandle, &EB2_PLAY_CSR);
			}

			/* clear the reset bit */
			AND_SET_WORD(phandle, &EB2_PLAY_CSR, ~EB2_RESET);

			/* disable the Codec */
			cs4231_reg_select(state->cs_ahandle, handle,
			    &CS4231_IAR, INTC_REG, __LINE__, thisfile);
			AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_PEN,
			    INTC_VALID_MASK);

			/* and reset the status */
			ddi_put8(handle, &CS4231_STATUS, STATUS_RESET);

			ATRACE("eb2_play_intr() Play DMA engine off", state);
		}
		rc = DDI_INTR_CLAIMED;
		ATRACE_32("eb2_play_intr() done", rc);
	} else if (csr & EB2_ERR_PEND) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_play_intr() error interrupt: 0x%x", csr);
		rc = DDI_INTR_CLAIMED;
	} else {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_play_intr() unknown interrupt: 0x%x", csr);
		rc = DDI_INTR_CLAIMED;
	}

done:

	/* update the kernel interrupt statisitcs */
	if (state->cs_ksp) {
		if (rc == DDI_INTR_CLAIMED) {
			KIOP(state)->intrs[KSTAT_INTR_HARD]++;
		}
	}

	mutex_exit(&state->cs_lock);

	ATRACE_32("eb2_play_intr() returning", rc);

	return (rc);

}	/* eb2_play_intr() */

/*
 * eb2_program_play()
 *
 * Description:
 *	This routine is used by eb2_p_start() and eb2_play_intr() to program
 *	the play DMA engine with the next buffer full of audio.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state pointer
 *	int		samples	The number of samples to be retrieved from the
 *				mixer
 *
 * Returns:
 *	0			The buffer wasn't programmed, no audio
 *	> 0			The buffer was programmed
 *	AUDIO_FAILURE		The buffer wasn't programmed
 */
static int
eb2_program_play(CS_state_t *state, int samples)
{
	ddi_acc_handle_t	handle = EB2_CODEC_HNDL;
	uint_t			reg;
	uint_t			precision;
	int			x;
	int			rc;

	ATRACE_32("in eb2_program_play()", samples);

	/* we need the precision to calculate the next count correctly */
	precision = state->cs_play_prec >> AUDIO_PRECISION_SHIFT;
	ATRACE_32("eb2_program_play() precision", precision);

	/* get the first buffer's worth of audio */
	mutex_exit(&state->cs_lock);
	rc = am_get_audio(state->cs_ahandle, PLAY_DMA_BUF, AUDIO_NO_CHANNEL,
	    samples);
	mutex_enter(&state->cs_lock);
	ATRACE_32("eb2_program_play() am_get_audio() returned", rc);

	if (rc == AUDIO_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_program_play() am_get_audio() failed");
		return (AUDIO_FAILURE);
	} else if (rc == 0) {
		ATRACE("eb2_program_play() am_get_audio() returned 0 samples",
		    state);
		return (0);
	}

	/* sync the DMA buffer before it is going to be used */
	ATRACE("eb2_program_play() dma buffer sync", state);
	if (ddi_dma_sync(PLAY_DMA_HANDLE, (off_t)0, (size_t)(rc * precision),
	    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!eb2_program_play() ddi_dma_sync(#2) failed");

		/* reset the DMA engine, this leaves the DMA engine ok */
		OR_SET_WORD(handle, &EB2_PLAY_CSR, EB2_RESET);
		/* wait for play data to drain */
		reg = ddi_get32(handle, &EB2_PLAY_CSR);
		for (x = 0; (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
			drv_usecwait(1);	/* don't beat on the bus */
			reg = ddi_get32(handle, &EB2_PLAY_CSR);
		}
		/* clear the reset bit */
		ddi_put32(handle, &EB2_PLAY_CSR, EB2_PCLEAR_RESET_VALUE);

		return (AUDIO_FAILURE);
	}

	/* make sure we are in NEXT mode */
	OR_SET_WORD(handle, &EB2_PLAY_CSR, EB2_EN_NEXT|EB2_EN_CNT);

	/* program the Next Byte Count Register */
	ATRACE_32("eb2_program_play() next count", (uint_t)(rc * precision));
	ddi_put32(handle, &EB2_PLAY_BCR, (uint_t)(rc * precision));

	/* now program the Next Address Register */
	ATRACE_32("eb2_program_play() next address",
	    (uint_t)PLAY_DMA_COOKIE.dmac_address);
	ddi_put32(handle, &EB2_PLAY_ACR, (uint_t)PLAY_DMA_COOKIE.dmac_address);

	/* now get ready for the next time we need a DMA buffer */
	AUDIO_TOGGLE(state->cs_pbuf_toggle);
	ATRACE_32("eb2_program_play() new toggle", state->cs_pbuf_toggle);

	ATRACE_32("eb2_program_play() returning", rc);

	return (rc);

}	/* eb2_program_play() */
