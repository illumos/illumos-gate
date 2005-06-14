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
 * Platform specifc code for the APC DMA controller. The APC is an SBus
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
static ddi_dma_attr_t apc_attr = {
	DMA_ATTR_V0,			/* version */
	0x0000000000000000LL,		/* dlim_addr_lo */
	0x00000000ffffffffLL,		/* dlim_addr_hi */
	0x0000000000000fffLL,		/* DMA counter register */
	0x0000000000000001LL,		/* DMA address alignment */
	0x00000014,			/* 4 and 16 byte burst sizes */
	0x00000001,			/* min effective DMA size */
	0x0000000000000fffLL,		/* maximum transfer size, 8k */
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
static uint_t apc_intr(caddr_t);
static int apc_program_play(CS_state_t *, int, caddr_t *, int);

/*
 * DMA ops vector functions
 */
static int apc_map_regs(dev_info_t *, CS_state_t *, size_t, size_t);
static void apc_unmap_regs(CS_state_t *);
static void apc_reset(CS_state_t *);
static int apc_add_intr(CS_state_t *);
static void apc_rem_intr(dev_info_t *);
static int apc_p_start(CS_state_t *);
static void apc_p_pause(CS_state_t *);
static void apc_p_restart(CS_state_t *);
static void apc_p_stop(CS_state_t *);
static int apc_r_start(CS_state_t *);
static void apc_r_stop(CS_state_t *);
static void apc_power(CS_state_t *, int);

cs4231_dma_ops_t cs4231_apcdma_ops = {
	"APC DMA controller",
	apc_map_regs,
	apc_unmap_regs,
	apc_reset,
	apc_add_intr,
	apc_rem_intr,
	apc_p_start,
	apc_p_pause,
	apc_p_restart,
	apc_p_stop,
	apc_r_start,
	apc_r_stop,
	apc_power
};

/* File name for the cs4231_put8() and cs4231_reg_select() routines */
static char *thisfile = __FILE__;

/*
 * apc_map_regs()
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
 *	CS_state_t	*state		The device's state structure
 *	size_t		pbuf_size	The size of the play DMA buffers to
 *					allocate, we need two
 *	size_t		cbuf_size	The size of the capture DMA buffers to
 *					allocate, we need two
 *
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
apc_map_regs(dev_info_t *dip, CS_state_t *state, size_t pbuf_size,
	size_t cbuf_size)
{
	ddi_acc_handle_t	*handle = &APC_HANDLE;
	uint_t			dma_cookie_count;
	int			rc;

	ATRACE("in apc_map_regs()", state);

	/* allocate two handles for play and two for record */
	if ((rc = ddi_dma_alloc_handle(dip, &apc_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ph[0])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_alloc_handle(0) failed: %d", rc);
		goto error;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &apc_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ph[1])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_alloc_handle(1) failed: %d", rc);
		goto error_ph0;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &apc_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ch[0])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_alloc_handle(2) failed: %d", rc);
		goto error_ph1;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &apc_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->cs_ch[1])) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_alloc_handle(3) failed: %d", rc);
		goto error_rh0;
	}

	/* allocate the four DMA buffers, two for play and two for record */
	if (ddi_dma_mem_alloc(state->cs_ph[0], pbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_pb[0], &state->cs_pml[0],
	    &state->cs_pmh[0]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_mem_alloc(0) failed");
		goto error_rh1;
	}
	if (ddi_dma_mem_alloc(state->cs_ph[1], pbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_pb[1], &state->cs_pml[1],
	    &state->cs_pmh[1]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_mem_alloc(1) failed");
		goto error_pb0;
	}
	if (ddi_dma_mem_alloc(state->cs_ch[0], cbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_cb[0], &state->cs_cml[0],
	    &state->cs_cmh[0]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_mem_alloc(2) failed");
		goto error_pb1;
	}
	if (ddi_dma_mem_alloc(state->cs_ch[1], cbuf_size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &state->cs_cb[1], &state->cs_cml[1],
	    &state->cs_cmh[1]) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_mem_alloc(3) failed");
		goto error_rb0;
	}

	/* bind each of the buffers to a DMA handle */
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ph[0], (struct as *)0,
	    state->cs_pb[0], state->cs_pml[0], DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, (caddr_t)0, &state->cs_pc[0],
	    &dma_cookie_count)) != DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_addr_bind_handle(0) failed: %d",
		    rc);
		goto error_rb1;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ph[1], (struct as *)0,
	    state->cs_pb[1], state->cs_pml[1], DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, (caddr_t)0, &state->cs_pc[1],
	    &dma_cookie_count)) != DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_addr_bind_handle(1) failed: %d",
		    rc);
		goto error_pc0;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ch[0], (struct as *)0,
	    state->cs_cb[0], state->cs_cml[0], DDI_DMA_READ,
	    DDI_DMA_SLEEP, (caddr_t)0, &state->cs_cc[0],
	    &dma_cookie_count)) != DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_addr_bind_handle(2) failed: %d",
		    rc);
		goto error_pc1;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->cs_ch[1], (struct as *)0,
	    state->cs_cb[1], state->cs_cml[1], DDI_DMA_READ,
	    DDI_DMA_SLEEP, (caddr_t)0, &state->cs_cc[1],
	    &dma_cookie_count)) != DDI_DMA_MAPPED) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_dma_addr_bind_handle(3) failed: %d",
		    rc);
		goto error_rc0;
	}
	ASSERT(dma_cookie_count == 1);

	/* map in the registers, getting a handle */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&state->cs_regs, 0,
	    sizeof (cs4231_regs_t), &acc_attr, handle) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_map_regs() ddi_regs_map_setup() failed: %d", rc);
		goto error_rc1;
	}

	/* clear the CSR so we have all interrupts disabled */
	ddi_put32(*handle, &APC_DMACSR, APC_CLEAR_RESET_VALUE);

	/* let the state structure know about the attributes */
	state->cs_dma_attr = &apc_attr;

	/* we start with play and record buffers 0 */
	state->cs_pbuf_toggle = 0;
	state->cs_cbuf_toggle = 0;

	ATRACE("apc_map_regs() returning success", state);

	return (AUDIO_SUCCESS);

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
	ATRACE("apc_map_regs() returning failure", state);

	return (AUDIO_FAILURE);

}	/* apc_map_regs() */

/*
 * apc_unmap_regs()
 *
 * Description:
 *	This routine unbinds the DMA cookies, frees the DMA buffers,
 *	deallocated the DMA handles, and finally unmaps the Codec's and
 *	DMA engine's registers.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
apc_unmap_regs(CS_state_t *state)
{
	ATRACE("in apc_unmap_regs()", state);

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

	ddi_regs_map_free(&APC_HANDLE);

	ATRACE("apc_unmap_regs() returning", state);

}	/* apc_unmap_regs() */

/*
 * apc_reset()
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
apc_reset(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;

	ATRACE("in apc_reset()", state);

	/*
	 * The APC has a bug where the reset is not done
	 * until you do the next pio to the APC. This
	 * next write to the CSR causes the posted reset to
	 * happen.
	 */

	ddi_put32(handle, &APC_DMACSR, APC_RESET);
	ddi_put32(handle, &APC_DMACSR, APC_CLEAR_RESET_VALUE);

	ATRACE("apc_reset() returning", state);

}	/* apc_reset() */

/*
 * apc_add_intr()
 *
 * Description:
 *	Register the APC interrupts with the kernel.
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
apc_add_intr(CS_state_t *state)
{
	dev_info_t	*dip = state->cs_dip;

	ATRACE("in apc_add_intr()", state);

	/* first we make sure this isn't a high level interrupt */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_add_intr() unsupported high level interrupt");
		return (AUDIO_FAILURE);
	}

	/* okay to register the interrupt */
	if (ddi_add_intr(dip, 0, (ddi_iblock_cookie_t *)NULL,
	    (ddi_idevice_cookie_t *)NULL, apc_intr,
	    (caddr_t)state) != DDI_SUCCESS) {
		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!apc_add_intr() bad interrupt specification");
		return (AUDIO_FAILURE);
	}

	ATRACE("apc_add_intr() returning successful", state);

	return (AUDIO_SUCCESS);

}	/* apc_add_intr() */

/*
 * apc_rem_intr()
 *
 * Description:
 *	Unregister the APC interrupts from the kernel.
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
apc_rem_intr(dev_info_t *dip)
{
	ATRACE("in apc_rem_intr()", dip);

	ddi_remove_intr(dip, 0, NULL);

	ATRACE("apc_rem_intr() returning", dip);

}	/* apc_rem_intr() */

/*
 * apc_p_start()
 *
 * Description:
 *	This routine starts the play DMA engine. This includes "hard" starts
 *	where the DMA engine's registers need to be loaded as well as starting
 *	after a pause.
 *
 *	For hard starts the DMA engine is started by programming the Play Next
 *	Virtual Address and then the Play Next Counter twice, and finally
 *	enabling the play DMA engine.
 *
 *	Starting after a pause is much eaiser, we just turn on the DMA GO bit.
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
apc_p_start(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;
	int			i;
	int			samples;

	ATRACE("in apc_p_start()", state);
	ASSERT(mutex_owned(&state->cs_lock));

	/* figure out the number of samples we want */
	samples = state->cs_play_sr * state->cs_play_ch /
	    state->cs_ad_info.ad_play.ad_int_rate;
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples % state->cs_play_ch) == 1) {
		ATRACE("apc_p_start() samples not mod", samples);
		/* need to adjust */
		samples++;
	}
	ATRACE("apc_p_start() samples per interrupt", samples);

	/* try to load 2 buffers worth to get things started */
	for (i = 0; i < 2; i++) {
		ATRACE_32("apc_p_start() calling apc_program_play()", samples);
		PLAY_COUNT = samples *
		    (state->cs_play_prec >> AUDIO_PRECISION_SHIFT);
		if (apc_program_play(state, samples, NULL, 0) <= 0) {
			ATRACE("apc_p_start() "
			    "apc_program_play() returns no samples", state);
			break;
		}
	}

	/*
	 * If there wasn't anything to get then we aren't active. This can
	 * happen if an AUDIO_DRAIN was issued with no audio in the stream.
	 */
	if (i == 0) {
		ATRACE("apc_p_start() nothing to do", state);
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
	ATRACE_8("apc_p_start() Read the Codec status reg, clearing Index 11",
	    ddi_get8(handle, &CS4231_STATUS));
#else
	(void) ddi_get8(handle, &CS4231_STATUS); /* we only need a read */
#endif

	ATRACE("apc_p_start() turn on play DMA engine", state);
	OR_SET_WORD(handle, &APC_DMACSR, APC_PLAY_ENABLE);

	state->cs_flags |= PDMA_ENGINE_INITIALIZED;

	ATRACE("apc_p_start() returning", state);

	return (AUDIO_SUCCESS);

}	/* apc_p_start() */

/*
 * apc_p_pause()
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
apc_p_pause(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;
	int			x;
	uint8_t			creg;

	ATRACE("in apc_p_pause()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* clear the PDMA_GO bit, pausing the DMA engine */
	AND_SET_WORD(handle, &APC_DMACSR, ~APC_PDMA_GO);

	/* we wait for the Codec FIFO to underrun */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, ESI_REG,
	    __LINE__, thisfile);
	creg = ddi_get8(handle, &CS4231_IDR);
	for (x = 0; !(creg & ESI_PUR) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		creg = ddi_get8(handle, &CS4231_IDR);
	}

	/* stop the Codec */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_PEN, INTC_VALID_MASK);

	ATRACE("apc_p_pause() returning", state);

}	/* apc_p_pause() */

/*
 * apc_p_restart()
 *
 * Description:
 *	This routine restarts the play DMA engine after pauseing. Buffers,
 *	FIFO, etc. Must be programmed and valid.
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
apc_p_restart(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;

	ATRACE("in apc_p_restart()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* start the Codec */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	OR_SET_BYTE(handle, &CS4231_IDR, INTC_PEN, INTC_VALID_MASK);

	/* set the PDMA_GO bit, restarting the DMA engine */
	OR_SET_WORD(handle, &APC_DMACSR, APC_PDMA_GO);

	ATRACE("apc_p_restart() returning", state);

}	/* apc_p_restart() */

/*
 * apc_p_stop()
 *
 * Description:
 *	This routine stops the play DMA engine.
 *
 *	The DMA engine is stopped by using the PLAY_ABORT bit.
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
apc_p_stop(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint_t			reg;
	int			x;
	uint8_t			creg;

	ATRACE("in apc_p_stop()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* Set stopped flag */
	state->cs_flags |= APC_P_STOPPED;

	/* set the play abort bit to stop playing audio */
	OR_SET_WORD(handle, &APC_DMACSR, APC_P_ABORT)

	/* wait for the pipeline to empty */
	reg = ddi_get32(handle, &APC_DMACSR);
	for (x = 0; !(reg & APC_PM) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		reg = ddi_get32(handle, &APC_DMACSR);
	}

#ifdef DEBUG
	if (x >= CS4231_TIMEOUT) {
		ATRACE("apc_p_stop() timeout", state);
	}
#endif

	/* now clear the play enable and abort bits */
	AND_SET_WORD(handle, &APC_DMACSR, ~(APC_PDMA_GO|APC_P_ABORT));

	/* we wait for the Codec FIFO to underrun */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, ESI_REG,
	    __LINE__, thisfile);
	creg = ddi_get8(handle, &CS4231_IDR);
	for (x = 0; !(creg & ESI_PUR) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		creg = ddi_get8(handle, &CS4231_IDR);
	}

	/* stop the Codec */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_PEN, INTC_VALID_MASK);

	state->cs_flags &= ~PDMA_ENGINE_INITIALIZED;

	ATRACE("apc_p_stop() returning", state);

}	/* apc_p_stop() */

/*
 * apc_r_start()
 *
 * Description:
 *	This routine starts the record DMA engine. The DMA engine is never
 *	paused for record, so a pause is equivalent to a stop. Thus all starts
 *	are hard starts.
 *
 *	For hard starts the DMA engine is started by programming the Record
 *	Next Virtual Address and then the Record Next Counter twice, and
 *	finally enabling the record DMA engine.
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
apc_r_start(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint_t			csr;
	int			bytes;
	int			i;
	int			samples;
	int			x;

	ATRACE("in apc_r_start()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* figure out the number of samples to capture */
	samples = state->cs_record_sr * state->cs_record_ch /
	    state->cs_ad_info.ad_record.ad_int_rate;
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples % state->cs_record_ch) == 1) {
		ATRACE("apc_r_start() samples not mod", samples);
		/* need to adjust */
		samples++;
	}
	ATRACE("apc_r_start() samples per interrupt", samples);

	/* now convert the number of samples to the "size" in bytes */
	ASSERT(state->cs_record_prec == AUDIO_PRECISION_8 ||
	    state->cs_record_prec == AUDIO_PRECISION_16);
	bytes = samples * (state->cs_record_prec >> AUDIO_PRECISION_SHIFT);
	ATRACE("apc_r_start() DMA count", bytes);

	/* make sure it's okay to program the Next Address/Count registers */
	csr = ddi_get32(handle, &APC_DMACSR);
	ATRACE_32("apc_r_start() CSR", csr);
	for (x = 0; !(csr & APC_CD) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* no reason to beat on the bus */
		csr = ddi_get32(handle, &APC_DMACSR);
	}
	if (x >= CS4231_TIMEOUT) {
		audio_sup_log(state->cs_ahandle, CE_NOTE, "!apc_r_start() "
		    "timeout waiting for Codec, record not started!");
		return (AUDIO_FAILURE);
	}

	/*
	 * Program the DMA engine with both buffers. We MUST do both buffers
	 * otherwise CAP_COUNT isn't going to set both byte counts.
	 */
	for (i = 0; i < 2; i++) {
		/* read the CNVA, as per APC document */
		(void) ddi_get32(handle, &APC_DMACNVA);

		/* sync the DMA buffer before it is going to be used */
		ATRACE("apc_r_start() dma buffer sync", state);
		if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0,
		    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
			audio_sup_log(state->cs_ahandle, CE_NOTE,
			    "!apc_r_start() ddi_dma_sync() failed, recording "
			    "stopped");

			/* send a cap. abort, this leaves the DMA engine ok */
			OR_SET_WORD(handle, &APC_DMACSR, APC_C_ABORT);

			/* wait for the pipeline to empty */
			csr = ddi_get32(handle, &APC_DMACSR);
			for (x = 0; !(csr & APC_CX) && x < CS4231_TIMEOUT;
			    x++) {
				drv_usecwait(1);	/* don't beat on bus */
				csr = ddi_get32(handle, &APC_DMACSR);
			}

			/* now clear it */
			AND_SET_WORD(handle, &APC_DMACSR, ~APC_C_ABORT);

			return (AUDIO_FAILURE);
		}

		ATRACE_32("apc_r_start() next address",
		    (uint_t)CAP_DMA_COOKIE.dmac_address);
		ddi_put32(handle, &APC_DMACNVA,
		    (uint_t)CAP_DMA_COOKIE.dmac_address);

		/* now program the CNC reg., which enables the state machine */
		ATRACE_32("apc_r_start() next count", (uint_t)(bytes));
		ddi_put32(handle, &APC_DMACNC, (uint_t)(bytes));
		CAP_COUNT = bytes;

		/* now get ready for the next DMA buffer */
		AUDIO_TOGGLE(state->cs_cbuf_toggle);
		ATRACE_32("apc_r_start() new toggle", state->cs_cbuf_toggle);
	}

	state->cs_flags |= RDMA_ENGINE_INITIALIZED;

	/* start the DMA engine */
	OR_SET_WORD(handle, &APC_DMACSR, APC_CAP_ENABLE);
	ATRACE("apc_r_start() returning success", 0);

	return (AUDIO_SUCCESS);

}	/* apc_r_start() */

/*
 * apc_r_stop()
 *
 * Description:
 *	This routine stops the record DMA engine. It then sends any collected
 *	data to the audio mixer.
 *
 *	The DMA engine is stopped by using the CAP_ABORT bit.
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
apc_r_stop(CS_state_t *state)
{
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint_t			reg;
	int			samples;
	int			x;

	ATRACE("in apc_r_stop()", state);

	ASSERT(mutex_owned(&state->cs_lock));

	/* clear the record interrupts so the ISR doesn't get involved */
	AND_SET_WORD(handle, &APC_DMACSR, ~APC_CINTR_ENABLE);

	/* first, abort the record DMA engine */
	OR_SET_WORD(handle, &APC_DMACSR, APC_C_ABORT);

	/* wait for the pipeline to empty */
	reg = ddi_get32(handle, &APC_DMACSR);
	for (x = 0; !(reg & APC_CX) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		reg = ddi_get32(handle, &APC_DMACSR);
	}

#ifdef DEBUG
	if (x >= CS4231_TIMEOUT) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "apc_r_stop() timeout, record buffer flushed");
	}
#endif

	/* clear the CXI interrupt bit, but CXI interrupt didn't go out */
	OR_SET_WORD(handle, &APC_DMACSR, APC_CXI_EN);

	/* stop the Codec */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_CEN, INTC_VALID_MASK);

	/* figure how many samples were recorded */
	samples = (CAP_COUNT - ddi_get32(handle, &APC_DMACC)) /
	    (state->cs_record_prec >> AUDIO_PRECISION_SHIFT);

	/* send the captured audio to the mixer */
	if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0, DDI_DMA_SYNC_FORCPU) ==
	    DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!apc_r_stop() ddi_dma_sync() failed, recorded audio lost");
	} else {
		mutex_exit(&state->cs_lock);
		am_send_audio(state->cs_ahandle, CAP_DMA_BUF, AUDIO_NO_CHANNEL,
		    samples);
		mutex_enter(&state->cs_lock);
	}

	AND_SET_WORD(handle, &APC_DMACSR, ~(APC_C_ABORT|APC_CAP_DISABLE));

	/* check that the pipeline is empty */
	reg = ddi_get32(handle, &APC_DMACSR);
	for (x = 0; !(reg & APC_CD) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on bus */
		reg = ddi_get32(handle, &APC_DMACSR);
	}

#ifdef DEBUG
	if (x >= CS4231_TIMEOUT) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "apc_r_stop() buffer pipeline not empty");
	}
#endif

	state->cs_flags &= ~RDMA_ENGINE_INITIALIZED;

	ATRACE("apc_r_stop() returning", state);

}	/* apc_r_stop() */

/*
 * apc_power()
 *
 * Description:
 *	This routine turns the Codec off by using the COD_PDWN bit in the
 *	apc chip. To turn power on we have to reset the APC, which clears
 *	the COD_PDWN bit. However, this is a settling bug in the APC which
 *	requires the driver to delay quite a while before we may continue.
 *	Since this is the first time this feature has actually been used
 *	it isn't too surprising that it has some problems.
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
apc_power(CS_state_t *state, int level)
{
	ddi_acc_handle_t	handle = APC_HANDLE;

	ATRACE("in apc_power()", state);
	ATRACE_32("apc_power() level", level);

	ASSERT(mutex_owned(&state->cs_lock));

	if (level == CS4231_PWR_ON) {	/* turn power on */
		AND_SET_WORD(handle, &APC_DMACSR, ~APC_COD_PDWN);
		OR_SET_WORD(handle, &APC_DMACSR, APC_RESET);
		AND_SET_WORD(handle, &APC_DMACSR, ~APC_RESET);

		/*
		 * wait for state change,
		 * __lock_lint tells warlock not to flag this delay()
		 */
#ifndef __lock_lint
		delay(drv_usectohz(CS4231_300MS));
#endif
		state->cs_powered = CS4231_PWR_ON;
	} else {	/* turn power off */
		ASSERT(level == CS4231_PWR_OFF);
		OR_SET_WORD(handle, &APC_DMACSR, APC_COD_PDWN);
		state->cs_powered = CS4231_PWR_OFF;
	}

	ATRACE_32("apc_power() done", ddi_get32(handle, &APC_DMACSR));

}	/* apc_power() */


/* *******  Local Routines ************************************************** */

/*
 * apc_intr()
 *
 * Description:
 *	APC interrupt service routine, which services both play and capture
 *	interrupts. First we find out why there was an interrupt, then we
 *	take the appropriate action.
 *
 *	Because this ISR deals with both play and record interrupts we have
 *	to be careful to not lose an interrupt. So we service the record
 *	interrupt first and save the incoming data until later. This is all
 *	done without releasing the lock, thus there can be no race conditions.
 *	Then we process the play interrupt. While processing the play interrupt
 *	we have to release the lock. When this happens we send recorded data
 *	to the mixer and then get the next chunk of data to play. If there
 *	wasn't a play interrupt then we finish by sending the recorded data,
 *	if any.
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
apc_intr(caddr_t T)
{
	CS_state_t		*state = (CS_state_t *)T;
	ddi_acc_handle_t	handle = APC_HANDLE;
	caddr_t			rec_buf = NULL;
	uint_t			csr;
	uint_t			reg;
	int			rc = DDI_INTR_UNCLAIMED;
	int			rec_samples;
	int			samples;
	int			x;
	uint8_t			creg;

	ATRACE("in apc_intr()", state);

	/* the state must be protected */
	mutex_enter(&state->cs_lock);

	/* get the APC CSR */
	csr = ddi_get32(handle, &APC_DMACSR);
	ATRACE_32("apc_intr() interrupt CSR", csr);

	/* make sure this device sent the interrupt */
	if (!(csr & APC_IP)) {
		/* Interrupt received when stopping play */
		if (state->cs_flags & APC_P_STOPPED) {
			/* Clear stopped flag */
			state->cs_flags &= ~APC_P_STOPPED;
			mutex_exit(&state->cs_lock);
			return (DDI_INTR_CLAIMED);
		} else if (csr & APC_PMI_EN) {
			/*
			 * Clear device generated interrupt while play is
			 * active (Only seen while playing and insane mode
			 * switching)
			 */
			mutex_exit(&state->cs_lock);
			return (DDI_INTR_CLAIMED);
		} else {
			/* nope, this isn't our interrupt */
			mutex_exit(&state->cs_lock);
			ATRACE_32("apc_intr() device didn't send interrupt",
			    csr);
			return (DDI_INTR_UNCLAIMED);
		}
	}

	/* Clear stopped flag */
	state->cs_flags &= ~APC_P_STOPPED;

	/* clear all interrupts we captured this time */
	ddi_put32(handle, &APC_DMACSR, csr);
	ATRACE_32("apc_intr() csr after clear", ddi_get32(handle, &APC_DMACSR));

	if (csr & APC_CINTR_MASK) {
		ATRACE("apc_intr(R) record interrupt", state);

		/* sync DMA memory before sending it to the audio mixer */
		if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0,
		    DDI_DMA_SYNC_FORCPU) == DDI_FAILURE) {
			audio_sup_log(state->cs_ahandle, CE_NOTE,
			    "!apc_intr(R) ddi_dma_sync(#1) failed, recorded "
			    "audio lost");
		} else {
			/* figure how many samples were recorded */
			ASSERT(ddi_get32(handle, &APC_DMACSR) & APC_CD);
			samples = CAP_COUNT /
			    (state->cs_record_prec >> AUDIO_PRECISION_SHIFT);

			/* save the data for when we free the lock */
			rec_buf = CAP_DMA_BUF;
			rec_samples = samples;
		}

		/* sync the DMA buffer before it is going to be reused */
		ATRACE("apc_intr(R) dma buffer sync", state);
		if (ddi_dma_sync(CAP_DMA_HANDLE, (off_t)0, 0,
		    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
			audio_sup_log(state->cs_ahandle, CE_NOTE,
			    "!apc_intr(R) ddi_dma_sync(#2) failed, recording "
			    "disabled");

			/* send a play abort, this leaves the DMA engine ok */
			OR_SET_WORD(handle, &APC_DMACSR, APC_C_ABORT);

			/* now clear it */
			AND_SET_WORD(handle, &APC_DMACSR, ~APC_C_ABORT);
		} else {
			ATRACE_32("apc_intr(R) next address",
			    (uint_t)CAP_DMA_COOKIE.dmac_address);

			/* read the CNVA, as per APC document */
			(void) ddi_get32(handle, &APC_DMACNVA);

			/* now program the DMA buffer into the Next Address */
			ddi_put32(handle, &APC_DMACNVA,
			    (uint_t)CAP_DMA_COOKIE.dmac_address);

			/* program the CNC reg., which enables the state mach */
			ATRACE_32("apc_intr(R) next count", (uint_t)CAP_COUNT);
			ddi_put32(handle, &APC_DMACNC, (uint_t)CAP_COUNT);

			/* now get ready for the next DMA buffer */
			AUDIO_TOGGLE(state->cs_cbuf_toggle);
			ATRACE_32("apc_intr(R) new toggle",
			    state->cs_cbuf_toggle);

		}
		/* we always claim the interrupt, even if DMA sync failed */
		rc = DDI_INTR_CLAIMED;
	}

	if (csr & APC_PINTR_MASK) {
		/* figure out the number of samples we want */
		samples = PLAY_COUNT /
		    (state->cs_play_prec >> AUDIO_PRECISION_SHIFT);
		ATRACE_32("apc_intr(P) samples to get", samples);

		/* try to load the next audio buffer, even if pipe is empty */
		samples = apc_program_play(state, samples, &rec_buf,
		    rec_samples);
		ATRACE_32("apc_intr(P) samples apc_program_play() returned",
		    samples);

		if (samples <= 0 && (csr & APC_PM)) {
			/*
			 * There isn't any more data to play, so wait for
			 * the pipe and the Codec FIFO to empty. Then turn
			 * off the play DMA engine by aborting. Also, we should
			 * note that simple play interrupts with no samples
			 * are ignored, but acknowledged. We wait for the pipe
			 * to empty before we declare the DMA engine is empty.
			 */
			ATRACE_32("apc_intr(P) no more data, wait for FIFO",
			    samples);

			/*
			 * We wait for the Codec FIFO to underrun, this
			 * implies that the APC pipe is also empty.
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
			ATRACE("apc_intr(P) shutdown play stream", state);
			mutex_exit(&state->cs_lock);

			/* send the captured audio to the mixer ASAP */
			if (rec_buf) {
				am_send_audio(state->cs_ahandle, rec_buf,
				    AUDIO_NO_CHANNEL, rec_samples);
				rec_buf = NULL;
			}

			am_play_shutdown(state->cs_ahandle, NULL);

			mutex_enter(&state->cs_lock);

			/* make sure playing wasn't restarted when lock lost */
			if (state->cs_flags & PDMA_ENGINE_INITIALIZED) {
				/* yes, it was, so we're done */
				ATRACE("apc_intr() restart after shutdown", 0);
				rc = DDI_INTR_CLAIMED;
				goto done;
			}

			/* reset the DMA engine, putting it in a known state */
			OR_SET_WORD(handle, &APC_DMACSR, APC_P_ABORT);

			/* wait for the pipeline to empty */
			reg = ddi_get32(handle, &APC_DMACSR);
			for (x = 0; !(reg & APC_PD) && x < CS4231_TIMEOUT;
			    x++) {
				drv_usecwait(1);	/* don't beat on bus */
				reg = ddi_get32(handle, &APC_DMACSR);
			}

			/* clear the abort bit */
			AND_SET_WORD(handle, &APC_DMACSR, ~APC_P_ABORT);

			/* disable the Codec */
			cs4231_reg_select(state->cs_ahandle, handle,
			    &CS4231_IAR, INTC_REG, __LINE__, thisfile);
			AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_PEN,
			    INTC_VALID_MASK);

			/* and reset the status */
			ddi_put8(handle, &CS4231_STATUS, STATUS_RESET);

			ATRACE("apc_intr(P) Play DMA engine off", state);
		}
		rc = DDI_INTR_CLAIMED;
		ATRACE_32("apc_intr(P) done", rc);
	}

done:

	/* APC error interrupt, not sure what to do here */
	if (csr & APC_EI) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!apc_intr() error interrupt: 0x%x", csr);
		rc = DDI_INTR_CLAIMED;
	}

	/* update the kernel interrupt statistics */
	if (state->cs_ksp) {
		if (rc == DDI_INTR_CLAIMED) {
			KIOP(state)->intrs[KSTAT_INTR_HARD]++;
		}
	}

	mutex_exit(&state->cs_lock);

	/* one last chance to send the captured audio to the mixer */
	if (rec_buf) {
		am_send_audio(state->cs_ahandle, rec_buf, AUDIO_NO_CHANNEL,
		    rec_samples);
	}

	ATRACE_32("apc_intr() returning", rc);

	return (rc);

}	/* apc_intr() */

/*
 * apc_program_play()
 *
 * Description:
 *	This routine is used by apc_p_start() and apc_intr() to program
 *	the play DMA engine with the next buffer full of audio.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state pointer
 *	int		samples		The number of samples to be retrieved
 *					from the mixer
 *	caddr_t		*rec_buf	Ptr to data buffer for record
 *	int		rec_samples	Num samples in record data buffer
 *
 * Returns:
 *	0			The buffer wasn't programmed, no audio
 *	> 0			The buffer was programmed
 *	AUDIO_FAILURE		The buffer wasn't programmed
 */
static int
apc_program_play(CS_state_t *state, int samples, caddr_t *rec_buf,
	int rec_samples)
{
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint_t			precision;
	int			rc;

	ATRACE_32("in apc_program_play()", samples);

	/* we need the precision to calculate the next count correctly */
	precision = state->cs_play_prec >> AUDIO_PRECISION_SHIFT;
	ATRACE_32("apc_program_play() precision", precision);

	/* send record audio, then get the first buffer's worth of audio */
	mutex_exit(&state->cs_lock);

	/* send the captured audio to the mixer */
	if (rec_buf && *rec_buf) {
		am_send_audio(state->cs_ahandle, *rec_buf, AUDIO_NO_CHANNEL,
		    rec_samples);
		*rec_buf = NULL;
	}

	rc = am_get_audio(state->cs_ahandle, PLAY_DMA_BUF, AUDIO_NO_CHANNEL,
	    samples);

	mutex_enter(&state->cs_lock);
	ATRACE_32("apc_program_play() am_get_audio() returned", rc);

	if (rc == AUDIO_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!apc_program_play() am_get_audio() failed");
		return (AUDIO_FAILURE);
	} else if (rc == 0) {
		ATRACE("apc_program_play() am_get_audio() returned 0 samples",
		    state);
		return (0);
	}

	/* sync the DMA buffer before it is going to be used */
	ATRACE("apc_program_play() dma buffer sync", state);
	if (ddi_dma_sync(PLAY_DMA_HANDLE, (off_t)0, (size_t)(rc * precision),
	    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
		audio_sup_log(state->cs_ahandle, CE_NOTE,
		    "!apc_program_play() ddi_dma_sync(#2) failed, audio lost");

		/* send a play abort, this leaves the DMA engine ok */
		OR_SET_WORD(handle, &APC_DMACSR, APC_P_ABORT);
		/* now clear it */
		AND_SET_WORD(handle, &APC_DMACSR, ~APC_P_ABORT);

		return (AUDIO_FAILURE);
	}

	/* program the PNVA */
	ATRACE_32("apc_program_play() next address",
	    (uint_t)PLAY_DMA_COOKIE.dmac_address);
	ddi_put32(handle, &APC_DMAPNVA, (uint_t)PLAY_DMA_COOKIE.dmac_address);

	/* now program the PNC register, which enables the state machine */
	ATRACE_32("apc_program_play() next count", (uint_t)(rc * precision));
	ddi_put32(handle, &APC_DMAPNC, (uint_t)(rc * precision));

	/* now get ready for the next time we need a DMA buffer */
	AUDIO_TOGGLE(state->cs_pbuf_toggle);
	ATRACE_32("apc_program_play() new toggle", state->cs_pbuf_toggle);

	ATRACE_32("apc_program_play() returning", rc);

	return (rc);

}	/* apc_program_play() */
