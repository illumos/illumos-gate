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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Platform specifc code for the EB2 DMA controller. The EB2 is a PCI bus
 * IC that includes play and record DMA engines and an interface for
 * the CS4231.
 */

#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include "audio_4231.h"

/*
 * Attribute structure for the APC, used to create DMA handles.
 */
static ddi_dma_attr_t eb2_dma_attr = {
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

static ddi_device_acc_attr_t codec_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t eb2_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA ops vector functions
 */
static int eb2_map_regs(CS_state_t *);
static void eb2_unmap_regs(CS_state_t *);
static void eb2_reset(CS_state_t *);
static int eb2_start_engine(CS_engine_t *);
static void eb2_stop_engine(CS_engine_t *);
static void eb2_power(CS_state_t *, int);
static void eb2_reload(CS_engine_t *);
static uint32_t eb2_addr(CS_engine_t *);

cs4231_dma_ops_t cs4231_eb2dma_ops = {
	"EB2 DMA controller",
	&eb2_dma_attr,
	eb2_map_regs,
	eb2_unmap_regs,
	eb2_reset,
	eb2_start_engine,
	eb2_stop_engine,
	eb2_power,
	eb2_reload,
	eb2_addr,
};

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
 *	CS_state_t	*state		The device's state
 *
 * Returns:
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
eb2_map_regs(CS_state_t *state)
{
	dev_info_t	*dip = state->cs_dip;

	/* now, map the codec */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&state->cs_regs, 0,
	    sizeof (cs4231_pioregs_t), &codec_attr, &CODEC_HANDLE) !=
	    DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "failed mapping codec regs");
		goto error;
	}

	/* next the play registers */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&state->cs_eb2_regs.play, 0,
	    sizeof (cs4231_eb2regs_t), &eb2_attr, &EB2_PLAY_HNDL) !=
	    DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "failed mapping play regs");
		goto error;
	}
	state->cs_engines[CS4231_PLAY]->ce_regsh = EB2_PLAY_HNDL;
	state->cs_engines[CS4231_PLAY]->ce_eb2regs = state->cs_eb2_regs.play;

	/* now the capture registers */
	if (ddi_regs_map_setup(dip, 2, (caddr_t *)&state->cs_eb2_regs.record, 0,
	    sizeof (cs4231_eb2regs_t), &eb2_attr, &EB2_REC_HNDL) !=
	    DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "failed mapping rec regs");
		goto error;
	}
	state->cs_engines[CS4231_REC]->ce_regsh = EB2_REC_HNDL;
	state->cs_engines[CS4231_REC]->ce_eb2regs = state->cs_eb2_regs.record;

	/* finally the auxio register */
	if (ddi_regs_map_setup(dip, 3, (caddr_t *)&state->cs_eb2_regs.auxio, 0,
	    sizeof (uint_t), &eb2_attr, &EB2_AUXIO_HNDL) != DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "failed mapping auxio reg");
		goto error;
	}

	/* disable play and record interrupts */
	ddi_put32(EB2_PLAY_HNDL, &EB2_PLAY_CSR, EB2_PCLEAR_RESET_VALUE);
	ddi_put32(EB2_REC_HNDL, &EB2_REC_CSR, EB2_RCLEAR_RESET_VALUE);

	return (DDI_SUCCESS);

error:
	eb2_unmap_regs(state);
	return (DDI_FAILURE);

}	/* eb2_map_regs() */

/*
 * eb2_unmap_regs()
 *
 * Description:
 *	This routine unmaps the Codec's and DMA engine's registers.
 *	It must be idempotent.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state
 */
static void
eb2_unmap_regs(CS_state_t *state)
{
	if (CODEC_HANDLE)
		ddi_regs_map_free(&CODEC_HANDLE);
	if (EB2_PLAY_HNDL)
		ddi_regs_map_free(&EB2_PLAY_HNDL);
	if (EB2_REC_HNDL)
		ddi_regs_map_free(&EB2_REC_HNDL);
	if (EB2_AUXIO_HNDL)
		ddi_regs_map_free(&EB2_AUXIO_HNDL);

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
 */
static void
eb2_reset(CS_state_t *state)
{
	ddi_acc_handle_t	phandle = EB2_PLAY_HNDL;
	ddi_acc_handle_t	rhandle = EB2_REC_HNDL;
	uint_t			reg;
	int			x;

	/* start with the play side */
	ddi_put32(phandle, &EB2_PLAY_CSR, EB2_RESET);
	/* wait for play data to drain */
	reg = ddi_get32(phandle, &EB2_PLAY_CSR);
	for (x = 0; (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on the bus */
		reg = ddi_get32(phandle, &EB2_PLAY_CSR);
	}
	/* clear the reset bit and program for chaining */
	ddi_put32(phandle, &EB2_PLAY_CSR, EB2_PCLEAR_RESET_VALUE);

	/* now do the record side and program for chaining */
	ddi_put32(rhandle, &EB2_REC_CSR, EB2_RESET);
	/* wait for record data to drain */
	reg = ddi_get32(rhandle, &EB2_REC_CSR);
	for (x = 0; (reg & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* don't beat on the bus */
		reg = ddi_get32(rhandle, &EB2_REC_CSR);
	}
	/* clear the reset bit */
	ddi_put32(rhandle, &EB2_REC_CSR, EB2_RCLEAR_RESET_VALUE);

}	/* eb2_reset() */

/*
 * eb2_start_engine()
 *
 * Description:
 *	This routine starts the DMA engine.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_engine_t	*eng	The DMA engine's state structure
 *
 * Returns:
 *	DDI_SUCCESS		The DMA engine was started
 *	DDI_FAILURE		The DMA engine was not started
 */
static int
eb2_start_engine(CS_engine_t *eng)
{
	CS_state_t		*state = eng->ce_state;
	ddi_acc_handle_t	handle = eng->ce_regsh;
	cs4231_eb2regs_t	*regs = eng->ce_eb2regs;
	uint_t			csr;
	int			x;
	uint32_t		reset;
	uint32_t		enable;

	if (eng->ce_num == CS4231_PLAY) {
		reset = EB2_PCLEAR_RESET_VALUE;
		enable = EB2_PLAY_ENABLE;
	} else {
		reset = EB2_RCLEAR_RESET_VALUE;
		enable = EB2_REC_ENABLE;
	}

	ASSERT(mutex_owned(&state->cs_lock));

	/* reset the DMA engine so we have a good starting place */
	OR_SET_WORD(handle, &regs->eb2csr, EB2_RESET);

	/* wait for the FIFO to drain, it should be empty */
	csr = ddi_get32(handle, &regs->eb2csr);
	for (x = 0; (csr & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* no reason to beat on the bus */
		csr = ddi_get32(handle, &regs->eb2csr);
	}
	if (x >= CS4231_TIMEOUT) {
		audio_dev_warn(state->cs_adev,
		    "timeout waiting for engine, not started!");
		return (DDI_FAILURE);
	}

	/* now clear the RESET and EN_DMA bits */
	AND_SET_WORD(handle, &regs->eb2csr, ~(EB2_RESET|EB2_EN_DMA));

	/* put into chaining mode, enable byte counts  */
	OR_SET_WORD(handle, &regs->eb2csr, reset);

	/*
	 * Program the DMA engine.
	 */
	eb2_reload(eng);

	/*
	 * Start playing before we load the next fragment.
	 */
	OR_SET_WORD(handle, &regs->eb2csr, enable);

	/*
	 * Program the next address, too.
	 */
	eb2_reload(eng);

	return (DDI_SUCCESS);

}	/* eb2_start_engine() */

/*
 * eb2_stop_engine()
 *
 * Description:
 *	This routine stops the DMA engine.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_engine_t	*eng	The engine to stop
 */
static void
eb2_stop_engine(CS_engine_t *eng)
{
	ddi_acc_handle_t	handle = eng->ce_regsh;
	cs4231_eb2regs_t	*regs = eng->ce_eb2regs;
	uint_t			csr;

	/* shut off DMA and disable interrupts */
	AND_SET_WORD(handle, &regs->eb2csr, ~(EB2_EN_DMA | EB2_INT_EN));

	csr = ddi_get32(handle, &regs->eb2csr);
	for (int x = 0; (csr & EB2_CYC_PENDING) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);
		csr = ddi_get32(handle, &regs->eb2csr);
	}

	/* set the RESET bit to stop audio, also clear any TC interrupt */
	OR_SET_WORD(handle, &regs->eb2csr, EB2_RESET | EB2_TC);

	/* wait for the FIFO to drain */
	csr = ddi_get32(handle, &regs->eb2csr);
	for (int x = 0; (csr & EB2_FIFO_DRAIN) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);		/* don't beat on the bus */
		csr = ddi_get32(handle, &regs->eb2csr);
	}

	/* clear the RESET and EN_DMA bits */
	AND_SET_WORD(handle, &regs->eb2csr, ~(EB2_RESET|EB2_EN_DMA));

}	/* eb2_stop_engine() */

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
 */
static void
eb2_power(CS_state_t *state, int level)
{
	ddi_acc_handle_t	xhandle = EB2_AUXIO_HNDL;

	if (level == CS4231_PWR_ON) {	/* turn power on */
		AND_SET_WORD(xhandle, EB2_AUXIO_REG, ~EB2_AUXIO_COD_PDWN);
	} else {	/* turn power off */
		OR_SET_WORD(xhandle, EB2_AUXIO_REG, EB2_AUXIO_COD_PDWN);
	}

}	/* eb2_power() */

/*
 * eb2_reload()
 *
 * Description:
 *	This routine reloads the DMA address, so that we can continue
 *	double buffer round-robin fashion.
 *
 * Arguments:
 *	CS_engine_t	*eng		The engine
 */
static void
eb2_reload(CS_engine_t *eng)
{
	ddi_acc_handle_t	handle = eng->ce_regsh;
	cs4231_eb2regs_t	*regs = eng->ce_eb2regs;

	/* if next address already loaded, then we're done */
	if ((ddi_get32(handle, &regs->eb2csr) & EB2_NA_LOADED)) {
		return;
	}

	/*
	 * For eb2 we first program the Next Byte Count Register.
	 */
	ddi_put32(handle, &regs->eb2bcr, CS4231_FRAGSZ);

	/* now program the Next Address Register */
	ddi_put32(handle, &regs->eb2acr,
	    eng->ce_paddr + (CS4231_FRAGSZ * eng->ce_curidx));

	eng->ce_curidx++;
	eng->ce_curidx %= CS4231_NFRAGS;
}

/*
 * eb2_addr()
 *
 * Description:
 *	This routine returns the current DMA address for the engine (the
 *	next address being accessed).
 *
 * Arguments:
 *	CS_engine_t	*eng		The engine
 *
 * Returns:
 *	Physical DMA address for current transfer.
 */
static uint32_t
eb2_addr(CS_engine_t *eng)
{
	ddi_acc_handle_t	handle = eng->ce_regsh;
	cs4231_eb2regs_t	*regs = eng->ce_eb2regs;

	return (ddi_get32(handle, &regs->eb2acr));
}
