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

/*
 * Platform specifc code for the APC DMA controller. The APC is an SBus
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
static ddi_dma_attr_t apc_dma_attr = {
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
static void apc_load_fragment(CS_engine_t *);

/*
 * DMA ops vector functions
 */
static int apc_map_regs(CS_state_t *);
static void apc_unmap_regs(CS_state_t *);
static void apc_reset(CS_state_t *);
static int apc_add_intr(CS_state_t *);
static void apc_rem_intr(CS_state_t *);
static int apc_start_engine(CS_engine_t *);
static void apc_stop_engine(CS_engine_t *);
static void apc_power(CS_state_t *, int);

cs4231_dma_ops_t cs4231_apcdma_ops = {
	"APC DMA controller",
	&apc_dma_attr,
	apc_map_regs,
	apc_unmap_regs,
	apc_reset,
	apc_add_intr,
	apc_rem_intr,
	apc_start_engine,
	apc_stop_engine,
	apc_power,
};

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
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
apc_map_regs(CS_state_t *state)
{
	ddi_acc_handle_t	*handle = &APC_HANDLE;
	dev_info_t		*dip = state->cs_dip;

	/* map in the registers, getting a handle */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&state->cs_regs, 0,
	    sizeof (cs4231_regs_t), &acc_attr, handle) != DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "ddi_regs_map_setup() failed");
		return (DDI_FAILURE);
	}

	/* clear the CSR so we have all interrupts disabled */
	ddi_put32(*handle, &APC_DMACSR, APC_CLEAR_RESET_VALUE);

	return (DDI_SUCCESS);
}	/* apc_map_regs() */

/*
 * apc_unmap_regs()
 *
 * Description:
 *	This routine unmaps the Codec's and DMA engine's registers.
 *	It must be idempotent.
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
	if (APC_HANDLE)
		ddi_regs_map_free(&APC_HANDLE);

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

	/*
	 * The APC has a bug where the reset is not done
	 * until you do the next pio to the APC. This
	 * next write to the CSR causes the posted reset to
	 * happen.
	 */

	ddi_put32(handle, &APC_DMACSR, APC_RESET);
	ddi_put32(handle, &APC_DMACSR, APC_CLEAR_RESET_VALUE);

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
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
apc_add_intr(CS_state_t *state)
{
	dev_info_t	*dip = state->cs_dip;

	/* first we make sure this isn't a high level interrupt */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_dev_warn(state->cs_adev,
		    "unsupported high level interrupt");
		return (DDI_FAILURE);
	}

	/* okay to register the interrupt */
	if (ddi_add_intr(dip, 0, NULL, NULL, apc_intr, (caddr_t)state) !=
	    DDI_SUCCESS) {
		audio_dev_warn(state->cs_adev, "bad interrupt specification");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);

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
 *	CS_state_t	*state	Pointer to the device's state structure
 *
 * Returns:
 *	void
 */
static void
apc_rem_intr(CS_state_t *state)
{
	ddi_remove_intr(state->cs_dip, 0, NULL);
}	/* apc_rem_intr() */

/*
 * apc_start_engine()
 *
 * Description:
 *	This routine starts the DMA engine.
 *
 *	For hard starts the DMA engine is started by programming the
 *	Next Virtual Address and then the Next Counter twice, and
 *	finally enabling the DMA engine.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 *	CAUTION: ?!? This routine doesn't start the Codec because the first
 *		interrupt causes a recursive mutex_enter.
 *
 * Arguments:
 *	CS_engine_t	*eng	The engine to start
 *
 * Returns:
 *	DDI_SUCCESS		The DMA engine was started
 *	DDI_FAILURE		The DMA engine was not started
 */
static int
apc_start_engine(CS_engine_t *eng)
{
	CS_state_t		*state = eng->ce_state;
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint32_t		csr;
	uint32_t		enable;
	uint32_t		dirty;
	int			x;

	ASSERT(mutex_owned(&state->cs_lock));

	if (eng->ce_num == CS4231_PLAY) {
		enable = APC_PLAY_ENABLE;
		dirty = APC_PD;
	} else {
		enable = APC_CAP_ENABLE;
		dirty = APC_CD;
	}

	/* make sure it's okay to program the Next Address/Count registers */
	csr = ddi_get32(handle, &APC_DMACSR);
	for (x = 0; !(csr & dirty) && x < CS4231_TIMEOUT; x++) {
		drv_usecwait(1);	/* no reason to beat on the bus */
		csr = ddi_get32(handle, &APC_DMACSR);
	}
	if (x >= CS4231_TIMEOUT) {
		audio_dev_warn(state->cs_adev,
		    "timeout waiting for engine, not started!");
		return (DDI_FAILURE);
	}

	/*
	 * Program the first fragment.
	 */
	apc_load_fragment(eng);

	/*
	 * Start the DMA engine, including interrupts.
	 */
	OR_SET_WORD(handle, &APC_DMACSR, enable);

	/*
	 * Program the second fragment.
	 */
	apc_load_fragment(eng);

	return (DDI_SUCCESS);
}

/*
 * apc_stop_engine()
 *
 * Description:
 *	This routine stops the engine.
 *
 *	The DMA engine is stopped by using the CAP_ABORT bit.
 *
 *	NOTE: The state structure must be locked before this routine is called.
 *
 * Arguments:
 *	CS_engine_t	*eng	The engine to sotp
 *
 * Returns:
 *	void
 */
static void
apc_stop_engine(CS_engine_t *eng)
{
	CS_state_t		*state = eng->ce_state;
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint32_t		reg;
	uint32_t		intren;
	uint32_t		abort;
	uint32_t		drainbit;
	uint32_t		disable;

	ASSERT(mutex_owned(&state->cs_lock));

	if (eng->ce_num == CS4231_PLAY) {
		intren = APC_PINTR_ENABLE;
		abort = APC_P_ABORT;
		drainbit = APC_PM;
		disable = APC_PLAY_DISABLE;
	} else {
		intren = APC_CINTR_ENABLE;
		abort = APC_C_ABORT;
		drainbit = APC_CX;
		disable = APC_CAP_DISABLE;
	}

	/* clear the interrupts so the ISR doesn't get involved */
	AND_SET_WORD(handle, &APC_DMACSR, ~intren);

	/* first, abort the DMA engine */
	OR_SET_WORD(handle, &APC_DMACSR, abort);

	/* wait for the pipeline to empty */
	reg = ddi_get32(handle, &APC_DMACSR);
	for (int x = 0; (!(reg & drainbit)) && (x < CS4231_TIMEOUT); x++) {
		drv_usecwait(1);	/* don't beat on bus */
		reg = ddi_get32(handle, &APC_DMACSR);
	}

	/* now clear the enable and abort bits */
	AND_SET_WORD(handle, &APC_DMACSR, ~(abort|disable));
}


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

	if (level == CS4231_PWR_ON) {	/* turn power on */
		AND_SET_WORD(handle, &APC_DMACSR, ~APC_COD_PDWN);
		OR_SET_WORD(handle, &APC_DMACSR, APC_RESET);
		AND_SET_WORD(handle, &APC_DMACSR, ~APC_RESET);

		/*
		 * wait for state change,
		 */
		delay(drv_usectohz(CS4231_300MS));
	} else {	/* turn power off */
		ASSERT(level == CS4231_PWR_OFF);
		OR_SET_WORD(handle, &APC_DMACSR, APC_COD_PDWN);
	}

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
	CS_state_t		*state = (void *)T;
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint_t			csr;
	int			rc = DDI_INTR_UNCLAIMED;

	/* the state must be protected */
	mutex_enter(&state->cs_lock);

	if (state->cs_suspended) {
		mutex_exit(&state->cs_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* get the APC CSR */
	csr = ddi_get32(handle, &APC_DMACSR);

	/* make sure this device sent the interrupt */
	if (!(csr & APC_IP)) {
		if (csr & APC_PMI_EN) {
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
			return (DDI_INTR_UNCLAIMED);
		}
	}

	/* clear all interrupts we captured this time */
	ddi_put32(handle, &APC_DMACSR, csr);

	if (csr & APC_CINTR_MASK) {
		/* try to load the next record buffer */
		apc_load_fragment(state->cs_engines[CS4231_REC]);
		rc = DDI_INTR_CLAIMED;
	}

	if (csr & APC_PINTR_MASK) {
		/* try to load the next play buffer */
		apc_load_fragment(state->cs_engines[CS4231_PLAY]);
		rc = DDI_INTR_CLAIMED;
	}

done:

	/* APC error interrupt, not sure what to do here */
	if (csr & APC_EI) {
		audio_dev_warn(state->cs_adev, "error interrupt: 0x%x", csr);
		rc = DDI_INTR_CLAIMED;
	}

	/* update the kernel interrupt statistics */
	if (state->cs_ksp) {
		if (rc == DDI_INTR_CLAIMED) {
			KIOP(state)->intrs[KSTAT_INTR_HARD]++;
		}
	}

	mutex_exit(&state->cs_lock);

	if (csr & APC_CINTR_MASK) {
		CS_engine_t	*eng = state->cs_engines[CS4231_REC];
		if (eng->ce_started)
			audio_engine_produce(eng->ce_engine);
	}
	if (csr & APC_PINTR_MASK) {
		CS_engine_t	*eng = state->cs_engines[CS4231_PLAY];
		if (eng->ce_started)
			audio_engine_consume(eng->ce_engine);
	}

	return (rc);

}	/* apc_intr() */

static void
apc_load_fragment(CS_engine_t *eng)
{
	CS_state_t		*state = eng->ce_state;
	ddi_acc_handle_t	handle = APC_HANDLE;
	uint32_t		dirty;
	uint32_t		*nva;	/* next VA reg */
	uint32_t		*nc;	/* next count reg */

	if (eng->ce_num == CS4231_PLAY) {
		dirty = APC_PD;
		nva = &APC_DMAPNVA;
		nc = &APC_DMAPNC;
	} else {
		dirty = APC_CD;
		nva = &APC_DMACNVA;
		nc = &APC_DMACNC;
	}

	/* if we can't load another address, then don't */
	if ((ddi_get32(handle, &APC_DMACSR) & dirty) == 0) {
		return;
	}

	/* read the NVA, as per APC document */
	(void) ddi_get32(handle, nva);

	/* write the address of the next fragment */
	ddi_put32(handle, nva, eng->ce_paddr[eng->ce_cfrag]);

	/* now program the NC reg., which enables the state machine */
	ddi_put32(handle, nc, eng->ce_fragsz);

	eng->ce_cfrag++;
	eng->ce_cfrag %= CS4231_NFRAGS;
	eng->ce_count += eng->ce_fragfr;
}
