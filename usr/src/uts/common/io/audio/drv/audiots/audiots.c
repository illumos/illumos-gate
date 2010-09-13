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
 * audiots Audio Driver
 *
 * This Audio Driver controls the T2 audio core in the ALI M1553
 * southbridge chip. This chip supports multiple play streams, but just
 * a single record stream. It also supports wave table synthesis and
 * hardware MIDI and joystick ports. Unfortunately the MIDI ports are
 * not available because their pins have been re-assigned to expose
 * interrupts. We also aren't going to do anything with the joystick
 * ports. The audio core controls an AC-97 V2.1 Codec.
 *
 * The DMA engine uses a single buffer which is large enough to hold
 * two interrupts worth of data. When it gets to the mid point an
 * interrupt is generated and data is either sent (for record) or
 * requested and put in that half of the buffer (for play). When the
 * second half is played we do the same, but the audio core loops the
 * pointer back to the beginning.
 *
 * The audio core has a bug in silicon that doesn't let it read the AC-97
 * Codec's register. T2 has provided an algorithm that attempts to read the
 * the Codec several times. This is probably heuristic and thus isn't
 * absolutely guaranteed to work. However we do have to place a limit on
 * the looping, otherwise when we read a valid 0x00 we would never exit
 * the loop. Unfortunately there is also a problem with writing the AC-97
 * Codec's registers as well. Thus we read it back to verify the write.
 *
 * The AC'97 common code provides shadow state for AC'97 registers for us,
 * so we only need to read those registers during early startup (primarily
 * to determine codec id and capabilities.)
 *
 * We don't save any of the audio controller registers during normal
 * operation. When we need to save register state we only have to save
 * the aram and eram. The rest of the controller state is never modified
 * from the initial programming. Thus restoring the controller state
 * can be done from audiots_chip_init() as well.
 *
 *
 * WARNING: The SME birdsnest platform uses a PCI bridge chip between the
 *	CPU and the southbridge containing the audio core. There is
 *	a bug in silicon that causes a bogus parity error. With the mixer
 *	reimplementation project, Bug 4374774, the audio driver is always
 *	set to the best precision and number of channels. Thus when turning
 *	the mixer on and off the only thing that changes is the sample rate.
 *	This change in programming doesn't trigger the silicon error.
 *	Thus the supported channels must always be 2 and the precision
 *	must always be 16-bits. This will keep any future change in the
 *	mixer from exposing this bug.
 *
 * Due to a hardware bug, system power management is not supported by this
 * driver.
 *
 *	CAUTION: If audio controller state is changed outside of aram
 *		and eram then that information must be saved and restored
 *		during power management shutdown and bringup.
 *
 *	NOTE: The AC-97 Codec's reset pin is set to PCI reset, so we
 *		can't power down the Codec all the way.
 *
 *	NOTE: This driver depends on the drv/audio and misc/ac97
 *		modules being loaded first.
 *
 *	NOTE: Don't OR the ap_stop register to stop a play or record. This
 *		will just stop all active channels because a read of ap_stop
 *		returns ap_start. Just set the ap_stop register with the
 *		channels you want to stop. The same goes for ap_start.
 *
 *	NOTE: There is a hardware problem with P2 rev motherboards. After
 *		prolonged use, reading the AC97 register will always return
 *		busy. The AC97 register is now useless. Consequently, we are no
 *		longer able to program the Codec. This work around disables
 *		audio when this state is detected. It's not great, but its
 *		better than having audio blasting out at 100% all the time.
 *
 *	NOTE: Power Management testing has also exposed this AC97 timeout
 *		problem. Management has decided this is too risky for customers
 *		and hence they want power management support removed from the
 *		audio subsystem. All PM support is now removed.
 */

/*
 * Synchronization notes:
 *
 * The audio framework guarantees that our entry points are exclusive
 * with suspend and resume.  This includes data flow and control entry
 * points alike.
 *
 * The audio framework guarantees that only one control is being
 * accessed on any given audio device at a time.
 *
 * The audio framework guarantees that entry points are themselves
 * serialized for a given engine.
 *
 * We have no interrupt routine or other internal asynchronous routines.
 *
 * Our device uses completely separate registers for each engine,
 * except for the start/stop registers, which are implemented in a
 * manner that allows for them to be accessed concurrently safely from
 * different threads.
 *
 * Hence, it turns out that we simply don't need any locking in this
 * driver.
 */

#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>
#include "audiots.h"

/*
 * Module linkage routines for the kernel
 */
static int audiots_attach(dev_info_t *, ddi_attach_cmd_t);
static int audiots_detach(dev_info_t *, ddi_detach_cmd_t);
static int audiots_quiesce(dev_info_t *);

/*
 * Entry point routine prototypes
 */
static int audiots_open(void *, int, unsigned *, caddr_t *);
static void audiots_close(void *);
static int audiots_start(void *);
static void audiots_stop(void *);
static int audiots_format(void *);
static int audiots_channels(void *);
static int audiots_rate(void *);
static void audiots_chinfo(void *, int, unsigned *, unsigned *);
static uint64_t audiots_count(void *);
static void audiots_sync(void *, unsigned);

static audio_engine_ops_t	audiots_engine_ops = {
	AUDIO_ENGINE_VERSION,
	audiots_open,
	audiots_close,
	audiots_start,
	audiots_stop,
	audiots_count,
	audiots_format,
	audiots_channels,
	audiots_rate,
	audiots_sync,
	NULL,
	audiots_chinfo,
	NULL,
};

/*
 * Local Routine Prototypes
 */
static void audiots_power_up(audiots_state_t *);
static void audiots_chip_init(audiots_state_t *);
static uint16_t audiots_get_ac97(void *, uint8_t);
static void audiots_set_ac97(void *, uint8_t, uint16_t);
static int audiots_init_state(audiots_state_t *, dev_info_t *);
static int audiots_map_regs(dev_info_t *, audiots_state_t *);
static uint16_t audiots_read_ac97(audiots_state_t *, int);
static void audiots_stop_everything(audiots_state_t *);
static void audiots_destroy(audiots_state_t *);
static int audiots_alloc_port(audiots_state_t *, int);

/*
 * Global variables, but viewable only by this file.
 */

/* anchor for soft state structures */
static void *audiots_statep;

/*
 * DDI Structures
 */

/* Device operations structure */
static struct dev_ops audiots_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audiots_attach,		/* devo_attach */
	audiots_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	audiots_quiesce,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv audiots_modldrv = {
	&mod_driverops,		/* drv_modops */
	TS_MOD_NAME,		/* drv_linkinfo */
	&audiots_dev_ops	/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage audiots_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&audiots_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};


/*
 * NOTE: Grover OBP v4.0.166 and rev G of the ALI Southbridge chip force the
 * audiots driver to use the upper 2 GB DMA address range. However to maintain
 * backwards compatibility with older systems/OBP, we're going to try the full
 * 4 GB DMA range.
 *
 * Eventually, this will be set back to using the proper high 2 GB DMA range.
 */

/* Device attribute structure - full 4 gig address range */
static ddi_dma_attr_t audiots_attr = {
	DMA_ATTR_VERSION,		/* version */
	0x0000000000000000LL,		/* dlim_addr_lo */
	0x00000000ffffffffLL,		/* dlim_addr_hi */
	0x0000000000003fffLL,		/* DMA counter register - 16 bits */
	0x0000000000000008LL,		/* DMA address alignment, 64-bit */
	0x0000007f,			/* 1 through 64 byte burst sizes */
	0x00000001,			/* min effective DMA size */
	0x0000000000003fffLL,		/* maximum transfer size, 16k */
	0x000000000000ffffLL,		/* segment boundary, 64k */
	0x00000001,			/* s/g list length, no s/g */
	0x00000001,			/* granularity of device, don't care */
	0				/* DMA flags */
};

static ddi_device_acc_attr_t ts_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t ts_regs_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * _init()
 *
 * Description:
 *	Driver initialization, called when driver is first loaded.
 *	This is how access is initially given to all the static structures.
 *
 * Arguments:
 *	None
 *
 * Returns:
 *	ddi_soft_state_init() status, see ddi_soft_state_init(9f), or
 *	mod_install() status, see mod_install(9f)
 */
int
_init(void)
{
	int		error;

	audio_init_ops(&audiots_dev_ops, TS_NAME);

	/* initialize the soft state */
	if ((error = ddi_soft_state_init(&audiots_statep,
	    sizeof (audiots_state_t), 1)) != 0) {
		audio_fini_ops(&audiots_dev_ops);
		return (error);
	}

	if ((error = mod_install(&audiots_modlinkage)) != 0) {
		audio_fini_ops(&audiots_dev_ops);
		ddi_soft_state_fini(&audiots_statep);
	}

	return (error);
}

/*
 * _fini()
 *
 * Description:
 *	Module de-initialization, called when the driver is to be unloaded.
 *
 * Arguments:
 *	None
 *
 * Returns:
 *	mod_remove() status, see mod_remove(9f)
 */
int
_fini(void)
{
	int		error;

	if ((error = mod_remove(&audiots_modlinkage)) != 0) {
		return (error);
	}

	/* free the soft state internal structures */
	ddi_soft_state_fini(&audiots_statep);

	/* clean up ops */
	audio_fini_ops(&audiots_dev_ops);

	return (0);
}

/*
 * _info()
 *
 * Description:
 *	Module information, returns infomation about the driver.
 *
 * Arguments:
 *	modinfo *modinfop	Pointer to the opaque modinfo structure
 *
 * Returns:
 *	mod_info() status, see mod_info(9f)
 */
int
_info(struct modinfo *modinfop)
{
	int		error;

	error = mod_info(&audiots_modlinkage, modinfop);

	return (error);
}


/*
 * audiots_attach()
 *
 * Description:
 *	Attach an instance of the audiots driver. This routine does the
 *	device dependent attach tasks.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *	ddi_attach_cmd_t cmd	Attach command
 *
 * Returns:
 *	DDI_SUCCESS		The driver was initialized properly
 *	DDI_FAILURE		The driver couldn't be initialized properly
 */
static int
audiots_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audiots_state_t		*state;
	int			instance;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:

		/* we've already allocated the state structure so get ptr */
		state = ddi_get_soft_state(audiots_statep, instance);
		ASSERT(dip == state->ts_dip);

		/* suspend/resume resets the chip, so we have no more faults */
		if (state->ts_flags & TS_AUDIO_READ_FAILED) {
			ddi_dev_report_fault(state->ts_dip,
			    DDI_SERVICE_RESTORED,
			    DDI_DEVICE_FAULT,
			    "check port, gain, balance, and mute settings");
			/* and clear the fault state flags */
			state->ts_flags &=
			    ~(TS_AUDIO_READ_FAILED|TS_READ_FAILURE_PRINTED);
		}

		audiots_power_up(state);
		audiots_chip_init(state);

		ac97_reset(state->ts_ac97);

		audio_dev_resume(state->ts_adev);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* before we do anything make sure that we haven't had a h/w failure */
	if (ddi_get_devstate(dip) == DDI_DEVSTATE_DOWN) {
		cmn_err(CE_WARN, "%s%d: The audio hardware has "
		    "been disabled.", ddi_driver_name(dip), instance);
		cmn_err(CE_CONT, "Please reboot to restore audio.");
		return (DDI_FAILURE);
	}

	/* allocate the state structure */
	if (ddi_soft_state_zalloc(audiots_statep, instance) == DDI_FAILURE) {
		cmn_err(CE_WARN, "!%s%d: soft state allocate failed",
		    ddi_driver_name(dip), instance);
		return (DDI_FAILURE);
	}

	/*
	 * WARNING: From here on all errors require that we free memory,
	 *	including the state structure.
	 */

	/* get the state structure - cannot fail */
	state = ddi_get_soft_state(audiots_statep, instance);
	ASSERT(state != NULL);

	if ((state->ts_adev = audio_dev_alloc(dip, 0)) == NULL) {
		cmn_err(CE_WARN, "unable to allocate audio dev");
		goto error;
	}

	/* map in the registers, allocate DMA buffers, etc. */
	if (audiots_map_regs(dip, state) == DDI_FAILURE) {
		audio_dev_warn(state->ts_adev, "unable to map registers");
		goto error;
	}

	/* initialize the audio state structures */
	if (audiots_init_state(state, dip) == DDI_FAILURE) {
		audio_dev_warn(state->ts_adev, "init state structure failed");
		goto error;
	}

	/* power up */
	audiots_power_up(state);

	/* initialize the audio controller */
	audiots_chip_init(state);

	/* initialize the AC-97 Codec */
	if (ac97_init(state->ts_ac97, state->ts_adev) != 0) {
		goto error;
	}

	/* put the engine interrupts into a known state -- all off */
	ddi_put32(state->ts_acch, &state->ts_regs->aud_regs.ap_ainten,
	    TS_ALL_DMA_OFF);

	/* call the framework attach routine */
	if (audio_dev_register(state->ts_adev) != DDI_SUCCESS) {
		audio_dev_warn(state->ts_adev, "unable to register audio");
		goto error;
	}

	/* everything worked out, so report the device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	audiots_destroy(state);
	return (DDI_FAILURE);
}

/*
 * audiots_detach()
 *
 * Description:
 *	Detach an instance of the audiots driver.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *	ddi_detach_cmd_t cmd	Detach command
 *
 * Returns:
 *	DDI_SUCCESS		The driver was detached
 *	DDI_FAILURE		The driver couldn't be detached
 */
static int
audiots_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audiots_state_t		*state;
	int			instance;

	instance = ddi_get_instance(dip);

	/* get the state structure */
	if ((state = ddi_get_soft_state(audiots_statep, instance)) == NULL) {
		cmn_err(CE_WARN, "!%s%d: detach get soft state failed",
		    ddi_driver_name(dip), instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:

		audio_dev_suspend(state->ts_adev);

		/* stop playing and recording */
		(void) audiots_stop_everything(state);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* attempt to unregister from the framework first */
	if (audio_dev_unregister(state->ts_adev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	audiots_destroy(state);

	return (DDI_SUCCESS);

}

/*
 * audiots_quiesce()
 *
 * Description:
 *	Quiesce an instance of the audiots driver. Stops all DMA and
 *	interrupts.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was quiesced
 *	DDI_SUCCESS		The driver was NOT quiesced
 */
static int
audiots_quiesce(dev_info_t *dip)
{
	audiots_state_t		*state;
	int			instance;

	instance = ddi_get_instance(dip);

	/* get the state structure */
	if ((state = ddi_get_soft_state(audiots_statep, instance)) == NULL) {
		return (DDI_FAILURE);
	}

	audiots_stop_everything(state);

	return (DDI_SUCCESS);
}

/*
 * audiots_power_up()
 *
 * Description
 *	Ensure that the device is running in PCI power state D0.
 */
static void
audiots_power_up(audiots_state_t *state)
{
	ddi_acc_handle_t	pcih = state->ts_pcih;
	uint8_t			ptr;
	uint16_t		pmcsr;

	if ((pci_config_get16(pcih, PCI_CONF_STAT) & PCI_STAT_CAP) == 0) {
		/* does not implement PCI capabilities -- no PM */
		return;
	}

	ptr = pci_config_get8(pcih, PCI_CONF_CAP_PTR);
	for (;;) {
		if (ptr == PCI_CAP_NEXT_PTR_NULL) {
			/* PM capability not found */
			return;
		}
		if (pci_config_get8(pcih, ptr + PCI_CAP_ID) == PCI_CAP_ID_PM) {
			/* found it */
			break;
		}
		ptr = pci_config_get8(pcih, ptr + PCI_CAP_NEXT_PTR);
	}

	/* if we got here, then got valid PMCSR pointer */
	ptr += PCI_PMCSR;

	/* check to see if we are already in state D0 */
	pmcsr = pci_config_get16(pcih, ptr);
	if ((pmcsr & PCI_PMCSR_STATE_MASK) != PCI_PMCSR_D0) {

		/* D3hot (or any other state) -> D0 */
		pmcsr &= ~PCI_PMCSR_STATE_MASK;
		pmcsr |= PCI_PMCSR_D0;
		pci_config_put16(pcih, ptr, pmcsr);
	}

	/*
	 * Wait for it to power up - PCI spec says 10 ms is enough.
	 * We double it.  Note that no locks are held when this routine
	 * is called, so we can sleep (we are in attach context only).
	 *
	 * We do this delay even if already powerd up, just to make
	 * sure we aren't seeing something that *just* transitioned
	 * into D0 state.
	 */
	delay(drv_usectohz(TS_20MS));

	/* clear PME# flag */
	pmcsr = pci_config_get16(pcih, ptr);
	pci_config_put16(pcih, ptr, pmcsr | PCI_PMCSR_PME_STAT);
}

/*
 * audiots_chip_init()
 *
 * Description:
 *	Initialize the audio core.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 */
static void
audiots_chip_init(audiots_state_t *state)
{
	ddi_acc_handle_t	handle = state->ts_acch;
	audiots_regs_t		*regs = state->ts_regs;
	int			str;

	/* start with all interrupts & dma channels disabled */
	ddi_put32(handle, &regs->aud_regs.ap_stop, TS_ALL_DMA_ENGINES);
	ddi_put32(handle, &regs->aud_regs.ap_ainten, TS_ALL_DMA_OFF);

	/* set global music and wave volume to 0dB */
	ddi_put32(handle, &regs->aud_regs.ap_volume, 0x0);

	/* enable end interrupts for all channels. */
	ddi_put32(handle, &regs->aud_regs.ap_cir_gc, AP_CIR_GC_ENDLP_IE);

	/* for each stream, set gain and vol settings */
	for (str = 0; str < TS_MAX_HW_CHANNELS; str++) {
		/*
		 * Set volume to all off, 1st left and then right.
		 * These are never changed, so we don't have to save them.
		 */
		ddi_put16(handle,
		    &regs->aud_ram[str].eram.eram_gvsel_pan_vol,
		    (ERAM_WAVE_VOL|ERAM_PAN_LEFT|ERAM_PAN_0dB|
		    ERAM_VOL_MAX_ATTEN));
		ddi_put16(handle,
		    &regs->aud_ram[str].eram.eram_gvsel_pan_vol,
		    (ERAM_WAVE_VOL|ERAM_PAN_RIGHT|ERAM_PAN_0dB|
		    ERAM_VOL_MAX_ATTEN));

		/*
		 * The envelope engine *MUST* remain in still mode (off).
		 * Otherwise bad things like gain randomly disappearing might
		 * happen. See bug #4332773.
		 */

		ddi_put32(handle, &regs->aud_ram[str].eram.eram_ebuf1,
		    ERAM_EBUF_STILL);
		ddi_put32(handle, &regs->aud_ram[str].eram.eram_ebuf2,
		    ERAM_EBUF_STILL);

		/* program the initial eram and aram rate */
		ddi_put16(handle, &regs->aud_ram[str].aram.aram_delta,
		    1 << TS_SRC_SHIFT);
		ddi_put16(handle, &regs->aud_ram[str].eram.eram_ctrl_ec,
		    ERAM_16_BITS | ERAM_STEREO | ERAM_LOOP_MODE |
		    ERAM_SIGNED_PCM);
	}

	/* program channel 31 for record */
	OR_SET_WORD(handle, &state->ts_regs->aud_regs.ap_global_control,
	    (AP_CLOGAL_CTRL_E_PCMIN_CH31|AP_CLOGAL_CTRL_PCM_OUT_AC97|
	    AP_CLOGAL_CTRL_MMC_FROM_MIXER|AP_CLOGAL_CTRL_PCM_OUT_TO_AC97));

	/* do a warm reset, which powers up the Codec */
	OR_SET_WORD(handle, &state->ts_regs->aud_regs.ap_sctrl,
	    AP_SCTRL_WRST_CODEC);
	drv_usecwait(2);
	AND_SET_WORD(handle, &state->ts_regs->aud_regs.ap_sctrl,
	    ~AP_SCTRL_WRST_CODEC);

	/* do a warm reset via the Codec, yes, I'm being paranoid! */
	audiots_set_ac97(state, AC97_RESET_REGISTER, 0);

	/* Make sure the Codec is powered up. */
	int i = TS_WAIT_CNT;
	while ((audiots_get_ac97(state, AC97_POWERDOWN_CTRL_STAT_REGISTER) &
	    PCSR_POWERD_UP) != PCSR_POWERD_UP && i--) {
		drv_usecwait(1);
	}

}

/*
 * audiots_get_ac97()
 *
 * Description:
 *	Get the value in the specified AC-97 Codec register. There is a
 *	bug in silicon which forces us to do multiple reads of the Codec's
 *	register. This algorithm was provided by T2 and is heuristic in
 *	nature. Unfortunately we have no guarantees that the real answer
 *	isn't 0x0000, which is what we get when a read fails. So we loop
 *	TS_LOOP_CNT times before we give up. We just have to hope this is
 *	sufficient to give us the correct value.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		reg		AC-97 register number
 *
 * Returns:
 *	unsigned short		The value in the specified register
 */
static uint16_t
audiots_get_ac97(void *arg, uint8_t reg)
{
	audiots_state_t		*state = arg;
	ddi_acc_handle_t	handle = state->ts_acch;
	uint16_t		*data;
	int			count;
	int			delay;
	uint16_t		first;
	uint16_t		next;

	if (state->ts_revid == AC_REV_ID1) {
		data = &state->ts_regs->aud_regs.ap_acrd_35D_data;
	} else {
		data = &state->ts_regs->aud_regs.ap_acrdwr_data;
	}

	/* make sure the register is good */
	reg &= AP_ACRD_INDEX_MASK;
	for (count = TS_LOOP_CNT; count--; ) {
		if ((first = audiots_read_ac97(state, reg)) != 0) {
			next = first;
			break;
		}

		delay = TS_DELAY_CNT;
		while (delay--) {
			(void) ddi_get16(handle, data);
		}

		if ((next = audiots_read_ac97(state, reg)) != 0) {
			break;
		}
	}

	/*
	 * Arggg, if you let the next read happen too soon then it fails.
	 * 12 usec fails, 13 usec succeeds. So set it to 20 for safety.
	 */
	drv_usecwait(TS_20US);

	return (next);

}

/*
 * audiots_init_state()
 *
 * Description:
 *	This routine initializes the audio driver's state structure.
 *	This includes reading the properties.
 *
 *	CAUTION: This routine cannot allocate resources, unless it frees
 *		them before returning for an error. Also, error_destroy:
 *		in audiots_attach() would need to be fixed as well.
 *
 *	NOTE: birdsnest supports CD ROM input. We check for the cdrom
 *		property. If there we turn it on.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	dev_info_t	*dip		Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS			State structure initialized
 *	DDI_FAILURE			State structure not initialized
 */
static int
audiots_init_state(audiots_state_t *state, dev_info_t *dip)
{
	state->ts_ac97 = ac97_alloc(dip, audiots_get_ac97,
	    audiots_set_ac97, state);

	if (state->ts_ac97 == NULL) {
		return (DDI_FAILURE);
	}

	/* save the device info pointer */
	state->ts_dip = dip;

	for (int i = 0; i < TS_NUM_PORTS; i++) {
		if (audiots_alloc_port(state, i) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);

}

/*
 * audiots_map_regs()
 *
 * Description:
 *	This routine maps the registers in.
 *
 *	Once the config space registers are mapped in we determine if the
 *	audio core may be power managed. It should, but if it doesn't,
 *	then trying to may cause the core to hang.
 *
 *	CAUTION: Make sure all errors call audio_dev_warn().
 *
 * Arguments:
 *	dev_info_t	*dip            Pointer to the device's devinfo
 *	audiots_state_t	*state          The device's state structure
 * Returns:
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
audiots_map_regs(dev_info_t *dip, audiots_state_t *state)
{
	char	rev[16];
	char	*name;

	/* map in the registers, the config and memory mapped registers */
	if (pci_config_setup(dip, &state->ts_pcih) != DDI_SUCCESS) {
		audio_dev_warn(state->ts_adev,
		    "unable to map PCI configuration space");
		return (DDI_FAILURE);
	}

	/* Read the Audio Controller's vendor, device, and revision IDs */
	state->ts_devid =
	    (pci_config_get16(state->ts_pcih, PCI_CONF_VENID) << 16) |
	    pci_config_get16(state->ts_pcih, PCI_CONF_DEVID);
	state->ts_revid = pci_config_get8(state->ts_pcih, PCI_CONF_REVID);

	if (ddi_regs_map_setup(dip, TS_MEM_MAPPED_REGS,
	    (caddr_t *)&state->ts_regs, 0, 0, &ts_regs_attr, &state->ts_acch) !=
	    DDI_SUCCESS) {
		audio_dev_warn(state->ts_adev,
		    "unable to map PCI device registers");
		return (DDI_FAILURE);
	}

	switch (state->ts_devid) {
	case 0x10b95451:
		name = "ALI M5451";
		break;
	default:
		name = "audiots";
		break;
	}
	(void) snprintf(rev, sizeof (rev), "Rev %x", state->ts_revid);
	audio_dev_set_description(state->ts_adev, name);
	audio_dev_set_version(state->ts_adev, rev);

	return (DDI_SUCCESS);
}

/*
 * audiots_alloc_port()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use. It then binds each of the buffers to its
 *	respective handle, getting a DMA cookie.
 *
 *	NOTE: All of the ddi_dma_... routines sleep if they cannot get
 *		memory. This means these calls should always succeed.
 *
 *	NOTE: ddi_dma_alloc_handle() attempts to use the full 4 GB DMA address
 *		range. This is to work around Southbridge rev E/G OBP issues.
 *		(See Grover OBP note above)
 *
 *	CAUTION: Make sure all errors call audio_dev_warn().
 *
 * Arguments:
 *	audiots_port_t	*state          The port structure for a device stream
 *	int		num		The port number
 *
 * Returns:
 *	DDI_SUCCESS		DMA resources mapped
 *	DDI_FAILURE		DMA resources not successfully mapped
 */
int
audiots_alloc_port(audiots_state_t *state, int num)
{
	audiots_port_t		*port;
	dev_info_t		*dip = state->ts_dip;
	audio_dev_t		*adev = state->ts_adev;
	int			dir;
	unsigned		caps;
	ddi_dma_cookie_t	cookie;
	unsigned		count;
	int			rc;
	ddi_acc_handle_t	regsh = state->ts_acch;
	uint32_t		*gcptr = &state->ts_regs->aud_regs.ap_cir_gc;

	port = kmem_zalloc(sizeof (*port), KM_SLEEP);
	state->ts_ports[num] = port;
	port->tp_num = num;
	port->tp_state = state;
	port->tp_rate = TS_RATE;

	if (num == TS_INPUT_PORT) {
		dir = DDI_DMA_READ;
		caps = ENGINE_INPUT_CAP;
		port->tp_dma_stream = 31;
		port->tp_sync_dir = DDI_DMA_SYNC_FORKERNEL;
	} else {
		dir = DDI_DMA_WRITE;
		caps = ENGINE_OUTPUT_CAP;
		port->tp_dma_stream = 0;
		port->tp_sync_dir = DDI_DMA_SYNC_FORDEV;
	}

	port->tp_dma_mask = (1U << port->tp_dma_stream);
	port->tp_nframes = 4096;
	port->tp_size = port->tp_nframes * TS_FRAMESZ;

	/* allocate dma handle */
	rc = ddi_dma_alloc_handle(dip, &audiots_attr, DDI_DMA_SLEEP,
	    NULL, &port->tp_dmah);
	if (rc != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_dma_alloc_handle failed: %d", rc);
		return (DDI_FAILURE);
	}
	/* allocate DMA buffer */
	rc = ddi_dma_mem_alloc(port->tp_dmah, port->tp_size, &ts_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &port->tp_kaddr,
	    &port->tp_size, &port->tp_acch);
	if (rc == DDI_FAILURE) {
		audio_dev_warn(adev, "dma_mem_alloc failed");
		return (DDI_FAILURE);
	}

	/* bind DMA buffer */
	rc = ddi_dma_addr_bind_handle(port->tp_dmah, NULL,
	    port->tp_kaddr, port->tp_size, dir|DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &cookie, &count);
	if (rc != DDI_DMA_MAPPED) {
		audio_dev_warn(adev,
		    "ddi_dma_addr_bind_handle failed: %d", rc);
		return (DDI_FAILURE);
	}
	ASSERT(count == 1);

	port->tp_paddr = cookie.dmac_address;
	if ((unsigned)port->tp_paddr & 0x80000000U) {
		ddi_put32(regsh, gcptr,
		    ddi_get32(regsh, gcptr) | AP_CIR_GC_SYS_MEM_4G_ENABLE);
	} else {
		ddi_put32(regsh, gcptr,
		    ddi_get32(regsh, gcptr) & ~(AP_CIR_GC_SYS_MEM_4G_ENABLE));
	}
	port->tp_engine = audio_engine_alloc(&audiots_engine_ops, caps);
	if (port->tp_engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(port->tp_engine, port);
	audio_dev_add_engine(adev, port->tp_engine);

	return (DDI_SUCCESS);
}

/*
 * audiots_read_ac97()
 *
 * Description:
 *	This routine actually reads the AC-97 Codec's register. It may
 *	be called several times to succeed.
 *
 * NOTE:
 * 	Revision M1535D B1-C of the ALI SouthBridge includes a workaround for
 *	the broken busy flag. Resetting the busy flag requires a software tweak
 *	to go with the worked around hardware. When we detect failure, we make
 *	10 attempts to reset the chip before we fail. This should reset the new
 *	SB systems. On all SB systems, this will increse the read delay
 *	slightly, but shouldn't bother it otherwise.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		reg		AC-97 register number
 *
 * Returns:
 *	unsigned short		The value in the specified register
 */
static uint16_t
audiots_read_ac97(audiots_state_t *state, int reg)
{
	ddi_acc_handle_t	acch = state->ts_acch;
	uint16_t		*addr;
	uint16_t		*data;
	uint32_t		*stimer = &state->ts_regs->aud_regs.ap_stimer;
	uint32_t		chk1;
	uint32_t		chk2;
	int			resets = 0;
	int			i;

	if (state->ts_revid == AC_REV_ID1) {
		addr = &state->ts_regs->aud_regs.ap_acrd_35D_reg;
		data = &state->ts_regs->aud_regs.ap_acrd_35D_data;
	} else {
		addr = &state->ts_regs->aud_regs.ap_acrdwr_reg;
		data = &state->ts_regs->aud_regs.ap_acrdwr_data;
	}

first_read:
	/* wait for ready to send read request */
	for (i = 0; i < TS_READ_TRIES; i++) {
		if (!(ddi_get16(acch, addr) & AP_ACRD_R_READ_BUSY)) {
			break;
		}
		/* don't beat on the bus */
		drv_usecwait(1);
	}
	if (i >= TS_READ_TRIES) {
		if (resets < TS_RESET_TRIES) {
			/* Attempt to reset */
			drv_usecwait(TS_20US);
			ddi_put16(acch, addr, TS_SB_RESET);
			resets++;
			goto first_read;
		} else {
			state->ts_flags |= TS_AUDIO_READ_FAILED;
			if (!(state->ts_flags & TS_READ_FAILURE_PRINTED)) {
				ddi_dev_report_fault(state->ts_dip,
				    DDI_SERVICE_LOST, DDI_DEVICE_FAULT,
				    "Unable to communicate with AC97 CODEC");
				audio_dev_warn(state->ts_adev,
				    "The audio AC97 register has timed out.");
				audio_dev_warn(state->ts_adev,
				    "Audio is now disabled.");
				audio_dev_warn(state->ts_adev,
				    "Please reboot to restore audio.");

				/* Don't flood the console */
				state->ts_flags |= TS_READ_FAILURE_PRINTED;
			}
		}
		return (0);
	}

	/* program the register to read */
	ddi_put16(acch, addr, (reg|AP_ACRD_W_PRIMARY_CODEC|
	    AP_ACRD_W_READ_MIXER_REG|AP_ACRD_W_AUDIO_READ_REQ&
	    (~AP_ACWR_W_SELECT_WRITE)));

	/* hardware bug work around */
	chk1 = ddi_get32(acch, stimer);
	chk2 = ddi_get32(acch, stimer);
	i = TS_WAIT_CNT;
	while (chk1 == chk2 && i) {
		chk2 = ddi_get32(acch, stimer);
		i--;
	}
	OR_SET_SHORT(acch, addr, AP_ACRD_W_READ_MIXER_REG);
	resets = 0;

second_read:
	/* wait again for read to send read request */
	for (i = 0; i < TS_READ_TRIES; i++) {
		if (!(ddi_get16(acch, addr) & AP_ACRD_R_READ_BUSY)) {
			break;
		}
		/* don't beat on the bus */
		drv_usecwait(1);
	}
	if (i >= TS_READ_TRIES) {
		if (resets < TS_RESET_TRIES) {
			/* Attempt to reset */
			drv_usecwait(TS_20US);
			ddi_put16(acch, addr, TS_SB_RESET);
			resets++;
			goto second_read;
		} else {
			state->ts_flags |= TS_AUDIO_READ_FAILED;
			if (!(state->ts_flags & TS_READ_FAILURE_PRINTED)) {
				ddi_dev_report_fault(state->ts_dip,
				    DDI_SERVICE_LOST, DDI_DEVICE_FAULT,
				    "Unable to communicate with AC97 CODEC");
				audio_dev_warn(state->ts_adev,
				    "The audio AC97 register has timed out.");
				audio_dev_warn(state->ts_adev,
				    "Audio is now disabled.");
				audio_dev_warn(state->ts_adev,
				    "Please reboot to restore audio.");

				/* Don't flood the console */
				state->ts_flags |= TS_READ_FAILURE_PRINTED;
			}
		}
		return (0);
	}

	return (ddi_get16(acch, data));

}	/* audiots_read_ac97() */

/*
 * audiots_set_ac97()
 *
 * Description:
 *	Set the value in the specified AC-97 Codec register. Just like
 *	reading the AC-97 Codec, it is possible there is a problem writing
 *	it as well. So we loop.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		reg		AC-97 register number
 *	uint16_t	value		The value to write
 */
static void
audiots_set_ac97(void *arg, uint8_t reg8, uint16_t data)
{
	audiots_state_t	*state = arg;
	ddi_acc_handle_t handle = state->ts_acch;
	uint16_t	*data_addr = &state->ts_regs->aud_regs.ap_acrdwr_data;
	uint16_t	*reg_addr = &state->ts_regs->aud_regs.ap_acrdwr_reg;
	int		count;
	int		i;
	uint16_t	tmp_short;
	uint16_t	reg = reg8;

	reg &= AP_ACWR_INDEX_MASK;

	/* Don't touch the reserved bits on the pre 35D+ SouthBridge */
	if (state->ts_revid == AC_REV_ID1) {
		reg |= AP_ACWR_W_PRIMARY_CODEC|AP_ACWR_W_WRITE_MIXER_REG;
	} else {
		reg |= AP_ACWR_W_PRIMARY_CODEC|AP_ACWR_W_WRITE_MIXER_REG|
		    AP_ACWR_W_SELECT_WRITE;
	}

	for (count = TS_LOOP_CNT; count--; ) {
		/* wait for ready to write */
		for (i = 0; i < TS_WAIT_CNT; i++) {
			if (!(ddi_get16(handle, reg_addr) &
			    AP_ACWR_R_WRITE_BUSY)) {
				/* ready to write */
				ddi_put16(handle, reg_addr, reg);

				/* Write the data */
				ddi_put16(handle, data_addr, data);
				break;
			}
		}
		if (i >= TS_WAIT_CNT) {
			/* try again */
			continue;
		}

		/* wait for write to complete */
		for (i = 0; i < TS_WAIT_CNT; i++) {
			if (!(ddi_get16(handle, reg_addr) &
			    AP_ACWR_R_WRITE_BUSY)) {
				/* done writing */
				break;
			}
		}

		/* verify the value written */
		tmp_short = audiots_get_ac97(state, reg8);
		if (data == tmp_short) {
			/* successfully loaded, so we can return */
			return;
		}
	}

}	/* audiots_set_ac97() */

/*
 * audiots_open()
 *
 * Description:
 *	Opens a DMA engine for use.  Will also ensure the device is powered
 *	up if not already done so.
 *
 * Arguments:
 *	void		*arg		The DMA engine to set up
 *	int		flag		Open flags
 *	unsigned	*nframesp	Receives number of frames
 *	caddr_t		*bufp		Receives kernel data buffer
 *
 * Returns:
 *	0	on success
 *	errno	on failure
 */
static int
audiots_open(void *arg, int flag, unsigned *nframesp, caddr_t *bufp)
{
	audiots_port_t	*port = arg;

	_NOTE(ARGUNUSED(flag));

	port->tp_count = 0;
	port->tp_cso = 0;
	*nframesp = port->tp_nframes;
	*bufp = port->tp_kaddr;

	return (0);
}

/*
 * audiots_close()
 *
 * Description:
 *	Closes an audio DMA engine that was previously opened.  Since
 *	nobody is using it, we could take this opportunity to possibly power
 *	down the entire device, or at least the DMA engine.
 *
 * Arguments:
 *	void	*arg		The DMA engine to shut down
 */
static void
audiots_close(void *arg)
{
	_NOTE(ARGUNUSED(arg));
}

/*
 * audiots_stop()
 *
 * Description:
 *	This is called by the framework to stop a port that is
 *	transferring data.
 *
 * Arguments:
 *	void	*arg		The DMA engine to stop
 */
static void
audiots_stop(void *arg)
{
	audiots_port_t	*port = arg;
	audiots_state_t	*state = port->tp_state;

	ddi_put32(state->ts_acch, &state->ts_regs->aud_regs.ap_stop,
	    port->tp_dma_mask);
}

/*
 * audiots_start()
 *
 * Description:
 *	This is called by the framework to start a port transferring data.
 *
 * Arguments:
 *	void	*arg		The DMA engine to start
 *
 * Returns:
 *	0 	on success (never fails, errno if it did)
 */
static int
audiots_start(void *arg)
{
	audiots_port_t		*port = arg;
	audiots_state_t		*state = port->tp_state;
	ddi_acc_handle_t	handle = state->ts_acch;
	audiots_regs_t		*regs = state->ts_regs;
	audiots_aram_t		*aram;
	audiots_eram_t		*eram;
	unsigned		delta;
	uint16_t		ctrl;
	uint16_t		gvsel;
	uint16_t		eso;

	aram = &regs->aud_ram[port->tp_dma_stream].aram;
	eram = &regs->aud_ram[port->tp_dma_stream].eram;

	port->tp_cso = 0;

	gvsel = ERAM_WAVE_VOL | ERAM_PAN_0dB | ERAM_VOL_DEFAULT;
	ctrl = ERAM_16_BITS | ERAM_STEREO | ERAM_LOOP_MODE | ERAM_SIGNED_PCM;

	delta = (port->tp_rate << TS_SRC_SHIFT) / TS_RATE;

	if (port->tp_num == TS_INPUT_PORT) {
		delta = (TS_RATE << TS_SRC_SHIFT) / port->tp_rate;
	}
	eso = port->tp_nframes - 1;

	/* program the sample rate */
	ddi_put16(handle, &aram->aram_delta, (uint16_t)delta);

	/* program the precision, number of channels and loop mode */
	ddi_put16(handle, &eram->eram_ctrl_ec, ctrl);

	/* program the volume settings */
	ddi_put16(handle, &eram->eram_gvsel_pan_vol, gvsel);

	/* set ALPHA and FMS to 0 */
	ddi_put16(handle, &aram->aram_alpha_fms, 0x0);

	/* set CSO to 0 */
	ddi_put16(handle, &aram->aram_cso, 0x0);

	/* set LBA */
	ddi_put32(handle, &aram->aram_cptr_lba,
	    port->tp_paddr & ARAM_LBA_MASK);

	/* set ESO */
	ddi_put16(handle, &aram->aram_eso, eso);

	/* stop the DMA engines */
	ddi_put32(handle, &regs->aud_regs.ap_stop, port->tp_dma_mask);

	/* now make sure it starts playing */
	ddi_put32(handle, &regs->aud_regs.ap_start, port->tp_dma_mask);

	return (0);
}

/*
 * audiots_chinfo()
 *
 * Description:
 *	This is called by the framework to query the channel offsets
 *	and ordering.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *	int	chan		Channel number.
 *	unsigned *offset	Starting offset of channel.
 *	unsigned *incr		Increment (in samples) between frames.
 *
 * Returns:
 *	0 indicating rate array is range instead of enumeration
 */

static void
audiots_chinfo(void *arg, int chan, unsigned *offset, unsigned *incr)
{
	_NOTE(ARGUNUSED(arg));
	*offset = chan;
	*incr = 2;
}

/*
 * audiots_format()
 *
 * Description:
 *	Called by the framework to query the format for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	AUDIO_FORMAT_S16_LE.
 */
static int
audiots_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}


/*
 * audiots_channels()
 *
 * Description:
 *	Called by the framework to query the channnels for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	2 (Stereo).
 */
static int
audiots_channels(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (2);
}

/*
 * audiots_rate()
 *
 * Description:
 *	Called by the framework to query the sample rates for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	Sample rate in HZ (always 48000).
 */
static int
audiots_rate(void *arg)
{
	audiots_port_t *port = arg;

	return (port->tp_rate);
}

/*
 * audiots_count()
 *
 * Description:
 *	This is called by the framework to get the engine's frame counter
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	frame count for current engine
 */
static uint64_t
audiots_count(void *arg)
{
	audiots_port_t	*port = arg;
	audiots_state_t	*state = port->tp_state;
	uint64_t	val;
	uint16_t	cso;
	unsigned	n;

	cso = ddi_get16(state->ts_acch,
	    &state->ts_regs->aud_ram[port->tp_dma_stream].aram.aram_cso);

	n = (cso >= port->tp_cso) ?
	    cso - port->tp_cso :
	    cso + port->tp_nframes - port->tp_cso;

	port->tp_cso = cso;
	port->tp_count += n;
	val = port->tp_count;

	return (val);
}

/*
 * audiots_sync()
 *
 * Description:
 *	This is called by the framework to synchronize DMA caches.
 *
 * Arguments:
 *	void	*arg		The DMA engine to sync
 */
static void
audiots_sync(void *arg, unsigned nframes)
{
	audiots_port_t *port = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->tp_dmah, 0, 0, port->tp_sync_dir);
}

/*
 * audiots_stop_everything()
 *
 * Description:
 *	This routine disables the address engine interrupt for all 32 DMA
 *	engines. Just to be sure, it then explicitly issues a stop command to
 *	the address engine and envelope engines for all 32 channels.
 *
 * NOTE:
 *
 * 	There is a hardware bug that generates a spurious interrupt
 *	when the DMA engines are stopped. It's not consistent - it
 *	happens every 1 out of 6 stops or so. It will show up as a
 *	record interrupt. The problem is that once the driver is
 *	detached or if the system goes into low power mode, nobody
 *	will service that interrupt. The system will eventually become
 *	unusable.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 */
static void
audiots_stop_everything(audiots_state_t *state)
{
	if (state->ts_acch == NULL)
		return;

	ddi_put32(state->ts_acch, &state->ts_regs->aud_regs.ap_ainten,
	    TS_ALL_DMA_OFF);

	ddi_put32(state->ts_acch, &state->ts_regs->aud_regs.ap_stop,
	    TS_ALL_DMA_ENGINES);

	ddi_put32(state->ts_acch, &state->ts_regs->aud_regs.ap_aint,
	    TS_ALL_DMA_ENGINES);
}

/*
 * audiots_free_port()
 *
 * Description:
 *	This routine unbinds the DMA cookies, frees the DMA buffers,
 *	deallocates the DMA handles.
 *
 * Arguments:
 *	audiots_port_t	*port	The port structure for a device stream.
 */
void
audiots_free_port(audiots_port_t *port)
{
	if (port == NULL)
		return;

	if (port->tp_engine) {
		audio_dev_remove_engine(port->tp_state->ts_adev,
		    port->tp_engine);
		audio_engine_free(port->tp_engine);
	}
	if (port->tp_paddr) {
		(void) ddi_dma_unbind_handle(port->tp_dmah);
	}
	if (port->tp_acch) {
		ddi_dma_mem_free(&port->tp_acch);
	}
	if (port->tp_dmah) {
		ddi_dma_free_handle(&port->tp_dmah);
	}
	kmem_free(port, sizeof (*port));
}

/*
 * audiots_destroy()
 *
 * Description:
 *	This routine releases all resources held by the device instance,
 *	as part of either detach or a failure in attach.
 *
 * Arguments:
 *	audiots_state_t	*state	The device soft state.
 */
void
audiots_destroy(audiots_state_t *state)
{
	audiots_stop_everything(state);

	for (int i = 0; i < TS_NUM_PORTS; i++)
		audiots_free_port(state->ts_ports[i]);

	if (state->ts_acch)
		ddi_regs_map_free(&state->ts_acch);

	if (state->ts_pcih)
		pci_config_teardown(&state->ts_pcih);

	if (state->ts_ac97)
		ac97_free(state->ts_ac97);

	if (state->ts_adev)
		audio_dev_free(state->ts_adev);

	ddi_soft_state_free(audiots_statep, ddi_get_instance(state->ts_dip));
}
