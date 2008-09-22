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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
 * This driver uses the mixer Audio Personality Module to implement
 * audio(7I) and mixer(7I) semantics. Although the play side of the
 * audio core supports multiple streams we don't use that feature.
 * The mixer needs to be fixed up first. Thus we let the mixer do it's
 * thing for both directions.
 *
 * The DMA engine uses a single buffer which is large enough to hold
 * two interrupts worth of data. When it gets to the mid point an
 * interrupt is generated and data is either sent (for record) or
 * requested and put in that half of the buffer (for play). When the
 * second half is played we do the same, but the audio core loops the
 * pointer back to the beginning. For play we bzero() the half buffer
 * before we ask for more audio. That way if there isn't enough waiting
 * for us we just play silence. If more arrives later we'll keep going,
 * but after a slight pop.
 *
 * The audio core has a bug in silicon that doesn't let it read the AC-97
 * Codec's register. T2 has provided an algorithm that attempts to read the
 * the Codec several times. This is probably heuristic and thus isn't
 * absolutely guaranteed to work. However we do have to place a limit on
 * the looping, otherwise when we read a valid 0x00 we would never exit
 * the loop. Unfortunately there is also a problem with writing the AC-97
 * Codec's registers as well. Thus we read it back to verify the write.
 *
 * Every time we program the AC-97 Codec we save the value in ts_shadow[].
 * Thus every time we need to get a Codec register we don't have to do
 * a very long read. This also means that register state information is
 * saved for power management shutdown (CPR). When the Codec is started
 * back up we use this saved state to restore the Codec's state in
 * audiots_chip_init().
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
 *	NOTE: This driver depends on the misc/audiosup and misc/mixer
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

#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/stropts.h>
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
#include <sys/audio/am_src2.h>
#include <sys/audio/audiots.h>
#include <sys/audio/impl/audiots_impl.h>
#include <sys/audio/ac97.h>

/*
 * Module linkage routines for the kernel
 */
static int audiots_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int audiots_attach(dev_info_t *, ddi_attach_cmd_t);
static int audiots_detach(dev_info_t *, ddi_detach_cmd_t);
static int audiots_power(dev_info_t *, int, int);

/*
 * Entry point routine prototypes
 */
static int audiots_ad_setup(audiohdl_t, int, int);
static void audiots_ad_pause_play(audiohdl_t, int);
static int audiots_ad_set_config(audiohdl_t, int, int, int, int, int);
static int audiots_ad_set_format(audiohdl_t, int, int, int, int, int, int);
static int audiots_ad_start_play(audiohdl_t, int);
static void audiots_ad_stop_play(audiohdl_t, int);
static int audiots_ad_start_record(audiohdl_t, int);
static void audiots_ad_stop_record(audiohdl_t, int);

/*
 * Local Routine Prototypes
 */
static void audiots_and_ac97(audiots_state_t *, int, uint16_t);
static void audiots_chip_init(audiots_state_t *, int);
static uint16_t audiots_get_ac97(audiots_state_t *, int);
static int audiots_init_state(audiots_state_t *, dev_info_t *);
static uint_t audiots_intr(caddr_t);
static int audiots_map_regs(dev_info_t *, audiots_state_t *);
static void audiots_or_ac97(audiots_state_t *, int, uint16_t);
static void audiots_power_down(audiots_state_t *);
static void audiots_power_up(audiots_state_t *);
static uint16_t audiots_read_ac97(audiots_state_t *, int);
static void audiots_save_controller(audiots_state_t *);
static void audiots_set_ac97(audiots_state_t *, int, const uint16_t);
static int audiots_set_busy(audiots_state_t *);
static int audiots_set_gain(audiots_state_t *, int, int, int, int);
static void audiots_set_idle(audiots_state_t *);
static int audiots_set_monitor_gain(audiots_state_t *, int);
static int audiots_set_port(audiots_state_t *, int, int);
static int audiots_start_play(audiots_state_t *);
static void audiots_stop_play(audiots_state_t *);
static int audiots_start_record(audiots_state_t *);
static void audiots_stop_record(audiots_state_t *);
static void audiots_stop_everything(audiots_state_t *);
static void audiots_unmap_regs(audiots_state_t *);

/*
 * Global variables, but viewable only by this file.
 */

/* anchor for soft state structures */
static void *audiots_statep;

/* driver name, so we don't have to call ddi_driver_name() or hard code strs */
static char *audiots_name = TS_NAME;

static uint_t audiots_mixer_srs[] = {
	TS_SAMPR5510, TS_SAMPR48000, 0
};

static uint_t audiots_compat_srs[] = {
	TS_SAMPR5510, TS_SAMPR6620, TS_SAMPR8000,
	TS_SAMPR9600, TS_SAMPR11025, TS_SAMPR16000,
	TS_SAMPR18900, TS_SAMPR22050, TS_SAMPR27420,
	TS_SAMPR32000, TS_SAMPR33075, TS_SAMPR37800,
	TS_SAMPR44100, TS_SAMPR48000, 0
};

static am_ad_sample_rates_t audiots_mixer_sample_rates = {
	MIXER_SRS_FLAG_SR_LIMITS,
	audiots_mixer_srs
};

static am_ad_sample_rates_t audiots_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audiots_compat_srs
};

static uint_t audiots_channels[] = {
	AUDIO_CHANNELS_STEREO, 0
};

static am_ad_cap_comb_t audiots_combinations[] = {
	{ AUDIO_PRECISION_16, AUDIO_ENCODING_LINEAR },
	{ 0 }
};

static am_ad_entry_t audiots_entry = {
	audiots_ad_setup,		/* ad_setup() */
	NULL,				/* ad_teardown() */
	audiots_ad_set_config,		/* ad_set_config() */
	audiots_ad_set_format,		/* ad_set_format() */
	audiots_ad_start_play,		/* ad_start_play() */
	audiots_ad_pause_play,		/* ad_pause_play() */
	audiots_ad_stop_play,		/* ad_stop_play() */
	audiots_ad_start_record,	/* ad_start_record() */
	audiots_ad_stop_record,		/* ad_stop_record() */
	NULL,				/* ad_ioctl() */
	NULL				/* ad_iocdata() */
};

/*
 * STREAMS Structures
 */

/* STREAMS driver id and limit value structure */
static struct module_info audiots_modinfo = {
	TS_IDNUM,		/* module ID number */
	TS_NAME,		/* module name */
	TS_MINPACKET,		/* minimum packet size */
	TS_MAXPACKET,		/* maximum packet size */
	TS_HIWATER,		/* high water mark */
	TS_LOWATER		/* low water mark */
};

/* STREAMS queue processing procedures structures */
/* read queue */
static struct qinit audiots_rqueue = {
	audio_sup_rput,		/* put procedure */
	audio_sup_rsvc,		/* service procedure */
	audio_sup_open,		/* open procedure */
	audio_sup_close,	/* close procedure */
	NULL,			/* unused */
	&audiots_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* write queue */
static struct qinit audiots_wqueue = {
	audio_sup_wput,		/* put procedure */
	audio_sup_wsvc,		/* service procedure */
	NULL,			/* open procedure */
	NULL,			/* close procedure */
	NULL,			/* unused */
	&audiots_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* STREAMS entity declaration structure */
static struct streamtab audiots_str_info = {
	&audiots_rqueue,	/* read queue */
	&audiots_wqueue,	/* write queue */
	NULL,			/* mux lower read queue */
	NULL,			/* mux lower write queue */
};

/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops audiots_cb_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&audiots_str_info,	/* cb_str */
	D_NEW|D_MP|D_64BIT,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_arwite */
};

/* Device operations structure */
static struct dev_ops audiots_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	audiots_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audiots_attach,		/* devo_attach */
	audiots_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&audiots_cb_ops,	/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	audiots_power,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
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
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};


/* *******  Loadable Module Configuration Entry Points  ********************* */

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

	ATRACE("in audiots _init()", NULL);

	/* initialize the soft state */
	if ((error = ddi_soft_state_init(&audiots_statep,
	    sizeof (audiots_state_t), 1)) != 0) {
		ATRACE("audiots ddi_soft_state_init() failed", audiots_statep);
		return (error);
	}

	if ((error = mod_install(&audiots_modlinkage)) != 0) {
		ddi_soft_state_fini(&audiots_statep);
	}

	ATRACE("audiots _init() audiots_statep", audiots_statep);

	ATRACE_32("audiots _init() returning", error);

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

	ATRACE("in audiots _fini()", audiots_statep);

	if ((error = mod_remove(&audiots_modlinkage)) != 0) {
		return (error);
	}

	/* free the soft state internal structures */
	ddi_soft_state_fini(&audiots_statep);

	ATRACE_32("audiots _fini() returning", error);

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

	ATRACE("in audiots _info()", NULL);

	error = mod_info(&audiots_modlinkage, modinfop);

	ATRACE_32("audiots _info() returning", error);

	return (error);
}


/* *******  Driver Entry Points  ******************************************** */

/*
 * audiots_getinfo()
 */
/*ARGSUSED*/
static int
audiots_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result)
{
	audiots_state_t	*state;
	int error = DDI_FAILURE;
	int instance;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = audio_sup_devt_to_instance((dev_t)arg);
		if ((state = ddi_get_soft_state(audiots_statep,
		    instance)) != NULL) {
			*result = state->ts_dip;
			error = DDI_SUCCESS;
		} else {
			*result = NULL;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result =
		    (void *)(uintptr_t)audio_sup_devt_to_instance((dev_t)arg);
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}

/*
 * audiots_attach()
 *
 * Description:
 *	Attach an instance of the audiots driver. This routine does the
 *	device dependent attach tasks. When it is complete it calls
 *	audio_sup_register() and am_attach() so they may do their work.
 *
 *	NOTE: mutex_init() no longer needs a name string, so set
 *		to NULL to save kernel space.
 *
 *	NOTE: audiots_attach() assumes the Codec is powered down.
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
	audio_sup_reg_data_t	data;
	char			*pm_comp[] = {
		"NAME=audiots audio device",
		"0=off",
		"1=on"
	};
	int			instance;

	ATRACE("in ts_attach()", dip);

	instance = ddi_get_instance(dip);
	ATRACE_32("ts_attach() instance", instance);
	ATRACE("ts_attach() audiots_statep", audiots_statep);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		ATRACE("ts_attach() DDI_RESUME", NULL);

		/* we've already allocated the state structure so get ptr */
		if ((state = ddi_get_soft_state(audiots_statep, instance)) ==
		    NULL) {
			audio_sup_log(NULL, CE_WARN,
			    "!%s%d: attach() RESUME get soft state failed",
			    audiots_name, instance);
			return (DDI_FAILURE);
		}

		ASSERT(dip == state->ts_dip);
		ASSERT(!mutex_owned(&state->ts_lock));

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

		if (state->ts_flags & TS_PM_SUPPORTED) {
			/*
			 * power up the Codec, see comment
			 * in audiots_set_busy()
			 */
			ASSERT(state->ts_powered == TS_PWR_OFF);
			(void) pm_busy_component(state->ts_dip, TS_COMPONENT);
			if (pm_raise_power(state->ts_dip, TS_COMPONENT,
			    TS_PWR_ON) == DDI_FAILURE) {
				/* match the busy call above */
				(void) pm_idle_component(state->ts_dip,
				    TS_COMPONENT);
				audio_sup_log(state->ts_ahandle, CE_WARN,
				    "!attach() DDI_RESUME failed");
				return (DDI_FAILURE);
			}
		}
		mutex_enter(&state->ts_lock);

		state->ts_powered = TS_PWR_ON;

		ASSERT(state->ts_suspended == TS_SUSPENDED);
		state->ts_suspended = TS_NOT_SUSPENDED;

		/* Restore the audiots chip's state */
		audiots_chip_init(state, TS_INIT_RESTORE);

		/*
		 * Put the address engine interrupt enable register in a known
		 * state - everything off.
		 */

		ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_ainten,
		    TS_ALL_DMA_OFF);

		mutex_exit(&state->ts_lock);

		/*
		 * Start playing and recording, if not needed they'll stop
		 * on their own. But, we don't start them if the hardware has
		 * failed.
		 */
		if (audio_sup_restore_state(state->ts_ahandle,
		    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(state->ts_ahandle, CE_WARN,
			    "!attach() audio restart failed");
		}

		cv_broadcast(&state->ts_cv);	/* let entry points continue */

		if (state->ts_flags & TS_PM_SUPPORTED) {
			/* we're no longer busy */
			ASSERT(state->ts_powered == TS_PWR_ON);
			(void) pm_idle_component(state->ts_dip, TS_COMPONENT);
		}

		ATRACE("ts_attach() DDI_RESUME done", NULL);

		ASSERT(!mutex_owned(&state->ts_lock));

		return (DDI_SUCCESS);

	default:
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() unknown command: 0x%x", audiots_name,
		    instance, cmd);
		return (DDI_FAILURE);
	}

	/* before we do anything make sure that we haven't had a h/w failure */
	if (ddi_get_devstate(dip) == DDI_DEVSTATE_DOWN) {
		audio_sup_log(NULL, CE_WARN, "%s%d: The audio hardware has "
		    "been disabled.", audiots_name, instance);
		audio_sup_log(NULL, CE_CONT, "Please reboot to restore audio.");
		return (DDI_FAILURE);
	}

	/* we don't support high level interrupts in this driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() unsupported high level interrupt",
		    audiots_name, instance);
		return (DDI_FAILURE);
	}

	/* allocate the state structure */
	if (ddi_soft_state_zalloc(audiots_statep, instance) == DDI_FAILURE) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() soft state allocate failed",
		    audiots_name, instance);
		return (DDI_FAILURE);
	}

	/*
	 * WARNING: From here on all errors require that we free memory,
	 *	including the state structure.
	 */

	/* get the state structure */
	if ((state = ddi_get_soft_state(audiots_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() get soft state failed",
		    audiots_name, instance);
		goto error_mem;
	}

	/* call audiosup module registration routine */
	ATRACE("ts_attach() calling audio_sup_register()", NULL);
	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;
	if ((state->ts_ahandle = audio_sup_register(dip, &data)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() audio_sup_register() failed",
		    audiots_name, instance);
		goto error_mem;
	}

	/* initialize the audio state structures */
	if (audiots_init_state(state, dip) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!attach() init state structure failed");
		goto error_audiosup;
	}

	/* map in the registers, allocate DMA buffers, etc. */
	if (audiots_map_regs(dip, state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!attach() couldn't map registers");
		goto error_destroy;
	}

	if (state->ts_rev_id == AC_REV_ID2) {
		/* set up the pm-components */
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "pm-components", pm_comp, 3) != DDI_PROP_SUCCESS) {
			audio_sup_log(state->ts_ahandle, CE_WARN,
			    "!init_state() couldn't create component");
			return (DDI_FAILURE);
		}

		/* Mark PM supported */
		state->ts_flags |= TS_PM_SUPPORTED;

		/* Mark as powering up at attach time */
		state->ts_flags |= TS_ATTACH_PWR;

		/* make sure the power framework knows the we are powered up */
		ASSERT(state->ts_powered == TS_PWR_OFF);
		(void) pm_busy_component(state->ts_dip, TS_COMPONENT);
		if (pm_raise_power(state->ts_dip, TS_COMPONENT, TS_PWR_ON) ==
		    DDI_FAILURE) {
			(void) pm_idle_component(state->ts_dip, TS_COMPONENT);
			ATRACE("ts_attach() pm_raise_power() failed", NULL);
			audio_sup_log(state->ts_ahandle, CE_WARN,
			    "!attach() power up failed");
			goto error_destroy;
		}
		(void) pm_idle_component(state->ts_dip, TS_COMPONENT);

		/* Clear the attach time powering flag */
		state->ts_flags &= ~TS_ATTACH_PWR;
	} else {
		/* Mark on for CPR */
		state->ts_powered = TS_PWR_ON;
	}

	/* initialize the audio controller and the AC-97 Codec */
	audiots_chip_init(state, TS_INIT_NO_RESTORE);

	/*
	 * Put the address engine interrupt enable register in a known
	 * state - everything off.
	 */

	ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_ainten,
	    TS_ALL_DMA_OFF);

	/* save private state */
	audio_sup_set_private(state->ts_ahandle, state);

	/* call the mixer attach() routine */
	ATRACE("ts_attach() calling am_attach()", &state->ts_ad_info);
	if (am_attach(state->ts_ahandle, cmd, &state->ts_ad_info) ==
	    AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!attach() am_attach() failed");
		goto error_unmap;
	}

	/* set up kernel statistics */
	if ((state->ts_ksp = kstat_create(TS_NAME, instance, TS_NAME,
	    "controller", KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(state->ts_ksp);
	}

	/* set up the interrupt handler */
	if (ddi_add_intr(dip, 0, (ddi_iblock_cookie_t *)NULL,
	    (ddi_idevice_cookie_t *)NULL, audiots_intr,
	    (caddr_t)state) != DDI_SUCCESS) {
		ATRACE("ts_attach() bad interrupt spec", state);
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!attach() bad interrupt specification");
		goto error_kstat;
	}

	/* everything worked out, so report the device */
	ddi_report_dev(dip);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (DDI_SUCCESS);

	/*
	 * CAUTION: Make sure there's an audio_sup_log() call before jumping
	 * here
	 */

error_kstat:
	ATRACE("ts_attach() error_kstat", state);
	if (state->ts_ksp) {
		kstat_delete(state->ts_ksp);
	}

	(void) am_detach(state->ts_ahandle, DDI_DETACH);

error_unmap:
	ATRACE("ts_attach() error_unmap", state);
	audiots_unmap_regs(state);

error_destroy:
	ATRACE("ts_attach() error_destroy", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	kmem_free(state->ts_tcbuf, state->ts_cbuf_size);

	/* destroy the state mutexes and cvs */
	mutex_destroy(&state->ts_lock);
	cv_destroy(&state->ts_cv);

error_audiosup:
	ATRACE("ts_attach() error_audiosup", state);
	(void) audio_sup_unregister(state->ts_ahandle);

error_mem:
	ATRACE("ts_attach() error_mem", state);
	ddi_soft_state_free(audiots_statep, instance);

	ATRACE("ts_attach() returning failure", NULL);

	return (DDI_FAILURE);

}	/* audiots_attach() */

/*
 * audiots_detach()
 *
 * Description:
 *	Detach an instance of the audiots driver. After the Codec is detached
 *	we call am_detach() and audio_sup_unregister() so they may do their
 *	work.
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

	ATRACE_32("in ts_detach()", cmd);

	instance = ddi_get_instance(dip);
	ATRACE_32("ts_detach() instance", instance);
	ATRACE("ts_detach() audiots_statep", audiots_statep);

	/* get the state structure */
	if ((state = ddi_get_soft_state(audiots_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: detach() get soft state failed",
		    audiots_name, instance);
		return (DDI_FAILURE);
	}

	ASSERT(!mutex_owned(&state->ts_lock));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		ATRACE("ts_detach() DDI_SUSPEND", NULL);

		mutex_enter(&state->ts_lock);

		ASSERT(state->ts_suspended == TS_NOT_SUSPENDED);

		state->ts_suspended = TS_SUSPENDED;	/* stop new ops */

		/* wait for current operations to complete */
		while (state->ts_busy_cnt != 0) {
			cv_wait(&state->ts_cv, &state->ts_lock);
		}

		/* we may already be powered down, so only save state if up */
		if (state->ts_powered == TS_PWR_ON) {

			/* stop playing and recording */
			(void) audiots_stop_everything(state);

			/*
			 * Save the controller state. The Codec's state is
			 * already in ts_shadow[]. audiots_power_down()
			 * saves the state and gets us ready to be powered
			 * back up when we resume.
			 */
			if (state->ts_flags & TS_PM_SUPPORTED) {
				audiots_power_down(state);
			} else {
				audiots_save_controller(state);
			}
		}

		if (audio_sup_save_state(state->ts_ahandle,
		    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(state->ts_ahandle, CE_WARN,
			    "!detach() audio save failed");
		}

		mutex_exit(&state->ts_lock);

		ATRACE("ts_detach() SUSPEND successful", state);

		ASSERT(!mutex_owned(&state->ts_lock));

		return (DDI_SUCCESS);

	default:
		ATRACE_32("ts_detach() unknown command failure", cmd);
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!detach() unknown command: 0x%x", cmd);
		ASSERT(!mutex_owned(&state->ts_lock));
		return (DDI_FAILURE);
	}

	/* Make sure play and record are stopped and disable all interrupts */
	ATRACE("ts_detach() stopping all DMA engines before detaching", 0);
	mutex_enter(&state->ts_lock);
	audiots_stop_everything(state);
	mutex_exit(&state->ts_lock);

	if (state->ts_flags & TS_PM_SUPPORTED) {
		/*
		 * power down the device, no reason to waste power
		 * without a driver
		 */
		(void) pm_lower_power(state->ts_dip, TS_COMPONENT, TS_PWR_OFF);
	}

	/* remove the interrupt handler */
	ATRACE("ts_detach() removing interrupt handler", state);
	ddi_remove_intr(dip, 0, NULL);

	/* free the kernel statistics structure */
	if (state->ts_ksp) {
		kstat_delete(state->ts_ksp);
	}

	/*
	 * Call the mixer detach routine to tear down the mixer before
	 * we lose the hardware.
	 */
	ATRACE("ts_detach() calling am_detach()", dip);
	(void) am_detach(state->ts_ahandle, cmd);

	/*
	 * Now call the audio support module's detach routine to remove this
	 * driver completely from the audio driver architecture.
	 */
	ATRACE("ts_detach() calling audio_sup_unregister()", dip);
	(void) audio_sup_unregister(state->ts_ahandle);

	/* unmap the registers */
	audiots_unmap_regs(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* free temporary capture buffer */
	kmem_free(state->ts_tcbuf, state->ts_cbuf_size);

	/* destroy the state mutexes and cvs */
	mutex_destroy(&state->ts_lock);
	cv_destroy(&state->ts_cv);

	/* free the memory for the state pointer */
	ddi_soft_state_free(audiots_statep, instance);

	ATRACE("ts_detach() returning success", audiots_statep);

	return (DDI_SUCCESS);

}	/* audiots_detach() */


/*
 * audiots_power()
 *
 * Description:
 *	This routine is used to turn the power to the Codec and audio core
 *	on and off. The Codec's registers are always saved, however, when
 *	we power down we have to save the audio core's state. When powering
 *	on we restore both Codec and core state via audiots_chip_init().
 *
 *	This routine doesn't worry about starting or stopping audio, other
 *	routines have that responsibility.
 *
 * Arguments:
 *	def_info_t	*dip		Ptr to the device's dev_info structure
 *	int		component	Which component to power up/down
 *	int		level		The power level for the component
 *
 * Returns:
 *	DDI_SUCCESS			Power level changed
 *	DDI_FAILURE			Power level didn't change
 */
/*ARGSUSED*/
static int
audiots_power(dev_info_t *dip, int component, int level)
{
	audiots_state_t		*state;
	int			instance;
	int			rc = DDI_FAILURE;

	ATRACE("in ts_power()", dip);
	ATRACE("ts_power() audiots_statep", audiots_statep);
	ATRACE_32("ts_power() component", component);
	ATRACE_32("ts_power() level", level);

	instance = ddi_get_instance(dip);
	ATRACE_32("ts_power() instance", instance);

	/* get the state structure */
	if ((state = ddi_get_soft_state(audiots_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: power() get soft state failed", audiots_name,
		    instance);
		return (DDI_FAILURE);
	}

	ASSERT(!mutex_owned(&state->ts_lock));
	ASSERT(component == 0);

	mutex_enter(&state->ts_lock);

	/* PM should be enabled */
	ASSERT(state->ts_flags & TS_PM_SUPPORTED);

	/* check the level change to see what we need to do */
	if (level == TS_PWR_OFF && state->ts_powered == TS_PWR_ON) {
		ATRACE("ts_power() powering down", NULL);

		/* don't power off if we're busy */
		if (ddi_get32(state->ts_handle,
		    &state->ts_regs->aud_regs.ap_start) ||
		    state->ts_busy_cnt) {
			/* device is busy, so don't power off */
			mutex_exit(&state->ts_lock);

			/* reset the timer */
			(void) pm_idle_component(dip, TS_COMPONENT);

			ATRACE("ts_power() power off failed, busy",
			    state->ts_busy_cnt);
			ASSERT(rc == DDI_FAILURE);

			goto done;
		}

		/* power down and save the state */
		audiots_power_down(state);

		ATRACE("ts_power() power down complete", NULL);
	} else if (level == TS_PWR_ON && state->ts_powered == TS_PWR_OFF) {
		ATRACE("ts_power() powering up", NULL);

		audiots_power_up(state);

		ATRACE("ts_power() power up complete", NULL);
#ifdef DEBUG
	} else {
		ATRACE_32("ts_power() no change to make", level);
#endif
	}

	mutex_exit(&state->ts_lock);

	rc = DDI_SUCCESS;

done:

	ATRACE("ts_power() done", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_power() */

/* *******  DDAudio Entry Point Routines ************************************ */

/*
 * audiots_ad_setup()
 *
 * Description:
 *	This routine checks whether the audio hardware has failed. If so, it
 *	returns AUDIO_FAILURE and opens are blocked. Otherwise, it lets
 *	everything proceed as normal.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which is not how we program the device
 *					for now.
 *	int		dir		Direction of audio, we don't care here
 *
 * Returns:
 *	AUDIO_SUCCESS		The audio hardware is working
 *	AUDIO_FAILURE		The audio hardware has failed
 */
/*ARGSUSED*/
static int
audiots_ad_setup(audiohdl_t ahandle, int stream, int dir)
{
	audiots_state_t		*state;
	int			rc = AUDIO_SUCCESS;

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	ATRACE_32("in audiots_ad_setup(), instance", state->ts_instance);

	/* Check if the hardware has failed */
	mutex_enter(&state->ts_lock);
	if (state->ts_flags & TS_AUDIO_READ_FAILED) {
		ATRACE_32("ts_ad_setup() h/w has failed", state->ts_flags);
		rc = AUDIO_FAILURE;
	}
	mutex_exit(&state->ts_lock);

	ATRACE_32("ts_ad_setup() returning", rc);

	return (rc);

}	/* audiots_ad_setup() */

/*
 * audiots_ad_pause_play()
 *
 * Description:
 *	This routine pauses the play DMA engine.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which is not how we program the device
 *					for now.
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
audiots_ad_pause_play(audiohdl_t ahandle, int stream)
{
	audiots_state_t		*state;
	ddi_acc_handle_t	handle;

	ATRACE("in ts_ad_pause_play()", ahandle);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!pause_play() set_busy() failed");
		return;
	}

	mutex_enter(&state->ts_lock);

	handle = state->ts_handle;

	/* we don't do anything if we aren't already running */
	if (!(ddi_get32(handle, &state->ts_regs->aud_regs.ap_start) &
	    TS_OUTPUT_CHANNEL)) {
		ATRACE("ts_pause_play() DMA engine already stopped", state);
		goto done;
	}

	ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_stop,
	    TS_OUTPUT_CHANNEL);
	state->ts_flags |= TS_DMA_ENGINE_PAUSED;

done:
	mutex_exit(&state->ts_lock);

	/* we're no longer busy */
	audiots_set_idle(state);

	ATRACE("ts_ad_pause_play() done", state);

	ASSERT(!mutex_owned(&state->ts_lock));

}	/* audiots_ad_pause_play() */

/*
 * audiots_ad_set_config()
 *
 * Description:
 *	This routine is used to set new Codec parameters, except the data
 *	format which has it's own routine. If the Codec doesn't support a
 *	particular parameter and it is asked to set it then we return
 *	AUDIO_FAILURE.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which is not how we program the device
 *					for now.
 *	int		command		The configuration to set
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
 *	int		arg1		Argument #1
 *	int		arg2		Argument #2, not always needed
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set, or the
 *				parameter couldn't be set
 */
/*ARGSUSED*/
static int
audiots_ad_set_config(audiohdl_t ahandle, int stream, int command, int dir,
    int arg1, int arg2)
{
	audiots_state_t		*state;
	int			rc = AUDIO_FAILURE;

	ATRACE_32("ts_ad_set_config() stream", stream);
	ATRACE_32("ts_ad_set_config() command", command);
	ATRACE_32("ts_ad_set_config() dir", dir);
	ATRACE_32("ts_ad_set_config() arg1", arg1);
	ATRACE_32("ts_ad_set_config() arg2", arg2);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* Check if the hardware has failed */
	mutex_enter(&state->ts_lock);
	if (state->ts_flags & TS_AUDIO_READ_FAILED) {
		mutex_exit(&state->ts_lock);
		ATRACE_32("ts_ad_set_config() h/w has failed", state->ts_flags);
		return (AUDIO_FAILURE);
	}
	mutex_exit(&state->ts_lock);

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!set_config() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	/*
	 * CAUTION: From here on we must goto done to exit.
	 */

	switch (command) {
	case AM_SET_GAIN:
		/*
		 * Set the gain for a channel. The audio mixer calculates the
		 * impact, if any, of balance on gain.
		 *
		 *	AUDIO_MIN_GAIN <= gain <= AUDIO_MAX_GAIN
		 *
		 *	arg1 --> gain
		 *	arg2 --> channel #, 0 == left, 1 == right
		 */
		rc = audiots_set_gain(state, stream, dir, arg1, arg2);
		break;

	case AM_SET_PORT:
		/*
		 * Enable/disable the input or output ports. The audio mixer
		 * enforces exclusiveness of in ports, as well as which ports
		 * are modifiable. We just turn on the ports that match the
		 * bits.
		 *
		 *	arg1 --> port bit pattern
		 *	arg2 --> not used
		 */
		rc = audiots_set_port(state, dir, arg1);
		break;

	case AM_SET_MONITOR_GAIN:
		/*
		 * Set the loopback monitor gain.
		 *
		 *	AUDIO_MIN_GAIN <= gain <= AUDIO_MAX_GAIN
		 *
		 *	dir ---> N/A
		 *	arg1 --> gain
		 *	arg2 --> not used
		 */
		rc = audiots_set_monitor_gain(state, arg1);
		break;

	case AM_OUTPUT_MUTE:
		/*
		 * Mute or enable the output.
		 *
		 *	dir ---> N/A
		 *	arg1 --> ~0 == mute, 0 == enable
		 *	arg2 --> not used
		 */

		if (arg1) {	/* mute */
			mutex_enter(&state->ts_lock);
			audiots_or_ac97(state, AC97_MASTER_VOLUME_REGISTER,
			    MVR_MUTE);
			audiots_or_ac97(state, AC97_HEADPHONE_VOLUME_REGISTER,
			    HPVR_MUTE);
			audiots_or_ac97(state, AC97_MONO_MASTER_VOLUME_REGSITER,
			    MMVR_MUTE);
			mutex_exit(&state->ts_lock);
		} else {	/* not muted */
			/* by setting the port we unmute only active ports */
			(void) audiots_set_port(state, AUDIO_PLAY,
			    TS_PORT_UNMUTE);
		}

		rc = AUDIO_SUCCESS;
		break;

	case AM_MIC_BOOST:
		/*
		 * Enable or disable the mic's 20 dB boost preamplifier.
		 *
		 *	dir ---> N/A
		 *	arg1 --> ~0 == enable, 0 == disabled
		 *	arg2 --> not used
		 */
		mutex_enter(&state->ts_lock);

		if (arg1) {	/* enable */
			audiots_or_ac97(state, AC97_MIC_VOLUME_REGISTER,
			    MICVR_20dB_BOOST);
			state->ts_ad_info.ad_add_mode |= AM_ADD_MODE_MIC_BOOST;
		} else {	/* disable */
			audiots_and_ac97(state, AC97_MIC_VOLUME_REGISTER,
			    ~MICVR_20dB_BOOST);
			state->ts_ad_info.ad_add_mode &= ~AM_ADD_MODE_MIC_BOOST;
		}

		mutex_exit(&state->ts_lock);

		rc = AUDIO_SUCCESS;
		break;

	case AM_SET_DIAG_MODE:
		/*
		 * Set the loopback diagnostics mode.
		 *
		 *	arg1 --> 1 == diagnostics on, 0 == diagnostics off
		 *	arg2 --> not used
		 */
		mutex_enter(&state->ts_lock);

		if (arg1) {
			state->ts_ad_info.ad_add_mode |= AM_ADD_MODE_DIAG_MODE;
		} else {
			state->ts_ad_info.ad_add_mode &= ~AM_ADD_MODE_DIAG_MODE;
		}

		mutex_exit(&state->ts_lock);

		rc = AUDIO_SUCCESS;
		break;

	default:
		/*
		 * We let default catch commands we don't support, as well
		 * as bad commands.
		 */
		ATRACE_32("ts_ad_set_config() unsupported command", command);
		break;
	}

done:
	ATRACE_32("ts_ad_set_config() done", rc);

	/* we're no longer busy */
	audiots_set_idle(state);

	ATRACE_32("ts_ad_set_config() returning", rc);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_ad_set_config() */

/*
 * audiots_ad_set_format()
 *
 * Description:
 *	This routine is used to set a new audio control data format.
 *	We only support 8 and 16 bit signed linear.
 *
 *	NOTE: We don't support mono or 8-bit. See the WARNING at the
 *		top of the file.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		sample_rate	Data sample rate
 *	int		channels	Number of channels, 1 or 2
 *	int		precision	Bits per sample, 8 or 16
 *	int		encoding	Encoding method, u-law, A-law and linear
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec data format has been set
 *	AUDIO_FAILURE		The Codec data format has not been set, or the
 *				data format couldn't be set
 */
/*ARGSUSED*/
static int
audiots_ad_set_format(audiohdl_t ahandle, int stream, int dir,
    int sample_rate, int channels, int precision, int encoding)
{
	audiots_state_t		*state;
	ddi_acc_handle_t	handle;
	int			ch;
	int			rc = AUDIO_FAILURE;
	uint16_t		sign;
	uint16_t		tmp_short;

	ATRACE_32("ts_ad_set_format() stream", stream);
	ATRACE_32("ts_ad_set_format() dir", dir);
	ATRACE_32("ts_ad_set_format() sample rate", sample_rate);
	ATRACE_32("ts_ad_set_format() channels", channels);
	ATRACE_32("ts_ad_set_format() precision", precision);
	ATRACE_32("ts_ad_set_format() encoding", encoding);

	/*
	 * first, check the encoding method
	 */
	if (encoding != AUDIO_ENCODING_LINEAR) {
		ATRACE_32("ts_ad_set_format() bad encoding", encoding);
		return (AUDIO_FAILURE);
	}

	/*
	 * get the state structure
	 */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* Check if the hardware has failed */
	mutex_enter(&state->ts_lock);
	if (state->ts_flags & TS_AUDIO_READ_FAILED) {
		mutex_exit(&state->ts_lock);
		ATRACE_32("ts_ad_set_format() h/w has failed", state->ts_flags);
		return (AUDIO_FAILURE);
	}
	mutex_exit(&state->ts_lock);

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!set_format() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	/*
	 * CAUTION: From here on we must goto done to exit.
	 */

	switch (sample_rate) {
	case TS_SAMPR5510:		break;
	case TS_SAMPR6620:		break;
	case TS_SAMPR8000:		break;
	case TS_SAMPR9600:		break;
	case TS_SAMPR11025:		break;
	case TS_SAMPR16000:		break;
	case TS_SAMPR18900:		break;
	case TS_SAMPR22050:		break;
	case TS_SAMPR27420:		break;
	case TS_SAMPR32000:		break;
	case TS_SAMPR33075:		break;
	case TS_SAMPR37800:		break;
	case TS_SAMPR44100:		break;
	case TS_SAMPR48000:		break;
	default:
		ATRACE_32("ts_ad_set_format() bad SR", sample_rate);
		goto done;
	}

	/* can't fail, so update the saved format and implement */
	mutex_enter(&state->ts_lock);
	if (dir == AUDIO_PLAY) {
		/* save for later use */
		state->ts_psample_rate = sample_rate;
		state->ts_pchannels = channels;
		state->ts_pprecision = precision;

		/*
		 * first find the h/w channel with the stream
		 */
		ch = TS_OUTPUT_STREAM;

		/*
		 * convert the sample rate into 4.12 format
		 */
		sample_rate = (sample_rate << TS_SRC_SHIFT) / TS_SAMPR48000;

		/* for play we always use signed */
		sign = ERAM_SIGNED_PCM;

		ATRACE_32("ts_ad_set_format() play SR", sample_rate);
	} else {
		/* save for later use */
		state->ts_csample_rate = sample_rate;
		state->ts_cchannels = channels;
		state->ts_cprecision = precision;

		/*
		 * we set the only record stream
		 */
		ch = TS_INPUT_STREAM;

		/*
		 * convert the sample rate into 4.12 format
		 */
		sample_rate = (TS_SAMPR48000 << TS_SRC_SHIFT) / sample_rate;

		ATRACE_32("ts_ad_set_format() record SR", sample_rate);

		/* for 16-bit record we use signed */
		sign = ERAM_SIGNED_PCM;
	}

	/* check for stereo only */
	ASSERT(channels == AUDIO_CHANNELS_STEREO);
	channels = ERAM_STEREO;

	/* check for 16-bit only */
	ASSERT(precision == AUDIO_PRECISION_16);
	precision = ERAM_16_BITS;

	/* always linear encoding */
	ASSERT(encoding == AUDIO_ENCODING_LINEAR);

	/* program the sample rate */
	handle = state->ts_handle;
	ddi_put16(handle, &state->ts_regs->aud_ram[ch].aram.aram_delta,
	    (uint16_t)sample_rate);

	/* program the precision and number of channels */
	tmp_short = ddi_get16(handle,
	    &state->ts_regs->aud_ram[ch].eram.eram_ctrl_ec) & ~(ERAM_CTRL_MASK);
	tmp_short |= precision|channels|ERAM_LOOP_MODE|sign;
	ddi_put16(handle, &state->ts_regs->aud_ram[ch].eram.eram_ctrl_ec,
	    tmp_short);

	mutex_exit(&state->ts_lock);

	ATRACE("ts_ad_set_format() finished programming the device", 0);

	rc = AUDIO_SUCCESS;

done:
	ATRACE_32("ts_ad_set_format() done", rc);

	/* we're no longer busy */
	audiots_set_idle(state);

	ATRACE_32("ts_ad_set_format() returning", rc);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_ad_set_format() */

/*
 * audiots_ad_start_play()
 *
 * Description:
 *	Wrapper to call audiots_start_play().
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which is not how we program the device
 *					for now.
 * Returns:
 *	AUDIO_SUCCESS		Playing started/restarted
 *	AUDIO_FAILURE		Play not started/restarted, no audio to play
 */
/*ARGSUSED*/
static int
audiots_ad_start_play(audiohdl_t ahandle, int stream)
{
	audiots_state_t		*state;
	int			rc;

	ATRACE("in ts_ad_start_play() handle", ahandle);
	ATRACE_32("ts_ad_start_play() stream", stream);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* Check if the hardware has failed */
	mutex_enter(&state->ts_lock);
	if (state->ts_flags & TS_AUDIO_READ_FAILED) {
		mutex_exit(&state->ts_lock);
		ATRACE_32("ts_ad_start_play() h/w has failed", state->ts_flags);
		return (AUDIO_FAILURE);
	}
	mutex_exit(&state->ts_lock);

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!start_play() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	mutex_enter(&state->ts_lock);
	rc = audiots_start_play(state);

	if (rc == AUDIO_SUCCESS && (state->ts_flags & TS_PLAY_ACTIVE) == 0) {
		state->ts_flags |= TS_PLAY_ACTIVE;

		if (state->ts_flags & TS_PM_SUPPORTED) {
			(void) pm_busy_component(state->ts_dip, TS_COMPONENT);
		}
	}
	mutex_exit(&state->ts_lock);

	/* we're no longer busy */
	audiots_set_idle(state);

	ATRACE_32("ts_ad_start_play() returning", rc);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_ad_start_play() */

/*
 * audiots_ad_stop_play()
 *
 * Description:
 *	Wrapper to call audiots_stop_play().
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
audiots_ad_stop_play(audiohdl_t ahandle, int stream)
{
	audiots_state_t		*state;

	ATRACE("in ts_ad_stop_play()", ahandle);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!stop_play() set_busy() failed");
		return;
	}

	mutex_enter(&state->ts_lock);
	audiots_stop_play(state);

	if ((state->ts_flags & (TS_PM_SUPPORTED|TS_PLAY_ACTIVE)) ==
	    (TS_PM_SUPPORTED|TS_PLAY_ACTIVE)) {
		(void) pm_idle_component(state->ts_dip, TS_COMPONENT);
	}

	state->ts_flags &= ~TS_PLAY_ACTIVE;

	mutex_exit(&state->ts_lock);

	/* we're no longer busy */
	audiots_set_idle(state);

	ATRACE("ts_ad_stop_play() returning", state);

	ASSERT(!mutex_owned(&state->ts_lock));

}	/* audiots_ad_stop_play() */

/*
 * audiots_ad_start_record()
 *
 * Description:
 *	Wrapper to call audiots_start_record().
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which isn't going to apply for record
 *
 * Returns:
 *	AUDIO_SUCCESS		Recording successfully started
 *	AUDIO_FAILURE		Record not started
 */
/*ARGSUSED*/
static int
audiots_ad_start_record(audiohdl_t ahandle, int stream)
{
	audiots_state_t		*state;
	int			rc;

	ATRACE("in ts_ad_start_record()", ahandle);
	ATRACE_32("ts_ad_start_record() stream", stream);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* Check if the hardware has failed */
	mutex_enter(&state->ts_lock);
	if (state->ts_flags & TS_AUDIO_READ_FAILED) {
		mutex_exit(&state->ts_lock);
		ATRACE_32("ts_ad_start_record() h/w has failed",
		    state->ts_flags);
		return (AUDIO_FAILURE);
	}
	mutex_exit(&state->ts_lock);

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!start_record() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	mutex_enter(&state->ts_lock);
	rc = audiots_start_record(state);
	mutex_exit(&state->ts_lock);

	/* we're no longer busy */
	audiots_set_idle(state);

	ATRACE_32("ts_ad_start_record() returning", rc);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_ad_start_record() */

/*
 * audiots_ad_stop_record()
 *
 * Description:
 *	Wrapper to call audiots_stop_record().
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which isn't going to apply for record
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
audiots_ad_stop_record(audiohdl_t ahandle, int stream)
{
	audiots_state_t		*state;

	ATRACE("in ts_ad_stop_record()", ahandle);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* wait on suspend, power up and mark as busy */
	if (audiots_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!stop_record() set_busy() failed");
		return;
	}

	mutex_enter(&state->ts_lock);
	audiots_stop_record(state);

	if (state->ts_flags & TS_PM_SUPPORTED) {
		(void) pm_idle_component(state->ts_dip, TS_COMPONENT);
	}
	mutex_exit(&state->ts_lock);

	/* we're no longer busy */
	audiots_set_idle(state);

	ASSERT(!mutex_owned(&state->ts_lock));

}	/* audiots_ad_stop_record() */


/* ******* Local Routines *************************************************** */

/*
 * audiots_and_ac97()
 *
 * Description:
 *	Logically AND a value with the specified AC-97 Codec register.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		reg		AC-97 register number
 *	uint16_t	data		The value to AND
 *
 * Returns:
 *	void
 */
static void
audiots_and_ac97(audiots_state_t *state, int reg, uint16_t data)
{
	audiots_set_ac97(state, reg,
	    (data & state->ts_shadow[TS_CODEC_REG(reg)]));

}	/* audiots_and_ac97() */

/*
 * audiots_chip_init()
 *
 * Description:
 *	Initialize the audio core and the AC-97 Codec. The AC-97 Codec is
 *	always programmed from ts_shadow[]. If we aren't doing a restore
 *	we initialize ts_shadow[], otherwise we use the current values of
 *	ts_shadow[]. This allows this routine to be used for both attaching
 *	and for power management power up.
 *
 *	Speaker, line out and headphone out gain are not set to 0 gain.
 *	Thus their respective registers are never set to 0. Since the failed
 *	read and write over the AC-97 link results in a 0 we now know for
 *	sure if the write succeeded or not.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		restore		If TS_INIT_RESTORE then restore
 *					from ts_shadow[]
 *
 * Returns:
 *	void
 */
static void
audiots_chip_init(audiots_state_t *state, int restore)
{
	ddi_acc_handle_t	handle = state->ts_handle;
	int			i;
	int			str;

	ATRACE("in ts_chip_init()", state);
	ATRACE_32("ts_chip_init() restore", restore);

	/* set global music and wave volume to 0dB */
	ddi_put32(handle, &state->ts_regs->aud_regs.ap_volume, 0x0);

	/*
	 * Enable middle and end interrupts for all channels. Since
	 * we always set these we don't have to save it as well.
	 */
	ddi_put32(handle, &state->ts_regs->aud_regs.ap_cir_gc,
	    (AP_CIR_GC_ENDLP_IE|AP_CIR_GC_MIDLP_IE));

	/* for each channel, set gain and enable interrupts for middle & end */
	for (str = 0; str < TS_MAX_HW_CHANNELS; str++) {
		/*
		 * Set volume to 0dB attenuation, 1st left and then right.
		 * These are never changed, so we don't have to save them.
		 */
		ddi_put16(handle,
		    &state->ts_regs->aud_ram[str].eram.eram_gvsel_pan_vol,
		    (ERAM_WAVE_VOL|ERAM_PAN_LEFT|ERAM_PAN_0dB|
		    ERAM_VOL_DEFAULT));
		ddi_put16(handle,
		    &state->ts_regs->aud_ram[str].eram.eram_gvsel_pan_vol,
		    (ERAM_WAVE_VOL|ERAM_PAN_RIGHT|ERAM_PAN_0dB|
		    ERAM_VOL_DEFAULT));

		/*
		 * The envelope engine *MUST* remain in still mode (off).
		 * Otherwise bad things like gain randomly disappearing might
		 * happen. See bug #4332773.
		 */

		ddi_put32(handle,
		    &state->ts_regs->aud_ram[str].eram.eram_ebuf1,
		    ERAM_EBUF_STILL);
		ddi_put32(handle,
		    &state->ts_regs->aud_ram[str].eram.eram_ebuf2,
		    ERAM_EBUF_STILL);

		/* Set the eram and aram state */
		ddi_put16(handle,
		    &state->ts_regs->aud_ram[str].aram.aram_delta,
		    state->ts_save_regs[str].aram_delta);
		ddi_put16(handle,
		    &state->ts_regs->aud_ram[str].eram.eram_ctrl_ec,
		    state->ts_save_regs[str].eram_ctrl_ec);
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
	i = TS_WAIT_CNT;
	while ((audiots_get_ac97(state, AC97_POWERDOWN_CTRL_STAT_REGISTER) &
	    PCSR_POWERD_UP) != PCSR_POWERD_UP && i--) {
		drv_usecwait(1);
	}

	if ((restore == TS_INIT_RESTORE) && (state->ts_flags & TS_ATTACH_PWR)) {
		/*
		 * Here we're raising power at attach time, we need to
		 * initialize the shadow array and then mute the outputs.
		 * If we don't, there's a loud double pop on the headphones.
		 */
		for (str = 0; str < sizeof (ac97_v21_t); str += 2) {
			(void) audiots_get_ac97(state, str);
		}

		/* set outputs muted */
		state->ts_shadow[TS_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] =
		    MVR_MUTE;
		state->ts_shadow[TS_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE;
		state->ts_shadow
		    [TS_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE;
		state->ts_shadow[TS_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_MUTE;
	}

	/* preload shadow registers if not restoring */
	if (restore == TS_INIT_NO_RESTORE) {
		for (str = 0; str < sizeof (ac97_v21_t); str += 2) {
			/* read the Codec & save in the shadow register array */
			(void) audiots_get_ac97(state, str);
		}

		/* 02h - set master line out volume, muted, 0dB */
		state->ts_shadow[TS_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] =
		    MVR_MUTE|TS_AC97_ATTEN_LINE;

		/* 04h - set alternate line out volume, muted, 0dB */
		state->ts_shadow[TS_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE|TS_AC97_ATTEN_HP;

		/* 06h - set master mono volume, muted, 0dB */
		state->ts_shadow[
		    TS_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE|TS_AC97_ATTEN_SPKR;

		/* 08h - set master tone control to no modification */
		state->ts_shadow[
		    TS_CODEC_REG(AC97_MASTER_TONE_CONTROL_REGISTER)] =
		    MTCR_BASS_BYPASS|MTCR_TREBLE_BYPASS;

		/* 0ah - mute pc beep, 0dB */
		state->ts_shadow[TS_CODEC_REG(AC97_PC_BEEP_REGISTER)] =
		    PCBR_MUTE|PCBR_0dB_ATTEN;

		/* 0ch - set phone input, mute, 0dB attenuation */
		state->ts_shadow[TS_CODEC_REG(AC97_PHONE_VOLUME_REGISTER)] =
		    PVR_MUTE|PVR_0dB_GAIN;

		/* 0eh - set mic input, mute, 0dB attenuation */
		state->ts_shadow[TS_CODEC_REG(AC97_MIC_VOLUME_REGISTER)] =
		    MICVR_MUTE|MICVR_0dB_GAIN;

		/* 10h - set line input, mute, 0dB attenuation */
		state->ts_shadow[TS_CODEC_REG(AC97_LINE_IN_VOLUME_REGISTER)] =
		    LIVR_MUTE|LIVR_RIGHT_0dB_GAIN|LIVR_LEFT_0dB_GAIN;

		/* 12h - set cd input, mute, 0dB attenuation */
		state->ts_shadow[TS_CODEC_REG(AC97_CD_VOLUME_REGISTER)] =
		    CDVR_MUTE|CDVR_RIGHT_0dB_GAIN|CDVR_LEFT_0dB_GAIN;

		/* 14h - set video input, mute, 0dB attenuation */
		state->ts_shadow[TS_CODEC_REG(AC97_VIDEO_VOLUME_REGISTER)] =
		    VIDVR_MUTE|VIDVR_RIGHT_0dB_GAIN|VIDVR_LEFT_0dB_GAIN;

		/* 16h - set aux input, mute, 0dB attenuation */
		state->ts_shadow[TS_CODEC_REG(AC97_AUX_VOLUME_REGISTER)] =
		    AUXVR_MUTE|AUXVR_RIGHT_0dB_GAIN|AUXVR_LEFT_0dB_GAIN;

		/* 18h - set PCM out input, NOT muted, 0dB gain */
		state->ts_shadow[TS_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_RIGHT_0dB_GAIN|PCMOVR_LEFT_0dB_GAIN;

		/* 1ah - set input device as mic */
		state->ts_shadow[
		    TS_CODEC_REG(AC97_RECORD_SELECT_CTRL_REGISTER)] =
		    RSCR_R_MIC|RSCR_L_MIC;

		/* 1ch - set record gain to 0dB and not muted */
		state->ts_shadow[TS_CODEC_REG(AC97_RECORD_GAIN_REGISTER)] =
		    RGR_RIGHT_0db_GAIN|RGR_LEFT_0db_GAIN;

		/* 1eh - set record mic gain to 0dB and not muted */
		state->ts_shadow[TS_CODEC_REG(AC97_RECORD_GAIN_MIC_REGISTER)] =
		    RGMR_0db_GAIN;

		/* 20h - set GP register, mic 1, everything else off */
		state->ts_shadow[TS_CODEC_REG(AC97_GENERAL_PURPOSE_REGISTER)] =
		    GPR_MS_MIC1|GPR_MONO_MIX_IN;

		/* 22h - set 3D control to NULL */
		state->ts_shadow[TS_CODEC_REG(AC97_THREE_D_CONTROL_REGISTER)] =
		    TDCR_NULL;

		/*
		 * The rest we ignore, most are reserved.
		 *
		 * CAUTION: If we add to the list we need to fix the end
		 *	of the loop below.
		 */
	}

	/* now program the AC-97 Codec from ts_shadow[] */
	for (i = 0; i < TS_LAST_AC_REG; i += TS_REG_SIZE) {
		audiots_set_ac97(state, i, state->ts_shadow[TS_CODEC_REG(i)]);
	}

	ATRACE("ts_chip_init() returning", state);

}	/* audiots_chip_init() */

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
audiots_get_ac97(audiots_state_t *state, int reg)
{
	ddi_acc_handle_t	handle = state->ts_handle;
	uint16_t		*data;
	int			count;
	int			delay;
	uint16_t		first;
	uint16_t		next;

	ATRACE_32("in ts_get_ac97()", reg);

	if (state->ts_rev_id == AC_REV_ID1) {
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
	/* save the value in the shadow register array */
	state->ts_shadow[TS_CODEC_REG(reg)] = next;

	ATRACE_16("ts_get_ac97() returning",
	    state->ts_shadow[TS_CODEC_REG(reg)]);

	/*
	 * Arggg, if you let the next read happen too soon then it fails.
	 * 12 usec fails, 13 usec succeeds. So set it to 20 for safety.
	 */
	drv_usecwait(TS_20US);

	return (state->ts_shadow[TS_CODEC_REG(reg)]);

}	/* audiots_get_ac97() */

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
 *	AUDIO_SUCCESS			State structure initialized
 *	AUDIO_FAILURE			State structure not initialized
 */
static int
audiots_init_state(audiots_state_t *state, dev_info_t *dip)
{
	int			ts_pints;
	int			ts_rints;
	int			cdrom = 0;

	ATRACE("in ts_init_state()", NULL);

	/* get the number of play and record interrupts per second */
	ts_pints = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "play-interrupts", TS_INTS);
	ts_rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "record-interrupts", TS_INTS);

	/* make sure the values are good */
	if (ts_pints < TS_MIN_INTS) {
		ATRACE_32("ts_init_state() "
		    "play interrupt rate set too low, resetting", ts_pints);
		audio_sup_log(state->ts_ahandle, CE_NOTE, "init_state() "
		    "play interrupt rate set too low, %d, resetting to %d",
		    ts_pints, TS_MIN_INTS);
		ts_pints = TS_INTS;
	} else if (ts_pints > TS_MAX_INTS) {
		ATRACE_32("ts_init_state() "
		    "play interrupt rate set too high, resetting", ts_pints);
		audio_sup_log(state->ts_ahandle, CE_NOTE, "init_state() "
		    "play interrupt rate set too high, %d, resetting to %d",
		    ts_pints, TS_MAX_INTS);
		ts_pints = TS_INTS;
	}
	if (ts_rints < TS_MIN_INTS) {
		ATRACE_32("ts_init_state() "
		    "record interrupt rate set too low, resetting", ts_rints);
		audio_sup_log(state->ts_ahandle, CE_NOTE, "init_state() "
		    "record interrupt rate set too low, %d, resetting to %d",
		    ts_rints, TS_MIN_INTS);
		ts_rints = TS_INTS;
	} else if (ts_rints > TS_MAX_INTS) {
		ATRACE_32("ts_init_state() "
		    "record interrupt rate set too high, resetting", ts_rints);
		audio_sup_log(state->ts_ahandle, CE_NOTE, "init_state() "
		    "record interrupt rate set too high, %d, resetting to %d",
		    ts_rints, TS_MAX_INTS);
		ts_rints = TS_INTS;
	}

	/* get the mode from the .conf file */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mixer-mode", AM_MIXER_MODE)) {
		state->ts_ad_info.ad_mode = AM_MIXER_MODE;
	} else {
		state->ts_ad_info.ad_mode = AM_COMPAT_MODE;
	}

	ATRACE_32("ts_init_state() setting mode", state->ts_ad_info.ad_mode);

	/* figure out the platform */
	cdrom = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "cdrom", 0);

	/* save the device info pointer */
	state->ts_dip = dip;

	/* get the iblock cookie needed for interrupt context */
	if (ddi_get_iblock_cookie(dip, (uint_t)0, &state->ts_iblock) !=
	    DDI_SUCCESS) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!init_state() cannot get iblock cookie");
		return (AUDIO_FAILURE);
	}

	/* initialize the state mutexes and condition variables */
	mutex_init(&state->ts_lock, NULL, MUTEX_DRIVER, state->ts_iblock);
	cv_init(&state->ts_cv, NULL, CV_DRIVER, NULL);

	/*
	 * CAUTION: From here on we must destroy the mutexes if there's
	 *	an error and we return failure.
	 */
	/* fill in the device default state */
	state->ts_defaults.play.sample_rate = TS_DEFAULT_SR;
	state->ts_defaults.play.channels = TS_DEFAULT_CH;
	state->ts_defaults.play.precision = TS_DEFAULT_PREC;
	state->ts_defaults.play.encoding = TS_DEFAULT_ENC;
	state->ts_defaults.play.gain = TS_DEFAULT_PGAIN;
	state->ts_defaults.play.port = AUDIO_SPEAKER|AUDIO_HEADPHONE;
	state->ts_defaults.play.avail_ports = AUDIO_SPEAKER|AUDIO_HEADPHONE|\
	    AUDIO_LINE_OUT;
	state->ts_defaults.play.mod_ports = AUDIO_SPEAKER|AUDIO_LINE_OUT;
	state->ts_defaults.play.buffer_size = TS_BSIZE;
	state->ts_defaults.play.balance = TS_DEFAULT_BAL;
	state->ts_defaults.record.sample_rate = TS_DEFAULT_SR;
	state->ts_defaults.record.channels = TS_DEFAULT_CH;
	state->ts_defaults.record.precision = TS_DEFAULT_PREC;
	state->ts_defaults.record.encoding = TS_DEFAULT_ENC;
	state->ts_defaults.record.gain = TS_DEFAULT_PGAIN;
	state->ts_defaults.record.port = AUDIO_MICROPHONE;
	state->ts_defaults.record.avail_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	state->ts_defaults.record.mod_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	state->ts_defaults.record.buffer_size = TS_BSIZE;
	state->ts_defaults.record.balance = TS_DEFAULT_BAL;
	state->ts_defaults.monitor_gain = TS_DEFAULT_MONITOR_GAIN;
	state->ts_defaults.output_muted = B_FALSE;
	state->ts_defaults.ref_cnt = B_FALSE;
	state->ts_defaults.hw_features = AUDIO_HWFEATURE_DUPLEX|
	    AUDIO_HWFEATURE_IN2OUT|AUDIO_HWFEATURE_PLAY|AUDIO_HWFEATURE_RECORD;
	state->ts_defaults.sw_features = AUDIO_SWFEATURE_MIXER;

	/* add CD ROM for birdsnest */
	if (cdrom) {
		state->ts_defaults.record.avail_ports |= AUDIO_CD;
		state->ts_defaults.record.mod_ports |= AUDIO_CD;
	}

	state->ts_psample_rate = state->ts_defaults.play.sample_rate;
	state->ts_pchannels = state->ts_defaults.play.channels;
	state->ts_pprecision = state->ts_defaults.play.precision;
	state->ts_csample_rate = state->ts_defaults.record.sample_rate;
	state->ts_cchannels = state->ts_defaults.record.channels;
	state->ts_cprecision = state->ts_defaults.record.precision;

	/* fill in the ad_info structure */
	state->ts_ad_info.ad_int_vers = AM_VERSION;
	state->ts_ad_info.ad_add_mode = NULL;
	state->ts_ad_info.ad_codec_type = AM_TRAD_CODEC;
	state->ts_ad_info.ad_defaults = &state->ts_defaults;
	state->ts_ad_info.ad_play_comb = audiots_combinations;
	state->ts_ad_info.ad_rec_comb = audiots_combinations;
	state->ts_ad_info.ad_entry = &audiots_entry;
	state->ts_ad_info.ad_dev_info = &state->ts_dev_info;
	state->ts_ad_info.ad_diag_flags = AM_DIAG_INTERNAL_LOOP;
	state->ts_ad_info.ad_diff_flags =
	    AM_DIFF_SR|AM_DIFF_CH|AM_DIFF_PREC|AM_DIFF_ENC;
	state->ts_ad_info.ad_assist_flags = AM_ASSIST_MIC;
	state->ts_ad_info.ad_misc_flags = AM_MISC_RP_EXCL|AM_MISC_MONO_DUP;
	state->ts_ad_info.ad_translate_flags = AM_MISC_8_R_TRANSLATE;
	state->ts_ad_info.ad_num_mics = 1;

	/* play capabilities */
	state->ts_ad_info.ad_play.ad_mixer_srs = audiots_mixer_sample_rates;
	state->ts_ad_info.ad_play.ad_compat_srs = audiots_compat_sample_rates;
	state->ts_ad_info.ad_play.ad_conv = &am_src2;
	state->ts_ad_info.ad_play.ad_sr_info = NULL;
	state->ts_ad_info.ad_play.ad_chs = audiots_channels;
	state->ts_ad_info.ad_play.ad_int_rate = ts_pints;
	state->ts_ad_info.ad_play.ad_max_chs = TS_MAX_OUT_CHANNELS;
	state->ts_ad_info.ad_play.ad_bsize = TS_BSIZE;

	/* record capabilities */
	state->ts_ad_info.ad_record.ad_mixer_srs = audiots_mixer_sample_rates;
	state->ts_ad_info.ad_record.ad_compat_srs = audiots_compat_sample_rates;
	state->ts_ad_info.ad_record.ad_conv = &am_src2;
	state->ts_ad_info.ad_record.ad_sr_info = NULL;
	state->ts_ad_info.ad_record.ad_chs = audiots_channels;
	state->ts_ad_info.ad_record.ad_int_rate = ts_rints;
	state->ts_ad_info.ad_record.ad_max_chs = TS_MAX_CHANNELS;
	state->ts_ad_info.ad_record.ad_bsize = TS_BSIZE;

	/* fill in device info strings */
	(void) strcpy(state->ts_dev_info.name, TS_DEV_NAME);
	(void) strcpy(state->ts_dev_info.config, TS_DEV_CONFIG);
	if (!cdrom) {
		(void) strcpy(state->ts_dev_info.version, TS_DEV_VERSION_A);
	} else {
		(void) strcpy(state->ts_dev_info.version, TS_DEV_VERSION_B);
	}

	/*
	 * Figure out the largest transfer size for the DMA engine. We then
	 * double the size because an interrupt happens in the middle and
	 * the end of the buffer. This size must be modulo 16 to fit two 16-bit
	 * stereo streams in on the interrupt boundaries, middle and end,
	 * with an 8-byte boundary.
	 */
	state->ts_pbuf_size = TS_BUF_HALVES * TS_SAMPR48000 *
	    AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / ts_pints;
	state->ts_pbuf_size += TS_MOD_SIZE -
	    (state->ts_pbuf_size % TS_MOD_SIZE);
	ASSERT(state->ts_pbuf_size > 0);
	ASSERT((state->ts_pbuf_size % TS_MOD_SIZE) == 0);

	state->ts_cbuf_size = TS_BUF_HALVES * TS_SAMPR48000 *
	    AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / ts_rints;
	state->ts_cbuf_size += TS_MOD_SIZE -
	    (state->ts_cbuf_size % TS_MOD_SIZE);
	ASSERT(state->ts_cbuf_size > 0);
	ASSERT((state->ts_cbuf_size % TS_MOD_SIZE) == 0);
	state->ts_tcbuf = kmem_alloc(state->ts_cbuf_size, KM_SLEEP);

	/* init power management state */
	state->ts_suspended = TS_NOT_SUSPENDED;
	state->ts_powered = TS_PWR_OFF;
	state->ts_busy_cnt = 0;

	ATRACE("ts_init_state() success", NULL);

	return (AUDIO_SUCCESS);

}	/* audiots_init_state() */

/*
 * audiots_intr()
 *
 * Description:
 *	Interrupt service routine for both play and record. For play we
 *	get the next buffers worth of audio. For record we send it on to
 *	the mixer.
 *
 *	NOTE: This device needs to make sure any PIO access required to clear
 *	its interrupt has made it out on the PCI bus before returning from its
 *	interrupt handler so that the interrupt has been deasserted. This is
 *	done by rereading the address engine interrupt register.
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
audiots_intr(caddr_t T)
{
	audiots_state_t		*state = (audiots_state_t *)T;
	ddi_acc_handle_t	handle;
	char			*bptr;
	uint16_t		*sptr;
	uint16_t		*tcbuf;
	uint32_t		interrupts;
	uint32_t		location;
	int			i;
	int			count;
	int			samples;
	int			rc = DDI_INTR_UNCLAIMED;

	ATRACE("in ts_intr()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	mutex_enter(&state->ts_lock);

	handle = state->ts_handle;

	if (state->ts_flags & TS_INTR_PENDING) {
		state->ts_flags &= ~TS_INTR_PENDING;
		rc = DDI_INTR_CLAIMED;
		mutex_exit(&state->ts_lock);
		ATRACE("ts_intr() servicing with pending intr from stop()", 0);
		goto done;
	}

	interrupts = ddi_get32(handle, &state->ts_regs->aud_regs.ap_aint);
	ATRACE_32("ts_intr() interrupts", interrupts);
	if (interrupts == 0) {
		mutex_exit(&state->ts_lock);
		/* no interrupts to process, so it's not us */
		ATRACE_32("ts_intr() device didn't send interrupt", interrupts);
		ASSERT(rc == DDI_INTR_UNCLAIMED);
		goto done;
	}

	if (interrupts & TS_OUTPUT_CHANNEL) {	/* play interrupt */
		ATRACE_32("ts_intr() play interrupt", interrupts);

		/* is this in the 1st or 2nd half of the buffer? */
		location = ddi_get32(handle, &state->ts_regs->aud_regs.ap_cspf);

		/* clear the interrupt, should this be after getting loc? */
		ddi_put32(handle, &state->ts_regs->aud_regs.ap_aint,
		    TS_OUTPUT_CHANNEL);

		/*
		 * Reread the interrupt reg to ensure that
		 * PIO write has completed.
		 */
		(void) ddi_get32(handle, &state->ts_regs->aud_regs.ap_aint);

		/* set up for 1st or 2nd half */
		if (location & TS_OUTPUT_CHANNEL) {	/* in the 2nd half */
			bptr = &state->ts_pb[TS_1ST_HALF];
			count = state->ts_pcnt[TS_1ST_HALF];
			samples = state->ts_psamples[TS_1ST_HALF];
		} else {				/* in 1st half */
			/* pcnt[0] could be different from pcnt[TS_2ND_HALF] */
			bptr = &state->ts_pb[state->ts_pcnt[TS_1ST_HALF]];
			count = state->ts_pcnt[TS_2ND_HALF];
			samples = state->ts_psamples[TS_2ND_HALF];
		}

		/* always zero for silence */
		bzero(bptr, count);

		/* get the next chunk of audio */
		mutex_exit(&state->ts_lock);
		if (am_get_audio(state->ts_ahandle, bptr, AUDIO_NO_CHANNEL,
		    samples) == 0) {
			mutex_enter(&state->ts_lock);
			if (state->ts_flags & TS_DMA_ENGINE_EMPTY) {
				/*
				 * Clear the flag so if audio is restarted while
				 * in am_play_shutdown() we can detect it and
				 * not mess things up.
				 */
				state->ts_flags &= ~TS_DMA_ENGINE_INITIALIZED;

				/* shutdown the mixer */
				mutex_exit(&state->ts_lock);
				am_play_shutdown(state->ts_ahandle, NULL);
				mutex_enter(&state->ts_lock);

				/*
				 * Make sure playing wasn't restarted when
				 * lock lost.
				 */
				if (state->ts_flags &
				    TS_DMA_ENGINE_INITIALIZED) {
					/* yes, it was, so we're done */
					ATRACE("ts_intr() restart after"
					    "shutdown", 0);
					rc = DDI_INTR_CLAIMED;
					goto rec_intr;
				}

				/* done playing, so stop playing */
				ddi_put32(handle,
				    &state->ts_regs->aud_regs.ap_stop,
				    TS_OUTPUT_CHANNEL);

				/* clr the flags getting ready for next start */
				state->ts_flags &= ~(TS_DMA_ENGINE_PAUSED|
				    TS_DMA_ENGINE_EMPTY);
			} else {
				/* next time we shut down, if no sound again */
				state->ts_flags |= TS_DMA_ENGINE_EMPTY;
			}
		} else {
			mutex_enter(&state->ts_lock);
			/* we got at least one sample, so don't shutdown yet */
			state->ts_flags &= ~TS_DMA_ENGINE_EMPTY;
			(void) ddi_dma_sync(state->ts_ph, (off_t)bptr, count,
			    DDI_DMA_SYNC_FORDEV);
		}
		rc = DDI_INTR_CLAIMED;
	}

rec_intr:

	if (interrupts & TS_INPUT_CHANNEL) {	/* record interrupt */
		ATRACE_32("ts_intr() record interrupt", interrupts);

		/* is this in the 1st or 2nd half of the buffer? */
		location = ddi_get32(handle, &state->ts_regs->aud_regs.ap_cspf);
		ATRACE_32("ts_intr(c) location", location);

		/* clear the interrupt, should this be after getting loc? */
		ddi_put32(handle, &state->ts_regs->aud_regs.ap_aint,
		    TS_INPUT_CHANNEL);

		/*
		 * Reread the interrupt reg to ensure that
		 * PIO write has completed.
		 */
		(void) ddi_get32(handle, &state->ts_regs->aud_regs.ap_aint);

		if (location & TS_INPUT_CHANNEL_MASK) {
			/* 1st half just filled */
			if (state->ts_flags & TS_DMA_RECORD_START) {
			    /* skip the first interrupt, it is NULL */
				state->ts_flags &= ~TS_DMA_RECORD_START;
			} else {
				if (ddi_dma_sync(state->ts_ch,
				    (off_t)((state->ts_ccnt<<1) - TS_FIFO_SIZE),
				    TS_FIFO_SIZE, DDI_DMA_SYNC_FORCPU) ==
				    DDI_FAILURE) {
					audio_sup_log(state->ts_ahandle,
					    CE_NOTE,
					    "!dma_sync(1) failed audio lost");
					mutex_exit(&state->ts_lock);
					goto done;
				}
				samples = TS_FIFO_SIZE /
				    (state->ts_cprecision >>
				    AUDIO_PRECISION_SHIFT);

				sptr =  (uint16_t *)
				    &state->ts_cb[(state->ts_ccnt<<1) -
				    TS_FIFO_SIZE];
				for (i = 0; i < (TS_FIFO_SIZE/2); i++) {
					state->ts_tcbuf[i] = sptr[i];
				}
				ATRACE_32("ts_intr(c1) "
				"calling am_send_audio() samples", samples);
				tcbuf = state->ts_tcbuf;
				mutex_exit(&state->ts_lock);
				am_send_audio(state->ts_ahandle, tcbuf,
				    AUDIO_NO_CHANNEL, samples);
				mutex_enter(&state->ts_lock);

				if (ddi_dma_sync(state->ts_ch, (off_t)0,
				    state->ts_ccnt - TS_FIFO_SIZE,
				    DDI_DMA_SYNC_FORCPU) == DDI_FAILURE) {
					audio_sup_log(state->ts_ahandle,
					    CE_NOTE,
					    "!dma_sync(2) failed audio lost");
					mutex_exit(&state->ts_lock);
					goto done;
				}
				samples = (state->ts_ccnt - TS_FIFO_SIZE) /
				    (state->ts_cprecision >>
				    AUDIO_PRECISION_SHIFT);

				sptr =  (uint16_t *)state->ts_cb;
				count = (state->ts_ccnt - TS_FIFO_SIZE) >> 1;
				for (i = 0; i < count; i++) {
				state->ts_tcbuf[i] = sptr[i];
				}
				ATRACE_32("ts_intr(c2) "
				"calling am_send_audio() samples", samples);
				tcbuf = state->ts_tcbuf;
				mutex_exit(&state->ts_lock);
				am_send_audio(state->ts_ahandle, tcbuf,
				    AUDIO_NO_CHANNEL, samples);
				mutex_enter(&state->ts_lock);
			}
		} else {
			/* 2nd half just filled */
			if (ddi_dma_sync(state->ts_ch,
			    (off_t)(state->ts_ccnt - TS_FIFO_SIZE),
			    state->ts_ccnt, DDI_DMA_SYNC_FORCPU) ==
			    DDI_FAILURE) {
				audio_sup_log(state->ts_ahandle, CE_NOTE,
				    "!dma_sync(2) failed audio lost");
				mutex_exit(&state->ts_lock);
				goto done;
			}
			samples = state->ts_ccnt / (state->ts_cprecision >>
			    AUDIO_PRECISION_SHIFT);

			sptr = (uint16_t *)&state->ts_cb[state->ts_ccnt -
			    TS_FIFO_SIZE];
			count = state->ts_ccnt >> 1;
			for (i = 0; i < count; i++) {
				state->ts_tcbuf[i] = sptr[i];
			}
			ATRACE_32("ts_intr(c3) "
			    "calling am_send_audio() samples", samples);
			tcbuf = state->ts_tcbuf;
			mutex_exit(&state->ts_lock);
			am_send_audio(state->ts_ahandle, tcbuf,
			    AUDIO_NO_CHANNEL, samples);
			mutex_enter(&state->ts_lock);
		}

		rc = DDI_INTR_CLAIMED;
	}

	interrupts &= ~(TS_INPUT_CHANNEL|TS_OUTPUT_CHANNEL);
	if (interrupts) {
		/*
		 * handle, but don't service non play or record audiots
		 * interrupts and shutdown the other DMA engines if they
		 * somehow activated themselves - which is why we are here in
		 * the first place.
		 */
		ATRACE_32("ts_intr() unused audiots interrupt", interrupts);
		ddi_put32(handle, &state->ts_regs->aud_regs.ap_aint,
		    interrupts);
		/*
		 * Reread the interrupt reg to ensure that
		 * PIO write has completed.
		 */
		(void) ddi_get32(handle, &state->ts_regs->aud_regs.ap_aint);

		AND_SET_WORD(handle, &state->ts_regs->aud_regs.ap_ainten,
		    TS_INPUT_CHANNEL|TS_OUTPUT_CHANNEL);

		ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_stop,
		    ~(TS_INPUT_CHANNEL|TS_OUTPUT_CHANNEL));

		rc = DDI_INTR_CLAIMED;
	}

	/* update the kernel interrupt statistics */
	if (state->ts_ksp) {
		if (rc == DDI_INTR_CLAIMED) {
			TS_KIOP(state)->intrs[KSTAT_INTR_HARD]++;
		}
	}

	mutex_exit(&state->ts_lock);

done:
	ATRACE("audiots_intr() done", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_intr() */

/*
 * audiots_map_regs()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use. It then binds each of the buffers to its
 *	respective handle, getting a DMA cookie. Finally, the registers
 *	are mapped in.
 *
 *	Once the config space registers are mapped in we determine if the
 *	audio core may be power managed. It should, but if it doesn't,
 *	then trying to may cause the core to hang.
 *
 *	NOTE: All of the ddi_dma_... routines sleep if they cannot get
 *		memory. This means these calls will almost always succeed.
 *
 *	NOTE: ddi_dma_alloc_handle() attempts to use the full 4 GB DMA address
 *		range. This is to work around Southbridge rev E/G OBP issues.
 *		(See Grover OBP note above)
 *
 *	CAUTION: Make sure all errors call audio_sup_log().
 *
 * Arguments:
 *	dev_info_t	*dip            Pointer to the device's devinfo
 *	audiots_state_t	*state          The device's state structure
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
audiots_map_regs(dev_info_t *dip, audiots_state_t *state)
{
	uint_t			dma_cookie_count;
	uint32_t		rev_id;
	int			rc;

	ATRACE("in ts_map_regs()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* allocate one handle for play and one for record */
	if ((rc = ddi_dma_alloc_handle(dip, &audiots_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->ts_ph)) != DDI_SUCCESS) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_dma_alloc_handle(P) failed: %d", rc);
		goto error;
	}
	if ((rc = ddi_dma_alloc_handle(dip, &audiots_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &state->ts_ch)) != DDI_SUCCESS) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_dma_alloc_handle(C) failed: %d", rc);
		goto error_ph;
	}

	/* allocate the two DMA buffers, one for play and one for record */
	ASSERT(state->ts_pbuf_size > 0);
	ASSERT(state->ts_cbuf_size > 0);
	if (ddi_dma_mem_alloc(state->ts_ph, state->ts_pbuf_size, &ts_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &state->ts_pb,
	    &state->ts_pml, &state->ts_pmh) == DDI_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_dma_mem_alloc(P) failed");
		goto error_ch;
	}
	if (ddi_dma_mem_alloc(state->ts_ch, state->ts_cbuf_size, &ts_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &state->ts_cb,
	    &state->ts_cml, &state->ts_cmh) == DDI_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_dma_mem_alloc(C) failed");
		goto error_pmh;
	}

	/* bind each of the buffers to a DMA handle */
	if ((rc = ddi_dma_addr_bind_handle(state->ts_ph, (struct as *)0,
	    state->ts_pb, state->ts_pbuf_size, DDI_DMA_WRITE|DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, (caddr_t)0, &state->ts_pc, &dma_cookie_count)) !=
	    DDI_DMA_MAPPED) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_dma_addr_bind_handle(P) failed: %d", rc);
		goto error_cmh;
	}
	ASSERT(dma_cookie_count == 1);
	if ((rc = ddi_dma_addr_bind_handle(state->ts_ch, (struct as *)0,
	    state->ts_cb, state->ts_cbuf_size, DDI_DMA_READ|DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, (caddr_t)0, &state->ts_cc, &dma_cookie_count)) !=
	    DDI_DMA_MAPPED) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_dma_addr_bind_handle(C) failed: %d", rc);
		goto error_pc;
	}
	ASSERT(dma_cookie_count == 1);

	/* map in the registers, the config and memory mapped registers */
	if (ddi_regs_map_setup(dip, TS_CONFIG_REGS,
	    (caddr_t *)&state->ts_config, 0, 0, &ts_acc_attr,
	    &state->ts_chandle) != DDI_SUCCESS) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_regs_map_setup() failed: %d", rc);
		goto error_cc;
	}

	/* make sure we can power manage the audio core */
	if (ddi_get16(state->ts_chandle, &state->ts_config->tsc_cap_ptr) ==
	    TS_CAP_PTR) {
		state->ts_pm_core = TS_PWR_MANAGE;
		ATRACE("Audio core is power manageable", 0);
	} else {
		state->ts_pm_core = TS_NO_PWR_MANAGE;
		ATRACE("Audio core is not power manageable", 0);
	}

	if (ddi_regs_map_setup(dip, TS_MEM_MAPPED_REGS,
	    (caddr_t *)&state->ts_regs, 0, 0, &ts_acc_attr,
	    &state->ts_handle) != DDI_SUCCESS) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!map_regs() ddi_regs_map_setup() failed: %d", rc);
		goto error_unmap;
	}

	/* Read the Audio Controller's revision ID */
	rev_id = ddi_get32(state->ts_chandle,
	    &state->ts_config->tsc_class_code_rev_id);
	if (rev_id & AC_REV_ID1) {
		state->ts_rev_id = AC_REV_ID1;
		ATRACE("Old SB audio rev ID", rev_id);
	} else if (rev_id & AC_REV_ID2) {
		state->ts_rev_id = AC_REV_ID2;
		ATRACE("New SB audio rev ID", rev_id);
	} else {
		/* Unknown rev, who knows what else has changed... */
		ATRACE("Unknown SB rev - don't use", rev_id);
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "map_regs() unsupported SouthBridge Chip revision: %x",
		    rev_id);
		return (AUDIO_FAILURE);
	}

	/* let the state structure know about the attributes */
	state->ts_dma_attr = &audiots_attr;

	ATRACE("ts_map_regs() returning success", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (AUDIO_SUCCESS);

error_unmap:
	ddi_regs_map_free(&state->ts_chandle);
error_cc:
	(void) ddi_dma_unbind_handle(state->ts_ch);
error_pc:
	(void) ddi_dma_unbind_handle(state->ts_ph);
error_cmh:
	ddi_dma_mem_free(&state->ts_cmh);
error_pmh:
	ddi_dma_mem_free(&state->ts_pmh);
error_ch:
	ddi_dma_free_handle(&state->ts_ch);
error_ph:
	ddi_dma_free_handle(&state->ts_ph);
error:
	ATRACE("ts_map_regs() returning failure", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (AUDIO_FAILURE);

}	/* audiots_map_regs() */

/*
 * audiots_or_ac97()
 *
 * Description:
 *	Logically OR a value with the specified AC-97 Codec register.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		reg		AC-97 register number
 *	uint16_t	data		The value to OR
 *
 * Returns:
 *	void
 */
static void
audiots_or_ac97(audiots_state_t *state, int reg, uint16_t data)
{

	audiots_set_ac97(state, reg,
	    (data | state->ts_shadow[TS_CODEC_REG(reg)]));

}	/* audiots_or_ac97() */

/*
 * audiots_power_down()
 *
 * Description:
 *	Power down the AC-97 Codec and then, if allowed, power down
 *	the audio core. The audio core implements PCI power management
 *	version 1.0. We don't support state D3 (cold) since we don't
 *	have an external device to drive reseting the core to get it
 *	back up and running. We just toggle between D0 and D3 since
 *	we need the device either all on or all off.
 *
 *	Minimum transition times between the power states:
 *		D0 <---> D1	no time delay
 *		D0 <---> D2	200 microseconds
 *		D0 <---> D3	10 milliseconds
 *
 *	To be safe I'm doubling that time because if you don't wait
 *	long enough you get a hard hang for the app opening audio.
 *
 *	AC-97 Codec's walk from power states PR0 through PR5 plus the
 *	optional PR6 and EAPD. We always set PR6 EAPD since they don't
 *	hurt anything. Then we walk to PR2|PR3. We don't go any further
 *	because this requires that we do a cold reset. Since this pin
 *	isn't connected in the 1553 we can't do this.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiots_power_down(audiots_state_t *state)
{
	ATRACE("in audiots_power_down() done", state);

	ASSERT(mutex_owned(&state->ts_lock));

	/* PM should be enabled */
	ASSERT(state->ts_flags & TS_PM_SUPPORTED);

	/* No interrupts should be pending before we power down */
	ASSERT(ddi_get32(state->ts_handle,
	    &state->ts_regs->aud_regs.ap_aint) == 0);
	ASSERT(ddi_get32(state->ts_handle,
	    &state->ts_regs->aud_regs.ap_eint) == 0);

	/* powering down, save the audio core's state */
	audiots_save_controller(state);

	/* power down the Codec, also shut down external amps */
	audiots_set_ac97(state, AC97_POWERDOWN_CTRL_STAT_REGISTER,
	    (PCSR_PR6|PCSR_EAPD));

	/* shut down ADC and inputs */
	audiots_set_ac97(state, AC97_POWERDOWN_CTRL_STAT_REGISTER, PCSR_PR0);

	/* shut down DAC */
	audiots_set_ac97(state, AC97_POWERDOWN_CTRL_STAT_REGISTER, PCSR_PR1);

	/* shut down analog mixer and Vref */
	audiots_set_ac97(state, AC97_POWERDOWN_CTRL_STAT_REGISTER,
	    (PCSR_PR2|PCSR_PR3));

	/* MUST clear the shadow register so we can power up! */
	state->ts_shadow[TS_CODEC_REG(AC97_POWERDOWN_CTRL_STAT_REGISTER)] = 0;

	/* power down the core, if allowed */
	if (state->ts_pm_core == TS_PWR_MANAGE) {
		/* okay, drop to D3 for the best power reduction */
		OR_SET_SHORT(state->ts_chandle,
		    &state->ts_config->tsc_pmcsr, TS_PWR_D3);

		/*
		 * wait 20 milliseconds for state change,
		 * __lock_lint tells warlock not to flag this delay()
		 */
#ifndef __lock_lint
		delay(drv_usectohz(TS_20MS));
#endif
	}

	state->ts_powered = TS_PWR_OFF;

	ATRACE("audiots_power_down() done", NULL);

	ASSERT(mutex_owned(&state->ts_lock));

}	/* audiots_power_down() */

/*
 * audiots_power_up()
 *
 * Description:
 *	Power up the audio core if allowed, and then the AC-97 Codec.
 *	The state change timings documented in audiots_power_down()
 *	apply to powering up as well.
 *
 *	audiots_chip_init() does a soft reset, which powers up all of
 *	the sections of the Codec that were powered down in
 *	audiots_power_down().
 *
 *	NOTE: We don't worry about locking since the only routines that
 *		may call us are audiots_attach() and audiots_power().
 *		Both of which should be the only threads in the driver.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiots_power_up(audiots_state_t *state)
{
	ATRACE("in audiots_power_up()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	/* PM should be enabled */
	ASSERT(state->ts_flags & TS_PM_SUPPORTED);

	/* power up the core, if allowed */
	if (state->ts_pm_core == TS_PWR_MANAGE) {
		/* go from D3 to D0 */
		AND_SET_SHORT(state->ts_chandle,
		    &state->ts_config->tsc_pmcsr, ~TS_PWR_D3);

		/*
		 * wait 20 milliseconds for state change,
		 * __lock_lint tells warlock not to flag this delay()
		 */
#ifndef __lock_lint
		delay(drv_usectohz(TS_20MS));
#endif
		/* clear the PME# flag */
		OR_SET_SHORT(state->ts_chandle,
		    &state->ts_config->tsc_pmcsr, TS_PWR_PME);
	}

	/* restore the state, does reset to power up the Codec */
	audiots_chip_init(state, TS_INIT_RESTORE);

	state->ts_powered = TS_PWR_ON;

	ATRACE("audiots_power_up() done", NULL);

	ASSERT(mutex_owned(&state->ts_lock));

}	/* audiots_power_up() */

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
	ddi_acc_handle_t	handle = state->ts_handle;
	uint16_t		*addr;
	uint16_t		*data;
	uint32_t		*stimer = &state->ts_regs->aud_regs.ap_stimer;
	uint32_t		chk1;
	uint32_t		chk2;
	int			resets = 0;
	int			i;

	if (state->ts_rev_id == AC_REV_ID1) {
		addr = &state->ts_regs->aud_regs.ap_acrd_35D_reg;
		data = &state->ts_regs->aud_regs.ap_acrd_35D_data;
		ATRACE("Using OLD SB 35D addresses for reading", 0x44);
	} else {
		addr = &state->ts_regs->aud_regs.ap_acrdwr_reg;
		data = &state->ts_regs->aud_regs.ap_acrdwr_data;
		ATRACE("Using NEW SB 35D+ addresses for reading", 0x40);
	}

first_read:
	/* wait for ready to send read request */
	for (i = 0; i < TS_READ_TRIES; i++) {
		if (!(ddi_get16(handle, addr) & AP_ACRD_R_READ_BUSY)) {
			break;
		}
		/* don't beat on the bus */
		drv_usecwait(1);
	}
	if (i >= TS_READ_TRIES) {
		if (resets < TS_RESET_TRIES) {
			/* Attempt to reset */
			ATRACE("Attempting to reset the AC97 #1", resets);
			drv_usecwait(TS_20US);
			ddi_put16(handle, addr, TS_SB_RESET);
			resets++;
			goto first_read;
		} else {
			ATRACE("Reading the AC97 register has failed #1", 0);
			state->ts_flags |= TS_AUDIO_READ_FAILED;
			if (!(state->ts_flags & TS_READ_FAILURE_PRINTED)) {
				ddi_dev_report_fault(state->ts_dip,
				    DDI_SERVICE_LOST, DDI_DEVICE_FAULT,
				    "Unable to communicate with AC97 CODEC");
				audio_sup_log(state->ts_ahandle, CE_WARN,
				    "The audio AC97 register has timed out.");
				audio_sup_log(state->ts_ahandle, CE_CONT,
				    "Audio is now disabled.\n");
				audio_sup_log(state->ts_ahandle, CE_CONT,
				    "Please reboot to restore audio.\n");

				/* Don't flood the console */
				state->ts_flags |= TS_READ_FAILURE_PRINTED;
			}
		}
		return (0);
	}

	/* program the register to read */
	ddi_put16(handle, addr, (reg|AP_ACRD_W_PRIMARY_CODEC|
	    AP_ACRD_W_READ_MIXER_REG|AP_ACRD_W_AUDIO_READ_REQ&
	    (~AP_ACWR_W_SELECT_WRITE)));

	/* hardware bug work around */
	chk1 = ddi_get32(handle, stimer);
	chk2 = ddi_get32(handle, stimer);
	i = TS_WAIT_CNT;
	while (chk1 == chk2 && i) {
		chk2 = ddi_get32(handle, stimer);
		i--;
	}
	OR_SET_SHORT(handle, addr, AP_ACRD_W_READ_MIXER_REG);
	resets = 0;

second_read:
	/* wait again for read to send read request */
	for (i = 0; i < TS_READ_TRIES; i++) {
		if (!(ddi_get16(handle, addr) & AP_ACRD_R_READ_BUSY)) {
			break;
		}
		/* don't beat on the bus */
		drv_usecwait(1);
	}
	if (i >= TS_READ_TRIES) {
		if (resets < TS_RESET_TRIES) {
			/* Attempt to reset */
			ATRACE("Attempting to reset the AC97 #2", resets);
			drv_usecwait(TS_20US);
			ddi_put16(handle, addr, TS_SB_RESET);
			resets++;
			goto second_read;
		} else {
			ATRACE("Reading the AC97 register has failed #2", 0);
			state->ts_flags |= TS_AUDIO_READ_FAILED;
			if (!(state->ts_flags & TS_READ_FAILURE_PRINTED)) {
				ddi_dev_report_fault(state->ts_dip,
				    DDI_SERVICE_LOST, DDI_DEVICE_FAULT,
				    "Unable to communicate with AC97 CODEC");
				audio_sup_log(state->ts_ahandle, CE_WARN,
				    "The audio AC97 register has timed out.");
				audio_sup_log(state->ts_ahandle, CE_CONT,
				    "Audio is now disabled.\n");
				audio_sup_log(state->ts_ahandle, CE_CONT,
				    "Please reboot to restore audio.\n");

				/* Don't flood the console */
				state->ts_flags |= TS_READ_FAILURE_PRINTED;
			}
		}
		return (0);
	}

	return (ddi_get16(handle, data));

}	/* audiots_read_ac97() */

/*
 * audiots_save_controller()
 *
 * Description:
 *	Save the state of the audio controller.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiots_save_controller(audiots_state_t *state)
{
	ddi_acc_handle_t	handle;
	int			str;

	ATRACE("in ts_save_controller()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	/* save the controller state, Codec state is in ts_shadow[] */
	handle = state->ts_handle;
	for (str = 0; str < TS_MAX_HW_CHANNELS; str++) {
		state->ts_save_regs[str].aram_delta = ddi_get16(handle,
		    &state->ts_regs->aud_ram[str].aram.aram_delta);
		state->ts_save_regs[str].eram_ctrl_ec = ddi_get16(handle,
		    &state->ts_regs->aud_ram[str].eram.eram_ctrl_ec);
	}

	ATRACE("ts_save_controller() done", NULL);

	ASSERT(mutex_owned(&state->ts_lock));

}	/* audiots_save_controller() */

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
 *
 * Returns:
 *	void
 */
static void
audiots_set_ac97(audiots_state_t *state, int reg, const uint16_t data)
{
	ddi_acc_handle_t handle = state->ts_handle;
	uint16_t	*data_addr = &state->ts_regs->aud_regs.ap_acrdwr_data;
	uint16_t	*reg_addr = &state->ts_regs->aud_regs.ap_acrdwr_reg;
	int		count;
	int		i;
	uint16_t	tmp_short;

	reg &= AP_ACWR_INDEX_MASK;

	/* Don't touch the reserved bits on the pre 35D+ SouthBridge */
	if (state->ts_rev_id == AC_REV_ID1) {
		reg |= AP_ACWR_W_PRIMARY_CODEC|AP_ACWR_W_WRITE_MIXER_REG;
		ATRACE("Writing to 35D SB", reg);
	} else {
		reg |= AP_ACWR_W_PRIMARY_CODEC|AP_ACWR_W_WRITE_MIXER_REG|
		    AP_ACWR_W_SELECT_WRITE;
		ATRACE("Writing to 35D+ SB", reg);
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

		/* verify the value written and also update ts_shadow[] */
		tmp_short = audiots_get_ac97(state, reg);
		if (data == tmp_short) {
			/* successfully loaded, so we can return */
			return;
		}
	}

}	/* audiots_set_ac97() */

/*
 * audiots_set_busy()
 *
 * Description:
 *	This routine is called whenever a routine needs to guarantee
 *	that it will not be suspended or the power removed by the power
 *	manager. It will also block any routine while a suspend is
 *	going on.
 *
 *	CAUTION: This routine cannot be called by routines that will
 *		block. Otherwise DDI_SUSPEND will be blocked for a
 *		long time. And that is the wrong thing to do.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS			Set busy and powered up
 *	AUDIO_FAILURE			Couldn't power up, so not busy
 */
static int
audiots_set_busy(audiots_state_t *state)
{
	ATRACE("in audiots_set_busy()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* get the lock so we are safe */
	mutex_enter(&state->ts_lock);

	/* Don't proceed if PM is not enabled */
	if (!(state->ts_flags & TS_PM_SUPPORTED)) {
		mutex_exit(&state->ts_lock);
		return (AUDIO_SUCCESS);
	}

	/* block if we are going to be suspended */
	while (state->ts_suspended == TS_SUSPENDED) {
		cv_wait(&state->ts_cv, &state->ts_lock);
	}

	/*
	 * Okay, we aren't going to be suspended yet, so mark as busy.
	 * This will keep us from being suspended when we release the lock.
	 */
	ASSERT(state->ts_busy_cnt >= 0);
	state->ts_busy_cnt++;

	/* now can release the lock before we raise the power */
	mutex_exit(&state->ts_lock);

	/*
	 * Mark as busy before we ask for power to be raised. This removes
	 * the race condtion between the call to audiots_power() and our call
	 * to raise power. After we raise power we immediately mark as idle
	 * so the count is still good.
	 */
	(void) pm_busy_component(state->ts_dip, TS_COMPONENT);
	if (pm_raise_power(state->ts_dip, TS_COMPONENT, TS_PWR_ON) ==
	    DDI_FAILURE) {
		/* match the busy call above */
		(void) pm_idle_component(state->ts_dip, TS_COMPONENT);

		ATRACE("ts_set_busy() pm_raise_power() failed", NULL);
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!set_busy() power up failed");

		mutex_enter(&state->ts_lock);
		state->ts_busy_cnt--;		/* restore busy count */
		if (state->ts_busy_cnt == 0) {
			/* let DDI_SUSPEND continue */
			cv_broadcast(&state->ts_cv);
		}
		mutex_exit(&state->ts_lock);

		return (AUDIO_FAILURE);
	}

	/* power is up and we are marked as busy, so we are done */

	ATRACE("audiots_set_busy() done", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (AUDIO_SUCCESS);

}	/* audiots_set_busy() */

/*
 * audiots_set_gain()
 *
 * Description:
 *	Set the play/record gain.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		stream		Stream number for multi-stream Codecs,
 *					which is not how we program the device
 *					for now.
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
 *	int		arg1		The gain to set
 *	int		arg2		The channel, 0 == left or 1 == right
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
/*ARGSUSED*/
static int
audiots_set_gain(audiots_state_t *state, int stream, int dir, int gain,
    int channel)
{
	uint16_t	tmp_short;

	ATRACE("in audiots_set_gain()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	if (dir == AUDIO_PLAY) {	/* play gain */
		/*
		 * For play we use PCM so all volumes change with just
		 * one write. This way we get line out, headphone and
		 * internal speaker in one shot.
		 *
		 * The AC-97 Codec goes from -34.5 dB (11111) to 0 dB
		 * (01000) to +12.0 dB (00000). We turn gain into atten.
		 */
		mutex_enter(&state->ts_lock);
		tmp_short = state->ts_shadow[
		    TS_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)];
		if (channel == 0) {	/* left channel */
			tmp_short &= ~PCMOVR_LEFT_GAIN_MASK;
			tmp_short |= (((AUDIO_MAX_GAIN - gain) >>
			    TS_GAIN_SHIFT3) << TS_BYTE_SHIFT) &
			    PCMOVR_LEFT_GAIN_MASK;
		} else {		/* right channel */
			ASSERT(channel == 1);
			tmp_short &= ~PCMOVR_RIGHT_GAIN_MASK;
			tmp_short |= ((AUDIO_MAX_GAIN - gain) >>
			    TS_GAIN_SHIFT3) & PCMOVR_RIGHT_GAIN_MASK;
		}
		audiots_set_ac97(state, AC97_PCM_OUT_VOLUME_REGISTER,
		    tmp_short);
		mutex_exit(&state->ts_lock);
	} else {
		ASSERT(dir == AUDIO_RECORD);
		/*
		 * For record we use the master record gain with all
		 * of the inputs set to 0dB.
		 *
		 * The AC-97 Codec goes from 0 dB (0000) to +22.5 dB
		 * (1111), so gain remains gain. We chop off the bottom
		 * 4 bits and use the top for the gain.
		 */
		mutex_enter(&state->ts_lock);
		tmp_short =
		    state->ts_shadow[TS_CODEC_REG(AC97_RECORD_GAIN_REGISTER)];
		if (channel == 0) {	/* left channel */
			tmp_short &= ~RGR_LEFT_MASK;
			tmp_short |= (gain << TS_GAIN_SHIFT4) & RGR_LEFT_MASK;
		} else {		/* right channel */
			ASSERT(channel == 1);
			tmp_short &= ~RGR_RIGHT_MASK;
			tmp_short |= (gain >> TS_GAIN_SHIFT4) & RGR_RIGHT_MASK;
		}
		audiots_set_ac97(state, AC97_RECORD_GAIN_REGISTER,
		    tmp_short);
		mutex_exit(&state->ts_lock);
	}

	ATRACE("audiots_set_gain() done", NULL);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (AUDIO_SUCCESS);

}	/* audiots_set_gain() */

/*
 * audiots_set_idle()
 *
 * Description:
 *	This routine reduces the busy count. It then does a cv_broadcast()
 *	if the count is 0 so a waiting DDI_SUSPEND will continue forward.
 *	It ends by resetting the power management timer.
 *
 *	We don't do anything with power because the routine that is no longer
 *	busy either doesn't need the hardware, or we are playing or recording
 *	so the power won't come down anyway.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiots_set_idle(audiots_state_t *state)
{
	ATRACE("in audiots_set_idle()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	/* get the lock so we are safe */
	mutex_enter(&state->ts_lock);

	/* Don't proceed if PM is not enabled */
	if (!(state->ts_flags & TS_PM_SUPPORTED)) {
		mutex_exit(&state->ts_lock);
		return;
	}

	ASSERT(state->ts_suspended == TS_NOT_SUSPENDED);

	/* decrement the busy count */
	state->ts_busy_cnt--;

	/* if no longer busy, then we wake up a waiting SUSPEND */
	if (state->ts_busy_cnt == 0) {
		cv_broadcast(&state->ts_cv);
	}

	/* we're done, so unlock */
	mutex_exit(&state->ts_lock);

	/* reset the timer */
	(void) pm_idle_component(state->ts_dip, TS_COMPONENT);

	ATRACE("audiots_set_idle() done", state);

	ASSERT(!mutex_owned(&state->ts_lock));

}	/* audiots_set_idle() */

/*
 * audiots_set_monitor_gain()
 *
 * Description:
 *	Set the monitor gain.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *	int		gain		The gain to set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
/*ARGSUSED*/
static int
audiots_set_monitor_gain(audiots_state_t *state, int gain)
{
	uint16_t	tmp_short;
	int		rc = AUDIO_SUCCESS;

	ATRACE("in audiots_set_monitor_gain()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	if (gain == 0) {
		/* disable loopbacks when gain == 0 */
		tmp_short = MVR_MUTE;
	} else {
		/* Adjust the value of gain to meet the requirement of AC'97 */
		tmp_short = (((AUDIO_MAX_GAIN - gain) >> TS_GAIN_SHIFT3) <<
		    TS_BYTE_SHIFT) & PCMOVR_LEFT_GAIN_MASK;
		tmp_short |= ((AUDIO_MAX_GAIN - gain) >> TS_GAIN_SHIFT3) &
		    PCMOVR_RIGHT_GAIN_MASK;
	}

	mutex_enter(&state->ts_lock);

	switch (state->ts_input_port) {
	case AUDIO_NONE:
		/*
		 * It is possible to set the value of gain before any input
		 * is selected. So, we just save the gain and then return
		 * SUCCESS.
		 */
		break;
	case AUDIO_MICROPHONE:
		/*
		 * MIC input has 20dB boost, we just preserve it
		 */
		tmp_short |= state->ts_shadow[TS_CODEC_REG(
		    AC97_MIC_VOLUME_REGISTER)] & MICVR_20dB_BOOST;
		audiots_set_ac97(state,
		    AC97_MIC_VOLUME_REGISTER, tmp_short);
		break;
	case AUDIO_LINE_IN:
		audiots_set_ac97(state,
		    AC97_LINE_IN_VOLUME_REGISTER, tmp_short);
		break;
	case AUDIO_CD:
		audiots_set_ac97(state,
		    AC97_CD_VOLUME_REGISTER, tmp_short);
		break;
	case AUDIO_CODEC_LOOPB_IN:
		/* we already are getting the loopback, so done */
		mutex_exit(&state->ts_lock);
		rc = AUDIO_SUCCESS;
		goto done;
	default:
		/* this should never happen! */
		mutex_exit(&state->ts_lock);
		ATRACE("ts_ad_set_config() monitor gain bad device",
		    NULL);
		rc = AUDIO_FAILURE;
		goto done;
	}

	if (gain == 0) {
		state->ts_monitor_gain = 0;
	} else {
		state->ts_monitor_gain = tmp_short;
	}
	mutex_exit(&state->ts_lock);

done:
	ATRACE_32("audiots_set_monitor_gain()", rc);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_set_monitor_gain() */

/*
 * audiots_set_port()
 *
 * Description:
 *	Set the play/record port.
 *
 *	We also use this routine to unmute the play ports. By passing
 *	TS_PORT_UNMUTE as the port we know to use the stored play port.
 *	This has to be done inside the lock, otherwise there is the
 *	possibility that the port passed in when this routine is called
 *	could be wrong by the time we execute the unmute.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *					which is not how we program the device
 *					for now.
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
 *	int		port		The port to set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The port could not been set
 */
static int
audiots_set_port(audiots_state_t *state, int dir, int port)
{
	uint32_t	tmp_word;
	uint16_t	tmp_short;
	int		rc = AUDIO_SUCCESS;

	ATRACE("in audiots_set_port()", state);

	ASSERT(!mutex_owned(&state->ts_lock));

	if (dir == AUDIO_PLAY) {	/* output port(s) */
		/* figure out which output port(s) to turn on */
		tmp_word = 0;

		mutex_enter(&state->ts_lock);

		/*
		 * CAUTION: We must get the saved output port after the
		 *	lock so we know it is good.
		 */
		if (port == TS_PORT_UNMUTE) {
			port = state->ts_output_port;
		}

		if (port & AUDIO_SPEAKER) {
			audiots_and_ac97(state,
			    AC97_MONO_MASTER_VOLUME_REGSITER,
			    (uint16_t)~MMVR_MUTE);
			tmp_word |= AUDIO_SPEAKER;
		} else {
			audiots_or_ac97(state,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MMVR_MUTE);
		}

		if (port & AUDIO_HEADPHONE) {
			audiots_and_ac97(state,
			    AC97_HEADPHONE_VOLUME_REGISTER,
			    (uint16_t)~HPVR_MUTE);
			tmp_word |= AUDIO_HEADPHONE;
		} else {
			audiots_or_ac97(state,
			    AC97_HEADPHONE_VOLUME_REGISTER, HPVR_MUTE);
		}

		if (port & AUDIO_LINE_OUT) {
			audiots_and_ac97(state, AC97_MASTER_VOLUME_REGISTER,
			    (uint16_t)~MVR_MUTE);
			tmp_word |= AUDIO_LINE_OUT;
		} else {
			audiots_or_ac97(state, AC97_MASTER_VOLUME_REGISTER,
			    MVR_MUTE);
		}

		state->ts_output_port = tmp_word;

		mutex_exit(&state->ts_lock);

		ATRACE_32("ts_ad_set_config() set out port", tmp_word);

		if (tmp_word != (port & TS_PORT_MASK)) {
			ATRACE_32("ts_ad_set_config() bad out port", port);
			rc = AUDIO_FAILURE;
			goto done;
		}

	} else {
		ASSERT(dir == AUDIO_RECORD);

		/* figure out which input port to set */
		mutex_enter(&state->ts_lock);
		switch (port) {
		case AUDIO_NONE:
			/* set to an unused input */
			tmp_short = RSCR_R_PHONE|RSCR_L_PHONE;

			/* mute the master record input */
			audiots_or_ac97(state, AC97_RECORD_GAIN_REGISTER,
			    RGR_MUTE);

			/* see if we need to update monitor loopback */
			if (state->ts_monitor_gain) {
				if (state->ts_input_port == AUDIO_MICROPHONE) {
					audiots_or_ac97(state,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (state->ts_input_port ==
				    AUDIO_LINE_IN) {
					audiots_or_ac97(state,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (state->ts_input_port ==
				    AUDIO_CD) {
					audiots_or_ac97(state,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			}
			break;
		case AUDIO_MICROPHONE:
			/* set to the mic input */
			tmp_short = RSCR_R_MIC|RSCR_L_MIC;

			/* see if we need to update monitor loopback */
			if (state->ts_monitor_gain) {
				if (state->ts_input_port == AUDIO_LINE_IN) {
					audiots_or_ac97(state,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (state->ts_input_port == AUDIO_CD) {
					audiots_or_ac97(state,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				audiots_set_ac97(state,
				    AC97_MIC_VOLUME_REGISTER,
				    state->ts_monitor_gain);
			}
			break;
		case AUDIO_LINE_IN:
			/* set to the line in input */
			tmp_short = RSCR_R_LINE_IN|RSCR_L_LINE_IN;

			/* see if we need to update monitor loopback */
			if (state->ts_monitor_gain) {
				if (state->ts_input_port == AUDIO_MICROPHONE) {
					audiots_or_ac97(state,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (state->ts_input_port == AUDIO_CD) {
					audiots_or_ac97(state,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				audiots_set_ac97(state,
				    AC97_LINE_IN_VOLUME_REGISTER,
				    state->ts_monitor_gain);
			}
			break;
		case AUDIO_CD:
			/* set to the line in input */
			tmp_short = RSCR_R_CD|RSCR_L_CD;

			/* see if we need to update monitor loopback */
			if (state->ts_monitor_gain) {
				if (state->ts_input_port == AUDIO_MICROPHONE) {
					audiots_or_ac97(state,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (state->ts_input_port ==
				    AUDIO_LINE_IN) {
					audiots_or_ac97(state,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				}
				audiots_set_ac97(state,
				    AC97_CD_VOLUME_REGISTER,
				    state->ts_monitor_gain);
			}
			break;
		case AUDIO_CODEC_LOOPB_IN:
			/* set to the loopback input */
			tmp_short = RSCR_R_STEREO_MIX|RSCR_L_STEREO_MIX;

			/* see if we need to update monitor loopback */
			if (state->ts_monitor_gain) {
				if (state->ts_input_port == AUDIO_LINE_IN) {
					audiots_or_ac97(state,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (state->ts_input_port ==
				    AUDIO_MICROPHONE) {
					audiots_or_ac97(state,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (state->ts_input_port == AUDIO_CD) {
					audiots_or_ac97(state,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			}
			break;
		default:
			/* unknown or inclusive input ports */
			mutex_exit(&state->ts_lock);
			ATRACE_32("ts_ad_set_config() bad in port", port);
			rc =  AUDIO_FAILURE;
			goto done;
		}
		/* select the input */
		audiots_set_ac97(state, AC97_RECORD_SELECT_CTRL_REGISTER,
		    tmp_short);

		/* if an input port then make sure we aren't muted */
		if (port != AUDIO_NONE &&
		    (state->ts_shadow[TS_CODEC_REG(AC97_RECORD_GAIN_REGISTER)] &
		    RGR_MUTE)) {
			audiots_and_ac97(state, AC97_RECORD_GAIN_REGISTER,
			    (uint16_t)~RGR_MUTE);
		}

		state->ts_input_port = port;

		mutex_exit(&state->ts_lock);
	}

done:
	ATRACE_32("audiots_set_port()", rc);

	ASSERT(!mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_set_port() */

/*
 * audiots_start_play()
 *
 * Description:
 *	The audio core uses a single DMA buffer which is divided into two
 *	halves. An interrupt is generated when the middle of the buffer has
 *	been reached and at the end. The audio core resets the pointer back
 *	to the beginning automatically. After the interrupt the driver clears
 *	the buffer and asks the mixer for more audio samples. If there aren't
 *	enough then silence is played out.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Playing started/restarted
 *	AUDIO_FAILURE		Play not started/restarted, no audio to play
 */
static int
audiots_start_play(audiots_state_t *state)
{
	ddi_acc_handle_t	handle;
	size_t			buf_size;
	char			*bptr;
	int			rc = AUDIO_SUCCESS;
	int			rs;
	int			samples;
	int			str = TS_OUTPUT_STREAM;

	ATRACE("in ts_start_play()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	handle = state->ts_handle;

	/* see if we are already playing */
	if ((ddi_get32(handle, &state->ts_regs->aud_regs.ap_start) &
	    TS_OUTPUT_CHANNEL)) {
		ATRACE("ts_start_play() DMA engine already running", state);
		ASSERT(rc == AUDIO_SUCCESS);
		goto done;
	}

	/* see if we are just paused */
	if (state->ts_flags & TS_DMA_ENGINE_PAUSED) {
		ATRACE_32("ts_start_play() DMA paused", state->ts_flags);
		state->ts_flags &= ~TS_DMA_ENGINE_PAUSED;

		/* make sure it starts playing */
		ddi_put32(handle, &state->ts_regs->aud_regs.ap_start,
		    TS_OUTPUT_CHANNEL);

		ATRACE_32("ts_start_play() DMA engine restarted",
		    state->ts_flags);
		ASSERT(rc == AUDIO_SUCCESS);
		goto done;
	}

	/*
	 * Okay, we are starting from scratch, so get the first chunks of audio.
	 * We ask for half of the buffer twice. That way we don't mess up the
	 * mixer's paradigm of using two buffers. But before we get the audio
	 * we zero the buffer, giving it silence, just in case there isn't
	 * enough audio.
	 */
	bzero(state->ts_pb, state->ts_pbuf_size);

	samples = state->ts_psample_rate * state->ts_pchannels /
	    state->ts_ad_info.ad_play.ad_int_rate;
	/* if not an even number of samples we panic! */
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples % AUDIO_CHANNELS_STEREO) != 0) {
		ATRACE_32("ts_start_play() samples not mod", samples);
		/* need to adjust */
		samples++;
	}

	buf_size = samples * (state->ts_pprecision >> AUDIO_PRECISION_SHIFT);
	ASSERT((buf_size << 1) <= state->ts_pbuf_size);

	ATRACE("ts_start_play() getting 1st audio", NULL);
	bptr = state->ts_pb;

	mutex_exit(&state->ts_lock);
	rs = am_get_audio(state->ts_ahandle, &bptr[0], AUDIO_NO_CHANNEL,
	    samples);
	mutex_enter(&state->ts_lock);

	if (rs == 0) {
		/* there's nothing to play */
		ATRACE("ts_start_play() nothing to play", NULL);
		rc = AUDIO_FAILURE;
		goto done;
	}
	ATRACE_32("ts_start_play() 1st am_get_audio()", rs);
	state->ts_pcnt[TS_1ST_HALF] = buf_size;
	state->ts_psamples[TS_1ST_HALF] = samples;

	ATRACE("ts_start_play() getting 2nd audio", NULL);

	mutex_exit(&state->ts_lock);
	rs = am_get_audio(state->ts_ahandle, &bptr[buf_size], AUDIO_NO_CHANNEL,
	    samples);
	mutex_enter(&state->ts_lock);

	ATRACE_32("ts_start_play() 2nd am_get_audio()", rs);
	if (rs > 0) {
		state->ts_pcnt[TS_2ND_HALF] = buf_size;
	} else {
		state->ts_pcnt[TS_2ND_HALF] = 0;
	}
	state->ts_psamples[TS_2ND_HALF] = samples;

	/* sync the DMA buffer */
	if (ddi_dma_sync(state->ts_ph, (off_t)0, (off_t)0,
	    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE) {
		audio_sup_log(state->ts_ahandle, CE_WARN,
		    "!start_play() ddi_dma_sync() failed, audio lost");
		rc = AUDIO_FAILURE;
		goto done;
	}

	/* set ALPHA and FMS to 0 */
	ddi_put16(handle, &state->ts_regs->aud_ram[str].aram.aram_alpha_fms,
	    0x0);

	/* set CSO to 0 */
	ddi_put16(handle, &state->ts_regs->aud_ram[str].aram.aram_cso, 0x0);

	/* set LBA */
	ddi_put32(handle, &state->ts_regs->aud_ram[str].aram.aram_cptr_lba,
	    state->ts_pc.dmac_address & ARAM_LBA_MASK);

	/* set ESO */
	if (state->ts_pchannels == AUDIO_CHANNELS_MONO) {
		samples = (samples << 1) - 1;
	} else {
		samples--;
	}
	ddi_put16(handle, &state->ts_regs->aud_ram[str].aram.aram_eso, samples);

	/* enable interrupts */
	OR_SET_WORD(handle, &state->ts_regs->aud_regs.ap_ainten,
	    TS_OUTPUT_CHANNEL);

	/* make sure it starts playing */
	ddi_put32(handle, &state->ts_regs->aud_regs.ap_start,
	    TS_OUTPUT_CHANNEL);

	state->ts_flags &= ~(TS_DMA_ENGINE_PAUSED|TS_DMA_ENGINE_EMPTY);
	state->ts_flags |= TS_DMA_ENGINE_INITIALIZED;

	ATRACE("ts_start_play() successful", state);
	ASSERT(rc == AUDIO_SUCCESS);

done:
	ASSERT(mutex_owned(&state->ts_lock));

	return (rc);

}	/* audiots_start_play() */

/*
 * audiots_stop_play()
 *
 * Description:
 *	This routine stops the play DMA engine.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiots_stop_play(audiots_state_t *state)
{
	ATRACE("in ts_stop_play()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_stop,
	    TS_OUTPUT_CHANNEL);

	AND_SET_WORD(state->ts_handle, &state->ts_regs->aud_regs.ap_ainten,
	    ~TS_OUTPUT_CHANNEL);

	state->ts_flags &= ~(TS_DMA_ENGINE_INITIALIZED|TS_DMA_ENGINE_PAUSED|
	    TS_DMA_ENGINE_EMPTY);

	ATRACE("ts_stop_play() returning", state);

	ASSERT(mutex_owned(&state->ts_lock));

}	/* audiots_stop_play() */

/*
 * audiots_start_record()
 *
 * Description:
 *	The record DMA engine works the same way as the play DMA engine.
 *	Record cannot be multi-stream and must be on T2 channel 31.
 *
 *	There isn't a pause for record, only start and stop. So this code
 *	is a touch simpler than starting up play.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Recording successfully started
 *	AUDIO_FAILURE		Record not started
 */
/*ARGSUSED*/
static int
audiots_start_record(audiots_state_t *state)
{
	ddi_acc_handle_t	handle;
	size_t			buf_size;
	int			rc = AUDIO_SUCCESS;
	int			samples;
	int			str = TS_INPUT_STREAM;

	ATRACE("in ts_start_record()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	handle = state->ts_handle;

	/* see if we are already recording */
	if ((ddi_get32(handle, &state->ts_regs->aud_regs.ap_start) &
	    TS_INPUT_CHANNEL)) {
		ATRACE("ts_start_record() DMA engine already running",
		    state);
		ASSERT(rc == AUDIO_SUCCESS);
		return (rc);
	}

	/* okay, we start from scratch; start by figuring out sample sizes */
	samples = state->ts_csample_rate * state->ts_cchannels /
	    state->ts_ad_info.ad_record.ad_int_rate;
	/* if not an even number of samples we panic! */
	if ((samples % AUDIO_CHANNELS_STEREO) != 0) {
		ATRACE_32("ts_start_record() samples not mod", samples);
		/* need to adjust */
		samples++;
	}

	buf_size = samples * (state->ts_cprecision >> AUDIO_PRECISION_SHIFT);
	ASSERT((buf_size << 1) <= state->ts_cbuf_size);

	state->ts_ccnt = buf_size;

	/* set ALPHA and FMS to 0 */
	ddi_put16(handle, &state->ts_regs->aud_ram[str].aram.aram_alpha_fms,
	    0x0);

	/* set CSO to 0 */
	ddi_put16(handle, &state->ts_regs->aud_ram[str].aram.aram_cso, 0x0);

	/* set LBA */
	ddi_put32(handle, &state->ts_regs->aud_ram[str].aram.aram_cptr_lba,
	    state->ts_cc.dmac_address & ARAM_LBA_MASK);

	/* set ESO */
	if (state->ts_cchannels == AUDIO_CHANNELS_MONO) {
		samples = (samples << 1) - 1;
	} else {
		samples--;
	}
	ddi_put16(handle, &state->ts_regs->aud_ram[str].aram.aram_eso, samples);

	/* enable interrupts */
	OR_SET_WORD(handle, &state->ts_regs->aud_regs.ap_ainten,
	    TS_INPUT_CHANNEL);

	/* make sure it starts recording */
	ddi_put32(handle, &state->ts_regs->aud_regs.ap_start, TS_INPUT_CHANNEL);

	state->ts_flags |= TS_DMA_RECORD_START;

	ATRACE("ts_start_record() done", NULL);
	ASSERT(rc == AUDIO_SUCCESS);

done:
	ASSERT(mutex_owned(&state->ts_lock));

	if (rc == AUDIO_SUCCESS && (state->ts_flags & TS_PM_SUPPORTED)) {
		(void) pm_busy_component(state->ts_dip, TS_COMPONENT);
	}

	return (rc);

}	/* audiots_start_record() */

/*
 * audiots_stop_record()
 *
 * Description:
 *	This routine stops the record DMA engine. Any data in the buffer
 *	is just thrown away. After all, we're done recording so there aren't
 *	any apps that need audio.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
audiots_stop_record(audiots_state_t *state)
{
	ddi_acc_handle_t	handle = state->ts_handle;

	ATRACE("in ts_stop_record()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	/* stop recording */
	ddi_put32(handle, &state->ts_regs->aud_regs.ap_stop, TS_INPUT_CHANNEL);

	AND_SET_WORD(state->ts_handle, &state->ts_regs->aud_regs.ap_ainten,
	    ~TS_INPUT_CHANNEL);

	state->ts_flags &= ~TS_DMA_RECORD_START;

	ATRACE("ts_stop_record() done", state);

	ASSERT(mutex_owned(&state->ts_lock));

}	/* audiots_stop_record() */

/*
 * audiots_stop_everything()
 *
 * Description:
 *	This routine disables the address engine interrupt for all 32 DMA
 *	engines. Just to be sure, it then explicitly issues a stop command to
 *	the address engine and envelope engines for all 32 channels.
 *
 * NOTE:
 * 	There is a hardware bug that generates a spurious interrupt when the DMA
 *	engines are stopped. It's not consistent - it happens every 1 out of 6
 *	stops or so. It will show up as a record interrupt. The problem is that
 *	once the driver is detached or if the system goes into low power mode,
 *	nobody will service that interrupt. The system will eventually become
 *	unusable.
 *
 * Arguments:
 *	audiots_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiots_stop_everything(audiots_state_t *state)
{
	uint_t		intr;

	ATRACE("in ts_stop_everything()", state);

	ASSERT(mutex_owned(&state->ts_lock));

	ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_ainten,
	    TS_ALL_DMA_OFF);

	ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_stop,
	    TS_ALL_DMA_ENGINES);

	intr = ddi_get32(state->ts_handle, &state->ts_regs->aud_regs.ap_aint);
	if (intr != 0) {
		ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_aint,
		    intr);
		ddi_put32(state->ts_handle, &state->ts_regs->aud_regs.ap_ainten,
		    TS_ALL_DMA_OFF);
		ATRACE("ts_stop_everything() clearing the bogus interrupt",
		    intr);

		/*
		 * Flag this interrupt for the audiots_intr() routine to claim,
		 * but this interrupt doesn't need to be processed.
		 */
		state->ts_flags |= TS_INTR_PENDING;
	}

	ATRACE("ts_stop_everything() done", state);

	ASSERT(mutex_owned(&state->ts_lock));

}	/* audiots_stop_everything() */

/*
 * audiots_unmap_regs()
 *
 * Description:
 *	This routine unbinds the DMA cookies, frees the DMA buffers,
 *	deallocates the DMA handles, and finally unmaps the Codec's and
 *	DMA engine's registers.
 *
 * Arguments:
 *	audiots_state_t	*state	The device's state structure
 *
 * Returns:
 *	None
 */
static void
audiots_unmap_regs(audiots_state_t *state)
{
	ATRACE("in ts_unmap_regs()", state);

	(void) ddi_dma_unbind_handle(state->ts_ph);
	(void) ddi_dma_unbind_handle(state->ts_ch);

	ddi_dma_mem_free(&state->ts_pmh);
	ddi_dma_mem_free(&state->ts_cmh);

	ddi_dma_free_handle(&state->ts_ph);
	ddi_dma_free_handle(&state->ts_ch);

	ddi_regs_map_free(&state->ts_handle);
	ddi_regs_map_free(&state->ts_chandle);

	ATRACE("ts_unmap_regs() returning", state);

}	/* audiots_unmap_regs() */
