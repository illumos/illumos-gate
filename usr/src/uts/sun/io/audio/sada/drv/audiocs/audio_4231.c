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
 * audiocs Audio Driver
 *
 * This Audio Driver controls the Crystal CS4231 Codec used on many SPARC
 * platforms. It does not support the CS4231 on Power PCs or x86 PCs. It
 * does support two different DMA engines, the APC and EB2. The code for
 * those DMA engines is split out and a well defined, but private, interface
 * is used to control those DMA engines.
 *
 * For some reason setting the CS4231's registers doesn't always succeed.
 * Therefore every time we set a register we always read it back to make
 * sure it was set. If not we wait a little while and then try again. This
 * is all taken care of in the routines cs4231_put8() and cs4231_reg_select()
 * and the macros OR_SET_BYTE() and AND_SET_BYTE(). We don't worry about
 * the status register because it is cleared by writing anything to it.
 * So it doesn't matter what the value written is.
 *
 * This driver uses the mixer Audio Personality Module to implement audio(7I)
 * and mixer(7I) semantics. Unfortunately this is a single stream Codec,
 * forcing the mixer to do sample rate conversion.
 *
 * This driver supports suspending and resuming. A suspend just stops playing
 * and recording. The play DMA buffers end up getting thrown away, but when
 * you shut down the machine there is a break in the audio anyway, so they
 * won't be missed and it isn't worth the effort to save them. When we resume
 * we always start playing and recording. If they aren't needed they get
 * shut off by the mixer.
 *
 * System power management is supported by this driver. To facilitate
 * this feature the routines audiocs_set_busy() and audiocs_set_idle()
 * are provided.
 *	audiocs_set_busy() is called at the beginning of all audiocs_ad_*()
 *	entry point routines. It blocks if the driver is being suspended.
 *	Once it unblocks it increments a busy count and raises power.
 *	Once this busy count is incremented any calls to suspend the driver
 *	will block until the count goes back to zero.
 *
 *	audiocs_set_idle() is called at the end of all audiocs_ad_*() entry
 *	points. It decrements the busy count. Once that count reaches zero
 *	it wakes up a sleeping suspend.
 *
 * Component power management is also supported by this driver. As long as
 * the busy count raised by audiocs_set_busy() is non-zero or audio is
 * actively playing or recording power can not be lowered.
 *
 * The ad_start_play()/record() routines call pm_busy_component() so that
 * as long as playing/recording is going on the device won't be powered down.
 * The ad_stop_play()/record() routines call pm_idle_component() so that when
 * the busy count goes to 0 the device will be powered down.
 *
 *	NOTE: This module depends on the misc/audiosup and misc/mixer modules
 *		being loaded first.
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
#include <sys/audio/impl/audio_4231_impl.h>
#include <sys/audio/audio_4231.h>

/*
 * Global routines.
 */
int cs4231_poll_ready(CS_state_t *);

/*
 * Module linkage routines for the kernel
 */
static int cs4231_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int cs4231_attach(dev_info_t *, ddi_attach_cmd_t);
static int cs4231_detach(dev_info_t *, ddi_detach_cmd_t);
static int cs4231_power(dev_info_t *, int, int);

/*
 * Entry point routine prototypes
 */
static int cs4231_ad_set_config(audiohdl_t, int, int, int, int, int);
static int cs4231_ad_set_format(audiohdl_t, int, int, int, int, int, int);
static int cs4231_ad_start_play(audiohdl_t, int);
static void cs4231_ad_pause_play(audiohdl_t, int);
static void cs4231_ad_stop_play(audiohdl_t, int);
static int cs4231_ad_start_record(audiohdl_t, int);
static void cs4231_ad_stop_record(audiohdl_t, int);

/* Local Routines */
static int cs4231_init_state(CS_state_t *, dev_info_t *);
static int cs4231_chip_init(CS_state_t *);
static void cs4231_get_ports(CS_state_t *, dev_info_t *);
static int cs4231_set_port(CS_state_t *, int, int);
static int cs4231_set_gain(CS_state_t *, int, int, int, int);
static int cs4231_set_monitor_gain(CS_state_t *, int);
static int cs4231_set_busy(CS_state_t *);
static void cs4231_set_idle(CS_state_t *);
static void cs4231_power_up(CS_state_t *);
static void cs4231_power_down(CS_state_t *);

/*
 * Global variables, but viewable only by this file.
 */

/* anchor for soft state structures */
static void *cs_statep;

/* driver name, so we don't have to call ddi_driver_name() or hard code strs */
static char *audiocs_name = CS4231_NAME;

/* File name for the cs4231_put8() and cs4231_reg_select() routines */
static char *thisfile = __FILE__;

static uint_t cs_mixer_srs[] = {
	CS4231_SAMPR5510, CS4231_SAMPR48000, 0
};

static uint_t cs_compat_srs[] = {
	CS4231_SAMPR5510, CS4231_SAMPR6620, CS4231_SAMPR8000,
	CS4231_SAMPR9600, CS4231_SAMPR11025, CS4231_SAMPR16000,
	CS4231_SAMPR18900, CS4231_SAMPR22050, CS4231_SAMPR27420,
	CS4231_SAMPR32000, CS4231_SAMPR33075, CS4231_SAMPR37800,
	CS4231_SAMPR44100, CS4231_SAMPR48000, 0
};

static am_ad_sample_rates_t cs_mixer_sample_rates = {
	MIXER_SRS_FLAG_SR_LIMITS,
	cs_mixer_srs
};

static am_ad_sample_rates_t cs_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	cs_compat_srs
};

static uint_t cs_channels[] = {
	AUDIO_CHANNELS_MONO, AUDIO_CHANNELS_STEREO, 0
};

static am_ad_cap_comb_t cs_combinations[] = {
	{ AUDIO_PRECISION_8, AUDIO_ENCODING_LINEAR },
	{ AUDIO_PRECISION_8, AUDIO_ENCODING_ULAW },
	{ AUDIO_PRECISION_8, AUDIO_ENCODING_ALAW },
	{ AUDIO_PRECISION_16, AUDIO_ENCODING_LINEAR },
	{ 0 }
};

static am_ad_entry_t cs_entry = {
	NULL,			/* ad_setup() */
	NULL,			/* ad_teardown() */
	cs4231_ad_set_config,	/* ad_set_config() */
	cs4231_ad_set_format,	/* ad_set_format() */
	cs4231_ad_start_play,	/* ad_start_play() */
	cs4231_ad_pause_play,	/* ad_pause_play() */
	cs4231_ad_stop_play,	/* ad_stop_play() */
	cs4231_ad_start_record,	/* ad_start_record() */
	cs4231_ad_stop_record,	/* ad_stop_record() */
	NULL,			/* ad_ioctl() */
	NULL			/* ad_iocdata() */
};

/* play gain array, converts linear gain to 64 steps of log10 gain */
static uint8_t cs4231_atten[] = {
	0x3f,	0x3e,	0x3d,	0x3c,	0x3b,	/* [000] -> [004] */
	0x3a,	0x39,	0x38,	0x37,	0x36,	/* [005] -> [009] */
	0x35,	0x34,	0x33,	0x32,	0x31,	/* [010] -> [014] */
	0x30,	0x2f,	0x2e,	0x2d,	0x2c,	/* [015] -> [019] */
	0x2b,	0x2a,	0x29,	0x29,	0x28,	/* [020] -> [024] */
	0x28,	0x27,	0x27,	0x26,	0x26,	/* [025] -> [029] */
	0x25,	0x25,	0x24,	0x24,	0x23,	/* [030] -> [034] */
	0x23,	0x22,	0x22,	0x21,	0x21,	/* [035] -> [039] */
	0x20,	0x20,	0x1f,	0x1f,	0x1f,	/* [040] -> [044] */
	0x1e,	0x1e,	0x1e,	0x1d,	0x1d,	/* [045] -> [049] */
	0x1d,	0x1c,	0x1c,	0x1c,	0x1b,	/* [050] -> [054] */
	0x1b,	0x1b,	0x1a,	0x1a,	0x1a,	/* [055] -> [059] */
	0x1a,	0x19,	0x19,	0x19,	0x19,	/* [060] -> [064] */
	0x18,	0x18,	0x18,	0x18,	0x17,	/* [065] -> [069] */
	0x17,	0x17,	0x17,	0x16,	0x16,	/* [070] -> [074] */
	0x16,	0x16,	0x16,	0x15,	0x15,	/* [075] -> [079] */
	0x15,	0x15,	0x15,	0x14,	0x14,	/* [080] -> [084] */
	0x14,	0x14,	0x14,	0x13,	0x13,	/* [085] -> [089] */
	0x13,	0x13,	0x13,	0x12,	0x12,	/* [090] -> [094] */
	0x12,	0x12,	0x12,	0x12,	0x11,	/* [095] -> [099] */
	0x11,	0x11,	0x11,	0x11,	0x11,	/* [100] -> [104] */
	0x10,	0x10,	0x10,	0x10,	0x10,	/* [105] -> [109] */
	0x10,	0x0f,	0x0f,	0x0f,	0x0f,	/* [110] -> [114] */
	0x0f,	0x0f,	0x0e,	0x0e,	0x0e,	/* [114] -> [119] */
	0x0e,	0x0e,	0x0e,	0x0e,	0x0d,	/* [120] -> [124] */
	0x0d,	0x0d,	0x0d,	0x0d,	0x0d,	/* [125] -> [129] */
	0x0d,	0x0c,	0x0c,	0x0c,	0x0c,	/* [130] -> [134] */
	0x0c,	0x0c,	0x0c,	0x0b,	0x0b,	/* [135] -> [139] */
	0x0b,	0x0b,	0x0b,	0x0b,	0x0b,	/* [140] -> [144] */
	0x0b,	0x0a,	0x0a,	0x0a,	0x0a,	/* [145] -> [149] */
	0x0a,	0x0a,	0x0a,	0x0a,	0x09,	/* [150] -> [154] */
	0x09,	0x09,	0x09,	0x09,	0x09,	/* [155] -> [159] */
	0x09,	0x09,	0x08,	0x08,	0x08,	/* [160] -> [164] */
	0x08,	0x08,	0x08,	0x08,	0x08,	/* [165] -> [169] */
	0x08,	0x07,	0x07,	0x07,	0x07,	/* [170] -> [174] */
	0x07,	0x07,	0x07,	0x07,	0x07,	/* [175] -> [179] */
	0x06,	0x06,	0x06,	0x06,	0x06,	/* [180] -> [184] */
	0x06,	0x06,	0x06,	0x06,	0x05,	/* [185] -> [189] */
	0x05,	0x05,	0x05,	0x05,	0x05,	/* [190] -> [194] */
	0x05,	0x05,	0x05,	0x05,	0x04,	/* [195] -> [199] */
	0x04,	0x04,	0x04,	0x04,	0x04,	/* [200] -> [204] */
	0x04,	0x04,	0x04,	0x04,	0x03,	/* [205] -> [209] */
	0x03,	0x03,	0x03,	0x03,	0x03,	/* [210] -> [214] */
	0x03,	0x03,	0x03,	0x03,	0x03,	/* [215] -> [219] */
	0x02,	0x02,	0x02,	0x02,	0x02,	/* [220] -> [224] */
	0x02,	0x02,	0x02,	0x02,	0x02,	/* [225] -> [229] */
	0x02,	0x01,	0x01,	0x01,	0x01,	/* [230] -> [234] */
	0x01,	0x01,	0x01,	0x01,	0x01,	/* [235] -> [239] */
	0x01,	0x01,	0x01,	0x00,	0x00,	/* [240] -> [244] */
	0x00,	0x00,	0x00,	0x00,	0x00,	/* [245] -> [249] */
	0x00,	0x00,	0x00,	0x00,	0x00,	/* [250] -> [254] */
	0x00					/* [255] */
};

/*
 * STREAMS Structures
 */

/* STREAMS driver id and limit value structure */
static struct module_info cs4231_modinfo = {
	CS4231_IDNUM,		/* module ID number */
	CS4231_NAME,		/* module name */
	CS4231_MINPACKET,	/* minimum packet size */
	CS4231_MAXPACKET,	/* maximum packet size */
	CS4231_HIWATER,		/* high water mark */
	CS4231_LOWATER		/* low water mark */
};

/* STREAMS queue processing procedures structures */
/* read queue */
static struct qinit cs4231_rqueue = {
	audio_sup_rput,		/* put procedure */
	audio_sup_rsvc,		/* service procedure */
	audio_sup_open,		/* open procedure */
	audio_sup_close,	/* close procedure */
	NULL,			/* unused */
	&cs4231_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* write queue */
static struct qinit cs4231_wqueue = {
	audio_sup_wput,		/* put procedure */
	audio_sup_wsvc,		/* service procedure */
	NULL,			/* open procedure */
	NULL,			/* close procedure */
	NULL,			/* unused */
	&cs4231_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* STREAMS entity declaration structure */
static struct streamtab cs4231_str_info = {
	&cs4231_rqueue,		/* read queue */
	&cs4231_wqueue,		/* write queue */
	NULL,			/* mux lower read queue */
	NULL,			/* mux lower write queue */
};

/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops cs4231_cb_ops = {
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
	&cs4231_str_info,	/* cb_str */
	D_NEW|D_MP|D_64BIT,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_arwite */
};

/* Device operations structure */
static struct dev_ops cs4231_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	cs4231_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe - not needed */
	cs4231_attach,		/* devo_attach */
	cs4231_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cs4231_cb_ops,		/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	cs4231_power,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv cs4231_modldrv = {
	&mod_driverops,		/* drv_modops */
	CS4231_MOD_NAME,	/* drv_linkinfo */
	&cs4231_dev_ops		/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage cs4231_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&cs4231_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
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

	ATRACE("in audiocs _init()", 0);

	/* initialize the soft state */
	if ((error = ddi_soft_state_init(&cs_statep, sizeof (CS_state_t), 0)) !=
	    0) {
		ATRACE("audiocs ddi_soft_state_init() failed", cs_statep);
		return (error);
	}

	if ((error = mod_install(&cs4231_modlinkage)) != 0) {
		ddi_soft_state_fini(&cs_statep);
	}

	ATRACE("audiocs _init() cs_statep", cs_statep);
	ATRACE_32("audiocs _init() returning", error);

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

	ATRACE("in audiocs _fini()", cs_statep);

	if ((error = mod_remove(&cs4231_modlinkage)) != 0) {
		return (error);
	}

	/* free the soft state internal structures */
	ddi_soft_state_fini(&cs_statep);

	ATRACE_32("audiocs _fini() returning", error);

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

	ATRACE("in audiocs _info()", 0);

	error = mod_info(&cs4231_modlinkage, modinfop);

	ATRACE_32("audiocs _info() returning", error);

	return (error);
}


/* *******  Driver Entry Points  ******************************************** */
/*
 * cs4231_getinfo()
 */
/*ARGSUSED*/
static int
cs4231_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result)
{
	CS_state_t	*state;
	int error = DDI_FAILURE;
	int instance;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = audio_sup_devt_to_instance((dev_t)arg);
		if ((state = ddi_get_soft_state(cs_statep,
		    instance)) != NULL) {
			*result = state->cs_dip;
			error = DDI_SUCCESS;
		} else {
			*result = NULL;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)
		    audio_sup_devt_to_instance((dev_t)arg);
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}

/*
 * cs4231_attach()
 *
 * Description:
 *	Attach an instance of the CS4231 driver. This routine does the device
 *	dependent attach tasks. When it is complete it calls
 *	audio_sup_register() and am_attach() so they may do their work.
 *
 *	NOTE: mutex_init() no longer needs a name string, so set
 *		to NULL to save kernel space.
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
cs4231_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	CS_state_t		*state;
	audiohdl_t		ahandle;
	audio_sup_reg_data_t	data;
	int			instance;

	ATRACE("in cs_attach()", dip);

	instance = ddi_get_instance(dip);
	ATRACE_32("cs_attach() instance", instance);
	ATRACE("cs_attach() cs_statep", cs_statep);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		ATRACE("cs_attach() DDI_RESUME", NULL);

		/* we've already allocated the state structure so get ptr */
		if ((state = ddi_get_soft_state(cs_statep, instance)) == NULL) {
			audio_sup_log(NULL, CE_WARN,
			    "!%s%d: attach() RESUME get soft state failed",
			    audiocs_name, instance);
			return (DDI_FAILURE);
		}

		ASSERT(dip == state->cs_dip);
		ASSERT(!mutex_owned(&state->cs_lock));

		ahandle = state->cs_ahandle;

		/* power up the Codec */
		ASSERT(state->cs_powered == CS4231_PWR_OFF);
		(void) pm_busy_component(state->cs_dip, CS4231_COMPONENT);
		if (pm_raise_power(dip, CS4231_COMPONENT, CS4231_PWR_ON)
		    == DDI_FAILURE) {
			/* match the busy call above */
			(void) pm_idle_component(state->cs_dip,
			    CS4231_COMPONENT);
			audio_sup_log(ahandle, CE_WARN,
			    "!attach() DDI_RESUME failed");
			return (DDI_FAILURE);
		}
		mutex_enter(&state->cs_lock);

		ASSERT(mutex_owned(&state->cs_lock));
		ASSERT(state->cs_suspended == CS4231_SUSPENDED);

		state->cs_suspended = CS4231_NOT_SUSPENDED;

		cv_broadcast(&state->cs_cv);	/* let entry points continue */

		mutex_exit(&state->cs_lock);

		/* now restart playing and recording */
		if (audio_sup_restore_state(ahandle, AUDIO_ALL_DEVICES,
		    AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(ahandle, CE_WARN,
			    "!attach() audio restart failed");
		}

		/* we're no longer busy */
		ASSERT(state->cs_powered == CS4231_PWR_ON);
		(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);

		ATRACE("cs_attach() DDI_RESUME succeeded", NULL);
		ASSERT(!mutex_owned(&state->cs_lock));

		return (DDI_SUCCESS);
	default:
		audio_sup_log(NULL, CE_NOTE,
		    "!%s%d: attach() unknown command 0x%x", audiocs_name,
		    instance, cmd);
		return (DDI_FAILURE);
	}

	/* allocate the state structure */
	if (ddi_soft_state_zalloc(cs_statep, instance) == DDI_FAILURE) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() soft state allocate failed", audiocs_name,
		    instance);
		return (DDI_FAILURE);
	}

	/*
	 * WARNING: From here on all errors require that we free memory,
	 *	including the state structure.
	 */

	/* get the state structure */
	if ((state = ddi_get_soft_state(cs_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() get soft state failed", audiocs_name,
		    instance);
		goto error_mem;
	}

	/* call audiosup module registration routine */
	ATRACE("cs_attach() calling audio_sup_register()", NULL);
	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;
	if ((state->cs_ahandle = audio_sup_register(dip, &data)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: cs4231_attach() audio_sup_register() failed",
		    audiocs_name, instance);
		goto error_mem;
	}

	ahandle = state->cs_ahandle;

	/* initialize the audio state structures */
	if ((cs4231_init_state(state, dip)) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!attach() init_state() failed");
		goto error_audiosup;
	}

	/* initialize the audio chip */
	ATRACE("cs_attach() calling chip_init()", NULL);
	if ((cs4231_chip_init(state)) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN, "!attach() chip_init() failed");
		goto error_destroy;
	}

	/* save private state */
	audio_sup_set_private(ahandle, state);

	/* call the mixer attach() routine */
	ATRACE("cs_attach() calling am_attach()", &state->cs_ad_info);
	if (am_attach(ahandle, cmd, &state->cs_ad_info) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN, "!attach() am_attach() failed");
		goto error_destroy;
	}

	/* set up kernel statistics */
	if ((state->cs_ksp = kstat_create(audiocs_name, instance, audiocs_name,
	    "controller", KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(state->cs_ksp);
	}

	/* we're ready, set up the interrupt handler */
	ATRACE("cs_attach() calling DMA_ADD_INTR()", state);
	if (CS4231_DMA_ADD_INTR(state) != AUDIO_SUCCESS) {
		ATRACE("cs_attach() DMA_ADD_INTR() failed", state);
		goto error_kstat;
	}

	/* everything worked out, so report the device */
	ddi_report_dev(dip);

	ATRACE("cs_attach() returning success", state);

	return (DDI_SUCCESS);

error_kstat:
	ATRACE("cs_attach() error_kstat", state);
	if (state->cs_ksp) {
		kstat_delete(state->cs_ksp);
	}

	(void) am_detach(ahandle, DDI_DETACH);

error_destroy:
	ATRACE("cs_attach() error_destroy", state);
	CS4231_DMA_UNMAP_REGS(state);
	mutex_destroy(&state->cs_lock);
	cv_destroy(&state->cs_cv);

error_audiosup:
	ATRACE("cs_attach() error_audiosup", state);
	(void) audio_sup_unregister(ahandle);

error_mem:
	ATRACE("cs_attach() error_mem", state);
	ddi_soft_state_free(cs_statep, instance);

	ATRACE("cs_attach() returning failure", NULL);

	return (DDI_FAILURE);

}	/* cs4231_attach() */

/*
 * cs4231_detach()
 *
 * Description:
 *	Detach an instance of the CS4231 driver. After the Codec is detached
 *	we call am_detach() and audio_sup_unregister() so they may do their
 *	work.
 *
 *	Power management is pretty simple. If active we fail, otherwise
 *	we save the Codec state.
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
cs4231_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	CS_state_t		*state;
	audiohdl_t		ahandle;
	ddi_acc_handle_t	handle;
	int			instance;

	ATRACE_32("in cs_detach()", cmd);

	instance = ddi_get_instance(dip);
	ATRACE_32("cs_detach() instance", instance);
	ATRACE("cs_detach() cs_statep", cs_statep);

	/* get the state structure */
	if ((state = ddi_get_soft_state(cs_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: detach() get soft state failed", audiocs_name,
		    instance);
		return (DDI_FAILURE);
	}

	ASSERT(!mutex_owned(&state->cs_lock));

	handle = state->cs_handles.cs_codec_hndl;
	ahandle = state->cs_ahandle;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		ATRACE("cs_detach() DDI_SUSPEND", NULL);

		mutex_enter(&state->cs_lock);

		ASSERT(state->cs_suspended == CS4231_NOT_SUSPENDED);
		state->cs_suspended = CS4231_SUSPENDED;	/* stop new ops */

		/* wait for current operations to complete */
		while (state->cs_busy_cnt != 0) {
			cv_wait(&state->cs_cv, &state->cs_lock);
		}

		if (state->cs_powered == CS4231_PWR_ON) {
			/* stop playing and recording */
			CS4231_DMA_STOP_RECORD(state);
			CS4231_DMA_STOP_PLAY(state);

			/* now we can power down the Codec */
			cs4231_power_down(state);

			if (audio_sup_save_state(ahandle, AUDIO_ALL_DEVICES,
			    AUDIO_BOTH) == AUDIO_FAILURE) {
				audio_sup_log(ahandle, CE_WARN,
				    "!detach() audio save failed");
			}
		}
		mutex_exit(&state->cs_lock);

		ATRACE("cs_detach() SUSPEND successful", state);
		ASSERT(!mutex_owned(&state->cs_lock));
		return (DDI_SUCCESS);
	default:
		ATRACE_32("cs_detach() unknown command failure", cmd);
		audio_sup_log(ahandle, CE_NOTE,
		    "!detach() unknown command 0x%x", cmd);
		return (DDI_FAILURE);
	}

	if (state->cs_powered == CS4231_PWR_ON) {
		/*
		 * Make sure the Codec and DMA engine are off.
		 */
		cs4231_reg_select(ahandle, handle, &CS4231_IAR, INTC_REG,
		    __LINE__, thisfile);
		AND_SET_BYTE(handle, &CS4231_IDR, ~(INTC_PEN|INTC_CEN),
		    INTC_VALID_MASK);

		/* make sure the DMA engine isn't going to do anything */
		CS4231_DMA_RESET(state);

		/*
		 * power down the device, no reason to waste power without
		 * a driver
		 */
		(void) pm_lower_power(state->cs_dip, CS4231_COMPONENT,
		    CS4231_PWR_OFF);
	}

	/*
	 * unregister the interrupt. That way we can't get called by and
	 * interrupt after the audio framework is removed.
	 */
	ATRACE("cs_detach() calling DMA_REM_INTR", state);
	CS4231_DMA_REM_INTR(dip, state);

	/*
	 * Call the mixer detach routine to tear down the mixer before
	 * we lose the hardware.
	 */
	ATRACE("cs_detach() calling am_detach()", dip);
	if (am_detach(ahandle, cmd) == AUDIO_FAILURE) {
		ATRACE_32("cs_detach() am_detach() failed", cmd);
		return (DDI_FAILURE);
	}
	ATRACE("cs_detach() calling audio_sup_unregister()", dip);
	if (audio_sup_unregister(ahandle) == AUDIO_FAILURE) {
		ATRACE_32("cs_detach() audio_sup_unregister() failed", cmd);
		return (DDI_FAILURE);
	}

	ASSERT(state->cs_busy_cnt == 0);

	/* unmap the registers */
	CS4231_DMA_UNMAP_REGS(state);

	/* free the kernel statistics structure */
	if (state->cs_ksp) {
		kstat_delete(state->cs_ksp);
	}
	state->cs_ksp = NULL;

	/* destroy the state mutex */
	mutex_destroy(&state->cs_lock);
	cv_destroy(&state->cs_cv);

	/* free the memory for the state pointer */
	ddi_soft_state_free(cs_statep, instance);

	ATRACE("cs_detach() returning success", cs_statep);

	return (DDI_SUCCESS);

}	/* cs4231_detach() */

/*
 * cs4231_power()
 *
 * Description:
 *	This routine is used to turn the power to the Codec on and off.
 *	The different DMA engines have different ways to turn on/off the
 *	power to the Codec. Therefore we call the DMA engine specific code
 *	to do the work, if we need to make a change.
 *
 *	If the level is CS4231_PWR_OFF then we call cs4231_power_down(). If the
 *	level is CS4231_PWR_ON then we call cs4231_power_up().
 *
 *	This routine doesn't stop or restart play and record. Other routines
 *	are responsible for that.
 *
 * Arguments:
 *	def_info_t	*dip		Ptr to the device's dev_info structure
 *	int		component	Which component to power up/down
 *	int		level		The power level for the component
 *
 * Returns:
 *	DDI_SUCCESS		Power level changed, we always succeed
 */
static int
cs4231_power(dev_info_t *dip, int component, int level)
{
	CS_state_t		*state;
	int			instance;
	int			rc = DDI_FAILURE;

	ATRACE("in cs_power()", dip);
	ATRACE("cs_power() cs_statep", cs_statep);
	ASSERT(component == 0);

	instance = ddi_get_instance(dip);
	ATRACE_32("cs_power() instance", instance);

	/* get the state structure */
	if ((state = ddi_get_soft_state(cs_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: power() get soft state failed", audiocs_name,
		    instance);
		return (DDI_FAILURE);
	}

	ASSERT(!mutex_owned(&state->cs_lock));

	/* make sure we have some work to do */
	mutex_enter(&state->cs_lock);

	/* check the level change to see what we need to do */
	if (level == CS4231_PWR_OFF && state->cs_powered == CS4231_PWR_ON) {

		/* don't power off if we're busy */
		if (state->cs_busy_cnt) {
			/* device is busy, so don't power off */
			mutex_exit(&state->cs_lock);

			/* reset the timer */
			(void) pm_idle_component(dip, CS4231_COMPONENT);

			ATRACE("cs_power() power off failed, busy",
			    state->cs_busy_cnt);
			ASSERT(rc == DDI_FAILURE);

			goto done;
		}
		/* power down and save the state */
		cs4231_power_down(state);

	} else if (level == CS4231_PWR_ON &&
	    state->cs_powered == CS4231_PWR_OFF) {

		/* power up */
		cs4231_power_up(state);

#ifdef DEBUG
	} else {
		ATRACE_32("cs_power() no change to make", level);
#endif
	}

	mutex_exit(&state->cs_lock);

	rc = DDI_SUCCESS;

done:
	ASSERT(!mutex_owned(&state->cs_lock));
	ATRACE("cs4231_power() done", level);

	return (rc);

}	/* cs4231_power() */


/* *******  Audio Driver Entry Point Routines ******************************* */

/*
 * cs4231_ad_pause_play()
 *
 * Description:
 *	This routine pauses the play DMA engine.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
cs4231_ad_pause_play(audiohdl_t ahandle, int stream)
{
	CS_state_t		*state;

	ATRACE("in cs_ad_pause_play()", ahandle);
	ATRACE("cs_ad_pause_play() cs_statep", cs_statep);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!pause_play() set_busy() failed");
		return;
	}

	/* we need to protect the state structure */
	mutex_enter(&state->cs_lock);

	ATRACE("cs_ad_pause_play() calling DMA_PAUSE_PLAY()", state);
	CS4231_DMA_PAUSE_PLAY(state);
	ATRACE("cs_ad_pause_play() DMA_PAUSE_PLAY() returned", state);

	mutex_exit(&state->cs_lock);

	/* need an idle for the busy above */
	cs4231_set_idle(state);

	ATRACE("cs_ad_pause_play() returning", state);

}	/* cs4231_ad_pause_play() */

/*
 * cs4231_ad_set_config()
 *
 * Description:
 *	This routine is used to set new Codec parameters, except the data
 *	format which has it's own routine. If the Codec doesn't support a
 *	particular parameter and it is asked to set it then we return
 *	AUDIO_FAILURE.
 *
 *	The stream argument is ignored because this isn't a multi-stream Codec.
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
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
cs4231_ad_set_config(audiohdl_t ahandle, int stream, int command, int dir,
	int arg1, int arg2)
{
	CS_state_t		*state;
	ddi_acc_handle_t	handle;
	int			rc = AUDIO_FAILURE;

	ATRACE_32("in cs_ad_set_config()", command);
	ATRACE_32("cs_ad_set_config() stream", stream);
	ATRACE_32("cs_ad_set_config() command", command);
	ATRACE_32("cs_ad_set_config() dir", dir);
	ATRACE_32("cs_ad_set_config() arg1", arg1);
	ATRACE_32("cs_ad_set_config() arg2", arg2);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* wait on suspend, power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!set_config() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	/* CAUTION: From here on we must goto done to exit. */

	handle = state->cs_handles.cs_codec_hndl;

	switch (command) {
	case AM_SET_GAIN:
		/*
		 * Set the gain for a channel. The audio mixer calculates the
		 * impact, if any, on the channel's gain.
		 *
		 *	0 <= gain <= AUDIO_MAX_GAIN
		 *
		 *	arg1 --> gain
		 *	arg2 --> channel #, 0 = left, 1 = right
		 */

		rc = cs4231_set_gain(state, stream, dir, arg1, arg2);
		break;

	case AM_SET_PORT:
		/*
		 * Enable/disable the input or output ports. The audio mixer
		 * enforces exclusiveness of ports, as well as which ports
		 * are modifyable. We just turn on the ports that match the
		 * bits.
		 *
		 *	arg1 --> port bit pattern
		 *	arg2 --> not used
		 */

		rc = cs4231_set_port(state, dir, arg1);
		break;

	case AM_SET_MONITOR_GAIN:
		/*
		 * Set the loopback monitor gain.
		 *
		 *	0 <= gain <= AUDIO_MAX_GAIN
		 *
		 *	dir ---> N/A
		 *	arg1 --> gain
		 *	arg2 --> not used
		 */

		rc = cs4231_set_monitor_gain(state, arg1);
		break;

	case AM_OUTPUT_MUTE:
		/*
		 * Mute or enable the output.
		 *
		 *	dir ---> N/A
		 *	arg1 --> ~0 = mute, 0 = unmute
		 *	arg2 --> not used
		 */
		mutex_enter(&state->cs_lock);

		if (arg1) {
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    LDACO_REG, __LINE__, thisfile);
			OR_SET_BYTE(handle, &CS4231_IDR, LDACO_LDM,
			    LDAC0_VALID_MASK);
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    RDACO_REG, __LINE__, thisfile);
			OR_SET_BYTE(handle, &CS4231_IDR, RDACO_RDM,
			    RDAC0_VALID_MASK);
			state->cs_output_muted = B_TRUE;
		} else { /* Unmute */
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    LDACO_REG, __LINE__, thisfile);
			AND_SET_BYTE(handle, &CS4231_IDR, ~LDACO_LDM,
			    LDAC0_VALID_MASK);
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    RDACO_REG, __LINE__, thisfile);
			AND_SET_BYTE(handle, &CS4231_IDR, ~RDACO_RDM,
			    RDAC0_VALID_MASK);
			state->cs_output_muted = B_FALSE;
		}
		mutex_exit(&state->cs_lock);

		rc = AUDIO_SUCCESS;
		goto done;

	case AM_MIC_BOOST:
		/*
		 * Enable or disable the mic's 20 dB boost preamplifier.
		 *
		 *	dir ---> N/A
		 *	arg1 --> ~0 == enable, 0 == disabled
		 *	arg2 --> not used
		 */
		mutex_enter(&state->cs_lock);
		if (arg1) {
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    LADCI_REG, __LINE__, thisfile);
			OR_SET_BYTE(handle, &CS4231_IDR, LADCI_LMGE,
			    LADCI_VALID_MASK);
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    RADCI_REG, __LINE__, thisfile);
			OR_SET_BYTE(handle, &CS4231_IDR, RADCI_RMGE,
			    RADCI_VALID_MASK);
			state->cs_ad_info.ad_add_mode |= AM_ADD_MODE_MIC_BOOST;
		} else {
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    LADCI_REG, __LINE__, thisfile);
			AND_SET_BYTE(handle, &CS4231_IDR, ~LADCI_LMGE,
			    LADCI_VALID_MASK);
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    RADCI_REG, __LINE__, thisfile);
			AND_SET_BYTE(handle, &CS4231_IDR, ~RADCI_RMGE,
			    RADCI_VALID_MASK);
			state->cs_ad_info.ad_add_mode &= ~AM_ADD_MODE_MIC_BOOST;
		}
		mutex_exit(&state->cs_lock);

		rc = AUDIO_SUCCESS;
		goto done;

	default:
		/*
		 * We let default catch commands we don't support, as well
		 * as bad commands.
		 */
		ATRACE_32("cs_ad_set_config() unsupported command", command);
		goto done;
	}

done:
	/* need an idle for the busy above */
	cs4231_set_idle(state);

	ATRACE_32("cs4231_ad_set_config() returning", rc);
	ASSERT(!mutex_owned(&state->cs_lock));

	return (rc);

}	/* cs4231_ad_set_config() */

/*
 * cs4231_ad_set_format()
 *
 * Description:
 *	This routine is used to set a new Codec data format.
 *
 *	The stream argument is ignored because this isn't a multi-stream Codec.
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
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
cs4231_ad_set_format(audiohdl_t ahandle, int stream, int dir,
	int sample_rate, int channels, int precision, int encoding)
{
	CS_state_t		*state;
	ddi_acc_handle_t	handle;
	uint8_t			mask;
	uint8_t			value;
	int			rc = AUDIO_FAILURE;

	ATRACE_32("in cs_ad_set_format()", sample_rate);
	ATRACE("cs_ad_set_format() cs_statep", cs_statep);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* wait on suspend, power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!set_format() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	handle = state->cs_handles.cs_codec_hndl;

	/*
	 * CAUTION: From here on we must goto done to exit.
	 */

	if (dir == AUDIO_PLAY) {	/* sample rate set on play side only */
		switch (sample_rate) {
		case CS4231_SAMPR5510:		value = FS_5510; break;
		case CS4231_SAMPR6620:		value = FS_6620; break;
		case CS4231_SAMPR8000:		value = FS_8000; break;
		case CS4231_SAMPR9600:		value = FS_9600; break;
		case CS4231_SAMPR11025:		value = FS_11025; break;
		case CS4231_SAMPR16000:		value = FS_16000; break;
		case CS4231_SAMPR18900:		value = FS_18900; break;
		case CS4231_SAMPR22050:		value = FS_22050; break;
		case CS4231_SAMPR27420:		value = FS_27420; break;
		case CS4231_SAMPR32000:		value = FS_32000; break;
		case CS4231_SAMPR33075:		value = FS_33075; break;
		case CS4231_SAMPR37800:		value = FS_37800; break;
		case CS4231_SAMPR44100:		value = FS_44100; break;
		case CS4231_SAMPR48000:		value = FS_48000; break;
		default:
			ATRACE_32("cs_ad_set_format() bad sample rate",
			    sample_rate);
			goto done;
		}
	} else {
		value = 0;
	}

	/* if not mono then must be stereo, i.e., the default */
	if (channels == AUDIO_CHANNELS_STEREO) {
		ATRACE_32("cs_ad_set_format() STEREO", channels);
		value |= PDF_STEREO;
	} else if (channels != AUDIO_CHANNELS_MONO) {
		ATRACE_32("cs_ad_set_format() bad # of channels", channels);
		goto done;
#ifdef DEBUG
	} else {
		ATRACE_32("cs_ad_set_format() MONO", channels);
#endif
	}

	if (precision == AUDIO_PRECISION_8) {
		ATRACE_32("cs_ad_set_format() 8-bit", precision);
		switch (encoding) {
		case AUDIO_ENCODING_ULAW:
			value |= PDF_ULAW8;
			break;
		case AUDIO_ENCODING_ALAW:
			value |= PDF_ALAW8;
			break;
		case AUDIO_ENCODING_LINEAR:
			value |= PDF_LINEAR8;
			break;
		default:
			goto done;
		}
	} else {	/* 16 bit, default, and there is only one choice */
		ATRACE_32("cs_ad_set_format() 16-bit", precision);
		if (encoding != AUDIO_ENCODING_LINEAR) {
			goto done;
		}

		value |= PDF_LINEAR16BE;
	}

	mutex_enter(&state->cs_lock);
	if (dir == AUDIO_PLAY) {	/* play side */
		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    (FSDF_REG | IAR_MCE), __LINE__, thisfile);
		ATRACE_8("cs_ad_set_format() programming FSDF_REG", value);
		state->cs_play_sr = sample_rate;
		state->cs_play_ch = channels;
		state->cs_play_prec = precision;
		state->cs_play_enc = encoding;
		state->cs_save_pe = value;
		mask = FSDF_VALID_MASK;
	} else {			/* capture side */
		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    (CDF_REG | IAR_MCE), __LINE__, thisfile);
		ATRACE_8("cs_ad_set_format() programming CDF_REG", value);
		state->cs_record_sr = sample_rate;
		state->cs_record_ch = channels;
		state->cs_record_prec = precision;
		state->cs_record_enc = encoding;
		state->cs_save_ce = value;
		mask = CDF_VALID_MASK;
	}

	cs4231_put8(ahandle, handle, &CS4231_IDR, value, mask,
	    __LINE__, thisfile);

	(void) cs4231_poll_ready(state);

	/* clear the mode change bit */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, FSDF_REG, __LINE__,
	    thisfile);
	mutex_exit(&state->cs_lock);

	ATRACE_32("cs_ad_set_format() returning", sample_rate);

	rc = AUDIO_SUCCESS;

done:
	/* we're no longer busy */
	cs4231_set_idle(state);

	ATRACE_32("cs_ad_set_format() returning", rc);
	ASSERT(!mutex_owned(&state->cs_lock));

	return (rc);

}	/* cs4231_ad_set_format() */

/*
 * cs4231_ad_start_play()
 *
 * Description:
 *	This routine starts the play DMA engine. It checks to make sure the
 *	DMA engine is off before it does anything, otherwise it may mess
 *	things up.
 *
 *	The stream argument is ignored because this isn't a multi-stream Codec.
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *
 * Returns:
 *	AUDIO_SUCCESS		Playing started/restarted
 *	AUDIO_FAILURE		Audio not restarted, no audio to play
 */
/*ARGSUSED*/
static int
cs4231_ad_start_play(audiohdl_t ahandle, int stream)
{
	CS_state_t		*state;
	ddi_acc_handle_t	handle;
	int			rc;

	ATRACE("in cs_ad_start_play()", ahandle);
	ATRACE("cs_ad_start_play() cs_statep", cs_statep);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!start_play() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	handle = state->cs_handles.cs_codec_hndl;

	/* we need to protect the state structure */
	mutex_enter(&state->cs_lock);
	ASSERT(state->cs_powered == CS4231_PWR_ON);

	/* see if we are already playing */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, INTC_REG, __LINE__,
	    thisfile);
	if (INTC_PEN & ddi_get8(handle, &CS4231_IDR)) {
		mutex_exit(&state->cs_lock);
		ATRACE("cs_ad_start_play() already playing", NULL);
		rc = AUDIO_SUCCESS;
		goto done;
	}

	if (state->cs_flags & PDMA_ENGINE_INITIALIZED) {
		ATRACE("cs_ad_start_play() calling DMA_RESTART_PLAY()", state);
		CS4231_DMA_RESTART_PLAY(state);
		ATRACE_32("cs_ad_start_play() DMA_RESTART_PLAY() returned", 0);
		rc = AUDIO_SUCCESS;
	} else {
		/*
		 * The newer versions of the EB2 DMA engine reset on a non-even
		 * sample boundary. Then when it restarts it'll be in mid sample
		 * which results in loud static. When we start again we reload
		 * the format register, which resets the Codec, starting on an
		 * even boundary, and thus no static. We end up doing this for
		 * the APC DMA engine as well, but it's harmless.
		 *
		 * CAUTION: Don't do this for record. It causes SunVTS to
		 *	fail. Also, do not reset the DMA engine if record is
		 *	active. This occasionally upsets everything.
		 */
		if (!(state->cs_flags & RDMA_ENGINE_INITIALIZED)) {
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    (FSDF_REG | IAR_MCE), __LINE__, thisfile);
			cs4231_put8(ahandle, handle, &CS4231_IDR,
			    state->cs_save_pe, FSDF_VALID_MASK,
			    __LINE__, thisfile);
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    FSDF_REG, __LINE__, thisfile);
			ATRACE("cs_ad_start_play() play DMA engine reset",
			    state);
		}

		ATRACE("cs_ad_start_play() calling DMA_START_PLAY()", state);
		rc = CS4231_DMA_START_PLAY(state);
		ATRACE_32("cs_ad_start_play() DMA_START_PLAY() returned", rc);

		if (rc == AUDIO_SUCCESS) {
			ATRACE("cs_ad_start_play() programming Codec to play",
			    state);
			cs4231_reg_select(ahandle, handle, &CS4231_IAR,
			    INTC_REG, __LINE__, thisfile);
			OR_SET_BYTE(handle, &CS4231_IDR, INTC_PEN,
			    INTC_VALID_MASK);

			ATRACE_8("cs_ad_start_play() Codec INTC_REG",
			    ddi_get8(handle, &CS4231_IDR));
			(void) pm_busy_component(state->cs_dip,
			    CS4231_COMPONENT);
			state->cs_flags |= PLAY_ACTIVE;
#ifdef DEBUG
		} else {
			ATRACE("cs_ad_start_play() Codec not started", rc);
#endif
		}

	}

	mutex_exit(&state->cs_lock);

done:
	/* need an idle for the busy above */
	cs4231_set_idle(state);

	ATRACE("cs4231_ad_start_play() returning", rc);

	return (rc);

}	/* cs4231_ad_start_play() */

/*
 * cs4231_ad_stop_play()
 *
 * Description:
 *	This routine stops the play DMA engine.
 *
 *	The stream argument is ignored because this isn't a multi-stream Codec.
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
cs4231_ad_stop_play(audiohdl_t ahandle, int stream)
{
	CS_state_t		*state;
	ddi_acc_handle_t	handle;

	ATRACE("cs_ad_stop_play() cs_statep", cs_statep);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!stop_play() set_busy() failed");
		return;
	}

	handle = state->cs_handles.cs_codec_hndl;

	/* we need to protect the state structure */
	mutex_enter(&state->cs_lock);

	ATRACE_8("cs_ad_stop_play() Codec INTC_REG",
	    ddi_get8(handle, &CS4231_IDR));

	/* stop the play DMA engine */
	ATRACE("cs_ad_stop_play() calling DMA_STOP_PLAY()", state);
	CS4231_DMA_STOP_PLAY(state);
	ATRACE("cs_ad_stop_play() DMA_STOP_PLAY() returned", state);
	/* DMA_STOP() returns with the PEN cleared */

	if (state->cs_flags & PLAY_ACTIVE) {
		state->cs_flags &= ~PLAY_ACTIVE;
		(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);
	}

	mutex_exit(&state->cs_lock);

	/* need an idle for the busy above */
	cs4231_set_idle(state);

	ATRACE("cs4231_ad_stop_play() returning", state);

}	/* cs4231_ad_stop_play() */

/*
 * cs4231_ad_start_record()
 *
 * Description:
 *	This routine starts the record DMA engine. It checks to make sure the
 *	DMA engine is off before it does anything, otherwise it may mess
 *	things up.
 *
 *	The stream argument is ignored because this isn't a multi-stream Codec.
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *
 * Returns:
 *	AUDIO_SUCCESS		Recording successfully started
 *	AUDIO_FAILURE		Recording not successfully started
 */
/*ARGSUSED*/
static int
cs4231_ad_start_record(audiohdl_t ahandle, int stream)
{
	CS_state_t		*state;
	ddi_acc_handle_t	handle;
	int			rc = AUDIO_FAILURE;

	ATRACE("cs_ad_start_record() cs_statep", cs_statep);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!start_record() set_busy() failed");
		return (AUDIO_FAILURE);
	}

	handle = state->cs_handles.cs_codec_hndl;

	/* we need to protect the state structure */
	mutex_enter(&state->cs_lock);
	ASSERT(state->cs_powered == CS4231_PWR_ON);

	/* see if we are already recording */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, INTC_REG, __LINE__,
	    thisfile);
	if (INTC_CEN & ddi_get8(handle, &CS4231_IDR)) {
		mutex_exit(&state->cs_lock);
		ATRACE("cs_ad_start_record() already recording", NULL);
		rc = AUDIO_SUCCESS;
		goto done;
	}

	/*
	 * Enable record DMA on the Codec, do NOT reprogram the Codec as
	 * done for play. This will cause SunVTS to fail.
	 */
	ATRACE("cs_ad_start_record() calling DMA_START_RECORD()", state);
	rc = CS4231_DMA_START_RECORD(state);
	ATRACE("cs_ad_start_record() DMA_START_RECORD() returned", rc);

	if (rc == AUDIO_SUCCESS) {
		ATRACE("cs_ad_start_record() programming Codec to rec.", state);
		cs4231_reg_select(ahandle, handle, &CS4231_IAR, INTC_REG,
		    __LINE__, thisfile);
		OR_SET_BYTE(handle, &CS4231_IDR, INTC_CEN, INTC_VALID_MASK);

		ATRACE_8("cs_ad_start_record() Codec INTC_REG",
		    ddi_get8(handle, &CS4231_IDR));

		(void) pm_busy_component(state->cs_dip, CS4231_COMPONENT);

#ifdef DEBUG
	} else {
		ATRACE("cs_ad_start_record() Codec not started", rc);
#endif
	}

	mutex_exit(&state->cs_lock);

done:
	/* need an idle for the busy above */
	cs4231_set_idle(state);

	ATRACE("cs4231_ad_start_record() returning", rc);

	return (rc);

}	/* cs4231_ad_start_record() */

/*
 * cs4231_ad_stop_record()
 *
 * Description:
 *	This routine stops the record DMA engine.
 *
 *	The stream argument is ignored because this isn't a multi-stream Codec.
 *
 *	NOTE: This routine must be called with the state unlocked.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
cs4231_ad_stop_record(audiohdl_t ahandle, int stream)
{
	CS_state_t		*state;
	ddi_acc_handle_t	handle;

	ATRACE("cs_ad_stop_record() cs_statep", cs_statep);

	/* get the state structure */
	state = audio_sup_get_private(ahandle);
	ASSERT(state);

	ASSERT(!mutex_owned(&state->cs_lock));

	/* power up and mark as busy */
	if (cs4231_set_busy(state) == AUDIO_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!stop_record() set_busy() failed");
		return;
	}

	handle = state->cs_handles.cs_codec_hndl;

	/* we need to protect the state structure */
	mutex_enter(&state->cs_lock);

	/* stop the record DMA engine and clear the active flag */
	ATRACE("cs_ad_stop_record() calling DMA_STOP_RECORD()", state);
	CS4231_DMA_STOP_RECORD(state);
	ATRACE("cs_ad_stop_record() DMA_STOP_RECORD() returned", state);

	ATRACE("cs_ad_stop_record() programming Codec to rec.", state);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, INTC_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~INTC_CEN, INTC_VALID_MASK);

	ATRACE_8("cs_ad_stop_record() Codec INTC_REG",
	    ddi_get8(handle, &CS4231_IDR));

	(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);

	mutex_exit(&state->cs_lock);

	/* need an idle for the busy above */
	cs4231_set_idle(state);

	ATRACE("cs4231_ad_stop_record() returning", state);

}       /* cs4231_ad_stop_record() */


/* ******* Local Routines *************************************************** */

/*
 * cs4231_chip_init()
 *
 * Description:
 *	Power up the audio core, initialize the audio Codec, prepare the chip
 *	for use.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS			Chip initialized and ready to use
 *	AUDIO_FAILURE			Chip not initialized and not ready
 */
static int
cs4231_chip_init(CS_state_t *state)
{
	ddi_acc_handle_t	handle;
	audiohdl_t		ahandle = state->cs_ahandle;

	/* make sure we are powered up */
	mutex_enter(&state->cs_lock);
	CS4231_DMA_POWER(state, CS4231_PWR_ON);
	mutex_exit(&state->cs_lock);

	ATRACE("cs_attach() calling DMA_RESET()", state);
	CS4231_DMA_RESET(state);

	/* no autocalibrate */
	state->cs_autocal = B_FALSE;

	/* initialize the Codec */
	handle = state->cs_handles.cs_codec_hndl;

	/* activate registers 16 -> 31 */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, MID_REG,
	    __LINE__, thisfile);
	ddi_put8(handle, &CS4231_IDR, MID_MODE2);

	/* now figure out what version we have */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, VID_REG,
	    __LINE__, thisfile);
	if (ddi_get8(handle, &CS4231_IDR) & VID_A) {
		ATRACE("cs_attach() revA", state);
		state->cs_revA = B_TRUE;
	} else {
		ATRACE("cs_attach() !revA", state);
		state->cs_revA = B_FALSE;
	}

	/* get rid of annoying popping by muting the output channels */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LDACO_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (LDACO_LDM | LDACO_MID_GAIN), LDAC0_VALID_MASK, __LINE__,
	    thisfile);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, RDACO_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (RDACO_RDM | RDACO_MID_GAIN), RDAC0_VALID_MASK, __LINE__,
	    thisfile);

	/* initialize aux input channels to known gain values & muted */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LAUX1_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (LAUX1_LX1M | LAUX1_UNITY_GAIN), LAUX1_VALID_MASK, __LINE__,
	    thisfile);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, RAUX1_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (RAUX1_RX1M | RAUX1_UNITY_GAIN), RAUX1_VALID_MASK, __LINE__,
	    thisfile);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LAUX2_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (LAUX2_LX2M | LAUX2_UNITY_GAIN), LAUX2_VALID_MASK, __LINE__,
	    thisfile);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, RAUX2_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (RAUX2_RX2M | RAUX2_UNITY_GAIN), RAUX2_VALID_MASK, __LINE__,
	    thisfile);

	/* initialize aux input channels to known gain values & muted */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LLIC_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR, (LLIC_LLM | LLIC_UNITY_GAIN),
	    LLIC_VALID_MASK, __LINE__, thisfile);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, RLIC_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR, (RLIC_RLM | RLIC_UNITY_GAIN),
	    RLIC_VALID_MASK, __LINE__, thisfile);

	/* program the sample rate, play and capture must be the same */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR,
	    (FSDF_REG | IAR_MCE), __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR,
	    (FS_8000 | PDF_ULAW8 | PDF_MONO), FSDF_VALID_MASK,
	    __LINE__, thisfile);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR,
	    (CDF_REG | IAR_MCE), __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR, (CDF_ULAW8 | CDF_MONO),
	    CDF_VALID_MASK, __LINE__, thisfile);

	/*
	 * Set up the Codec for playback and capture disabled, dual DMA, and
	 * playback and capture DMA. Also, set autocal if we are supposed to.
	 */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR,
	    (INTC_REG | IAR_MCE), __LINE__, thisfile);
	if (state->cs_autocal == B_TRUE) {
		cs4231_put8(ahandle, handle, &CS4231_IDR,
		    (INTC_ACAL|INTC_DDC|INTC_PDMA|INTC_CDMA), INTC_VALID_MASK,
		    __LINE__, thisfile);
	} else {
		cs4231_put8(ahandle, handle, &CS4231_IDR,
		    (INTC_DDC | INTC_PDMA | INTC_CDMA), INTC_VALID_MASK,
		    __LINE__, thisfile);
	}

	/* turn off the MCE bit */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LADCI_REG,
	    __LINE__, thisfile);

	/* wait for the Codec before we continue XXX - do we need this? */
	if (cs4231_poll_ready(state) == AUDIO_FAILURE) {
		ATRACE("cs_attach() poll_ready() #1 failed", state);
		return (AUDIO_FAILURE);
	}

	/*
	 * Turn on the output level bit to be 2.8 Vpp. Also, don't go to 0 on
	 * underflow.
	 */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, AFE1_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR, AFE1_OLB, AFE1_VALID_MASK,
	    __LINE__, thisfile);

	/* turn on the high pass filter if Rev A */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, AFE2_REG,
	    __LINE__, thisfile);
	if (state->cs_revA) {
		cs4231_put8(ahandle, handle, &CS4231_IDR, AFE2_HPF,
		    AFE2_VALID_MASK, __LINE__, thisfile);
	} else {
		cs4231_put8(ahandle, handle, &CS4231_IDR, 0,
		    AFE2_VALID_MASK, __LINE__, thisfile);
	}

	/* clear the play and capture interrupt flags */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, AFS_REG,
	    __LINE__, thisfile);
	ddi_put8(handle, &CS4231_STATUS, (AFS_RESET_STATUS));

	/* the play and record gains will be set by the audio mixer */

	/* unmute the output */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LDACO_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~LDACO_LDM, LDAC0_VALID_MASK);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, RDACO_REG,
	    __LINE__, thisfile);
	AND_SET_BYTE(handle, &CS4231_IDR, ~RDACO_RDM, RDAC0_VALID_MASK);

	/* unmute the mono speaker and mute mono in */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, MIOC_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR, MIOC_MIM, MIOC_VALID_MASK,
	    __LINE__, thisfile);

	/* clear the mode change bit */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, RDACO_REG,
	    __LINE__, thisfile);

	/* wait for the Codec before we continue XXX - do we need this? */
	if (cs4231_poll_ready(state) == AUDIO_FAILURE) {
		ATRACE("attach() poll_ready() #2 failed", state);
		return (AUDIO_FAILURE);
	}

	ATRACE("cs_attach() chip initialized", state);
	return (AUDIO_SUCCESS);

}	/* cs4231_chip_init() */

/*
 * audiocs_init_state()
 *
 * Description:
 *	This routine initializes the audio driver's state structure and
 *	maps in the registers. This also includes reading the properties.
 *
 *	CAUTION: This routine maps the registers and initializes a mutex.
 *		 Failure cleanup is handled by cs4231_attach(). It is not
 *		 handled locally by this routine.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *	dev_info_t	*dip		Pointer to the device's dev_info struct
 *
 * Returns:
 *	AUDIO_SUCCESS			State structure initialized
 *	AUDIO_FAILURE			State structure not initialized
 */
static int
cs4231_init_state(CS_state_t *state, dev_info_t *dip)
{
	audiohdl_t		ahandle = state->cs_ahandle;
	char			*prop_str;
	char			*pm_comp[] = {
					"NAME=audiocs audio device",
					"0=off",
					"1=on" };
	int			cs4231_pints;
	int			cs4231_rints;
	size_t			cbuf_size;
	size_t			pbuf_size;
	int			instance;

	ATRACE("in cs_init_state()", dip);
	instance = ddi_get_instance(dip);
	ATRACE_32("cs_attach() instance", instance);

	/*
	 * get the play and record interrupts per second,
	 * look for either cs4231_XXXX or XXXX-interrupts.
	 */
	if ((cs4231_pints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cs4231_pints", -1)) == -1) {
		cs4231_pints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "play-interrupts", CS4231_INTS);
	}
	ATRACE_32("cs_init_state() play interrupts per sec", cs4231_pints);

	if ((cs4231_rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cs4231_rints", -1)) == -1) {
		cs4231_rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "record-interrupts", CS4231_INTS);
	}
	ATRACE_32("cs_init_state() record interrupts per sec", cs4231_rints);

	if (cs4231_pints < CS4231_MIN_INTS) {
		audio_sup_log(ahandle, CE_NOTE,
		    "attach() play interrupt rate set too low: %d, resetting"
		    " to %d", cs4231_pints, CS4231_INTS);
		cs4231_pints = CS4231_INTS;
	} else if (cs4231_pints > CS4231_MAX_INTS) {
		audio_sup_log(ahandle, CE_NOTE,
		    "attach() play interrupt rate set too high: %d, resetting"
		    " to %d", cs4231_pints, CS4231_INTS);
		cs4231_pints = CS4231_INTS;
	}

	if (cs4231_rints < CS4231_MIN_INTS) {
		audio_sup_log(ahandle, CE_NOTE,
		    "attach() record interrupt rate set too low: %d, resetting"
		    " to %d", cs4231_rints, CS4231_INTS);
		cs4231_rints = CS4231_INTS;
	} else if (cs4231_rints > CS4231_MAX_INTS) {
		audio_sup_log(ahandle, CE_NOTE,
		    "attach() record interrupt rate set too high: %d, resetting"
		    " to %d", cs4231_rints, CS4231_INTS);
		cs4231_rints = CS4231_INTS;
	}

	/*
	 * Figure out the largest transfer size for the DMA engine. Then
	 * map in the CS4231 and the DMA registers and reset the DMA engine.
	 */
	pbuf_size = CS4231_SAMPR48000 * AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / cs4231_pints;
	cbuf_size = CS4231_SAMPR48000 * AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / cs4231_rints;

	/* get the mode from the .conf file */

	if ((state->cs_ad_info.ad_mode = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cs4231_mode", -1)) == -1) {
		if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "mixer-mode", AM_MIXER_MODE)) {
			state->cs_ad_info.ad_mode = AM_MIXER_MODE;
		} else {
			state->cs_ad_info.ad_mode = AM_COMPAT_MODE;
		}
	}
	ATRACE_32("cs_init_state() setting mode", state->cs_ad_info.ad_mode);

	/* set up the pm-components */
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", pm_comp, 3) != DDI_PROP_SUCCESS) {
		audio_sup_log(ahandle, CE_WARN,
		    "!init_state() couldn't create component");
		return (AUDIO_FAILURE);
	}

	/* save the device info pointer */
	state->cs_dip = dip;

	/* get the iblock cookie needed for interrupt context */
	if (ddi_get_iblock_cookie(dip, (uint_t)0, &state->cs_iblock) !=
	    DDI_SUCCESS) {
		audio_sup_log(ahandle, CE_WARN,
		    "!init_state() cannot get iblock cookie");
		return (AUDIO_FAILURE);
	}

	/* now fill it in, initialize the state mutexs first */
	mutex_init(&state->cs_lock, NULL, MUTEX_DRIVER, state->cs_iblock);
	cv_init(&state->cs_cv, NULL, CV_DRIVER, NULL);

	/* fill in the device default state */
	state->cs_defaults.play.sample_rate = CS4231_DEFAULT_SR;
	state->cs_defaults.play.channels = CS4231_DEFAULT_CH;
	state->cs_defaults.play.precision = CS4231_DEFAULT_PREC;
	state->cs_defaults.play.encoding = CS4231_DEFAULT_ENC;
	state->cs_defaults.play.gain = CS4231_DEFAULT_PGAIN;
	state->cs_defaults.play.port = AUDIO_SPEAKER;
	state->cs_defaults.play.buffer_size = CS4231_BSIZE;
	state->cs_defaults.play.balance = CS4231_DEFAULT_BAL;
	state->cs_defaults.record.sample_rate = CS4231_DEFAULT_SR;
	state->cs_defaults.record.channels = CS4231_DEFAULT_CH;
	state->cs_defaults.record.precision = CS4231_DEFAULT_PREC;
	state->cs_defaults.record.encoding = CS4231_DEFAULT_ENC;
	state->cs_defaults.record.gain = CS4231_DEFAULT_PGAIN;
	state->cs_defaults.record.port = AUDIO_MICROPHONE;
	state->cs_defaults.record.buffer_size = CS4231_BSIZE;
	state->cs_defaults.record.balance = CS4231_DEFAULT_BAL;
	state->cs_defaults.monitor_gain = CS4231_DEFAULT_MONITOR_GAIN;
	state->cs_defaults.output_muted = B_FALSE;
	state->cs_defaults.hw_features = AUDIO_HWFEATURE_DUPLEX|
	    AUDIO_HWFEATURE_IN2OUT|AUDIO_HWFEATURE_PLAY|AUDIO_HWFEATURE_RECORD;
	state->cs_defaults.sw_features = AUDIO_SWFEATURE_MIXER;

	/* fill in the ad_info structure */
	state->cs_ad_info.ad_int_vers = AM_VERSION;

	state->cs_ad_info.ad_add_mode = 0;
	state->cs_ad_info.ad_codec_type = AM_TRAD_CODEC;
	state->cs_ad_info.ad_defaults = &state->cs_defaults;
	state->cs_ad_info.ad_play_comb = cs_combinations;
	state->cs_ad_info.ad_rec_comb = cs_combinations;
	state->cs_ad_info.ad_entry = &cs_entry;
	state->cs_ad_info.ad_dev_info = &state->cs_dev_info;
	state->cs_ad_info.ad_diag_flags = 0;
	state->cs_ad_info.ad_diff_flags = AM_DIFF_CH|AM_DIFF_PREC|AM_DIFF_ENC;
	state->cs_ad_info.ad_assist_flags = AM_ASSIST_MIC;
	state->cs_ad_info.ad_misc_flags = AM_MISC_RP_EXCL|AM_MISC_MONO_DUP;
	state->cs_ad_info.ad_translate_flags =
	    AM_MISC_8_P_TRANSLATE|AM_MISC_8_R_TRANSLATE;
	state->cs_ad_info.ad_num_mics = 1;

	/* play capabilities */
	state->cs_ad_info.ad_play.ad_mixer_srs = cs_mixer_sample_rates;
	state->cs_ad_info.ad_play.ad_compat_srs = cs_compat_sample_rates;
	state->cs_ad_info.ad_play.ad_conv = &am_src2;
	state->cs_ad_info.ad_play.ad_sr_info = NULL;
	state->cs_ad_info.ad_play.ad_chs = cs_channels;
	state->cs_ad_info.ad_play.ad_int_rate = cs4231_pints;
	state->cs_ad_info.ad_play.ad_max_chs = CS4231_MAX_CHANNELS;
	state->cs_ad_info.ad_play.ad_bsize = CS4231_BSIZE;

	/* record capabilities */
	state->cs_ad_info.ad_record.ad_mixer_srs = cs_mixer_sample_rates;
	state->cs_ad_info.ad_record.ad_compat_srs = cs_compat_sample_rates;
	state->cs_ad_info.ad_record.ad_conv = &am_src2;
	state->cs_ad_info.ad_record.ad_sr_info = NULL;
	state->cs_ad_info.ad_record.ad_chs = cs_channels;
	state->cs_ad_info.ad_record.ad_int_rate = cs4231_rints;
	state->cs_ad_info.ad_record.ad_max_chs = CS4231_MAX_CHANNELS;
	state->cs_ad_info.ad_record.ad_bsize = CS4231_BSIZE;

	/* figure out which DMA engine hardware we have */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "dma-model", &prop_str) == DDI_PROP_SUCCESS) {
		if (strcmp(prop_str, "eb2dma") == 0) {
			ATRACE("cs_attach() eb2dma", state);
			state->cs_dma_engine = EB2_DMA;
			state->cs_dma_ops = &cs4231_eb2dma_ops;
		} else {
			ATRACE("cs_attach() apcdma", state);
			state->cs_dma_engine = APC_DMA;
			state->cs_dma_ops = &cs4231_apcdma_ops;
		}
		ddi_prop_free(prop_str);
	} else {
		ATRACE("cs_attach() no prop apcdma", state);
		state->cs_dma_engine = APC_DMA;
		state->cs_dma_ops = &cs4231_apcdma_ops;
	}

	/* cs_regs, cs_eb2_regs and cs_handles filled in later */

	(void) strcpy(&state->cs_dev_info.name[0], CS_DEV_NAME);
	/* always set to onboard1, not really correct, but very high runner */
	(void) strcpy(&state->cs_dev_info.config[0], CS_DEV_CONFIG_ONBRD1);
	/* version filled in below */

	/* most of what's left is filled in when the registers are mapped */

	ATRACE("cs_init_state() calling get_ports()", state);
	cs4231_get_ports(state, dip);

	/* Map in the registers */
	if (CS4231_DMA_MAP_REGS(dip, state, pbuf_size, cbuf_size) ==
	    AUDIO_FAILURE) {
		goto error_regs;
	}

	state->cs_instance = ddi_get_instance(dip);
	state->cs_suspended = CS4231_NOT_SUSPENDED;
	state->cs_powered = CS4231_PWR_OFF;
	state->cs_busy_cnt = 0;

	return (AUDIO_SUCCESS);

error_regs:
	ATRACE("cs_init_state() error_regs", state);
	mutex_destroy(&state->cs_lock);

	ATRACE("cs_init_state() returning failure", NULL);

	return (AUDIO_FAILURE);

}	/* cs4231_init_state */

/*
 * cs4231_get_ports()
 *
 * Description:
 *	Get which audiocs h/w version we have and use this to
 *	determine the input and output ports as well whether or not
 *	the hardware has internal loopbacks or not. We also have three
 *	different ways for the properties to be specified, which we
 *	also need to worry about.
 *
 * Vers	Platform(s)	DMA eng.	audio-module**	loopback
 * a    SS-4+/SS-5+	apcdma		no		no
 * b	Ultra-1&2	apcdma		no		yes
 * c	positron	apcdma		no		yes
 * d	PPC - retired
 * e	x86 - retired
 * f	tazmo		eb2dma		Perigee		no
 * g	tazmo		eb2dma		Quark		yes
 * h	darwin+		eb2dma		no		N/A
 *
 * Vers	model~		aux1*		aux2*
 * a	N/A		N/A		N/A
 * b	N/A		N/A		N/A
 * c	N/A		N/A		N/A
 * d	retired
 * e	retired
 * f	SUNW,CS4231f	N/A		N/A
 * g	SUNW,CS4231g	N/A		N/A
 * h	SUNW,CS4231h	cdrom		none
 *
 * *   = Replaces internal-loopback for latest property type, can be
 *	 set to "cdrom", "loopback", or "none".
 *
 * **  = For plugin audio modules only. Starting with darwin, this
 *	 property is replaces by the model property.
 *
 * ~   = Replaces audio-module.
 *
 * +   = Has the capability of having a cable run from the internal
 *	 CD-ROM to the audio device.
 *
 * N/A = Not applicable, the property wasn't created for early
 *	 platforms, or the property has been retired.
 *
 * NOTE: Older tazmo and quark machines don't have the model property.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *	dev_info_t	*dip		Pointer to the device's dev_info struct
 *
 * Returns:
 *	void
 */
static void
cs4231_get_ports(CS_state_t *state, dev_info_t *dip)
{
	audiohdl_t		ahandle = state->cs_ahandle;
	char			*prop_str;

	ATRACE("Beginning cs4231_get_ports()", NULL);

	/* First we set the common ports, etc. */
	state->cs_defaults.play.avail_ports =
	    AUDIO_SPEAKER|AUDIO_HEADPHONE|AUDIO_LINE_OUT;
	state->cs_defaults.play.mod_ports =
	    AUDIO_SPEAKER|AUDIO_HEADPHONE|AUDIO_LINE_OUT;
	state->cs_defaults.record.avail_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	state->cs_defaults.record.mod_ports |=
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	state->cs_cd_input_line = NO_INTERNAL_CD;

	/* now we try the new "model" property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "model", &prop_str) == DDI_PROP_SUCCESS) {
		if (strcmp(prop_str, "SUNW,CS4231h") == 0) {
			/* darwin */
			ATRACE("cs_attach() NEW - darwin", state);
			(void) strcpy(&state->cs_dev_info.version[0],
			    CS_DEV_VERSION_H);
			state->cs_defaults.record.avail_ports |=
			    AUDIO_INTERNAL_CD_IN;
			state->cs_defaults.play.mod_ports =
			    AUDIO_SPEAKER;
			state->cs_defaults.record.avail_ports |= AUDIO_CD;
			state->cs_defaults.record.mod_ports |= AUDIO_CD;
			state->cs_cd_input_line = INTERNAL_CD_ON_AUX1;
		} else if (strcmp(prop_str, "SUNW,CS4231g") == 0) {
			/* quark audio module */
			ATRACE("cs_attach() NEW - quark", state);
			(void) strcpy(&state->cs_dev_info.version[0],
			    CS_DEV_VERSION_G);
			state->cs_defaults.record.avail_ports |= AUDIO_SUNVTS;
			state->cs_defaults.record.mod_ports |= AUDIO_SUNVTS;
		} else if (strcmp(prop_str, "SUNW,CS4231f") == 0) {
			/* tazmo */
			ATRACE("cs_attach() NEW - tazmo", state);
			(void) strcpy(&state->cs_dev_info.version[0],
			    CS_DEV_VERSION_F);
		} else {
			ATRACE("cs_attach() NEW - unknown", state);
			(void) strcpy(&state->cs_dev_info.version[0], "?");
			audio_sup_log(ahandle, CE_NOTE,
			    "!attach() unknown audio model: %s, some parts of "
			    "audio may not work correctly",
			    (prop_str ? prop_str : "unknown"));
		}
		ddi_prop_free(prop_str);	/* done with the property */
	} else {	/* now try the older "audio-module" property */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "audio-module", &prop_str) ==
		    DDI_PROP_SUCCESS) {
			switch (*prop_str) {
			case 'Q':	/* quark audio module */
				ATRACE("cs_attach() OLD - quark", state);
				(void) strcpy(&state->cs_dev_info.version[0],
				    CS_DEV_VERSION_G);
				state->cs_defaults.record.avail_ports |=
				    AUDIO_SUNVTS;
				state->cs_defaults.record.mod_ports |=
				    AUDIO_SUNVTS;
				break;
			case 'P':	/* tazmo */
				ATRACE("cs_attach() OLD - tazmo", state);
				(void) strcpy(&state->cs_dev_info.version[0],
				    CS_DEV_VERSION_F);
				break;
			default:
				ATRACE("cs_attach() OLD - unknown", state);
				(void) strcpy(&state->cs_dev_info.version[0],
				    "?");
				audio_sup_log(ahandle, CE_NOTE,
				    "!attach() unknown audio module: %s, some "
				    "parts of audio may not work correctly",
				    (prop_str ? prop_str : "unknown"));
				break;
			}
			ddi_prop_free(prop_str);	/* done with the prop */
		} else {	/* now try heuristics, ;-( */
			if (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "internal-loopback", B_FALSE)) {
				if (state->cs_dma_engine == EB2_DMA) {
					ATRACE("cs_attach() OLD - C", state);
					(void) strcpy(
					    &state->cs_dev_info.version[0],
					    CS_DEV_VERSION_C);
				} else {
					ATRACE("cs_attach() OLD - B", state);
					(void) strcpy(
					    &state->cs_dev_info.version[0],
					    CS_DEV_VERSION_B);
				}
				state->cs_defaults.record.avail_ports |=
				    AUDIO_SUNVTS;
				state->cs_defaults.record.mod_ports |=
				    AUDIO_SUNVTS;
			} else {
				ATRACE("cs_attach() ANCIENT - A", state);
				(void) strcpy(&state->cs_dev_info.version[0],
				    CS_DEV_VERSION_A);
				state->cs_defaults.record.avail_ports |=
				    AUDIO_INTERNAL_CD_IN;
				state->cs_defaults.record.mod_ports |=
				    AUDIO_INTERNAL_CD_IN;
				state->cs_cd_input_line = INTERNAL_CD_ON_AUX1;
			}
		}
	}

	ATRACE("Finished in cs4231_get_ports()", NULL);

}	/* cs4231_get_ports() */

/*
 * cs4231_power_up()
 *
 * Description:
 *	Power up the Codec and restore the codec's registers.
 *
 *	NOTE: Like the audiots driver, we don't worry about locking since
 *		the only routines that may call us are attach() and power()
 *		Both of which should be the only threads in the driver.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
cs4231_power_up(CS_state_t *state)
{
	audiohdl_t		ahandle = state->cs_ahandle;
	ddi_acc_handle_t	handle;
	int			i;

	ASSERT(mutex_owned(&state->cs_lock));
	ATRACE("in cs4231_power_up()", NULL);

	handle = state->cs_handles.cs_codec_hndl;

	/* turn on the Codec */
	CS4231_DMA_POWER(state, CS4231_PWR_ON);

	/* reset the DMA engine(s) */
	CS4231_DMA_RESET(state);

	/*
	 * Reload the Codec's registers, the DMA engines will be
	 * taken care of when play and record start up again. But
	 * first enable registers 16 -> 31.
	 */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, MID_REG,
	    __LINE__, thisfile);
	cs4231_put8(ahandle, handle, &CS4231_IDR, state->cs_save[MID_REG],
	    MID_VALID_MASK, __LINE__, thisfile);

	for (i = 0; i < CS4231_REGS; i++) {
		/* restore Codec registers */
		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    (i | IAR_MCE), __LINE__, thisfile);
		ddi_put8(handle, &CS4231_IDR, state->cs_save[i]);
		drv_usecwait(500);	/* chip bug */
	}
	/* clear MCE bit */
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, 0, __LINE__,
	    thisfile);

	ASSERT(state->cs_powered == CS4231_PWR_ON);

	ATRACE("cs_power() power up successful", state);
	ASSERT(mutex_owned(&state->cs_lock));

}	/* cs4231_power_up() */

/*
 * cs4231_power_down()
 *
 * Description:
 *	Power down the Codec and save the codec's registers.
 *
 *	NOTE: See the note in cs4231_power_up() about locking.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
cs4231_power_down(CS_state_t *state)
{
	ddi_acc_handle_t	handle;
	int			i;

	ASSERT(mutex_owned(&state->cs_lock));
	ATRACE("in cs4231_power_down()", NULL);

	handle = state->cs_handles.cs_codec_hndl;

	/*
	 * We are powering down, so we don't need to do a thing with
	 * the DMA engines. However, we do need to save the Codec
	 * registers.
	 */

	for (i = 0; i < CS4231_REGS; i++) {
		/* save Codec regs */
		cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, i,
		    __LINE__, thisfile);
		state->cs_save[i] = ddi_get8(handle, &CS4231_IDR);
	}

	/* turn off the Codec */
	CS4231_DMA_POWER(state, CS4231_PWR_OFF);

	ASSERT(state->cs_powered == CS4231_PWR_OFF);

	ATRACE("cs_power() power down successful", state);
	ASSERT(mutex_owned(&state->cs_lock));

}	/* cs4231_power_down() */

/*
 * cs4231_set_gain()
 *
 * Description:
 *	Set the play or record gain.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *	int		stream		Stream number for multi-stream Codecs,
 *					which this isn't, so just ignore
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
 *	int		gain		The gain to set
 *	int		channels	Number of channels, 1 or 2
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
/*ARGSUSED*/
static int
cs4231_set_gain(CS_state_t *state, int stream, int dir, int gain,
    int channel)
{
	audiohdl_t		ahandle = state->cs_ahandle;
	ddi_acc_handle_t	handle;
	uint8_t			tmp_value;
	int			rc = AUDIO_FAILURE;

	ATRACE("in cs_set_gain()", state);
	ASSERT(!mutex_owned(&state->cs_lock));

	handle = state->cs_handles.cs_codec_hndl;

	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	if (dir == AUDIO_PLAY) {	/* play gain */
		mutex_enter(&state->cs_lock);
		if (channel == 0) {	/* left channel */
			cs4231_reg_select(ahandle, handle,
			    &CS4231_IAR, LDACO_REG, __LINE__, thisfile);
		} else {		/* right channel */
			ASSERT(channel == 1);
			cs4231_reg_select(ahandle, handle,
			    &CS4231_IAR, RDACO_REG, __LINE__, thisfile);
		}
		/* NOTE: LDAC0_VALID_MASK == RDAC0_VALID_MASK, so either ok */

		/* we use cs4231_atten[] to linearize attenuation */
		if (state->cs_output_muted || gain == 0) {
			/* mute the output */
			cs4231_put8(ahandle, handle, &CS4231_IDR,
			    (cs4231_atten[gain]|LDACO_LDM), LDAC0_VALID_MASK,
			    __LINE__, thisfile);
			/* NOTE: LDACO_LDM == RDACO_LDM, so either ok */
		} else {
			cs4231_put8(ahandle, handle, &CS4231_IDR,
			    cs4231_atten[gain], LDAC0_VALID_MASK,
			    __LINE__, thisfile);
			ATRACE("cs_set_gain() play gain set",
			    cs4231_atten[gain]);

		}
		rc = AUDIO_SUCCESS;
		mutex_exit(&state->cs_lock);
	} else {
		ASSERT(dir == AUDIO_RECORD);

		mutex_enter(&state->cs_lock);
		if (channel == 0) {	/* left channel */
			cs4231_reg_select(ahandle, handle,
			    &CS4231_IAR, LADCI_REG, __LINE__, thisfile);
			tmp_value = ddi_get8(handle, &CS4231_IDR) &
			    ~LADCI_GAIN_MASK;
		} else {		/* right channel */
			ASSERT(channel == 1);
			cs4231_reg_select(ahandle, handle,
			    &CS4231_IAR, RADCI_REG, __LINE__, thisfile);
			tmp_value = ddi_get8(handle, &CS4231_IDR) &
			    ~RADCI_GAIN_MASK;
		}
		/* NOTE: LADCI_VALID_MASK == RADCI_VALID_MASK, so either ok */

		/* we shift right by 4 to go from 8-bit to 4-bit gain */
		cs4231_put8(ahandle, handle, &CS4231_IDR,
		    (tmp_value|(gain >> 4)), LADCI_VALID_MASK,
		    __LINE__, thisfile);
		ATRACE("cs_set_gain() record gain set",
		    (tmp_value|(gain >> 4)));
		rc = AUDIO_SUCCESS;
		mutex_exit(&state->cs_lock);
	}

	ATRACE("cs_set_gain() returning", rc);
	ASSERT(!mutex_owned(&state->cs_lock));

	return (rc);

}	/* cs4231_set_gain() */

/*
 * cs4231_set_port()
 *
 * Description:
 *	Set the play/record port.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
 *	int		port		The port to set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The port could not been set
 */
static int
cs4231_set_port(CS_state_t *state, int dir, int port)
{
	audiohdl_t		ahandle = state->cs_ahandle;
	ddi_acc_handle_t	handle;
	uint8_t			tmp_value;
	int			rc = AUDIO_SUCCESS;

	ATRACE("in cs_set_port()", state);
	ASSERT(!mutex_owned(&state->cs_lock));

	handle = state->cs_handles.cs_codec_hndl;

	if (dir == AUDIO_PLAY) {	/* output port(s) */
		/* figure out which output port(s) to turn on */
		tmp_value = 0;

		mutex_enter(&state->cs_lock);
		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    MIOC_REG, __LINE__, thisfile);
		if (port & AUDIO_SPEAKER) {
			AND_SET_BYTE(handle, &CS4231_IDR, ~MIOC_MONO_SPKR_MUTE,
			    MIOC_VALID_MASK);
			tmp_value |= AUDIO_SPEAKER;
		} else {
			OR_SET_BYTE(handle, &CS4231_IDR, MIOC_MONO_SPKR_MUTE,
			    MIOC_VALID_MASK);
		}

		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    PC_REG, __LINE__, thisfile);
		if (port & AUDIO_HEADPHONE) {
			AND_SET_BYTE(handle, &CS4231_IDR, ~PC_HEADPHONE_MUTE,
			    PC_VALID_MASK);
			tmp_value |= AUDIO_HEADPHONE;
		} else {
			OR_SET_BYTE(handle, &CS4231_IDR, PC_HEADPHONE_MUTE,
			    PC_VALID_MASK);
		}

		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    PC_REG, __LINE__, thisfile);
		if (port & AUDIO_LINE_OUT) {
			AND_SET_BYTE(handle, &CS4231_IDR, ~PC_LINE_OUT_MUTE,
			    PC_VALID_MASK);
			tmp_value |= AUDIO_LINE_OUT;
		} else {
			OR_SET_BYTE(handle, &CS4231_IDR, PC_LINE_OUT_MUTE,
			    PC_VALID_MASK);
		}
		mutex_exit(&state->cs_lock);

		ATRACE_32("cs_ad_set_config() set out port", tmp_value);

		if (tmp_value != (port & 0x0ff)) {
			ATRACE_32("cs_ad_set_config() bad out port", port);
			rc = AUDIO_FAILURE;
			goto done;
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);

		/*
		 * Figure out which input port to set. Fortunately
		 * the left and right port bit patterns are the same.
		 */
		switch (port) {
		case AUDIO_NONE:
			tmp_value = 0;
			break;
		case AUDIO_MICROPHONE:
			tmp_value = LADCI_LMIC;
			break;
		case AUDIO_LINE_IN:
			tmp_value = LADCI_LLINE;
			break;
		case AUDIO_CD:
			tmp_value = LADCI_LAUX1;
			break;
		case AUDIO_CODEC_LOOPB_IN:
			tmp_value = LADCI_LLOOP;
			break;
		case AUDIO_SUNVTS:
			tmp_value = LADCI_LAUX1;
			break;
		default:
			/* unknown or inclusive input ports */
			ATRACE_32("cs_ad_set_config() bad in port", port);
			rc = AUDIO_FAILURE;
			goto done;
		}

		mutex_enter(&state->cs_lock);
		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    LADCI_REG, __LINE__, thisfile);
		cs4231_put8(ahandle, handle, &CS4231_IDR,
		    (ddi_get8(handle, &CS4231_IDR) & ~LADCI_IN_MASK)|tmp_value,
		    LADCI_VALID_MASK, __LINE__, thisfile);
		cs4231_reg_select(ahandle, handle, &CS4231_IAR,
		    RADCI_REG, __LINE__, thisfile);
		cs4231_put8(ahandle, handle, &CS4231_IDR,
		    (ddi_get8(handle, &CS4231_IDR) & ~RADCI_IN_MASK)|tmp_value,
		    RADCI_VALID_MASK, __LINE__, thisfile);
		mutex_exit(&state->cs_lock);
	}

done:
	ATRACE("cs_set_port() returning", rc);
	ASSERT(!mutex_owned(&state->cs_lock));

	return (rc);

}	/* cs4231_set_port() */

/*
 * cs4231_set_monitor_gain()
 *
 * Description:
 *	Set the monitor gain.
 *
 * Arguments:
 *	CS_state_t	*state		The device's state structure
 *	int		gain		The gain to set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
static int
cs4231_set_monitor_gain(CS_state_t *state, int gain)
{
	audiohdl_t		ahandle = state->cs_ahandle;
	ddi_acc_handle_t	handle;
	int			rc = AUDIO_SUCCESS;

	ATRACE("in cs_set_monitor gain()", state);
	ASSERT(!mutex_owned(&state->cs_lock));

	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	handle = state->cs_handles.cs_codec_hndl;
	mutex_enter(&state->cs_lock);
	cs4231_reg_select(ahandle, handle, &CS4231_IAR, LC_REG,
	    __LINE__, thisfile);

	if (gain == 0) {
		/* disable loopbacks when gain == 0 */
		cs4231_put8(ahandle, handle, &CS4231_IDR, LC_OFF,
		    LC_VALID_MASK, __LINE__, thisfile);
	} else {
		/* we use cs4231_atten[] to linearize attenuation */
		cs4231_put8(ahandle, handle, &CS4231_IDR,
		    ((cs4231_atten[gain] << 2) | LC_LBE), LC_VALID_MASK,
		    __LINE__, thisfile);
	}
	mutex_exit(&state->cs_lock);

	ATRACE("cs_set_monitor_gain() returning", rc);
	ASSERT(!mutex_owned(&state->cs_lock));

	return (rc);

}	/* cs4231_set_monitor_gain() */

/*
 * cs4231_set_busy()
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
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS			Set busy and powered up
 *	AUDIO_FAILURE			Couldn't power up, so not busy
 */
static int
cs4231_set_busy(CS_state_t *state)
{
	ATRACE("in cs4231_set_busy()", state);
	ASSERT(!mutex_owned(&state->cs_lock));

	/* get the lock so we are safe */
	mutex_enter(&state->cs_lock);

	/* block if we are going to be suspended */
	while (state->cs_suspended == CS4231_SUSPENDED) {
		cv_wait(&state->cs_cv, &state->cs_lock);
	}

	/*
	 * Okay, we aren't going to be suspended yet, so mark as busy.
	 * This will keep us from being suspended when we release the lock.
	 */
	ASSERT(state->cs_busy_cnt >= 0);
	state->cs_busy_cnt++;

	/* now can release the lock before we raise the power */
	mutex_exit(&state->cs_lock);

	/*
	 * Mark as busy before we ask for power to be raised. This removes
	 * the race condtion between the call to cs4231_power() and our call
	 * to raise power. After we raise power we immediately mark as idle
	 * so the count is still good.
	 */
	(void) pm_busy_component(state->cs_dip, CS4231_COMPONENT);
	if (pm_raise_power(state->cs_dip, CS4231_COMPONENT, CS4231_PWR_ON) ==
	    DDI_FAILURE) {
		/* match the busy call above */
		(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);

		audio_sup_log(state->cs_ahandle, CE_WARN,
		    "!%s%d:set_busy() power up failed",
		    audiocs_name, state->cs_instance);

		mutex_enter(&state->cs_lock);
		state->cs_busy_cnt--;		/* restore busy count */
		if (state->cs_busy_cnt == 0) {
			/* let DDI_SUSPEND continue */
			cv_broadcast(&state->cs_cv);
		}
		mutex_exit(&state->cs_lock);

		return (AUDIO_FAILURE);
	}

	/* power is up and we are marked as busy, so we are done */

	ATRACE("audiocs_set_busy() done", state);
	ASSERT(!mutex_owned(&state->cs_lock));

	return (AUDIO_SUCCESS);

}	/* cs4231_set_busy() */

/*
 * cs4231_set_idle()
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
 *	CS_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
cs4231_set_idle(CS_state_t *state)
{
	ATRACE("in cs4231_set_idle()", state);
	ASSERT(!mutex_owned(&state->cs_lock));

	/* get the lock so we are safe */
	mutex_enter(&state->cs_lock);

	ASSERT(state->cs_suspended == CS4231_NOT_SUSPENDED);

	/* decrement the busy count */
	state->cs_busy_cnt--;

	/* if no longer busy, then we wake up a waiting SUSPEND */
	if (state->cs_busy_cnt == 0) {
		cv_broadcast(&state->cs_cv);
	}

	/* we're done, so unlock */
	mutex_exit(&state->cs_lock);

	/* reset the timer */
	(void) pm_idle_component(state->cs_dip, CS4231_COMPONENT);

	ATRACE("cs4231_set_idle() done", state);
	ASSERT(!mutex_owned(&state->cs_lock));

}	/* cs4231_set_idle() */


/* *******  Global Local Routines ******************************************* */

/*
 * cs4231_poll_ready()
 *
 * Description:
 *	This routine waits for the Codec to complete its initialization
 *	sequence and is done with its autocalibration.
 *
 *	Early versions of the Codec have a bug that can take as long as
 *	15 seconds to complete its initialization. For these cases we
 *	use a timeout mechanism so we don't keep the machine locked up.
 *
 * Arguments:
 *	CS_state_t	*state	The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec is ready to continue
 *	AUDIO_FAILURE		The Codec isn't ready to continue
 */
int
cs4231_poll_ready(CS_state_t *state)
{
	ddi_acc_handle_t	handle = state->cs_handles.cs_codec_hndl;
	int			x = 0;
	uint8_t			iar;
	uint8_t			idr;

	ATRACE("in cs_poll_ready()", state);

	ASSERT(state->cs_regs != NULL);
	ASSERT(handle != NULL);

	/* wait for the chip to initialize itself */
	iar = ddi_get8(handle, &CS4231_IAR);

	while ((iar & IAR_INIT) && x++ < CS4231_TIMEOUT) {
		drv_usecwait(50);
		iar = ddi_get8(handle, &CS4231_IAR);
	}

	if (x >= CS4231_TIMEOUT) {
		ATRACE("cs_poll_ready() timeout #1", state);
		return (AUDIO_FAILURE);
	}

	x = 0;

	/*
	 * Now wait for the chip to complete its autocalibration.
	 * Set the test register.
	 */
	cs4231_reg_select(state->cs_ahandle, handle, &CS4231_IAR, ESI_REG,
	    __LINE__, thisfile);

	idr = ddi_get8(handle, &CS4231_IDR);

	while ((idr & ESI_ACI) && x++ < CS4231_TIMEOUT) {
		drv_usecwait(50);
		idr = ddi_get8(handle, &CS4231_IDR);
	}

	if (x >= CS4231_TIMEOUT) {
		ATRACE("cs_poll_ready() timeout #2", state);
		return (AUDIO_FAILURE);
	}

	ATRACE("cs_poll_ready() returning", state);

	return (AUDIO_SUCCESS);

}	/* cs4231_poll_ready() */

/*
 * cs4231_reg_select()
 *
 * Description:
 *	Select a cs4231 register. The cs4231 has a hardware bug where a
 *	register is not always selected the first time. We try and try
 *	again until the proper register is selected or we time out and
 *	print an error message.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	ddi_acc_handle_t handle		A handle to the device's registers
 *	uint8_t		addr		The register address to program
 *	int		reg		The register to select
 *	int		line		The line number where this function was
 *					called
 *	char *		*thefile	The name of the c file that called this
 *					function
 *
 * Returns:
 *	void
 */
void
cs4231_reg_select(audiohdl_t ahandle, ddi_acc_handle_t handle, uint8_t *addr,
    uint8_t reg, int line, char *thefile)
{
	int		x;
	uint8_t		T;

	for (x = 0; x < CS4231_RETRIES; x++) {
		ddi_put8(handle, addr, reg);
		T = ddi_get8(handle, addr);
		if (T == reg) {
			break;
		}
		drv_usecwait(1000);
	}

	if (x == CS4231_RETRIES) {
		audio_sup_log(ahandle, CE_NOTE,
		    "!Couldn't select register (%s, Line #%d 0x%02x 0x%02x)",
		    thefile, line, T, reg);
		audio_sup_log(ahandle, CE_CONT,
		    "!audio may not work correctly until it is stopped and "
		    "restarted\n");
	}

}	/* cs4231_reg_select() */

/*
 * cs4231_put8()
 *
 * Description:
 *	Program a cs4231 register. The cs4231 has a hardware bug where a
 *	register is not programmed properly the first time. We program a value,
 *	then immediately read back the value and reprogram if nescessary.
 *	We do this until the register is properly programmed or we time out and
 *	print an error message.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	ddi_acc_handle_t handle		A handle to the device's registers
 *	uint8_t		addr		The register address to program
 *	uint8_t		mask		Mask to not set reserved register bits
 *	int		val		The value to program
 *	int		line		The line number where this function was
 *					called
 *	char *		*thefile	The name of the c file that called this
 *					function
 *
 * Returns:
 *	void
 */
void
cs4231_put8(audiohdl_t ahandle, ddi_acc_handle_t handle, uint8_t *addr,
    uint8_t val, uint8_t mask, int line, char *thefile)
{
	int		x;
	uint8_t		T;

	val &= mask;

	for (x = 0; x < CS4231_RETRIES; x++) {
		ddi_put8(handle, addr, val);
		T = ddi_get8(handle, addr);
		if (T == val) {
			break;
		}
		drv_usecwait(1000);
	}

	if (x == CS4231_RETRIES) {
		audio_sup_log(ahandle, CE_NOTE,
		    "!Couldn't set value (%s, Line #%d 0x%02x 0x%02x)",
		    thefile, line, T, val);
		audio_sup_log(ahandle, CE_CONT,
		    "!audio may not work correctly until it is stopped and "
		    "restarted\n");
	}

}	/* cs4231_put8() */
