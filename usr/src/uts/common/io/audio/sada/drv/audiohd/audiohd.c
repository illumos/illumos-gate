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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The audiohd driver provides functionality for playing audio on
 * the nVidia MCP55 high-definition audio controller with Realtek
 * ALC88x codec. This enables basic audio functionality for Sun's
 * 2006 line of new workstations and PCs, which are MCP55-based
 * with Realtek ALC88x codec. Due to short time constraints on the
 * production of this software kernel module, we used a minimalistic
 * approach to provide audio functionality for just the nVidia HD
 * audio controller and the Realtek ALC880, ALC883 and ALC885
 * codecs.  Certainly, the driver may work and attach to Intel
 * High-Definition audio devices which have same the Realtek Codec.
 *
 * HD audio supports multiple streams, each of which can act as an
 * independent device. However, we just support two streams: the
 * first input stream for recording, and the first output stream
 * for playback. And because ALC880 doesn't support sample rates
 * below 48K (except 44.1K), this driver just supports 48K sample
 * rate in compatible mode.
 *
 * Currently, this driver only supports limit CODECs, such as Realtek
 * ALC880/882/883/885/888, ALC260/262, Sigmatel STAC9200(D) and
 * Analog Devices 1986/1988.
 */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/pci.h>
#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_trace.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_src.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/am_src2.h>
#include <sys/audio/audiohd.h>
#include <sys/audio/impl/audiohd_impl.h>

/*
 * Module linkage routines for the kernel
 */
static int audiohd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int audiohd_attach(dev_info_t *, ddi_attach_cmd_t);
static int audiohd_detach(dev_info_t *, ddi_detach_cmd_t);
static int audiohd_resume(audiohd_state_t *);
static int audiohd_suspend(audiohd_state_t *);

/*
 * Entry point routine prototypes
 */
static int audiohd_ad_set_config(audiohdl_t, int, int, int, int, int);
static int audiohd_ad_set_format(audiohdl_t, int, int, int, int, int, int);
static int audiohd_ad_start_play(audiohdl_t, int);
static int audiohd_ad_start_record(audiohdl_t, int);
static void audiohd_ad_pause_play(audiohdl_t, int);
static void audiohd_ad_stop_play(audiohdl_t, int);
static void audiohd_ad_stop_record(audiohdl_t, int);

/* interrupt handler */
static uint_t audiohd_intr(caddr_t);

/*
 * Local routines
 */
static int audiohd_init_state(audiohd_state_t *, dev_info_t *);
static int audiohd_init_pci(audiohd_state_t *, ddi_device_acc_attr_t *);
static void audiohd_fini_pci(audiohd_state_t *);
static int audiohd_reinit_hda(audiohd_state_t *);
static int audiohd_reset_controller(audiohd_state_t *);
static int audiohd_init_controller(audiohd_state_t *);
static void audiohd_fini_controller(audiohd_state_t *);
static void audiohd_stop_dma(audiohd_state_t *);
static void audiohd_disable_intr(audiohd_state_t *);
static int audiohd_create_codec(audiohd_state_t *);
static int audiohd_init_codec(audiohd_state_t *);
static void audiohd_destroy_codec(audiohd_state_t *);
static int audiohd_reset_stream(audiohd_state_t	*, int);
static int audiohd_fill_pbuf(audiohd_state_t *);
static void audiohd_refill_pbuf(audiohd_state_t *);
static void audiohd_preset_rbuf(audiohd_state_t *);
static void audiohd_get_rbuf(audiohd_state_t *);
static int audiohd_set_gain(audiohd_state_t *, int, int, int);
static int audiohd_set_port(audiohd_state_t *, int, int);
static void audiohd_mute_outputs(audiohd_state_t *, boolean_t);
static int audiohd_set_monitor_gain(audiohd_state_t *, int);
static int audiohd_alloc_dma_mem(audiohd_state_t *, audiohd_dma_t *,
    size_t, ddi_dma_attr_t *, uint_t);

static uint32_t audioha_codec_verb_get(void *, uint8_t,
    uint8_t, uint16_t, uint8_t);
static uint32_t audioha_codec_4bit_verb_get(void *, uint8_t,
    uint8_t, uint16_t, uint16_t);
static void audiohd_set_busy(audiohd_state_t *);
static void audiohd_set_idle(audiohd_state_t *);

/*
 * operation routines for ALC260, ALC262 and ALC88x
 */
static int audiohd_alc880_init_codec(audiohd_state_t *);
static int audiohd_alc880_set_pcm_fmt(audiohd_state_t *, int, uint_t);
static int audiohd_alc880_set_gain(audiohd_state_t *, int, int, int);
static int audiohd_alc880_set_port(audiohd_state_t *, int, int);
static int audiohd_alc880_mute_outputs(audiohd_state_t *, boolean_t);
static int audiohd_alc880_set_monitor_gain(audiohd_state_t *, int);
static void audiohd_alc880_max_gain(audiohd_state_t *, uint_t *,
    uint_t *, uint_t *);

/* ops for ALC260, ALC262 and ALC88x */
static struct audiohd_codec_ops audiohd_alc880_ops = {
	audiohd_alc880_init_codec,		/* ac_init_codec */
	audiohd_alc880_set_pcm_fmt,		/* ac_set_pcm_fmt */
	audiohd_alc880_set_gain,		/* ac_set_out_gain */
	audiohd_alc880_set_port,		/* ac_set_port */
	audiohd_alc880_mute_outputs,		/* ac_mute_outputs */
	audiohd_alc880_set_monitor_gain,	/* ac_set_monitor_gain */
	audiohd_alc880_max_gain			/* ac_get_max_gain */
};


/*
 * operation routines for STAC9200 codec
 */
static int audiohd_stac_init_codec(audiohd_state_t *);
static int audiohd_stac_set_pcm_fmt(audiohd_state_t *, int, uint_t);
static int audiohd_stac_set_gain(audiohd_state_t *, int, int, int);
static int audiohd_stac_set_port(audiohd_state_t *, int, int);
static int audiohd_stac_mute_outputs(audiohd_state_t *, boolean_t);
static int audiohd_stac_set_monitor_gain(audiohd_state_t *, int);
static void audiohd_stac_max_gain(audiohd_state_t *, uint_t *,
    uint_t *, uint_t *);

/* ops for STAC9200, STAC9200D */
static struct audiohd_codec_ops audiohd_stac9200_ops = {
	audiohd_stac_init_codec,		/* ac_init_codec */
	audiohd_stac_set_pcm_fmt,		/* ac_set_pcm_fmt */
	audiohd_stac_set_gain,			/* ac_set_out_gain */
	audiohd_stac_set_port,			/* ac_set_port */
	audiohd_stac_mute_outputs,		/* ac_mute_outputs */
	audiohd_stac_set_monitor_gain,	/* ac_set_monitor_gain */
	audiohd_stac_max_gain			/* ac_get_max_gain */
};


static int audiohd_stac9872_init_codec(audiohd_state_t *);

/* ops for STAC9872 (CXD9872RD, STAC9872AK, CXD9872AKD) */
static struct audiohd_codec_ops audiohd_stac9872_ops = {
	audiohd_stac9872_init_codec,	/* ac_init_codec */
	audiohd_stac_set_pcm_fmt,		/* ac_set_pcm_fmt */
	audiohd_stac_set_gain,			/* ac_set_out_gain */
	audiohd_stac_set_port,			/* ac_set_port */
	audiohd_stac_mute_outputs,		/* ac_mute_outputs */
	audiohd_stac_set_monitor_gain,	/* ac_set_monitor_gain */
	audiohd_stac_max_gain			/* ac_get_max_gain */
};


/*
 * operation routines for AD1986A codec
 */
static int audiohd_ad1986_init_codec(audiohd_state_t *);
static int audiohd_ad1986_set_pcm_fmt(audiohd_state_t *, int, uint_t);
static int audiohd_ad1986_set_gain(audiohd_state_t *, int, int, int);
static int audiohd_ad1986_set_port(audiohd_state_t *, int, int);
static int audiohd_ad1986_mute_outputs(audiohd_state_t *, boolean_t);
static int audiohd_ad1986_set_monitor_gain(audiohd_state_t *, int);
static void audiohd_ad1986_max_gain(audiohd_state_t *, uint_t *,
    uint_t *, uint_t *);

/* ops for AD1986A */
static struct audiohd_codec_ops audiohd_ad1986_ops = {
	audiohd_ad1986_init_codec,		/* ac_init_codec */
	audiohd_ad1986_set_pcm_fmt,		/* ac_set_pcm_fmt */
	audiohd_ad1986_set_gain,		/* ac_set_out_gain */
	audiohd_ad1986_set_port,		/* ac_set_port */
	audiohd_ad1986_mute_outputs,		/* ac_mute_outputs */
	audiohd_ad1986_set_monitor_gain,	/* ac_set_monitor_gain */
	audiohd_ad1986_max_gain			/* ac_get_max_gain */
};

/*
 * operation routines for AD1988A/B codec
 */
static int audiohd_ad1988_init_codec(audiohd_state_t *);
static int audiohd_ad1988_set_pcm_fmt(audiohd_state_t *, int, uint_t);
static int audiohd_ad1988_set_gain(audiohd_state_t *, int, int, int);
static int audiohd_ad1988_set_port(audiohd_state_t *, int, int);
static int audiohd_ad1988_mute_outputs(audiohd_state_t *, boolean_t);
static int audiohd_ad1988_set_monitor_gain(audiohd_state_t *, int);
static void audiohd_ad1988_max_gain(audiohd_state_t *, uint_t *,
    uint_t *, uint_t *);

/* ops for AD1988 */
static struct audiohd_codec_ops audiohd_ad1988_ops = {
	audiohd_ad1988_init_codec,		/* ac_init_codec */
	audiohd_ad1988_set_pcm_fmt,		/* ac_set_pcm_fmt */
	audiohd_ad1988_set_gain,		/* ac_set_out_gain */
	audiohd_ad1988_set_port,		/* ac_set_port */
	audiohd_ad1988_mute_outputs,		/* ac_mute_outputs */
	audiohd_ad1988_set_monitor_gain,	/* ac_set_monitor_gain */
	audiohd_ad1988_max_gain			/* ac_get_max_gain */
};

/* anchor for soft state structures */
static void *audiohd_statep;

/* driver name */
static char *audiohd_name = AUDIOHD_NAME;

static uint_t audiohd_mixer_srs[] = {
	AUDIOHD_SAMPR5510, AUDIOHD_SAMPR48000, 0
};

static uint_t audiohd_comp_srs[] = {
	AUDIOHD_SAMPR48000,
	0
};

static am_ad_sample_rates_t audiohd_mixer_sample_rates = {
	MIXER_SRS_FLAG_SR_LIMITS,
	audiohd_mixer_srs
};

static am_ad_sample_rates_t audiohd_comp_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audiohd_comp_srs
};

static uint_t audiohd_channels[] = {
	AUDIO_CHANNELS_STEREO,
	0
};

static am_ad_cap_comb_t audiohd_combinations[] = {
	{ AUDIO_PRECISION_16, AUDIO_ENCODING_LINEAR },
	{ 0 }
};

static ddi_device_acc_attr_t hda_dev_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* STREAMS driver id and limit value struct */
static struct module_info audiohd_modinfo = {
	AUDIOHD_IDNUM,
	AUDIOHD_NAME,
	AUDIOHD_MINPACKET,
	AUDIOHD_MAXPACKET,
	AUDIOHD_HIWATER,
	AUDIOHD_LOWATER,
};

/* STREAMS queue processing procedures structures for read queue */
static struct qinit audiohd_rqueue = {
	audio_sup_rput,
	audio_sup_rsvc,
	audio_sup_open,
	audio_sup_close,
	NULL,
	&audiohd_modinfo,
	NULL,
};

/* STREAMS queue processing procedures structures for write queue */
static struct qinit audiohd_wqueue = {
	audio_sup_wput,
	audio_sup_wsvc,
	NULL,
	NULL,
	NULL,
	&audiohd_modinfo,
	NULL
};

/* STREAMS entity declaration structure */
static struct streamtab audiohd_streamtab = {
	&audiohd_rqueue,
	&audiohd_wqueue,
	NULL,
	NULL,
};

/* Entry points structure */
static struct cb_ops audiohd_cb_ops = {
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
	&audiohd_streamtab,		/* cb_str */
	D_NEW | D_MP | D_64BIT,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

/* Device operations structure */
static struct dev_ops audiohd_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	audiohd_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	audiohd_attach,		/* devo_attach */
	audiohd_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&audiohd_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL			/* devo_power */
};

/* Linkage structure for loadable drivers */
static struct modldrv audiohd_modldrv = {
	&mod_driverops,		/* drv_modops */
	AUDIOHD_MOD_NAME,	/* drv_linkinfo */
	&audiohd_dev_ops,		/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage audiohd_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&audiohd_modldrv,	/* ml_linkage */
	NULL				/* NULL */
};


/*
 * Audio driver ops vector for mixer
 */
static am_ad_entry_t audiohd_entry = {
	NULL,				/* ad_setup() */
	NULL,				/* ad_teardown() */
	audiohd_ad_set_config,		/* ad_set_config() */
	audiohd_ad_set_format,		/* ad_set_format() */
	audiohd_ad_start_play,		/* ad_start_play() */
	audiohd_ad_pause_play,		/* ad_pause_play() */
	audiohd_ad_stop_play,		/* ad_stop_play() */
	audiohd_ad_start_record,	/* ad_start_record() */
	audiohd_ad_stop_record,		/* ad_stop_record() */
	NULL,				/* ad_ioctl() */
	NULL				/* ad_iocdata() */
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&audiohd_statep,
	    sizeof (audiohd_state_t), 1)) != 0) {
		return (error);
	}

	if ((error = mod_install(&audiohd_modlinkage)) != 0) {
		ddi_soft_state_fini(&audiohd_statep);
	}

	return (error);

}	/* _init() */


int
_fini(void)
{
	int error;

	if ((error = mod_remove(&audiohd_modlinkage)) != 0) {
		return (error);
	}

	ddi_soft_state_fini(&audiohd_statep);

	return (0);

}	/* _fini() */


int
_info(struct modinfo *modinfop)
{
	int error;

	error = mod_info(&audiohd_modlinkage, modinfop);

	return (error);

}	/* _info() */


int
audiohd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	audiohd_state_t	*statep;
	int		instance;
	int		error;

	ATRACE("in audiohd_getinfo()", dip);
	error = DDI_FAILURE;
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = audio_sup_devt_to_instance((dev_t)arg);
		if ((statep = ddi_get_soft_state(audiohd_statep,
		    instance)) != NULL) {
			*result = statep->hda_dip;
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

}	/* audiohd_getinfo() */

/*
 * audiohd_attach()
 *
 * Arguments:
 * 	dev_info_t  *dip    Pointer to the device's dev_info struct
 *	ddi_attach_cmd_t cmd    Attach command
 *
 * Returns:
 *	DDI_SUCCESS		The driver was initialized properly
 *	DDI_FAILURE		The driver couldn't be initialized properly
 */
int
audiohd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audio_sup_reg_data_t		data;
	audiohd_state_t		*statep;
	int			instance;

	instance = ddi_get_instance(dip);
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		ATRACE("audiohd_attach() DDI_RESUME", NULL);
		statep = ddi_get_soft_state(audiohd_statep, instance);
		ASSERT(statep != NULL);
		return (audiohd_resume(statep));

	default:
		return (DDI_FAILURE);
	}

	/* High-level interrupt isn't supported by this driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audiohd_attach() unsupported high level interrupt",
		    audiohd_name, instance);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(audiohd_statep, instance) != DDI_SUCCESS) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audiohd_attach() softstate alloc failed",
		    audiohd_name, instance);
		return (DDI_FAILURE);
	}

	if ((statep = ddi_get_soft_state(audiohd_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audiohd_attach() no softstate",
		    audiohd_name, instance);
		goto err_attach_exit1;
	}

	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;
	if ((statep->hda_ahandle = audio_sup_register(dip, &data)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audiohd_attach() audio_sup_register() failed",
		    audiohd_name, instance);
		goto err_attach_exit2;
	}

	/* save private state */
	audio_sup_set_private(statep->hda_ahandle, statep);

	/* interrupt cookie and initialize mutex */
	if (audiohd_init_state(statep, dip) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() audiohd_init_state failed");
		goto err_attach_exit3;
	}

	/* Set PCI command register to enable bus master and memeory I/O */
	if (audiohd_init_pci(statep, &hda_dev_accattr) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() couldn't init pci regs");
		goto err_attach_exit4;
	}

	if (audiohd_init_controller(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() couldn't init controller");
		goto err_attach_exit5;
	}

	if (audiohd_create_codec(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() couldn't create codec");
		goto err_attach_exit6;
	}

	AUDIOHD_CODEC_MAX_GAIN(statep, &statep->hda_pgain_max,
	    &statep->hda_rgain_max, &statep->hda_mgain_max);

	if (audiohd_init_codec(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() couldn't init codec");
		goto err_attach_exit7;
	}

	/*
	 * This is a workaround. ALC880 doesn't support 8k sample rate,
	 * but solaris requires hardware to be set to 8K by default. This
	 * checking is performed in am_attach(). To overcome this flaw,
	 * we have to set default sample to 48K before calling am_attach().
	 * After we fix bug 6363625 in near future, we will change this
	 * and set sample rate to 8K by default.
	 */
	statep->hda_info_defaults.play.sample_rate = audiohd_comp_srs[0];
	statep->hda_info_defaults.record.sample_rate = audiohd_comp_srs[0];

	if (am_attach(statep->hda_ahandle, cmd, &statep->hda_ad_info) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!attach() am_attach() failed");
		goto err_attach_exit7;
	}

	/* set up kernel statistics */
	if ((statep->hda_ksp = kstat_create(AUDIOHD_NAME, instance,
	    AUDIOHD_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->hda_ksp);
	}

	/* disable interrupts and clear interrupt status */
	audiohd_disable_intr(statep);

	/* set up the interrupt handler */
	if (ddi_add_intr(dip, 0, &statep->hda_intr_cookie,
	    (ddi_idevice_cookie_t *)NULL, audiohd_intr, (caddr_t)statep) !=
	    DDI_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!attach() bad interrupt specification ");
		goto err_attach_exit8;
	}
	ddi_report_dev(dip);

	/* enable interrupt */
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL,
	    AUDIOHD_INTCTL_BIT_GIE | AUDIOHD_INTCTL_BIT_SIE);

	return (DDI_SUCCESS);

err_attach_exit8:
	if (statep->hda_ksp)
		kstat_delete(statep->hda_ksp);
	(void) am_detach(statep->hda_ahandle, DDI_DETACH);

err_attach_exit7:
	audiohd_destroy_codec(statep);

err_attach_exit6:
	audiohd_fini_controller(statep);

err_attach_exit5:
	audiohd_fini_pci(statep);

err_attach_exit4:
	mutex_destroy(&statep->hda_mutex);
	cv_destroy(&statep->hda_cv);

err_attach_exit3:
	(void) audio_sup_unregister(statep->hda_ahandle);

err_attach_exit2:
err_attach_exit1:
	ddi_soft_state_free(audiohd_statep, instance);

	return (DDI_FAILURE);

}	/* audiohd_attach() */

/*
 * audiohd_detach()
 * Arguments:
 *	dev_info_t		*dip	Pointer to the device's dev_info struct
 *	ddi_detach_cmd_t	cmd	Detach command
 *
 * Returns:
 *	DDI_SUCCESS		The driver was detached
 *	DDI_FAILURE		The driver couldn't be detached
 */
int
audiohd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audiohd_state_t		*statep;
	int			instance;

	instance = ddi_get_instance(dip);

	if ((statep = ddi_get_soft_state(audiohd_statep, instance)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (audiohd_suspend(statep));

	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&statep->hda_mutex);
	audiohd_stop_dma(statep);
	audiohd_disable_intr(statep);
	mutex_exit(&statep->hda_mutex);
	ddi_remove_intr(dip, 0, statep->hda_intr_cookie);
	if (statep->hda_ksp)
		kstat_delete(statep->hda_ksp);
	(void) am_detach(statep->hda_ahandle, DDI_DETACH);
	audiohd_destroy_codec(statep);
	audiohd_fini_controller(statep);
	audiohd_fini_pci(statep);
	mutex_destroy(&statep->hda_mutex);
	cv_destroy(&statep->hda_cv);
	(void) audio_sup_unregister(statep->hda_ahandle);
	ddi_soft_state_free(audiohd_statep, instance);

	return (DDI_SUCCESS);

}	/* audiohd_detach() */

static int
audiohd_resume(audiohd_state_t *statep)
{
	mutex_enter(&statep->hda_mutex);
	statep->suspended = B_FALSE;
	/* Restore the hda state */
	if (audiohd_reinit_hda(statep) == AUDIO_FAILURE) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_resume() hda reinit failed");
		mutex_exit(&statep->hda_mutex);
		return (DDI_SUCCESS);
	}
	/* Enable interrupt */
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL,
	    AUDIOHD_INTCTL_BIT_GIE | AUDIOHD_INTCTL_BIT_SIE);
	mutex_exit(&statep->hda_mutex);

	/* Resume playing and recording */
	if (audio_sup_restore_state(statep->hda_ahandle,
	    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_resume() audio restore failed");
		audiohd_disable_intr(statep);
		audiohd_stop_dma(statep);
	}

	mutex_enter(&statep->hda_mutex);
	cv_broadcast(&statep->hda_cv); /* wake up entry points */
	mutex_exit(&statep->hda_mutex);

	return (DDI_SUCCESS);
}	/* audiohd_resume() */

static int
audiohd_suspend(audiohd_state_t *statep)
{
	mutex_enter(&statep->hda_mutex);
	statep->suspended = B_TRUE;
	/* wait for current operations to complete */
	while (statep->hda_busy_cnt != 0)
		cv_wait(&statep->hda_cv, &statep->hda_mutex);
	if (audio_sup_save_state(statep->hda_ahandle,
	    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_suspend() audio save failed");
		statep->suspended = B_FALSE;
		cv_broadcast(&statep->hda_cv);
		mutex_exit(&statep->hda_mutex);
		return (DDI_FAILURE);
	}
	/* Disable h/w */
	audiohd_disable_intr(statep);
	audiohd_stop_dma(statep);
	mutex_exit(&statep->hda_mutex);

	return (DDI_SUCCESS);
}	/* audiohd_suspend() */


/*
 * audiohd_intr()
 *
 * Description
 *
 *
 * Arguments:
 *	caddr_t     arg Pointer to the interrupting device's state
 *	            structure
 *
 * Returns:
 *	DDI_INTR_CLAIMED    Interrupt claimed and processed
 *	DDI_INTR_UNCLAIMED  Interrupt not claimed, and thus ignored
 */
static uint_t
audiohd_intr(caddr_t arg)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	status;
	uint32_t	regbase;
	uint8_t		sdstatus;
	int	i;

	mutex_enter(&statep->hda_mutex);
	if (statep->suspended) {
		mutex_exit(&statep->hda_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	status = AUDIOHD_REG_GET32(AUDIOHD_REG_INTSTS);
	if (status == 0) {
		mutex_exit(&statep->hda_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* stream intr */
	for (i = 0; i < statep->hda_streams_nums; i++) {
		if ((status & (1<<i)) == 0)
			continue;

		regbase = AUDIOHD_REG_SD_BASE + AUDIOHD_REG_SD_LEN * i;
		sdstatus = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_STS);

		/* clear intrs */
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS, sdstatus);

		if ((sdstatus & AUDIOHDR_SD_STS_DESE) != 0) {
			/*
			 * fatal error. Hardware will clear run bit. So,
			 * we need to shutdown the stream
			 */
			audio_sup_log(statep->hda_ahandle, CE_WARN,
			    "!audiohd_intr() fatal error, shutdown "
			    "stream %d", i);

			if (i == statep->hda_input_streams) {
				/* playback */
				mutex_exit(&statep->hda_mutex);
				am_play_shutdown(statep->hda_ahandle, NULL);
				mutex_enter(&statep->hda_mutex);
				statep->hda_flags &= ~(AUDIOHD_PLAY_EMPTY |
				    AUDIOHD_PLAY_STARTED);
				continue;
			} else if (i == 0) { /* recording */
				statep->hda_flags &= ~(AUDIOHD_RECORD_STARTED);
				continue;
			}
		}

		/* Buffer Complete Intr */
		if (sdstatus & AUDIOHDR_SD_STS_BCIS)
			if (i < statep->hda_input_streams) {
				if (statep->hda_flags & AUDIOHD_RECORD_STARTED)
					audiohd_get_rbuf(statep);
			} else if (statep->hda_flags & AUDIOHD_PLAY_STARTED)
				audiohd_refill_pbuf(statep);
	}

	/* update the kernel interrupt statistics */
	if (statep->hda_ksp) {
		((kstat_intr_t *)
		    (statep->hda_ksp->ks_data))->intrs[KSTAT_INTR_HARD]++;
	}

	mutex_exit(&statep->hda_mutex);
	return (DDI_INTR_CLAIMED);

}	/* audiohd_intr() */

/*
 * audiohd_ad_start_play()
 *
 * Description:
 *	This routine starts the first output stream of hardware
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number for multi-stream Codecs
 *
 * Returns:
 *	AUDIO_SUCCESS   Playing started/restarted
 *	AUDIO_FAILURE   Play not started/restarted, no audio to play
 */
static int
audiohd_ad_start_play(audiohdl_t ahandle, int stream)
{
	audiohd_state_t	*statep;
	uint64_t	sbd_phys_addr;
	uint8_t		cTmp;
	uint_t	regbase;
	int		rc = AUDIO_SUCCESS;

	ATRACE_32("audiohd_ad_start_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);

	mutex_enter(&statep->hda_mutex);
	if (statep->hda_flags & AUDIOHD_PLAY_STARTED)
		goto done;

	regbase = statep->hda_play_regbase;
	if (statep->hda_flags & AUDIOHD_PLAY_PAUSED) {
		cTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
		statep->hda_flags |= AUDIOHD_PLAY_STARTED;
		statep->hda_flags &= ~AUDIOHD_PLAY_PAUSED;
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
		    cTmp | AUDIOHDR_SD_CTL_SRUN);
		goto done;
	}

	if (audiohd_reset_stream(statep, statep->hda_input_streams)
	    != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_play() failed to reset play stream");
		rc = AUDIO_FAILURE;
		goto done;
	}

	statep->hda_flags |= AUDIOHD_PLAY_STARTED;

	if (audiohd_fill_pbuf(statep) != AUDIO_SUCCESS) {
		mutex_exit(&statep->hda_mutex);
		am_play_shutdown(statep->hda_ahandle, NULL);
		audiohd_set_idle(statep);
		return (AUDIO_FAILURE);
	}

	sbd_phys_addr = statep->hda_dma_play_bd.ad_paddr;
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_BDLPL,
	    (uint32_t)sbd_phys_addr);
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_BDLPU,
	    (uint32_t)(sbd_phys_addr >> 32));
	AUDIOHD_REG_SET16(regbase + AUDIOHD_SDREG_OFFSET_LVI,
	    AUDIOHD_BDLE_NUMS - 1);
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_CBL,
	    statep->hda_pbuf_size * AUDIOHD_BDLE_NUMS);

	AUDIOHD_REG_SET16(regbase + AUDIOHD_SDREG_OFFSET_FORMAT,
	    statep->hda_play_format);
	AUDIOHD_CODEC_SET_PCM_FORMAT(statep, AUDIO_PLAY,
	    statep->hda_play_format);

	/* clear status */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS,
	    AUDIOHDR_SD_STS_BCIS | AUDIOHDR_SD_STS_FIFOE |
	    AUDIOHDR_SD_STS_DESE);

	/* set playback stream tag */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL + 2,
	    (statep->hda_play_stag) << 4);

	/* Enable interrupt and start DMA */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);

done:
	mutex_exit(&statep->hda_mutex);
	audiohd_set_idle(statep);
	return (rc);

}	/* audiohd_ad_start_play() */


/*
 * audiohd_ad_set_config()
 */
static int
audiohd_ad_set_config(audiohdl_t ahandle, int stream, int command,
    int dir, int arg1, int arg2)
{
	audiohd_state_t	*statep;
	int 	rc = AUDIO_SUCCESS;

	ATRACE_32("audiohd_ad_set_config() stream", stream);
	ATRACE_32("audiohd_ad_set_config() command", command);
	ATRACE_32("audiohd_ad_set_config() dir", dir);
	ATRACE_32("audiohd_ad_set_config() arg1", arg1);
	ATRACE_32("audiohd_ad_set_config() arg2", arg2);

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);

	mutex_enter(&statep->hda_mutex);

	switch (command) {
	case AM_SET_GAIN:
		/*
		 * Set the gain for a channel. The audio mixer calculates the
		 * impact, if any, of balance on gain.
		 *
		 * 	AUDIO_MIN_GAIN <= gain <= AUDIO_MAX_GAIN
		 *
		 * 	arg1 --> gain
		 * 	arg2 --> channel #, 0 == left, 1 == right
		 */
		rc = audiohd_set_gain(statep, dir, arg1, arg2);
		break;

	case AM_SET_PORT:
		/*
		 * Enable/disable the input or output ports. The audio mixer
		 * enforces exclusiveness of in ports, as well as which ports
		 * are modifiable. We just turn on the ports that match the
		 * bits.
		 *
		 * 	arg1 --> port bit pattern
		 * 	arg2 --> not used
		 */
		rc = audiohd_set_port(statep, dir, arg1);
		break;

	case AM_SET_MONITOR_GAIN:
		/*
		 * Set the loopback monitor gain.
		 *
		 * 	AUDIO_MIN_GAIN <= gain <= AUDIO_MAX_GAIN
		 *
		 * 	dir ---> N/A
		 *	arg1 --> gain
		 * 	arg2 --> not used
		 */
		rc = audiohd_set_monitor_gain(statep, arg1);
		break;

	case AM_OUTPUT_MUTE:
		/*
		 * Mute or enable the output.
		 *
		 * 	dir ---> N/A
		 * 	arg1 --> ~0 == mute, 0 == enable
		 * 	arg2 --> not used
		 */
		audiohd_mute_outputs(statep, arg1);
		break;

	case AM_MIC_BOOST:
		break;

	default:
		/*
		 * We let default catch commands we don't support, as well
		 * as bad commands.
		 *
		 *
		 * AM_SET_GAIN_BAL
		 * AM_SET_MONO_MIC
		 * AM_BASS_BOOST
		 * AM_MID_BOOST
		 * AM_TREBLE_BOOST
		 * AM_LOUDNESS
		 */
		rc = AUDIO_FAILURE;
		ATRACE_32("audiohd_ad_set_config() unsupported command",
		    command);
		break;
	}

	mutex_exit(&statep->hda_mutex);
	audiohd_set_idle(statep);

	return (rc);

}	/* audiohd_ad_set_config */

/*
 * audiohd_ad_set_format()
 *
 * Description
 *	currently, only 48k sample rate, 16-bit precision,
 *	2-channel format is supported.
 */
/*ARGSUSED*/
static int
audiohd_ad_set_format(audiohdl_t ahandle, int stream, int dir,
    int sample_rate, int channels, int precision, int encoding)
{
	audiohd_state_t	*statep;

	/*
	 * Currently, force to 48k, 16bits, 2-channel
	 */
	if ((sample_rate != AUDIOHD_SAMPR48000) ||
	    (channels != AUDIO_CHANNELS_STEREO) ||
	    (precision != AUDIO_PRECISION_16) ||
	    (encoding != AUDIO_ENCODING_LINEAR))
		return (AUDIO_FAILURE);

	/*
	 * we will support other format later
	 */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);
	mutex_enter(&statep->hda_mutex);

	if (dir == AUDIO_PLAY) {
		statep->hda_psample_rate = sample_rate;
		statep->hda_pchannels = channels;
		statep->hda_pprecision = precision;
		statep->hda_play_format = AUDIOHD_FMT_PCMOUT;
	} else {
		ASSERT(dir == AUDIO_RECORD);
		statep->hda_csample_rate = sample_rate;
		statep->hda_cchannels = channels;
		statep->hda_cprecision = precision;
		statep->hda_record_format = AUDIOHD_FMT_PCMIN;
	}

	mutex_exit(&statep->hda_mutex);
	return (AUDIO_SUCCESS);

}	/* audiohd_ad_set_format() */


/*
 * audiohd_ad_pause_play()
 */
/*ARGSUSED*/
static void
audiohd_ad_pause_play(audiohdl_t ahandle, int stream)
{
	audiohd_state_t	*statep;
	uint32_t	regbase;
	uint8_t		cTmp;

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);

	mutex_enter(&statep->hda_mutex);
	regbase = statep->hda_play_regbase;
	cTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
	cTmp &= ~AUDIOHDR_SD_CTL_SRUN;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, cTmp);
	statep->hda_flags &= ~AUDIOHD_PLAY_STARTED;
	statep->hda_flags |= AUDIOHD_PLAY_PAUSED;
	mutex_exit(&statep->hda_mutex);

	audiohd_set_idle(statep);
}	/* audiohd_ad_pause_play() */

/*
 * audiohd_ad_stop_play()
 */
/*ARGSUSED*/
static void
audiohd_ad_stop_play(audiohdl_t ahandle, int stream)
{
	audiohd_state_t	*statep;
	uint32_t	regbase;

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);

	mutex_enter(&statep->hda_mutex);
	regbase = statep->hda_play_regbase;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, 0);
	statep->hda_flags &=
	    ~(AUDIOHD_PLAY_EMPTY | AUDIOHD_PLAY_STARTED);
	mutex_exit(&statep->hda_mutex);

	audiohd_set_idle(statep);
}	/* audiohd_ad_stop_play() */

/*
 * audiohd_ad_start_record()
 */
/*ARGSUSED*/
static int
audiohd_ad_start_record(audiohdl_t ahandle, int stream)
{
	audiohd_state_t	*statep;
	uint64_t	sbd_phys_addr;
	uint_t		regbase;
	int		rc = AUDIO_SUCCESS;

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);

	mutex_enter(&statep->hda_mutex);
	if (statep->hda_flags & AUDIOHD_RECORD_STARTED)
		goto done;

	if (audiohd_reset_stream(statep, 0) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_record() failed to reset record stream");
		rc = AUDIO_FAILURE;
		goto done;
	}

	audiohd_preset_rbuf(statep);
	statep->hda_rbuf_pos = 0;

	regbase = statep->hda_record_regbase;
	sbd_phys_addr = statep->hda_dma_record_bd.ad_paddr;
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_BDLPL,
	    (uint32_t)sbd_phys_addr);
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_BDLPU,
	    (uint32_t)(sbd_phys_addr >> 32));
	AUDIOHD_REG_SET16(regbase + AUDIOHD_SDREG_OFFSET_FORMAT,
	    statep->hda_record_format);
	AUDIOHD_REG_SET16(regbase + AUDIOHD_SDREG_OFFSET_LVI,
	    AUDIOHD_BDLE_NUMS - 1);
	AUDIOHD_REG_SET32(regbase + AUDIOHD_SDREG_OFFSET_CBL,
	    statep->hda_rbuf_size * AUDIOHD_BDLE_NUMS);

	/* clear status */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS,
	    AUDIOHDR_SD_STS_INTRS);

	AUDIOHD_CODEC_SET_PCM_FORMAT(statep, AUDIO_RECORD,
	    statep->hda_record_format);

	/* set stream tag to 1 */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL + 2,
	    statep->hda_record_stag << 4);
	statep->hda_flags |= AUDIOHD_RECORD_STARTED;

	/* start DMA */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);

done:
	mutex_exit(&statep->hda_mutex);
	audiohd_set_idle(statep);
	return (rc);

}	/* audiohd_ad_start_record() */


/*
 * audiohd_ad_stop_record()
 */
/*ARGSUSED*/
static void
audiohd_ad_stop_record(audiohdl_t ahandle, int stream)
{
	audiohd_state_t	*statep;
	uint32_t	regbase;

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);

	mutex_enter(&statep->hda_mutex);
	regbase = statep->hda_record_regbase;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, 0);
	statep->hda_flags &= ~(AUDIOHD_RECORD_STARTED);
	mutex_exit(&statep->hda_mutex);

	audiohd_set_idle(statep);
}	/* audiohd_ad_stop_play */

/*
 * audiohd_init_state()
 *
 * Description
 *	This routine initailizes soft state of driver instance,
 *	also, it requests an interrupt cookie and initializes
 *	mutex for soft state.
 */
/*ARGSUSED*/
static int
audiohd_init_state(audiohd_state_t *statep, dev_info_t *dip)
{
	int	pints, rints, mode;

	statep->hda_dip = dip;

	/* get the mode from the .conf file */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mixer-mode", 1)) {
		mode = AM_MIXER_MODE;
	} else {
		mode = AM_COMPAT_MODE;
	}

	pints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "play-interrupts", AUDIOHD_INTS);
	if (pints > AUDIOHD_MAX_INTS) {
		audio_sup_log(statep->hda_ahandle, CE_NOTE, "init_state() "
		    "play interrupt rate set too high, %d, resetting to %d",
		    pints, AUDIOHD_INTS);
		pints = AUDIOHD_INTS;
	} else if (pints < AUDIOHD_MIN_INTS) {
		audio_sup_log(statep->hda_ahandle, CE_NOTE, "init_state() "
		    "play interrupt rate set too low, %d, resetting to %d",
		    pints, AUDIOHD_INTS);
		pints = AUDIOHD_INTS;
	}
	rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "record-interrupts", AUDIOHD_INTS);
	if (rints > AUDIOHD_MAX_INTS) {
		audio_sup_log(statep->hda_ahandle, CE_NOTE, "init_state() "
		    "record interrupt rate set too high, %d, resetting to %d",
		    rints, AUDIOHD_INTS);
		rints = AUDIOHD_INTS;
	} else if (rints < AUDIOHD_MIN_INTS) {
		audio_sup_log(statep->hda_ahandle, CE_NOTE, "init_state() "
		    "record interrupt rate set too low, %d, resetting to %d",
		    rints, AUDIOHD_INTS);
		rints = AUDIOHD_INTS;
	}

	statep->hda_pint_freq = pints;
	statep->hda_rint_freq = rints;
	statep->hda_pbuf_size = (AUDIOHD_SAMPLER_MAX * AUDIOHD_MAX_CHANNELS *
	    AUDIOHD_MAX_PRECISION / 8) / pints;
	statep->hda_pbuf_size = (statep->hda_pbuf_size +
	    AUDIOHD_BDLE_BUF_ALIGN - 1) & ~(AUDIOHD_BDLE_BUF_ALIGN - 1);
	statep->hda_rbuf_size = (AUDIOHD_SAMPLER_MAX * AUDIOHD_MAX_CHANNELS *
	    AUDIOHD_MAX_PRECISION / 8) / rints;
	statep->hda_rbuf_size = (statep->hda_rbuf_size +
	    AUDIOHD_BDLE_BUF_ALIGN - 1) & ~(AUDIOHD_BDLE_BUF_ALIGN - 1);

	/* fill in the device default state */
	statep->hda_info_defaults.play.sample_rate = AUDIOHD_DEFAULT_SR;
	statep->hda_info_defaults.play.channels = AUDIOHD_DEFAULT_CH;
	statep->hda_info_defaults.play.precision = AUDIOHD_DEFAULT_PREC;
	statep->hda_info_defaults.play.encoding = AUDIOHD_DEFAULT_ENC;
	statep->hda_info_defaults.play.gain = AUDIOHD_DEFAULT_PGAIN;
	statep->hda_info_defaults.play.buffer_size = AUDIOHD_BSIZE;
	statep->hda_info_defaults.play.balance = AUDIOHD_DEFAULT_BAL;

	statep->hda_info_defaults.record.sample_rate = AUDIOHD_DEFAULT_SR;
	statep->hda_info_defaults.record.channels = AUDIOHD_DEFAULT_CH;
	statep->hda_info_defaults.record.precision = AUDIOHD_DEFAULT_PREC;
	statep->hda_info_defaults.record.encoding = AUDIOHD_DEFAULT_ENC;
	statep->hda_info_defaults.record.gain = AUDIOHD_DEFAULT_RGAIN;
	statep->hda_info_defaults.record.buffer_size = AUDIOHD_BSIZE;
	statep->hda_info_defaults.record.balance = AUDIOHD_DEFAULT_BAL;

	statep->hda_info_defaults.monitor_gain = AUDIOHD_DEFAULT_MONITOR_GAIN;
	statep->hda_info_defaults.output_muted = B_FALSE;
	statep->hda_info_defaults.ref_cnt = B_FALSE;
	statep->hda_info_defaults.hw_features =
	    AUDIO_HWFEATURE_DUPLEX | AUDIO_HWFEATURE_PLAY |
	    AUDIO_HWFEATURE_IN2OUT | AUDIO_HWFEATURE_RECORD;
	statep->hda_info_defaults.sw_features = AUDIO_SWFEATURE_MIXER;

	statep->hda_psample_rate =
	    statep->hda_info_defaults.play.sample_rate;
	statep->hda_pchannels =
	    statep->hda_info_defaults.play.channels;
	statep->hda_pprecision =
	    statep->hda_info_defaults.play.precision;
	statep->hda_play_format = AUDIOHD_FMT_PCMOUT;

	statep->hda_csample_rate =
	    statep->hda_info_defaults.record.sample_rate;
	statep->hda_cchannels =
	    statep->hda_info_defaults.record.channels;
	statep->hda_cprecision =
	    statep->hda_info_defaults.record.precision;
	statep->hda_record_format = AUDIOHD_FMT_PCMIN;


	/*
	 * fill in the ad_info structure
	 */
	statep->hda_ad_info.ad_mode = mode;
	statep->hda_ad_info.ad_int_vers = AM_VERSION;
	statep->hda_ad_info.ad_add_mode = NULL;
	statep->hda_ad_info.ad_codec_type = AM_TRAD_CODEC;
	statep->hda_ad_info.ad_defaults = &statep->hda_info_defaults;
	statep->hda_ad_info.ad_play_comb = audiohd_combinations;
	statep->hda_ad_info.ad_rec_comb = audiohd_combinations;
	statep->hda_ad_info.ad_entry = &audiohd_entry;
	statep->hda_ad_info.ad_dev_info = &statep->hda_dev_info;
	statep->hda_ad_info.ad_diag_flags = AM_DIAG_INTERNAL_LOOP;
	statep->hda_ad_info.ad_diff_flags =
	    AM_DIFF_SR | AM_DIFF_CH | AM_DIFF_PREC | AM_DIFF_ENC;
	statep->hda_ad_info.ad_assist_flags = AM_ASSIST_MIC;
	statep->hda_ad_info.ad_misc_flags = AM_MISC_RP_EXCL | AM_MISC_MONO_DUP;
	statep->hda_ad_info.ad_num_mics = 1;

	/* play capabilities */
	statep->hda_ad_info.ad_play.ad_mixer_srs = audiohd_mixer_sample_rates;
	statep->hda_ad_info.ad_play.ad_compat_srs = audiohd_comp_sample_rates;
	statep->hda_ad_info.ad_play.ad_conv = &am_src2;
	statep->hda_ad_info.ad_play.ad_sr_info = NULL;
	statep->hda_ad_info.ad_play.ad_chs = audiohd_channels;
	statep->hda_ad_info.ad_play.ad_int_rate = pints;
	statep->hda_ad_info.ad_play.ad_max_chs = AUDIOHD_MAX_OUT_CHANNELS;
	statep->hda_ad_info.ad_play.ad_bsize = AUDIOHD_BSIZE;

	/* record capabilities */
	statep->hda_ad_info.ad_record.ad_mixer_srs = audiohd_mixer_sample_rates;
	statep->hda_ad_info.ad_record.ad_compat_srs = audiohd_comp_sample_rates;
	statep->hda_ad_info.ad_record.ad_conv = &am_src2;
	statep->hda_ad_info.ad_record.ad_sr_info = NULL;
	statep->hda_ad_info.ad_record.ad_chs = audiohd_channels;
	statep->hda_ad_info.ad_record.ad_int_rate = rints;
	statep->hda_ad_info.ad_record.ad_max_chs = AUDIOHD_MAX_IN_CHANNELS;
	statep->hda_ad_info.ad_record.ad_bsize = AUDIOHD_BSIZE;

	/* fill in device info strings */
	(void) strcpy(statep->hda_dev_info.name, AUDIOHD_DEV_NAME);
	(void) strcpy(statep->hda_dev_info.config, AUDIOHD_DEV_CONFIG);
	(void) strcpy(statep->hda_dev_info.version, AUDIOHD_DEV_VERSION);

	if (ddi_get_iblock_cookie(dip, (uint_t)0, &statep->hda_intr_cookie) !=
	    DDI_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_state() cannot get iblock cookie");
		return (AUDIO_FAILURE);
	}
	mutex_init(&statep->hda_mutex, NULL,
	    MUTEX_DRIVER, statep->hda_intr_cookie);
	cv_init(&statep->hda_cv, NULL, CV_DRIVER, NULL);

	statep->hda_outputs_muted = B_FALSE;
	statep->hda_rirb_rp = 0;

	return (AUDIO_SUCCESS);

}	/* audiohd_init_state() */

/*
 * audiohd_init_pci()
 *
 * Description
 *	enable driver to access PCI configure space and memory
 *	I/O space.
 */
static int
audiohd_init_pci(audiohd_state_t *statep, ddi_device_acc_attr_t *acc_attr)
{
	uint16_t	cmdreg;
	uint16_t	vid;
	uint8_t		cTmp;
	dev_info_t	*dip = statep->hda_dip;
	audiohdl_t	ahandle = statep->hda_ahandle;

	if (!statep->suspended) {
		if (pci_config_setup(dip, &statep->hda_pci_handle)
		    == DDI_FAILURE) {
			audio_sup_log(ahandle, CE_WARN,
			    "!map_regs() pci config mapping failed");
			goto err_init_pci_exit1;
		}

		if (ddi_regs_map_setup(dip, 1, &statep->hda_reg_base, 0,
		    AUDIOHD_MEMIO_LEN, acc_attr, &statep->hda_reg_handle) !=
		    DDI_SUCCESS) {
			audio_sup_log(ahandle, CE_WARN,
			    "!map_regs() memory I/O mapping failed");
			goto err_init_pci_exit2;
		}
	}

	/*
	 * HD audio control uses memory I/O only, enable it here.
	 */
	cmdreg = pci_config_get16(statep->hda_pci_handle, PCI_CONF_COMM);
	pci_config_put16(statep->hda_pci_handle, PCI_CONF_COMM,
	    cmdreg | PCI_COMM_MAE | PCI_COMM_ME);

	vid = pci_config_get16(statep->hda_pci_handle, PCI_CONF_VENID);
	switch (vid) {

	case AUDIOHD_VID_INTEL:
		/*
		 * Currently, Intel (G)MCH and ICHx chipsets support PCI
		 * Express QoS. It implemenets two VCs(virtual channels)
		 * and allows OS software to map 8 traffic classes to the
		 * two VCs. Some BIOSes initialize HD audio hardware to
		 * use TC7 (traffic class 7) and to map TC7 to VC1 as Intel
		 * recommended. However, solaris doesn't support PCI express
		 * QoS yet. As a result, this driver can not work for those
		 * hardware without touching PCI express control registers.
		 * Here, we set TCSEL to 0 so as to use TC0/VC0 (VC0 is
		 * always enabled and TC0 is always mapped to VC0) for all
		 * Intel HD audio controllers.
		 */
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_INTEL_PCI_TCSEL);
		pci_config_put8(statep->hda_pci_handle,
		    AUDIOHD_INTEL_PCI_TCSEL, (cTmp & 0xf8));
		break;

	case AUDIOHD_VID_ATI:
		/*
		 * Refer to ATI SB450 datesheet. We set snoop for SB450
		 * like hardware.
		 */
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_ATI_PCI_MISC2);
		pci_config_put8(statep->hda_pci_handle, AUDIOHD_ATI_PCI_MISC2,
		    (cTmp & 0xf8) | AUDIOHD_ATI_MISC2_SNOOP);
		break;

	default:
		break;
	}

	return (AUDIO_SUCCESS);

err_init_pci_exit2:
	pci_config_teardown(&statep->hda_pci_handle);

err_init_pci_exit1:
	return (AUDIO_FAILURE);

}	/* audiohd_init_pci() */


/*
 * audiohd_fini_pci()
 *
 * Description
 *	Release mapping for PCI configure space.
 */
static void
audiohd_fini_pci(audiohd_state_t *statep)
{
	if (statep->hda_reg_handle != NULL) {
		ddi_regs_map_free(&statep->hda_reg_handle);
		statep->hda_reg_handle = NULL;
	}

	if (statep->hda_pci_handle != NULL) {
		pci_config_teardown(&statep->hda_pci_handle);
		statep->hda_pci_handle = NULL;
	}

}	/* audiohd_fini_pci() */

/*
 * audiohd_stop_dma()
 *
 * Description
 *	Stop all DMA behaviors of controllers, for command I/O
 *	and each audio stream.
 */
static void
audiohd_stop_dma(audiohd_state_t *statep)
{
	int	i;
	uint_t	base;
	uint8_t	bTmp;

	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBCTL, 0);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, 0);

	base = AUDIOHD_REG_SD_BASE;
	for (i = 0; i < statep->hda_streams_nums; i++) {
		bTmp = AUDIOHD_REG_GET8(base + AUDIOHD_SDREG_OFFSET_CTL);

		/* for input/output stream, it is the same */
		bTmp &= ~AUDIOHDR_RIRBCTL_DMARUN;

		AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_CTL, bTmp);
		base += AUDIOHD_REG_SD_LEN;
	}

	/* wait 40us for stream DMA to stop */
	drv_usecwait(40);

}	/* audiohd_stop_dma() */

/*
 * audiohd_reset_controller()
 *
 * Description:
 *	This routine is just used to reset controller and
 *	CODEC as well by HW reset bit in global control
 *	register of HD controller.
 */
static int
audiohd_reset_controller(audiohd_state_t *statep)
{
	int		i;
	uint8_t	gctl;

	/* reset controller */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL, 0);  /* entering reset state */
	for (i = 0; i < 60; i++) {
		drv_usecwait(30);
		gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL) & AUDIOHDR_GCTL_CRST;
		if (!gctl)
			break;
	}

	if (gctl) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!reset_controller() failed to enter reset state");
		return (AUDIO_FAILURE);
	}

	/* how long should we wait for reset ? */
	drv_usecwait(300);

	/* exit reset state */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL, AUDIOHDR_GCTL_CRST);

	for (i = 0; i < 60; i++) {
		drv_usecwait(30);
		gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL) & AUDIOHDR_GCTL_CRST;
		if (gctl)
			break;
	}

	if (!gctl) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!reset_controller() failed to exit reset state");
		return (AUDIO_FAILURE);
	}

	/* HD spec requires to wait 250us at least. we use 300us */
	drv_usecwait(300);

	/* enable unsolicited response */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL,
	    AUDIOHDR_GCTL_CRST |  AUDIOHDR_GCTL_URESPE);

	return (AUDIO_SUCCESS);

}	/* audiohd_reset_controller() */

/*
 * audiohd_alloc_dma_mem()
 *
 * Description:
 *	This is an utility routine. It is used to allocate DMA
 *	memory.
 */
static int
audiohd_alloc_dma_mem(audiohd_state_t *statep, audiohd_dma_t *pdma,
    size_t memsize, ddi_dma_attr_t *dma_attr_p, uint_t dma_flags)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	dev_info_t		*dip = statep->hda_dip;
	audiohdl_t		ahandle = statep->hda_ahandle;

	if (ddi_dma_alloc_handle(dip, dma_attr_p, DDI_DMA_SLEEP,
	    (caddr_t)0, &pdma->ad_dmahdl) != DDI_SUCCESS) {
		audio_sup_log(ahandle, CE_WARN,
		    "!map_regs() ddi_dma_alloc_hanlde failed");
		goto error_alloc_dma_exit1;
	}

	if (ddi_dma_mem_alloc(pdma->ad_dmahdl, memsize, &hda_dev_accattr,
	    dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    DDI_DMA_SLEEP, NULL, (caddr_t *)&pdma->ad_vaddr,
	    &pdma->ad_real_sz, &pdma->ad_acchdl) != DDI_SUCCESS) {
		audio_sup_log(ahandle, CE_WARN,
		    "!map_regs() ddi_dma_mem_alloc failed");
		goto error_alloc_dma_exit2;
	}

	if (ddi_dma_addr_bind_handle(pdma->ad_dmahdl, NULL,
	    (caddr_t)pdma->ad_vaddr, pdma->ad_real_sz, dma_flags,
	    DDI_DMA_SLEEP, NULL, &cookie, &count) != DDI_DMA_MAPPED) {
		audio_sup_log(ahandle, CE_WARN,
		    "!map_regs() ddi_dma_addr_bind_handle failed");
		goto error_alloc_dma_exit3;
	}

	/*
	 * there some bugs in the DDI framework and it is possible to
	 * get multiple cookies
	 */
	if (count != 1) {
		(void) ddi_dma_unbind_handle(pdma->ad_dmahdl);
		audio_sup_log(ahandle, CE_WARN,
		    "!map_regs() addr_bind_handle failed, cookies > 1");
		goto error_alloc_dma_exit3;
	}
	pdma->ad_paddr = (uint64_t)(cookie.dmac_laddress);
	pdma->ad_req_sz = memsize;

	return (AUDIO_SUCCESS);

error_alloc_dma_exit3:
	ddi_dma_mem_free(&pdma->ad_acchdl);

error_alloc_dma_exit2:
	ddi_dma_free_handle(&pdma->ad_dmahdl);

error_alloc_dma_exit1:
	return (AUDIO_FAILURE);

}	/* audiohd_alloc_dma_mem() */

/*
 * audiohd_release_dma_mem()
 *
 * Description:
 *	Release DMA memory.
 */

static void
audiohd_release_dma_mem(audiohd_dma_t *pdma)
{
	if (pdma->ad_dmahdl != NULL) {
		(void) ddi_dma_unbind_handle(pdma->ad_dmahdl);
		pdma->ad_dmahdl = NULL;
	}

	if (pdma->ad_acchdl != NULL) {
		ddi_dma_mem_free(&pdma->ad_acchdl);
		pdma->ad_acchdl = NULL;
	}

	if (pdma->ad_dmahdl != NULL) {
		ddi_dma_free_handle(&pdma->ad_dmahdl);
		pdma->ad_dmahdl = NULL;
	}

}	/* audiohd_release_dma_mem() */

/*
 * audiohd_reinit_hda()
 *
 * Description:
 *	This routine is used to re-initialize HD controller and codec.
 */
static int
audiohd_reinit_hda(audiohd_state_t *statep)
{
	uint64_t	addr;

	/* set PCI configure space in case it's not restored OK */
	(void) audiohd_init_pci(statep, &hda_dev_accattr);

	/* reset controller */
	if (audiohd_reset_controller(statep) != AUDIO_SUCCESS)
		return (AUDIO_FAILURE);
	AUDIOHD_REG_SET32(AUDIOHD_REG_SYNC, 0); /* needn't sync stream */

	/* Initialize controller RIRB */
	addr = statep->hda_dma_rirb.ad_paddr;
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET16(AUDIOHD_REG_RIRBWP, AUDIOHDR_RIRBWP_RESET);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSIZE, AUDIOHDR_RIRBSZ_256);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN);

	/* Initialize controller CORB */
	addr = statep->hda_dma_corb.ad_paddr;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, AUDIOHDR_CORBRP_RESET);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBSIZE, AUDIOHDR_CORBSZ_256);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, 0);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, 0);
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBCTL, AUDIOHDR_CORBCTL_DMARUN);

	return (audiohd_init_codec(statep));	/* Initialize codec */
}	/* audiohd_reinit_hda() */

/*
 * audiohd_init_controller()
 *
 * Description:
 *	This routine is used to initialize HD controller. It
 *	allocates DMA memory for CORB/RIRB, buffer descriptor
 *	list and cylic data buffer for both play and record
 *	stream.
 */
static int
audiohd_init_controller(audiohd_state_t *statep)
{
	uint64_t	addr;
	uint16_t	gcap;
	int		retval;

	ddi_dma_attr_t	dma_attr = {
		DMA_ATTR_V0,		/* version */
		0,			/* addr_lo */
		0xffffffffffffffffULL,	/* addr_hi */
		0x00000000ffffffffULL,	/* count_max */
		128,			/* 128-byte alignment as HD spec */
		0xfff,			/* burstsize */
		1,			/* minxfer */
		0xffffffff,		/* maxxfer */
		0xffffffff,		/* seg */
		1,			/* sgllen */
		1,			/* granular */
		0			/* flags */
	};

	gcap = AUDIOHD_REG_GET16(AUDIOHD_REG_GCAP);

	/*
	 * If the device doesn't support 64-bit DMA, we should not
	 * allocate DMA memory from 4G above
	 */
	if ((gcap & AUDIOHDR_GCAP_64OK) == 0)
		dma_attr.dma_attr_addr_hi = 0xffffffffUL;

	statep->hda_input_streams = (gcap & AUDIOHDR_GCAP_INSTREAMS) >> 8;
	statep->hda_output_streams = (gcap & AUDIOHDR_GCAP_OUTSTREAMS) >> 12;
	statep->hda_streams_nums = statep->hda_input_streams +
	    statep->hda_output_streams;

	statep->hda_record_stag = 1;
	statep->hda_play_stag = statep->hda_input_streams + 1;
	statep->hda_record_regbase = AUDIOHD_REG_SD_BASE;
	statep->hda_play_regbase = AUDIOHD_REG_SD_BASE + AUDIOHD_REG_SD_LEN *
	    statep->hda_input_streams;

	/* stop all dma before starting to reset controller */
	audiohd_stop_dma(statep);

	if (audiohd_reset_controller(statep) != AUDIO_SUCCESS)
		return (AUDIO_FAILURE);

	/* check codec */
	statep->hda_codec_mask = AUDIOHD_REG_GET16(AUDIOHD_REG_STATESTS);
	if (! statep->hda_codec_mask) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() no codec exists");
		goto err_init_ctlr_exit1;
	}

	/* allocate DMA for CORB */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_corb,
	    AUDIOHD_CDBIO_CORB_LEN, &dma_attr,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING);
	if (retval != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() failed to alloc DMA for CORB");
		goto err_init_ctlr_exit1;
	}

	/* allocate DMA for RIRB */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_rirb,
	    AUDIOHD_CDBIO_RIRB_LEN, &dma_attr,
	    DDI_DMA_READ | DDI_DMA_STREAMING);
	if (retval != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() failed to alloc DMA for RIRB");
		goto err_init_ctlr_exit2;
	}

	/* allocate DMA for data buffer of playback stream */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_play_buf,
	    statep->hda_pbuf_size * AUDIOHD_BDLE_NUMS, &dma_attr,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING);
	if (retval != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() failed to alloc DMA for playback buf");
		goto err_init_ctlr_exit3;
	}

	/* allocate DMA for data buffer of recording stream */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_record_buf,
	    statep->hda_rbuf_size * AUDIOHD_BDLE_NUMS, &dma_attr,
	    DDI_DMA_READ | DDI_DMA_STREAMING);
	if (retval != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() failed to alloc DMA for recording buf");
		goto err_init_ctlr_exit4;
	}

	/* allocate DMA for buffer descriptor list of playback stream */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_play_bd,
	    sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS, &dma_attr,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING);
	if (retval != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() failed to alloc DMA for playback BDL");
		goto err_init_ctlr_exit5;
	}

	/* allocate DMA for buffer descriptor list of recording stream */
	retval = audiohd_alloc_dma_mem(statep, &statep->hda_dma_record_bd,
	    sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS, &dma_attr,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING);
	if (retval != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!init_controller() failed to alloc DMA for record BDL");
		goto err_init_ctlr_exit6;
	}

	AUDIOHD_REG_SET32(AUDIOHD_REG_SYNC, 0); /* needn't sync stream */

	/* Initialize RIRB */
	addr = statep->hda_dma_rirb.ad_paddr;
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_RIRBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET16(AUDIOHD_REG_RIRBWP, AUDIOHDR_RIRBWP_RESET);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSIZE, AUDIOHDR_RIRBSZ_256);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN);

	/* initialize CORB */
	addr = statep->hda_dma_corb.ad_paddr;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, AUDIOHDR_CORBRP_RESET);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBLBASE, (uint32_t)addr);
	AUDIOHD_REG_SET32(AUDIOHD_REG_CORBUBASE,
	    (uint32_t)(addr >> 32));
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBSIZE, AUDIOHDR_CORBSZ_256);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, 0);
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, 0);
	AUDIOHD_REG_SET8(AUDIOHD_REG_CORBCTL, AUDIOHDR_CORBCTL_DMARUN);

	return (AUDIO_SUCCESS);

err_init_ctlr_exit6:
	audiohd_release_dma_mem(&(statep->hda_dma_play_bd));

err_init_ctlr_exit5:
	audiohd_release_dma_mem(&(statep->hda_dma_record_buf));

err_init_ctlr_exit4:
	audiohd_release_dma_mem(&(statep->hda_dma_play_buf));

err_init_ctlr_exit3:
	audiohd_release_dma_mem(&(statep->hda_dma_rirb));

err_init_ctlr_exit2:
	audiohd_release_dma_mem(&(statep->hda_dma_corb));

err_init_ctlr_exit1:
	return (AUDIO_FAILURE);

}	/* audiohd_init_controller() */

/*
 * audiohd_fini_controller()
 *
 * Description:
 *	Releases DMA memory allocated in audiohd_init_controller()
 */
static void
audiohd_fini_controller(audiohd_state_t *statep)
{
	audiohd_stop_dma(statep);
	audiohd_release_dma_mem(&statep->hda_dma_rirb);
	audiohd_release_dma_mem(&statep->hda_dma_corb);
	audiohd_release_dma_mem(&statep->hda_dma_play_buf);
	audiohd_release_dma_mem(&statep->hda_dma_record_buf);
	audiohd_release_dma_mem(&statep->hda_dma_record_bd);
	audiohd_release_dma_mem(&statep->hda_dma_play_bd);

}	/* audiohd_fini_controller() */

/*
 * audiohd_create_codec()
 *
 * Description:
 *	Searching for supported CODEC. If find, allocate memory
 *	to hold codec structure.
 */
static int
audiohd_create_codec(audiohd_state_t *statep)
{
	audiohd_hda_codec_t	*codec;
	uint32_t	mask, type;
	uint32_t	nid, nums;
	uint32_t	i, j;
	boolean_t	found = B_FALSE;

	mask = statep->hda_codec_mask;
	ASSERT(mask != 0);

	codec = (audiohd_hda_codec_t *)kmem_zalloc(
	    sizeof (audiohd_hda_codec_t), KM_SLEEP);

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if ((mask & (1 << i)) == 0)
			continue;

		codec->hc_addr = i;
		codec->hc_vid = audioha_codec_verb_get(statep, i,
		    AUDIOHDC_NODE_ROOT, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_VENDOR_ID);
		codec->hc_revid = audioha_codec_verb_get(statep, i,
		    AUDIOHDC_NODE_ROOT, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_REV_ID);

		switch (codec->hc_vid) {

		case AUDIOHD_VID_ALC260:
		case AUDIOHD_VID_ALC262:
		case AUDIOHD_VID_ALC880:
		case AUDIOHD_VID_ALC882:
		case AUDIOHD_VID_ALC883:
		case AUDIOHD_VID_ALC885:
		case AUDIOHD_VID_ALC888:
			codec->hc_ops = &audiohd_alc880_ops;
			found = B_TRUE;
			break;

		case AUDIOHD_VID_STAC9200:
		case AUDIOHD_VID_STAC9200D:
			codec->hc_ops = &audiohd_stac9200_ops;
			found = B_TRUE;
			break;

		case AUDIOHD_VID_CXD9872RD:
		case AUDIOHD_VID_STAC9872AK:
		case AUDIOHD_VID_CXD9872AKD:
			codec->hc_ops = &audiohd_stac9872_ops;
			found = B_TRUE;
			break;

		case AUDIOHD_VID_AD1986A:
			codec->hc_ops = &audiohd_ad1986_ops;
			found = B_TRUE;
			break;

		case AUDIOHD_VID_AD1988A:
		case AUDIOHD_VID_AD1988B:
			codec->hc_ops = &audiohd_ad1988_ops;
			found = B_TRUE;
			break;

		case AUDIOHD_CODEC_FAILURE:
			ATRACE_32("failed to get VID of codec", NULL);
			break;

		default:
			audio_sup_log(statep->hda_ahandle, CE_WARN,
			    "!unsupported HD codec: vid=0x%08x, rev=0x%08x",
			    codec->hc_vid, codec->hc_revid);
			break;
		}

		if (! found)
			continue;

		nums = audioha_codec_verb_get(statep, i, AUDIOHDC_NODE_ROOT,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_NODE_COUNT);
		nid = (nums >> 16) & 0x000000ff;
		nums = nums & 0x000000ff;

		for (j = 0; j < nums; j++, nid++) {
			type = audioha_codec_verb_get(statep, i, nid,
			    AUDIOHDC_VERB_GET_PARAM,
			    AUDIOHDC_PAR_FUNCTION_TYPE);
			switch (type) {
			case AUDIOHDC_AUDIO_FUNC_GROUP:
				codec->hc_afg_id = nid;
				break;
			default:
				break;
			}
		}

		/* subsystem id is attached to funtion group */
		codec->hc_sid = audioha_codec_verb_get(statep, i,
		    codec->hc_afg_id, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_SUBSYS_ID);

		audio_sup_log(statep->hda_ahandle, CE_NOTE,
		    "!codec info: vid=0x%08x, sid=0x%08x, rev=0x%08x",
		    codec->hc_vid, codec->hc_sid, codec->hc_revid);

		statep->hda_codec = codec;

		return (AUDIO_SUCCESS);
	}

	kmem_free(codec, sizeof (audiohd_hda_codec_t));
	return (AUDIO_FAILURE);

}	/* audiohd_create_codec() */

/*
 * audiohd_destroy_codec()
 *
 * Description:
 *	destory codec structure, and release its memory
 */
static void
audiohd_destroy_codec(audiohd_state_t *statep)
{
	kmem_free(statep->hda_codec, sizeof (audiohd_hda_codec_t));
	statep->hda_codec = NULL;

}	/* audiohd_destroy_codec() */

/*
 * audiohd_init_codec()
 */
static int
audiohd_init_codec(audiohd_state_t *statep)
{
	int		ret;

	ret = AUDIOHD_CODEC_INIT_CODEC(statep);

	return (ret);
}

/*
 * audiohd_disable_intr()
 *
 * Description:
 *	Disable all possible interrupts.
 */
static void
audiohd_disable_intr(audiohd_state_t *statep)
{
	int		i;
	uint32_t	base;

	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL, 0);
	base = AUDIOHD_REG_SD_BASE;
	for (i = 0; i < statep->hda_streams_nums; i++) {
		AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_STS,
		    AUDIOHDR_SD_STS_INTRS);
		base += AUDIOHD_REG_SD_LEN;
	}
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTSTS, (uint32_t)(-1));

}	/* audiohd_disable_intr() */


/*
 * audiohd_reset_stream()
 *
 * Description:
 *	Reset specified stream
 */
static int
audiohd_reset_stream(audiohd_state_t *statep, int stream)
{
	uint32_t	base;
	uint8_t		bTmp;
	int		i;

	base = AUDIOHD_REG_SD_BASE + AUDIOHD_REG_SD_LEN * stream;
	bTmp = AUDIOHD_REG_GET8(base + AUDIOHD_SDREG_OFFSET_CTL);

	/* stop stream */
	bTmp &= ~AUDIOHD_REG_RIRBSIZE;
	AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	/* wait 40us for stream to stop as HD spec */
	drv_usecwait(40);

	/* reset stream */
	bTmp |= AUDIOHDR_SD_CTL_SRST;
	AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	for (i = 0; i < 50; i++) {
		drv_usecwait(10);
		bTmp = AUDIOHD_REG_GET8(base + AUDIOHD_SDREG_OFFSET_CTL);
		bTmp &= AUDIOHDR_SD_CTL_SRST;
		if (bTmp)
			break;
	}

	if (!bTmp) {
		audio_sup_log(NULL, CE_WARN, "!Failed to reset stream %d",
		    stream);
		return (AUDIO_FAILURE);
	}

	/* Need any RESET# assertion time, 300us ??? */
	drv_usecwait(50);

	/* exit reset stream */
	bTmp &= ~AUDIOHDR_SD_CTL_SRST;
	AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	for (i = 0; i < 50; i++) {
		drv_usecwait(10);
		bTmp = AUDIOHD_REG_GET8(base + AUDIOHD_SDREG_OFFSET_CTL);
		bTmp &= AUDIOHDR_SD_CTL_SRST;
		if (!bTmp)
			break;
	}

	if (bTmp) {
		audio_sup_log(NULL, CE_WARN, "!Failed to exit reset state for"
		    " stream %d, bTmp=0x%02x", stream, bTmp);
		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_reset_stream() */

/*
 * audiohd_preset_rbuf()
 *
 * Description:
 *	Fill out entries of stream descriptor list for
 *	recording.
 */
static void
audiohd_preset_rbuf(audiohd_state_t *statep)
{
	sd_bdle_t	*entry;
	uint64_t	 buf_phys_addr;
	int		i;

	entry = (sd_bdle_t *)(statep->hda_dma_record_bd.ad_vaddr);
	buf_phys_addr = statep->hda_dma_record_buf.ad_paddr;

	for (i = 0; i < AUDIOHD_BDLE_NUMS; i++) {
		entry->sbde_addr = buf_phys_addr;
		entry->sbde_len = statep->hda_rbuf_size;
		entry->sbde_ioc = 1;
		buf_phys_addr += statep->hda_rbuf_size;
		entry++;
	}

	(void) ddi_dma_sync(statep->hda_dma_record_bd.ad_dmahdl, 0,
	    sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS, DDI_DMA_SYNC_FORDEV);

}	/* audiohd_preset_rbuf() */

/*
 * audiohd_fill_pbuf()
 *
 * Description:
 *	Get pending audio data, and fill out entries of stream	descriptor
 *	list for playback. This routine returns	AUDIO_FAILURE if it doesn't
 *	fill any audio samples to DMA buffers. This can happen:
 *		1) when mixer cannot provide any samples;
 *		2) playback has been stopped during fetching samples;
 */
static int
audiohd_fill_pbuf(audiohd_state_t *statep)
{
	uint64_t	 buf_phys_addr;
	sd_bdle_t	*entry;
	char		*buf;
	int		samples;
	int		rs;
	int		i;

	entry = (sd_bdle_t *)(statep->hda_dma_play_bd.ad_vaddr);
	buf = (char *)(statep->hda_dma_play_buf.ad_vaddr);
	buf_phys_addr = statep->hda_dma_play_buf.ad_paddr;

	/* assume that 2-channel, 16-bit */
	samples = statep->hda_pbuf_size * AUDIOHD_BDLE_NUMS / 2;

	mutex_exit(&statep->hda_mutex);
	rs = am_get_audio(statep->hda_ahandle, buf, AUDIO_NO_CHANNEL, samples);
	mutex_enter(&statep->hda_mutex);

	if (rs == 0) {
		/*
		 * If system is busy so that no sample is available, an
		 * AUDIO_PLAY_EMPTY flag is set. And we will try to get
		 * sample to refill play buffer when we receive an interrupt.
		 * Only if we still cannot get sample then, we could stop
		 * the playback engine.
		 */
		statep->hda_flags |= AUDIOHD_PLAY_EMPTY;
	} else if (rs < 0) {
		/*
		 * Unknown error occurs, we have to stop playback.
		 */
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!fill_pbuf() failed to get play sample");
		statep->hda_flags &= ~AUDIOHD_PLAY_STARTED;
		return (AUDIO_FAILURE);
	}

	/*
	 * Because users can quickly start and stop audio streams, it
	 * is possible that playback already stopped before we re-grab
	 * mutex. In this case, we dispose fetched samples, and return
	 * AUDIO_FAILURE as we didn't get samples.
	 */
	if ((statep->hda_flags & AUDIOHD_PLAY_STARTED) == 0) {
		return (AUDIO_FAILURE);
	}

	for (i = 0; i < AUDIOHD_BDLE_NUMS; i++) {
		entry->sbde_addr = buf_phys_addr;
		entry->sbde_len = statep->hda_pbuf_size;
		entry->sbde_ioc = 1;
		buf_phys_addr += statep->hda_pbuf_size;
		entry++;
	}

	(void) ddi_dma_sync(statep->hda_dma_play_bd.ad_dmahdl, 0,
	    sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS, DDI_DMA_SYNC_FORDEV);

	if (rs == samples)
		statep->hda_pbuf_pos = 0;
	else
		statep->hda_pbuf_pos = (rs << 1);

	return (AUDIO_SUCCESS);

}	/* audiohd_fill_pbuf() */

/*
 * audiohd_refill_pbuf()
 *
 * Description:
 *	Called by interrupt handler.
 */
static void
audiohd_refill_pbuf(audiohd_state_t *statep)
{
	int		rs;
	int		pos;
	char		*buf;
	uint32_t	len;
	uint32_t	regbase = statep->hda_play_regbase;

	buf = (char *)(statep->hda_dma_play_buf.ad_vaddr);
	buf += statep->hda_pbuf_pos;
	pos = AUDIOHD_REG_GET32(regbase + AUDIOHD_SDREG_OFFSET_LPIB);
	pos &= ~0x00000003;

	if (pos > statep->hda_pbuf_pos) {
		len = (pos - statep->hda_pbuf_pos) & ~0x00000003;
	} else {
		len = statep->hda_pbuf_size * AUDIOHD_BDLE_NUMS -
		    statep->hda_pbuf_pos;
		len &= ~0x00000003;
	}
	mutex_exit(&statep->hda_mutex);
	rs = am_get_audio(statep->hda_ahandle, buf, AUDIO_NO_CHANNEL, len / 2);
	mutex_enter(&statep->hda_mutex);

	if (rs > 0) {
		statep->hda_flags &= ~AUDIOHD_PLAY_EMPTY;
		statep->hda_pbuf_pos += (rs << 1);
		if (statep->hda_pbuf_pos >= statep->hda_pbuf_size *
		    AUDIOHD_BDLE_NUMS)
			statep->hda_pbuf_pos = 0;
		return;
	}

	/* We didn't get any sample */
	if ((statep->hda_flags & AUDIOHD_PLAY_EMPTY) == 0)
		statep->hda_flags |= AUDIOHD_PLAY_EMPTY;
	else {
		/* once again, we don't get samples, stop it */
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, 0);
		statep->hda_flags &= ~(AUDIOHD_PLAY_EMPTY |
		    AUDIOHD_PLAY_STARTED);

		/* shutdown the mixer */
		mutex_exit(&statep->hda_mutex);
		am_play_shutdown(statep->hda_ahandle, NULL);
		mutex_enter(&statep->hda_mutex);
	}

}	/* audiohd_refill_pbuf() */


/*
 * audiohd_get_rbuf()
 *
 * Description:
 *	Called by interrupt handler.
 */
static void
audiohd_get_rbuf(audiohd_state_t *statep)
{
	uint32_t	regbase;
	uint32_t	len;
	char		*buf;
	int		pos;

	regbase = statep->hda_record_regbase;
	pos = AUDIOHD_REG_GET32(regbase + AUDIOHD_SDREG_OFFSET_LPIB);
	pos &= ~0x00000003;
	buf = (char *)statep->hda_dma_record_buf.ad_vaddr;
	buf += statep->hda_rbuf_pos;

	if (pos > statep->hda_rbuf_pos) {
		len = (pos - statep->hda_rbuf_pos) & ~0x00000003;
		mutex_exit(&statep->hda_mutex);
		am_send_audio(statep->hda_ahandle, buf, AUDIO_NO_CHANNEL,
		    len / 2);
		mutex_enter(&statep->hda_mutex);
		statep->hda_rbuf_pos += len;
		if (statep->hda_rbuf_pos >= statep->hda_rbuf_size *
		    AUDIOHD_BDLE_NUMS)
			statep->hda_rbuf_pos = 0;
	} else {
		len = statep->hda_rbuf_size * AUDIOHD_BDLE_NUMS -
		    statep->hda_rbuf_pos;
		mutex_exit(&statep->hda_mutex);
		am_send_audio(statep->hda_ahandle, buf, AUDIO_NO_CHANNEL,
		    len / 2);
		mutex_enter(&statep->hda_mutex);
		statep->hda_rbuf_pos = 0;
	}

}	/* audiohd_get_rbuf() */

/*
 * auidohd_set_gain()
 *
 * Description:
 */
static int
audiohd_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
{
	int rc;

	if (gain > AUDIO_MAX_GAIN) {
		gain = AUDIO_MAX_GAIN;
	} else if (gain < AUDIO_MIN_GAIN) {
		gain = AUDIO_MIN_GAIN;
	}

	/*
	 * SADA uses 255 as the max volume, but HD spec uses at most 7bits
	 * to represent volum. Here, adjust vlaue of gain
	 */
	if (dir == AUDIO_PLAY)
		gain = gain * statep->hda_pgain_max / AUDIO_MAX_GAIN;
	else
		gain = gain * statep->hda_rgain_max / AUDIO_MAX_GAIN;

	rc = AUDIOHD_CODEC_SET_GAIN(statep, dir, gain, channel);
	return (rc);

}	/* audiohd_set_gain() */

/*
 * audiohd_set_port()
 *
 * Description:
 *
 */
static int
audiohd_set_port(audiohd_state_t *statep, int dir, int port)
{
	int rc;

	rc = AUDIOHD_CODEC_SET_PORT(statep, dir, port);

	return (rc);

}	/* audiohd_set_port() */

/*
 * audiohd_mute_outputs()
 */
static void
audiohd_mute_outputs(audiohd_state_t *statep, boolean_t mute)
{
	(void) AUDIOHD_CODEC_MUTE_OUTPUTS(statep, mute);

}	/* audiohd_mute_outputs() */

/*
 * audiohd_set_monitor_gain()
 *
 * Description:
 *
 */
static int
audiohd_set_monitor_gain(audiohd_state_t *statep, int gain)
{
	int	ret;

	ASSERT(statep);

	if (gain > AUDIO_MAX_GAIN) {
		gain = AUDIO_MAX_GAIN;
	} else if (gain < AUDIO_MIN_GAIN) {
		gain = AUDIO_MIN_GAIN;
	}
	gain = gain * statep->hda_mgain_max / AUDIO_MAX_GAIN;

	/*
	 * Allow to set monitor gain even if no input is selected
	 */
	statep->hda_monitor_gain = gain;

	if (statep->hda_in_ports == AUDIO_NONE)
		ret = AUDIO_SUCCESS;
	else
		ret = AUDIOHD_CODEC_SET_MON_GAIN(statep, gain);

	return (ret);

}	/* audiohd_set_monitor_gain() */

/*
 * audiohd_12bit_verb_to_codec()
 *
 * Description:
 *
 */
static int
audiohd_12bit_verb_to_codec(audiohd_state_t *statep, uint8_t caddr, uint8_t nid,
    uint16_t cmd, uint8_t param)
{
	uint32_t	verb;
	uint16_t	wptr;
	uint16_t	rptr;

	ASSERT((cmd & AUDIOHDC_12BIT_VERB_MASK) == 0);

	wptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBWP) & AUDIOHD_CMDIO_ENT_MASK;
	rptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBRP) & AUDIOHD_CMDIO_ENT_MASK;

	wptr++;
	wptr &= AUDIOHD_CMDIO_ENT_MASK;

	/* overflow */
	if (wptr == rptr) {
		return (AUDIO_FAILURE);
	}

	verb = (caddr & 0x0f) << 28;
	verb |= nid << 20;
	verb |= cmd << 8;
	verb |= param;

	*((uint32_t *)(statep->hda_dma_corb.ad_vaddr) + wptr) = verb;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, wptr);

	return (AUDIO_SUCCESS);

}	/* audiohd_12bit_verb_to_codec() */

/*
 * audiohd_4bit_verb_to_codec()
 *
 * Description:
 *
 */
static int
audiohd_4bit_verb_to_codec(audiohd_state_t *statep, uint8_t caddr, uint8_t nid,
    uint32_t cmd, uint16_t param)
{
	uint32_t	verb;
	uint16_t	wptr;
	uint16_t	rptr;

	ASSERT((cmd & AUDIOHDC_4BIT_VERB_MASK) == 0);

	wptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBWP) & AUDIOHD_CMDIO_ENT_MASK;
	rptr = AUDIOHD_REG_GET16(AUDIOHD_REG_CORBRP) & AUDIOHD_CMDIO_ENT_MASK;

	wptr++;
	wptr &= AUDIOHD_CMDIO_ENT_MASK;

	/* overflow */
	if (wptr == rptr) {
		return (AUDIO_FAILURE);
	}

	verb = (caddr & 0x0f) << 28;
	verb |= nid << 20;
	verb |= cmd << 16;
	verb |= param;

	*((uint32_t *)(statep->hda_dma_corb.ad_vaddr) + wptr) = verb;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBWP, wptr);

	return (AUDIO_SUCCESS);

}	/* audiohd_4bit_verb_to_codec() */

/*
 * audiohd_response_from_codec()
 *
 * Description:
 *
 */
static int
audiohd_response_from_codec(audiohd_state_t *statep, uint32_t *resp,
    uint32_t *respex)
{
	uint16_t	wptr;
	uint16_t	rptr;
	uint32_t	*lp;

	wptr = AUDIOHD_REG_GET16(AUDIOHD_REG_RIRBWP) & 0x00ff;
	rptr = statep->hda_rirb_rp;

	if (rptr == wptr) {
		return (AUDIO_FAILURE);
	}

	rptr++;
	rptr &= 0x00ff;

	lp = (uint32_t *)(statep->hda_dma_rirb.ad_vaddr) + (rptr << 1);
	*resp = *(lp);
	*respex = *(lp + 1);

	statep->hda_rirb_rp = rptr;

	return (AUDIO_SUCCESS);

}	/* audiohd_response_from_codec() */


/*
 * audioha_codec_verb_get()
 */
static uint32_t
audioha_codec_verb_get(void *arg, uint8_t caddr, uint8_t nid, uint16_t verb,
    uint8_t param)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	resp;
	uint32_t	respex;
	int		ret;
	int		i;

	ret = audiohd_12bit_verb_to_codec(statep, caddr, nid, verb, param);
	if (ret != AUDIO_SUCCESS) {
		return (uint32_t)(-1);
	}

	for (i = 0; i < 50; i++) {
		drv_usecwait(30);
		ret = audiohd_response_from_codec(statep, &resp, &respex);
		if (((respex & AUDIOHD_BDLE_RIRB_SDI) == caddr) &&
		    ((respex & AUDIOHD_BDLE_RIRB_UNSOLICIT) == 0) &&
		    (ret == AUDIO_SUCCESS))
			break;
	}

	if (ret == AUDIO_SUCCESS) {
		return (resp);
	}

	audio_sup_log(NULL, CE_WARN, "!%s: verb_get() timeout when get "
	    " response from codec: nid=%d, verb=0x%04x, param=0x%04x",
	    audiohd_name, nid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_verb_get() */


/*
 * audioha_codec_4bit_verb_get()
 */
static uint32_t
audioha_codec_4bit_verb_get(void *arg, uint8_t caddr, uint8_t nid, uint16_t
    verb, uint16_t param)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	resp;
	uint32_t	respex;
	int		ret;
	int		i;

	ret = audiohd_4bit_verb_to_codec(statep, caddr, nid, verb, param);
	if (ret != AUDIO_SUCCESS) {
		return (uint32_t)(-1);
	}

	for (i = 0; i < 50; i++) {
		drv_usecwait(30);
		ret = audiohd_response_from_codec(statep, &resp, &respex);
		if (((respex & AUDIOHD_BDLE_RIRB_SDI) == caddr) &&
		    ((respex & AUDIOHD_BDLE_RIRB_UNSOLICIT) == 0) &&
		    (ret == AUDIO_SUCCESS))
			break;
	}

	if (ret == AUDIO_SUCCESS) {
		return (resp);
	}

	audio_sup_log(NULL, CE_WARN, "!%s: 4bit_verb_get() timeout when get "
	    " response from codec: nid=%d, verb=0x%04x, param=0x%04x",
	    audiohd_name, nid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_4bit_verb_get() */

/*
 * audiohd_alc880_init_codec()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 */
static int
audiohd_alc880_init_codec(audiohd_state_t *statep)
{
	uint_t		val;
	uint_t		inputs, outputs;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	outputs = 0;
	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_ALC880:
		AUDIOHD_NODE_INIT_DAC(statep, caddr, 4);
		AUDIOHD_NODE_INIT_MIXER(statep, caddr, 0x0E, 0);
		AUDIOHD_NODE_INIT_DAC(statep, caddr, 3);
		AUDIOHD_NODE_INIT_MIXER(statep, caddr, 0x0D, 0);
		/*FALLTHRU*/

	case AUDIOHD_VID_ALC882:
	case AUDIOHD_VID_ALC883:
	case AUDIOHD_VID_ALC885:
	case AUDIOHD_VID_ALC888:
		/* AUDIO_AUX2_OUT */
		outputs |= AUDIO_AUX2_OUT;
		AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, 0x16);
		if (!statep->hda_outputs_muted)
			AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, 0x16);
		/*FALLTHRU*/

	case AUDIOHD_VID_ALC262:
		AUDIOHD_NODE_INIT_DAC(statep, caddr, 2);
		AUDIOHD_NODE_INIT_MIXER(statep, caddr, 0x0C, 0);

		/* AUDIO_HEADPHONE */
		AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, 0x14);
		(void) audioha_codec_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x14), AUDIOHDC_VERB_SET_CONN_SEL, 0);

		/* AUDIO_AUX1_OUT */
		AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, 0x15);
		(void) audioha_codec_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_CONN_SEL, 0);

		/* AUDIO_LINE_OUT */
		AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, 0x1B);
		(void) audioha_codec_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1B), AUDIOHDC_VERB_SET_CONN_SEL, 0);

		if (!statep->hda_outputs_muted) {
			AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, 0x14);
			AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, 0x15);
			AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, 0x1B);
		}

		outputs |= AUDIO_HEADPHONE | AUDIO_LINE_OUT | AUDIO_AUX1_OUT;
		break;

	case AUDIOHD_VID_ALC260:
		AUDIOHD_NODE_INIT_DAC(statep, caddr, 2);
		AUDIOHD_NODE_INIT_MIXER(statep, caddr, 0x8, 0);
		AUDIOHD_NODE_INIT_MIXER(statep, caddr, 0x9, 0);

		if (!statep->hda_outputs_muted) {
			AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, 0x10);
			AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, 0x0f);
		}

		/* AUDIO_HEADPHONE */
		AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, 0x10);

		/* AUDIO_LINE_OUT */
		AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, 0x0F);

		outputs = AUDIO_HEADPHONE | AUDIO_LINE_OUT;
		break;

	default:
		return (AUDIO_FAILURE);
	}

	statep->hda_info_defaults.play.port = outputs;
	statep->hda_info_defaults.play.avail_ports = outputs;
	statep->hda_info_defaults.play.mod_ports = outputs;
	statep->hda_out_ports = 0;

	/*
	 * Up to now, we initialized playback paths. we begin
	 * to initialize record paths.
	 */
	inputs = AUDIO_MICROPHONE | AUDIO_LINE_IN | AUDIO_CD;
	statep->hda_info_defaults.record.port = AUDIO_MICROPHONE;
	statep->hda_info_defaults.record.avail_ports = inputs;
	statep->hda_info_defaults.record.mod_ports = inputs;
	statep->hda_in_ports = 0;

	val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_GAIN_MAX;
	val |= (1 << AUDIOHDC_AMP_SET_INDEX_OFFSET);
	if (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) {
		/*
		 * enable gain for monitor path, from node 0x07 to node 0x08,
		 * and 0x09. In the input list of 0x08 & 0x09, 0x0b node has
		 * index 1
		 */
		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_AMP_MUTE, val) ==
		    AUDIOHD_CODEC_FAILURE)
			audio_sup_log(statep->hda_ahandle, CE_WARN,
			    "!alc880_init_codec() failed to set monitor");

		AUDIOHD_NODE_INIT_ADC(statep, caddr, 0x04);
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x12); /* MIC1 */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x13); /* MIC2 */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x14); /* line-in1 */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x16); /* cd-in */
	} else {
		/*
		 * enable gain for monitor path, from node 0x0B to node 0x0C,
		 * In the input list of 0x0c, 0x0b node has index 1
		 */
		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_AMP_MUTE, val) ==
		    AUDIOHD_CODEC_FAILURE)
			audio_sup_log(statep->hda_ahandle, CE_WARN,
			    "!alc880_init_codec() failed to set monitor");

		AUDIOHD_NODE_INIT_ADC(statep, caddr, 0x08);
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x18); /* MIC1 */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x19); /* MIC2 */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x1a); /* line-in1 */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, 0x1c); /* cd-in */
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_init_codec() */

/*
 * audiohd_alc880_set_pcm_fmt()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 */
static int
audiohd_alc880_set_pcm_fmt(audiohd_state_t *statep, int dir, uint_t format)
{
	uint32_t	lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	if (dir == AUDIO_PLAY) {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
	} else {
		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_ALC262:
		case AUDIOHD_VID_ALC880:
		case AUDIOHD_VID_ALC882:
		case AUDIOHD_VID_ALC883:
		case AUDIOHD_VID_ALC885:
		case AUDIOHD_VID_ALC888:
			/*
			 * We choose node 8 as active ADC
			 */
			lTmp = audioha_codec_4bit_verb_get(
			    statep, caddr, AUDIOHDC_NID(0x8),
			    AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
			break;
		case AUDIOHD_VID_ALC260:
			lTmp = audioha_codec_4bit_verb_get(
			    statep, caddr, AUDIOHDC_NID(0x4),
			    AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
			break;
		default:
			break;
		}
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_pcm_fmt() */

/*
 * audiohd_alc880_set_gain()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 */
static int
audiohd_alc880_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
{
	uint32_t	lTmp;
	uint_t		val;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	if (dir == AUDIO_PLAY) {
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_play_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_play_rgain = gain;
		}

		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_ALC880:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0xE), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			/*FALLTHRU*/

		case AUDIOHD_VID_ALC262:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0xD), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			/*FALLTHRU*/

		case AUDIOHD_VID_ALC882:
		case AUDIOHD_VID_ALC883:
		case AUDIOHD_VID_ALC885:
		case AUDIOHD_VID_ALC888:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0xC), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			break;

		case AUDIOHD_VID_ALC260:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			break;
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		val = AUDIOHDC_AMP_SET_INPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_record_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_record_rgain = gain;
		}

		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_ALC262:
		case AUDIOHD_VID_ALC880:
		case AUDIOHD_VID_ALC882:
		case AUDIOHD_VID_ALC883:
		case AUDIOHD_VID_ALC885:
		case AUDIOHD_VID_ALC888:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			break;
		case AUDIOHD_VID_ALC260:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x4), AUDIOHDC_VERB_SET_AMP_MUTE, val);
			break;
		default:
			break;
		}
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_gain() */

/*
 * audiohd_alc880_set_port()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 */
static int
audiohd_alc880_set_port(audiohd_state_t *statep, int dir, int port)
{
	uint_t	val;
	uint_t	tmp_port = 0;
	uint_t	caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	if (dir == AUDIO_PLAY) {
		if (port == AUDIOHD_PORT_UNMUTE)
			port = statep->hda_out_ports;

		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_ALC880:
		case AUDIOHD_VID_ALC882:
		case AUDIOHD_VID_ALC883:
		case AUDIOHD_VID_ALC885:
		case AUDIOHD_VID_ALC888:
			val = AUDIOHDC_AMP_SET_LR_OUTPUT;
			if (port & AUDIO_AUX2_OUT)
				tmp_port |= AUDIO_AUX2_OUT;
			else
				val |= AUDIOHDC_AMP_SET_MUTE;

			if (audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x16), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val) == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);
			/*FALLTHRU*/

		case AUDIOHD_VID_ALC262:
			val = AUDIOHDC_AMP_SET_LR_OUTPUT;
			if (port & AUDIO_HEADPHONE)
				tmp_port |= AUDIO_HEADPHONE;
			else
				val |= AUDIOHDC_AMP_SET_MUTE;
			if (audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x14), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val) == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);

			/*
			 * Munich workstation uses 0x1B of ALC885 as Line-out
			 * pin. so we consider this pin as line-out for all
			 * codec of alc88x series.
			 */
			val = AUDIOHDC_AMP_SET_LR_OUTPUT;
			if (port & AUDIO_LINE_OUT)
				tmp_port |= AUDIO_LINE_OUT;
			else
				val |= AUDIOHDC_AMP_SET_MUTE;
			if (audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x1B), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val) == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);

			val = AUDIOHDC_AMP_SET_LR_OUTPUT;
			if (port & AUDIO_AUX1_OUT)
				tmp_port |= AUDIO_AUX1_OUT;
			else
				val |= AUDIOHDC_AMP_SET_MUTE;

			if (audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val) == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);
			break;

		case AUDIOHD_VID_ALC260:
			val = AUDIOHDC_AMP_SET_LR_OUTPUT;
			if (port & AUDIO_HEADPHONE)
				tmp_port |= AUDIO_HEADPHONE;
			else
				val |= AUDIOHDC_AMP_SET_MUTE;
			if (audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x10), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val) == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);

			val = AUDIOHDC_AMP_SET_LR_OUTPUT;
			if (port & AUDIO_LINE_OUT)
				tmp_port |= AUDIO_LINE_OUT;
			else
				val |= AUDIOHDC_AMP_SET_MUTE;
			if (audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x0F), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val) == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);
			break;

		default:	/* unknown CODEC */
			return (AUDIO_FAILURE);
		}

		statep->hda_out_ports = tmp_port;

		if (tmp_port != port)
			return (AUDIO_FAILURE);

		return (AUDIO_SUCCESS);
	}

	/*
	 * Now, deal with recording
	 */
	ASSERT(dir == AUDIO_RECORD);

	switch (port) {
	case AUDIO_NONE:
		/*
		 * Mute ADC node: node 0x04 for ALC260, 0x08 for others.
		 */
		val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_AMP_SET_MUTE;
		if (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260)
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x4), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		else
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		statep->hda_in_ports = port;
		return (AUDIO_SUCCESS);

	case AUDIO_MICROPHONE:
		tmp_port = 0;	/* MIC1 */
		break;
	case AUDIO_LINE_IN:
		tmp_port = 2;	/* Line-in1 */
		break;
	case AUDIO_CD:
		tmp_port = 4;	/* CD in */
		break;
	default:
		return (AUDIO_FAILURE);
	}

	/* if ADC 0x08 is muted, we resume its gains */
	if (statep->hda_in_ports == AUDIO_NONE) {
		if (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) {
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_AMP_MUTE,
			    (AUDIOHDC_AMP_SET_INPUT | AUDIOHDC_AMP_SET_LEFT |
			    statep->hda_record_lgain));
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_AMP_MUTE,
			    (AUDIOHDC_AMP_SET_INPUT | AUDIOHDC_AMP_SET_RIGHT |
			    statep->hda_record_rgain));
		} else {
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x4), AUDIOHDC_VERB_SET_AMP_MUTE,
			    (AUDIOHDC_AMP_SET_INPUT | AUDIOHDC_AMP_SET_LEFT |
			    statep->hda_record_lgain));
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x4), AUDIOHDC_VERB_SET_AMP_MUTE,
			    (AUDIOHDC_AMP_SET_INPUT | AUDIOHDC_AMP_SET_RIGHT |
			    statep->hda_record_rgain));
		}
	}

	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_ALC260:
		/*
		 * For ALC260, node 4 has multiple inputs,
		 * we need to select the right one among
		 * those inputs
		 */
		(void) audioha_codec_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x4), AUDIOHDC_VERB_SET_CONN_SEL,
		    tmp_port);
		break;

	case AUDIOHD_VID_ALC880:
		/*
		 * For ALC880, node 8 has multiple inputs,
		 * we need to select the right one among
		 * those inputs
		 */
		(void) audioha_codec_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_CONN_SEL,
		    tmp_port);
		break;

	case AUDIOHD_VID_ALC262:
	case AUDIOHD_VID_ALC882:
	case AUDIOHD_VID_ALC883:
	case AUDIOHD_VID_ALC885:
	case AUDIOHD_VID_ALC888:
		/*
		 * For ALC883/885, node 8 has only one input,
		 * which is a mixer with node number 0x23. So,
		 * we mute all inputs except the one selected
		 * by users. Note that all inputs are muted by
		 * default, it is needed to mute the one being
		 * used.
		 */

		if (statep->hda_in_ports != AUDIO_NONE) {
			uint_t		old_index;

			switch (statep->hda_in_ports) {
			case AUDIO_MICROPHONE:
				old_index = 0;	/* MIC1 */
				break;
			case AUDIO_LINE_IN:
				old_index = 2;	/* Line-in1 */
				break;
			case AUDIO_CD:
				old_index = 4;	/* CD in */
				break;
			default:	/* impossible to reach here */
				return (AUDIO_FAILURE);
			}

			/* mute old input port */
			val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_AMP_SET_MUTE;
			val |= (old_index << AUDIOHDC_AMP_SET_INDEX_OFFSET);
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x23), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val);

			if (statep->hda_in_ports == AUDIO_MICROPHONE) {
				/* mute MIC2 as well */
				old_index = 1;
				val = AUDIOHDC_AMP_SET_LR_INPUT;
				val |= AUDIOHDC_AMP_SET_MUTE;
				val |=
				    old_index << AUDIOHDC_AMP_SET_INDEX_OFFSET;
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr, AUDIOHDC_NID(0x23),
				    AUDIOHDC_VERB_SET_AMP_MUTE, val);
			}
		}

		/* unmute new input port */
		val = AUDIOHDC_AMP_SET_LR_INPUT;
		val |= tmp_port << AUDIOHDC_AMP_SET_INDEX_OFFSET;
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x23), AUDIOHDC_VERB_SET_AMP_MUTE, val);

		if (port == AUDIO_MICROPHONE) {
			/*
			 * SADA only exports control for one MIC, so if MIC
			 * is selected, we unmute MIC2 as well
			 */
			tmp_port = 1;
			val = AUDIOHDC_AMP_SET_LR_INPUT;
			val |= tmp_port << AUDIOHDC_AMP_SET_INDEX_OFFSET;
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x23), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val);
		}

		break;

	default:
		/* impossible to reach here */
		break;
	}

	statep->hda_in_ports = port;

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_port() */

/*
 * audiohd_alc880_mute_outputs()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 */
static int
audiohd_alc880_mute_outputs(audiohd_state_t *statep, boolean_t mute)
{
	uint_t	val;
	uint_t	caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	if (statep->hda_outputs_muted == mute)
		return (AUDIO_SUCCESS);

	statep->hda_outputs_muted = mute;
	val = AUDIOHDC_AMP_SET_LR_OUTPUT;
	if (mute) {
		val |= AUDIOHDC_AMP_SET_MUTE;
	}

	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_ALC262:
	case AUDIOHD_VID_ALC880:
	case AUDIOHD_VID_ALC882:
	case AUDIOHD_VID_ALC883:
	case AUDIOHD_VID_ALC885:
	case AUDIOHD_VID_ALC888:
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1b), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x16), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x14), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		break;
	case AUDIOHD_VID_ALC260:
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x10), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x0f), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		break;
	default:
		break;
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_mute_outputs() */

/*
 * audiohd_alc880_set_monitor_gain()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 *
 * Description:
 *	Set the gain for input-to-ouput path
 */
static int
audiohd_alc880_set_monitor_gain(audiohd_state_t *statep, int gain)
{
	uint_t	val;
	uint_t	index;
	uint_t	caddr = statep->hda_codec->hc_addr;
	uint_t	mix_nid;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	switch (statep->hda_in_ports) {
	case AUDIO_MICROPHONE:
		index = 0;
		break;
	case AUDIO_LINE_IN:
		index = 2;
		break;
	case AUDIO_CD:
		index = 4;
		break;
	}

	if (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260)
		mix_nid = 0x7;
	else
		mix_nid = 0xB;
	val = AUDIOHDC_AMP_SET_LR_INPUT | gain;
	val |= (index << AUDIOHDC_AMP_SET_INDEX_OFFSET);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    mix_nid, AUDIOHDC_VERB_SET_AMP_MUTE, val);

	/* set MIC1 and MIC2 if MIC is requested */
	if (statep->hda_in_ports == AUDIO_MICROPHONE) {
		index = 1;
		val = AUDIOHDC_AMP_SET_LR_INPUT | gain;
		val |= (index << AUDIOHDC_AMP_SET_INDEX_OFFSET);
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    mix_nid, AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}
	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_monitor_gain() */



/*
 * audiohd_alc880_max_gain()
 *
 * common routines for Realtek ALC260, ALC262, ALC88x
 *
 * Description:
 *	Get max gains for packplay and recording
 */
static void
audiohd_alc880_max_gain(audiohd_state_t *statep, uint_t *pgain, uint_t
	*rgain, uint_t *mgain)
{
	uint_t	caddr = statep->hda_codec->hc_addr;
	uint_t	nid_p, nid_r, nid_m;
	uint_t	lTmp;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC262) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC880) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC882) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC883) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC885) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC888));

	if (statep->hda_codec->hc_vid == AUDIOHD_VID_ALC260) {
		nid_p = 0x08;
		nid_r = 0x04;
		nid_m = 0x07;
	} else {
		nid_p = 0x0c;
		nid_r = 0x08;
		nid_m = 0x0b;
	}
	lTmp = audioha_codec_verb_get(statep, caddr, nid_p,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*pgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	lTmp = audioha_codec_verb_get(statep, caddr, nid_r,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_IN_CAP);
	*rgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	lTmp = audioha_codec_verb_get(statep, caddr, nid_m,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_IN_CAP);
	*mgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

}	/* audiohd_alc880_max_gain() */


/*
 * audiohd_stac_init_codec()
 */
static int
audiohd_stac_init_codec(audiohd_state_t *statep)
{
	uint_t		inputs, outputs;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200D));

	/* power-up AFG node */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* power-up DAC node */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_DAC(statep, caddr, AUDIOHDC_NID(0x2));

	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x7), AUDIOHDC_VERB_SET_CONN_SEL, 0);

	/* HEADPHONE_OUT */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0x0D));

	/* AUDIO_LINE_OUT */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0x0E));

	outputs = AUDIO_HEADPHONE | AUDIO_LINE_OUT;

	statep->hda_info_defaults.play.port = outputs;
	statep->hda_info_defaults.play.avail_ports = outputs;
	statep->hda_info_defaults.play.mod_ports = outputs;
	statep->hda_out_ports = 0;

	/* set master volume to max */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0B), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_ROUT_MAX);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0B), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_LOUT_MAX);

	/*
	 * Up to now, we initialized playback paths. we begin
	 * to initialize record paths.
	 */
	inputs = AUDIO_MICROPHONE | AUDIO_LINE_IN | AUDIO_CD;
	statep->hda_info_defaults.record.port = AUDIO_MICROPHONE;
	statep->hda_info_defaults.record.avail_ports = inputs;
	statep->hda_info_defaults.record.mod_ports = inputs;
	statep->hda_in_ports = 0;

	/* power-up ADC node */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x3), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_ADC(statep, caddr, AUDIOHDC_NID(0x3));

	/* set MUX volume to max */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_ROUT_MAX);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_LOUT_MAX);

	/* MIC */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x10));
	(void) audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0xC),
	    AUDIOHDC_VERB_SET_CONN_SEL, 0);

	return (AUDIO_SUCCESS);

}	/* audiohd_stac_init_codec() */


/*
 * audiohd_stac9872_init_codec()
 */
static int
audiohd_stac9872_init_codec(audiohd_state_t *statep)
{
	uint_t		inputs, outputs;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872RD) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9872AK) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872AKD));

	/* power-up AFG node */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* power-up DAC_0 */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_DAC(statep, caddr, AUDIOHDC_NID(0x2));

	/* power-up DAC_1 */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x5), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_DAC(statep, caddr, AUDIOHDC_NID(0x5));

	/* set master volume to max */

	/* HP volume */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_LOUT_MAX);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_ROUT_MAX);

	/* Speaker volume */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x5), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_LOUT_MAX);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x5), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_ROUT_MAX);

	/* enable output ports */

	/* HP */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0xA));

	/* Speaker */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0xF));

	outputs = AUDIO_HEADPHONE | AUDIO_LINE_OUT;

	statep->hda_info_defaults.play.port = outputs;
	statep->hda_info_defaults.play.avail_ports = outputs;
	statep->hda_info_defaults.play.mod_ports = outputs;
	statep->hda_out_ports = 0;

	/*
	 * Up to now, we initialized playback paths. we begin
	 * to initialize record paths.
	 */

	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x6), AUDIOHDC_VERB_SET_POWER_STATE, 0); /* CD */

	AUDIOHD_NODE_INIT_ADC(statep, caddr, AUDIOHDC_NID(0x6));

	/* power-up ADC nodes */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_ADC(statep, caddr, AUDIOHDC_NID(0x8));

	/* unmte MUX */
	AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, AUDIOHDC_NID(0x15));

	/* set MUX volume to max */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_ROUT_MAX);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_LOUT_MAX);

	/* unmute CD */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x7), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_INPUT | (0 << AUDIOHDC_AMP_SET_INDEX_OFFSET));

	/* unmute Capture */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_INPUT | (0 << AUDIOHDC_AMP_SET_INDEX_OFFSET));

	/* enable input ports */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0xD));
	/* Ext. Mic1 */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0xE));
	/* CD */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x14));
	/* Int. Mic2 */

	/* Select: 0x0a (HP), 0x0d (Mic1), 0x14* (Mic2), 0x02 (Loopback) */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_CONN_SEL, 2);

	inputs = AUDIO_MICROPHONE | AUDIO_LINE_IN | AUDIO_CODEC_LOOPB_IN;
	statep->hda_info_defaults.record.port = AUDIO_LINE_IN;
	statep->hda_info_defaults.record.avail_ports = inputs;
	statep->hda_info_defaults.record.mod_ports = inputs;
	statep->hda_in_ports = 0;

	return (AUDIO_SUCCESS);

}	/* audiohd_stac9872_init_codec() */


/*
 * audiohd_stac_set_pcm_fmt()
 */
static int
audiohd_stac_set_pcm_fmt(audiohd_state_t *statep, int dir, uint_t format)
{
	uint_t		lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200D) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872RD) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9872AK) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872AKD));

	if (dir == AUDIO_PLAY) {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
	} else {
		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_STAC9200:
		case AUDIOHD_VID_STAC9200D:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x3), AUDIOHDC_VERB_SET_CONVERTER_FMT,
			    format);
			break;

		case AUDIOHD_VID_CXD9872RD:
		case AUDIOHD_VID_STAC9872AK:
		case AUDIOHD_VID_CXD9872AKD:
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_CONVERTER_FMT,
			    format);
			break;
		}
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_stac_set_pcm_fmt() */


/*
 * audiohd_stac_set_gain()
 */
static int
audiohd_stac_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
{
	uint_t		val, lTmp;
	uint_t		nid_p[2], nid_r;
	int		nid_p_num;
	uint_t		caddr = statep->hda_codec->hc_addr;


	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200D) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872RD) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9872AK) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872AKD));

	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_STAC9200:
	case AUDIOHD_VID_STAC9200D:
		nid_p_num = 1;
		nid_p[0] = 0xB;
		nid_r = 0xA;
		break;

	case AUDIOHD_VID_CXD9872RD:
	case AUDIOHD_VID_STAC9872AK:
	case AUDIOHD_VID_CXD9872AKD:
		nid_p_num = 2;
		nid_p[0] = 0x2;
		nid_p[1] = 0x5;
		nid_r = 0x9;
		break;

	default:
		return (AUDIO_FAILURE);
	}

	if (dir == AUDIO_PLAY) {

		int i;
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_play_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_play_rgain = gain;
		}

		for (i = 0; i < nid_p_num; i++) {
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    nid_p[i], AUDIOHDC_VERB_SET_AMP_MUTE, val);
			if (lTmp == AUDIOHD_CODEC_FAILURE)
				return (AUDIO_FAILURE);
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_record_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_record_rgain = gain;
		}

		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    nid_r, AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_stac_set_gain() */

/*
 * audiohd_stac_set_port()
 */
static int
audiohd_stac_set_port(audiohd_state_t *statep, int dir, int port)
{
	uint_t		nid;
	uint_t		tmp_port = 0;
	uint_t		index_port;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200D) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872RD) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9872AK) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872AKD));

	if (dir == AUDIO_PLAY) {
		uint_t	nid_hp = 0;
		uint_t	nid_sp = 0;

		if (port == AUDIOHD_PORT_UNMUTE)
			port = statep->hda_out_ports;

		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_STAC9200:
		case AUDIOHD_VID_STAC9200D:
			nid_hp = 0x0D;
			nid_sp = 0x0E;
			break;

		case AUDIOHD_VID_CXD9872RD:
		case AUDIOHD_VID_STAC9872AK:
		case AUDIOHD_VID_CXD9872AKD:
			nid_hp = 0x0A;
			nid_sp = 0x0F;
			break;

		default:
			break;
		}

		if (port & AUDIO_HEADPHONE) {
			tmp_port |= AUDIO_HEADPHONE;
			AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, nid_hp);
		} else {
			AUDIOHD_NODE_DISABLE_PIN_OUT(statep, caddr, nid_hp);
		}

		if (port & AUDIO_LINE_OUT) {
			tmp_port |= AUDIO_LINE_OUT;
			AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, nid_sp);
		} else {
			AUDIOHD_NODE_DISABLE_PIN_OUT(statep, caddr, nid_sp);
		}

		statep->hda_out_ports = tmp_port;
		if (tmp_port != port)
			return (AUDIO_FAILURE);

		return (AUDIO_SUCCESS);
	}

	ASSERT(dir == AUDIO_RECORD);

	nid = 0;

	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_STAC9200:
	case AUDIOHD_VID_STAC9200D:
		switch (port) {
		case AUDIO_NONE:
			nid = statep->hda_in_ports;
			if (nid != 0) {
				AUDIOHD_NODE_DISABLE_PIN_IN(statep, caddr, nid);
				statep->hda_in_ports = 0;
			}
			return (AUDIO_SUCCESS);

		case AUDIO_MICROPHONE:
			index_port = 0;
			nid = 0x10;
			break;

		case AUDIO_LINE_IN:
			index_port = 1;
			nid = 0x0F;
			break;

		case AUDIO_CD:
			index_port = 4;
			nid = 0x12;
			break;

		default:
			return (AUDIO_FAILURE);
		}
		break;

	case AUDIOHD_VID_CXD9872RD:
	case AUDIOHD_VID_STAC9872AK:
	case AUDIOHD_VID_CXD9872AKD:
		switch (port) {
		case AUDIO_NONE:
			nid = statep->hda_in_ports;
			if (nid != 0) {
				AUDIOHD_NODE_DISABLE_PIN_IN(statep, caddr, nid);
				statep->hda_in_ports = 0;
			}
			return (AUDIO_SUCCESS);

		case AUDIO_MICROPHONE:
			index_port = 1;
			nid = 0x0D;
			break;

		case AUDIO_LINE_IN:
			index_port = 2;
			nid = 0x14;
			break;

		case AUDIO_CODEC_LOOPB_IN:
			index_port = 3;
			nid = 0x02;
			break;

		default:
			return (AUDIO_FAILURE);
		}
		break;

	default:
		break;
	}

	if (nid != statep->hda_in_ports) {
		statep->hda_in_ports = nid;

		/* disable last selected input */
		AUDIOHD_NODE_DISABLE_PIN_IN(statep, caddr,
		    statep->hda_in_ports);

		/* enable currently selected input */
		AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, nid);
		switch (statep->hda_codec->hc_vid) {
		case AUDIOHD_VID_STAC9200:
		case AUDIOHD_VID_STAC9200D:
			(void) audioha_codec_verb_get(statep, caddr,
			    AUDIOHDC_NID(0xC), AUDIOHDC_VERB_SET_CONN_SEL,
			    index_port);
			break;
		case AUDIOHD_VID_CXD9872RD:
		case AUDIOHD_VID_STAC9872AK:
		case AUDIOHD_VID_CXD9872AKD:
			(void) audioha_codec_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_CONN_SEL,
			    index_port);
			break;
		default:
			break;
		}
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_stac_set_port() */

/*
 * audiohd_stac_mute_outputs()
 */
static int
audiohd_stac_mute_outputs(audiohd_state_t *statep, boolean_t mute)
{
	uint_t		caddr = statep->hda_codec->hc_addr;
	uint32_t		lTmp;
	uint_t			nid_p[2];
	int			nid_p_num;
	int			i;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200D) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872RD) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9872AK) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872AKD));

	if (statep->hda_outputs_muted == mute)
		return (AUDIO_SUCCESS);

	statep->hda_outputs_muted = mute;

	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_STAC9200:
	case AUDIOHD_VID_STAC9200D:
		nid_p[0] = 0x0B;
		nid_p_num = 1;
		break;

	case AUDIOHD_VID_CXD9872RD:
	case AUDIOHD_VID_STAC9872AK:
	case AUDIOHD_VID_CXD9872AKD:
		nid_p[0] = 0x02;
		nid_p[1] = 0x05;
		nid_p_num = 2;
		break;

	default:
		break;
	}

	for (i = 0; i < nid_p_num; i++) {
		if (mute) {
			/* mute master volume */
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(nid_p[i]), AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_MUTE | AUDIOHDC_AMP_SET_LR_OUTPUT);
		} else {
			/* resume left volume */
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(nid_p[i]), AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_OUTPUT | AUDIOHDC_AMP_SET_LEFT |
			    statep->hda_play_lgain);

				if (lTmp == AUDIOHD_CODEC_FAILURE)
					return (AUDIO_FAILURE);

			/* resume right volume */
			lTmp = audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(nid_p[i]), AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_OUTPUT | AUDIOHDC_AMP_SET_RIGHT |
			    statep->hda_play_rgain);
		}
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_stac_mute_outputs() */

/*
 * audiohd_stac_set_monitor_gain()
 */
static int
audiohd_stac_set_monitor_gain(audiohd_state_t *statep, int gain)
{
	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9200D) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872RD) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_STAC9872AK) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_CXD9872AKD));

	/*
	 * In STAC9200, there is a critical node (NID=7), which is
	 * a MUX instead of mixer. All output streams and loopback
	 * steams of input-ouput must walk through this node. As a
	 * result, STAC9200(D) cannot perform this task: do playback
	 * while spy the input streams of MIC/Line-in. For simplifying,
	 * we just ignore this request.
	 */
	statep->hda_monitor_gain = gain;

	return (AUDIO_SUCCESS);

}	/* audiohd_stac_set_monitor_gain() */

/*
 * audiohd_stac_max_gain()
 */
static void audiohd_stac_max_gain(audiohd_state_t *statep, uint_t *pgain,
    uint_t *rgain, uint_t *mgain)
{
	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_STAC9200:
	case AUDIOHD_VID_STAC9200D:
		*pgain = 0x1f;
		*rgain = 0x1f;
		*mgain = 0x1f;
		break;

	case AUDIOHD_VID_CXD9872RD:
	case AUDIOHD_VID_STAC9872AK:
	case AUDIOHD_VID_CXD9872AKD:
		*pgain = 0x7f;
		*rgain = 0x0f;
		*mgain = 0x7f;
		break;

	default:
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!stac_max_gain() unknown codec");
		break;
	}
}	/* audiohd_stac_max_gain() */




/*
 * AD1986A HD codec support
 */

/*
 * audiohd_ad1986_init_codec()
 */
static int
audiohd_ad1986_init_codec(audiohd_state_t *statep)
{
	uint_t		inputs, outputs;
	uint32_t	lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT(statep->hda_codec->hc_vid == AUDIOHD_VID_AD1986A);

	/* Power up audio function group */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x01), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* Power up analog mixer power widget */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x26), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* Power up DAC */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x03), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_DAC(statep, caddr, AUDIOHDC_NID(0x03));

	/* set output amp of DAC to 0 dB */
	if (audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x03), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | 0x17) == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* Set HPSEL selector input to analog mixer output */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x0a),
	    AUDIOHDC_VERB_SET_CONN_SEL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* Set LOSEL selector input to analog mixer output */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x0b),
	    AUDIOHDC_VERB_SET_CONN_SEL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* HP_OUT */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0x1a));

	/* LINE_OUT */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0x1b));

	outputs = AUDIO_HEADPHONE | AUDIO_LINE_OUT;

	statep->hda_info_defaults.play.port = outputs;
	statep->hda_info_defaults.play.avail_ports = outputs;
	statep->hda_info_defaults.play.mod_ports = outputs;
	statep->hda_out_ports = 0;

	/* Power up ADC */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x06), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	AUDIOHD_NODE_INIT_ADC(statep, caddr, AUDIOHDC_NID(0x06));

	/* Set record selector input to microphone */
	lTmp = audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_CONN_SEL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/*
	 * Set microphone selector 0x0F to MIC/Front + MIC/Rear mixer 0x27;
	 * (the mixer 0x27 is at index 4 in the selector's connection list)
	 */
	lTmp = audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0F), AUDIOHDC_VERB_SET_CONN_SEL, 4);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* set output amp of microphone selector (0..3) */
	lTmp = audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0F), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | 0x3);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	lTmp = audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x11), AUDIOHDC_VERB_SET_CONN_SEL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* MIC/Front */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x1f));
	/* MIC/Rear */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x1d));

	/* LINE_IN */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x20));

	/* CD_IN */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x22));

	inputs = AUDIO_MICROPHONE | AUDIO_LINE_IN | AUDIO_CD;
	statep->hda_info_defaults.record.port = AUDIO_MICROPHONE;
	statep->hda_info_defaults.record.avail_ports = inputs;
	statep->hda_info_defaults.record.mod_ports = inputs;
	statep->hda_in_ports = 0;

	return (AUDIO_SUCCESS);
}

/*
 * audiohd_ad1986_set_pcm_fmt()
 */
static int
audiohd_ad1986_set_pcm_fmt(audiohd_state_t *statep, int dir, uint_t format)
{
	uint32_t	lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x3), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
	} else {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x6), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1986_set_pcm_fmt() */

/*
 * audiohd_ad1986_set_gain()
 */
static int
audiohd_ad1986_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
{
	uint32_t	lTmp;
	uint_t		val;
	uint_t		caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_play_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_play_rgain = gain;
		}
		/* Set HP_OUT pin amplifier */
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1a), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		/* Set LINE_OUT pin amplifier */
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1b), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	} else {
		ASSERT(dir == AUDIO_RECORD);
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_record_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_record_rgain = gain;
		}
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	}


	return (AUDIO_SUCCESS);

}	/* audiohd_ad1986_set_gain() */

/*
 * audiohd_ad1986_set_port()
 */
static int
audiohd_ad1986_set_port(audiohd_state_t *statep, int dir, int port)
{
	uint_t	val;
	uint_t	tmp_port = 0;
	int	node;
	uint_t	caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {

		if (port == AUDIOHD_PORT_UNMUTE) {
			port = statep->hda_out_ports;
		}

		val = AUDIOHDC_AMP_SET_OUTPUT;
		if (port & AUDIO_HEADPHONE) {
			tmp_port |= AUDIO_HEADPHONE;
		} else { /* mute */
			val |= AUDIOHDC_AMP_SET_MUTE;
		}

		/* HP_OUT */
		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1a), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_LEFT | val | statep->hda_play_lgain)) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1a), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_RIGHT | val | statep->hda_play_rgain)) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		val = AUDIOHDC_AMP_SET_OUTPUT;
		if (port & AUDIO_LINE_OUT) {
			tmp_port |= AUDIO_LINE_OUT;
		} else { /* mute */
			val |= AUDIOHDC_AMP_SET_MUTE;
		}

		/* LINE_OUT */
		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1B), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_LEFT | val | statep->hda_play_lgain)) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1B), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_RIGHT | val | statep->hda_play_rgain)) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		if (tmp_port != port)
			return (AUDIO_FAILURE);
		statep->hda_out_ports = tmp_port;

		return (AUDIO_SUCCESS);
	}

	/*
	 * Now, deal with recording
	 */
	ASSERT(dir == AUDIO_RECORD);

	switch (port) {
	case AUDIO_NONE:
		/* mute record selector node 0x12 */
		val = AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_AMP_SET_MUTE;
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		statep->hda_in_ports = port;
		return (AUDIO_SUCCESS);

	case AUDIO_MICROPHONE:
		tmp_port = 0;	/* MIC1 */
		break;
	case AUDIO_LINE_IN:
		tmp_port = 4;	/* Line-in1 */
		break;
	case AUDIO_CD:
		tmp_port = 1;	/* CD in */
		break;
	default:
		return (AUDIO_FAILURE);
	}

	/* if record is muted, we resume its gains */
	if (statep->hda_in_ports == AUDIO_NONE) {
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_OUTPUT | AUDIOHDC_AMP_SET_LEFT |
		    statep->hda_record_lgain));
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_OUTPUT | AUDIOHDC_AMP_SET_RIGHT |
		    statep->hda_record_rgain));
	}

	/*
	 * For AD1986, node 0x12 has multiple inputs,
	 * we need to select the right one among
	 * those inputs
	 */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_CONN_SEL,
	    tmp_port);

	/*
	 * Select the same recording source as analog mixer input.
	 *
	 * Start by muting all selector widgets that input into the
	 * analog mixer.
	 */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x13), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_AMP_SET_MUTE);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x15), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_AMP_SET_MUTE);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x17), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_AMP_SET_MUTE);

	/* input node for analog mixer */
	switch (port) {
	case AUDIO_MICROPHONE:
		node = AUDIOHDC_NID(0x13);
		break;
	case AUDIO_LINE_IN:
		node = AUDIOHDC_NID(0x17);
		break;
	case AUDIO_CD:
		node = AUDIOHDC_NID(0x15);
		break;
	default:
		node = AUDIOHDC_NULL_NODE;
		break;
	}

	/* Set selector output amplifier (in the analog mixer input path) */
	if (node != AUDIOHDC_NULL_NODE) {
		val = AUDIOHDC_AMP_SET_LR_OUTPUT | statep->hda_monitor_gain;
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(node), AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}

	statep->hda_in_ports = port;

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1986_set_port() */

/*
 * audiohd_ad1986_mute_outputs()
 */
static int
audiohd_ad1986_mute_outputs(audiohd_state_t *statep, boolean_t mute)
{
	uint_t	val;
	uint_t	caddr = statep->hda_codec->hc_addr;

	if (statep->hda_outputs_muted == mute)
		return (AUDIO_SUCCESS);

	statep->hda_outputs_muted = mute;
	val = AUDIOHDC_AMP_SET_OUTPUT;
	if (mute) {
		val |= AUDIOHDC_AMP_SET_MUTE;
	}

	/* HP_OUT */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1a), AUDIOHDC_VERB_SET_AMP_MUTE,
	    (AUDIOHDC_AMP_SET_LEFT | val | statep->hda_play_lgain));
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1a), AUDIOHDC_VERB_SET_AMP_MUTE,
	    (AUDIOHDC_AMP_SET_RIGHT | val | statep->hda_play_rgain));

	/* LINE_OUT */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1b), AUDIOHDC_VERB_SET_AMP_MUTE,
	    (AUDIOHDC_AMP_SET_LEFT | val | statep->hda_play_lgain));
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1b), AUDIOHDC_VERB_SET_AMP_MUTE,
	    (AUDIOHDC_AMP_SET_RIGHT | val | statep->hda_play_rgain));

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1986_mute_outputs() */

/*
 * audiohd_ad1986_set_monitor_gain()
 *
 * Description:
 *	Set the gain for input-to-ouput path
 */
static int
audiohd_ad1986_set_monitor_gain(audiohd_state_t *statep, int gain)
{
	uint_t	val;
	int	node;
	uint_t	caddr = statep->hda_codec->hc_addr;

	/* input node for analog mixer */
	switch (statep->hda_in_ports) {
	case AUDIO_MICROPHONE:
		node = AUDIOHDC_NID(0x13);
		break;
	case AUDIO_LINE_IN:
		node = AUDIOHDC_NID(0x17);
		break;
	case AUDIO_CD:
		node = AUDIOHDC_NID(0x15);
		break;
	default:
		node = AUDIOHDC_NULL_NODE;
		break;
	}

	/* Set selector output amplifier (in the analog mixer input path) */
	if (node != AUDIOHDC_NULL_NODE) {
		val = AUDIOHDC_AMP_SET_LR_OUTPUT | gain;
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(node), AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1986_set_monitor_gain() */

/*
 * audiohd_ad1986_max_gain()
 *
 * Description:
 *	Get max gains for packplay and recording
 */
static void
audiohd_ad1986_max_gain(audiohd_state_t *statep, uint_t *pgain, uint_t
	*rgain, uint_t *mgain)
{
	uint_t	caddr = statep->hda_codec->hc_addr;
	uint_t	lTmp;

	/* get pgain from HPSEL amplifier */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x1a),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*pgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	/* get rgain from record selector */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x12),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*rgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	/* get mgain from cd-in analog mixer input path */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x15),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*mgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

}	/* audiohd_ad1986_max_gain() */


/*
 * AD1988A/AD1988B HD codec support
 */

/*
 * audiohd_ad1988_init_codec()
 */
static int
audiohd_ad1988_init_codec(audiohd_state_t *statep)
{
	uint_t		inputs, outputs;
	uint32_t	lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	ASSERT((statep->hda_codec->hc_vid == AUDIOHD_VID_AD1988A) ||
	    (statep->hda_codec->hc_vid == AUDIOHD_VID_AD1988B));

	/* Power up audio function group */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x01), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/*
	 * Configure the widgets needed for playback
	 */

	/* Power up DAC_0 (NID 3) */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x03), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* DAC_0, set playback input stream */
	AUDIOHD_NODE_INIT_DAC(statep, caddr, AUDIOHDC_NID(0x03));

	/* PORT-A output selector (NID 37), set to DAC_0 input */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x37),
	    AUDIOHDC_VERB_SET_CONN_SEL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* PORT-A mixer (NID 22), unmute PORT-A output selector input */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x22), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_INPUT | (0 << AUDIOHDC_AMP_SET_INDEX_OFFSET));

	/* Power up DAC_1 (NID 4) */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x04), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* DAC_1, set playback input stream */
	AUDIOHD_NODE_INIT_DAC(statep, caddr, AUDIOHDC_NID(0x04));

	/* PORT-D mixer (NID 29), unmute DAC_1 input */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x29), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_INPUT | (0 << AUDIOHDC_AMP_SET_INDEX_OFFSET));

	outputs = AUDIO_HEADPHONE | AUDIO_LINE_OUT;

	statep->hda_info_defaults.play.port = outputs;
	statep->hda_info_defaults.play.avail_ports = outputs;
	statep->hda_info_defaults.play.mod_ports = outputs;
	statep->hda_out_ports = 0;

	/*
	 * Configure the widgets needed for recording
	 */

	/* Power up ADC_0 (NID 8) */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x08), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* for ADC_0 node 0x8, set channel and stream tag */
	AUDIOHD_NODE_INIT_ADC(statep, caddr, AUDIOHDC_NID(0x08));

	/* output amp of ADC selector node 0xc */
	lTmp = audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | 0x27 /* AUDIOHDC_GAIN_MAX */);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* Select analog mixer as recording source */
	lTmp = audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_CONN_SEL, 9);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	inputs = AUDIO_MICROPHONE | AUDIO_LINE_IN | AUDIO_CD;
	statep->hda_info_defaults.record.port = AUDIO_MICROPHONE;
	statep->hda_info_defaults.record.avail_ports = inputs;
	statep->hda_info_defaults.record.mod_ports = inputs;
	statep->hda_in_ports = 0;

	/*
	 * Configure the mixer and input/output pins
	 */

	/* Power up analog mixer */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x19), AUDIOHDC_VERB_SET_POWER_STATE, 0);

	/* PORT-A mixer (NID 22), unmute analog mixer input */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x22), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_INPUT | (1 << AUDIOHDC_AMP_SET_INDEX_OFFSET));

	/* PORT-A, HP Out/Front, pin (NID 11): enable output */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0x11));

	/* Unmute HP Out/Front */
	lTmp = AUDIOHDC_AMP_SET_LR_OUTPUT;
	if (statep->hda_outputs_muted)
		lTmp |= AUDIOHDC_AMP_SET_MUTE;
	lTmp = audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x11), AUDIOHDC_VERB_SET_AMP_MUTE, lTmp);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* PORT-D mixer (NID 29), unmute analog mixer input */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x29), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_INPUT | (1 << AUDIOHDC_AMP_SET_INDEX_OFFSET));

	/* PORT-D, Line out/Rear, pin (NID 12): enable output */
	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, AUDIOHDC_NID(0x12));

	/* Unmute Line out/Rear */
	lTmp = AUDIOHDC_AMP_SET_LR_OUTPUT;
	if (statep->hda_outputs_muted)
		lTmp |= AUDIOHDC_AMP_SET_MUTE;
	lTmp = audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE, lTmp);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* MIC1/Front */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x14));

	/* MIC2/Rear */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x17));

	/* Set microphone boost, for both MIC1/MIC2 */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x39), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | 3);

	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x3C), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | 3);

	/* PORT-E input selector (NID 34), set to PORT-E, MIC2/Rear input */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x34),
	    AUDIOHDC_VERB_SET_CONN_SEL, 0);

	/* line-in1 */
	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, AUDIOHDC_NID(0x15));

	/* Disable line-in microphone boost */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x3A), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | 0);

	/* PORT-C input selector (NID 33), set to PORT-C, line-in */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x33),
	    AUDIOHDC_VERB_SET_CONN_SEL, 0);

	/* cd-in, AUDIOHD_NODE_ENABLE_PIN_IN, no VRef supported on AD1988 */
	(void) audioha_codec_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x18), AUDIOHDC_VERB_SET_PIN_CTRL,
	    AUDIOHDC_PIN_CONTROL_IN_ENABLE);

	return (AUDIO_SUCCESS);
}

/*
 * audiohd_ad1988_set_pcm_fmt()
 */
static int
audiohd_ad1988_set_pcm_fmt(audiohd_state_t *statep, int dir, uint_t format)
{
	uint32_t	lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {
		/* DAC_0 */
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x3), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		/* DAC_1 */
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x4), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	} else {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x8), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1988_set_pcm_fmt() */

/*
 * audiohd_ad1988_set_gain()
 */
static int
audiohd_ad1988_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
{
	uint32_t	lTmp;
	uint_t		val;
	uint_t		caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_play_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_play_rgain = gain;
		}
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x03), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x04), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	} else {
		ASSERT(dir == AUDIO_RECORD);
		val = AUDIOHDC_AMP_SET_OUTPUT | gain;
		if (channel == 0) {
			/* left channel */
			val |= AUDIOHDC_AMP_SET_LEFT;
			statep->hda_record_lgain = gain;
		} else {
			/* right channel */
			val |= AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_record_rgain = gain;
		}
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x0C), AUDIOHDC_VERB_SET_AMP_MUTE, val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1988_set_gain() */

/*
 * audiohd_ad1988_set_port()
 */
static int
audiohd_ad1988_set_port(audiohd_state_t *statep, int dir, int port)
{
	uint_t	val;
	uint_t	tmp_port = 0;
	int	index, index2;
	uint_t	input_gain;
	uint_t	caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {

		if (port == AUDIOHD_PORT_UNMUTE) {
			port = statep->hda_out_ports;
		}

		val = AUDIOHDC_AMP_SET_LR_OUTPUT;
		if (port & AUDIO_HEADPHONE) {
			tmp_port |= AUDIO_HEADPHONE;
		} else { /* mute */
			val |= AUDIOHDC_AMP_SET_MUTE;
		}

		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x11), AUDIOHDC_VERB_SET_AMP_MUTE, val) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		val = AUDIOHDC_AMP_SET_LR_OUTPUT;
		if (port & AUDIO_LINE_OUT) {
			tmp_port |= AUDIO_LINE_OUT;
		} else { /* mute */
			val |= AUDIOHDC_AMP_SET_MUTE;
		}

		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE, val) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		if (tmp_port != port)
			return (AUDIO_FAILURE);
		statep->hda_out_ports = tmp_port;

		return (AUDIO_SUCCESS);
	}

	/*
	 * Now, deal with recording
	 */
	ASSERT(dir == AUDIO_RECORD);

	/*
	 * Select the recording source by unmuting it's analog mixer input.
	 */
	switch (port) {
	case AUDIO_MICROPHONE:
		index = AD1988_NID20H_INPUT_INDEX_MIC1;		/* Mic1 */
		index2 = AD1988_NID20H_INPUT_INDEX_MIC2;	/* Mic2 */
		break;
	case AUDIO_LINE_IN:
		index = AD1988_NID20H_INPUT_INDEX_LINE_IN;
		index2 = AD1988_NID20H_INPUT_INDEX_NULL;
		break;
	case AUDIO_CD:
		index = AD1988_NID20H_INPUT_INDEX_CD;
		index2 = AD1988_NID20H_INPUT_INDEX_NULL;
		break;
	default:
		return (AUDIO_FAILURE);
	}

	/*
	 * Unmute the new recording source, mute all other mixer inputs.
	 */
	for (tmp_port = 0; tmp_port < 8; tmp_port++) {
		input_gain = 0x1f;
		val = AUDIOHDC_AMP_SET_LR_INPUT | input_gain |
		    (tmp_port << AUDIOHDC_AMP_SET_INDEX_OFFSET);

		if (tmp_port != index && ((tmp_port != index2) ||
		    (index2 == AD1988_NID20H_INPUT_INDEX_NULL)))
			val |= AUDIOHDC_AMP_SET_MUTE;

		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x20), AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}

	statep->hda_in_ports = port;

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1988_set_port() */

/*
 * audiohd_ad1988_mute_outputs()
 */
static int
audiohd_ad1988_mute_outputs(audiohd_state_t *statep, boolean_t mute)
{
	uint_t	val;
	uint_t	caddr = statep->hda_codec->hc_addr;

	if (statep->hda_outputs_muted == mute)
		return (AUDIO_SUCCESS);

	statep->hda_outputs_muted = mute;
	val = AUDIOHDC_AMP_SET_LR_OUTPUT;
	if (mute) {
		val |= AUDIOHDC_AMP_SET_MUTE;
	}

	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x11), AUDIOHDC_VERB_SET_AMP_MUTE, val);

	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x12), AUDIOHDC_VERB_SET_AMP_MUTE, val);

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1988_mute_outputs() */

/*
 * audiohd_ad1988_set_monitor_gain()
 *
 * Description:
 *	Set the gain for input-to-ouput path
 */
static int
audiohd_ad1988_set_monitor_gain(audiohd_state_t *statep, int gain)
{
	uint_t	caddr = statep->hda_codec->hc_addr;

	/* Set mixer output attenuator */
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x21), AUDIOHDC_VERB_SET_AMP_MUTE,
	    AUDIOHDC_AMP_SET_LR_OUTPUT | gain);

	return (AUDIO_SUCCESS);

}	/* audiohd_ad1988_set_monitor_gain() */

/*
 * audiohd_ad1988_max_gain()
 *
 * Description:
 *	Get max gains for packplay and recording
 */
static void
audiohd_ad1988_max_gain(audiohd_state_t *statep, uint_t *pgain, uint_t
	*rgain, uint_t *mgain)
{
	uint_t	caddr = statep->hda_codec->hc_addr;
	uint_t	lTmp;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x03),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*pgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x0C),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*rgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x21),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*mgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

}	/* audiohd_ad1988_max_gain() */

/*
 * audiohd_set_busy()
 *
 * Description:
 *	This routine is called whenever a routine needs to guarantee
 *	that it will not be suspended.  It will also block any routine
 *	while a suspend is going on.
 *
 *	CAUTION: This routine cannot be called by routines that will
 *		block. Otherwise DDI_SUSPEND will be blocked for a
 *		long time. And that is the wrong thing to do.
 *
 * Arguments:
 *	audiohd_state_t	*statep		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiohd_set_busy(audiohd_state_t *statep)
{
	ASSERT(!mutex_owned(&statep->hda_mutex));

	mutex_enter(&statep->hda_mutex);

	/* block if we are suspended */
	while (statep->suspended) {
		cv_wait(&statep->hda_cv, &statep->hda_mutex);
	}

	/*
	 * Okay, we aren't suspended, so mark as busy.
	 * This will keep us from being suspended when we release the lock.
	 */
	ASSERT(statep->hda_busy_cnt >= 0);
	statep->hda_busy_cnt++;

	mutex_exit(&statep->hda_mutex);

}	/* audiohd_set_busy() */

/*
 * audiohd_set_idle()
 *
 * Description:
 *	This routine reduces the busy count. It then does a cv_broadcast()
 *	if the count is 0 so a waiting DDI_SUSPEND will continue forward.
 *
 * Arguments:
 *	audiohd_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audiohd_set_idle(audiohd_state_t *statep)
{
	ASSERT(!mutex_owned(&statep->hda_mutex));

	mutex_enter(&statep->hda_mutex);

	ASSERT(!statep->suspended);

	/* decrement the busy count */
	ASSERT(statep->hda_busy_cnt > 0);
	statep->hda_busy_cnt--;

	/* if no longer busy, then we wake up a waiting SUSPEND */
	if (statep->hda_busy_cnt == 0) {
		cv_broadcast(&statep->hda_cv);
	}

	mutex_exit(&statep->hda_mutex);
}	/* audiohd_set_idle() */
