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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
static int audiohd_reset_controller(audiohd_state_t *);
static int audiohd_init_controller(audiohd_state_t *);
static void audiohd_fini_controller(audiohd_state_t *);
static void audiohd_stop_dma(audiohd_state_t *);
static void audiohd_disable_intr(audiohd_state_t *);
static int audiohd_create_codec(audiohd_state_t *);
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

/*
 * operation routines for ALC88x codec
 */
static int audiohd_alc880_enable_play(audiohd_state_t *);
static int audiohd_alc880_enable_record(audiohd_state_t *);
static int audiohd_alc880_set_pcm_fmt(audiohd_state_t *, int, uint_t);
static int audiohd_alc880_set_gain(audiohd_state_t *, int, int, int);
static int audiohd_alc880_set_port(audiohd_state_t *, int, int);
static int audiohd_alc880_mute_outputs(audiohd_state_t *, boolean_t);
static int audiohd_alc880_set_monitor_gain(audiohd_state_t *, int);
static void audiohd_alc880_max_gain(audiohd_state_t *, uint_t *,
    uint_t *, uint_t *);

/* ops for ALC880 */
static struct audiohd_codec_ops audiohd_alc880_ops = {
	audiohd_alc880_enable_play,		/* ac_enable_play */
	audiohd_alc880_enable_record,		/* ac_enable_record */
	audiohd_alc880_set_pcm_fmt,		/* ac_set_pcm_fmt */
	audiohd_alc880_set_gain,		/* ac_set_out_gain */
	audiohd_alc880_set_port,		/* ac_set_port */
	audiohd_alc880_mute_outputs,		/* ac_mute_outputs */
	audiohd_alc880_set_monitor_gain,	/* ac_set_monitor_gain */
	audiohd_alc880_max_gain		/* ac_get_max_gain */
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
	AUDIOHD_MOD_NAME"1.3",	/* drv_linkinfo */
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
		return (DDI_FAILURE);

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

	/* interrupt cookie and initilize mutex */
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
		    "!audiohd_attach() counldn't init controller");
		goto err_attach_exit5;
	}

	if (audiohd_create_codec(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() counldn't create codec");
		goto err_attach_exit6;
	}

	AUDIOHD_CODEC_MAX_GAIN(statep, &statep->hda_pgain_max,
	    &statep->hda_rgain_max, &statep->hda_mgain_max);

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
		return (DDI_FAILURE);

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
	(void) audio_sup_unregister(statep->hda_ahandle);
	ddi_soft_state_free(audiohd_statep, instance);

	return (DDI_SUCCESS);

}	/* audiohd_detach() */

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
	uintptr_t	sbd_phys_addr;
	uint8_t		cTmp;
	uint_t	regbase;

	ATRACE_32("i810_ad_start_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->hda_mutex);
	if (statep->hda_flags & AUDIOHD_PLAY_STARTED) {
		mutex_exit(&statep->hda_mutex);
		return (AUDIO_SUCCESS);
	}

	regbase = statep->hda_play_regbase;
	if (statep->hda_flags & AUDIOHD_PLAY_PAUSED) {
		cTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
		statep->hda_flags |= AUDIOHD_PLAY_STARTED;
		statep->hda_flags &= ~AUDIOHD_PLAY_PAUSED;
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
		    cTmp | AUDIOHDR_SD_CTL_SRUN);
		mutex_exit(&statep->hda_mutex);
		return (AUDIO_SUCCESS);
	}

	if (audiohd_reset_stream(statep, statep->hda_input_streams)
	    != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_play() failed to reset play stream");
		mutex_exit(&statep->hda_mutex);
		return (AUDIO_FAILURE);
	}

	statep->hda_flags |= AUDIOHD_PLAY_STARTED;

	if (audiohd_fill_pbuf(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_play() failed to get play sample");
		statep->hda_flags &= ~AUDIOHD_PLAY_STARTED;
		mutex_exit(&statep->hda_mutex);
		return (AUDIO_FAILURE);
	}

	sbd_phys_addr = statep->hda_dma_play_bd.ad_paddr;
	AUDIOHD_REG_SET64(regbase + AUDIOHD_SDREG_OFFSET_BDLPL, sbd_phys_addr);
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

	AUDIOHD_CODEC_ENABLE_PLAY(statep);

	/* set playback stream tag */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL + 2,
	    (statep->hda_play_stag) << 4 | 4);

	/* Enable interrupt and start DMA */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);

	mutex_exit(&statep->hda_mutex);
	return (AUDIO_SUCCESS);

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

	mutex_enter(&statep->hda_mutex);
	regbase = statep->hda_play_regbase;
	cTmp = AUDIOHD_REG_GET8(regbase + AUDIOHD_SDREG_OFFSET_CTL);
	cTmp &= ~AUDIOHDR_SD_CTL_SRUN;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, cTmp);
	statep->hda_flags &= ~AUDIOHD_PLAY_STARTED;
	statep->hda_flags |= AUDIOHD_PLAY_PAUSED;
	mutex_exit(&statep->hda_mutex);

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

	mutex_enter(&statep->hda_mutex);
	regbase = statep->hda_play_regbase;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, 0);
	statep->hda_flags &=
	    ~(AUDIOHD_PLAY_EMPTY | AUDIOHD_PLAY_STARTED);
	mutex_exit(&statep->hda_mutex);

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

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->hda_mutex);
	if (statep->hda_flags & AUDIOHD_RECORD_STARTED) {
		mutex_exit(&statep->hda_mutex);
		return (AUDIO_SUCCESS);
	}

	if (audiohd_reset_stream(statep, 0) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_record() failed to reset record stream");
		mutex_exit(&statep->hda_mutex);
		return (AUDIO_FAILURE);
	}

	audiohd_preset_rbuf(statep);
	statep->hda_rbuf_pos = 0;

	regbase = statep->hda_record_regbase;
	sbd_phys_addr = statep->hda_dma_record_bd.ad_paddr;
	AUDIOHD_REG_SET64(regbase + AUDIOHD_SDREG_OFFSET_BDLPL, sbd_phys_addr);
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
	AUDIOHD_CODEC_ENABLE_RECORD(statep);

	/* set stream tag to 1 */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL + 2,
	    statep->hda_record_stag << 4 | 4);
	statep->hda_flags |= AUDIOHD_RECORD_STARTED;

	/* start DMA */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);

	mutex_exit(&statep->hda_mutex);
	return (AUDIO_SUCCESS);

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

	mutex_enter(&statep->hda_mutex);
	regbase = statep->hda_record_regbase;
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL, 0);
	statep->hda_flags &= ~(AUDIOHD_RECORD_STARTED);
	mutex_exit(&statep->hda_mutex);

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
	statep->hda_info_defaults.play.port =
	    AUDIO_HEADPHONE | AUDIO_LINE_OUT;
	statep->hda_info_defaults.play.avail_ports =
	    AUDIO_HEADPHONE | AUDIO_LINE_OUT;
	statep->hda_info_defaults.play.mod_ports =
	    AUDIO_HEADPHONE | AUDIO_LINE_OUT;
	statep->hda_info_defaults.play.buffer_size = AUDIOHD_BSIZE;
	statep->hda_info_defaults.play.balance = AUDIOHD_DEFAULT_BAL;

	statep->hda_info_defaults.record.sample_rate = AUDIOHD_DEFAULT_SR;
	statep->hda_info_defaults.record.channels = AUDIOHD_DEFAULT_CH;
	statep->hda_info_defaults.record.precision = AUDIOHD_DEFAULT_PREC;
	statep->hda_info_defaults.record.encoding = AUDIOHD_DEFAULT_ENC;
	statep->hda_info_defaults.record.gain = AUDIOHD_DEFAULT_RGAIN;
	statep->hda_info_defaults.record.port = AUDIO_MICROPHONE;
	statep->hda_info_defaults.record.avail_ports =
	    AUDIO_MICROPHONE | AUDIO_LINE_IN;
	statep->hda_info_defaults.record.mod_ports =
	    AUDIO_MICROPHONE | AUDIO_LINE_IN;
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

	statep->hda_out_ports = AUDIO_HEADPHONE;
	statep->hda_in_ports = AUDIO_MICROPHONE;

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
	dev_info_t	*dip = statep->hda_dip;
	audiohdl_t	ahandle = statep->hda_ahandle;

	if (pci_config_setup(dip, &statep->hda_pci_handle) == DDI_FAILURE) {
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

	/*
	 * HD audio control uses memory I/O only, enable it here.
	 */
	cmdreg = pci_config_get16(statep->hda_pci_handle, PCI_CONF_COMM);
	pci_config_put16(statep->hda_pci_handle, PCI_CONF_COMM,
	    cmdreg | PCI_COMM_MAE | PCI_COMM_ME);

	/* set TCSEL to TC1 */
	pci_config_put8(statep->hda_pci_handle, 0x44, 1);

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
	pdma->ad_paddr = (uintptr_t)(cookie.dmac_laddress);
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
	uintptr_t	addr;
	uint16_t	gcap;
	int		retval;

	ddi_dma_attr_t	dma_attr = {
		DMA_ATTR_V0,		/* version */
		0,			/* addr_lo */
		0xffffffffffffffff,	/* addr_hi */
		0x00000000ffffffff,	/* count_max */
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
	AUDIOHD_REG_SET64(AUDIOHD_REG_RIRBLBASE, addr);
	AUDIOHD_REG_SET16(AUDIOHD_REG_RIRBWP, AUDIOHDR_RIRBWP_RESET);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSIZE, AUDIOHDR_RIRBSZ_256);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN);

	/* initialize CORB */
	addr = statep->hda_dma_corb.ad_paddr;
	AUDIOHD_REG_SET16(AUDIOHD_REG_CORBRP, AUDIOHDR_CORBRP_RESET);
	AUDIOHD_REG_SET64(AUDIOHD_REG_CORBLBASE, addr);
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

		case AUDIOHD_VID_ALC880:
		case AUDIOHD_VID_ALC883:
		case AUDIOHD_VID_ALC885:
			codec->hc_ops = &audiohd_alc880_ops;
			found = B_TRUE;
			break;

		default:
			audio_sup_log(statep->hda_ahandle, CE_WARN,
			    "!unsupported audio codec: vid=0x%08x, rev=0x%08x",
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
 *	Get pending audio data, and fill out entries of stream
 *	descriptor list for playback.
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

	/*
	 * If we cannot get sample or playback already stopped before
	 * we re-grab mutex
	 */
	if ((rs <= 0) || ((statep->hda_flags & AUDIOHD_PLAY_STARTED) == 0))
		return (AUDIO_FAILURE);

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

	audio_sup_log(NULL, CE_WARN, "!%s: verb_get() timeout when get "
	    " response from codec: nid=%d, verb=0x%04x, param=0x%04x",
	    audiohd_name, nid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_4bit_verb_get() */


/*
 * audiohd_alc880_enable_play()
 */
static int
audiohd_alc880_enable_play(audiohd_state_t *statep)
{
	uint32_t	lTmp;
	uint_t		output_val;
	uint_t		input_val;
	uint_t		caddr = statep->hda_codec->hc_addr;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x02),
	    AUDIOHDC_VERB_SET_STREAM_CHANN, statep->hda_play_stag << 4);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	output_val = AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_GAIN_MAX;
	input_val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_GAIN_MAX;

	/* output amp of DAC */
	lTmp = audioha_codec_4bit_verb_get(statep, caddr, AUDIOHDC_NID(0x02),
	    AUDIOHDC_VERB_SET_AMP_MUTE, output_val);

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* unmute input for DAC2 of mixer */
	lTmp = audioha_codec_4bit_verb_get(statep, caddr, AUDIOHDC_NID(0xc),
	    AUDIOHDC_VERB_SET_AMP_MUTE, input_val);

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* output amp of mixer */
	(void) audioha_codec_4bit_verb_get(statep, caddr, AUDIOHDC_NID(0xc),
	    AUDIOHDC_VERB_SET_AMP_MUTE, AUDIOHDC_AMP_SET_OUTPUT |
	    AUDIOHDC_AMP_SET_LEFT | statep->hda_play_lgain);

	(void) audioha_codec_4bit_verb_get(statep, caddr, AUDIOHDC_NID(0xc),
	    AUDIOHDC_VERB_SET_AMP_MUTE, AUDIOHDC_AMP_SET_OUTPUT |
	    AUDIOHDC_AMP_SET_RIGHT | statep->hda_play_rgain);

	/* Unmute pin */
	if (!statep->hda_outputs_muted) {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x14), AUDIOHDC_VERB_SET_AMP_MUTE, output_val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1b), AUDIOHDC_VERB_SET_AMP_MUTE,
			output_val);
		if (lTmp == AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);
	}

	/* enable output for pin node 0x14 */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x14),
	    AUDIOHDC_VERB_GET_PIN_CTRL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x14),
	    AUDIOHDC_VERB_SET_PIN_CTRL, (lTmp |
	    AUDIOHDC_PIN_CONTROL_OUT_ENABLE));
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* enable output for pin node 0x1b */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x1b),
	    AUDIOHDC_VERB_GET_PIN_CTRL, 0);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x1b),
	    AUDIOHDC_VERB_SET_PIN_CTRL, (lTmp |
	    AUDIOHDC_PIN_CONTROL_OUT_ENABLE));
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_enable_play() */

/*
 * audiohd_alc880_enable_record()
 */
static int
audiohd_alc880_enable_record(audiohd_state_t *statep)
{
	uint32_t	lTmp;
	uint_t		val;
	uint_t		caddr = statep->hda_codec->hc_addr;

	/* for ADC node 0x9, set channel and stream tag */
	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x09),
	    AUDIOHDC_VERB_SET_STREAM_CHANN, statep->hda_record_stag << 4);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* input amp of ADC node 0x9 */
	val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_GAIN_MAX;
	lTmp = audioha_codec_4bit_verb_get(statep, caddr, AUDIOHDC_NID(0x09),
	    AUDIOHDC_VERB_SET_AMP_MUTE, val);
	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	/* MIC1 */
	(void) audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x18),
	    AUDIOHDC_VERB_SET_PIN_CTRL, AUDIOHDC_PIN_CONTROL_IN_ENABLE | 4);

	/* MIC 2 */
	(void) audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x19),
	    AUDIOHDC_VERB_SET_PIN_CTRL, AUDIOHDC_PIN_CONTROL_IN_ENABLE | 4);

	/* line-in1 */
	(void) audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x1a),
	    AUDIOHDC_VERB_SET_PIN_CTRL, AUDIOHDC_PIN_CONTROL_IN_ENABLE | 4);

	/* cd-in */
	(void) audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x1c),
	    AUDIOHDC_VERB_SET_PIN_CTRL, AUDIOHDC_PIN_CONTROL_IN_ENABLE | 4);

	/*
	 * enable gain for monitor path, from node 0x0B to node 0x0C,
	 * In the input list of 0x0c, 0x0b node has index 1
	 */
	val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_GAIN_MAX;
	val |= (1 << AUDIOHDC_AMP_SET_INDEX_OFFSET);
	lTmp = audioha_codec_4bit_verb_get(statep, caddr, AUDIOHDC_NID(0x0C),
	    AUDIOHDC_VERB_SET_AMP_MUTE, val);
	if (lTmp == AUDIOHD_CODEC_FAILURE) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!alc880_enable_record() failed to set monitor");
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_enable_record */

/*
 * audiohd_alc880_set_pcm_fmt()
 */
static int
audiohd_alc880_set_pcm_fmt(audiohd_state_t *statep, int dir, uint_t format)
{
	uint32_t	lTmp;
	uint_t		caddr = statep->hda_codec->hc_addr;

	if (dir == AUDIO_PLAY) {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x2), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
	} else {
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_CONVERTER_FMT, format);
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_pcm_fmt() */

/*
 * audiohd_alc880_set_gain()
 */
static int
audiohd_alc880_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
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
		    AUDIOHDC_NID(0xC), AUDIOHDC_VERB_SET_AMP_MUTE, val);
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
		lTmp = audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}

	if (lTmp == AUDIOHD_CODEC_FAILURE)
		return (AUDIO_FAILURE);

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_gain() */

/*
 * audiohd_alc880_set_port()
 */
static int
audiohd_alc880_set_port(audiohd_state_t *statep, int dir, int port)
{
	uint_t	val;
	uint_t	tmp_port = 0;
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
		    AUDIOHDC_NID(0x14), AUDIOHDC_VERB_SET_AMP_MUTE, val) ==
		    AUDIOHD_CODEC_FAILURE)
			return (AUDIO_FAILURE);

		val = AUDIOHDC_AMP_SET_LR_OUTPUT;
		if (port & AUDIO_LINE_OUT) {
			tmp_port |= AUDIO_LINE_OUT;
		} else { /* mute */
			val |= AUDIOHDC_AMP_SET_MUTE;
		}

		if (audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x1B), AUDIOHDC_VERB_SET_AMP_MUTE,
		    val) == AUDIOHD_CODEC_FAILURE)
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
		/* mute ADC node 0x09 */
		val = AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_AMP_SET_MUTE;
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_AMP_MUTE, val);
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

	/* if ADC 0x09 is muted, we resume its gains */
	if (statep->hda_in_ports == AUDIO_NONE) {
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_INPUT | AUDIOHDC_AMP_SET_LEFT |
		    statep->hda_record_lgain));
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_AMP_MUTE,
		    (AUDIOHDC_AMP_SET_INPUT | AUDIOHDC_AMP_SET_RIGHT |
		    statep->hda_record_rgain));
	}

	switch (statep->hda_codec->hc_vid) {
	case AUDIOHD_VID_ALC880:
		/*
		 * For ALC880, node 9 has multiple inputs,
		 * we need to select the right one among
		 * those inputs
		 */
		(void) audioha_codec_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x9), AUDIOHDC_VERB_SET_CONN_SEL,
		    tmp_port);
		break;

	case AUDIOHD_VID_ALC883:
	case AUDIOHD_VID_ALC885:
		/*
		 * For ALC883/885, node 9 has only one input,
		 * which is a mixer with node number 0x22. So,
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
			    AUDIOHDC_NID(0x22), AUDIOHDC_VERB_SET_AMP_MUTE,
			    val);

			if (statep->hda_in_ports == AUDIO_MICROPHONE) {
				/* mute MIC2 as well */
				old_index = 1;
				val = AUDIOHDC_AMP_SET_LR_INPUT;
				val |= AUDIOHDC_AMP_SET_MUTE;
				val |=
				    old_index << AUDIOHDC_AMP_SET_INDEX_OFFSET;
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr, AUDIOHDC_NID(0x22),
					AUDIOHDC_VERB_SET_AMP_MUTE, val);
			}
		}

		/* unmute new input port */
		val = AUDIOHDC_AMP_SET_LR_INPUT;
		val |= tmp_port << AUDIOHDC_AMP_SET_INDEX_OFFSET;
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0x22), AUDIOHDC_VERB_SET_AMP_MUTE, val);

		if (port == AUDIO_MICROPHONE) {
			/*
			 * SADA only exports control for one MIC, so if MIC
			 * is selected, we unmute MIC2 as well
			 */
			tmp_port = 1;
			val = AUDIOHDC_AMP_SET_LR_INPUT;
			val |= tmp_port << AUDIOHDC_AMP_SET_INDEX_OFFSET;
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    AUDIOHDC_NID(0x22), AUDIOHDC_VERB_SET_AMP_MUTE,
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
 */
static int
audiohd_alc880_mute_outputs(audiohd_state_t *statep, boolean_t mute)
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
	    AUDIOHDC_NID(0x14), AUDIOHDC_VERB_SET_AMP_MUTE, val);

	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0x1b), AUDIOHDC_VERB_SET_AMP_MUTE, val);

	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_mute_outputs() */

/*
 * audiohd_alc880_set_monitor_gain()
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

	val = AUDIOHDC_AMP_SET_LR_INPUT | gain;
	val |= (index << AUDIOHDC_AMP_SET_INDEX_OFFSET);
	(void) audioha_codec_4bit_verb_get(statep, caddr,
	    AUDIOHDC_NID(0xB), AUDIOHDC_VERB_SET_AMP_MUTE, val);

	/* set MIC1 and MIC2 if MIC is requested */
	if (statep->hda_in_ports == AUDIO_MICROPHONE) {
		index = 1;
		val = AUDIOHDC_AMP_SET_LR_INPUT | gain;
		val |= (index << AUDIOHDC_AMP_SET_INDEX_OFFSET);
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    AUDIOHDC_NID(0xB), AUDIOHDC_VERB_SET_AMP_MUTE, val);
	}
	return (AUDIO_SUCCESS);

}	/* audiohd_alc880_set_monitor_gain() */

/*
 * audiohd_alc880_max_gain()
 *
 * Description:
 *	Get max gains for packplay and recording
 */
static void
audiohd_alc880_max_gain(audiohd_state_t *statep, uint_t *pgain, uint_t
	*rgain, uint_t *mgain)
{
	uint_t	caddr = statep->hda_codec->hc_addr;
	uint_t	lTmp;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0xC),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_OUT_CAP);
	*pgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0x9),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_IN_CAP);
	*rgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

	lTmp = audioha_codec_verb_get(statep, caddr, AUDIOHDC_NID(0xb),
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AMP_IN_CAP);
	*mgain = (lTmp & AUDIOHDC_AMP_CAP_STEP_NUMS) >> 8;

}	/* audiohd_alc880_max_gain() */
