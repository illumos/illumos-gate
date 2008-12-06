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
static int audiohd_quiesce(dev_info_t *);
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
static int audiohd_reset_controller(audiohd_state_t *);
static int audiohd_init_controller(audiohd_state_t *);
static void audiohd_fini_controller(audiohd_state_t *);
static void audiohd_stop_dma(audiohd_state_t *);
static void audiohd_disable_intr(audiohd_state_t *);
static int audiohd_create_codec(audiohd_state_t *);
static void audiohd_build_path(audiohd_state_t *);
static int audiohd_init_ports(audiohd_state_t *);
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
static void audiohd_finish_output_path(hda_codec_t *codec);
static void audiohd_finish_input_path(hda_codec_t *codec);
static void audiohd_finish_monitor_path(hda_codec_t *codec);

static uint32_t audioha_codec_verb_get(void *, uint8_t,
    uint8_t, uint16_t, uint8_t);
static uint32_t audioha_codec_4bit_verb_get(void *, uint8_t,
    uint8_t, uint16_t, uint16_t);
static int audiohd_reinit_hda(audiohd_state_t *);
static void audiohd_set_busy(audiohd_state_t *);
static void audiohd_set_idle(audiohd_state_t *);
static int audiohd_response_from_codec(audiohd_state_t *statep,
    uint32_t *resp, uint32_t *respex);
static void audiohd_restore_codec_gpio(audiohd_state_t *statep);
static void audiohd_change_speaker_state(audiohd_state_t *statep, int on);
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
	NULL,			/* devo_power */
	audiohd_quiesce,	/* devo_quiesce */
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

static const uint_t g_outport[] = {
	AUDIO_LINE_OUT,
	AUDIO_SPEAKER,
	AUDIO_HEADPHONE,
	AUDIO_AUX1_OUT,
	AUDIO_AUX2_OUT
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

	audiohd_build_path(statep);

	if (audiohd_init_ports(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_attach() couldn't init ports");
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
	    AUDIOHD_INTCTL_BIT_GIE |
	    AUDIOHD_INTCTL_BIT_CIE |
	    AUDIOHD_INTCTL_BIT_SIE);
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

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
audiohd_quiesce(dev_info_t *dip)
{
	audiohd_state_t		*statep;
	int			instance;

	instance = ddi_get_instance(dip);

	if ((statep = ddi_get_soft_state(audiohd_statep, instance)) == NULL) {
		return (DDI_SUCCESS);
	}

	audiohd_stop_dma(statep);
	audiohd_disable_intr(statep);

	return (DDI_SUCCESS);
}
/*
 * audiohd_change_widget_power_state(audiohd_state_t *statep, int off)
 * Description:
 * 	This routine is used to change the widget power betwen D0 and D2.
 * 	D0 is fully on; D2 allows the lowest possible power consuming state
 * 	from which it can return to the fully on state: D0.
 */
static void
audiohd_change_widget_power_state(audiohd_state_t *statep, int off)
{
	int			i;
	wid_t			wid;
	hda_codec_t		*codec;
	audiohd_widget_t	*widget;

	/* Change power to D2 */
	if (off) {
		for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			codec = statep->codec[i];
			if (!codec)
				continue;
			for (wid = codec->first_wid; wid <= codec->last_wid;
			    wid++) {
				widget = codec->widget[wid];
				if (widget->widget_cap &
				    AUDIOHD_WIDCAP_PWRCTRL) {
					(void) audioha_codec_verb_get(statep,
					    codec->index, wid,
					    AUDIOHDC_VERB_SET_POWER_STATE,
					    AUDIOHD_PW_D2);
				}
			}
		}
	/* Change power to D0 */
	} else {
		for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			codec = statep->codec[i];
			if (!codec)
				continue;
			for (wid = codec->first_wid; wid <= codec->last_wid;
			    wid++) {
				widget = codec->widget[wid];
				if (widget->widget_cap &
				    AUDIOHD_WIDCAP_PWRCTRL) {
					(void) audioha_codec_verb_get(statep,
					    codec->index, wid,
					    AUDIOHDC_VERB_SET_POWER_STATE,
					    AUDIOHD_PW_D0);
				}
			}
		}
	}
}
/*
 * audiohd_restore_path()
 * Description:
 * 	This routine is used to restore the path on the codec.
 */
static void
audiohd_restore_path(audiohd_state_t *statep)
{
	int			i;
	hda_codec_t		*codec;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (!codec)
			continue;
		audiohd_finish_output_path(statep->codec[i]);
		audiohd_finish_input_path(statep->codec[i]);
		audiohd_finish_monitor_path(statep->codec[i]);
	}
}

/*
 * restore_play_and_record()
 */
static void
audiohd_restore_play_and_record(audiohd_state_t *statep)
{
	uint64_t	sbd_phys_addr;
	uint_t		regbase;

	regbase = statep->hda_play_regbase;
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

	/* clear status */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS,
	    AUDIOHDR_SD_STS_BCIS | AUDIOHDR_SD_STS_FIFOE |
	    AUDIOHDR_SD_STS_DESE);

	/* set playback stream tag */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL +
	    AUDIOHD_PLAY_CTL_OFF,
	    (statep->hda_play_stag) << AUDIOHD_PLAY_TAG_OFF);

	if (statep->hda_flags & AUDIOHD_PLAY_STARTED) {
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
		    AUDIOHDR_SD_CTL_SRUN);
	}

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

	/* set stream tag to 1 */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL +
	    AUDIOHD_REC_CTL_OFF,
	    statep->hda_record_stag << AUDIOHD_REC_TAG_OFF);

	if (statep->hda_flags & AUDIOHD_RECORD_STARTED) {
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
		    AUDIOHDR_SD_CTL_SRUN);
	}

}
/*
 * audiohd_reset_pins_ur_cap()
 * Description:
 * 	Enable the unsolicited response of the pins which have the unsolicited
 * 	response capability
 */
static void
audiohd_reset_pins_ur_cap(audiohd_state_t *statep)
{
	hda_codec_t		*codec;
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget;
	uint32_t		urctrl;
	int			i;

	for (i = 0; i <= AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (!codec)
			continue;
		pin = codec->first_pin;
		while (pin) {
			/* enable the unsolicited response of the pin */
			widget = codec->widget[pin->wid];
			if ((widget->widget_cap &
			    (AUDIOHD_URCAP_MASK) &&
			    (pin->cap & AUDIOHD_DTCCAP_MASK)) &&
			    ((pin->device == DTYPE_LINEOUT) ||
			    (pin->device == DTYPE_SPDIF_OUT) ||
			    (pin->device == DTYPE_HP_OUT) ||
			    (pin->device == DTYPE_MIC_IN))) {
				urctrl = (uint8_t)(1 <<
				    (AUDIOHD_UR_ENABLE_OFF - 1));
				urctrl |= (pin->wid & AUDIOHD_UR_TAG_MASK);
				(void) audioha_codec_verb_get(statep,
				    codec->index,
				    pin->wid,
				    AUDIOHDC_VERB_SET_URCTRL, urctrl);
			}
			pin = pin->next;
		}
	}
}
static void
audiohd_restore_codec_gpio(audiohd_state_t *statep)
{
	int		i;
	wid_t		wid;
	hda_codec_t	*codec;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (codec == NULL)
			continue;
		wid = codec->wid_afg;

		/*
		 * GPIO controls which are laptop specific workarounds and
		 * might be changed. Some laptops use GPIO, so we need to
		 * enable and set the GPIO correctly.
		 */
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_MASK, AUDIOHDC_GPIO_ENABLE);
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_DIREC, AUDIOHDC_GPIO_DIRECT);
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_STCK, AUDIOHDC_GPIO_DATA_CTRL);
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_DATA, AUDIOHDC_GPIO_STCK_CTRL);

		/* power-up audio function group */
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_POWER_STATE, 0);

	}
}
/*
 * audiohd_resume()
 */
static int
audiohd_resume(audiohd_state_t *statep)
{
	uint_t		regbase;
	uint8_t		rirbsts;

	mutex_enter(&statep->hda_mutex);
	statep->suspended = B_FALSE;
	/* Restore the hda state */
	if (audiohd_reinit_hda(statep) == AUDIO_FAILURE) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_resume() hda reinit failed");
		mutex_exit(&statep->hda_mutex);
		return (DDI_SUCCESS);
	}
	/* reset to enable the capability of unsolicited response for pin */
	audiohd_reset_pins_ur_cap(statep);
	/* Enable interrupt */
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTCTL,
	    AUDIOHD_INTCTL_BIT_GIE |
	    AUDIOHD_INTCTL_BIT_SIE);
	/* clear the unsolicited response interrupt */
	rirbsts = AUDIOHD_REG_GET8(AUDIOHD_REG_RIRBSTS);
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSTS, rirbsts);
	mutex_exit(&statep->hda_mutex);

	/* Resume playing and recording */
	if (audio_sup_restore_state(statep->hda_ahandle,
	    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!audiohd_resume() audioh restore failed");
		audiohd_disable_intr(statep);
		audiohd_stop_dma(statep);
	}
	audiohd_restore_play_and_record(statep);
	/* Enable interrupt and start DMA for play */
	if (statep->hda_flags & AUDIOHD_PLAY_STARTED) {
		regbase = statep->hda_play_regbase;
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
		    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);
	}

	/* Enable interrupt and start DMA for record */
	if (statep->hda_flags & AUDIOHD_RECORD_STARTED) {
		regbase = statep->hda_record_regbase;
		AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
		    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);
	}
	/* set widget power to D0 */
	audiohd_change_widget_power_state(statep, AUDIOHD_PW_ON);
	mutex_enter(&statep->hda_mutex);
	cv_broadcast(&statep->hda_cv); /* wake up entry points */
	mutex_exit(&statep->hda_mutex);

	return (DDI_SUCCESS);
}	/* audiohd_resume */

/*
 * audiohd_suspend()
 */
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
		    "audiohd_suspend() audio save failed");
		statep->suspended = B_FALSE;
		cv_broadcast(&statep->hda_cv);
		mutex_exit(&statep->hda_mutex);
		return (DDI_FAILURE);
	}

	/* set widget power to D2 */
	audiohd_change_widget_power_state(statep, AUDIOHD_PW_OFF);
	/* Disable h/w */
	audiohd_disable_intr(statep);
	audiohd_stop_dma(statep);
	mutex_exit(&statep->hda_mutex);

	return (DDI_SUCCESS);
}	/* audiohd_suspend */

/*
 * audiohd_disable_pin()
 */
static int
audiohd_disable_pin(audiohd_state_t *statep, int caddr, wid_t wid)
{
	AUDIOHD_DISABLE_PIN_OUT(statep, caddr, wid);
	return (AUDIO_SUCCESS);
}

/*
 * audiohd_enable_pin()
 */
static int
audiohd_enable_pin(audiohd_state_t *statep, int caddr, wid_t wid)
{
	AUDIOHD_ENABLE_PIN_OUT(statep, caddr, wid);
	return (AUDIO_SUCCESS);
}
/*
 * audiohd_change_speaker_state()
 */
static void
audiohd_change_speaker_state(audiohd_state_t *statep, int on)
{
	hda_codec_t		*codec;
	audiohd_ostream_t	*ostream;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	int			i, j;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i]) {
			codec = statep->codec[i];
			break;
		}
	}
	if (!codec)
		return;
	if (on) {
		ostream = codec->ostream;
		while (ostream) {
			for (j = 0; j < ostream->pin_nums; j++) {
				widget = codec->widget[ostream->pin_wid[j]];
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_SPEAKER) {
					(void) audiohd_enable_pin(statep,
					    codec->index, pin->wid);
				}
			}
			ostream = ostream->next_stream;
		}

	} else {
		ostream = codec->ostream;
		while (ostream) {
			for (j = 0; j < ostream->pin_nums; j++) {
				widget = codec->widget[ostream->pin_wid[j]];
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_SPEAKER) {
					(void) audiohd_disable_pin(statep,
					    codec->index, pin->wid);
				}
			}
			ostream = ostream->next_stream;
		}
	}
}
/*
 * audiohd_select_mic()
 *
 * Description:
 *	This funciton is used for the recording path which has a selector
 *	as the sumwidget. We select the external MIC if it is plugged into the
 *	MIC jack, otherwise the internal integrated MIC is selected.
 */
static void
audiohd_select_mic(audiohd_state_t *statep, uint8_t index,
uint8_t id, int select)
{
	hda_codec_t		*codec;
	audiohd_istream_t	*istream;
	audiohd_widget_t	*widget, *sumwgt;
	audiohd_pin_t		*pin;
	int			i;
	wid_t			wid;

	codec = statep->codec[index];
	if (codec == NULL)
		return;
	istream = codec->istream;
	sumwgt = codec->widget[istream->sum_wid];
	while (istream && sumwgt && (sumwgt->type == WTYPE_AUDIO_SEL)) {
		if (select) {
			for (i = 0; i < istream->pin_nums; i++) {
				wid = istream->pin_wid[i];
				widget = codec->widget[wid];
				if (widget == NULL)
					return;
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_MIC_IN &&
				    pin->wid == id &&
				    (((pin->config >> AUDIOHD_PIN_CONTP_OFF) &
				    AUDIOHD_PIN_CONTP_MASK) ==
				    AUDIOHD_PIN_CON_JACK)) {
					(void) audioha_codec_verb_get(statep,
					    index,
					    istream->sum_wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    istream->sum_selconn[i]);
					statep->hda_record_stag = istream->rtag;
					return;
				}
			}
		} else {
			for (i = 0; i < istream->pin_nums; i++) {
				wid = istream->pin_wid[i];
				widget = codec->widget[wid];
				if (widget == NULL)
					return;
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_MIC_IN &&
				    (((pin->config >> AUDIOHD_PIN_CONTP_OFF) &
				    AUDIOHD_PIN_CONTP_MASK) ==
				    AUDIOHD_PIN_CON_FIXED)) {
					(void) audioha_codec_verb_get(statep,
					    index,
					    istream->sum_wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    istream->sum_selconn[i]);
					statep->hda_record_stag = istream->rtag;
					return;
				}
			}
		}
		istream = istream->next_stream;
		if (istream == NULL)
			break;
		sumwgt = codec->widget[istream->sum_wid];
	}
	/*
	 * If the input istream > 1, we should set the the record stream tag
	 * repectively. All the input streams sharing one tag may make the
	 * record sound distorted.
	 */
	if (codec->nistream > 1) {
		istream = codec->istream;
		while (istream) {
			if (select) {
				for (i = 0; i < istream->pin_nums; i++) {
					wid = istream->pin_wid[i];
					widget = codec->widget[wid];
					if (widget == NULL)
						return;
					pin = (audiohd_pin_t *)widget->priv;
					if (pin->device == DTYPE_MIC_IN &&
					    pin->wid == id &&
					    (((pin->config >>
					    AUDIOHD_PIN_CONTP_OFF) &
					    AUDIOHD_PIN_CONTP_MASK) ==
					    AUDIOHD_PIN_CON_JACK)) {
						statep->hda_record_stag =
						    istream->rtag;
						return;
					}
				}
			} else {
				for (i = 0; i < istream->pin_nums; i++) {
					wid = istream->pin_wid[i];
					widget = codec->widget[wid];
					if (widget == NULL)
						return;
					pin = (audiohd_pin_t *)widget->priv;
					if (pin->device == DTYPE_MIC_IN &&
					    (((pin->config >>
					    AUDIOHD_PIN_CONTP_OFF) &
					    AUDIOHD_PIN_CONTP_MASK) ==
					    AUDIOHD_PIN_CON_FIXED)) {
						statep->hda_record_stag =
						    istream->rtag;
						return;
					}
				}
			}
			istream = istream->next_stream;
		}
	}
}
/*
 * audiohd_pin_sense()
 *
 * Description
 *
 * 	When the earphone is plugged into the jack associtated with the pin
 * 	complex, we disable the built in speaker. When the earphone is plugged
 * 	out of the jack, we enable the built in speaker.
 */
static void
audiohd_pin_sense(audiohd_state_t *statep, uint32_t resp, uint32_t respex)
{
	uint8_t			index;
	uint8_t			id;
	uint32_t		rs;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	hda_codec_t		*codec;

	index = respex & AUDIOHD_RIRB_CODEC_MASK;
	id = resp >> (AUDIOHD_RIRB_WID_OFF - 1);

	codec = statep->codec[index];
	if (codec == NULL)
		return;
	widget = codec->widget[id];
	if (widget == NULL)
		return;

	rs = audioha_codec_verb_get(statep, index, id,
	    AUDIOHDC_VERB_GET_PIN_SENSE, 0);
	if (rs >> (AUDIOHD_PIN_PRES_OFF - 1) & 1) {
		/* A MIC is plugged in, we select the MIC as input */
		if ((widget->type == WTYPE_PIN) &&
		    (pin = (audiohd_pin_t *)widget->priv) &&
		    (pin->device == DTYPE_MIC_IN)) {
			audiohd_select_mic(statep, index, id, 1);
			return;
		}
		/* output pin is plugged */
		audiohd_change_speaker_state(statep, AUDIOHD_SP_OFF);
	} else {
		/*
		 * A MIC is unplugged, we select the built in MIC
		 * as input.
		 */
		if ((widget->type == WTYPE_PIN) &&
		    (pin = (audiohd_pin_t *)widget->priv) &&
		    (pin->device == DTYPE_MIC_IN)) {
			audiohd_select_mic(statep, index, id, 0);
			return;
		}
		/* output pin is unplugged */
		audiohd_change_speaker_state(statep, AUDIOHD_SP_ON);
	}

}
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
	uint32_t	resp, respex;
	uint8_t		sdstatus, rirbsts;
	int		i, ret;

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
	AUDIOHD_REG_SET32(AUDIOHD_REG_INTSTS, status);

	/*
	 * unsolicited response from pins, maybe something plugged in or out
	 * of the jack.
	 */
	if (status & AUDIOHD_CIS_MASK) {
		/* clear the unsolicited response interrupt */
		rirbsts = AUDIOHD_REG_GET8(AUDIOHD_REG_RIRBSTS);
		AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBSTS, rirbsts);
		/*
		 * We have to wait and try several times to make sure the
		 * unsolicited response is generated by our pins.
		 * we need to make it work for audiohd spec 0.9, which is
		 * just a draft version and requires more time to wait.
		 */
		for (i = 0; i < AUDIOHD_TEST_TIMES; i++) {
			ret = audiohd_response_from_codec(statep, &resp,
			    &respex);
			if ((ret == AUDIO_SUCCESS) &&
			    (respex & AUDIOHD_RIRB_UR_MASK)) {
				/*
				 * A pin may generate more than one ur rirb,
				 * we only need handle one of them, and clear
				 * the other ones
				 */
				statep->hda_rirb_rp =
				    AUDIOHD_REG_GET16(AUDIOHD_REG_RIRBWP) &
				    AUDIOHD_RIRB_WPMASK;
				break;
			}
			drv_usecwait(30);
		}
		if ((ret == AUDIO_SUCCESS) &&
		    (respex & AUDIOHD_RIRB_UR_MASK))
			audiohd_pin_sense(statep, resp, respex);
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

	ATRACE_32("audiohd_ad_start_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);
	mutex_enter(&statep->hda_mutex);
	if (statep->hda_flags & AUDIOHD_PLAY_STARTED) {
		mutex_exit(&statep->hda_mutex);
		audiohd_set_idle(statep);
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
		audiohd_set_idle(statep);
		return (AUDIO_SUCCESS);
	}

	if (audiohd_reset_stream(statep, statep->hda_input_streams)
	    != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_play() failed to reset play stream");
		mutex_exit(&statep->hda_mutex);
		audiohd_set_idle(statep);
		return (AUDIO_FAILURE);
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

	/* clear status */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_STS,
	    AUDIOHDR_SD_STS_BCIS | AUDIOHDR_SD_STS_FIFOE |
	    AUDIOHDR_SD_STS_DESE);

	/* set playback stream tag */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL +
	    AUDIOHD_PLAY_CTL_OFF,
	    (statep->hda_play_stag) << AUDIOHD_PLAY_TAG_OFF);

	/* Enable interrupt and start DMA */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);

	mutex_exit(&statep->hda_mutex);
	audiohd_set_idle(statep);
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
	audiohd_ostream_t	*ostream;
	audiohd_istream_t	*istream;
	hda_codec_t		*codec;
	uint_t		caddr;
	int			i;

	/*
	 * we will support other format later. For the time being,
	 * AUDIOHD_FMT_PCMOUT is used for 48k-16bit-2channel.
	 */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);
	mutex_enter(&statep->hda_mutex);

	if (dir == AUDIO_PLAY) {
		statep->hda_psample_rate = sample_rate;
		statep->hda_pchannels = channels;
		statep->hda_pprecision = precision;
		statep->hda_play_format = AUDIOHD_FMT_PCMOUT;

		for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			if (statep->codec[i] == NULL)
				continue;
			codec = statep->codec[i];
			caddr = codec->index;
			ostream = codec->ostream;
			while (ostream) {
				if (ostream->in_use == 0)
					break;
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr, ostream->dac_wid,
				    AUDIOHDC_VERB_SET_CONV_FMT,
				    AUDIOHD_FMT_PCMOUT);
				ostream = ostream->next_stream;
			}
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		statep->hda_csample_rate = sample_rate;
		statep->hda_cchannels = channels;
		statep->hda_cprecision = precision;
		statep->hda_record_format = AUDIOHD_FMT_PCMIN;
		for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
			if (statep->codec[i] == NULL)
				continue;
			codec = statep->codec[i];
			caddr = codec->index;
			istream = codec->istream;
			while (istream) {
				if (istream->in_use == 0)
					break;
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr, istream->adc_wid,
				    AUDIOHDC_VERB_SET_CONV_FMT,
				    AUDIOHD_FMT_PCMOUT);
				istream = istream->next_stream;
			}
		}
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

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audiohd_set_busy(statep);
	mutex_enter(&statep->hda_mutex);
	if (statep->hda_flags & AUDIOHD_RECORD_STARTED) {
		mutex_exit(&statep->hda_mutex);
		audiohd_set_idle(statep);
		return (AUDIO_SUCCESS);
	}

	if (audiohd_reset_stream(statep, 0) != AUDIO_SUCCESS) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!start_record() failed to reset record stream");
		mutex_exit(&statep->hda_mutex);
		audiohd_set_idle(statep);
		return (AUDIO_FAILURE);
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

	/* set stream tag to 1 */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL +
	    AUDIOHD_REC_CTL_OFF,
	    statep->hda_record_stag << AUDIOHD_REC_TAG_OFF);
	statep->hda_flags |= AUDIOHD_RECORD_STARTED;

	/* start DMA */
	AUDIOHD_REG_SET8(regbase + AUDIOHD_SDREG_OFFSET_CTL,
	    AUDIOHDR_SD_CTL_INTS | AUDIOHDR_SD_CTL_SRUN);

	mutex_exit(&statep->hda_mutex);
	audiohd_set_idle(statep);
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
	statep->hda_busy_cnt = 0;
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

	if (pci_config_setup(dip, &statep->hda_pci_handle) == DDI_FAILURE) {
		audio_sup_log(ahandle, CE_WARN,
		    "!map_regs() pci config mapping failed");
		goto err_init_pci_exit1;
	}

	if (ddi_regs_map_setup(dip, 1, &statep->hda_reg_base, 0,
	    0, acc_attr, &statep->hda_reg_handle) != DDI_SUCCESS) {
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
		    AUDIOHD_INTEL_PCI_TCSEL, (cTmp & AUDIOHD_INTEL_TCS_MASK));
		break;

	case AUDIOHD_VID_ATI:
		/*
		 * Refer to ATI SB450 datesheet. We set snoop for SB450
		 * like hardware.
		 */
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_ATI_PCI_MISC2);
		pci_config_put8(statep->hda_pci_handle, AUDIOHD_ATI_PCI_MISC2,
		    (cTmp & AUDIOHD_ATI_MISC2_MASK) | AUDIOHD_ATI_MISC2_SNOOP);
		break;
		/*
		 * Refer to the datasheet, we set snoop for NVIDIA
		 * like hardware
		 */
	case AUDIOHD_VID_NVIDIA:
		cTmp = pci_config_get8(statep->hda_pci_handle,
		    AUDIOHD_CORB_SIZE_OFF);
		pci_config_put8(statep->hda_pci_handle, AUDIOHD_CORB_SIZE_OFF,
		    cTmp | AUDIOHD_NVIDIA_SNOOP);
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
	uint16_t	sTmp;
	uint32_t	gctl;

	/* Reset Status register but preserve the first bit */
	sTmp = AUDIOHD_REG_GET16(AUDIOHD_REG_STATESTS);
	AUDIOHD_REG_SET16(AUDIOHD_REG_STATESTS, sTmp & 0x8000);

	/* reset controller */
	gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL);
	gctl &= ~AUDIOHDR_GCTL_CRST;
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL, gctl);  /* entering reset state */
	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empirical testing time: 150 */
		drv_usecwait(150);
		gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL);
		if ((gctl & AUDIOHDR_GCTL_CRST) == 0)
			break;
	}

	if ((gctl & AUDIOHDR_GCTL_CRST) != 0) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!reset_controller() failed to enter reset state");
		return (AUDIO_FAILURE);
	}

	/* Empirical testing time:300 */
	drv_usecwait(300);

	/* exit reset state */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL, gctl | AUDIOHDR_GCTL_CRST);

	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empirical testing time: 150, which works well */
		drv_usecwait(150);
		gctl = AUDIOHD_REG_GET32(AUDIOHD_REG_GCTL);
		if (gctl & AUDIOHDR_GCTL_CRST)
			break;
	}

	if ((gctl & AUDIOHDR_GCTL_CRST) == 0) {
		audio_sup_log(statep->hda_ahandle, CE_WARN,
		    "!reset_controller() failed to exit reset state");
		return (AUDIO_FAILURE);
	}

	/* HD spec requires to wait 250us at least. we use 500us */
	drv_usecwait(500);

	ATRACE_32("in reset_controller: mask is",
	    AUDIOHD_REG_GET16(AUDIOHD_REG_STATESTS));

	/* enable unsolicited response */
	AUDIOHD_REG_SET32(AUDIOHD_REG_GCTL,
	    gctl |  AUDIOHDR_GCTL_URESPE);

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
	    DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&pdma->ad_vaddr, &pdma->ad_real_sz,
	    &pdma->ad_acchdl) != DDI_SUCCESS) {
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
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN |
	    AUDIOHDR_RIRBCTL_RINTCTL);

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

	audiohd_restore_codec_gpio(statep);
	audiohd_restore_path(statep);
	return (audiohd_init_ports(statep));
}	/* audiohd_reinit_hda */

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

	statep->hda_input_streams = (gcap & AUDIOHDR_GCAP_INSTREAMS) >>
	    AUDIOHD_INSTR_NUM_OFF;
	statep->hda_output_streams = (gcap & AUDIOHDR_GCAP_OUTSTREAMS) >>
	    AUDIOHD_OUTSTR_NUM_OFF;
	statep->hda_streams_nums = statep->hda_input_streams +
	    statep->hda_output_streams;

	statep->hda_record_stag = 1;
	statep->hda_play_stag = statep->hda_input_streams + 1;
	statep->hda_record_regbase = AUDIOHD_REG_SD_BASE;
	statep->hda_play_regbase = AUDIOHD_REG_SD_BASE + AUDIOHD_REG_SD_LEN *
	    statep->hda_input_streams;

	ATRACE_16("GCAP = ", gcap);

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
	AUDIOHD_REG_SET8(AUDIOHD_REG_RIRBCTL, AUDIOHDR_RIRBCTL_DMARUN |
	    AUDIOHDR_RIRBCTL_RINTCTL);

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
 * audiohd_get_conns_from_entry()
 *
 * Description:
 *	Get connection list from every entry for a widget
 */
static void
audiohd_get_conns_from_entry(hda_codec_t *codec, audiohd_widget_t *widget,
    uint32_t entry, audiohd_entry_prop_t *prop)
{
	int	i, k, num;
	wid_t	input_wid;

	for (i = 0; i < prop->conns_per_entry &&
	    widget->nconns < prop->conn_len;
	    i++, entry >>= prop->bits_per_conn) {
		ASSERT(widget->nconns < AUDIOHD_MAX_CONN);
		input_wid = entry & prop->mask_wid;
		if (entry & prop->mask_range) {
			if (widget->nconns == 0) {
				if (input_wid < codec->first_wid ||
				    (input_wid > codec->last_wid)) {
					ATRACE_32(
					    "collection list out of range",
					    widget->wid_wid);
					break;
				}
				widget->avail_conn[widget->nconns++] =
				    input_wid;
			} else {
				for (k = widget->avail_conn[widget->nconns-1] +
				    1; k <= input_wid; k++) {
					ASSERT(widget->nconns <
					    AUDIOHD_MAX_CONN);
					if (k < codec->first_wid ||
					    (k > codec->last_wid)) {
						ATRACE_32(
						    "collection out of range",
						    widget->wid_wid);
						break;
					} else {
						num = widget->nconns;
						widget->avail_conn[num] = k;
						widget->nconns++;
					}
				}
			}
		} else {
			if ((codec->first_wid <= input_wid) && (input_wid <=
			    codec->last_wid))
				widget->avail_conn[widget->nconns++] =
				    input_wid;
		}
	}
}

/*
 * audiohd_get_conns()
 *
 * Description:
 *	Get all connection list for a widget. The connection list is used for
 *	build output path, input path, and monitor path
 */
static void
audiohd_get_conns(hda_codec_t *codec, wid_t wid)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_widget_t	*widget = codec->widget[wid];
	uint8_t	caddr = codec->index;
	uint32_t	entry;
	audiohd_entry_prop_t	prop;
	wid_t	input_wid;
	int	i;

	prop.conn_len = audioha_codec_verb_get(statep, caddr, wid,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_CONNLIST_LEN);

	if (prop.conn_len & AUDIOHD_FORM_MASK) {
		prop.conns_per_entry = 2;
		prop.bits_per_conn = 16;
		prop.mask_range = 0x00008000;
		prop.mask_wid = 0x00007fff;
	} else {
		prop.conns_per_entry = 4;
		prop.bits_per_conn = 8;
		prop.mask_range = 0x00000080;
		prop.mask_wid = 0x0000007f;
	}
	prop.conn_len &= AUDIOHD_LEN_MASK;

	/*
	 * This should not happen since the ConnectionList bit of
	 * widget capabilities already told us that this widget
	 * has a connection list
	 */
	if (prop.conn_len == 0) {
		widget->nconns = 0;
		cmn_err(CE_WARN, "node %d has 0 connections\n", wid);
		return;
	}

	if (prop.conn_len == 1) {
		entry = audioha_codec_verb_get(statep, caddr,
		    wid, AUDIOHDC_VERB_GET_CONN_LIST_ENT, 0);
		input_wid = entry & prop.mask_wid;
		if ((input_wid < codec->first_wid) ||
		    (input_wid > codec->last_wid)) {
			ATRACE("node input out of range:", NULL);
			ATRACE_32("node:", wid);
			ATRACE_32("input:", input_wid);
			return;
		}
		widget->avail_conn[0] = input_wid;
		widget->nconns = 1;
		return;
	}
	widget->nconns = 0;
	for (i = 0; i < prop.conn_len; i += prop.conns_per_entry) {
		entry = audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_GET_CONN_LIST_ENT, i);
		audiohd_get_conns_from_entry(codec, widget, entry, &prop);
	}
}

/*
 * Read PinCapabilities & default configuration
 */
static void
audiohd_get_pin_config(audiohd_widget_t *widget)
{
	hda_codec_t		*codec = widget->codec;
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_pin_t		*pin, *prev, *p;

	int		caddr = codec->index;
	wid_t		wid = widget->wid_wid;
	uint32_t	cap, config, pinctrl;
	uint8_t		urctrl, vrefbits;

	cap = audioha_codec_verb_get(statep, caddr, wid,
	    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_PIN_CAP);
	config = audioha_codec_verb_get(statep, caddr,
	    wid, AUDIOHDC_VERB_GET_DEFAULT_CONF, 0);
	pinctrl = audioha_codec_verb_get(statep, caddr,
	    wid, AUDIOHDC_VERB_GET_PIN_CTRL, 0);

	pin = (audiohd_pin_t *)kmem_zalloc(sizeof (audiohd_pin_t), KM_SLEEP);
	widget->priv = pin;

	/*
	 * If the pin has no physical connection for port,
	 * we won't link it to pin linkage list ???
	 */
	if (((config >> AUDIOHD_PIN_CON_STEP) & AUDIOHD_PIN_CON_MASK) == 0x1) {
		pin->no_phys_conn = 1;
	}

	/* bit 4:3 are reserved, read-modify-write is needed */
	pin->ctrl = pinctrl & AUDIOHD_PIN_IO_MASK;
	pin->wid = wid;
	pin->cap = cap;
	pin->config = config;
	pin->num = 0;
	pin->finish = 0;
	/*
	 * get the voltage reference state supported by the pin
	 * from high level to low level
	 */
	vrefbits = (cap >> AUDIOHD_PIN_VREF_OFF) & AUDIOHD_PIN_VREF_MASK;
	if (vrefbits & AUDIOHD_PIN_VREF_L1)
		pin->vrefvalue = 0x5;
	else if (vrefbits & AUDIOHD_PIN_VREF_L2)
		pin->vrefvalue = 0x4;
	else if (vrefbits & AUDIOHD_PIN_VREF_L3)
		pin->vrefvalue = 0x2;
	else
		pin->vrefvalue = 0x1;

	pin->seq = config & AUDIOHD_PIN_SEQ_MASK;
	pin->assoc = (config & AUDIOHD_PIN_ASO_MASK) >> AUDIOHD_PIN_ASO_OFF;
	pin->device = (config & AUDIOHD_PIN_DEV_MASK) >> AUDIOHD_PIN_DEV_OFF;

	/* enable the unsolicited response of the pin */
	if ((widget->widget_cap & AUDIOHD_URCAP_MASK) &&
	    (pin->cap & AUDIOHD_DTCCAP_MASK) &&
	    ((pin->device == DTYPE_LINEOUT) ||
	    (pin->device == DTYPE_SPDIF_OUT) ||
	    (pin->device == DTYPE_HP_OUT) ||
	    (pin->device == DTYPE_MIC_IN))) {
			urctrl = (uint8_t)(1 << (AUDIOHD_UR_ENABLE_OFF - 1));
			urctrl |= (wid & AUDIOHD_UR_TAG_MASK);
			(void) audioha_codec_verb_get(statep, caddr,
			    wid, AUDIOHDC_VERB_SET_URCTRL, urctrl);
	}
	/* accommodate all the pins in a link list sorted by assoc and seq */
	if (codec->first_pin == NULL) {
		codec->first_pin = pin;
	} else {
		prev = NULL;
		p = codec->first_pin;
		while (p) {
			if (p->assoc > pin->assoc)
				break;
			if ((p->assoc == pin->assoc) &&
			    (p->seq > pin->seq))
				break;
			prev = p;
			p = p->next;
		}
		if (prev) {
			pin->next = prev->next;
			prev->next = pin;
		} else {
			pin->next = codec->first_pin;
			codec->first_pin = pin;
		}
	}

}	/* audiohd_get_pin_config() */

/*
 * audiohd_create_widgets()
 *
 * Description:
 *	All widgets are created and stored in an array of codec
 */
static int
audiohd_create_widgets(hda_codec_t *codec)
{
	audiohd_widget_t	*widget;
	audiohd_state_t		*statep = codec->soft_statep;
	wid_t	wid;
	uint32_t	type, widcap;
	int		caddr = codec->index;

	for (wid = codec->first_wid;
	    wid <= codec->last_wid; wid++) {
		widget = (audiohd_widget_t *)
		    kmem_zalloc(sizeof (audiohd_widget_t), KM_SLEEP);
		codec->widget[wid] = widget;
		widget->codec = codec;
		widget->selconn = AUDIOHD_NULL_CONN;

		widcap = audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_AUDIO_WID_CAP);
		type = AUDIOHD_WIDCAP_TO_WIDTYPE(widcap);
		widget->wid_wid = wid;
		widget->type = type;
		widget->widget_cap = widcap;
		widget->finish = 0;
		widget->used = 0;

		/* if there's connection list */
		if (widcap & AUDIOHD_WIDCAP_CONNLIST) {
			audiohd_get_conns(codec, wid);
		}

		/* if power control, power it up to D0 state */
		if (widcap & AUDIOHD_WIDCAP_PWRCTRL) {
			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_POWER_STATE, 0);
		}

		/*
		 * if this widget has format override, we read it.
		 * Otherwise, it uses the format of audio function.
		 */
		if (widcap & AUDIOHD_WIDCAP_FMT_OVRIDE) {
			widget->pcm_format =
			    audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_PCM);
		} else {
			widget->pcm_format = codec->pcm_format;
		}

		/*
		 * Input amplifier. Has the widget input amplifier ?
		 */
		if (widcap & AUDIOHD_WIDCAP_INAMP) {
			/*
			 * if overrided bit is 0, use the default
			 * amplifier of audio function as HD spec.
			 * Otherwise, we read it.
			 */
			if ((widcap & AUDIOHD_WIDCAP_AMP_OVRIDE) == 0)
				widget->inamp_cap = codec->inamp_cap;
			else
				widget->inamp_cap =
				    audioha_codec_verb_get(statep, caddr, wid,
				    AUDIOHDC_VERB_GET_PARAM,
				    AUDIOHDC_PAR_INAMP_CAP);
		} else {
			widget->inamp_cap = 0;
		}

		/*
		 * output amplifier. Has this widget output amplifier ?
		 */
		if (widcap & AUDIOHD_WIDCAP_OUTAMP) {
			if ((widcap & AUDIOHD_WIDCAP_AMP_OVRIDE) == 0)
				widget->outamp_cap = codec->outamp_cap;
			else
				widget->outamp_cap =
				    audioha_codec_verb_get(statep, caddr, wid,
				    AUDIOHDC_VERB_GET_PARAM,
				    AUDIOHDC_PAR_OUTAMP_CAP);
		} else {
			widget->outamp_cap = 0;
		}

		switch (type) {
		case WTYPE_AUDIO_OUT:
		case WTYPE_AUDIO_IN:
		case WTYPE_AUDIO_MIX:
		case WTYPE_AUDIO_SEL:
		case WTYPE_VENDOR:
		case WTYPE_POWER:
		case WTYPE_VOL_KNOB:
			break;
		case WTYPE_PIN:
			audiohd_get_pin_config(widget);
			break;
		case WTYPE_BEEP:
			ATRACE("Get a beep widget", NULL);
			break;
		default:
			ATRACE("Unknown widget", NULL);
			break;
		}
	}

	return (DDI_SUCCESS);

}	/* audiohd_create_widgets() */

/*
 * audiohd_destroy_widgets()
 */
static void
audiohd_destroy_widgets(hda_codec_t *codec)
{
	for (int i = 0; i < AUDIOHD_MAX_WIDGET; i++) {
		if (codec->widget[i]) {
			kmem_free(codec->widget[i], sizeof (audiohd_widget_t));
			codec->widget[i] = NULL;
		}
	}

}	/* audiohd_destroy_widgets() */

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
	hda_codec_t	*codec;
	uint32_t	mask, type;
	uint32_t	nums;
	uint32_t	i, j;
	wid_t		wid;

	mask = statep->hda_codec_mask;
	ASSERT(mask != 0);

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if ((mask & (1 << i)) == 0)
			continue;
		codec = (hda_codec_t *)kmem_zalloc(
		    sizeof (hda_codec_t), KM_SLEEP);
		codec->index = i;
		codec->vid = audioha_codec_verb_get(statep, i,
		    AUDIOHDC_NODE_ROOT, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_VENDOR_ID);
		codec->revid =
		    audioha_codec_verb_get(statep, i,
		    AUDIOHDC_NODE_ROOT, AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_REV_ID);

		nums = audioha_codec_verb_get(statep,
		    i, AUDIOHDC_NODE_ROOT,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_NODE_COUNT);
		if (nums == (uint32_t)(-1)) {
			kmem_free(codec, sizeof (hda_codec_t));
			continue;
		}
		wid = (nums >> AUDIOHD_CODEC_STR_OFF) & AUDIOHD_CODEC_STR_MASK;
		nums = nums & AUDIOHD_CODEC_NUM_MASK;

		/*
		 * Assume that each codec has just one audio function group
		 */
		for (j = 0; j < nums; j++, wid++) {
			type = audioha_codec_verb_get(statep, i, wid,
			    AUDIOHDC_VERB_GET_PARAM,
			    AUDIOHDC_PAR_FUNCTION_TYPE);
			if ((type & AUDIOHD_CODEC_TYPE_MASK) ==
			    AUDIOHDC_AUDIO_FUNC_GROUP) {
				codec->wid_afg = wid;
				break;
			}
		}

		if (codec->wid_afg == 0) {
			kmem_free(codec, sizeof (hda_codec_t));
			continue;
		}

		ASSERT(codec->wid_afg == wid);
		/*
		 * GPIO controls which are laptop specific workarounds and
		 * might be changed. Some laptops use GPIO, so we need to
		 * enable and set the GPIO correctly.
		 */
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_MASK, AUDIOHDC_GPIO_ENABLE);
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_DIREC, AUDIOHDC_GPIO_DIRECT);
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_STCK, AUDIOHDC_GPIO_DATA_CTRL);
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_GPIO_DATA, AUDIOHDC_GPIO_STCK_CTRL);

		/* power-up audio function group */
		(void) audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_SET_POWER_STATE, 0);

		/* subsystem id is attached to funtion group */
		codec->outamp_cap = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_OUTAMP_CAP);
		codec->inamp_cap = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_INAMP_CAP);
		codec->stream_format = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_STREAM);
		codec->pcm_format = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM, AUDIOHDC_PAR_PCM);

		nums = audioha_codec_verb_get(statep, i, wid,
		    AUDIOHDC_VERB_GET_PARAM,
		    AUDIOHDC_PAR_NODE_COUNT);
		wid = (nums >> AUDIOHD_CODEC_STR_OFF) & AUDIOHD_CODEC_STR_MASK;
		nums = nums & AUDIOHD_CODEC_NUM_MASK;
		codec->first_wid = wid;
		codec->last_wid = wid + nums;
		codec->nnodes = nums;

		/*
		 * We output the codec information to syslog
		 */
		ATRACE_32("codec = ", codec->index);
		ATRACE_32("vid = ", codec->vid);
		ATRACE_32("rev = ", codec->revid);

		statep->codec[i] = codec;
		codec->soft_statep = statep;
		(void) audiohd_create_widgets(codec);
	}

	return (AUDIO_SUCCESS);

}	/* audiohd_create_codec() */

/*
 * audiohd_destroy_codec()
 *
 * Description:
 *	destroy codec structure, and release its memory
 */
static void
audiohd_destroy_codec(audiohd_state_t *statep)
{
	audiohd_ostream_t    *ostream, *nostream;
	audiohd_istream_t    *istream, *nistream;
	audiohd_pin_t		*pin, *npin;

	for (int i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i]) {
			audiohd_destroy_widgets(statep->codec[i]);

			/*
			 * free output streams
			 */
			ostream = statep->codec[i]->ostream;
			while (ostream) {
				nostream = ostream;
				ostream = ostream->next_stream;
				kmem_free(nostream, sizeof (audiohd_ostream_t));
			}

			/*
			 * free input streams
			 */
			istream = statep->codec[i]->istream;
			while (istream) {
				nistream = istream;
				istream = istream->next_stream;
				kmem_free(nistream, sizeof (audiohd_istream_t));
			}

			/*
			 * free pins
			 */
			pin = statep->codec[i]->first_pin;
			while (pin) {
				npin = pin;
				pin = pin->next;
				kmem_free(npin, sizeof (audiohd_pin_t));
			}

			kmem_free(statep->codec[i], sizeof (hda_codec_t));
			statep->codec[i] = NULL;
		}
	}
}	/* audiohd_destroy_codec() */

/*
 * audiohd_find_dac()
 * Description:
 *	Find a dac for a output path. Then the play data can be sent to the out
 *	put pin through the output path.
 *
 * Arguments:
 *	hda_codec_t	*codec		where the dac widget exists
 *	wid_t		wid		the no. of a widget
 *	int		mixer		whether the path need mixer or not
 *	int		*mixernum	the total of mixer in the output path
 *	int		exclusive	an exclusive path or share path
 *	int		depth		the depth of search
 *
 * Return:
 *	1) wid of the first shared widget in the path from
 *	   pin to DAC if exclusive is 0;
 *	2) wid of DAC widget;
 *	3) 0 if no path
 */
static wid_t
audiohd_find_dac(hda_codec_t *codec, wid_t wid,
    int mixer, int *mixernum,
    int exclusive, int depth)
{
	audiohd_widget_t	*widget = codec->widget[wid];
	wid_t	wdac = (uint32_t)(AUDIO_FAILURE);
	wid_t	retval;

	if (depth > AUDIOHD_MAX_DEPTH)
		return (uint32_t)(AUDIO_FAILURE);

	if (widget == NULL)
		return (uint32_t)(AUDIO_FAILURE);
	/*
	 * If exclusive is true, we try to find a path which doesn't
	 * share any widget with other paths.
	 */
	if (exclusive) {
		if (widget->path_flags & AUDIOHD_PATH_DAC)
			return (uint32_t)(AUDIO_FAILURE);
	} else {
		if (widget->path_flags & AUDIOHD_PATH_DAC)
			return (wid);
	}

	switch (widget->type) {
	case WTYPE_AUDIO_OUT:
		/* We need mixer widget, but the the mixer num is 0, failed  */
		if (mixer && !*mixernum)
			return (uint32_t)(AUDIO_FAILURE);
		widget->path_flags |= AUDIOHD_PATH_DAC;
		widget->out_weight++;
		wdac = widget->wid_wid;
		ATRACE_32("(DAC:", widget->wid_wid);
		break;

	case WTYPE_AUDIO_MIX:
	case WTYPE_AUDIO_SEL:
		if (widget->type == WTYPE_AUDIO_MIX)
			(*mixernum)++;
		for (int i = 0; i < widget->nconns; i++) {
			retval = audiohd_find_dac(codec,
			    widget->avail_conn[i],
			    mixer, mixernum,
			    exclusive, depth + 1);
			if (retval != (uint32_t)AUDIO_FAILURE) {
				if (widget->selconn == AUDIOHD_NULL_CONN) {
					widget->selconn = i;
					wdac = retval;
				}
				ATRACE_32("widget:", widget->wid_wid);
				ATRACE_32("type:", widget->type);
				widget->path_flags |= AUDIOHD_PATH_DAC;
				widget->out_weight++;

				/* return when found a path */
				return (wdac);
			}
		}
	default:
		break;
	}

	return (wdac);
}	/* audiohd_find_dac() */

/*
 * audiohd_do_build_output_path()
 *
 * Description:
 *	Search an output path for each pin in the codec.
 * Arguments:
 *	hda_codec_t	*codec		where the output path exists
 *	int		mixer		wheter the path needs mixer widget
 *	int		*mnum		total of mixer widget in the path
 *	int		exclusive	an exclusive path or shared path
 *	int		depth		search depth
 */
static void
audiohd_do_build_output_path(hda_codec_t *codec, int mixer, int *mnum,
    int exclusive, int depth)
{
	audiohd_pin_t		*pin;
	audiohd_widget_t	*widget, *wdac;
	audiohd_ostream_t	*ostream;
	wid_t			wid;
	int			i;

	for (pin = codec->first_pin; pin; pin = pin->next) {
		if ((pin->cap & AUDIOHD_PIN_CAP_MASK) == 0)
			continue;
		if ((pin->config & AUDIOHD_PIN_CONF_MASK) ==
		    AUDIOHD_PIN_NO_CONN)
			continue;
		if ((pin->device != DTYPE_LINEOUT) &&
		    (pin->device != DTYPE_SPEAKER) &&
		    (pin->device != DTYPE_SPDIF_OUT) &&
		    (pin->device != DTYPE_HP_OUT))
			continue;
		if (pin->finish)
			continue;
		widget = codec->widget[pin->wid];

		widget->inamp_cap = 0;
		for (i = 0; i < widget->nconns; i++) {
			/*
			 * If a dac found, the return value is the wid of the
			 * widget on the path, or the return value is
			 * AUDIO_FAILURE
			 */
			wid = audiohd_find_dac(codec,
			    widget->avail_conn[i], mixer, mnum, exclusive,
			    depth);
			/*
			 * A dac was not found
			 */
			if (wid == (wid_t)AUDIO_FAILURE)
				continue;
			ostream = (audiohd_ostream_t *)
			    kmem_zalloc(sizeof (audiohd_ostream_t),
			    KM_SLEEP);
			ostream->dac_wid = wid;
			ostream->pin_wid[0] = widget->wid_wid;
			ostream->pin_nums = 1;
			wdac = codec->widget[wid];
			wdac->priv = ostream;
			pin->adc_dac_wid = wid;
			pin->finish = 1;
			ATRACE_32("widget:", widget->wid_wid);
			ATRACE_32("type:", widget->type);
			widget->path_flags |= AUDIOHD_PATH_DAC;
			widget->out_weight++;
			widget->selconn = i;
			if (codec->ostream == NULL)
				codec->ostream = ostream;
			else {
				audiohd_ostream_t *p = codec->ostream;
				while (p->next_stream)
					p = p->next_stream;
				p->next_stream = ostream;
			}
			break;
		}
	}

}	/* audiohd_do_build_output_path() */

/*
 * audiohd_build_output_path()
 *
 * Description:
 *	Build the output path in the codec for every pin.
 *	First we try to search output path with mixer widget exclusively
 *	Then we try to search shared output path with mixer widget.
 *	Then we try to search output path without mixer widget exclusively.
 *	At last we try to search shared ouput path for the remained pins
 */
static void
audiohd_build_output_path(hda_codec_t *codec)
{
	audiohd_pin_t		*pin;
	int 			mnum = 0;

	/* search an exclusive mixer widget path. This is preferred */
	audiohd_do_build_output_path(codec, 1, &mnum, 1, 0);

	/* search a shared mixer widget path for the remained pins */
	audiohd_do_build_output_path(codec, 1, &mnum, 0, 0);

	/* search an exclusive widget path without mixer for the remained pin */
	audiohd_do_build_output_path(codec, 0, &mnum, 1, 0);

	/* search a shared widget path without mixer for the remained pin */
	audiohd_do_build_output_path(codec, 0, &mnum, 0, 0);

	for (pin = codec->first_pin; pin; pin = pin->next) {
		if ((pin->cap & AUDIOHD_PIN_CAP_MASK) == 0) {
			continue;
		}
		if ((pin->config & AUDIOHD_PIN_CONF_MASK) ==
		    AUDIOHD_PIN_NO_CONN)
			continue;
		if ((pin->device != DTYPE_LINEOUT) &&
		    (pin->device != DTYPE_SPEAKER) &&
		    (pin->device != DTYPE_SPDIF_OUT) &&
		    (pin->device != DTYPE_HP_OUT))
			continue;
		if (!pin->finish) {
			ATRACE_32("pin has no output path:", pin->wid);
		}
	}
}	/* audiohd_build_output_path */

/*
 * audiohd_build_output_amp
 *
 * Description:
 *	Find the gain control and mute control widget
 */
static void
audiohd_build_output_amp(hda_codec_t *codec)
{
	audiohd_ostream_t	*ostream;
	audiohd_widget_t	*w, *widget, *wpin, *wdac;
	audiohd_pin_t		*pin;
	wid_t		wid;
	int		weight;
	int		i;
	uint32_t	gain;

	ostream = codec->ostream;
	while (ostream) {
		for (i = 0; i < ostream->pin_nums; i++) {
			wid = ostream->pin_wid[i];
			wpin = codec->widget[wid];
			pin = (audiohd_pin_t *)wpin->priv;
			weight = wpin->out_weight;

			/*
			 * search a node which can mute this pin while
			 * the mute functionality doesn't effect other
			 * pins.
			 */
			widget = wpin;
			while (widget) {
				if (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					pin->mute_wid = widget->wid_wid;
					pin->mute_dir = AUDIOHDC_AMP_SET_OUTPUT;
					break;
				}
				if (widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					pin->mute_wid = widget->wid_wid;
					pin->mute_dir = AUDIOHDC_AMP_SET_INPUT;
					break;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
				if (widget && widget->out_weight != weight)
					break;
			}

			/*
			 * We select the wid which has maxium gain range in
			 * the output path. Meanwhile, the gain controlling
			 * of this node doesn't effect other pins if this
			 * output stream has multiple pins.
			 */
			gain = 0;
			widget = wpin;
			while (widget) {
				gain = (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS);
				if (gain && gain > pin->gain_bits) {
					pin->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
					pin->gain_bits = gain;
					pin->gain_wid = widget->wid_wid;
				}
				gain = widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS;
				if (gain && gain > pin->gain_bits) {
					pin->gain_dir = AUDIOHDC_AMP_SET_INPUT;
					pin->gain_bits = gain;
					pin->gain_wid = widget->wid_wid;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
				if (widget && widget->out_weight != weight)
					break;
			}
			pin->gain_bits >>= AUDIOHD_GAIN_OFF;
		}

		/*
		 * if this stream has multiple pins, we try to find
		 * a mute & gain-controlling nodes which can effect
		 * all output pins of this stream to be used for the
		 * whole stream
		 */
		if (ostream->pin_nums == 1) {
			ostream->mute_wid = pin->mute_wid;
			ostream->mute_dir = pin->mute_dir;
			ostream->gain_wid = pin->gain_wid;
			ostream->gain_dir = pin->gain_dir;
			ostream->gain_bits = pin->gain_bits;
		} else {
			wdac = codec->widget[ostream->dac_wid];
			weight = wdac->out_weight;
			wid = ostream->pin_wid[0];
			w = codec->widget[wid];
			while (w && w->out_weight != weight) {
				wid = w->avail_conn[w->selconn];
				w = codec->widget[wid];
			}

			/* find mute controlling node for this stream */
			widget = w;
			while (widget) {
				if (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					ostream->mute_wid = widget->wid_wid;
					ostream->mute_dir =
					    AUDIOHDC_AMP_SET_OUTPUT;
					break;
				}
				if (widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_MUTE_CAP) {
					ostream->mute_wid = widget->wid_wid;
					ostream->mute_dir =
					    AUDIOHDC_AMP_SET_INPUT;
					break;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}

			/* find volume controlling node for this stream */
			gain = 0;
			widget = w;
			while (widget) {
				gain = (widget->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS);
				if (gain && gain > pin->gain_bits) {
					ostream->gain_dir =
					    AUDIOHDC_AMP_SET_OUTPUT;
					ostream->gain_bits = gain;
					ostream->gain_wid = widget->wid_wid;
				}
				gain = widget->inamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS;
				if (gain && (gain > pin->gain_bits) &&
				    (widget->type != WTYPE_AUDIO_MIX)) {
					ostream->gain_dir =
					    AUDIOHDC_AMP_SET_INPUT;
					ostream->gain_bits = gain;
					ostream->gain_wid = widget->wid_wid;
				}
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}
			ostream->gain_bits >>= AUDIOHD_GAIN_OFF;
		}

		ostream = ostream->next_stream;
	}

}	/* audiohd_build_output_amp */

/*
 * audiohd_finish_output_path()
 *
 * Description:
 *	Enable the widgets on the output path
 */
static void
audiohd_finish_output_path(hda_codec_t *codec)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_ostream_t	*ostream;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	uint_t			caddr = codec->index;
	wid_t			wid;
	int			i;

	ostream = codec->ostream;
	while (ostream) {
		for (i = 0; i < ostream->pin_nums; i++) {
			wid = ostream->pin_wid[i];
			widget = codec->widget[wid];
			pin = (audiohd_pin_t *)widget->priv;
			{
			uint32_t    lTmp;

			lTmp = audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_GET_PIN_CTRL, 0);
			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_PIN_CTRL, (lTmp |
			    pin->vrefvalue |
			    AUDIOHDC_PIN_CONTROL_OUT_ENABLE |
			    AUDIOHDC_PIN_CONTROL_HP_ENABLE) &
			    ~ AUDIOHDC_PIN_CONTROL_IN_ENABLE);
			}
			/* If this pin has external amplifier, enable it */
			if (pin->cap & AUDIOHD_EXT_AMP_MASK)
				(void) audioha_codec_verb_get(statep, caddr,
				    wid, AUDIOHDC_VERB_SET_EAPD,
				    AUDIOHD_EXT_AMP_ENABLE);

			if (widget->outamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr, wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_OUTPUT |
				    AUDIOHDC_GAIN_MAX);
			}

			(void) audioha_codec_verb_get(statep, caddr, wid,
			    AUDIOHDC_VERB_SET_CONN_SEL, widget->selconn);

			wid = widget->avail_conn[widget->selconn];
			widget = codec->widget[wid];

			while (widget) {
				/*
				 * Set all amplifiers in this path to
				 * the maximum
				 * volume and unmute them.
				 */
				if (widget->outamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    wid, AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_OUTPUT |
					    AUDIOHDC_GAIN_MAX);
				}
				if (widget->inamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    wid, AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_INPUT |
					    AUDIOHDC_GAIN_MAX |
					    (widget->selconn <<
					    AUDIOHDC_AMP_SET_INDEX_OFFSET));
				}

				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				/*
				 * Accoding to HD spec, mixer doesn't support
				 * "select connection"
				 */
				if ((widget->type != WTYPE_AUDIO_MIX) &&
				    (widget->nconns > 1))
					(void) audioha_codec_verb_get(statep,
					    caddr,
					    wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    widget->selconn);

				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}
		}
		ostream = ostream->next_stream;
	}
}	/* audiohd_finish_output_path() */

/*
 * audiohd_find_input_pins()
 *
 * Description:
 * 	Here we consider a mixer/selector with multi-input as a real sum
 * 	widget. Only the first real mixer/selector widget is permitted in
 * 	an input path(recording path). If there are more mixers/selectors
 * 	execept the first one, only the first input/connection of those
 * 	widgets will be used by our driver, that means, we ignore other
 * 	inputs of those mixers/selectors.
 */
static int
audiohd_find_input_pins(hda_codec_t *codec, wid_t wid, int allowmixer,
    int depth, audiohd_istream_t *istream)
{
	audiohd_widget_t	*widget = codec->widget[wid];
	audiohd_pin_t		*pin;
	audiohd_state_t		*statep = codec->soft_statep;
	uint_t			caddr = codec->index;
	int			retval = -1;
	int			num, i;
	uint32_t		pinctrl;

	if (depth > AUDIOHD_MAX_DEPTH)
		return (uint32_t)(AUDIO_FAILURE);
	if (widget == NULL)
		return (uint32_t)(AUDIO_FAILURE);

	/* we don't share widgets */
	if (widget->path_flags & AUDIOHD_PATH_ADC)
		return (uint32_t)(AUDIO_FAILURE);

	switch (widget->type) {
	case WTYPE_PIN:
		pin = (audiohd_pin_t *)widget->priv;
		if (pin->no_phys_conn)
			return (uint32_t)(AUDIO_FAILURE);
		/* enable the pins' input capability */
		pinctrl = audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_GET_PIN_CTRL, 0);
		(void) audioha_codec_verb_get(statep, caddr, wid,
		    AUDIOHDC_VERB_SET_PIN_CTRL,
		    pinctrl | AUDIOHD_PIN_IN_ENABLE);
		if (pin->cap & AUDIOHD_EXT_AMP_MASK) {
			(void) audioha_codec_verb_get(statep, caddr,
			    wid, AUDIOHDC_VERB_SET_EAPD,
			    AUDIOHD_EXT_AMP_ENABLE);
		}
		switch (pin->device) {
		case DTYPE_CD:
		case DTYPE_LINE_IN:
		case DTYPE_MIC_IN:
		case DTYPE_AUX:
			widget->path_flags |= AUDIOHD_PATH_ADC;
			widget->in_weight++;
			istream->pin_wid[istream->pin_nums++] = wid;
			pin->adc_dac_wid = istream->adc_wid;
			ATRACE_32("Pin in:", wid);
			return (AUDIO_SUCCESS);
		}
		break;
	case WTYPE_AUDIO_MIX:
	case WTYPE_AUDIO_SEL:
		/*
		 * If the sum widget has only one input, we don't
		 * consider it as a real sum widget.
		 */
		if (widget->nconns == 1) {
			widget->selconn = 0;
			retval = audiohd_find_input_pins(codec,
			    widget->avail_conn[0],
			    allowmixer, depth + 1, istream);
			if (retval != AUDIO_FAILURE) {
				widget->path_flags |= AUDIOHD_PATH_ADC;
				widget->in_weight++;
			}
			break;
		}

		if (allowmixer) {
			/*
			 * This is a real sum widget, we will reject
			 * other real sum widget when we find more in
			 * the following path-searching.
			 */
			for (int i = 0; i < widget->nconns; i++) {
				retval = audiohd_find_input_pins(codec,
				    widget->avail_conn[i], 0, depth + 1,
				    istream);
				if (retval != AUDIO_FAILURE) {
					widget->in_weight++;
					num = istream->pin_nums - 1;
					istream->sum_selconn[num] = i;
					istream->sum_wid = wid;
					widget->path_flags |=
					    AUDIOHD_PATH_ADC;
					if (widget->selconn ==
					    AUDIOHD_NULL_CONN) {
						widget->selconn = i;
					}
				}
			}

			/* return SUCCESS if we found at least one input path */
			if (istream->pin_nums > 0)
				retval = AUDIO_SUCCESS;
		} else {
			/*
			 * We had already found a real sum before this one since
			 * allowmixer is 0.
			 */
			for (i = 0; i < widget->nconns; i++) {
				retval = audiohd_find_input_pins(codec,
				    widget->avail_conn[i], 0, depth + 1,
				    istream);
				if (retval != AUDIO_FAILURE) {
					widget->selconn = i;
					widget->path_flags |= AUDIOHD_PATH_ADC;
					widget->in_weight++;
					break;
				}
			}
		}
		break;
	default:
		break;
	}

	return (retval);
}	/* audiohd_find_input_pins */

/*
 * audiohd_build_input_path()
 *
 * Description:
 *	Find input path for the codec
 */
static void
audiohd_build_input_path(hda_codec_t *codec)
{
	audiohd_widget_t	*widget;
	audiohd_istream_t	*istream = NULL;
	wid_t			wid;
	int			i;
	int			retval;
	uint8_t			rtag = 0;

	for (wid = codec->first_wid; wid <= codec->last_wid; wid++) {

		widget = codec->widget[wid];

		/* check if it is an ADC widget */
		if (!widget || widget->type != WTYPE_AUDIO_IN)
			continue;

		if (istream == NULL)
			istream = kmem_zalloc(sizeof (audiohd_istream_t),
			    KM_SLEEP);
		else
			bzero(istream, sizeof (audiohd_istream_t));

		istream->adc_wid = wid;

		/*
		 * Is there any ADC widget which has more than one input ??
		 * I don't believe. Anyway, we carefully deal with this. But
		 * if hardware vendors embed a selector in a ADC, we just use
		 * the first available input, which has connection to input pin
		 * widget. Because selector cannot perform mixer functionality,
		 * and we just permit one selector or mixer in a recording path,
		 * if we use the selector embedded in ADC,we cannot use possible
		 * mixer during path searching.
		 */
		for (i = 0; i < widget->nconns; i++) {
			retval = audiohd_find_input_pins(codec,
			    widget->avail_conn[i], 1, 0, istream);
			if (retval == AUDIO_SUCCESS) {
				istream->rtag = ++rtag;
				codec->nistream++;
				if (codec->istream) {
					audiohd_istream_t	*p =
					    codec->istream;
					while (p->next_stream)
						p = p->next_stream;
					p->next_stream = istream;
				} else {
					codec->istream = istream;
				}
				widget->selconn = i;
				widget->priv = istream;
				istream = NULL;
				break;
			}
		}
	}
	if (istream)
		kmem_free(istream, sizeof (audiohd_istream_t));
}	/* audiohd_build_input_path */

/*
 * audiohd_build_input_amp()
 *
 * Description:
 *	Find gain and mute control widgets on the input path
 */
static void
audiohd_build_input_amp(hda_codec_t *codec)
{
	audiohd_istream_t	*istream;
	audiohd_widget_t	*wsum, *wadc, *w;
	audiohd_pin_t		*pin;
	uint_t			gain;
	wid_t			wid;
	int			i;
	int			weight;

	istream = codec->istream;
	while (istream) {
		wid = istream->adc_wid;
		wadc = codec->widget[wid];
		weight = wadc->in_weight;

		/*
		 * Search node which has mute functionality for
		 * the whole input path
		 */
		w = wadc;
		while (w) {
			if (w->outamp_cap & AUDIOHDC_AMP_CAP_MUTE_CAP) {
				istream->mute_wid = w->wid_wid;
				istream->mute_dir = AUDIOHDC_AMP_SET_OUTPUT;
				break;
			}
			if ((w->inamp_cap & AUDIOHDC_AMP_CAP_MUTE_CAP) &&
			    (w->wid_wid != istream->sum_wid)) {
				istream->mute_wid = w->wid_wid;
				istream->mute_dir = AUDIOHDC_AMP_SET_INPUT;
				break;
			}

			if (w->selconn == AUDIOHD_NULL_CONN)
				break;
			wid = w->avail_conn[w->selconn];
			w = codec->widget[wid];
			if (w && w->in_weight != weight)
				break;
		}

		/*
		 * Search a node for amplifier adjusting for the whole
		 * input path
		 */
		w = wadc;
		gain = 0;
		while (w) {
			gain = (w->outamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS);
			if (gain && gain > istream->gain_bits) {
				istream->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
				istream->gain_bits = gain;
				istream->gain_wid = w->wid_wid;
			}
			gain = w->inamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS;
			if (gain && (gain > istream->gain_bits) &&
			    (w->wid_wid != istream->sum_wid)) {
				istream->gain_dir = AUDIOHDC_AMP_SET_INPUT;
				istream->gain_bits = gain;
				istream->gain_wid = w->wid_wid;
			}
			if (w->selconn == AUDIOHD_NULL_CONN)
				break;
			wid = w->avail_conn[w->selconn];
			w = codec->widget[wid];
		}
		istream->gain_bits >>= AUDIOHD_GAIN_OFF;

		/*
		 * If the input path has one pin only, the mute/amp
		 * controlling is shared by the whole path and pin
		 */
		if (istream->pin_nums == 1) {
			wid = istream->pin_wid[0];
			w = codec->widget[wid];
			pin = (audiohd_pin_t *)w->priv;
			pin->gain_dir = istream->gain_dir;
			pin->gain_bits = istream->gain_bits;
			pin->gain_wid = istream->gain_wid;
			pin->mute_wid = istream->mute_wid;
			pin->mute_dir = istream->mute_dir;
			istream = istream->next_stream;
			continue;
		}

		/*
		 * For multi-pin device, there must be a selector
		 * or mixer along the input path, and the sum_wid
		 * is the widget's node id.
		 */
		wid = istream->sum_wid;
		wsum = codec->widget[wid]; /* sum widget */
		if (wsum == NULL) {
			istream = istream->next_stream;
			continue;
		}

		for (i = 0; i < istream->pin_nums; i++) {
			wid = istream->pin_wid[i];
			w = codec->widget[wid];
			pin = (audiohd_pin_t *)w->priv;

			/* find node for mute */
			if (wsum->inamp_cap & AUDIOHDC_AMP_CAP_MUTE_CAP) {
				pin->mute_wid = wsum->wid_wid;
				pin->mute_dir = AUDIOHDC_AMP_SET_INPUT;
			} else {
				wid = wsum->avail_conn[istream->sum_selconn[i]];
				w = codec->widget[wid];
				while (w) {
					if (w->outamp_cap &
					    AUDIOHDC_AMP_CAP_MUTE_CAP) {
						pin->mute_wid = w->wid_wid;
						pin->mute_dir =
						    AUDIOHDC_AMP_SET_OUTPUT;
						break;
					}
					if (w->inamp_cap &
					    AUDIOHDC_AMP_CAP_MUTE_CAP) {
						pin->mute_wid = w->wid_wid;
						pin->mute_dir =
						    AUDIOHDC_AMP_SET_INPUT;
						break;
					}

					if (w->selconn == AUDIOHD_NULL_CONN)
						break;
					wid = w->avail_conn[w->selconn];
					w = codec->widget[wid];
				}
			}

			/* find node for amp controlling */
			gain = (wsum->inamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS);
			wid = wsum->avail_conn[istream->sum_selconn[i]];
			w = codec->widget[wid];
			while (w) {
				gain = (w->outamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS);
				if (gain && gain > pin->gain_bits) {
					pin->gain_dir = AUDIOHDC_AMP_SET_OUTPUT;
					pin->gain_bits = gain;
					pin->gain_wid = w->wid_wid;
				}
				gain = w->inamp_cap &
				    AUDIOHDC_AMP_CAP_STEP_NUMS;
				if (gain && (gain > pin->gain_bits)) {
					pin->gain_dir = AUDIOHDC_AMP_SET_INPUT;
					pin->gain_bits = gain;
					pin->gain_wid = w->wid_wid;
				}
				if (w->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = w->avail_conn[w->selconn];
				w = codec->widget[wid];
			}
			pin->gain_bits >>= AUDIOHD_GAIN_OFF;
		}
		istream = istream->next_stream;
	}
}	/* audiohd_build_input_amp() */

/*
 * audiohd_finish_input_path()
 *
 * Description:
 *	Enable the widgets on the input path
 */
static void
audiohd_finish_input_path(hda_codec_t *codec)
{
	audiohd_state_t		*statep = codec->soft_statep;
	audiohd_istream_t	*istream;
	audiohd_widget_t	*w, *wsum;
	uint_t			caddr = codec->index;
	wid_t			wid;
	int			i;

	for (istream = codec->istream; istream;
	    istream = istream->next_stream) {
		wid = istream->adc_wid;
		w = codec->widget[wid];
		while (w && (w->wid_wid != istream->sum_wid) &&
		    (w->type != WTYPE_PIN)) {
			if ((w->type == WTYPE_AUDIO_SEL) && (w->nconns > 1))
				(void) audioha_codec_verb_get(statep, caddr,
				    w->wid_wid,
				    AUDIOHDC_VERB_SET_CONN_SEL, w->selconn);

			if (w->outamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    w->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_OUTPUT |
				    AUDIOHDC_GAIN_MAX);
			}

			if (w->inamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    w->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_INPUT |
				    AUDIOHDC_GAIN_MAX |
				    (w->selconn <<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET));
			}

			wid = w->avail_conn[w->selconn];
			w = codec->widget[wid];
		}

		/*
		 * After exiting from the above loop, the widget pointed
		 * by w can be a pin widget or select/mixer widget. If it
		 * is a pin widget, we already finish "select connection"
		 * operation for the whole path.
		 */
		if (w && w->type == WTYPE_PIN)
			continue;

		/*
		 * deal with multi-pin input devices.
		 */
		wid = istream->sum_wid;
		wsum = codec->widget[wid];
		if (wsum == NULL)
			continue;
		if (wsum->outamp_cap) {
			(void) audioha_codec_4bit_verb_get(statep,
			    caddr,
			    wsum->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_LR_OUTPUT |
			    AUDIOHDC_GAIN_MAX);
		}

		for (i = 0; i < istream->pin_nums; i++) {
			if (wsum->inamp_cap) {
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    wsum->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_LR_INPUT |
				    AUDIOHDC_GAIN_MAX |
				    (istream->sum_selconn[i] <<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET));
			}
			if (wsum->type == WTYPE_AUDIO_SEL) {
				(void) audioha_codec_verb_get(statep, caddr,
				    wsum->wid_wid,
				    AUDIOHDC_VERB_SET_CONN_SEL,
				    istream->sum_selconn[i]);
			}

			wid = wsum->avail_conn[istream->sum_selconn[i]];
			w = codec->widget[wid];
			while (w && w->type != WTYPE_PIN) {
				if ((w->type != WTYPE_AUDIO_MIX) &&
				    (w->nconns > 1))
					(void) audioha_codec_verb_get(statep,
					    caddr, w->wid_wid,
					    AUDIOHDC_VERB_SET_CONN_SEL,
					    w->selconn);

				if (w->outamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    w->wid_wid,
					    AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_OUTPUT |
					    AUDIOHDC_GAIN_MAX);
				}

				if (w->inamp_cap) {
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    w->wid_wid,
					    AUDIOHDC_VERB_SET_AMP_MUTE,
					    AUDIOHDC_AMP_SET_LR_INPUT |
					    AUDIOHDC_GAIN_MAX |
					    (w->selconn <<
					    AUDIOHDC_AMP_SET_INDEX_OFFSET));
				}
				wid = w->avail_conn[w->selconn];
				w = codec->widget[wid];
			}
		}
	}	/* end of istream loop */
}	/* audiohd_finish_input_path */

/*
 * audiohd_find_inpin_for_monitor()
 *
 * Description:
 *	Find input pin for monitor path.
 *
 * Arguments:
 *	hda_codec_t		*codec		where the monitor path exists
 *	audiohd_ostream_t	*ostream	output ostream
 *	wid_t			id		no. of widget being searched
 *	int			mixer		share or not
 */
static int
audiohd_find_inpin_for_monitor(hda_codec_t *codec,
    audiohd_ostream_t *ostream, wid_t id, int mixer)
{
	wid_t wid;
	audiohd_widget_t	*widget;
	audiohd_pin_t		*pin;
	int 			i, find = 0;

	wid = id;
	widget = codec->widget[wid];
	if (widget == NULL)
		return (uint32_t)(AUDIO_FAILURE);

	if (widget->type == WTYPE_PIN) {
		pin = (audiohd_pin_t *)widget->priv;
		if (pin->no_phys_conn)
			return (uint32_t)(AUDIO_FAILURE);
		switch (pin->device) {
			case DTYPE_SPDIF_IN:
				ATRACE("Monitor SPDIF found!", NULL);
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (AUDIO_SUCCESS);
			case DTYPE_CD:
				ATRACE("Monitor CD found!", NULL);
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (AUDIO_SUCCESS);
			case DTYPE_LINE_IN:
				ATRACE("Monitor Line in found!", NULL);
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (AUDIO_SUCCESS);
			case DTYPE_MIC_IN:
				ATRACE("Monitor Mic found!", NULL);
				widget->path_flags |= AUDIOHD_PATH_MON;
				return (AUDIO_SUCCESS);
			case DTYPE_AUX:
				widget->path_flags |= AUDIOHD_PATH_MON;
				ATRACE("Monitor AUX found!", NULL);
				return (AUDIO_SUCCESS);
			default:
				return (uint32_t)(AUDIO_FAILURE);
		}
	}
	/* the widget has been visited and can't be directed to input pin */
	if (widget->path_flags & AUDIOHD_PATH_NOMON) {
		return (uint32_t)(AUDIO_FAILURE);
	}
	/* the widget has been used by the monitor path, and we can share it */
	if (widget->path_flags & AUDIOHD_PATH_MON) {
		if (mixer)
			return (AUDIO_SUCCESS);
		else
			return (uint32_t)(AUDIO_FAILURE);
	}
	switch (widget->type) {
		case WTYPE_AUDIO_MIX:
			for (i = 0; i < widget->nconns; i++) {
				if (widget->selconn == i && widget->path_flags &
				    AUDIOHD_PATH_DAC)
					continue;
				if (audiohd_find_inpin_for_monitor(codec,
				    ostream,
				    widget->avail_conn[i], mixer) ==
				    AUDIO_SUCCESS) {
					widget->selmon[widget->used++] = i;
					widget->path_flags |= AUDIOHD_PATH_MON;
					find = 1;
				}
			}
			break;
		case WTYPE_AUDIO_SEL:
			for (i = 0; i < widget->nconns; i++) {
				if (widget->selconn == i && widget->path_flags &
				    AUDIOHD_PATH_DAC)
					continue;
				if (audiohd_find_inpin_for_monitor(codec,
				    ostream,
				    widget->avail_conn[i],
				    mixer) ==
				    AUDIO_SUCCESS) {
					widget->selmon[0] = i;
					widget->path_flags |= AUDIOHD_PATH_MON;
					return (AUDIO_SUCCESS);
				}
			}
		default:
			break;
	}
	if (!find) {
		widget->path_flags |= AUDIOHD_PATH_NOMON;
		return (uint32_t)(AUDIO_FAILURE);
	}
	else
		return (AUDIO_SUCCESS);
}	/* audiohd_find_inpin_for_monitor */

/*
 * audiohd_build_monitor_path()
 *
 * Description:
 * 	The functionality of mixer is to mix inputs, such as CD-IN, MIC,
 * 	Line-in, etc, with DAC outputs, so as to minitor what is being
 * 	recorded and implement "What you hear is what you get". However,
 * 	this functionality are really hardware-dependent: the inputs
 * 	must be directed to MIXER if they can be directed to ADC as
 * 	recording sources.
 */
static void
audiohd_build_monitor_path(hda_codec_t *codec)
{
	audiohd_ostream_t		*ostream;
	audiohd_widget_t		*widget;
	wid_t				wid;
	int				i, j, k, find;
	int				mixernum = 0;

	ostream = codec->ostream;
	while (ostream) {
		for (i = 0; i < ostream->pin_nums; i++) {
		wid = ostream->pin_wid[i];
		widget = codec->widget[wid];
		k = 0;

		while (widget) {
			while (widget && ((widget->type != WTYPE_AUDIO_MIX) ||
			    (widget->nconns < 2))) {
				if (widget->selconn == AUDIOHD_NULL_CONN)
					break;
				wid = widget->avail_conn[widget->selconn];
				widget = codec->widget[wid];
			}

			/*
			 * No mixer in this output path, we cannot build
			 * mixer path for this path, skip it, and continue
			 * for next output path.
			 */
			if (widget == NULL || widget->selconn ==
			    AUDIOHD_NULL_CONN) {
				break;
			}
			mixernum++;
			for (j = 0; j < widget->nconns; j++) {

				/*
				 * this connection must be routined to DAC
				 * instead
				 * of an input pin widget, we needn't waste
				 * time for
				 * it
				 */
				if (widget->selconn == j)
					continue;
				find = 0;
				if (audiohd_find_inpin_for_monitor(codec,
				    ostream,
				    widget->avail_conn[j], 0) ==
				    AUDIO_SUCCESS) {
					ostream->mon_wid[i][k] = wid;
					widget->selmon[widget->used++] = j;
					widget->path_flags |= AUDIOHD_PATH_MON;
					find = 1;
					ATRACE("Exclusive monitor found",
					    NULL);
				} else if (
				    audiohd_find_inpin_for_monitor(codec,
				    ostream,
				    widget->avail_conn[j], 1) ==
				    AUDIO_SUCCESS) {
					ostream->mon_wid[i][k] = wid;
					widget->selmon[widget->used++] = j;
					widget->path_flags |= AUDIOHD_PATH_MON;

					find = 1;
					ATRACE("Share monitor found", NULL);

				}

			}

			/*
			 * we needn't check widget->selconn here since this
			 * widget
			 * is a selector or mixer, it cannot be NULL connection.
			 */
			if (!find) {
				ATRACE_32(
				    "No input pin found on this mixer:",
				    widget->wid_wid);
				ostream->mon_wid[i][k] = 0;
				widget->path_flags |= AUDIOHD_PATH_NOMON;
			}
			wid = widget->avail_conn[widget->selconn];
			widget = codec->widget[wid];
			k++;
		}
		ostream->maxmixer[i] = k;
		}

		ostream = ostream->next_stream;
	}
	if (mixernum == 0)
		ATRACE("Monitor unsupported", NULL);
}	/* audiohd_build_monitor_path */

/*
 * audiohd_do_finish_monitor_path
 *
 * Description:
 *	Enable the widgets on the monitor path
 */
static void
audiohd_do_finish_monitor_path(hda_codec_t *codec, audiohd_widget_t *wgt)
{
	uint_t			caddr = codec->index;
	audiohd_widget_t 	*widget = wgt;
	audiohd_widget_t	*w;
	audiohd_state_t		*statep = codec->soft_statep;
	wid_t			wid;
	int			i;
	int			share = 0;

	if (!widget || widget->finish)
		return;
	if (widget->path_flags & AUDIOHD_PATH_ADC)
		share = 1;
	if ((widget->outamp_cap)&&!share)
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    widget->wid_wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_LR_OUTPUT
			    | AUDIOHDC_GAIN_MAX);
	if ((widget->inamp_cap)&&!share) {
		for (i = 0; i < widget->used; i++) {
		(void) audioha_codec_4bit_verb_get(statep, caddr,
		    widget->wid_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
		    AUDIOHDC_AMP_SET_LR_INPUT |
		    AUDIOHDC_GAIN_MAX |
		    (widget->selmon[i] <<
		    AUDIOHDC_AMP_SET_INDEX_OFFSET));
		}
	}
	if ((widget->type == WTYPE_AUDIO_SEL) && (widget->nconns > 1) &&
	    !share) {
		(void) audioha_codec_verb_get(statep, caddr,
		    widget->wid_wid,
		    AUDIOHDC_VERB_SET_CONN_SEL, widget->selmon[0]);
		ATRACE("Monitor selector exist!", NULL);
	}
	widget->finish = 1;
	if (widget->used == 0)
		return;
	if (widget->used > 0) {
		for (i = 0; i < widget->used; i++) {
			wid = widget->avail_conn[widget->selmon[i]];
			w = codec->widget[wid];
			audiohd_do_finish_monitor_path(codec, w);
		}
	}
}	/* audiohd_do_finish_monitor_path */

/*
 * audiohd_finish_monitor_path
 *
 * Description:
 *	Enable the monitor path for every ostream path
 */
static void
audiohd_finish_monitor_path(hda_codec_t *codec)
{
	audiohd_ostream_t	*ostream;
	audiohd_widget_t	*widget;
	wid_t			wid;
	int 			i, j;

	ostream = codec->ostream;
	while (ostream) {
		for (i = 0; i < ostream->pin_nums; i++) {
			for (j = 0; j < ostream->maxmixer[j]; j++) {
				wid = ostream->mon_wid[i][j];
				if (wid == 0) {
					continue;
				}
				widget = codec->widget[wid];
				audiohd_do_finish_monitor_path(codec, widget);
			}
		}
	ostream = ostream->next_stream;
	}
}	/* audiohd_finish_monitor_path */

/*
 * audiohd_do_build_monit_amp()
 *
 * Description:
 *	Search for the gain control widget for the monitor path
 */
static void
audiohd_do_build_monitor_amp(hda_codec_t *codec, audiohd_pin_t *pin,
    audiohd_widget_t *widget)
{
	audiohd_widget_t	*w = widget;
	uint32_t		gain;
	int			i;
	wid_t			wid;

	if (!w ||
	    (w->type == WTYPE_PIN) ||
	    !w->used ||
	    (pin->num == AUDIOHD_MAX_CONN) ||
	    (w->path_flags & AUDIOHD_PATH_ADC))
		return;
	if (!(w->path_flags & AUDIOHD_PATH_DAC)) {
		gain = w->outamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS;
		if (gain) {
			pin->mg_dir[pin->num] = AUDIOHDC_AMP_SET_OUTPUT;
			pin->mg_gain[pin->num] = gain;
			pin->mg_wid[pin->num] = w->wid_wid;
			pin->mg_gain[pin->num] >>= AUDIOHD_GAIN_OFF;
			pin->num++;
			return;
		}
		gain = w->inamp_cap & AUDIOHDC_AMP_CAP_STEP_NUMS;
		if (gain) {
			pin->mg_dir[pin->num] = AUDIOHDC_AMP_SET_INPUT;
			pin->mg_gain[pin->num] = gain;
			pin->mg_wid[pin->num] = w->wid_wid;
			pin->mg_gain[pin->num] >>= AUDIOHD_GAIN_OFF;
			pin->num++;
			return;
		}
	}
	for (i = 0; i < w->used; i++) {
		wid = w->avail_conn[w->selmon[i]];
		audiohd_do_build_monitor_amp(codec, pin, codec->widget[wid]);
	}


}	/* audiohd_do_build_monitor_amp() */

/*
 * audiohd_build_monitor_amp()
 *
 * Description:
 *	Search gain control widget for every ostream monitor
 */
static void
audiohd_build_monitor_amp(hda_codec_t *codec)
{
	audiohd_ostream_t	*ostream;
	audiohd_widget_t	*widget, *w;
	audiohd_pin_t		*pin;
	wid_t			wid, id;
	int			i, j;

	ostream = codec->ostream;
	while (ostream) {
		for (i = 0; i < ostream->pin_nums; i++) {
			id = ostream->pin_wid[i];
			w = codec->widget[id];
			pin = (audiohd_pin_t *)(w->priv);
			for (j = 0; j < ostream->maxmixer[i]; j++) {
				wid = ostream->mon_wid[i][j];
				if (!wid)
					continue;
				widget = codec->widget[wid];
				audiohd_do_build_monitor_amp(codec, pin,
				    widget);
			}
		}
		ostream = ostream->next_stream;
	}
}

/*
 * audiohd_build_path()
 *
 * Description:
 *	Here we build the output, input, monitor path.
 *	And also enable the path in default.
 *	Search for the gain and mute control for the path
 */
static void
audiohd_build_path(audiohd_state_t *statep)
{
	int		i;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i]) {
			audiohd_build_output_path(statep->codec[i]);
			audiohd_build_output_amp(statep->codec[i]);
			audiohd_finish_output_path(statep->codec[i]);

			audiohd_build_input_path(statep->codec[i]);
			audiohd_build_input_amp(statep->codec[i]);
			audiohd_finish_input_path(statep->codec[i]);

			audiohd_build_monitor_path(statep->codec[i]);
			audiohd_build_monitor_amp(statep->codec[i]);
			audiohd_finish_monitor_path(statep->codec[i]);
		}
	}
}	/* audiohd_build_path */

/*
 * audiohd_init_ports()
 *
 * Description:
 * 	Since the Solaris framework only supports 5 types of output port,
 * 	and each type can have only one instance. So we use a global
 * 	array (g_outport) to hold  all output ports, and when the framework
 * 	has this restriction lifted, we need to reimplement it.
 */
static int
audiohd_init_ports(audiohd_state_t *statep)
{
	hda_codec_t			*codec;
	audiohd_ostream_t		*ostream;
	audiohd_istream_t		*istream;
	audiohd_widget_t		*widget;
	audiohd_pin_t			*pin;
	uint_t				inputs, outputs;
	int				i;
	uint32_t			ctrl;
	uint8_t				ctrl8;

	codec = NULL;
	for (i = 0; i < AUDIOHD_CODEC_MAX; i++)
		if (statep->codec[i]) {
			codec = statep->codec[i];
			break;
		}

	if (codec == NULL)
		return (DDI_FAILURE);

	if (codec->ostream) {
		outputs = 0;
		ostream = codec->ostream;
		while (ostream) {
			ostream->in_use = 1;
			for (i = 0; i < ostream->pin_nums; i++) {
				widget = codec->widget[ostream->pin_wid[i]];
				pin = (audiohd_pin_t *)widget->priv;
				if (pin->device == DTYPE_SPDIF_OUT) {
					ATRACE("SPDIFOUT found!", NULL);
					pin->sada_porttype = AUDIO_SPDIF_OUT |
					    AUDIOHD_SADA_OUTPUT;
					outputs |= AUDIO_SPDIF_OUT;
					ctrl = audioha_codec_verb_get(statep,
					    codec->index, ostream->dac_wid,
					    AUDIOHDC_VERB_GET_SPDIF_CONTROL, 0);
					ctrl |= AUDIOHD_SPDIF_ON;
					ctrl8 = ctrl & AUDIOHD_SPDIF_MASK;
					(void) audioha_codec_verb_get(statep,
					    codec->index,
					    ostream->dac_wid,
					    AUDIOHDC_VERB_SET_SPDIF_LCONTROL,
					    ctrl8);
				} else if (pin->device == DTYPE_LINEOUT) {
					pin->sada_porttype = AUDIO_LINE_OUT |
					    AUDIOHD_SADA_OUTPUT;
					outputs |= AUDIO_LINE_OUT;
				} else if (pin->device == DTYPE_SPEAKER) {
					pin->sada_porttype = AUDIO_SPEAKER |
					    AUDIOHD_SADA_OUTPUT;
					outputs |= AUDIO_SPEAKER;

				} else if (pin->device == DTYPE_HP_OUT) {
					pin->sada_porttype = AUDIO_HEADPHONE |
					    AUDIOHD_SADA_OUTPUT;
					outputs |= AUDIO_HEADPHONE;
				} else {
					pin->sada_porttype = AUDIO_AUX1_OUT |
					    AUDIOHD_SADA_OUTPUT;
					outputs |= AUDIO_AUX1_OUT;
				}
			}
			ostream = ostream->next_stream;
		}
		statep->hda_info_defaults.play.port = outputs;
		statep->hda_info_defaults.play.avail_ports = outputs;
		statep->hda_info_defaults.play.mod_ports = outputs;
		statep->hda_out_ports = outputs;
		ostream = codec->ostream;
		while (ostream) {
			if (ostream->in_use == 0)
				break;
			(void) audioha_codec_verb_get(statep, codec->index,
			    ostream->dac_wid, AUDIOHDC_VERB_SET_STREAM_CHANN,
			    statep->hda_play_stag << AUDIOHD_PLAY_TAG_OFF);
			ostream = ostream->next_stream;
		}
	}

	/*
	 * Init input ports. Because solaris supports just one MIC, so we
	 * will enable all MICs if applications select MIC as input sources.
	 * For others, we do the same.
	 */
	inputs = 0;
	for (istream = codec->istream; istream;
	    istream = istream->next_stream) {
		istream->in_use = 1;
		for (i = 0; i < istream->pin_nums; i++) {
				widget = codec->widget[istream->pin_wid[i]];
				pin = (audiohd_pin_t *)widget->priv;
				switch (pin->device) {
				case DTYPE_SPDIF_IN:
					break;
				case DTYPE_MIC_IN:
					inputs |= AUDIO_MICROPHONE;
					pin->sada_porttype = AUDIO_MICROPHONE |
					    AUDIOHD_SADA_INPUT;
					if (((pin->config >>
					    AUDIOHD_PIN_CONTP_OFF) &
					    AUDIOHD_PIN_CONTP_MASK) ==
					    AUDIOHD_PIN_CON_FIXED)
						statep->hda_record_stag =
						    istream->rtag;
					break;
				case DTYPE_LINE_IN:
					inputs |= AUDIO_LINE_IN;
					pin->sada_porttype = AUDIO_LINE_IN |
					    AUDIOHD_SADA_INPUT;
					break;
				case DTYPE_CD:
					inputs |= AUDIO_CD;
					pin->sada_porttype = AUDIO_CD |
					    AUDIOHD_SADA_INPUT;
					break;
				case DTYPE_AUX:
					inputs |= AUDIO_AUX1_IN |
					    AUDIOHD_SADA_INPUT;
				}
		}
		if (inputs & AUDIO_MICROPHONE)
			statep->hda_info_defaults.record.port =
			    AUDIO_MICROPHONE;
		else if (inputs & AUDIO_LINE_IN)
			statep->hda_info_defaults.record.port = AUDIO_LINE_IN;
		else if (inputs & AUDIO_CD)
			statep->hda_info_defaults.record.port = AUDIO_CD;
		else if (inputs & AUDIO_AUX1_IN)
			statep->hda_info_defaults.record.port = AUDIO_AUX1_IN;
		else if (inputs & AUDIO_SPDIF_IN)
			statep->hda_info_defaults.record.port = AUDIO_SPDIF_IN;
		else
			statep->hda_info_defaults.record.port = 0;

		statep->hda_info_defaults.record.avail_ports = inputs;
		statep->hda_info_defaults.record.mod_ports = inputs;
		statep->hda_in_port = 0;

		(void) audioha_codec_verb_get(statep, codec->index,
		    istream->adc_wid, AUDIOHDC_VERB_SET_STREAM_CHANN,
		    istream->rtag << AUDIOHD_REC_TAG_OFF);
	}

	return (DDI_SUCCESS);
}	/* audiohd_init_ports() */

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

	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empirical testing time, which works well */
		drv_usecwait(50);
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

	/* Empirical testing time, which works well */
	drv_usecwait(300);

	/* exit reset stream */
	bTmp &= ~AUDIOHDR_SD_CTL_SRST;
	AUDIOHD_REG_SET8(base + AUDIOHD_SDREG_OFFSET_CTL, bTmp);

	for (i = 0; i < AUDIOHD_RETRY_TIMES; i++) {
		/* Empircal testing time */
		drv_usecwait(50);
		bTmp = AUDIOHD_REG_GET8(base + AUDIOHD_SDREG_OFFSET_CTL);
		bTmp &= AUDIOHDR_SD_CTL_SRST;
		if (!bTmp)
			break;
	}

	if (bTmp) {
		audio_sup_log(NULL, CE_WARN,
		    "!Failed to exit reset state for"
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
	uint64_t	buf_phys_addr;
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
	rs = am_get_audio(statep->hda_ahandle, buf,
	    AUDIO_NO_CHANNEL, samples);
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
	} else {

		(void) ddi_dma_sync(statep->hda_dma_play_buf.ad_dmahdl,
		    0, rs << 2, DDI_DMA_SYNC_FORDEV);
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
	pos &= AUDIOHD_POS_MASK;

	if (pos > statep->hda_pbuf_pos) {
		len = (pos - statep->hda_pbuf_pos) & AUDIOHD_POS_MASK;
	} else {
		len = statep->hda_pbuf_size * AUDIOHD_BDLE_NUMS -
		    statep->hda_pbuf_pos;
		len &= AUDIOHD_POS_MASK;
	}
	mutex_exit(&statep->hda_mutex);
	rs = am_get_audio(statep->hda_ahandle, buf,
	    AUDIO_NO_CHANNEL, len / 2);
	mutex_enter(&statep->hda_mutex);

	(void) ddi_dma_sync(statep->hda_dma_play_buf.ad_dmahdl,
	    statep->hda_pbuf_pos, rs << 2, DDI_DMA_SYNC_FORDEV);

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
	pos &= AUDIOHD_POS_MASK;
	buf = (char *)statep->hda_dma_record_buf.ad_vaddr;
	buf += statep->hda_rbuf_pos;

	if (pos > statep->hda_rbuf_pos) {
		len = (pos - statep->hda_rbuf_pos) & AUDIOHD_POS_MASK;
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
 *	Set gain value for the path
 */
static int
audiohd_set_gain(audiohd_state_t *statep, int dir, int gain, int channel)
{
	audiohd_ostream_t	*ostream;
	audiohd_istream_t	*istream;
	audiohd_pin_t		*pin;
	hda_codec_t		*codec;
	uint_t			tmp;
	uint_t			caddr;
	uint_t			val;
	int			i;

	if (gain > AUDIO_MAX_GAIN) {
		gain = AUDIO_MAX_GAIN;
	} else if (gain < AUDIO_MIN_GAIN) {
		gain = AUDIO_MIN_GAIN;
	}

	codec = NULL;
	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i]) {
			codec = statep->codec[i];
			break;
		}
	}
	if (codec == NULL)
		return (DDI_FAILURE);

	caddr = codec->index;
	if (dir == AUDIO_PLAY) {
		if (channel == 0) { /* left channel */
			val = AUDIOHDC_AMP_SET_LEFT;
			statep->hda_play_lgain = gain;
		} else { /* right channel */
			val = AUDIOHDC_AMP_SET_RIGHT;
			statep->hda_play_rgain = gain;
		}

		for (ostream = codec->ostream; ostream;
		    ostream = ostream->next_stream) {
			if (ostream->in_use == 0)
				break;

			if (ostream->gain_wid) {
				tmp = gain * ostream->gain_bits /
				    AUDIO_MAX_GAIN;
				(void) audioha_codec_4bit_verb_get(statep,
				    caddr,
				    ostream->gain_wid,
				    AUDIOHDC_VERB_SET_AMP_MUTE,
				    val | ostream->gain_dir | tmp);
				continue;
			}
			/* We have to set each pin one by one */
			for (i = 0; i < ostream->pin_nums; i++) {
				audiohd_widget_t	*w;
				wid_t		wid;

				wid = ostream->pin_wid[i];
				w = codec->widget[wid];
				pin = (audiohd_pin_t *)w->priv;
				if (pin->gain_wid) {
					tmp = gain * pin->gain_bits /
					    AUDIO_MAX_GAIN;
					(void) audioha_codec_4bit_verb_get(
					    statep, caddr,
					    pin->gain_wid,
					    AUDIOHDC_VERB_SET_AMP_MUTE,
					    val | pin->gain_dir | tmp);
				}

			}
		}
		return (DDI_SUCCESS);
	}

	if (dir != AUDIO_RECORD)
		return (DDI_FAILURE);

	for (istream = codec->istream; istream;
	    istream = istream->next_stream) {
		if (istream->in_use == 0)
			break;
		if (istream->gain_wid) {
			tmp = gain * istream->gain_bits / AUDIO_MAX_GAIN;
			(void) audioha_codec_4bit_verb_get(statep, caddr,
			    istream->gain_wid, AUDIOHDC_VERB_SET_AMP_MUTE,
			    val | istream->gain_dir | tmp);
		} else {
			for (pin = codec->first_pin; pin; pin = pin->next) {
				if ((statep->hda_in_port |
				    AUDIOHD_SADA_OUTPUT) ==
				    pin->sada_porttype) {
					tmp = gain * pin->gain_bits /
					    AUDIO_MAX_GAIN;
					(void) audioha_codec_4bit_verb_get(
					    statep,
					    caddr,
					    pin->gain_wid,
					    AUDIOHDC_VERB_SET_AMP_MUTE,
					    val | pin->gain_dir | tmp);
				}
			}
		}
	}

	return (DDI_SUCCESS);

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
	int			i;
	uint_t			tmp_port = 0;
	wid_t			pin_wid = 0;
	int			caddr;
	audiohd_istream_t	*istream;
	audiohd_widget_t	*w;
	audiohd_pin_t		*pin;
	hda_codec_t		*codec;

	codec =  NULL;
	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		if (statep->codec[i])
			codec = statep->codec[i];
	}
	if (codec == NULL)
		return (DDI_FAILURE);

	caddr = codec->index;
	if (dir == AUDIO_PLAY) {
		for (i = 0; i < AUDIOHD_PIN_NUMS-1; i++) {
			if (port & g_outport[i]) {
				tmp_port |= g_outport[i];
				pin = codec->first_pin;
				while (pin) {
					if ((AUDIOHD_SADA_OUTPUT |
					    g_outport[i]) ==
					    pin->sada_porttype)
						AUDIOHD_ENABLE_PIN_OUT(statep,
						    caddr,
						    pin->wid);
					pin = pin->next;
				}
			} else if (statep->hda_out_ports & g_outport[i]) {
				tmp_port &= ~(g_outport[i]);
				pin = codec->first_pin;
				while (pin) {
					if ((AUDIOHD_SADA_OUTPUT |
					    g_outport[i]) ==
					    pin->sada_porttype)
						AUDIOHD_DISABLE_PIN_OUT(statep,
						    caddr,
						    pin->wid);
					pin = pin->next;
				}
			}
		}
		if (port & AUDIO_SPDIF_OUT) {
			tmp_port |= AUDIO_SPDIF_OUT;
			pin = codec->first_pin;
			while (pin) {
				if ((AUDIOHD_SADA_OUTPUT | AUDIO_SPDIF_OUT) ==
				    pin->sada_porttype)
					AUDIOHD_ENABLE_PIN_OUT(statep, caddr,
					    pin->wid);
				pin = pin->next;
			}

		} else if (statep->hda_out_ports & AUDIO_SPDIF_OUT) {
			tmp_port &= ~(AUDIO_SPDIF_OUT);
			pin = codec->first_pin;
			while (pin) {
				if ((AUDIOHD_SADA_OUTPUT | AUDIO_SPDIF_OUT) ==
				    pin->sada_porttype)
					AUDIOHD_DISABLE_PIN_OUT(statep, caddr,
					    pin->wid);
				pin = pin->next;
			}
		}
		statep->hda_out_ports = tmp_port;
		return (DDI_SUCCESS);
	}

	if (dir != AUDIO_RECORD) {
		return (DDI_FAILURE);
	}

	/* now, we handle recording */
	switch (port) {
	case AUDIO_NONE:
		for (pin = codec->first_pin; pin; pin = pin->next) {
			if ((statep->hda_in_port | AUDIOHD_SADA_INPUT) ==
			    pin->sada_porttype)
				AUDIOHD_DISABLE_PIN_IN(statep, caddr, pin->wid);
		}
		tmp_port = 0;
		pin_wid = 0;
		break;
	case AUDIO_MICROPHONE:
	case AUDIO_LINE_IN:
	case AUDIO_CD:
	case AUDIO_AUX1_IN:
		for (pin = codec->first_pin; pin; pin = pin->next) {
			if ((port | AUDIOHD_SADA_INPUT) == pin->sada_porttype) {
				AUDIOHD_ENABLE_PIN_IN(statep, caddr, pin->wid);
				pin_wid = pin->wid;
			} else if ((statep->hda_in_port | AUDIOHD_SADA_INPUT) ==
			    pin->sada_porttype) {
				AUDIOHD_DISABLE_PIN_IN(statep, caddr, pin->wid);
			}
		}
		tmp_port = port;
		break;
	default:
		break;
	}
	statep->hda_in_port = tmp_port;

	/*
	 * During path searching, we allow one real selector/mixer
	 * in the input path. So, if there is a multi-input selector
	 * we must set the right input connection for the selector.
	 */
	if (pin_wid == 0)
		return (DDI_SUCCESS);
	w = codec->widget[pin_wid];
	pin = (audiohd_pin_t *)w->priv;

	/* find ADC widget */
	w = codec->widget[pin->adc_dac_wid];

	istream = (audiohd_istream_t *)w->priv;

	/*
	 * If there is a real selector in this input stream,
	 * we select the right one input for the selector.
	 */
	if (istream->sum_wid) {
		w = codec->widget[istream->sum_wid];
		if (w->type == WTYPE_AUDIO_SEL) {
			for (i = 0; i < istream->pin_nums; i++)
				if (istream->pin_wid[i] == pin_wid)
					break;
			if (i > istream->pin_nums) {
				cmn_err(CE_WARN, "bug in istream-pin");
			} else {
				(void) audioha_codec_verb_get(
				    statep, codec->index,
				    istream->sum_wid,
				    AUDIOHDC_VERB_SET_CONN_SEL,
				    istream->sum_selconn[i]);
			}
		}
	}

	return (DDI_SUCCESS);

}	/* audiohd_set_port() */

/*
 * audiohd_do_mute_outputs()
 *
 * Description:
 *	Mute the output path.
 */
static void
audiohd_do_mute_outputs(audiohd_state_t *statep,
    audiohd_ostream_t *ostream, hda_codec_t *codec,
    boolean_t mute)
{
	audiohd_widget_t	*w;
	audiohd_pin_t		*pin;
	wid_t			wid;
	int			lgain, rgain;
	int			j;
	uint_t			lg, rg;
	uint16_t		caddr = codec->index;

	if (mute == 0) {
		if (ostream->mute_wid) {
			if (ostream->mute_wid ==
			    ostream->gain_wid) {
				lgain = statep->hda_play_lgain *
				    ostream->gain_bits /
				    AUDIO_MAX_GAIN;
				rgain = statep->hda_play_rgain *
				    ostream->gain_bits /
				    AUDIO_MAX_GAIN;
			} else {
				lgain = AUDIOHDC_GAIN_MAX;
				rgain = AUDIOHDC_GAIN_MAX;
			}
			(void) audioha_codec_4bit_verb_get(statep,
			    caddr,
			    ostream->mute_wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    ostream->mute_dir |
			    AUDIOHDC_AMP_SET_LEFT |
			    lgain);
			(void) audioha_codec_4bit_verb_get(statep,
			    caddr,
			    ostream->mute_wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    ostream->mute_dir |
			    AUDIOHDC_AMP_SET_RIGHT |
			    rgain);
		} else {
			for (j = 0; j < ostream->pin_nums;
			    j++) {
				wid = ostream->pin_wid[j];
				w = codec->widget[wid];
				lg = statep->hda_play_lgain;
				rg = statep->hda_play_rgain;
				pin = (audiohd_pin_t *)w->priv;
				if (pin->mute_wid ==
				    pin->gain_wid) {
					lgain =
					    lg *
					    pin->gain_bits /
					    AUDIO_MAX_GAIN;
					rgain =
					    rg *
					    pin->gain_bits /
					    AUDIO_MAX_GAIN;
				} else {
					lgain =
					    AUDIOHDC_GAIN_MAX;
					rgain =
					    AUDIOHDC_GAIN_MAX;
				}
				(void) audioha_codec_4bit_verb_get(
				    statep,
				    caddr,
				    pin->mute_wid,
				    AUDIOHDC_VERB_SET_AMP_MUTE,
				    pin->mute_dir |
				    AUDIOHDC_AMP_SET_LEFT |
				    lgain);
				(void) audioha_codec_4bit_verb_get(
				    statep,
				    caddr,
				    pin->mute_wid,
				    AUDIOHDC_VERB_SET_AMP_MUTE,
				    pin->mute_dir |
				    AUDIOHDC_AMP_SET_RIGHT |
				    rgain);
			}
		}
	} else {
		if (ostream->mute_wid) {
			(void) audioha_codec_4bit_verb_get(statep,
			    caddr, ostream->mute_wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    ostream->mute_dir |
			    AUDIOHDC_AMP_SET_LNR |
			    AUDIOHDC_AMP_SET_MUTE);
		} else {
			for (j = 0; j < ostream->pin_nums;
			    j++) {
			wid = ostream->pin_wid[j];
			w = codec->widget[wid];
			pin = (audiohd_pin_t *)w->priv;
			(void) audioha_codec_4bit_verb_get(
			    statep,
			    caddr,
			    pin->wid,
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    pin->mute_dir |
			    AUDIOHDC_AMP_SET_LNR |
			    AUDIOHDC_AMP_SET_MUTE);
			}
		}
	}
}	/* audiohd_do_mute_outputs() */

/*
 * audiohd_mute_outputs()
 *
 * Description:
 *	Mute all the output streams
 */
static void
audiohd_mute_outputs(audiohd_state_t *statep, boolean_t mute)
{
	audiohd_ostream_t	*ostream;
	hda_codec_t		*codec;
	int			i;

	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (codec == NULL)
			continue;
		for (ostream = codec->ostream; ostream;
		    ostream = ostream->next_stream) {
			audiohd_do_mute_outputs(statep, ostream, codec, mute);
		}
	}

}	/* audiohd_mute_outputs() */

/*
 * audiohd_set_pin_monitor_gain()
 *
 * Description:
 *	Set the gain value for the monitor path.
 */
static void
audiohd_set_pin_monitor_gain(hda_codec_t *codec, audiohd_state_t *statep,
    uint_t caddr, audiohd_pin_t *pin, int gain)
{
	int 			i, k;
	uint_t			tmp;
	audiohd_widget_t	*widget;

	for (k = 0; k < pin->num; k++) {
		tmp = gain * pin->mg_gain[k]/
		    AUDIO_MAX_GAIN;
		widget = codec->widget[pin->mg_wid[k]];
		if (pin->mg_dir[k] == AUDIOHDC_AMP_SET_OUTPUT) {
			(void) audioha_codec_4bit_verb_get(
			    statep,
			    caddr,
			    pin->mg_wid[k],
			    AUDIOHDC_VERB_SET_AMP_MUTE,
			    AUDIOHDC_AMP_SET_RIGHT|
			    AUDIOHDC_AMP_SET_LEFT|
			    pin->mg_dir[k] | tmp);
		} else if (pin->mg_dir[k] == AUDIOHDC_AMP_SET_INPUT) {
			for (i = 0; i < widget->used; i++) {
				(void) audioha_codec_4bit_verb_get(
				    statep,
				    caddr,
				    pin->mg_wid[k],
				    AUDIOHDC_VERB_SET_AMP_MUTE,
				    AUDIOHDC_AMP_SET_RIGHT|
				    AUDIOHDC_AMP_SET_LEFT|
				    widget->selmon[i]<<
				    AUDIOHDC_AMP_SET_INDEX_OFFSET |
				    pin->mg_dir[k] | tmp);
			}
		}
	}
}	/* audiohd_set_pin_monitor_gain() */
/*
 * audiohd_set_monitor_gain()
 *
 * Description:
 *	Set the gain value for the monitor widget control
 */
static int
audiohd_set_monitor_gain(audiohd_state_t *statep, int gain)
{
	int			ret;
	int 			i, j;
	audiohd_ostream_t	*ostream;
	audiohd_pin_t		*pin;
	hda_codec_t		*codec;
	audiohd_widget_t	*w;
	uint_t			caddr;
	wid_t			wid;

	ASSERT(statep);

	if (gain > AUDIO_MAX_GAIN)
		gain = AUDIO_MAX_GAIN;
	else if (gain < AUDIO_MIN_GAIN)
		gain = AUDIO_MIN_GAIN;

	/*
	 * Allow to set monitor gain even if no input is selected
	 */
	statep->hda_monitor_gain = gain;
	for (i = 0; i < AUDIOHD_CODEC_MAX; i++) {
		codec = statep->codec[i];
		if (codec == NULL)
			continue;
		caddr = codec->index;
		for (ostream = codec->ostream; ostream;
		    ostream = ostream->next_stream) {
			for (j = 0; j < ostream->pin_nums; j++) {
				wid = ostream->pin_wid[j];
				w = codec->widget[wid];
				pin = (audiohd_pin_t *)w->priv;
				audiohd_set_pin_monitor_gain(codec, statep,
				    caddr, pin, gain);
			}
		}
	}


	ret = AUDIO_SUCCESS;
	return (ret);

}	/* audiohd_set_monitor_gain() */

/*
 * audiohd_12bit_verb_to_codec()
 *
 * Description:
 *
 */
static int
audiohd_12bit_verb_to_codec(audiohd_state_t *statep, uint8_t caddr,
    uint8_t wid,
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

	verb = (caddr & 0x0f) << AUDIOHD_VERB_ADDR_OFF;
	verb |= wid << AUDIOHD_VERB_NID_OFF;
	verb |= cmd << AUDIOHD_VERB_CMD_OFF;
	verb |= param;

	*((uint32_t *)(statep->hda_dma_corb.ad_vaddr) + wptr) = verb;
	(void) ddi_dma_sync(statep->hda_dma_corb.ad_dmahdl, 0,
	    sizeof (sd_bdle_t) * AUDIOHD_BDLE_NUMS, DDI_DMA_SYNC_FORDEV);
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
audiohd_4bit_verb_to_codec(audiohd_state_t *statep, uint8_t caddr,
    uint8_t wid,
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

	verb = (caddr & 0x0f) << AUDIOHD_VERB_ADDR_OFF;
	verb |= wid << AUDIOHD_VERB_NID_OFF;
	verb |= cmd << AUDIOHD_VERB_CMD16_OFF;
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
	rptr &= AUDIOHD_RING_MAX_SIZE;

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
audioha_codec_verb_get(void *arg, uint8_t caddr, uint8_t wid,
    uint16_t verb,
    uint8_t param)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	resp;
	uint32_t	respex;
	int		ret;
	int		i;

	ret = audiohd_12bit_verb_to_codec(statep, caddr, wid, verb, param);
	if (ret != AUDIO_SUCCESS) {
		return (uint32_t)(-1);
	}

	/*
	 * Empirical testing times. 50 times is enough for audiohd spec 1.0.
	 * But we need to make it work for audiohd spec 0.9, which is just a
	 * draft version and requires more time to wait.
	 */
	for (i = 0; i < 500; i++) {
		/* Empirical testing time, which works well */
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
	    " response from codec: wid=%d, verb=0x%04x, param=0x%04x",
	    audiohd_name, wid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_verb_get() */


/*
 * audioha_codec_4bit_verb_get()
 */
static uint32_t
audioha_codec_4bit_verb_get(void *arg, uint8_t caddr, uint8_t wid,
    uint16_t verb, uint16_t param)
{
	audiohd_state_t	*statep = (audiohd_state_t *)arg;
	uint32_t	resp;
	uint32_t	respex;
	int		ret;
	int		i;

	ret = audiohd_4bit_verb_to_codec(statep, caddr, wid, verb, param);
	if (ret != AUDIO_SUCCESS) {
		return (uint32_t)(-1);
	}

	for (i = 0; i < 500; i++) {
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
	    " response from codec: wid=%d, verb=0x%04x, param=0x%04x",
	    audiohd_name, wid, verb, param);

	return ((uint32_t)(-1));

}	/* audioha_codec_4bit_verb_get() */

/*
 * audiohd_set_busy()
 *
 * Description:
 *	This routine is called whenever a routine needs to guarantee
 *	that it will not be suspended. It will also block any routine
 *	while a suspend is going on.
 *	CAUTION: This routine cannot be called by routines that will
 *		block. Otherwise DDI_SUSPEND will be blocked for a
 *		long time. And that is the wrong thing to do.
 *
 * Arguments:
 *	audiohd_state_t *statep		The device's state structure
 * Returns:
 *	void
 */
static void
audiohd_set_busy(audiohd_state_t *statep)
{
	ASSERT(!mutex_owned(&statep->hda_mutex));

	mutex_enter(&statep->hda_mutex);
	/* block if we are suspended */
	while (statep->suspended)
		cv_wait(&statep->hda_cv, &statep->hda_mutex);
	/*
	 * OK, we aren't suspended, so mark as busy.
	 * This will keep us from being suspended when we release the lock.
	 */
	ASSERT(statep->hda_busy_cnt >= 0);
	statep->hda_busy_cnt++;

	mutex_exit(&statep->hda_mutex);
}	/* audiohd_set_busy() */

/*
 * audiohd_set_idle()
 * Description:
 *	This routine reduces the busy count. It then does a cv_broadcast()
 *	if the count is 0 so a waiting DDI_SUSPEND will continue forward.
 * Arguments:
 *	audiohd_state_t *state		The device's state structure
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
	if (statep->hda_busy_cnt == 0)
		cv_broadcast(&statep->hda_cv);

	mutex_exit(&statep->hda_mutex);
}	/* audiohd_set_idle() */
