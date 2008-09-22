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
 * audioixp Audio Driver
 *
 * This driver supports audio hardware integrated in ATI IXP400 chipset.
 *
 * This driver uses the mixer Audio Personality Module to implement
 * audio(7I) and mixer(7I) semantics. Both play and record are single
 * streaming.
 *
 * The IXP400 audio core is an AC'97 controller, which has independent
 * channels for PCM in, PCM out. The AC'97 controller is a PCI bus master
 * with scatter/gather support. Each channel has a DMA engine. Currently,
 * we use only the PCM in and PCM out channels. Each DMA engine uses one
 * buffer descriptor list.  And the buffer descriptor list is an array
 * of up to 32 entries, each of which describes a data buffer. You dont need
 * to use all these entries. Each entry contains a pointer to a data buffer,
 * status, length of the buffer being pointed to and the pointer to the next
 * entry. Length of the buffer is in number of bytes. Interrupt will be
 * triggered each time a entry is processed by hardware.
 *
 * We use the BD list (buffer descriptor list) as a round-robin FIFO.
 * Both the software and hardware loop around the BD list. For playback,
 * the software writes to the buffers pointed by the BD entries of BD
 * list, and the hardware sends the data in the buffers out. For record,
 * the process is reversed. So we define the struct, audioixp_sample_buf,
 * to handle BD. The software uses the head, tail and avail fields of
 * this structure to manipulate the FIFO. The head field indicates the
 * first valid BD hardware can manipulate. The tail field indicates the
 * BD after the last valid BD. And the avail field indicates how many
 * buffers are available. Two DMA buffers are allocated for both playback
 * and record, and two BD entries are used. When processing interrupt,
 * the current hardware pointer will be check to tell which buffer is
 * being processed. It's possible for the hardware to interrupt twice
 * for one buffer, this logic is handled in the routine
 * audioixp_chunk_processed.
 *
 * Every time we program AC97 codec, we save the value in codec_shadow[].
 * This means that register state information is saved for power management
 * shutdown (we'll support this later). When the codec is started back up
 * we use this saved state to restore codec's state in audioixp_chip_init().
 *
 * System power management is not yet supported by the driver.
 *
 * 	NOTE:
 * 	This driver depends on the misc/audiosup, misc/amsrc2 and
 * 	misc/mixer modules being loaded first.
 */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_trace.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_src.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/am_src2.h>
#include <sys/audio/ac97.h>
#include <sys/audio/impl/audioixp_impl.h>
#include <sys/audio/audioixp.h>

/*
 * Module linkage routines for the kernel
 */
static int audioixp_getinfo(dev_info_t *, ddi_info_cmd_t, void*, void**);
static int audioixp_attach(dev_info_t *, ddi_attach_cmd_t);
static int audioixp_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Entry point routine prototypes
 */
static int audioixp_ad_set_config(audiohdl_t, int, int, int, int, int);
static int audioixp_ad_set_format(audiohdl_t, int, int, int, int, int, int);
static int audioixp_ad_start_play(audiohdl_t, int);
static void audioixp_ad_pause_play(audiohdl_t, int);
static void audioixp_ad_stop_play(audiohdl_t, int);
static int audioixp_ad_start_record(audiohdl_t, int);
static void audioixp_ad_stop_record(audiohdl_t, int);

/*
 * interrupt handler
 */
static uint_t	audioixp_intr(caddr_t);

/*
 * Local Routine Prototypes
 */
static int audioixp_codec_sync(audioixp_state_t *);
static int audioixp_write_ac97(audioixp_state_t *, int, uint16_t);
static int audioixp_read_ac97(audioixp_state_t *, int, uint16_t *);
static int audioixp_and_ac97(audioixp_state_t *, int, uint16_t);
static int audioixp_or_ac97(audioixp_state_t *, int, uint16_t);
static int audioixp_reset_ac97(audioixp_state_t *);
static int audioixp_init_state(audioixp_state_t *, dev_info_t *);
static int audioixp_map_regs(dev_info_t *, audioixp_state_t *);
static void audioixp_unmap_regs(audioixp_state_t *);
static int audioixp_alloc_sample_buf(audioixp_state_t *, int, int);
static void audioixp_free_sample_buf(audioixp_state_t *,
						audioixp_sample_buf_t *);
static void audioixp_setup_bdl(audioixp_state_t *);
static void audioixp_start_dma(audioixp_state_t *, int);
static void audioixp_stop_dma(audioixp_state_t *, int);
static int audioixp_chip_init(audioixp_state_t *, int);
static void audioixp_chip_fini(audioixp_state_t *);
static int audioixp_chunk_processed(audioixp_state_t *, int);
static int audioixp_fill_play_buf(audioixp_state_t *);
static int audioixp_prepare_record_buf(audioixp_state_t *);
static void audioixp_reclaim_play_buf(audioixp_state_t *);
static void audioixp_reclaim_record_buf(audioixp_state_t *);
static int audioixp_set_gain(audioixp_state_t *, int, int, int);
static int audioixp_set_port(audioixp_state_t *, int, int);
static int audioixp_set_monitor_gain(audioixp_state_t *, int);

/*
 * Global variables, but used only by this file.
 */

/* anchor for soft state structures */
static void	*audioixp_statep;

/* driver name, so we don't have to call ddi_driver_name() or hard code strs */
static char	*audioixp_name = IXP_NAME;

/*
 * STREAMS structures
 */

/* STREAMS driver id and limit value struct */
static struct module_info audioixp_modinfo = {
	IXP_IDNUM,		/* module ID number */
	IXP_NAME,		/* module name */
	IXP_MINPACKET,		/* minimum packet size */
	IXP_MAXPACKET,		/* maximum packet size */
	IXP_HIWATER,		/* high water mark */
	IXP_LOWATER,		/* low water mark */
};

/* STREAMS queue processing procedures structures */
/* read queue */
static struct qinit audioixp_rqueue = {
	audio_sup_rput,		/* put procedure */
	audio_sup_rsvc,		/* service procedure */
	audio_sup_open,		/* open procedure */
	audio_sup_close,	/* close procedure */
	NULL,			/* unused */
	&audioixp_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* write queue */
static struct qinit audioixp_wqueue = {
	audio_sup_wput,		/* write procedure */
	audio_sup_wsvc,		/* service procedure */
	NULL,			/* open procedure */
	NULL,			/* close procedure */
	NULL,			/* unused */
	&audioixp_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* STREAMS entity declaration structure */
static struct streamtab audioixp_str_info = {
	&audioixp_rqueue,	/* read queue */
	&audioixp_wqueue,	/* write queue */
	NULL,			/* mux lower read queue */
	NULL,			/* mux lower write queue */
};

/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops audioixp_cb_ops = {
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
	&audioixp_str_info,	/* cb_str */
	D_NEW | D_MP | D_64BIT, /* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

/* Device operations structure */
static struct dev_ops audioixp_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	audioixp_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audioixp_attach,	/* devo_attach */
	audioixp_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&audioixp_cb_ops,	/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv audioixp_modldrv = {
	&mod_driverops,		/* drv_modops */
	IXP_MOD_NAME,		/* drv_linkinfo */
	&audioixp_dev_ops,	/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage audioixp_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&audioixp_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};

static uint_t audioixp_mixer_srs[] = {
	IXP_SAMPR8000, IXP_SAMPR48000, 0
};

static uint_t audioixp_min_compat_srs[] = {
	IXP_SAMPR48000, 0
};

static uint_t audioixp_compat_srs [] = {
	IXP_SAMPR8000, IXP_SAMPR11025, IXP_SAMPR16000,
	IXP_SAMPR22050, IXP_SAMPR24000, IXP_SAMPR32000,
	IXP_SAMPR44100, IXP_SAMPR48000, 0
};

static am_ad_sample_rates_t audioixp_mixer_sample_rates = {
	MIXER_SRS_FLAG_SR_LIMITS,
	audioixp_mixer_srs
};

static am_ad_sample_rates_t audioixp_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audioixp_compat_srs
};

/* Some codec, only support 48K sample rate */
static am_ad_sample_rates_t audioixp_min_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audioixp_min_compat_srs
};

static uint_t audioixp_channels[] = {
	AUDIO_CHANNELS_STEREO,
	0
};

static am_ad_cap_comb_t audioixp_combinations[] = {
	{ AUDIO_PRECISION_16, AUDIO_ENCODING_LINEAR },
	{ 0 }
};

/*
 * device access attributes for register mapping
 */
static struct ddi_device_acc_attr dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA attributes of buffer descriptor list
 */
static ddi_dma_attr_t	bdlist_dma_attr = {
	DMA_ATTR_V0,	/* version */
	0,		/* addr_lo */
	0xffffffff,	/* addr_hi */
	0x0000ffff,	/* count_max */
	8,		/* align, BDL must be aligned on a 8-byte boundary */
	0x3c,		/* burstsize */
	8,		/* minxfer, set to the size of a BDlist entry */
	0x0000ffff,	/* maxxfer */
	0x00000fff,	/* seg, set to the RAM pagesize of intel platform */
	1,		/* sgllen, there's no scatter-gather list */
	8,		/* granular, set to the value of minxfer */
	0		/* flags, use virtual address */
};

/*
 * DMA attributes of buffers to be used to receive/send audio data
 */
static ddi_dma_attr_t	sample_buf_dma_attr = {
	DMA_ATTR_V0,
	0,		/* addr_lo */
	0xffffffff,	/* addr_hi */
	0x0001fffe,	/* count_max */
	2,		/* align, data buffer is aligned on a 2-byte boundary */
	0x3c,		/* burstsize */
	4,		/* minxfer, set to the size of a sample data */
	0x0001ffff,	/* maxxfer */
	0x0001ffff,	/* seg */
	1,		/* sgllen, no scatter-gather */
	4,		/* granular, set to the value of minxfer */
	0,		/* flags, use virtual address */
};

static am_ad_entry_t audioixp_entry = {
	NULL,				/* ad_setup() */
	NULL,				/* ad_teardown() */
	audioixp_ad_set_config,		/* ad_set_config() */
	audioixp_ad_set_format,		/* ad_set_format() */
	audioixp_ad_start_play,		/* ad_start_play() */
	audioixp_ad_pause_play,		/* ad_pause_play() */
	audioixp_ad_stop_play,		/* ad_stop_play() */
	audioixp_ad_start_record,	/* ad_start_record() */
	audioixp_ad_stop_record,	/* ad_stop_record() */
	NULL,				/* ad_ioctl() */
	NULL				/* ad_iocdata() */
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
	int	error;

	ATRACE("in audioixp _init()", NULL);

	if ((error = ddi_soft_state_init(&audioixp_statep,
	    sizeof (audioixp_state_t), 1)) != 0) {
		ATRACE("audioixp ddi_soft_state_init() failed",
		    audioixp_statep);
		return (error);
	}

	if ((error = mod_install(&audioixp_modlinkage)) != 0) {
		ddi_soft_state_fini(&audioixp_statep);
	}

	ATRACE("audioixp _init() audioixp_statep", audioixp_statep);
	ATRACE("audioixp _init() returning", error);

	return (error);

}	/* _init() */

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

	ATRACE("in audioixp _fini()", audioixp_statep);

	if ((error = mod_remove(&audioixp_modlinkage)) != 0) {
		return (error);
	}

	ddi_soft_state_fini(&audioixp_statep);

	ATRACE_32("audioixp _fini() returning", error);

	return (0);

}	/* _fini() */

/*
 * _info()
 *
 * Description:
 *	Module information, returns information about the driver.
 *
 * Arguments:
 *	modinfo		*modinfop	Pointer to the opaque modinfo structure
 *
 * Returns:
 *	mod_info() status, see mod_info(9f)
 */
int
_info(struct modinfo *modinfop)
{
	int	error;

	ATRACE("in audioixp _info()", NULL);

	error = mod_info(&audioixp_modlinkage, modinfop);

	ATRACE_32("audioixp _info() returning", error);

	return (error);

}	/* _info() */


/* ******************* Driver Entry Points ********************************* */

/*
 * audioixp_getinfo()
 */
static int
audioixp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
	void *arg, void **result)
{
	audioixp_state_t	*state;
	int 			instance;
	int 			error;

	error = DDI_FAILURE;
	ATRACE("in audioixp_getinfo()", dip);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = audio_sup_devt_to_instance((dev_t)arg);
		if ((state = ddi_get_soft_state(audioixp_statep,
		    instance)) != NULL) {
			*result = state->dip;
			error = DDI_SUCCESS;
		} else {
			*result = NULL;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void*)(uintptr_t)
		    audio_sup_devt_to_instance((dev_t)arg);
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (error);

}	/* audioixp_getinfo() */

/*
 * audioixp_attach()
 *
 * Description:
 *	Attach an instance of the audioixp driver. This routine does
 * 	the device dependent attach tasks. When it is completed, it calls
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
audioixp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int 			instance;
	uint16_t		cmdeg;
	audioixp_state_t	*statep;
	audio_sup_reg_data_t	data;

	ATRACE("in audioixp_attach()", dip);

	instance = ddi_get_instance(dip);

	ATRACE("audioixp_attach() audioixp_statep",
	    audioixp_statep);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	/*
	 * now, no suspend/resume supported. we'll do it in the future.
	 */
	case DDI_RESUME:
		ATRACE("audioixp_attach() DDI_RESUME", NULL);
		audio_sup_log(NULL, CE_WARN,
		    "%s%d: audioixp_attach() resume is not supported yet",
		    audioixp_name, instance);
		return (DDI_FAILURE);

	default:
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audioixp_attach() unknown command: 0x%x",
		    audioixp_name, instance, cmd);
		return (DDI_FAILURE);
	}

	/* we don't support high level interrupts in the driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audioixp_attach()"
		    " unsupported high level interrupt",
		    audioixp_name, instance);
		return (DDI_FAILURE);
	}

	/* allocate the soft state structure */
	if (ddi_soft_state_zalloc(audioixp_statep, instance) !=
	    DDI_SUCCESS) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audioixp_attach() soft state allocate failed",
		    audioixp_name, instance);
		return (DDI_FAILURE);
	}

	if ((statep = ddi_get_soft_state(audioixp_statep, instance)) ==
	    NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audioixp_attach() soft state failed",
		    audioixp_name, instance);
		goto error_state;
	}

	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;
	if ((statep->audio_handle = audio_sup_register(dip, &data)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audioixp_attach() audio_sup_register() failed",
		    audioixp_name, instance);
		goto error_state;
	}

	/* save private state */
	audio_sup_set_private(statep->audio_handle, statep);

	if ((audioixp_init_state(statep, dip)) != AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() init state structure failed");
		goto error_audiosup;
	}

	/* map in the registers, allocate DMA buffers, etc. */
	if (audioixp_map_regs(dip, statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() couldn't map registers");
		goto error_destroy;
	}

	/* set PCI command register */
	cmdeg = pci_config_get16(statep->pci_conf_handle, PCI_CONF_COMM);
	pci_config_put16(statep->pci_conf_handle, PCI_CONF_COMM,
	    cmdeg | PCI_COMM_IO | PCI_COMM_MAE);

	if (audioixp_alloc_sample_buf(statep, IXP_DMA_PCM_OUT,
	    statep->play_buf_size) == AUDIO_FAILURE) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() couldn't allocate play sample "
		    "buffers");
		goto error_unmap;
	}

	if (audioixp_alloc_sample_buf(statep, IXP_DMA_PCM_IN,
	    statep->record_buf_size) == AUDIO_FAILURE) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() couldn't allocate record sample "
		    "buffers");
		goto error_dealloc_play;
	}

	audioixp_setup_bdl(statep);

	/* set up kernel statistics */
	if ((statep->ixp_ksp = kstat_create(IXP_NAME, instance,
	    IXP_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->ixp_ksp);
	}

	/* set up the interrupt handler */
	if (ddi_add_intr(dip, 0, &statep->intr_iblock,
	    (ddi_idevice_cookie_t *)NULL, audioixp_intr, (caddr_t)statep) !=
	    DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() bad interrupt specification ");
		goto error_kstat;
	}

	if (audioixp_chip_init(statep, IXP_INIT_NO_RESTORE) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() failed to init chip");
		goto error_intr;
	}

	/* call the mixer attach() routine */
	if (am_attach(statep->audio_handle, cmd, &statep->ad_info) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_attach() am_attach() failed");
		goto error_intr;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error_intr:
	ddi_remove_intr(dip, 0, statep->intr_iblock);

error_kstat:
	if (statep->ixp_ksp) {
		kstat_delete(statep->ixp_ksp);
	}

error_dealloc:
	audioixp_free_sample_buf(statep, &statep->record_buf);

error_dealloc_play:
	audioixp_free_sample_buf(statep, &statep->play_buf);

error_unmap:
	audioixp_unmap_regs(statep);

error_destroy:
	ATRACE("audioixp_attach() error_destroy", statep);
	mutex_destroy(&statep->inst_lock);

error_audiosup:
	ATRACE("audioixp_attach() error_audiosup", statep);
	(void) audio_sup_unregister(statep->audio_handle);

error_state:
	ATRACE("audioixp_attach() error_state", statep);
	ddi_soft_state_free(audioixp_statep, instance);

	ATRACE("audioixp_attach() returning failure", NULL);

	return (DDI_FAILURE);

}	/* audioixp_attach() */

/*
 * audioixp_detach()
 *
 * Description:
 *	Detach an instance of the audioixp driver. After the Codec is
 *	detached, we call am_detach() and audio_sup_register() so they may
 *	do their work.
 *
 * Arguments:
 *	dev_info_t		*dip	Pointer to the device's dev_info struct
 *	ddi_detach_cmd_t	cmd	Detach command
 *
 * Returns:
 *	DDI_SUCCESS	The driver was detached
 *	DDI_FAILURE	The driver couldn't be detached
 */
static int
audioixp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audioixp_state_t	*statep;
	int			instance;

	instance = ddi_get_instance(dip);

	ATRACE_32("audioixp_detach() instance", instance);
	ATRACE("audioixp_detach() audioixp_statep",
	    audioixp_statep);

	if ((statep = ddi_get_soft_state(audioixp_statep, instance)) ==
	    NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: audioixp_detach() get soft state failed",
		    audioixp_name, instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	/*
	 * now, no suspend/resume supported. we'll do it in the future.
	 */
	case DDI_SUSPEND:
		ATRACE("audioixp_detach() SUSPEND", statep);
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "audioixp_detach() suspend is not supported yet");
		return (DDI_FAILURE);

	default:
		ATRACE("audioixp_detach() unknown command", cmd);
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_detach() unknown command: 0x%x", cmd);
		return (DDI_FAILURE);
	}

	audioixp_chip_fini(statep);

	/* stop DMA engines */
	mutex_enter(&statep->inst_lock);
	audioixp_stop_dma(statep, AUDIO_PLAY);
	audioixp_stop_dma(statep, AUDIO_RECORD);
	mutex_exit(&statep->inst_lock);

	/* remove the interrupt handler */
	ddi_remove_intr(dip, 0, statep->intr_iblock);

	/* free DMA memory */
	audioixp_free_sample_buf(statep, &statep->play_buf);
	audioixp_free_sample_buf(statep, &statep->record_buf);

	/* free the kernel statistics structure */
	if (statep->ixp_ksp) {
		kstat_delete(statep->ixp_ksp);
	}

	/* detach audio mixer */
	(void) am_detach(statep->audio_handle, cmd);

	/*
	 * call the audio support module's detach routine to remove this
	 * driver completely from the audio driver architecture.
	 */
	(void) audio_sup_unregister(statep->audio_handle);

	mutex_destroy(&statep->inst_lock);

	audioixp_unmap_regs(statep);

	ddi_soft_state_free(audioixp_statep, instance);

	return (DDI_SUCCESS);

}	/* audioixp_detach */

/*
 * audioixp_intr()
 *
 * Description:
 *	Interrupt service routine for both play and record. For play we
 *	get the next buffers worth of audio. For record we send it on to
 *	the mixer.
 *
 *	There's a hardware pointer which indicate memory location where
 *	the hardware is processing. We check this pointer to decide whether
 *	to handle the buffer and how many buffers should be handled.
 *	Refer to ATI IXP400/450 Register Reference Manual, page 193,194.
 *
 * Arguments:
 *	caddr_t		arg	Pointer to the interrupting device's state
 *				structure
 *
 * Returns:
 *	DDI_INTR_CLAIMED	Interrupt claimed and processed
 *	DDI_INTR_UNCLAIMED	Interrupt not claimed, and thus ignored
 */
static uint_t
audioixp_intr(caddr_t arg)
{
	audioixp_state_t	*statep;
	uint32_t		sr;
	int			intr_claimed = DDI_INTR_UNCLAIMED;

	statep = (audioixp_state_t *)arg;
	mutex_enter(&statep->inst_lock);

	sr = IXP_AM_GET32(IXP_AUDIO_INT);

	/* PCM in interrupt */
	if (sr & IXP_AUDIO_INT_IN_DMA) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_IN_DMA);

		if (statep->flags & IXP_DMA_RECD_STARTED) {
			audioixp_reclaim_record_buf(statep);
		}
	}

	/* PCM out interrupt */
	if (sr & IXP_AUDIO_INT_OUT_DMA) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_OUT_DMA);

		if (statep->flags & IXP_DMA_PLAY_STARTED) {
			audioixp_reclaim_play_buf(statep);
			(void) audioixp_fill_play_buf(statep);
		}
	}

	/* system is too busy to process the input stream, ignore it */
	if (sr & IXP_AUDIO_INT_IN_DMA_OVERFLOW) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_IN_DMA_OVERFLOW);
	}

	/* System is too busy, ignore it */
	if (sr & IXP_AUDIO_INT_OUT_DMA_UNDERFLOW) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_OUT_DMA_UNDERFLOW);
	}

	if (sr & IXP_AUDIO_INT_CODEC0_NOT_READY) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_CODEC0_NOT_READY);
		statep -> ixp_codec_not_ready_bits |=
		    IXP_AUDIO_INT_CODEC0_NOT_READY;
	}

	if (sr & IXP_AUDIO_INT_CODEC1_NOT_READY) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_CODEC1_NOT_READY);
		statep -> ixp_codec_not_ready_bits |=
		    IXP_AUDIO_INT_CODEC1_NOT_READY;
	}

	if (sr & IXP_AUDIO_INT_CODEC2_NOT_READY) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_CODEC2_NOT_READY);
		statep -> ixp_codec_not_ready_bits |=
		    IXP_AUDIO_INT_CODEC2_NOT_READY;
	}

	if (sr & IXP_AUDIO_INT_NEW_FRAME) {
		intr_claimed = DDI_INTR_CLAIMED;
		IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_NEW_FRAME);
		statep -> ixp_codec_not_ready_bits |= IXP_AUDIO_INT_NEW_FRAME;
	}

	if (intr_claimed == DDI_INTR_UNCLAIMED) {
		mutex_exit(&statep->inst_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* update the kernel interrupt statistics */
	if (statep->ixp_ksp) {
		IXP_KIOP(statep)->intrs[KSTAT_INTR_HARD]++;
	}

	mutex_exit(&statep->inst_lock);

	ATRACE("audioixp_intr() done", statep);

	return (DDI_INTR_CLAIMED);

}	/* audioixp_intr() */

/* *********************** Mixer Entry Point Routines ******************* */
/*
 * audioixp_ad_set_config()
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
 *	AUDIO_FAILURE		The Codec parameter has not been set,
 *				or the parameter couldn't be set
 */
static int
audioixp_ad_set_config(audiohdl_t ahandle, int stream, int command,
	int dir, int arg1, int arg2)
{
	audioixp_state_t	*statep;
	int 			rc = AUDIO_SUCCESS;

	ATRACE_32("audioixp_ad_set_config() stream", stream);
	ATRACE_32("audioixp_ad_set_config() command", command);
	ATRACE_32("audioixp_ad_set_config() dir", dir);
	ATRACE_32("audioixp_ad_set_config() arg1", arg1);
	ATRACE_32("audioixp_ad_set_config() arg2", arg2);

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->inst_lock);
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
		rc = audioixp_set_gain(statep, dir, arg1, arg2);
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
		rc = audioixp_set_port(statep, dir, arg1);
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
		rc = audioixp_set_monitor_gain(statep, arg1);
		break;

	case AM_OUTPUT_MUTE:
		/*
		 * Mute or enable the output.
		 *
		 * 	dir ---> N/A
		 * 	arg1 --> ~0 == mute, 0 == enable
		 * 	arg2 --> not used
		 */
		if (arg1) {	/* mute */
			if (statep->swap_out == B_FALSE) {
				(void) audioixp_or_ac97(statep,
				    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE);
			} else {
				(void) audioixp_or_ac97(statep,
				    AC97_EXTENDED_LRS_VOLUME_REGISTER,
				    AD1980_SURR_MUTE);
			}
			(void) audioixp_or_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER, HPVR_MUTE);
			(void) audioixp_or_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MMVR_MUTE);

		} else {	/* not muted */

			/* by setting the port we unmute only active ports */
			(void) audioixp_set_port(statep,
			    AUDIO_PLAY, statep->ixp_output_port);
		}
		break;

	case AM_MIC_BOOST:
		/*
		 * Enable or disable the mic's 20 dB boost preamplifier.
		 *
		 * 	dir ---> N/A
		 * 	arg1 --> ~0 == enable, 0 == disabled
		 * 	arg2 --> not used
		 */
		if (arg1) {	/* enable */
			(void) audioixp_or_ac97(statep,
			    AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
			statep->ad_info.ad_add_mode |= AM_ADD_MODE_MIC_BOOST;
		} else {	/* disable */
			(void) audioixp_and_ac97(statep,
			    AC97_MIC_VOLUME_REGISTER,
			    (uint16_t)~MICVR_20dB_BOOST);
			statep->ad_info.ad_add_mode &=
			    ~AM_ADD_MODE_MIC_BOOST;
		}
		break;

	default:
		/*
		 * We let default catch commands we don't support, as well
		 * as bad commands.
		 *
		 * AM_SET_GAIN_BAL
		 * AM_SET_MONO_MIC
		 * AM_BASS_BOOST
		 * AM_MID_BOOST
		 * AM_TREBLE_BOOST
		 * AM_LOUDNESS
		 */
		rc = AUDIO_FAILURE;
		ATRACE_32("audioixp_ad_set_config() unsupported command",
		    command);
		break;
	}
	mutex_exit(&statep->inst_lock);

	ATRACE_32("audioixp_ad_set_config() returning", rc);

	return (rc);

}	/* audioixp_ad_set_config() */

/*
 * audioixp_ad_set_format()
 *
 * Description:
 *	This routine is used to set a new audio control data format.
 *
 * Arguments:
 * 	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		sample_rate	Data sample rate
 *	int		channels	Number of channels, 2
 *	int		precision	Bits per sample, 16
 *	int		encoding	Encoding method, linear
 *
 * Returns:
 *	AUDIO_SUCCESS	The Codec data format has been set
 *	AUDIO_FAILURE	The Codec data format has not been set, or the
 *			data format couldn't be set
 */
static int
audioixp_ad_set_format(audiohdl_t ahandle, int stream, int dir,
	int sample_rate, int channels, int precision, int encoding)
{
	audioixp_state_t	*statep;
	uint16_t		val;
	uint32_t		slot;
	uint32_t		cmd;

	ASSERT(precision == AUDIO_PRECISION_16);
	ASSERT(channels == AUDIO_CHANNELS_STEREO);
	ASSERT(encoding == AUDIO_ENCODING_LINEAR);

	ATRACE_32("audioixp_ad_set_format() stream", stream);
	ATRACE_32("audioixp_ad_set_format() dir", dir);
	ATRACE_32("audioixp_ad_set_format() sample_rate", sample_rate);
	ATRACE_32("audioixp_ad_set_format() channels", channels);
	ATRACE_32("audioixp_ad_set_format() precision", precision);
	ATRACE_32("audioixp_ad_set_format() encoding", encoding);

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->inst_lock);

	if (statep->var_sr == B_FALSE) {
		/* codec doesn't support variable sample rate */

		if (sample_rate != IXP_SAMPR48000) {
			audio_sup_log(statep->audio_handle, CE_NOTE,
			    "!audioixp_ad_set_format() bad sample"
			    " rate %d\n", sample_rate);
			mutex_exit(&statep->inst_lock);
			return (AUDIO_FAILURE);
		}
	} else {
		switch (sample_rate) {
		case IXP_SAMPR8000:	break;
		case IXP_SAMPR11025:	break;
		case IXP_SAMPR16000:	break;
		case IXP_SAMPR22050:	break;
		case IXP_SAMPR24000:	break;
		case IXP_SAMPR32000:	break;
		case IXP_SAMPR44100:	break;
		case IXP_SAMPR48000:	break;
		default:
			ATRACE_32("audioixp_ad_set_format() bad SR",
			    sample_rate);
			mutex_exit(&statep->inst_lock);
			return (AUDIO_FAILURE);
		}
	}

	if (dir == AUDIO_PLAY) {

		(void) audioixp_write_ac97(statep,
		    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, sample_rate);

		/*
		 * Some codecs before ac97 2.2, such as YMF753 produced by
		 * Yamaha LSI, don't have the AC'97 registers indexed range
		 * from 0x2c to 0x34. So we assume this kind of codec
		 * supports fixed 48k sample rate.
		 */
		if (statep->var_sr == B_TRUE) {
			(void) audioixp_read_ac97(statep,
			    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, &val);
			if (val != sample_rate) {
				ATRACE_32("audioixp_ad_set_format()"
				    " bad out SR", sample_rate);
				audio_sup_log(statep->audio_handle, CE_NOTE,
				    "!audioixp_ad_set_format() bad out"
				    " SR %d\n", sample_rate);
				mutex_exit(&statep->inst_lock);
				return (AUDIO_FAILURE);
			}
		}

		slot = IXP_AM_GET32(IXP_AUDIO_OUT_DMA_SLOT_EN_THRESHOLD);
		slot |= IXP_AUDIO_OUT_DMA_SLOT_3
		    | IXP_AUDIO_OUT_DMA_SLOT_4;
		slot &= ~ (IXP_AUDIO_OUT_DMA_SLOT_5
		    |IXP_AUDIO_OUT_DMA_SLOT_6
		    |IXP_AUDIO_OUT_DMA_SLOT_7
		    |IXP_AUDIO_OUT_DMA_SLOT_8
		    |IXP_AUDIO_OUT_DMA_SLOT_9
		    |IXP_AUDIO_OUT_DMA_SLOT_10
		    |IXP_AUDIO_OUT_DMA_SLOT_11
		    |IXP_AUDIO_OUT_DMA_SLOT_12);

		IXP_AM_PUT32(IXP_AUDIO_OUT_DMA_SLOT_EN_THRESHOLD, slot);

		cmd = IXP_AM_GET32(IXP_AUDIO_CMD);
		cmd |= IXP_AUDIO_CMD_INTER_OUT;
		IXP_AM_PUT32(IXP_AUDIO_CMD, cmd);

		statep->ixp_psample_rate = sample_rate;
		statep->ixp_pchannels = channels;
		statep->ixp_pprecision = precision;
	} else {
		(void) audioixp_write_ac97(statep,
		    AC97_EXTENDED_LR_DAC_RATE_REGISTER, sample_rate);

		/*
		 * Some codecs before ac97 2.2, such as YMF753 produced by
		 * Yamaha LSI, don't have the AC'97 registers indexed range
		 * from 0x2c to 0x34. So we assume this kind of codec
		 * supports fixed 48k sample rate.
		 */
		if (statep->var_sr == B_TRUE) {
			(void) audioixp_read_ac97(statep,
			    AC97_EXTENDED_LR_DAC_RATE_REGISTER, &val);
			if (val != sample_rate) {
				ATRACE_32("audioixp_ad_set_format() bad"
				    " in SR", sample_rate);
				audio_sup_log(statep->audio_handle, CE_NOTE,
				    "!audioixp_ad_set_format() bad in"
				    " SR %d\n", sample_rate);
				mutex_exit(&statep->inst_lock);
				return (AUDIO_FAILURE);
			}
		}

		cmd = IXP_AM_GET32(IXP_AUDIO_CMD);
		cmd |= IXP_AUDIO_CMD_INTER_IN;
		IXP_AM_PUT32(IXP_AUDIO_CMD, cmd);

		statep->ixp_csample_rate = sample_rate;
		statep->ixp_cchannels = channels;
		statep->ixp_cprecision = precision;
	}

done:
	mutex_exit(&statep->inst_lock);

	ATRACE_32("audioixp_ad_set_format() returning success", 0);

	return (AUDIO_SUCCESS);

}	/* audioixp_ad_set_format() */

/*
 * audioixp_ad_start_play()
 *
 * Description:
 *	This routine starts the playback DMA engine
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
static int
audioixp_ad_start_play(audiohdl_t ahandle, int stream)
{
	audioixp_state_t	*statep;
	int			rc = AUDIO_SUCCESS;


	ATRACE_32("audioixp_ad_start_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->inst_lock);

	if (statep->flags & IXP_DMA_PLAY_PAUSED) {
		statep->flags |= IXP_DMA_PLAY_STARTED;
		statep->flags &= ~IXP_DMA_PLAY_PAUSED;
		audioixp_start_dma(statep, AUDIO_PLAY);
		IXP_AM_UPDATE32(
		    IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_OUT,
		    IXP_AUDIO_CMD_EN_OUT);
		goto done;
	}

	if (statep->flags & IXP_DMA_PLAY_STARTED) {
		goto done;
	}

	audioixp_start_dma(statep, AUDIO_PLAY);
	rc = audioixp_fill_play_buf(statep);
	if (rc == AUDIO_SUCCESS) {
		statep->flags |= IXP_DMA_PLAY_STARTED;
	}

done:
	mutex_exit(&statep->inst_lock);
	return (rc);

}	/* audioixp_ad_start_play() */

/*
 * audioixp_ad_pause_play()
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
 * 	void
 */
static void
audioixp_ad_pause_play(audiohdl_t ahandle, int stream)
{
	audioixp_state_t	*statep;

	statep = audio_sup_get_private(ahandle);

	ASSERT(statep);
	ATRACE("audioixp_ad_pause_play() ", ahandle);
	ATRACE_32("audioixp_ad_pause_play() stream", stream);

	mutex_enter(&statep->inst_lock);

	if ((statep->flags & IXP_DMA_PLAY_STARTED) == 0) {
		mutex_exit(&statep->inst_lock);
		return;
	}
	IXP_AM_UPDATE32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT, 0);
	statep->flags |= IXP_DMA_PLAY_PAUSED;

	mutex_exit(&statep->inst_lock);

}	/* audioixp_ad_pause_play() */

/*
 * audioixp_ad_stop_play()
 *
 * Description:
 *	This routine stops the playback DMA engine.
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle for this driver
 *	int		stream		Stream number for multi-stream Codecs,
 *					which is not how we program the device
 *					for now.
 *
 * Returns:
 *	void
 */
static void
audioixp_ad_stop_play(audiohdl_t ahandle, int stream)
{
	audioixp_state_t		*statep;
	audioixp_sample_buf_t		*buf;

	ATRACE("audioixp_ad_stop_play() ", ahandle);
	ATRACE_32("audioixp_ad_stop_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->inst_lock);

	IXP_AM_UPDATE32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT, 0);
	audioixp_stop_dma(statep, AUDIO_PLAY);

	buf = &statep->play_buf;
	buf->io_started = B_FALSE;
	statep->flags &= ~(IXP_DMA_PLAY_STARTED
	    | IXP_DMA_PLAY_PAUSED | IXP_DMA_PLAY_EMPTY);

	mutex_exit(&statep->inst_lock);

}	/* audioixp_ad_stop_play() */

/*
 * audioixp_ad_start_record()
 *
 * Description:
 *	This routine starts the PCM in DMA engine
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
static int
audioixp_ad_start_record(audiohdl_t ahandle, int stream)
{
	audioixp_state_t	*statep;
	int			rc;

	ATRACE("audioixp_ad_start_record() ", ahandle);
	ATRACE_32("audioixp_ad_start_record() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->inst_lock);

	if (statep->flags & IXP_DMA_RECD_STARTED) {
		mutex_exit(&statep->inst_lock);
		return (AUDIO_SUCCESS);
	}

	audioixp_start_dma(statep, AUDIO_RECORD);
	rc = audioixp_prepare_record_buf(statep);
	if (rc == AUDIO_SUCCESS) {
		statep->flags |= IXP_DMA_RECD_STARTED;
	}

	mutex_exit(&statep->inst_lock);

	return (rc);

}	/* audioixp_ad_start_record() */

/*
 * audioixp_ad_stop_record()
 *
 * Description:
 *	This routine stops the PCM in DMA engine
 *
 * Arguments:
 *	audiohdl_t	ahandle		Handle for this driver
 *	int		stream		Stream number for multi-stream
 *					Codecs, which isn't going to apply
 *					for record
 *
 * Returns:
 *	void
 */
static void
audioixp_ad_stop_record(audiohdl_t ahandle, int stream)
{
	audioixp_state_t		*statep;
	audioixp_sample_buf_t		*buf;

	ATRACE("audioixp_ad_stop_record() ", ahandle);
	ATRACE_32("audioixp_ad_stop_record() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->inst_lock);
	statep->flags &= ~IXP_DMA_RECD_STARTED;

	buf = &statep->record_buf;
	buf->io_started = B_FALSE;

	IXP_AM_UPDATE32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN, 0);
	audioixp_stop_dma(statep, AUDIO_RECORD);

	mutex_exit(&statep->inst_lock);

}	/* audioixp_ad_stop_record() */

/* *********************** Local Routines *************************** */

/*
 * audioixp_init_state()
 *
 * Description:
 *	This routine initializes the audio driver's state structure
 *
 *	CAUTION: This routine cannot allocate resources, unless it frees
 *		them before returning for an error. Also, error_destroy:
 *		in audioixp_attach() would need to be fixed as well.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	dev_info_t		*dip		Pointer to the device's
 *						dev_info struct
 *
 * Returns:
 *	AUDIO_SUCCESS		State structure initialized
 *	AUDIO_FAILURE		State structure not initialized
 */
static int
audioixp_init_state(audioixp_state_t *statep, dev_info_t *dip)
{
	int rints;
	int pints;
	int cdrom;
	int mode;

	ATRACE("audioixp_init_state()", NULL);

	statep->dip = dip;
	statep->vol_bits_mask = 5;

	cdrom = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "cdrom", 0);

	/* get the mode from the .conf file */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mixer-mode", 1)) {
		mode = AM_MIXER_MODE;
	} else {
		mode = AM_COMPAT_MODE;
	}

	pints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "play-interrupts", IXP_INTS);
	if (pints > IXP_MAX_INTS) {
		ATRACE_32("audioixp_init_state() "
		    "play interrupt rate too high, resetting", pints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "audioixp_init_state() "
		    "play interrupt rate set too high, %d, resetting to %d",
		    pints, IXP_INTS);
		pints = IXP_INTS;
	} else if (pints < IXP_MIN_INTS) {
		ATRACE_32("audioixp_init_state() "
		    "play interrupt rate too low, resetting", pints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "audioixp_init_state() "
		    "play interrupt rate set too low, %d, resetting to %d",
		    pints, IXP_INTS);
		pints = IXP_INTS;
	}
	rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "record-interrupts", IXP_INTS);
	if (rints > IXP_MAX_INTS) {
		ATRACE_32("audioixp_init_state() "
		    "record interrupt rate too high, resetting", rints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "audioixp_init_state() "
		    "record interrupt rate set too high, %d, resetting to "
		    "%d",
		    rints, IXP_INTS);
		rints = IXP_INTS;
	} else if (rints < IXP_MIN_INTS) {
		ATRACE_32("audioixp_init_state() "
		    "record interrupt rate too low, resetting", rints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "audioixp_init_state() "
		    "record interrupt rate set too low, %d, resetting to "
		    "%d",
		    rints, IXP_INTS);
		rints = IXP_INTS;
	}

	/* fill in the device default state */
	statep->ixp_defaults.play.sample_rate = IXP_DEFAULT_SR;
	statep->ixp_defaults.play.channels = IXP_DEFAULT_CH;
	statep->ixp_defaults.play.precision = IXP_DEFAULT_PREC;
	statep->ixp_defaults.play.encoding = IXP_DEFAULT_ENC;
	statep->ixp_defaults.play.gain = IXP_DEFAULT_PGAIN;
	statep->ixp_defaults.play.port =
	    AUDIO_SPEAKER | AUDIO_LINE_OUT;
	statep->ixp_defaults.play.avail_ports =
	    AUDIO_SPEAKER | AUDIO_LINE_OUT;
	statep->ixp_defaults.play.mod_ports =
	    AUDIO_SPEAKER | AUDIO_LINE_OUT;
	statep->ixp_defaults.play.buffer_size = IXP_BSIZE;
	statep->ixp_defaults.play.balance = IXP_DEFAULT_BAL;

	statep->ixp_defaults.record.sample_rate = IXP_DEFAULT_SR;
	statep->ixp_defaults.record.channels = IXP_DEFAULT_CH;
	statep->ixp_defaults.record.precision = IXP_DEFAULT_PREC;
	statep->ixp_defaults.record.encoding = IXP_DEFAULT_ENC;
	statep->ixp_defaults.record.gain = IXP_DEFAULT_PGAIN;
	statep->ixp_defaults.record.port = AUDIO_MICROPHONE;
	statep->ixp_defaults.record.avail_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	statep->ixp_defaults.record.mod_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	statep->ixp_defaults.record.buffer_size = IXP_BSIZE;
	statep->ixp_defaults.record.balance = IXP_DEFAULT_BAL;

	statep->ixp_defaults.monitor_gain = IXP_DEFAULT_MONITOR_GAIN;
	statep->ixp_defaults.output_muted = B_FALSE;
	statep->ixp_defaults.ref_cnt = B_FALSE;
	statep->ixp_defaults.hw_features =
	    AUDIO_HWFEATURE_DUPLEX | AUDIO_HWFEATURE_PLAY |
	    AUDIO_HWFEATURE_IN2OUT | AUDIO_HWFEATURE_RECORD;
	statep->ixp_defaults.sw_features = AUDIO_SWFEATURE_MIXER;

	if (cdrom) {
		statep->ixp_defaults.record.avail_ports |= AUDIO_CD;
		statep->ixp_defaults.record.mod_ports |= AUDIO_CD;
	}

	statep->ixp_psample_rate =
	    statep->ixp_defaults.play.sample_rate;
	statep->ixp_pchannels =
	    statep->ixp_defaults.play.channels;
	statep->ixp_pprecision =
	    statep->ixp_defaults.play.precision;
	statep->ixp_csample_rate =
	    statep->ixp_defaults.record.sample_rate;
	statep->ixp_cchannels =
	    statep->ixp_defaults.record.channels;
	statep->ixp_cprecision =
	    statep->ixp_defaults.record.precision;

	/*
	 * fill in the ad_info structure
	 */
	statep->ad_info.ad_mode = mode;
	statep->ad_info.ad_int_vers = AM_VERSION;
	statep->ad_info.ad_add_mode = NULL;
	statep->ad_info.ad_codec_type = AM_TRAD_CODEC;
	statep->ad_info.ad_defaults = &statep->ixp_defaults;
	statep->ad_info.ad_play_comb = audioixp_combinations;
	statep->ad_info.ad_rec_comb = audioixp_combinations;
	statep->ad_info.ad_entry = &audioixp_entry;
	statep->ad_info.ad_dev_info = &statep->ixp_dev_info;
	statep->ad_info.ad_diag_flags = AM_DIAG_INTERNAL_LOOP;
	statep->ad_info.ad_diff_flags =
	    AM_DIFF_SR | AM_DIFF_CH | AM_DIFF_PREC | AM_DIFF_ENC;
	statep->ad_info.ad_assist_flags = AM_ASSIST_MIC;
	statep->ad_info.ad_misc_flags = AM_MISC_RP_EXCL | AM_MISC_MONO_DUP;
	statep->ad_info.ad_num_mics = 1;

	/* play capabilities */
	statep->ad_info.ad_play.ad_mixer_srs =
	    audioixp_mixer_sample_rates;
	statep->ad_info.ad_play.ad_compat_srs =
	    audioixp_compat_sample_rates;
	statep->ad_info.ad_play.ad_conv = &am_src2;
	statep->ad_info.ad_play.ad_sr_info = NULL;
	statep->ad_info.ad_play.ad_chs = audioixp_channels;
	statep->ad_info.ad_play.ad_int_rate = pints;
	statep->ad_info.ad_play.ad_max_chs = IXP_MAX_OUT_CHANNELS;
	statep->ad_info.ad_play.ad_bsize = IXP_BSIZE;

	/* record capabilities */
	statep->ad_info.ad_record.ad_mixer_srs =
	    audioixp_mixer_sample_rates;
	statep->ad_info.ad_record.ad_compat_srs =
	    audioixp_compat_sample_rates;
	statep->ad_info.ad_record.ad_conv = &am_src2;
	statep->ad_info.ad_record.ad_sr_info = NULL;
	statep->ad_info.ad_record.ad_chs = audioixp_channels;
	statep->ad_info.ad_record.ad_int_rate = rints;
	statep->ad_info.ad_record.ad_max_chs = IXP_MAX_CHANNELS;
	statep->ad_info.ad_record.ad_bsize = IXP_BSIZE;

	if (ddi_get_iblock_cookie(dip, (uint_t)0, &statep->intr_iblock) !=
	    DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_init_state() cannot get iblock cookie");
		return (AUDIO_FAILURE);
	}
	mutex_init(&statep->inst_lock, NULL, MUTEX_DRIVER, statep->intr_iblock);

	/* fill in device info strings */
	(void) strcpy(statep->ixp_dev_info.name, IXP_DEV_NAME);
	(void) strcpy(statep->ixp_dev_info.config, IXP_DEV_CONFIG);
	(void) strcpy(statep->ixp_dev_info.version, IXP_DEV_VERSION);

	statep->play_buf_size = IXP_SAMPR48000 * AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / pints;
	statep->play_buf_size += IXP_MOD_SIZE -
	    (statep->play_buf_size % IXP_MOD_SIZE);
	statep->record_buf_size = IXP_SAMPR48000 * AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / rints;
	statep->record_buf_size += IXP_MOD_SIZE - 1;
	statep->record_buf_size -= statep->record_buf_size % IXP_MOD_SIZE;

	return (AUDIO_SUCCESS);

}	/* audioixp_init_state() */

/*
 * audioixp_map_regs()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use. Finally, the registers are mapped in.
 *
 *	CAUTION: Make sure all errors call audio_sup_log().
 *
 * Arguments:
 *	dev_info_t		*dip		Pointer to the device's devinfo
 *	audioixp_state_t	*state		  The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
audioixp_map_regs(dev_info_t *dip, audioixp_state_t *statep)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;

	ATRACE("audioixp_map_regs()", statep);

	statep->ixp_res_flags = 0;

	/* map PCI config space */
	if (pci_config_setup(statep->dip, &statep->pci_conf_handle) ==
	    DDI_FAILURE) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_map_regs() configuration "
		    "memory mapping failed");
		goto error;
	}
	statep->ixp_res_flags |= IXP_RS_PCI_REGS;

	/* map audio mixer register */
	if ((ddi_regs_map_setup(dip, IXP_IO_AM_REGS,
	    (caddr_t *)&statep->am_regs_base, 0, 0,
	    &dev_attr, &statep->am_regs_handle)) != DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_map_regs() audio mixer "
		    "memory mapping failed");
		goto error;
	}
	statep->ixp_res_flags |= IXP_RS_AM_REGS;

	/*
	 * now, from here we allocate DMA memory for buffer descriptor list.
	 * we allocate adjacent DMA memory for all DMA engines.
	 */
	if (ddi_dma_alloc_handle(dip, &bdlist_dma_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &statep->bdl_dma_handle) != DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_map_regs() ddi_dma_alloc_handle(bdlist)"
		    " failed");
		goto error;
	}
	statep->ixp_res_flags |= IXP_RS_DMA_BDL_HANDLE;

	if (ddi_dma_mem_alloc(statep->bdl_dma_handle,
	    sizeof (audioixp_bd_list_t), &dev_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, (caddr_t *)&statep->bdl_virtual,
	    &statep->bdl_size, &statep->bdl_acc_handle) != DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_map_regs() ddi_dma_mem_alloc(bdlist) "
		    "failed");
		goto error;
	}
	statep->ixp_res_flags |= IXP_RS_DMA_BDL_MEM;

	if (ddi_dma_addr_bind_handle(statep->bdl_dma_handle, NULL,
	    (caddr_t)statep->bdl_virtual, statep->bdl_size,
	    DDI_DMA_RDWR|DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &cookie,
	    &count) != DDI_DMA_MAPPED) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_map_regs() addr_bind_handle failed");
		goto error;
	}

	/*
	 * there are some bugs in the DDI framework and it is possible to
	 * get multiple cookies
	 */
	if (count != 1) {
		(void) ddi_dma_unbind_handle(statep->bdl_dma_handle);
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_map_regs() addr_bind_handle failed,"
		    " cookies > 1");
		goto error;
	}

	statep->bdl_phys =
	    (audioixp_bd_list_t *)(long)(cookie.dmac_address);
	statep->ixp_res_flags |= IXP_RS_DMA_BDL_BIND;

	return (AUDIO_SUCCESS);

error:
	audioixp_unmap_regs(statep);

	return (AUDIO_FAILURE);

}	/* audioixp_map_regs() */

/*
 * audioixp_unmap_regs()
 *
 * Description:
 *	This routine unbinds the play and record DMA handles, frees
 *	the DMA buffers and then unmaps control registers.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audioixp_unmap_regs(audioixp_state_t *statep)
{
	if (statep->ixp_res_flags & IXP_RS_DMA_BDL_BIND) {
		statep->ixp_res_flags &= ~IXP_RS_DMA_BDL_BIND;
		(void) ddi_dma_unbind_handle(statep->bdl_dma_handle);
	}

	if (statep->ixp_res_flags & IXP_RS_DMA_BDL_MEM) {
		statep->ixp_res_flags &= ~IXP_RS_DMA_BDL_MEM;
		ddi_dma_mem_free(&statep->bdl_acc_handle);
	}

	if (statep->ixp_res_flags & IXP_RS_DMA_BDL_HANDLE) {
		statep->ixp_res_flags &= ~IXP_RS_DMA_BDL_HANDLE;
		ddi_dma_free_handle(&statep->bdl_dma_handle);
	}

	if (statep->ixp_res_flags & IXP_RS_AM_REGS) {
		statep->ixp_res_flags &= ~IXP_RS_AM_REGS;
		ddi_regs_map_free(&statep->am_regs_handle);
	}

	if (statep->ixp_res_flags & IXP_RS_PCI_REGS) {
		statep->ixp_res_flags &= ~IXP_RS_PCI_REGS;
		pci_config_teardown(&statep->pci_conf_handle);
	}

}	/* audioixp_unmap_regs() */

/*
 * audioixp_alloc_sample_buf()
 *
 * Description:
 *	This routine allocates DMA buffers for the sample buffer. It
 *	allocates two DMA chunks (buffers) to the specified DMA engine
 *	(sample buffer structure). The two data chunks will be bound
 *	to the buffer descriptor entries of corresponding buffer
 *	descriptor list, and be used to transfer audio sample data to
 *	and from the audio controller.
 *
 * Arguments:
 *	audioixp_state_t	*state	The device's state structure
 *	int			which	Which sample buffer, PCM in or PCM out
 *					IXP_DMA_PCM_IN ---PCM in DMA engine
 *					IXP_DMA_PCM_OUT---PCM out DMA engine
 *	int			len	The length of the DMA buffers
 *
 * Returns:
 *	AUDIO_SUCCESS	 Allocating DMA buffers successfully
 *	AUDIO_FAILURE	 Failed to allocate dma buffers
 */

static int
audioixp_alloc_sample_buf(audioixp_state_t *statep, int which, int len)
{
	audioixp_sample_buf_t	*buf;
	audioixp_bdlist_chunk_t	*chunk;
	ddi_dma_cookie_t		cookie;
	uint_t				count;
	int				i;

	if (which == IXP_DMA_PCM_OUT) {
		buf = &statep->play_buf;
	} else {
		ASSERT(which == IXP_DMA_PCM_IN);
		buf = &statep->record_buf;
	}

	for (i = 0; i < 2; i++) {
		chunk = &(buf->chunk[i]);

		if (ddi_dma_alloc_handle(statep->dip, &sample_buf_dma_attr,
		    DDI_DMA_SLEEP, NULL, &chunk->dma_handle) !=
		    DDI_SUCCESS) {
			goto error;
		}

		if (ddi_dma_mem_alloc(chunk->dma_handle, len, &dev_attr,
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    &chunk->data_buf, &chunk->real_len,
		    &chunk->acc_handle) != DDI_SUCCESS) {
			ddi_dma_free_handle(&chunk->dma_handle);
			goto error;
		}

		if (ddi_dma_addr_bind_handle(chunk->dma_handle, NULL,
		    chunk->data_buf, chunk->real_len, DDI_DMA_WRITE,
		    DDI_DMA_SLEEP, NULL, &cookie, &count) !=
		    DDI_DMA_MAPPED) {
			ddi_dma_mem_free(&chunk->acc_handle);
			ddi_dma_free_handle(&chunk->dma_handle);
			goto error;
		}

		/*
		 * there some bugs in the DDI framework and it is possible to
		 * get multiple cookies
		 */
		if (count != 1) {
			(void) ddi_dma_unbind_handle(chunk->dma_handle);
			ddi_dma_mem_free(&chunk->acc_handle);
			ddi_dma_free_handle(&chunk->dma_handle);
			goto error;
		}

		chunk->addr_phy = (uint32_t)cookie.dmac_address;
	}

	return (AUDIO_SUCCESS);

error:
	if (i != 0) {
		(void) ddi_dma_unbind_handle((buf->chunk[0].dma_handle));
		ddi_dma_mem_free(&(buf->chunk[0].acc_handle));
		ddi_dma_free_handle(&(buf->chunk[0].dma_handle));
	}

	return (AUDIO_FAILURE);

}	/* audioixp_alloc_sample_buf() */

/*
 * audioixp_free_sample_buf()
 *
 * Description:
 *	This routine frees the DMA buffers of the sample buffer. The DMA
 *	buffers were allocated by calling audioixp_alloc_sample_buf().
 *
 * Arguments:
 *	audioixp_state_t		*state	The device's state structure
 *	audioixp_sample_buf_t	*buf	The sample buffer structure
 *
 * Returns:
 *	void
 */
static void
audioixp_free_sample_buf(audioixp_state_t *statep,
	audioixp_sample_buf_t *buf)
{
	audioixp_bdlist_chunk_t	*chunk;
	int 				i;

	ATRACE("audioixp_free_sample_buf() audioixp_statep", statep);

	for (i = 0; i < 2; i++) {
		chunk = &(buf->chunk[i]);
		(void) ddi_dma_unbind_handle(chunk->dma_handle);
		ddi_dma_mem_free(&chunk->acc_handle);
		chunk->acc_handle = 0;
		ddi_dma_free_handle(&chunk->dma_handle);
	}

}	/* audioixp_free_sample_buf() */


/*
 * audioixp_setup_bdl()
 *
 * Description:
 * 	This routine setup the buf descriptor list.
 *
 * Arguments:
 *	audioixp_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */

static void audioixp_setup_bdl(audioixp_state_t *statep)
{
	int i;
	audioixp_bd_entry_t *bd_p;

	/* setup playback bdlist */
	for (i = 0; i < IXP_BD_NUMS; i ++) {
		bd_p = &(((audioixp_bd_list_t *)(statep->bdl_virtual))
		    ->pcm_out[i]);
		bd_p->buf_base = statep->play_buf.chunk[i&IXP_CHUNK_MASK]
		    .addr_phy;
		bd_p->status = 0;
		bd_p->buf_len = 0;
		bd_p->next = (uintptr_t)&(((audioixp_bd_list_t *)
		    (statep->bdl_phys))->pcm_out[(i+1)%IXP_BD_NUMS]);
	}

	/* setup record bdlist */
	for (i = 0; i < IXP_BD_NUMS; i ++) {
		bd_p = &(((audioixp_bd_list_t *)(statep->bdl_virtual))
		    ->pcm_in[i]);
		bd_p->buf_base = statep->record_buf.chunk[i&IXP_CHUNK_MASK]
		    .addr_phy;
		bd_p->status = 0;
		bd_p->buf_len = 0;
		bd_p->next = (uintptr_t)&(((audioixp_bd_list_t *)
		    (statep->bdl_phys))->pcm_in[(i+1)%IXP_BD_NUMS]);
	}
}	/* audioixp_setup_bdl() */

/*
 * audioixp_start_dma()
 *
 * Description:
 *	This routine is used to put each DMA engine into working state.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audioixp_start_dma(audioixp_state_t *statep, int dir)
{

	ASSERT(dir == AUDIO_PLAY || dir == AUDIO_RECORD);

	if (dir == AUDIO_PLAY) {
		IXP_AM_PUT32(IXP_AUDIO_FIFO_FLUSH, IXP_AUDIO_FIFO_FLUSH_OUT);
		IXP_AM_UPDATE32(IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_OUT_DMA,
		    IXP_AUDIO_CMD_EN_OUT_DMA);
	} else {
		IXP_AM_PUT32(IXP_AUDIO_FIFO_FLUSH, IXP_AUDIO_FIFO_FLUSH_IN);
		IXP_AM_UPDATE32(IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_IN_DMA,
		    IXP_AUDIO_CMD_EN_IN_DMA);
	}

}	/* audioixp_start_dma() */

/*
 * audioixp_stop_dma()
 *
 * Description:
 *	This routine is used to put each DMA engine into the quiet state.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audioixp_stop_dma(audioixp_state_t *statep, int dir)
{

	ASSERT(dir == AUDIO_PLAY || dir == AUDIO_RECORD);

	IXP_AM_PUT32(IXP_AUDIO_FIFO_FLUSH, IXP_AUDIO_FIFO_FLUSH_IN);

	if (dir == AUDIO_PLAY) {
		IXP_AM_UPDATE32(IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_OUT_DMA,
		    0);
	} else {
		IXP_AM_UPDATE32(IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_IN_DMA,
		    0);
	}

}	/* audioixp_stop_dma() */


/*
 * audioixp_codec_ready ()
 *
 * Description:
 *	This routine checks the state of codecs. This routine is called by
 *	chip_init before interrupt is enabled. It enables interrupt first,
 *	then waits a moment for interrupt handler to set the flag according
 *	to the hardware configuration. Then it checks the flag to confirm
 *	that primary codec is ready. The original value of interrupt enable
 *	register is restored.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS	 codec is ready
 *	AUDIO_FAILURE	 codec is not ready
 */
static int
audioixp_codec_ready(audioixp_state_t *statep)
{
	uint32_t	old_reg;

	old_reg = IXP_AM_GET32(IXP_AUDIO_INT_EN);

	IXP_AM_UPDATE32(IXP_AUDIO_INT_EN,
	    IXP_AUDIO_INT_EN_CODEC0_NOT_READY
	    | IXP_AUDIO_INT_EN_CODEC1_NOT_READY
	    | IXP_AUDIO_INT_EN_CODEC2_NOT_READY,
	    IXP_AUDIO_INT_EN_CODEC0_NOT_READY
	    | IXP_AUDIO_INT_EN_CODEC1_NOT_READY
	    | IXP_AUDIO_INT_EN_CODEC2_NOT_READY);

	drv_usecwait(1000);
	IXP_AM_PUT32(IXP_AUDIO_INT_EN, old_reg);

	if (statep->ixp_codec_not_ready_bits & IXP_AUDIO_INT_CODEC0_NOT_READY) {
		audio_sup_log(NULL, CE_WARN, "primary codec not ready");
		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);
}

/*
 * audioixp_codec_sync()
 *
 * Description:
 *	Serialize access to the AC97 audio mixer registers.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Ready for an I/O access to the codec
 *	AUDIO_FAILURE		An I/O access is currently in progress, can't
 *				perform another I/O access.
 */
static int
audioixp_codec_sync(audioixp_state_t *statep)
{
	int 		i;
	uint32_t	cmd;

	for (i = 0; i < 300; i++) {
		cmd = IXP_AM_GET32(IXP_AUDIO_OUT_PHY_ADDR_DATA);
		if (!(cmd & IXP_AUDIO_OUT_PHY_EN)) {
			return (AUDIO_SUCCESS);
		}
		drv_usecwait(10);
	}

	return (AUDIO_FAILURE);

}	/* audioixp_codec_sync() */


/*
 * audioixp_read_ac97()
 *
 * Description:
 *	Get the specific AC97 Codec register. It also updates codec_shadow[]
 *	with the register value.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		*data		The data to be returned
 *
 * Returns:
 *	AUDIO_SUCCESS		Reading the codec register successfully
 *	AUDIO_FAILURE		Failed to read the register
 */
static int
audioixp_read_ac97(audioixp_state_t *statep, int reg, uint16_t *data)
{
	uint32_t	value;
	uint32_t	result;
	int		i;

	if (audioixp_codec_sync(statep) != AUDIO_SUCCESS) {
		*data = 0xffff;
		return (AUDIO_FAILURE);
	}

	value = IXP_AUDIO_OUT_PHY_PRIMARY_CODEC
	    | IXP_AUDIO_OUT_PHY_READ
	    | IXP_AUDIO_OUT_PHY_EN
	    | ((reg << IXP_AUDIO_OUT_PHY_ADDR_SHIFT)
	    & IXP_AUDIO_OUT_PHY_ADDR_MASK);
	IXP_AM_PUT32(IXP_AUDIO_OUT_PHY_ADDR_DATA, value);

	if (audioixp_codec_sync(statep) != AUDIO_SUCCESS) {
		*data = 0xffff;
		return (AUDIO_FAILURE);
	}

	for (i = 0; i < 300; i++) {
		result = IXP_AM_GET32(IXP_AUDIO_IN_PHY_ADDR_DATA);
		if (result & IXP_AUDIO_IN_PHY_READY)	{
			*data = (result & IXP_AUDIO_IN_PHY_DATA_MASK)
			    >> IXP_AUDIO_IN_PHY_DATA_SHIFT;
			statep->codec_shadow[IXP_CODEC_REG(reg)] = *data;
			return (AUDIO_SUCCESS);
		}
		drv_usecwait(10);
	}

	*data = 0xffff;
	return (AUDIO_FAILURE);

}	/* audioixp_read_ac97() */

/*
 * audioixp_write_ac97()
 *
 * Description:
 *	Set the specific AC97 Codec register.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The data want to be set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audioixp_write_ac97(audioixp_state_t *statep, int reg, uint16_t data)
{
	uint16_t	tmp;
	uint32_t	value;

	if (audioixp_codec_sync(statep) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	value = IXP_AUDIO_OUT_PHY_PRIMARY_CODEC
	    | IXP_AUDIO_OUT_PHY_WRITE
	    | IXP_AUDIO_OUT_PHY_EN
	    | ((reg << IXP_AUDIO_OUT_PHY_ADDR_SHIFT)
	    & IXP_AUDIO_OUT_PHY_ADDR_MASK)
	    | ((data << IXP_AUDIO_OUT_PHY_DATA_SHIFT)
	    & IXP_AUDIO_OUT_PHY_DATA_MASK);
	IXP_AM_PUT32(IXP_AUDIO_OUT_PHY_ADDR_DATA, value);

	(void) audioixp_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audioixp_write_ac97() */

/*
 * audioixp_and_ac97()
 *
 * Description:
 *	Logically AND the value with the specified ac97 codec register
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The value to AND
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audioixp_and_ac97(audioixp_state_t *statep, int reg, uint16_t data)
{
	data &= statep->codec_shadow[IXP_CODEC_REG(reg)];
	if (audioixp_write_ac97(statep, reg, data) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audioixp_and_ac97() */

/*
 * audioixp_or_ac97()
 *
 * Description:
 *	Logically OR the value with the specified ac97 codec register
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The value to OR
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audioixp_or_ac97(audioixp_state_t *statep, int reg, uint16_t data)
{
	data |= statep->codec_shadow[IXP_CODEC_REG(reg)];
	if (audioixp_write_ac97(statep, reg, data) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audioixp_or_ac97() */

/*
 * audioixp_reset_ac97()
 *
 * Description:
 *	Reset AC97 Codec register.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Reset the codec successfully
 *	AUDIO_FAILURE		Failed to reset the codec
 */
static int
audioixp_reset_ac97(audioixp_state_t *statep)
{
	uint32_t	cmd;
	int i;

	IXP_AM_UPDATE32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_POWER_DOWN, 0);
	drv_usecwait(10);

	/* register reset */
	IXP_AM_UPDATE32(IXP_AUDIO_CMD,
	    IXP_AUDIO_CMD_AC_SOFT_RESET,
	    IXP_AUDIO_CMD_AC_SOFT_RESET);

	drv_usecwait(10);
	IXP_AM_UPDATE32(IXP_AUDIO_CMD,
	    IXP_AUDIO_CMD_AC_SOFT_RESET,
	    0);

	/* cold reset */
	for (i = 0; i < 300; i++) {
		cmd = IXP_AM_GET32(IXP_AUDIO_CMD);
		if (cmd & IXP_AUDIO_CMD_AC_ACTIVE) {
			cmd |= IXP_AUDIO_CMD_AC_RESET;
			IXP_AM_PUT32(IXP_AUDIO_CMD, cmd);
			return (AUDIO_SUCCESS);
		}
		cmd &= ~IXP_AUDIO_CMD_AC_RESET;
		IXP_AM_PUT32(IXP_AUDIO_CMD, cmd);
		(void) IXP_AM_GET32(IXP_AUDIO_CMD);
		drv_usecwait(10);
		cmd |= IXP_AUDIO_CMD_AC_RESET;
		IXP_AM_PUT32(IXP_AUDIO_CMD, cmd);
		drv_usecwait(10);
	}

	return (AUDIO_FAILURE);

}	/* audioixp_reset_ac97() */

/*
 * audioixp_chunk_processed()
 *
 * Description:
 *	This routine returns the count of chunk processed. It's called by
 *	audioixp_reclaim_play_buf and audioixp_reclaim_record_buf
 *	This routine compares the current hw_point value with its last value,
 *	there're two cases:
 *	case 1: new pointer is bigger than the last one and smaller than the
 *		last one + len of the last chunk, which mean the current
 *		chunk has not been finished, return 0.
 *	case 2: the hw_pointer return to the old value, which means both chunks
 *		have been processed,return 2
 *	case 3: one chunk is processed, return 1.
 *
 * Arguments:
 *	audioixp_state_t 	*statep	The device's state structure
 *	int			dir	AUDIO_PLAY or AUDIO_RECORD, if
 *					direction is important
 *
 * Returns:
 *	count of chunk processed
 */
static int
audioixp_chunk_processed(audioixp_state_t *statep, int dir)
{
	audioixp_sample_buf_t	*buf;
	uint32_t 		hw_pointer;
	int			result;
	audioixp_bd_entry_t	*bd;
	int 			i;
	int			retry_count;

	ASSERT(mutex_owned(&statep->inst_lock));

	retry_count = 0;
	while (++retry_count < 100) {
		if (dir == AUDIO_PLAY) {
			buf = &statep->play_buf;
			hw_pointer = IXP_AM_GET32(IXP_AUDIO_OUT_DMA_DT_CUR);
		} else {
			buf = &statep->record_buf;
			hw_pointer = IXP_AM_GET32(IXP_AUDIO_IN_DMA_DT_CUR);
		}

		for (i = 0; i < IXP_BD_NUMS; i ++) {
			if (dir == AUDIO_PLAY)
				bd = &statep->bdl_virtual->pcm_out[i];
			else
				bd = &statep->bdl_virtual->pcm_in[i];

			if (hw_pointer >= bd->buf_base &&
			    hw_pointer < bd->buf_base + bd->buf_len*4)
				break;
		}

		if (i < IXP_BD_NUMS)
			break;
	}

	/*
	 * cannot get valid hw_pointer, return 0 without updating
	 * last_hw_pointer
	 */
	if (retry_count == 100) {
		cmn_err(CE_WARN, "!bad hw_pointer, hw_pointer=0x%08x",
		    hw_pointer);
		for (i = 0; i < IXP_BD_NUMS; i ++) {
			if (dir == AUDIO_PLAY)
				bd = &statep->bdl_virtual->pcm_out[i];
			else
				bd = &statep->bdl_virtual->pcm_in[i];

			cmn_err(CE_WARN, "!bd[%d], base=0x%08x, len=0x%x",
			    i, bd->buf_base, bd->buf_len);
		}
		return (0);
	}

	if (buf->last_hw_pointer >= bd->buf_base && /* case 1 */
	    hw_pointer > buf->last_hw_pointer &&
	    hw_pointer < bd->buf_base + bd->buf_len * 4)
		result = 0;
	else if (buf->last_hw_pointer == hw_pointer) /* case 2 */
		result = 2;
	else /* case 3 */
		result = 1;

	buf->last_hw_pointer = hw_pointer;

	return (result);

}	/* audioixp_chunk_processed() */

/*
 * audioixp_fill_play_buf()
 *
 * Description:
 *	This routine is called by audioixp_ad_start_play() and the
 * 	interrupt handler. It fills playback samples into the DMA memory,
 *	sets the BDL entries, and starts the playback DMA engine.
 *
 * Arguments:
 *	audioixp_state_t 	*statep	The device's state structure
 *
 * Returns:
 * 	AUDIO_SUCCESS		Starting PCM out engine successfully
 * 	AUDIO_FAILURE		Failed to start PCM out engine.
 */
static int
audioixp_fill_play_buf(audioixp_state_t *statep)
{
	audioixp_bdlist_chunk_t	*chunk;
	audioixp_sample_buf_t	*buf;
	audioixp_bd_entry_t		*bdesc;
	int				samples;
	int				rs;

	buf = &statep->play_buf;

	if (!buf->io_started) {
		/*
		 * ready to start PCM out engine
		 */
		IXP_AM_PUT32(
		    IXP_AUDIO_OUT_DMA_LINK_P,
		    (uint32_t)(uintptr_t)statep->bdl_phys->pcm_out |
		    IXP_AUDIO_OUT_DMA_LINK_P_EN);

		buf->next = 0;
		buf->avail = 2;	/* have only two buffers for playback */
		buf->last_hw_pointer = statep->bdl_virtual->pcm_out[0].buf_base;
	}

	if (buf->avail == 0) {
		return (AUDIO_SUCCESS);
	}

	samples = statep->ixp_psample_rate * statep->ixp_pchannels /
	    statep->ad_info.ad_play.ad_int_rate;

	/* if not an even number of samples we panic! */
	if ((samples & 1) != 0) {
		samples++;
	}

	while (buf->avail > 0) {
		chunk = &(buf->chunk[buf->next & 1]);
		mutex_exit(&statep->inst_lock);
		rs = am_get_audio(statep->audio_handle,
		    (char *)(chunk->data_buf), AUDIO_NO_CHANNEL, samples);

		mutex_enter(&statep->inst_lock);

		if (((statep->flags & IXP_DMA_PLAY_STARTED) == 0) &&
		    (buf->io_started)) {
			return (AUDIO_FAILURE);
		}

		if (rs <= 0) {
			if (statep->flags & IXP_DMA_PLAY_EMPTY) {

				/*
				 * Clear the flag so if audio is restarted while
				 * in am_play_shutdown() we can detect it and
				 * not mess things up.
				 */
				statep->flags &= ~IXP_DMA_PLAY_STARTED;

				/* shutdown the mixer */
				mutex_exit(&statep->inst_lock);
				am_play_shutdown(statep->audio_handle, NULL);
				mutex_enter(&statep->inst_lock);

				/*
				 * Make sure playing wasn't restarted when lock
				 * lost if reopened, should return success
				 */
				if (statep->flags & IXP_DMA_PLAY_STARTED) {
					return (AUDIO_SUCCESS);
				}

				/* Finished playing, then stop it */
				IXP_AM_UPDATE32(IXP_AUDIO_CMD,
				    IXP_AUDIO_CMD_EN_OUT,
				    0);

				buf->io_started = B_FALSE;

				/* clr the flags getting ready for next start */
				statep->flags &= ~(IXP_DMA_PLAY_PAUSED |
				    IXP_DMA_PLAY_EMPTY);

				return (AUDIO_FAILURE);
			} else {
				/*
				 * this time, we use one BD entry with empty
				 * buffer next time we shut down, if no sound
				 * again
				 */
				statep->flags |= IXP_DMA_PLAY_EMPTY;
			}
		} else {
			/* we got at least one sample */
			statep->flags &= ~IXP_DMA_PLAY_EMPTY;
			(void) ddi_dma_sync(chunk->dma_handle, 0, rs<<1,
			    DDI_DMA_SYNC_FORDEV);
		}

		/* put the samples into buffer descriptor list entry */
		bdesc = &(statep->bdl_virtual->pcm_out[buf->next]);
		bdesc->buf_len = (uint16_t)rs>>1; /* in dword */

		buf->avail --;
		buf->next ++;
		buf->next %= IXP_BD_NUMS;
	}

	/* start PCM out engine */
	if (!buf->io_started) {
		IXP_AM_UPDATE32(
		    IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_OUT,
		    IXP_AUDIO_CMD_EN_OUT);

		buf->io_started = B_TRUE;
	}

	return (AUDIO_SUCCESS);

}	/* audioixp_fill_play_buf() */

/*
 * audioixp_reclaim_play_buf()
 *
 * Description:
 *	When the audio controller finishes fetching the data from DMA
 *	buffers, this routine will be called by interrupt handler to
 *	reclaim the DMA buffers.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audioixp_reclaim_play_buf(audioixp_state_t *statep)
{

	audioixp_sample_buf_t *buf;

	buf = &statep->play_buf;
	buf->avail += audioixp_chunk_processed(statep, AUDIO_PLAY);

	return;

}	/* audioixp_reclaim_play_buf() */

/*
 * audioixp_prepare_record_buf()
 *
 * Description:
 *	This routine is called by audioixp_ad_start_record(). It prepares
 *	DMA memory for PCM in engine, sets the buffer descriptor entries for PCM
 *	in engine, and starts PCM in engine for recording.
 *
 * Arguments:
 *	audioixp_state_t	*statep		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Started PCM in  engine successfully
 *	AUDIO_FAILURE		Failed to start PCM in engine.
 *
 */
static int
audioixp_prepare_record_buf(audioixp_state_t *statep)
{
	audioixp_sample_buf_t	*buf;
	audioixp_bd_entry_t		*bdesc;
	int				samples;
	int 				i;

	buf = &statep->record_buf;

	if (!buf->io_started) {

		/* buffer base */
		IXP_AM_PUT32(IXP_AUDIO_IN_DMA_LINK_P,
		    (uint32_t)(uintptr_t)statep->bdl_phys->pcm_in |
		    IXP_AUDIO_IN_DMA_LINK_P_EN);
		buf->next = 0;
		buf->avail = 2;
		buf->last_hw_pointer = statep->bdl_virtual->pcm_in[0].buf_base;
	}

	if (buf->avail == 0) {
		return (AUDIO_SUCCESS);
	}

	samples = statep->ixp_csample_rate * statep->ixp_cchannels /
	    statep->ad_info.ad_record.ad_int_rate;

	/* if not an even number of samples we panic! */
	if ((samples & 1) != 0) {
		samples++;
	}

	statep->ixp_csamples = samples;
	for (i = 0; i < 2; i ++) {
		samples = statep->ixp_csamples;
		bdesc = &(statep->bdl_virtual->pcm_in[i]);
		bdesc->buf_len = (uint16_t)samples >> 1; /* in dword */
		buf->avail --;
	}

	if (!buf->io_started) {
		buf->io_started = B_TRUE;
		IXP_AM_UPDATE32(IXP_AUDIO_CMD,
		    IXP_AUDIO_CMD_EN_IN,
		    IXP_AUDIO_CMD_EN_IN);
	}

	return (AUDIO_SUCCESS);

}	/* audioixp_prepare_record_buf() */

/*
 * audioixp_reclaim_record_buf()
 *
 * Description:
 *	This routine is called by the interrupt handler. It sends the PCM
 *	samples (record data) up to the mixer module by calling am_send_audio(),
 *	and reclaims the buffer descriptor entries for PCM in engine.
 *
 * Arguments:
 *	audioixp_state_t	*statep		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audioixp_reclaim_record_buf(audioixp_state_t *statep)
{
	audioixp_bdlist_chunk_t 	*chunk;
	audioixp_sample_buf_t	*buf;
	int				samples;

	buf = &statep->record_buf;
	samples = statep->ixp_csamples;

	buf->avail += audioixp_chunk_processed(statep, AUDIO_RECORD);

	while (buf->avail > 0) {
		chunk = &buf->chunk[buf->next & 1];
		(void) ddi_dma_sync(chunk->dma_handle, 0,
		    samples<<1, DDI_DMA_SYNC_FORCPU);
		mutex_exit(&statep->inst_lock);
		am_send_audio(statep->audio_handle, chunk->data_buf,
		    AUDIO_NO_CHANNEL, samples);
		mutex_enter(&statep->inst_lock);
		buf->avail --;
		buf->next ++;
		buf->next %= IXP_BD_NUMS;

		if ((statep->flags & IXP_DMA_RECD_STARTED) == 0) {
			break;
		}
	}
}	/* audioixp_reclaim_record_buf() */

/*
 * audioixp_set_gain()
 *
 * Description:
 *	Set the play/record gain.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			dir		AUDIO_PLAY or AUDIO_RECORD, if
 *						direction is important
 *	int			arg1		The gain to set
 *	int			arg2		The channel, 0 == left
 *						or 1 == right
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
static int
audioixp_set_gain(audioixp_state_t *statep, int dir, int gain,
	int channel)
{
	uint16_t	tmp;
	uint16_t	channel_gain;
	int		regidx;
	int		max_channel_gain;

	if (gain > AUDIO_MAX_GAIN) {
		gain = AUDIO_MAX_GAIN;
	} else if (gain < AUDIO_MIN_GAIN) {
		gain = AUDIO_MIN_GAIN;
	}

	max_channel_gain = (1<<PCMOVR_GAIN_BITS)-1;
	channel_gain = 31-gain*max_channel_gain/AUDIO_MAX_GAIN;

	if (dir == AUDIO_PLAY) {
		if (statep->swap_out == B_TRUE) {
			regidx = AC97_EXTENDED_LRS_VOLUME_REGISTER;
		} else {
			regidx = AC97_PCM_OUT_VOLUME_REGISTER;
		}
		(void) audioixp_read_ac97(statep, regidx, &tmp);

		if (channel == 0) { /* left channel */
			tmp &= PCMOVR_RIGHT_GAIN_MASK;
			tmp |= (channel_gain << 8);
		} else {	/* right channel */
			tmp &= PCMOVR_LEFT_GAIN_MASK;
			tmp |= channel_gain;
		}

		(void) audioixp_write_ac97(statep, regidx, tmp);
	} else {
		ASSERT(dir == AUDIO_RECORD);

		(void) audioixp_read_ac97(statep,
		    AC97_RECORD_GAIN_REGISTER, &tmp);

		if (channel == 0) {	/* left channel */
			tmp &= ~RGR_LEFT_MASK;
			tmp |= gain & RGR_LEFT_MASK;
		} else {
			/* right channel */
			ASSERT(channel == 1);
			tmp &= ~RGR_RIGHT_MASK;
			tmp |= gain & RGR_RIGHT_MASK;
		}
		(void) audioixp_write_ac97(statep,
		    AC97_RECORD_GAIN_REGISTER, tmp);
	}

	return (AUDIO_SUCCESS);

}	/* audioixp_set_gain() */

/*
 * audioixp_set_port()
 *
 * Description:
 *	Set the play/record port.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *						which is not how we program
 *						the device for now.
 *	int			dir		AUDIO_PLAY or AUDIO_RECORD,
 *						if direction is important
 *	int			port		The port to set
 *				AUDIO_SPEAKER	output to built-in speaker
 *
 *				AUDIO_MICROPHONE	input from microphone
 *				AUDIO_LINE_IN		input from line in
 *				AUDIO_CODEC_LOOPB_IN	input from Codec
 *							internal loopback
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The port could not been set
 */
static int
audioixp_set_port(audioixp_state_t *statep, int dir, int port)
{
	uint16_t	tmp;

	if (dir == AUDIO_PLAY) {	/* output port */
		tmp = 0;
		if (port == IXP_PORT_UNMUTE) {
			port = statep->ixp_output_port;
		}

		if (port & AUDIO_SPEAKER) {
			(void) audioixp_and_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_SPEAKER;
		} else {
			(void) audioixp_or_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MVR_MUTE);
		}

		if (port & AUDIO_LINE_OUT) {
			if (statep->swap_out == B_FALSE) {
				(void) audioixp_and_ac97(statep,
				    AC97_MASTER_VOLUME_REGISTER,
				    (uint16_t)~MVR_MUTE);
			} else {
				(void) audioixp_and_ac97(statep,
				    AC97_EXTENDED_LRS_VOLUME_REGISTER,
				    (uint16_t)~AD1980_SURR_MUTE);
			}
			tmp |= AUDIO_LINE_OUT;
		} else {
			if (statep->swap_out == B_FALSE) {
				(void) audioixp_or_ac97(statep,
				    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE);
			} else {
				(void) audioixp_or_ac97(statep,
				    AC97_EXTENDED_LRS_VOLUME_REGISTER,
				    AD1980_SURR_MUTE);
			}
		}

		if (port & AUDIO_HEADPHONE) {
			(void) audioixp_and_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_HEADPHONE;
		} else {
			(void) audioixp_or_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER, MVR_MUTE);
		}

		ATRACE_32("audioixp_set_port() out port", tmp);
		statep->ixp_output_port = tmp;
		if (tmp != port) {
			ATRACE_32("audioixp_set_port() bad out port", port);
			return (AUDIO_FAILURE);
		}

	} else {		/* input port */
		ASSERT(dir == AUDIO_RECORD);

		switch (port) {
		case AUDIO_NONE:
			/* set to an unused input */
			tmp = RSCR_R_PHONE | RSCR_L_PHONE;

			/* mute the master record input */
			(void) audioixp_or_ac97(statep,
			    AC97_RECORD_GAIN_REGISTER, RGR_MUTE);

			if (statep->ixp_monitor_gain) {
				if (statep->ixp_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audioixp_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_LINE_IN) {
					(void) audioixp_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_CD) {
					(void) audioixp_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			}
			break;

		case AUDIO_MICROPHONE:
			/* set to the mic input */
			tmp = RSCR_R_MIC | RSCR_L_MIC;

			if (statep->ixp_monitor_gain) {
				if (statep->ixp_input_port ==
				    AUDIO_LINE_IN) {
					(void) audioixp_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_CD) {
					(void) audioixp_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				(void) audioixp_write_ac97(statep,
				    AC97_MIC_VOLUME_REGISTER,
				    statep->ixp_monitor_gain);
			}
			break;

		case AUDIO_LINE_IN:
			/* set to the line in input */
			tmp = RSCR_R_LINE_IN | RSCR_L_LINE_IN;

			/* see if we need to update monitor loopback */
			if (statep->ixp_monitor_gain) {
				if (statep->ixp_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audioixp_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_CD) {
					(void) audioixp_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				(void) audioixp_write_ac97(statep,
				    AC97_LINE_IN_VOLUME_REGISTER,
				    statep->ixp_monitor_gain);
			}
			break;

		case AUDIO_CD:
			/* set to the line in input */
			tmp = RSCR_R_CD|RSCR_L_CD;

			/* see if we need to update monitor loopback */
			if (statep->ixp_monitor_gain) {
				if (statep->ixp_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audioixp_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_LINE_IN) {
					(void) audioixp_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				}
				(void) audioixp_write_ac97(statep,
				    AC97_CD_VOLUME_REGISTER,
				    statep->ixp_monitor_gain);
			}
			break;

		case AUDIO_CODEC_LOOPB_IN:
			/* set to the loopback input */
			tmp = RSCR_R_STEREO_MIX | RSCR_L_STEREO_MIX;

			if (statep->ixp_monitor_gain) {
				if (statep->ixp_input_port ==
				    AUDIO_LINE_IN) {
					(void) audioixp_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audioixp_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->ixp_input_port ==
				    AUDIO_CD) {
					(void) audioixp_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			}
			break;

		default:
			ATRACE_32("audioixp_set_port bad in port", port);
			return (AUDIO_FAILURE);
		}

		/* select the input */
		(void) audioixp_write_ac97(statep,
		    AC97_RECORD_SELECT_CTRL_REGISTER, tmp);
		if ((port != AUDIO_NONE) &&
		    (statep->codec_shadow[IXP_CODEC_REG(
		    AC97_RECORD_GAIN_REGISTER)] & RGR_MUTE)) {
			(void) audioixp_and_ac97(statep,
			    AC97_RECORD_GAIN_REGISTER,
			    (uint16_t)~RGR_MUTE);
		}
		statep->ixp_input_port = port;
	}

	ATRACE_32("audioixp_set_port() returning", 0);
	return (AUDIO_SUCCESS);

}	/* audioixp_set_port() */

/*
 * audioixp_set_monitor_gain()
 *
 * Description:
 *	Set the monitor gain.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			gain		The gain to set
 *
 * Returns:
 * 	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
static int
audioixp_set_monitor_gain(audioixp_state_t *statep, int gain)
{
	uint16_t	tmp_short;
	int		rc = AUDIO_SUCCESS;

	ATRACE("in audioixp_set_monitor_gain()", statep);

	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	if (gain == 0) {
		/* disable loopbacks when gain == 0 */
		tmp_short = MVR_MUTE;
	} else {
		/* Adjust the value of gain to the requirement of AC'97 */
		tmp_short = AUDIO_MAX_GAIN - gain;
		tmp_short = ((tmp_short << statep->vol_bits_mask) - tmp_short)
		    / AUDIO_MAX_GAIN;
		tmp_short |= (((tmp_short << statep->vol_bits_mask) -
		    tmp_short) / AUDIO_MAX_GAIN) << 8;
	}

	switch (statep->ixp_input_port) {
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
		tmp_short |=
		    statep->codec_shadow[IXP_CODEC_REG(
		    AC97_MIC_VOLUME_REGISTER)] & MICVR_20dB_BOOST;
		(void) audioixp_write_ac97(statep,
		    AC97_MIC_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_LINE_IN:
		(void) audioixp_write_ac97(statep,
		    AC97_LINE_IN_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_CD:
		(void) audioixp_write_ac97(statep,
		    AC97_CD_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_CODEC_LOOPB_IN:
		/* we already are getting the loopback, so done */
		rc = AUDIO_SUCCESS;
		goto done;

	default:
		/* this should never happen! */
		ATRACE("audioixp_ad_set_config() monitor gain bad device",
		    NULL);
		rc = AUDIO_FAILURE;
		goto done;
	}

	if (gain == 0) {
		statep->ixp_monitor_gain = 0;
	} else {
		statep->ixp_monitor_gain = tmp_short;
	}

done:
	ATRACE_32("audioixp_set_monitor_gain()", rc);

	return (rc);

}	/* audioixp_set_monitor_gain() */

/*
 * audioixp_chip_init()
 *
 * Description:
 *	This routine initializes ATI IXP audio controller and the AC97
 *	codec.  The AC97 codec registers are programmed from codec_shadow[].
 *	If we are not doing a restore, we initialize codec_shadow[], otherwise
 *	we use the current values of shadow
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *	int			restore		If IXP_INIT_RESTORE then
 *						restore	from codec_shadow[]
 * Returns:
 *	AUDIO_SUCCESS	The hardware was initialized properly
 *	AUDIO_FAILURE	The hardware couldn't be initialized properly
 */
static int
audioixp_chip_init(audioixp_state_t *statep, int restore)
{
	uint16_t	*shadow;
	int 		i;
	int 		j;
	uint16_t	xid;
	uint16_t	vid1;
	uint16_t	vid2;
	uint16_t	sr;
	uint16_t 	tmp;

	/*
	 * put the audio controller into quiet state, everything off
	 */
	audioixp_stop_dma(statep, AUDIO_PLAY);
	audioixp_stop_dma(statep, AUDIO_RECORD);

	/* AC97 reset */
	if (audioixp_reset_ac97(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_chip_init() AC97 codec reset failed");
		return (AUDIO_FAILURE);
	}

	if (audioixp_codec_ready(statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!audioixp_chip_init() AC97 codec not ready");
		return (AUDIO_FAILURE);
	}

	shadow = statep->codec_shadow;

	if (restore == IXP_INIT_NO_RESTORE) {
		for (i = 0; i <= IXP_LAST_AC_REG; i += 2) {
			(void) audioixp_read_ac97(statep, i,
			    &(shadow[IXP_CODEC_REG(i)]));
		}

		/* 02h - set master line out volume, muted, 0dB */
		shadow[IXP_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] =
		    MVR_MUTE;

		/* 04h - set alternate line out volume, muted, 0dB */
		shadow[IXP_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE;

		/* 06h - set master mono volume, muted, 0dB */
		shadow[IXP_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE;

		/* 08h - set master tone control to no modification */
		shadow[IXP_CODEC_REG(AC97_MASTER_TONE_CONTROL_REGISTER)] =
		    MTCR_BASS_BYPASS|MTCR_TREBLE_BYPASS;

		/*
		 * 0ah - turn pc beep mute off, 0dB
		 *
		 * AC'97 Spec does define the optional PC Beep support, that is,
		 * the BIOS (dependent on hardware design) can use the audio
		 * hardware for the beep, especially on some laptops, in order
		 * to save cost. So we have to turn the pc_beep mute off, that
		 * is, enable the PC Beep support.
		 */
		shadow[IXP_CODEC_REG(AC97_PC_BEEP_REGISTER)] =
		    PCBR_0dB_ATTEN;

		/* 0ch - set phone input, mute, 0dB attenuation */
		shadow[IXP_CODEC_REG(AC97_PHONE_VOLUME_REGISTER)] =
		    PVR_MUTE|PVR_0dB_GAIN;

		/* 0eh - set mic input, mute, 0dB attenuation */
		shadow[IXP_CODEC_REG(AC97_MIC_VOLUME_REGISTER)] =
		    MICVR_MUTE|MICVR_0dB_GAIN;

		/* 10h - set line input, mute, 0dB attenuation */
		shadow[IXP_CODEC_REG(AC97_LINE_IN_VOLUME_REGISTER)] =
		    LIVR_MUTE|LIVR_RIGHT_0dB_GAIN|LIVR_LEFT_0dB_GAIN;

		/* 12h - set cd input, mute, 0dB attenuation */
		shadow[IXP_CODEC_REG(AC97_CD_VOLUME_REGISTER)] =
		    CDVR_MUTE|CDVR_RIGHT_0dB_GAIN|CDVR_LEFT_0dB_GAIN;

		/* 14h - set video input, mute, 0dB attenuation */
		shadow[IXP_CODEC_REG(AC97_VIDEO_VOLUME_REGISTER)] =
		    VIDVR_MUTE|VIDVR_RIGHT_0dB_GAIN|VIDVR_LEFT_0dB_GAIN;

		/* 16h - set aux input, mute, 0dB attenuation */
		shadow[IXP_CODEC_REG(AC97_AUX_VOLUME_REGISTER)] =
		    AUXVR_MUTE|AUXVR_RIGHT_0dB_GAIN|AUXVR_LEFT_0dB_GAIN;

		/* 18h - set PCM out input, NOT muted, 0dB gain */
		shadow[IXP_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_RIGHT_0dB_GAIN|PCMOVR_LEFT_0dB_GAIN;

		/* 1ah - set input device as mic */
		shadow[IXP_CODEC_REG(AC97_RECORD_SELECT_CTRL_REGISTER)] =
		    RSCR_R_MIC|RSCR_L_MIC;

		/* 1ch - set record gain to 0dB and not muted */
		shadow[IXP_CODEC_REG(AC97_RECORD_GAIN_REGISTER)] =
		    RGR_RIGHT_0db_GAIN|RGR_LEFT_0db_GAIN;

		/* 1eh - set record mic gain to 0dB and not muted */
		shadow[IXP_CODEC_REG(AC97_RECORD_GAIN_MIC_REGISTER)] =
		    RGMR_0db_GAIN;

		/* 20h - set GP register, mic 1, everything else off */
		shadow[IXP_CODEC_REG(AC97_GENERAL_PURPOSE_REGISTER)] =
		    GPR_MS_MIC1|GPR_MONO_MIX_IN;

		/* 22h - set 3D control to NULL */
		shadow[IXP_CODEC_REG(AC97_THREE_D_CONTROL_REGISTER)] =
		    TDCR_NULL;

		/*
		 * The rest we ignore, most are reserved.
		 */

	}

	if (restore == IXP_INIT_RESTORE) {
		/* Restore from saved values */
		shadow[IXP_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] =
		    MVR_MUTE;
		shadow[IXP_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE;
		shadow[IXP_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE;
		shadow[IXP_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_MUTE;
	}

	/* Now we set the AC97 codec registers to the saved values */
	for (i = 2; i <= IXP_LAST_AC_REG; i += 2)
		(void) audioixp_write_ac97(statep, i,
		    shadow[IXP_CODEC_REG(i)]);

	(void) audioixp_read_ac97(statep, AC97_RESET_REGISTER, &tmp);
	if (tmp & RR_HEADPHONE_SUPPORT) {
		statep->ixp_defaults.play.port |= AUDIO_HEADPHONE;
		statep->ixp_defaults.play.avail_ports |= AUDIO_HEADPHONE;
		statep->ixp_defaults.play.mod_ports |= AUDIO_HEADPHONE;
	}

	/*
	 * Most vendors connect the surr-out of ad1980/ad1985 codecs to the
	 * line-out jack. So far we haven't found which vendors don't
	 * do that. So we assume that all vendors swap the surr-out
	 * and the line-out outputs. So we need swap the two outputs.
	 * But we still internally process the "ad198x-swap-output"
	 * property. If someday some vendors do not swap the outputs,
	 * we would set "ad198x-swap-output = 0" in the
	 * /kernel/drv/audioixp.conf file, and unload and reload the
	 * audioixp driver (or reboot).
	 */
	(void) audioixp_read_ac97(statep, AC97_VENDOR_ID1_REGISTER, &vid1);
	(void) audioixp_read_ac97(statep, AC97_VENDOR_ID2_REGISTER, &vid2);
	if (vid1 == AD1980_VID1 &&
	    (vid2 == AD1980_VID2 || vid2 == AD1985_VID2)) {
		if (ddi_prop_get_int(DDI_DEV_T_ANY, statep->dip,
		    DDI_PROP_DONTPASS, "ad198x-swap-output", 1) == 1) {
			statep->swap_out = B_TRUE;
			(void) audioixp_read_ac97(statep, CODEC_AD_REG_MISC,
			    &tmp);
			(void) audioixp_write_ac97(statep,
			    CODEC_AD_REG_MISC,
			    tmp | AD1980_MISC_LOSEL | AD1980_MISC_HPSEL);
		}
	}

	/*
	 * check if the codec implements 6 bit volume register,
	 * but the ALC202 does not strictly obey the AC'97 Spec
	 * and it only supports 5 bit volume register, so we
	 * skip the check for it as a workaround.
	 */
	if (!(vid1 == ALC202_VID1 && vid2 == ALC202_VID2)) {
		(void) audioixp_write_ac97(statep,
		    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE |
		    MVR_RIGHT_OPTIONAL_MASK | MVR_LEFT_OPTIONAL_MASK);

		(void) audioixp_read_ac97(statep,
		    AC97_MASTER_VOLUME_REGISTER, &tmp);

		if ((tmp & 0x7fff) != (MVR_RIGHT_MASK | MVR_LEFT_MASK)) {
			statep->vol_bits_mask = 6;
		}
	}

	/* resume the master volume to the max */
	(void) audioixp_write_ac97(statep, AC97_MASTER_VOLUME_REGISTER,
	    MVR_MUTE);

	/*
	 * if the codec chip does not support variable sample rate,
	 * we set the sample rate to 48K
	 */
	(void) audioixp_read_ac97(statep, AC97_EXTENDED_AUDIO_REGISTER,
	    &xid);
	audio_sup_log(statep->audio_handle, CE_NOTE,
	    "!%s%d: xid=0x%04x, vid1=0x%04x, vid2=0x%04x",
	    audioixp_name,  ddi_get_instance(statep->dip), xid, vid1, vid2);
	if (!(xid & EAR_VRA)) {
		statep->var_sr = B_FALSE;
		statep->ad_info.ad_record.ad_compat_srs =
		    audioixp_min_compat_sample_rates;
		statep->ad_info.ad_play.ad_compat_srs =
		    audioixp_min_compat_sample_rates;
		statep->ixp_defaults.play.sample_rate =
		    IXP_SAMPR48000;
		statep->ixp_defaults.record.sample_rate =
		    IXP_SAMPR48000;
	} else {	/* variable sample rate supported */
		statep->var_sr = B_TRUE;

		/* set variable rate mode */
		(void) audioixp_write_ac97(statep,
		    AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER, EASCR_VRA);

		/* check the sample rates supported */
		for (i = 0, j = 0; audioixp_compat_srs[i] != 0; i++) {
			(void) audioixp_write_ac97(statep,
			    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER,
			    audioixp_compat_srs[i]);
			(void) audioixp_read_ac97(statep,
			    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, &sr);

			if (sr == audioixp_compat_srs[i]) {
				if (i != j) {
					audioixp_compat_srs[j] =
					    audioixp_compat_srs[i];
				}
				j++;
			}
		}

		if (j < 1) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!No standard sample rate is supported");
			return (AUDIO_FAILURE);
		}
		audioixp_compat_srs[j] = 0;

		/*
		 * if the configuration doesn't support 8K sample rate,
		 * we modify the default value to the first.
		 */
		for (i = 0; audioixp_compat_srs[i] != 0; i++) {
			if (audioixp_compat_srs[i] == IXP_SAMPR8000) {
				break;
			}
		}
		if (audioixp_compat_srs[i] != IXP_SAMPR8000) {
			statep->ixp_defaults.play.sample_rate =
			    audioixp_compat_srs[0];
			statep->ixp_defaults.record.sample_rate =
			    audioixp_compat_srs[0];
		}
	}

	/* enable interrupts */
	IXP_AM_PUT32(IXP_AUDIO_INT, 0xffffffff);
	IXP_AM_PUT32(
	    IXP_AUDIO_INT_EN,
	    IXP_AUDIO_INT_EN_IN_DMA_OVERFLOW |
	    IXP_AUDIO_INT_EN_STATUS |
	    IXP_AUDIO_INT_EN_OUT_DMA_UNDERFLOW);
	return (AUDIO_SUCCESS);

}	/* audioixp_chip_init() */

/*
 * audioixp_chip_fini()
 *
 * Description:
 *	This routine disables hardware interrupts.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void audioixp_chip_fini(audioixp_state_t *statep)
{
	IXP_AM_PUT32(IXP_AUDIO_INT, IXP_AM_GET32(IXP_AUDIO_INT));
	IXP_AM_PUT32(IXP_AUDIO_INT_EN, 0);
}	/* audioixp_chip_fini() */
