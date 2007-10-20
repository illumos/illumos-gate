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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * audio810 Audio Driver
 *
 * The driver is primarily targeted at providing audio support for
 * the W1100z and W2100z systems, which use the AMD 8111 audio core
 * and the Realtek ALC 655 codec. The ALC 655 chip supports only
 * fixed 48k sample rate. However, the audio core of AMD 8111 is
 * completely compatible to the Intel ICHx chips (Intel 8x0 chipsets),
 * so the driver can work for the ICHx. In order to support more
 * chipsets, the driver supports variable sample rates, rather than
 * fixed 48k, but it does not support the rates below 8k because some
 * codec chips do not support the sample rates in that scope. Therefore
 * the option of loading the driver in compat mode through the .conf
 * file on the W1100z and W2100z systems is not supported and the
 * "mixer-mode" property has been removed from that file.
 *
 * This driver uses the mixer Audio Personality Module to implement
 * audio(7I) and mixer(7I) semantics. Both play and record are single
 * streaming.
 *
 * The AMD 8111 audio core, as an AC'97 controller, has independent
 * channels for PCM in, PCM out, mic in, modem in, and modem out.
 * The AC'97 controller is a PCI bus master with scatter/gather
 * support. Each channel has a DMA engine. Currently, we use only
 * the PCM in and PCM out channels. Each DMA engine uses one buffer
 * descriptor list. And the buffer descriptor list is an array of up
 * to 32 entries, each of which describes a data buffer. Each entry
 * contains a pointer to a data buffer, control bits, and the length
 * of the buffer being pointed to, where the length is expressed as
 * the number of samples. This, combined with the 16-bit sample size,
 * gives the actual physical length of the buffer.
 *
 * We use the BD list (buffer descriptor list) as a round-robin FIFO.
 * Both the software and hardware loop around the BD list. For playback,
 * the software writes to the buffers pointed by the BD entries of BD
 * list, and the hardware sends the data in the buffers out. For record,
 * the process is reversed. So we define the struct, i810_sample_buf,
 * to handle BD. The software uses the head, tail and avail fields of
 * this structure to manipulate the FIFO. The head field indicates the
 * first valid BD hardware can manipulate. The tail field indicates the
 * BD after the last valid BD. And the avail field indicates how many
 * buffers are available. There're also two hardware registers to index
 * the FIFO, the CIV (current index value) indicating the current BD the
 * hardware is transferring, and the LVI (last valid index) indicating
 * the last valid BD that contains proper data which the hardware should
 * not pass over. Each time a BD is processed, the hardware will issue an
 * interrupt. If the system is busy, there can be more than one BD to be
 * processed when the OS have chance to handle the interrupt. When an
 * interrupt generated, the interrupt handler will first reclaim the BD(s)
 * which had been transferred, which will be the limit [head, CIV-1], then
 * update the value of the head field to CIV, update the value of avail to
 * CIV - head. And then it will process avail BDs from tail, and set the
 * LVI to the last processed BD and update tail to LVI + 1, and update the
 * avail to 0.
 *
 * We allocate only 2 blocks of DMA memory, say A and B, for every DMA
 * engine, and bind the first, Block A, to the even entries of BDL,
 * while bind the second to the odd entries. That's say, for each buffer
 * descriptor list of DMA engine, entry 0, 2,,, 30 would be bound to Block
 * A, and entry 1, 3,,, 31 would be bound to Block B. Take the playback as
 * an example. At the beginning of playback, we set the entry 0 and 1 to
 * point to block A and B separately, and tell the DMA engine that the last
 * valid entry is entry 1. So the DMA engine doesn't access the entries after
 * entry 1. When the first playback interrupt generated, we reclaim entry
 * 0, and fill the BD entry 2 with the address of Block A, then set the
 * entry 2 to be the last valid entry, and so on. So at any time there are
 * at most two entries available for per DMA engine.
 *
 * Every time we program AC97 codec, we save the value in codec_shadow[].
 * This means that register state information is saved for power management
 * shutdown (we'll support this later). When the codec is started back up
 * we use this saved state to restore codec's state in audio810_chip_init()
 *
 * A workaround for the AD1980 and AD1985 codec:
 *	Most vendors connect the surr-out of the codecs to the line-out jack.
 *	So far we haven't found which vendors don't do that. So we assume that
 *	all vendors swap the surr-out and the line-out outputs. So we need swap
 *	the two outputs. But we still internally process the
 *	"ad198x-swap-output" property. If someday some vendors do not swap the
 *	outputs, we would set "ad198x-swap-output = 0" in the
 *	/kernel/drv/audio810.conf file, and unload and reload the audio810
 *	driver (or reboot).
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
#include <sys/audio/impl/audio810_impl.h>
#include <sys/audio/audio810.h>

/*
 * Module linkage routines for the kernel
 */
static int audio810_getinfo(dev_info_t *, ddi_info_cmd_t, void*, void**);
static int audio810_attach(dev_info_t *, ddi_attach_cmd_t);
static int audio810_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Entry point routine prototypes
 */
static int audio810_ad_set_config(audiohdl_t, int, int, int, int, int);
static int audio810_ad_set_format(audiohdl_t, int, int, int, int, int, int);
static int audio810_ad_start_play(audiohdl_t, int);
static void audio810_ad_pause_play(audiohdl_t, int);
static void audio810_ad_stop_play(audiohdl_t, int);
static int audio810_ad_start_record(audiohdl_t, int);
static void audio810_ad_stop_record(audiohdl_t, int);

/*
 * interrupt handler
 */
static uint_t	audio810_intr(caddr_t);

/*
 * Local Routine Prototypes
 */
static void audio810_set_busy(audio810_state_t *);
static void audio810_set_idle(audio810_state_t *);
static int audio810_codec_sync(audio810_state_t *);
static int audio810_write_ac97(audio810_state_t *, int, uint16_t);
static int audio810_read_ac97(audio810_state_t *, int, uint16_t *);
static int audio810_and_ac97(audio810_state_t *, int, uint16_t);
static int audio810_or_ac97(audio810_state_t *, int, uint16_t);
static int audio810_reset_ac97(audio810_state_t *);
static int audio810_init_state(audio810_state_t *, dev_info_t *);
static int audio810_map_regs(dev_info_t *, audio810_state_t *);
static void audio810_unmap_regs(audio810_state_t *);
static int audio810_alloc_sample_buf(audio810_state_t *, int, int);
static void audio810_free_sample_buf(audio810_state_t *, i810_sample_buf_t *);
static void audio810_stop_dma(audio810_state_t *);
static int audio810_chip_init(audio810_state_t *, int);
static int audio810_fill_play_buf(audio810_state_t *);
static int audio810_prepare_record_buf(audio810_state_t *);
static void audio810_reclaim_play_buf(audio810_state_t *);
static void audio810_reclaim_record_buf(audio810_state_t *);
static int audio810_set_gain(audio810_state_t *, int, int, int);
static int audio810_set_port(audio810_state_t *, int, int);
static int audio810_set_monitor_gain(audio810_state_t *, int);

/*
 * Global variables, but used only by this file.
 */

/* anchor for soft state structures */
static void	*audio810_statep;

/* driver name, so we don't have to call ddi_driver_name() or hard code strs */
static char	*audio810_name = I810_NAME;


/*
 * STREAMS structures
 */

/* STREAMS driver id and limit value struct */
static struct module_info audio810_modinfo = {
	I810_IDNUM,		/* module ID number */
	I810_NAME,		/* module name */
	I810_MINPACKET,		/* minimum packet size */
	I810_MAXPACKET,		/* maximum packet size */
	I810_HIWATER,		/* high water mark */
	I810_LOWATER,		/* low water mark */
};

/* STREAMS queue processing procedures structures */
/* read queue */
static struct qinit audio810_rqueue = {
	audio_sup_rput,		/* put procedure */
	audio_sup_rsvc,		/* service procedure */
	audio_sup_open,		/* open procedure */
	audio_sup_close,	/* close procedure */
	NULL,			/* unused */
	&audio810_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* write queue */
static struct qinit audio810_wqueue = {
	audio_sup_wput,		/* write procedure */
	audio_sup_wsvc,		/* service procedure */
	NULL,			/* open procedure */
	NULL,			/* close procedure */
	NULL,			/* unused */
	&audio810_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* STREAMS entity declaration structure */
static struct streamtab audio810_str_info = {
	&audio810_rqueue,	/* read queue */
	&audio810_wqueue,	/* write queue */
	NULL,			/* mux lower read queue */
	NULL,			/* mux lower write queue */
};

/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops audio810_cb_ops = {
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
	&audio810_str_info,	/* cb_str */
	D_NEW | D_MP | D_64BIT, /* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

/* Device operations structure */
static struct dev_ops audio810_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	audio810_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audio810_attach,	/* devo_attach */
	audio810_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&audio810_cb_ops,	/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL			/* devo_power */
};

/* Linkage structure for loadable drivers */
static struct modldrv audio810_modldrv = {
	&mod_driverops,		/* drv_modops */
	I810_MOD_NAME" %I%",	/* drv_linkinfo */
	&audio810_dev_ops,	/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage audio810_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&audio810_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};

static uint_t audio810_mixer_srs[] = {
	I810_SAMPR5510, I810_SAMPR48000, 0
};

static uint_t audio810_min_compat_srs[] = {
	I810_SAMPR48000, 0
};

static uint_t audio810_compat_srs [] = {
	I810_SAMPR8000, I810_SAMPR9600, I810_SAMPR11025,
	I810_SAMPR16000, I810_SAMPR18900, I810_SAMPR22050,
	I810_SAMPR27420, I810_SAMPR32000, I810_SAMPR33075,
	I810_SAMPR37800, I810_SAMPR44100, I810_SAMPR48000,
	0
};

static am_ad_sample_rates_t audio810_mixer_sample_rates = {
	MIXER_SRS_FLAG_SR_LIMITS,
	audio810_mixer_srs
};

static am_ad_sample_rates_t audio810_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audio810_compat_srs
};

/* Some codec, such as the ALC 655, only support 48K sample rate */
static am_ad_sample_rates_t audio810_min_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audio810_min_compat_srs
};

/* now, only support stereo */
static uint_t audio810_channels[] = {
	AUDIO_CHANNELS_STEREO,
	0
};


static am_ad_cap_comb_t audio810_combinations[] = {
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

static am_ad_entry_t audio810_entry = {
	NULL,				/* ad_setup() */
	NULL,				/* ad_teardown() */
	audio810_ad_set_config,		/* ad_set_config() */
	audio810_ad_set_format,		/* ad_set_format() */
	audio810_ad_start_play,		/* ad_start_play() */
	audio810_ad_pause_play,		/* ad_pause_play() */
	audio810_ad_stop_play,		/* ad_stop_play() */
	audio810_ad_start_record,	/* ad_start_record() */
	audio810_ad_stop_record,	/* ad_stop_record() */
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

	ATRACE("in audio810 _init()", NULL);

	if ((error = ddi_soft_state_init(&audio810_statep,
	    sizeof (audio810_state_t), 1)) != 0) {
		ATRACE("i810 ddi_soft_state_init() failed", audio810_statep);
		return (error);
	}

	if ((error = mod_install(&audio810_modlinkage)) != 0) {
		ddi_soft_state_fini(&audio810_statep);
	}

	ATRACE("audio810 _init() audio810_statep", audio810_statep);
	ATRACE("audio810 _init() returning", error);

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

	ATRACE("in audio810 _fini()", audio810_statep);

	if ((error = mod_remove(&audio810_modlinkage)) != 0) {
		return (error);
	}

	ddi_soft_state_fini(&audio810_statep);

	ATRACE_32("audio810 _fini() returning", error);

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

	ATRACE("in audio810 _info()", NULL);

	error = mod_info(&audio810_modlinkage, modinfop);

	ATRACE_32("audio810 _info() returning", error);

	return (error);

}	/* _info() */


/* ******************* Driver Entry Points ********************************* */

/*
 * audio810_getinfo()
 */
static int
audio810_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	audio810_state_t	*state;
	int 			instance;
	int 			error;

	error = DDI_FAILURE;
	ATRACE("in audio810_getinfo()", dip);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = audio_sup_devt_to_instance((dev_t)arg);
		if ((state = ddi_get_soft_state(audio810_statep,
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

}	/* audio810_getinfo() */

/*
 * audio810_attach()
 *
 * Description:
 *	Attach an instance of the audio810 driver. This routine does the
 * 	device dependent attach tasks. When it is completed, it calls
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
audio810_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int 			instance;
	uint16_t		cmdreg;
	audio810_state_t	*statep;
	audio_sup_reg_data_t	data;

	ATRACE("in audio810_attach()", dip);

	instance = ddi_get_instance(dip);

	ATRACE("audio810_attach() audio810_statep", audio810_statep);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		ATRACE("I810_attach() DDI_RESUME", NULL);

		if ((statep = ddi_get_soft_state(audio810_statep, instance)) ==
		    NULL) {
			audio_sup_log(NULL, CE_WARN,
			    "!attach() DDI_RESUME get soft state failed");
			return (DDI_FAILURE);
		}

		ASSERT(dip == statep->dip);

		mutex_enter(&statep->inst_lock);

		ASSERT(statep->i810_suspended == I810_SUSPENDED);

		statep->i810_suspended = I810_NOT_SUSPENDED;

		/* Restore the audio810 chip's state */
		if (audio810_chip_init(statep, I810_INIT_RESTORE) !=
		    AUDIO_SUCCESS) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!attach() DDI_RESUME failed to init chip");
			mutex_exit(&statep->inst_lock);
			return (DDI_FAILURE);
		}

		mutex_exit(&statep->inst_lock);

		/* Resume playing and recording, if required */
		if (audio_sup_restore_state(statep->audio_handle,
		    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!attach() DDI_RESUME audio restart failed");
		}

		mutex_enter(&statep->inst_lock);
		cv_broadcast(&statep->i810_cv);	/* let entry points continue */
		mutex_exit(&statep->inst_lock);

		ATRACE("audio810_attach() DDI_RESUME done", NULL);

		return (DDI_SUCCESS);
	default:
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() unknown command: 0x%x",
		    audio810_name, instance, cmd);
		return (DDI_FAILURE);
	}

	/* we don't support high level interrupts in the driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() unsupported high level interrupt",
		    audio810_name, instance);
		return (DDI_FAILURE);
	}

	/* allocate the soft state structure */
	if (ddi_soft_state_zalloc(audio810_statep, instance) != DDI_SUCCESS) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() soft state allocate failed",
		    audio810_name, instance);
		return (DDI_FAILURE);
	}

	if ((statep = ddi_get_soft_state(audio810_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() soft state failed",
		    audio810_name, instance);
		goto error_state;
	}

	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;
	if ((statep->audio_handle = audio_sup_register(dip, &data)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() audio_sup_register() failed",
		    audio810_name, instance);
		goto error_state;
	}

	/* save private state */
	audio_sup_set_private(statep->audio_handle, statep);

	if ((audio810_init_state(statep, dip)) != AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!attach() init state structure failed");
		goto error_audiosup;
	}

	/* map in the registers, allocate DMA buffers, etc. */
	if (audio810_map_regs(dip, statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!attach() couldn't map registers");
		goto error_destroy;
	}

	/* set PCI command register */
	cmdreg = pci_config_get16(statep->pci_conf_handle, PCI_CONF_COMM);
	pci_config_put16(statep->pci_conf_handle, PCI_CONF_COMM,
	    cmdreg | PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);

	if ((audio810_alloc_sample_buf(statep, I810_DMA_PCM_OUT,
	    statep->play_buf_size) == AUDIO_FAILURE) ||
	    (audio810_alloc_sample_buf(statep, I810_DMA_PCM_IN,
	    statep->record_buf_size) == AUDIO_FAILURE)) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!attach() couldn't allocate sample buffers");
		goto error_unmap;
	}

	/* initialize audio controller and AC97 codec */
	if (audio810_chip_init(statep, I810_INIT_NO_RESTORE) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!attach() failed to init chip");
		goto error_dealloc;
	}

	/* call the mixer attach() routine */
	if (am_attach(statep->audio_handle, cmd, &statep->ad_info) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!attach() am_attach() failed");
		goto error_dealloc;
	}

	/* set up kernel statistics */
	if ((statep->i810_ksp = kstat_create(I810_NAME, instance,
	    I810_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->i810_ksp);
	}

	/* set up the interrupt handler */
	if (ddi_add_intr(dip, 0, &statep->intr_iblock,
	    (ddi_idevice_cookie_t *)NULL, audio810_intr, (caddr_t)statep) !=
	    DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!attach() bad interrupt specification ");
		goto error_kstat;
	}
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error_kstat:
	if (statep->i810_ksp) {
		kstat_delete(statep->i810_ksp);
	}
	(void) am_detach(statep->audio_handle, DDI_DETACH);

error_dealloc:
	audio810_free_sample_buf(statep, &statep->play_buf);
	audio810_free_sample_buf(statep, &statep->record_buf);

error_unmap:
	audio810_unmap_regs(statep);

error_destroy:
	ATRACE("audio810_attach() error_destroy", statep);
	mutex_destroy(&statep->inst_lock);
	cv_destroy(&statep->i810_cv);

error_audiosup:
	ATRACE("audio810_attach() error_audiosup", statep);
	(void) audio_sup_unregister(statep->audio_handle);

error_state:
	ATRACE("audio810_attach() error_state", statep);
	ddi_soft_state_free(audio810_statep, instance);

	ATRACE("audio810_attach() returning failure", NULL);

	return (DDI_FAILURE);

}	/* audio810_attach() */

/*
 * audio810_detach()
 *
 * Description:
 *	Detach an instance of the audio810 driver. After the Codec is detached
 *	we call am_detach() and audio_sup_register() so they may do their work.
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
audio810_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audio810_state_t	*statep;
	int			instance;

	instance = ddi_get_instance(dip);

	ATRACE_32("audio810_detach() instance", instance);
	ATRACE("audio810_detach() audio810_statep", audio810_statep);

	if ((statep = ddi_get_soft_state(audio810_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: detach() get soft state failed",
		    audio810_name, instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		ATRACE("i810_detach() SUSPEND", statep);

		mutex_enter(&statep->inst_lock);

		ASSERT(statep->i810_suspended == I810_NOT_SUSPENDED);

		statep->i810_suspended = I810_SUSPENDED; /* stop new ops */

		/* wait for current operations to complete */
		while (statep->i810_busy_cnt != 0)
			cv_wait(&statep->i810_cv, &statep->inst_lock);

		/* stop DMA engines */
		audio810_stop_dma(statep);

		if (audio_sup_save_state(statep->audio_handle,
		    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!detach() DDI_SUSPEND audio save failed");
		}

		mutex_exit(&statep->inst_lock);

		ATRACE("audio810_detach() DDI_SUSPEND successful", statep);

		return (DDI_SUCCESS);
	default:
		ATRACE("i810_detach() unknown command", cmd);
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!detach() unknown command: 0x%x", cmd);
		return (DDI_FAILURE);
	}

	/* stop DMA engines */
	mutex_enter(&statep->inst_lock);
	audio810_stop_dma(statep);
	mutex_exit(&statep->inst_lock);

	/* remove the interrupt handler */
	ddi_remove_intr(dip, 0, statep->intr_iblock);

	/* free DMA memory */
	audio810_free_sample_buf(statep, &statep->play_buf);
	audio810_free_sample_buf(statep, &statep->record_buf);

	/* free the kernel statistics structure */
	if (statep->i810_ksp) {
		kstat_delete(statep->i810_ksp);
	}

	/* detach audio mixer */
	(void) am_detach(statep->audio_handle, cmd);

	/*
	 * call the audio support module's detach routine to remove this
	 * driver completely from the audio driver architecture.
	 */
	(void) audio_sup_unregister(statep->audio_handle);

	mutex_destroy(&statep->inst_lock);
	cv_destroy(&statep->i810_cv);

	audio810_unmap_regs(statep);

	ddi_soft_state_free(audio810_statep, instance);

	return (DDI_SUCCESS);

}	/* audio810_detach */

/*
 * audio810_intr()
 *
 * Description:
 *	Interrupt service routine for both play and record. For play we
 *	get the next buffers worth of audio. For record we send it on to
 *	the mixer.
 *
 *	Each of buffer descriptor has a field IOC(interrupt on completion)
 *	When both this and the IOC bit of correspondent dma control register
 *	is set, it means that the controller should issue an interrupt upon
 *	completion of this buffer.
 *	(AMD 8111 hypertransport I/O hub data sheet. 3.8.3 page 71)
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
audio810_intr(caddr_t arg)
{
	audio810_state_t	*statep;
	uint16_t		gsr;

	statep = (audio810_state_t *)arg;
	mutex_enter(&statep->inst_lock);

	if (statep->i810_suspended == I810_SUSPENDED) {
		ATRACE("audio810_intr() device suspended", NULL);
		mutex_exit(&statep->inst_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	gsr = I810_BM_GET32(I810_REG_GSR);

	/* check if device is interrupting */
	if ((gsr & I810_GSR_USE_INTR) == 0) {
		ATRACE_32("audio810_intr() not our interrupt", gsr);
		mutex_exit(&statep->inst_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* PCM in interrupt */
	if (gsr & I810_GSR_INTR_PIN) {
		I810_BM_PUT8(I810_PCM_IN_SR,
		    I810_BM_SR_LVBCI |
		    I810_BM_SR_BCIS |
		    I810_BM_SR_FIFOE);

		if (statep->flags & I810_DMA_RECD_STARTED) {
			audio810_reclaim_record_buf(statep);
			(void) audio810_prepare_record_buf(statep);
		}
	}

	/* PCM out interrupt */
	if (gsr & I810_GSR_INTR_POUT) {
		I810_BM_PUT8(I810_PCM_OUT_SR,
		    I810_BM_SR_LVBCI |
		    I810_BM_SR_BCIS |
		    I810_BM_SR_FIFOE);

		if (statep->flags & I810_DMA_PLAY_STARTED) {
			audio810_reclaim_play_buf(statep);
			(void) audio810_fill_play_buf(statep);
		}
	}

	/* update the kernel interrupt statistics */
	if (statep->i810_ksp) {
		I810_KIOP(statep)->intrs[KSTAT_INTR_HARD]++;
	}

	mutex_exit(&statep->inst_lock);

	ATRACE("audio810_intr() done", statep);

	return (DDI_INTR_CLAIMED);

}	/* audio810_intr() */

/*
 * audio810_set_busy()
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
 *	audio810_state_t	*statep		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio810_set_busy(audio810_state_t *statep)
{
	ATRACE("in audio810_set_busy()", statep);

	ASSERT(!mutex_owned(&statep->inst_lock));

	/* get the lock so we are safe */
	mutex_enter(&statep->inst_lock);

	/* block if we are suspended */
	while (statep->i810_suspended == I810_SUSPENDED) {
		cv_wait(&statep->i810_cv, &statep->inst_lock);
	}

	/*
	 * Okay, we aren't suspended, so mark as busy.
	 * This will keep us from being suspended when we release the lock.
	 */
	ASSERT(statep->i810_busy_cnt >= 0);
	statep->i810_busy_cnt++;

	mutex_exit(&statep->inst_lock);

	ATRACE("audio810_set_busy() done", statep);

	ASSERT(!mutex_owned(&statep->inst_lock));

}	/* audio810_set_busy() */

/*
 * audio810_set_idle()
 *
 * Description:
 *	This routine reduces the busy count. It then does a cv_broadcast()
 *	if the count is 0 so a waiting DDI_SUSPEND will continue forward.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio810_set_idle(audio810_state_t *statep)
{
	ATRACE("in audio810_set_idle()", statep);

	ASSERT(!mutex_owned(&statep->inst_lock));

	/* get the lock so we are safe */
	mutex_enter(&statep->inst_lock);

	ASSERT(statep->i810_suspended == I810_NOT_SUSPENDED);

	/* decrement the busy count */
	ASSERT(statep->i810_busy_cnt > 0);
	statep->i810_busy_cnt--;

	/* if no longer busy, then we wake up a waiting SUSPEND */
	if (statep->i810_busy_cnt == 0) {
		cv_broadcast(&statep->i810_cv);
	}

	/* we're done, so unlock */
	mutex_exit(&statep->inst_lock);

	ATRACE("audio810_set_idle() done", statep);

	ASSERT(!mutex_owned(&statep->inst_lock));

}	/* audio810_set_idle() */

/* *********************** Mixer Entry Point Routines ******************* */
/*
 * audio810_ad_set_config()
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
audio810_ad_set_config(audiohdl_t ahandle, int stream, int command,
    int dir, int arg1, int arg2)
{
	audio810_state_t	*statep;
	int 			rc = AUDIO_SUCCESS;

	ATRACE_32("i810_ad_set_config() stream", stream);
	ATRACE_32("i810_ad_set_config() command", command);
	ATRACE_32("i810_ad_set_config() dir", dir);
	ATRACE_32("i810_ad_set_config() arg1", arg1);
	ATRACE_32("i810_ad_set_config() arg2", arg2);

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audio810_set_busy(statep);

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
		rc = audio810_set_gain(statep, dir, arg1, arg2);
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
		rc = audio810_set_port(statep, dir, arg1);
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
		rc = audio810_set_monitor_gain(statep, arg1);
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
			(void) audio810_or_ac97(statep,
			    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE);
			(void) audio810_or_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER, HPVR_MUTE);
			(void) audio810_or_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MMVR_MUTE);
		} else {	/* not muted */

			/* by setting the port we unmute only active ports */
			(void) audio810_set_port(statep,
			    AUDIO_PLAY, statep->i810_output_port);
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
			(void) audio810_or_ac97(statep,
			    AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
			statep->ad_info.ad_add_mode |= AM_ADD_MODE_MIC_BOOST;
		} else {	/* disable */
			(void) audio810_and_ac97(statep,
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
		ATRACE_32("i810_ad_set_config() unsupported command",
		    command);
		break;
	}
	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

	ATRACE_32("i810_ad_set_config() returning", rc);

	return (rc);

}	/* audio810_ad_set_config() */

/*
 * audio810_ad_set_format()
 *
 * Description:
 *	This routine is used to set a new audio control data format.
 *	We only support 16 bit signed linear.
 *
 * Arguments:
 * 	audiohdl_t	ahandle		Handle to this device
 *	int		stream		Stream number
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		sample_rate	Data sample rate
 *	int		channels	Number of channels, 1 or 2
 *	int		precision	Bits per sample, 16
 *	int		encoding	Encoding method, linear
 *
 * Returns:
 *	AUDIO_SUCCESS	The Codec data format has been set
 *	AUDIO_FAILURE	The Codec data format has not been set, or the
 *			data format couldn't be set
 */
static int
audio810_ad_set_format(audiohdl_t ahandle, int stream, int dir,
    int sample_rate, int channels, int precision, int encoding)
{
	audio810_state_t	*statep;
	uint16_t		val;
	int			rc = AUDIO_FAILURE;

	ASSERT(precision == AUDIO_PRECISION_16);
	ASSERT(channels == AUDIO_CHANNELS_STEREO);

	ATRACE_32("i810_ad_set_format() stream", stream);
	ATRACE_32("i810_ad_set_format() dir", dir);
	ATRACE_32("i810_ad_set_format() sample_rate", sample_rate);
	ATRACE_32("i810_ad_set_format() channels", channels);
	ATRACE_32("i810_ad_set_format() precision", precision);
	ATRACE_32("i810_ad_set_format() encoding", encoding);

	if (encoding != AUDIO_ENCODING_LINEAR) {
		ATRACE("i810_ad_set_format() bad encoding", encoding);
		return (AUDIO_FAILURE);
	}

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audio810_set_busy(statep);

	mutex_enter(&statep->inst_lock);

	if (statep->var_sr == B_FALSE) {
		/* codec doesn't support variable sample rate */

		if (sample_rate != I810_SAMPR48000) {
			audio_sup_log(statep->audio_handle, CE_NOTE,
			    "!ad_set_format() bad sample rate %d\n",
			    sample_rate);
			goto done;
		}
	} else {
		switch (sample_rate) {
		case I810_SAMPR8000:	break;
		case I810_SAMPR9600:	break;
		case I810_SAMPR11025:	break;
		case I810_SAMPR16000:	break;
		case I810_SAMPR18900:	break;
		case I810_SAMPR22050:	break;
		case I810_SAMPR27420:	break;
		case I810_SAMPR32000:	break;
		case I810_SAMPR33075:	break;
		case I810_SAMPR37800:	break;
		case I810_SAMPR44100:	break;
		case I810_SAMPR48000:	break;
		default:
			ATRACE_32("i810_ad_set_format() bad SR", sample_rate);
			goto done;
		}
	}

	if (dir == AUDIO_PLAY) {

		(void) audio810_write_ac97(statep,
		    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, sample_rate);
		(void) audio810_write_ac97(statep,
		    AC97_EXTENDED_SURROUND_DAC_RATE_REGISTER, sample_rate);
		(void) audio810_write_ac97(statep,
		    AC97_EXTENDED_LFE_DAC_RATE_REGISTER, sample_rate);

		/*
		 * Some codecs before ac97 2.2, such as YMF753 produced by
		 * Yamaha LSI, don't have the AC'97 registers indexed range
		 * from 0x2c to 0x34. So we assume this kind of codec
		 * supports fixed 48k sample rate.
		 */
		if (statep->var_sr == B_TRUE) {
			(void) audio810_read_ac97(statep,
			    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, &val);
			if (val != sample_rate) {
				ATRACE_32("ad_set_format() bad out SR",
				    sample_rate);
				audio_sup_log(statep->audio_handle, CE_NOTE,
				    "!set_format() bad output sample rate %d",
				    sample_rate);
				goto done;
			}
		}

		statep->i810_psample_rate = sample_rate;
		statep->i810_pchannels = channels;
		statep->i810_pprecision = precision;
	} else {

		(void) audio810_write_ac97(statep,
		    AC97_EXTENDED_LR_DAC_RATE_REGISTER, sample_rate);
		(void) audio810_write_ac97(statep,
		    AC97_EXTENDED_MIC_ADC_RATE_REGISTER, sample_rate);

		/*
		 * Some codecs before ac97 2.2, such as YMF753 produced by
		 * Yamaha LSI, don't have the AC'97 registers indexed range
		 * from 0x2c to 0x34. So we assume this kind of codec
		 * supports fixed 48k sample rate.
		 */
		if (statep->var_sr == B_TRUE) {
			(void) audio810_read_ac97(statep,
			    AC97_EXTENDED_LR_DAC_RATE_REGISTER, &val);
			if (val != sample_rate) {
				ATRACE_32("ad_set_format() bad input SR",
				    sample_rate);
				audio_sup_log(statep->audio_handle, CE_NOTE,
				    "!set_format() bad input sample rate %d",
				    sample_rate);
				goto done;
			}
		}

		statep->i810_csample_rate = sample_rate;
		statep->i810_cchannels = channels;
		statep->i810_cprecision = precision;
	}

	rc = AUDIO_SUCCESS;
done:
	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

	ATRACE_32("i810_ad_set_format() returning", rc);

	return (rc);

}	/* audio810_ad_set_format() */

/*
 * audio810_ad_start_play()
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
audio810_ad_start_play(audiohdl_t ahandle, int stream)
{
	audio810_state_t	*statep;
	uint8_t			cr;
	int			rc = AUDIO_SUCCESS;

	ATRACE_32("i810_ad_start_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audio810_set_busy(statep);

	mutex_enter(&statep->inst_lock);

	if (statep->flags & I810_DMA_PLAY_PAUSED) {
		statep->flags |= I810_DMA_PLAY_STARTED;
		statep->flags &= ~I810_DMA_PLAY_PAUSED;
		cr = I810_BM_GET8(I810_PCM_OUT_CR);
		cr |= I810_BM_CR_RUN;
		I810_BM_PUT8(I810_PCM_OUT_CR, cr);
		goto done;
	}

	if (statep->flags & I810_DMA_PLAY_STARTED) {
		goto done;
	}

	rc = audio810_fill_play_buf(statep);
	if (rc == AUDIO_FAILURE) {
		statep->flags &= ~I810_DMA_PLAY_STARTED;
	} else {
		statep->flags |= I810_DMA_PLAY_STARTED;
	}

done:
	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

	return (rc);

}	/* audio810_ad_start_play() */

/*
 * audio810_ad_pause_play()
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
audio810_ad_pause_play(audiohdl_t ahandle, int stream)
{
	audio810_state_t	*statep;
	uint8_t			cr;

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);
	ATRACE("audio810_ad_pause_play() ", ahandle);
	ATRACE_32("i810_ad_pause_play() stream", stream);

	audio810_set_busy(statep);

	mutex_enter(&statep->inst_lock);
	if ((statep->flags & I810_DMA_PLAY_STARTED) == 0)
		goto done;
	cr = I810_BM_GET8(I810_PCM_OUT_CR);
	cr &= ~I810_BM_CR_RUN;
	I810_BM_PUT8(I810_PCM_OUT_CR, cr);
	statep->flags |= I810_DMA_PLAY_PAUSED;
done:
	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

}	/* audio810_ad_pause_play() */

/*
 * audio810_ad_stop_play()
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
audio810_ad_stop_play(audiohdl_t ahandle, int stream)
{
	audio810_state_t	*statep;
	i810_sample_buf_t	*buf;

	ATRACE("audio810_ad_stop_play() ", ahandle);
	ATRACE_32("i810_ad_stop_play() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audio810_set_busy(statep);

	mutex_enter(&statep->inst_lock);

	/* pause bus master */
	I810_BM_PUT8(I810_PCM_OUT_CR, I810_BM_CR_PAUSE);

	/* reset registers */
	I810_BM_PUT8(I810_PCM_OUT_CR, I810_BM_CR_RST);

	buf = &statep->play_buf;
	buf->io_started = B_FALSE;
	statep->flags &= ~(I810_DMA_PLAY_STARTED
	    |I810_DMA_PLAY_PAUSED | I810_DMA_PLAY_EMPTY);

	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

}	/* audio810_ad_stop_play() */

/*
 * audio810_ad_start_record()
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
audio810_ad_start_record(audiohdl_t ahandle, int stream)
{
	audio810_state_t	*statep;
	int			rc = AUDIO_SUCCESS;

	ATRACE("audio810_ad_start_record() ", ahandle);
	ATRACE_32("i810_ad_start_record() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audio810_set_busy(statep);

	mutex_enter(&statep->inst_lock);
	if (statep->flags & I810_DMA_RECD_STARTED)
		goto done;

	rc = audio810_prepare_record_buf(statep);
	if (rc == AUDIO_SUCCESS) {
		statep->flags |= I810_DMA_RECD_STARTED;
	}
done:
	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

	return (rc);

}	/* audio810_ad_start_record() */

/*
 * audio810_ad_stop_record()
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
audio810_ad_stop_record(audiohdl_t ahandle, int stream)
{
	audio810_state_t	*statep;
	i810_sample_buf_t	*buf;

	ATRACE("audio810_ad_stop_record() ", ahandle);
	ATRACE_32("i810_ad_stop_record() stream", stream);
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	audio810_set_busy(statep);

	mutex_enter(&statep->inst_lock);
	statep->flags &= ~I810_DMA_RECD_STARTED;

	buf = &statep->record_buf;
	buf->io_started = B_FALSE;

	/* pause bus master */
	I810_BM_PUT8(I810_PCM_IN_CR, I810_BM_CR_PAUSE);

	/* reset registers */
	I810_BM_PUT8(I810_PCM_IN_CR, I810_BM_CR_RST);

	mutex_exit(&statep->inst_lock);

	audio810_set_idle(statep);

}	/* audio810_ad_stop_record() */

/* *********************** Local Routines *************************** */

/*
 * audio810_init_state()
 *
 * Description:
 *	This routine initializes the audio driver's state structure
 *
 *	CAUTION: This routine cannot allocate resources, unless it frees
 *		them before returning for an error. Also, error_destroy:
 *		in audio810_attach() would need to be fixed as well.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *	dev_info_t		*dip		Pointer to the device's
 *						dev_info struct
 *
 * Returns:
 *	AUDIO_SUCCESS		State structure initialized
 *	AUDIO_FAILURE		State structure not initialized
 */
static int
audio810_init_state(audio810_state_t *statep, dev_info_t *dip)
{
	int rints;
	int pints;
	int cdrom;
	int mode;

	ATRACE("audio810_init_state()", NULL);

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
	    DDI_PROP_DONTPASS, "play-interrupts", I810_INTS);
	if (pints > I810_MAX_INTS) {
		ATRACE_32("i810_init_state() "
		    "play interrupt rate too high, resetting", pints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "init_state() "
		    "play interrupt rate set too high, %d, resetting to %d",
		    pints, I810_INTS);
		pints = I810_INTS;
	} else if (pints < I810_MIN_INTS) {
		ATRACE_32("i810_init_state() "
		    "play interrupt rate too low, resetting", pints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "init_state() "
		    "play interrupt rate set too low, %d, resetting to %d",
		    pints, I810_INTS);
		pints = I810_INTS;
	}
	rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "record-interrupts", I810_INTS);
	if (rints > I810_MAX_INTS) {
		ATRACE_32("i810_init_state() "
		    "record interrupt rate too high, resetting", rints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "init_state() "
		    "record interrupt rate set too high, %d, resetting to %d",
		    rints, I810_INTS);
		rints = I810_INTS;
	} else if (rints < I810_MIN_INTS) {
		ATRACE_32("i810_init_state() "
		    "record interrupt rate too low, resetting", rints);
		audio_sup_log(statep->audio_handle, CE_NOTE,
		    "init_state() "
		    "record interrupt rate set too low, %d, resetting to %d",
		    rints, I810_INTS);
		rints = I810_INTS;
	}

	/* fill in the device default state */
	statep->i810_defaults.play.sample_rate = I810_DEFAULT_SR;
	statep->i810_defaults.play.channels = I810_DEFAULT_CH;
	statep->i810_defaults.play.precision = I810_DEFAULT_PREC;
	statep->i810_defaults.play.encoding = I810_DEFAULT_ENC;
	statep->i810_defaults.play.gain = I810_DEFAULT_PGAIN;
	statep->i810_defaults.play.port = AUDIO_SPEAKER | AUDIO_LINE_OUT;
	statep->i810_defaults.play.avail_ports = AUDIO_SPEAKER | AUDIO_LINE_OUT;
	statep->i810_defaults.play.mod_ports = AUDIO_SPEAKER | AUDIO_LINE_OUT;
	statep->i810_defaults.play.buffer_size = I810_BSIZE;
	statep->i810_defaults.play.balance = I810_DEFAULT_BAL;

	statep->i810_defaults.record.sample_rate = I810_DEFAULT_SR;
	statep->i810_defaults.record.channels = I810_DEFAULT_CH;
	statep->i810_defaults.record.precision = I810_DEFAULT_PREC;
	statep->i810_defaults.record.encoding = I810_DEFAULT_ENC;
	statep->i810_defaults.record.gain = I810_DEFAULT_PGAIN;
	statep->i810_defaults.record.port = AUDIO_MICROPHONE;
	statep->i810_defaults.record.avail_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	statep->i810_defaults.record.mod_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	statep->i810_defaults.record.buffer_size = I810_BSIZE;
	statep->i810_defaults.record.balance = I810_DEFAULT_BAL;

	statep->i810_defaults.monitor_gain = I810_DEFAULT_MONITOR_GAIN;
	statep->i810_defaults.output_muted = B_FALSE;
	statep->i810_defaults.ref_cnt = B_FALSE;
	statep->i810_defaults.hw_features =
	    AUDIO_HWFEATURE_DUPLEX | AUDIO_HWFEATURE_PLAY |
	    AUDIO_HWFEATURE_IN2OUT | AUDIO_HWFEATURE_RECORD;
	statep->i810_defaults.sw_features = AUDIO_SWFEATURE_MIXER;

	if (cdrom) {
		statep->i810_defaults.record.avail_ports |= AUDIO_CD;
		statep->i810_defaults.record.mod_ports |= AUDIO_CD;
	}

	statep->i810_psample_rate = statep->i810_defaults.play.sample_rate;
	statep->i810_pchannels = statep->i810_defaults.play.channels;
	statep->i810_pprecision = statep->i810_defaults.play.precision;
	statep->i810_csample_rate = statep->i810_defaults.record.sample_rate;
	statep->i810_cchannels = statep->i810_defaults.record.channels;
	statep->i810_cprecision = statep->i810_defaults.record.precision;

	/*
	 * fill in the ad_info structure
	 */
	statep->ad_info.ad_mode = mode;
	statep->ad_info.ad_int_vers = AM_VERSION;
	statep->ad_info.ad_add_mode = NULL;
	statep->ad_info.ad_codec_type = AM_TRAD_CODEC;
	statep->ad_info.ad_defaults = &statep->i810_defaults;
	statep->ad_info.ad_play_comb = audio810_combinations;
	statep->ad_info.ad_rec_comb = audio810_combinations;
	statep->ad_info.ad_entry = &audio810_entry;
	statep->ad_info.ad_dev_info = &statep->i810_dev_info;
	statep->ad_info.ad_diag_flags = AM_DIAG_INTERNAL_LOOP;
	statep->ad_info.ad_diff_flags =
	    AM_DIFF_SR | AM_DIFF_CH | AM_DIFF_PREC | AM_DIFF_ENC;
	statep->ad_info.ad_assist_flags = AM_ASSIST_MIC;
	statep->ad_info.ad_misc_flags = AM_MISC_RP_EXCL | AM_MISC_MONO_DUP;
	statep->ad_info.ad_num_mics = 1;

	/* play capabilities */
	statep->ad_info.ad_play.ad_mixer_srs = audio810_mixer_sample_rates;
	statep->ad_info.ad_play.ad_compat_srs = audio810_compat_sample_rates;
	statep->ad_info.ad_play.ad_conv = &am_src2;
	statep->ad_info.ad_play.ad_sr_info = NULL;
	statep->ad_info.ad_play.ad_chs = audio810_channels;
	statep->ad_info.ad_play.ad_int_rate = pints;
	statep->ad_info.ad_play.ad_max_chs = I810_MAX_OUT_CHANNELS;
	statep->ad_info.ad_play.ad_bsize = I810_BSIZE;

	/* record capabilities */
	statep->ad_info.ad_record.ad_mixer_srs = audio810_mixer_sample_rates;
	statep->ad_info.ad_record.ad_compat_srs =
	    audio810_compat_sample_rates;
	statep->ad_info.ad_record.ad_conv = &am_src2;
	statep->ad_info.ad_record.ad_sr_info = NULL;
	statep->ad_info.ad_record.ad_chs = audio810_channels;
	statep->ad_info.ad_record.ad_int_rate = rints;
	statep->ad_info.ad_record.ad_max_chs = I810_MAX_CHANNELS;
	statep->ad_info.ad_record.ad_bsize = I810_BSIZE;

	if (ddi_get_iblock_cookie(dip, (uint_t)0, &statep->intr_iblock) !=
	    DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!init_state() cannot get iblock cookie");
		return (AUDIO_FAILURE);
	}
	mutex_init(&statep->inst_lock, NULL, MUTEX_DRIVER, statep->intr_iblock);
	cv_init(&statep->i810_cv, NULL, CV_DRIVER, NULL);

	/* fill in device info strings */
	(void) strcpy(statep->i810_dev_info.name, I810_DEV_NAME);
	(void) strcpy(statep->i810_dev_info.config, I810_DEV_CONFIG);
	(void) strcpy(statep->i810_dev_info.version, I810_DEV_VERSION);

	statep->play_buf_size = I810_SAMPR48000 * AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / pints;
	statep->play_buf_size += I810_MOD_SIZE -
	    (statep->play_buf_size % I810_MOD_SIZE);
	statep->record_buf_size = I810_SAMPR48000 * AUDIO_CHANNELS_STEREO *
	    (AUDIO_PRECISION_16 >> AUDIO_PRECISION_SHIFT) / rints;
	statep->record_buf_size += I810_MOD_SIZE -
	    (statep->record_buf_size % I810_MOD_SIZE);

	return (AUDIO_SUCCESS);

}	/* audio810_init_state */


/*
 * audio810_map_regs()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use. Finally, the registers are mapped in.
 *
 *	CAUTION: Make sure all errors call audio_sup_log().
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's devinfo
 *
 * Returns:
 *	AUDIO_SUCCESS		Registers successfully mapped
 *	AUDIO_FAILURE		Registers not successfully mapped
 */
static int
audio810_map_regs(dev_info_t *dip, audio810_state_t *statep)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	uint_t			nregs = 0;
	int			*regs_list;
	int			i;
	int			pciBar1 = 0;
	int			pciBar2 = 0;
	int			pciBar3 = 0;
	int			pciBar4 = 0;

	ATRACE("audio810_map_regs()", statep);

	statep->i810_res_flags = 0;

	/* map PCI config space */
	if (pci_config_setup(statep->dip, &statep->pci_conf_handle) ==
	    DDI_FAILURE) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_regs() configuration memory mapping failed");
		goto error;
	}
	statep->i810_res_flags |= I810_RS_PCI_REGS;

	/* check the "reg" property to get the length of memory-mapped I/O */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&regs_list, &nregs) != DDI_PROP_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_regs() inquire regs property failed");
		goto error;
	}
	/*
	 * Some hardwares, such as Intel ICH0/ICH and AMD 8111, use PCI 0x10
	 * and 0x14 BAR separately for native audio mixer BAR and native bus
	 * mastering BAR. More advanced hardwares, such as Intel ICH4 and ICH5,
	 * support PCI memory BAR, via PCI 0x18 and 0x1C BAR, that allows for
	 * higher performance access to the controller register. All features
	 * can be accessed via this BAR making the I/O BAR (PCI 0x10 and 0x14
	 * BAR) capabilities obsolete. However, these controller maintain the
	 * I/O BAR capability to allow for the reuse of legacy code maintaining
	 * backward compatibility. The I/O BAR is disabled unless system BIOS
	 * enables the simultaneous backward compatible capability on the 0x41
	 * register.
	 *
	 * When I/O BAR is enabled, the value of "reg" property should be like
	 * this,
	 *	phys_hi   phys_mid  phys_lo   size_hi   size_lo
	 * --------------------------------------------------------
	 *	0000fd00  00000000  00000000  00000000  00000000
	 *	0100fd10  00000000  00000000  00000000  00000100
	 *	0100fd14  00000000  00000000  00000000  00000040
	 *	0200fd18  00000000  00000000  00000000  00000200
	 *	0200fd1c  00000000  00000000  00000000  00000100
	 *
	 * When I/O BAR is disabled, the "reg" property of the device node does
	 * not consist of the description for the I/O BAR. The following example
	 * illustrates the vaule of "reg" property,
	 *
	 *	phys_hi   phys_mid  phys_lo   size_hi   size_lo
	 * --------------------------------------------------------
	 *	0000fd00  00000000  00000000  00000000  00000000
	 *	0200fd18  00000000  00000000  00000000  00000200
	 *	0200fd1c  00000000  00000000  00000000  00000100
	 *
	 * If the hardware has memory-mapped I/O access, first try to use
	 * this facility, otherwise we will try I/O access.
	 */
	for (i = 1; i < nregs/I810_INTS_PER_REG_PROP; i++) {
		switch (regs_list[I810_INTS_PER_REG_PROP * i] & 0x000000ff) {
			case 0x10:
				pciBar1 = i;
				break;
			case 0x14:
				pciBar2 = i;
				break;
			case 0x18:
				pciBar3 = i;
				break;
			case 0x1c:
				pciBar4 = i;
				break;
			default:	/* we don't care others */
				break;
		}
	}

	if ((pciBar3 != 0) && (pciBar4 != 0)) {
		/* map audio mixer registers */
		if ((ddi_regs_map_setup(dip, pciBar3,
		    (caddr_t *)&statep->am_regs_base, 0,
		    regs_list[I810_INTS_PER_REG_PROP * pciBar3 +
		    I810_REG_PROP_ADDR_LEN_IDX], &dev_attr,
		    &statep->am_regs_handle)) != DDI_SUCCESS) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!map_regs() memory am mapping failed, len=0x%08x",
			    regs_list[I810_INTS_PER_REG_PROP * pciBar3 +
			    I810_REG_PROP_ADDR_LEN_IDX]);
			goto error;
		}
		statep->i810_res_flags |= I810_RS_AM_REGS;

		/* map bus master register */
		if ((ddi_regs_map_setup(dip, pciBar4,
		    (caddr_t *)&statep->bm_regs_base, 0,
		    regs_list[I810_INTS_PER_REG_PROP * pciBar4 +
		    I810_REG_PROP_ADDR_LEN_IDX], &dev_attr,
		    &statep->bm_regs_handle)) != DDI_SUCCESS) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!map_regs() memory bm mapping failed, len=0x%08x",
			    regs_list[I810_INTS_PER_REG_PROP * pciBar4 +
			    I810_REG_PROP_ADDR_LEN_IDX]);
			goto error;
		}
		statep->i810_res_flags |= I810_RS_BM_REGS;

	} else if ((pciBar1 != 0) && (pciBar2 != 0)) {
		/* map audio mixer registers */
		if ((ddi_regs_map_setup(dip, pciBar1,
		    (caddr_t *)&statep->am_regs_base, 0,
		    regs_list[I810_INTS_PER_REG_PROP * pciBar1 +
		    I810_REG_PROP_ADDR_LEN_IDX], &dev_attr,
		    &statep->am_regs_handle)) != DDI_SUCCESS) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!map_regs() I/O am mapping failed, len=0x%08x",
			    regs_list[I810_INTS_PER_REG_PROP * pciBar1 +
			    I810_REG_PROP_ADDR_LEN_IDX]);
			goto error;
		}
		statep->i810_res_flags |= I810_RS_AM_REGS;

		/* map bus master register */
		if ((ddi_regs_map_setup(dip, pciBar2,
		    (caddr_t *)&statep->bm_regs_base, 0,
		    regs_list[I810_INTS_PER_REG_PROP * pciBar2 +
		    I810_REG_PROP_ADDR_LEN_IDX], &dev_attr,
		    &statep->bm_regs_handle)) != DDI_SUCCESS) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!map_regs() I/O bm mapping failed, len=: 0x%08x",
			    regs_list[I810_INTS_PER_REG_PROP * pciBar2 +
			    I810_REG_PROP_ADDR_LEN_IDX]);
			goto error;
		}
		statep->i810_res_flags |= I810_RS_BM_REGS;
	} else {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_reg() pci BAR error");
		goto error;
	}

	/*
	 * now, from here we allocate DMA memory for buffer descriptor list.
	 * we allocate adjacent DMA memory for all DMA engines.
	 */
	if (ddi_dma_alloc_handle(dip, &bdlist_dma_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &statep->bdl_dma_handle) != DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_regs() ddi_dma_alloc_handle(bdlist) failed ");
		goto error;
	}
	statep->i810_res_flags |= I810_RS_DMA_BDL_HANDLE;

	/*
	 * we allocate all buffer descriptors lists in continuous dma memory.
	 */
	if (ddi_dma_mem_alloc(statep->bdl_dma_handle,
	    sizeof (i810_bd_entry_t) * I810_BD_NUMS * 2,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&statep->bdl_virtual, &statep->bdl_size,
	    &statep->bdl_acc_handle) != DDI_SUCCESS) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_regs() ddi_dma_mem_alloc(bdlist) failed");
		goto error;
	}
	statep->i810_res_flags |= I810_RS_DMA_BDL_MEM;

	if (ddi_dma_addr_bind_handle(statep->bdl_dma_handle, NULL,
	    (caddr_t)statep->bdl_virtual, statep->bdl_size,
	    DDI_DMA_RDWR|DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &cookie,
	    &count) != DDI_DMA_MAPPED) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_regs() addr_bind_handle failed");
		goto error;
	}

	/*
	 * there some bugs in the DDI framework and it is possible to
	 * get multiple cookies
	 */
	if (count != 1) {
		(void) ddi_dma_unbind_handle(statep->bdl_dma_handle);
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!map_regs() addr_bind_handle failed, cookies > 1");
		goto error;
	}

	statep->bdl_virt_pin = (i810_bd_entry_t *)(statep->bdl_virtual);
	statep->bdl_virt_pout = statep->bdl_virt_pin + I810_BD_NUMS;
	statep->bdl_phys_pin = (uint32_t)(cookie.dmac_address);
	statep->bdl_phys_pout = statep->bdl_phys_pin +
	    sizeof (i810_bd_entry_t) * I810_BD_NUMS;

	statep->i810_res_flags |= I810_RS_DMA_BDL_BIND;

	ddi_prop_free(regs_list);

	return (AUDIO_SUCCESS);

error:
	if (nregs > 0) {
		ddi_prop_free(regs_list);
	}
	audio810_unmap_regs(statep);

	return (AUDIO_FAILURE);

}	/* audio810_map_regs() */

/*
 * audio810_unmap_regs()
 *
 * Description:
 *	This routine unbinds the play and record DMA handles, frees
 *	the DMA buffers and the unmaps control registers.
 *
 * Arguments:
 *	audio810_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio810_unmap_regs(audio810_state_t *statep)
{
	if (statep->i810_res_flags & I810_RS_DMA_BDL_BIND) {
		statep->i810_res_flags &= ~I810_RS_DMA_BDL_BIND;
		(void) ddi_dma_unbind_handle(statep->bdl_dma_handle);
	}

	if (statep->i810_res_flags & I810_RS_DMA_BDL_MEM) {
		statep->i810_res_flags &= ~I810_RS_DMA_BDL_MEM;
		ddi_dma_mem_free(&statep->bdl_acc_handle);
	}

	if (statep->i810_res_flags & I810_RS_DMA_BDL_HANDLE) {
		statep->i810_res_flags &= ~I810_RS_DMA_BDL_HANDLE;
		ddi_dma_free_handle(&statep->bdl_dma_handle);
	}

	if (statep->i810_res_flags & I810_RS_BM_REGS) {
		statep->i810_res_flags &= ~I810_RS_BM_REGS;
		ddi_regs_map_free(&statep->bm_regs_handle);
	}

	if (statep->i810_res_flags & I810_RS_AM_REGS) {
		statep->i810_res_flags &= ~I810_RS_AM_REGS;
		ddi_regs_map_free(&statep->am_regs_handle);
	}

	if (statep->i810_res_flags & I810_RS_PCI_REGS) {
		statep->i810_res_flags &= ~I810_RS_PCI_REGS;
		pci_config_teardown(&statep->pci_conf_handle);
	}

}	/* audio810_unmap_regs() */

/*
 * audio810_alloc_sample_buf()
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
 *	audio810_state_t	*state	The device's state structure
 *	int			which	Which sample buffer, PCM in or PCM out
 *					I810_DMA_PCM_IN ---PCM in DMA engine
 *					I810_DMA_PCM_OUT---PCM out DMA engine
 *	int			len	The length of the DMA buffers
 *
 * Returns:
 *	AUDIO_SUCCESS	 Allocating DMA buffers successfully
 *	AUDIO_FAILURE	 Failed to allocate dma buffers
 */

static int
audio810_alloc_sample_buf(audio810_state_t *statep, int which, int len)
{
	i810_sample_buf_t	*buf;
	i810_bdlist_chunk_t	*chunk;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			i;

	if (which == I810_DMA_PCM_OUT) {
		buf = &statep->play_buf;
	} else {
		ASSERT(which == I810_DMA_PCM_IN);
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
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &chunk->data_buf,
		    &chunk->real_len, &chunk->acc_handle) != DDI_SUCCESS) {
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

}	/* audio810_alloc_sample_buf() */

/*
 * audio810_free_sample_buf()
 *
 * Description:
 *	This routine frees the DMA buffers of the sample buffer. The DMA
 *	buffers were allocated by calling audio810_alloc_sample_buf().
 *
 * Arguments:
 *	audio810_state_t	*state	The device's state structure
 *	i810_sample_buf_t	*buf	The sample buffer structure
 *
 * Returns:
 *	void
 */
static void
audio810_free_sample_buf(audio810_state_t *statep, i810_sample_buf_t *buf)
{
	i810_bdlist_chunk_t	 *chunk;
	int 	i;

	ATRACE("audio810_free_sample_buf() audio810_statep", statep);

	for (i = 0; i < 2; i++) {
		chunk = &(buf->chunk[i]);
		(void) ddi_dma_unbind_handle(chunk->dma_handle);
		ddi_dma_mem_free(&chunk->acc_handle);
		chunk->acc_handle = 0;
		ddi_dma_free_handle(&chunk->dma_handle);
	}

}	/* audio810_free_sample_buf() */

/*
 * audio810_reclaim_play_buf()
 *
 * Description:
 *	When the audio controller finishes fetching the data from DMA
 *	buffers, this routine will be called by interrupt handler to
 *	reclaim the DMA buffers.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio810_reclaim_play_buf(audio810_state_t *statep)
{
	i810_sample_buf_t	*buf;
	int16_t		bmciv;

	ASSERT(mutex_owned(&statep->inst_lock));

	buf = &statep->play_buf;
	bmciv = I810_BM_GET8(I810_PCM_OUT_CIV);
	while (buf->head != bmciv) {
		buf->avail++;
		buf->head++;
		if (buf->head >= I810_BD_NUMS) {
			buf->head = 0;
		}
	}

}	/* audio810_reclaim_play_buf() */

/*
 * audio810_chip_init()
 *
 * Description:
 *	This routine initializes the AMD 8111 audio controller and the AC97
 *	codec.  The AC97 codec registers are programmed from codec_shadow[].
 *	If we are not doing a restore, we initialize codec_shadow[], otherwise
 *	we use the current values of shadow
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *	int			restore		If I810_INIT_RESTORE then
 *						restore	from codec_shadow[]
 * Returns:
 *	AUDIO_SUCCESS	The hardware was initialized properly
 *	AUDIO_FAILURE	The hardware couldn't be initialized properly
 */
static int
audio810_chip_init(audio810_state_t *statep, int restore)
{
	uint32_t	gcr;
	uint32_t	gsr;
	uint32_t	codec_ready;
	uint16_t	*shadow;
	int 		loop;
	int 		i;
	int		j;
	uint16_t	sr;
	uint16_t	vid1;
	uint16_t	vid2;
	uint16_t	tmp;
	clock_t		ticks;

	gcr = I810_BM_GET32(I810_REG_GCR);
	ticks = drv_usectohz(100);

	/*
	 * SADA only supports stereo, so we set the channel bits
	 * to "00" to select 2 channels.
	 */
	gcr &= ~(I810_GCR_ACLINK_OFF | I810_GCR_CHANNELS_MASK);

	/*
	 * Datasheet(ICH5, document number of Intel: 252751-001):
	 * 3.6.5.5(page 37)
	 * 	if reset bit(bit1) is "0", driver must set it
	 * 	to "1" to de-assert the AC_RESET# signal in AC
	 * 	link, thus completing a cold reset. But if the
	 * 	bit is "1", then a warm reset is required.
	 */
	gcr |= (gcr & I810_GCR_COLD_RST) == 0 ?
	    I810_GCR_COLD_RST:I810_GCR_WARM_RST;
	I810_BM_PUT32(I810_REG_GCR, gcr);

	/* according AC'97 spec, wait for codec reset */
	for (loop = 6000; --loop >= 0; ) {
		delay(ticks);
		gcr = I810_BM_GET32(I810_REG_GCR);
		if ((gcr & I810_GCR_WARM_RST) == 0) {
			break;
		}
	}

	/* codec reset failed */
	if (loop < 0) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!Failed to reset codec");
		return (AUDIO_FAILURE);
	}

	/*
	 * Wait for codec ready. The hardware can provide the state of
	 * codec ready bit on SDATA_IN[0], SDATA_IN[1] or SDATA_IN[2]
	 */
	codec_ready =
	    I810_GSR_PRI_READY | I810_GSR_SEC_READY | I810_GSR_TRI_READY;
	for (loop = 7000; --loop >= 0; ) {
		delay(ticks);
		gsr = I810_BM_GET32(I810_REG_GSR);
		if ((gsr & codec_ready) != 0) {
			break;
		}
	}
	if (loop < 0) {
		audio_sup_log(statep->audio_handle, CE_WARN,
		    "!No codec ready signal received");
		return (AUDIO_FAILURE);
	}

	/*
	 * put the audio controller into quiet state, everything off
	 */
	audio810_stop_dma(statep);

	/* AC97 register reset */
	if (audio810_reset_ac97(statep) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	shadow = statep->codec_shadow;

	if (restore == I810_INIT_NO_RESTORE) {
		for (i = 0; i < I810_LAST_AC_REG; i += 2) {
			(void) audio810_read_ac97(statep, i,
			    &(shadow[I810_CODEC_REG(i)]));
		}

		/* 02h - set master line out volume, muted, 0dB */
		shadow[I810_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] = MVR_MUTE;

		/* 04h - set alternate line out volume, muted, 0dB */
		shadow[I810_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE;

		/* 06h - set master mono volume, muted, 0dB */
		shadow[I810_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE;

		/* 08h - set master tone control to no modification */
		shadow[I810_CODEC_REG(AC97_MASTER_TONE_CONTROL_REGISTER)] =
		    MTCR_BASS_BYPASS|MTCR_TREBLE_BYPASS;

		/* 0ah - open pc beep, 0dB */
		shadow[I810_CODEC_REG(AC97_PC_BEEP_REGISTER)] = PCBR_0dB_ATTEN;

		/* 0ch - set phone input, mute, 0dB attenuation */
		shadow[I810_CODEC_REG(AC97_PHONE_VOLUME_REGISTER)] =
		    PVR_MUTE|PVR_0dB_GAIN;

		/* 0eh - set mic input, mute, 0dB attenuation */
		shadow[I810_CODEC_REG(AC97_MIC_VOLUME_REGISTER)] =
		    MICVR_MUTE|MICVR_0dB_GAIN;

		/* 10h - set line input, mute, 0dB attenuation */
		shadow[I810_CODEC_REG(AC97_LINE_IN_VOLUME_REGISTER)] =
		    LIVR_MUTE|LIVR_RIGHT_0dB_GAIN|LIVR_LEFT_0dB_GAIN;

		/* 12h - set cd input, mute, 0dB attenuation */
		shadow[I810_CODEC_REG(AC97_CD_VOLUME_REGISTER)] =
		    CDVR_MUTE|CDVR_RIGHT_0dB_GAIN|CDVR_LEFT_0dB_GAIN;

		/* 14h - set video input, mute, 0dB attenuation */
		shadow[I810_CODEC_REG(AC97_VIDEO_VOLUME_REGISTER)] =
		    VIDVR_MUTE|VIDVR_RIGHT_0dB_GAIN|VIDVR_LEFT_0dB_GAIN;

		/* 16h - set aux input, mute, 0dB attenuation */
		shadow[I810_CODEC_REG(AC97_AUX_VOLUME_REGISTER)] =
		    AUXVR_MUTE|AUXVR_RIGHT_0dB_GAIN|AUXVR_LEFT_0dB_GAIN;

		/* 18h - set PCM out input, NOT muted, 0dB gain */
		shadow[I810_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_RIGHT_0dB_GAIN|PCMOVR_LEFT_0dB_GAIN;

		/* 1ah - set input device as mic */
		shadow[I810_CODEC_REG(AC97_RECORD_SELECT_CTRL_REGISTER)] =
		    RSCR_R_MIC|RSCR_L_MIC;

		/* 1ch - set record gain to 0dB and not muted */
		shadow[I810_CODEC_REG(AC97_RECORD_GAIN_REGISTER)] =
		    RGR_RIGHT_0db_GAIN|RGR_LEFT_0db_GAIN;

		/* 1eh - set record mic gain to 0dB and not muted */
		shadow[I810_CODEC_REG(AC97_RECORD_GAIN_MIC_REGISTER)] =
		    RGMR_0db_GAIN;

		/* 20h - set GP register, mic 1, everything else off */
		shadow[I810_CODEC_REG(AC97_GENERAL_PURPOSE_REGISTER)] =
		    GPR_MS_MIC1|GPR_MONO_MIX_IN;

		/* 22h - set 3D control to NULL */
		shadow[I810_CODEC_REG(AC97_THREE_D_CONTROL_REGISTER)] =
		    TDCR_NULL;

		/*
		 * 26h - set EAPD to 1 for devices with ac97-invert-amp
		 * property.
		 *
		 * According to AC'97 spec, EAPD (PR7) independently controls
		 * an output pin that manages an optional external audio
		 * amplifier. AC'97 compliance requires the implementation of
		 * a dedicated output pin for external audio amplifier control.
		 * The pin is controlled via the ¡°EAPD¡±(External Amplifier
		 * Powerdown) bit in Powerdown Ctrl/Stat Register, bit 15
		 * (formerly PR7). EAPD = 0 places a 0 on the output pin,
		 * enabling an external audio amplifier, EAPD = 1 shuts it
		 * down. Audio amplifier devices that operate with reverse
		 * polarity may require an external inverter. By default,
		 * EAPD = 0 is to enable external audio amplifier, but for
		 * some Sony Vaio laptops, we need to revert polarity to
		 * enable external amplifier.
		 */
		switch (ddi_prop_get_int(DDI_DEV_T_ANY, statep->dip,
		    DDI_PROP_DONTPASS, "ac97-invert-amp", -1)) {
		case -1:
			/* not attempt to flip EAPD */
			break;

		case 0:
			/* set EAPD to 0 */
			shadow[I810_CODEC_REG(
			    AC97_POWERDOWN_CTRL_STAT_REGISTER)] &= ~PCSR_EAPD;
			break;

		case 1:
			/* set EAPD to 1 */
			shadow[I810_CODEC_REG(
			    AC97_POWERDOWN_CTRL_STAT_REGISTER)] |= PCSR_EAPD;
			break;

		default:
			/* invalid */
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!Invalid value for ac97-invert-amp property");
			break;
		}

		/*
		 * The rest we ignore, most are reserved.
		 */

	}

	if (restore == I810_INIT_RESTORE) {
		/* Restore from saved values */
		shadow[I810_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] =
		    MVR_MUTE;
		shadow[I810_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE;
		shadow[I810_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE;
		shadow[I810_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_MUTE;
	}

	/* Now we set the AC97 codec registers to the saved values */
	for (i = 2; i <= I810_LAST_AC_REG; i += 2)
		(void) audio810_write_ac97(statep, i,
		    shadow[I810_CODEC_REG(i)]);

	(void) audio810_read_ac97(statep, AC97_RESET_REGISTER, &tmp);
	if (tmp & RR_HEADPHONE_SUPPORT) {
		statep->i810_defaults.play.port |= AUDIO_HEADPHONE;
		statep->i810_defaults.play.avail_ports |= AUDIO_HEADPHONE;
		statep->i810_defaults.play.mod_ports |= AUDIO_HEADPHONE;
	}

	/*
	 * Most vendors connect the surr-out of ad1980/ad1985 codecs to the
	 * line-out jack. So far we haven't found which vendors don't
	 * do that. So we assume that all vendors swap the surr-out
	 * and the line-out outputs. So we need swap the two outputs.
	 * But we still internally process the "ad198x-swap-output"
	 * property. If someday some vendors do not swap the outputs,
	 * we would set "ad198x-swap-output = 0" in the
	 * /kernel/drv/audio810.conf file, and unload and reload the
	 * audio810 driver (or reboot).
	 */
	(void) audio810_read_ac97(statep, AC97_VENDOR_ID1_REGISTER, &vid1);
	(void) audio810_read_ac97(statep, AC97_VENDOR_ID2_REGISTER, &vid2);
	if (vid1 == AD1980_VID1 &&
	    (vid2 == AD1980_VID2 || vid2 == AD1985_VID2)) {
		if (ddi_prop_get_int(DDI_DEV_T_ANY, statep->dip,
		    DDI_PROP_DONTPASS, "ad198x-swap-output", 1) == 1) {
			statep->swap_out = B_TRUE;
			(void) audio810_read_ac97(statep, CODEC_AD_REG_MISC,
			    &tmp);
			(void) audio810_write_ac97(statep, CODEC_AD_REG_MISC,
			    tmp | AD1980_MISC_LOSEL | AD1980_MISC_HPSEL);
		}
	}

	/* check if the codec implements 6 bit volume register */
	(void) audio810_write_ac97(statep, AC97_MASTER_VOLUME_REGISTER,
	    MVR_MUTE | MVR_RIGHT_OPTIONAL_MASK | MVR_LEFT_OPTIONAL_MASK);
	(void) audio810_read_ac97(statep, AC97_MASTER_VOLUME_REGISTER, &tmp);
	if ((tmp & 0x7fff) != (MVR_RIGHT_MASK | MVR_LEFT_MASK)) {
		statep->vol_bits_mask = 6;
	}
	/* resume the master volume to the max */
	(void) audio810_write_ac97(statep, AC97_MASTER_VOLUME_REGISTER,
	    MVR_MUTE);

	/*
	 * if the codec chip does not support variable sample rate,
	 * we set the sample rate to 48K
	 */
	(void) audio810_read_ac97(statep, AC97_EXTENDED_AUDIO_REGISTER, &tmp);
	audio_sup_log(statep->audio_handle, CE_NOTE,
	    "!%s%d: xid=0x%04x, vid1=0x%04x, vid2=0x%04x",
	    audio810_name,  ddi_get_instance(statep->dip), tmp, vid1, vid2);
	if (!(tmp & EAR_VRA)) {
		statep->var_sr = B_FALSE;
		statep->ad_info.ad_record.ad_compat_srs =
		    audio810_min_compat_sample_rates;
		statep->ad_info.ad_play.ad_compat_srs =
		    audio810_min_compat_sample_rates;
		statep->i810_defaults.play.sample_rate =
		    I810_SAMPR48000;
		statep->i810_defaults.record.sample_rate =
		    I810_SAMPR48000;
	} else {	/* variable sample rate supported */
		statep->var_sr = B_TRUE;

		/* set variable rate mode */
		(void) audio810_write_ac97(statep,
		    AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER, EASCR_VRA);

		/* check the sample rates supported */
		for (i = 0, j = 0; audio810_compat_srs[i] != 0; i++) {
			(void) audio810_write_ac97(statep,
			    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER,
			    audio810_compat_srs[i]);
			(void) audio810_read_ac97(statep,
			    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, &sr);

			if (sr == audio810_compat_srs[i]) {
				if (i != j) {
					audio810_compat_srs[j] =
					    audio810_compat_srs[i];
				}
				j++;
			}
		}

		if (j < 1) {
			audio_sup_log(statep->audio_handle, CE_WARN,
			    "!No standard sample rate is supported");
			return (AUDIO_FAILURE);
		}
		audio810_compat_srs[j] = 0;

		/*
		 * if the configuration doesn't support 8K sample rate,
		 * we modify the default value to the first.
		 */
		if (audio810_compat_srs[0] != I810_SAMPR8000) {
			statep->i810_defaults.play.sample_rate =
			    audio810_compat_srs[0];
			statep->i810_defaults.record.sample_rate =
			    audio810_compat_srs[0];
		}
	}

	return (AUDIO_SUCCESS);

}	/* audio810_chip_init() */

/*
 * audio810_stop_dma()
 *
 * Description:
 *	This routine is used to put each DMA engine into the quiet state.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio810_stop_dma(audio810_state_t *statep)
{
	/* pause bus master (needed for the following reset register) */
	I810_BM_PUT8(I810_PCM_IN_CR, 0x0);
	I810_BM_PUT8(I810_PCM_OUT_CR, 0x0);
	I810_BM_PUT8(I810_MIC_CR, 0x0);

	/* and then reset the bus master registers for a three DMA engines */
	I810_BM_PUT8(I810_PCM_IN_CR, I810_BM_CR_RST);
	I810_BM_PUT8(I810_PCM_OUT_CR, I810_BM_CR_RST);
	I810_BM_PUT8(I810_MIC_CR, I810_BM_CR_RST);

	statep->flags = 0;

/*
 * XXXX Not sure what these declarations are for, but I brought them from
 * the PM gate.
 */
	statep->play_buf.io_started = B_FALSE;

	statep->record_buf.io_started = B_FALSE;

}	/* audio810_stop_dma() */

/*
 * audio810_set_gain()
 *
 * Description:
 *	Set the play/record gain.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
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
audio810_set_gain(audio810_state_t *statep, int dir, int gain, int channel)
{
	uint16_t	tmp;
	uint16_t	channel_gain;
	int		regidx;
	uint16_t	mask;

	if (gain > AUDIO_MAX_GAIN) {
		gain = AUDIO_MAX_GAIN;
	} else if (gain < AUDIO_MIN_GAIN) {
		gain = AUDIO_MIN_GAIN;
	}

	if (statep->vol_bits_mask == 6)
		mask = 0x3f;
	else
		mask = 0x1f;

	channel_gain = AUDIO_MAX_GAIN - gain;
	channel_gain = ((channel_gain << statep->vol_bits_mask) -
	    channel_gain) / AUDIO_MAX_GAIN;

	if (dir == AUDIO_PLAY) {
		if (statep->swap_out == B_TRUE) {
			regidx = AC97_EXTENDED_LRS_VOLUME_REGISTER;
		} else {
			regidx = AC97_PCM_OUT_VOLUME_REGISTER;
		}
		(void) audio810_read_ac97(statep, regidx, &tmp);

		if (channel == 0) { /* left channel */
			tmp &= mask;
			tmp |= (channel_gain << 8);
		} else {	/* right channel */
			tmp &= (mask << 8);
			tmp |= channel_gain;
		}

		(void) audio810_write_ac97(statep, regidx, tmp);
	} else {
		ASSERT(dir == AUDIO_RECORD);

		(void) audio810_read_ac97(statep,
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
		(void) audio810_write_ac97(statep,
		    AC97_RECORD_GAIN_REGISTER, tmp);
	}

	return (AUDIO_SUCCESS);

}	/* audio810_set_gain() */

/*
 * audio810_set_port()
 *
 * Description:
 *	Set the play/record port.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
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
audio810_set_port(audio810_state_t *statep, int dir, int port)
{
	uint16_t	tmp;

	if (dir == AUDIO_PLAY) {	/* output port */
		tmp = 0;
		if (port == I810_PORT_UNMUTE) {
			port = statep->i810_output_port;
		}

		if (port & AUDIO_SPEAKER) {
			(void) audio810_and_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_SPEAKER;
		} else {
			(void) audio810_or_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MVR_MUTE);
		}

		if (port & AUDIO_LINE_OUT) {
			if (statep->swap_out == B_FALSE) {
				(void) audio810_and_ac97(statep,
				    AC97_MASTER_VOLUME_REGISTER,
				    (uint16_t)~MVR_MUTE);
			} else {
				(void) audio810_and_ac97(statep,
				    AC97_EXTENDED_LRS_VOLUME_REGISTER,
				    (uint16_t)~AD1980_SURR_MUTE);
			}
			tmp |= AUDIO_LINE_OUT;
		} else {
			if (statep->swap_out == B_FALSE) {
				(void) audio810_or_ac97(statep,
				    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE);
			} else {
				(void) audio810_or_ac97(statep,
				    AC97_EXTENDED_LRS_VOLUME_REGISTER,
				    AD1980_SURR_MUTE);
			}
		}

		if (port & AUDIO_HEADPHONE) {
			(void) audio810_and_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_HEADPHONE;
		} else {
			(void) audio810_or_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER, MVR_MUTE);
		}

		ATRACE_32("810_set_port() out port", tmp);
		statep->i810_output_port = tmp;
		if (tmp != port) {
			ATRACE_32("810_set_port() bad out port", port);
			return (AUDIO_FAILURE);
		}

	} else {		/* input port */
		ASSERT(dir == AUDIO_RECORD);

		switch (port) {
		case AUDIO_NONE:
			/* set to an unused input */
			tmp = RSCR_R_PHONE | RSCR_L_PHONE;

			/* mute the master record input */
			(void) audio810_or_ac97(statep,
			    AC97_RECORD_GAIN_REGISTER, RGR_MUTE);

			if (statep->i810_monitor_gain) {
				if (statep->i810_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio810_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_LINE_IN) {
					(void) audio810_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_CD) {
					(void) audio810_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			}
			break;

		case AUDIO_MICROPHONE:
			/* set to the mic input */
			tmp = RSCR_R_MIC | RSCR_L_MIC;

			if (statep->i810_monitor_gain) {
				if (statep->i810_input_port == AUDIO_LINE_IN) {
					(void) audio810_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_CD) {
					(void) audio810_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				(void) audio810_write_ac97(statep,
				    AC97_MIC_VOLUME_REGISTER,
				    statep->i810_monitor_gain);
			}
			break;

		case AUDIO_LINE_IN:
			/* set to the line in input */
			tmp = RSCR_R_LINE_IN | RSCR_L_LINE_IN;

			/* see if we need to update monitor loopback */
			if (statep->i810_monitor_gain) {
				if (statep->i810_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio810_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_CD) {
					(void) audio810_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				(void) audio810_write_ac97(statep,
				    AC97_LINE_IN_VOLUME_REGISTER,
				    statep->i810_monitor_gain);
			}
			break;

		case AUDIO_CD:
			/* set to the line in input */
			tmp = RSCR_R_CD|RSCR_L_CD;

			/* see if we need to update monitor loopback */
			if (statep->i810_monitor_gain) {
				if (statep->i810_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio810_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_LINE_IN) {
					(void) audio810_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				}
				(void) audio810_write_ac97(statep,
				    AC97_CD_VOLUME_REGISTER,
				    statep->i810_monitor_gain);
			}
			break;

		case AUDIO_CODEC_LOOPB_IN:
			/* set to the loopback input */
			tmp = RSCR_R_STEREO_MIX | RSCR_L_STEREO_MIX;

			if (statep->i810_monitor_gain) {
				if (statep->i810_input_port == AUDIO_LINE_IN) {
					(void) audio810_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio810_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->i810_input_port ==
				    AUDIO_CD) {
					(void) audio810_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			}
			break;

		default:
			ATRACE_32("810_set_port bad in port", port);
			return (AUDIO_FAILURE);
		}

		/* select the input */
		(void) audio810_write_ac97(statep,
		    AC97_RECORD_SELECT_CTRL_REGISTER, tmp);
		if ((port != AUDIO_NONE) &&
		    (statep->codec_shadow[I810_CODEC_REG(
		    AC97_RECORD_GAIN_REGISTER)] & RGR_MUTE)) {
			(void) audio810_and_ac97(statep,
			    AC97_RECORD_GAIN_REGISTER,
			    (uint16_t)~RGR_MUTE);
		}
		statep->i810_input_port = port;
	}

	ATRACE_32("810_set_port() returning", 0);
	return (AUDIO_SUCCESS);

}	/* audio810_set_port() */

/*
 * audio810_set_monitor_gain()
 *
 * Description:
 *	Set the monitor gain.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *	int			gain		The gain to set
 *
 * Returns:
 * 	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
static int
audio810_set_monitor_gain(audio810_state_t *statep, int gain)
{
	uint16_t	tmp_short;
	int		rc = AUDIO_SUCCESS;

	ATRACE("in audio810_set_monitor_gain()", statep);

	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	if (gain == 0) {
		/* disable loopbacks when gain == 0 */
		tmp_short = MVR_MUTE;
	} else {
		/* Adjust the value of gain to the requirement of AC'97 */
		tmp_short = AUDIO_MAX_GAIN - gain;
		tmp_short = ((tmp_short << statep->vol_bits_mask) - tmp_short) /
		    AUDIO_MAX_GAIN;
		tmp_short |= (((tmp_short << statep->vol_bits_mask) -
		    tmp_short) / AUDIO_MAX_GAIN) << 8;
	}

	switch (statep->i810_input_port) {
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
		tmp_short |= statep->codec_shadow[I810_CODEC_REG(
		    AC97_MIC_VOLUME_REGISTER)] & MICVR_20dB_BOOST;
		(void) audio810_write_ac97(statep,
		    AC97_MIC_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_LINE_IN:
		(void) audio810_write_ac97(statep,
		    AC97_LINE_IN_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_CD:
		(void) audio810_write_ac97(statep,
		    AC97_CD_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_CODEC_LOOPB_IN:
		/* we already are getting the loopback, so done */
		rc = AUDIO_SUCCESS;
		goto done;

	default:
		/* this should never happen! */
		ATRACE("i810_ad_set_config() monitor gain bad device", NULL);
		rc = AUDIO_FAILURE;
		goto done;
	}

	if (gain == 0) {
		statep->i810_monitor_gain = 0;
	} else {
		statep->i810_monitor_gain = tmp_short;
	}

done:
	ATRACE_32("audio810_set_monitor_gain()", rc);

	return (rc);

}	/* audio810_set_monitor_gain() */

/*
 * audio810_codec_sync()
 *
 * Description:
 *	Serialize access to the AC97 audio mixer registers.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Ready for an I/O access to the codec
 *	AUDIO_FAILURE		An I/O access is currently in progress, can't
 *				perform another I/O access.
 */
static int
audio810_codec_sync(audio810_state_t *statep)
{
	int 	i;
	uint16_t	casr;

	for (i = 0; i < 300; i++) {
		casr = I810_BM_GET8(I810_REG_CASR);
		if ((casr & 1) == 0) {
			return (AUDIO_SUCCESS);
		}
		drv_usecwait(10);
	}

	return (AUDIO_FAILURE);

}	/* audio810_codec_sync() */

/*
 * audio810_and_ac97()
 *
 * Description:
 *	Logically AND the value with the specified ac97 codec register
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The value to AND
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audio810_and_ac97(audio810_state_t *statep, int reg, uint16_t data)
{
	uint16_t	tmp;

	if (audio810_codec_sync(statep) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	I810_AM_PUT16(reg, data & statep->codec_shadow[I810_CODEC_REG(reg)]);

	(void) audio810_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audio810_and_ac97() */

/*
 * audio810_or_ac97()
 *
 * Description:
 *	Logically OR the value with the specified ac97 codec register
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The value to OR
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audio810_or_ac97(audio810_state_t *statep, int reg, uint16_t data)
{
	uint16_t	tmp;

	if (audio810_codec_sync(statep) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	I810_AM_PUT16(reg, data | statep->codec_shadow[I810_CODEC_REG(reg)]);

	(void) audio810_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audio810_or_ac97() */

/*
 * audio810_write_ac97()
 *
 * Description:
 *	Set the specific AC97 Codec register.
 *
 * Arguments:
 *	audio810_state_t	 *state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The data want to be set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audio810_write_ac97(audio810_state_t *statep, int reg, uint16_t data)
{
	uint16_t tmp;

	if (audio810_codec_sync(statep) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}
	I810_AM_PUT16(reg, data);

	(void) audio810_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audio810_write_ac97() */

/*
 * audio810_read_ac97()
 *
 * Description:
 *	Get the specific AC97 Codec register. It also updates codec_shadow[]
 *	with the register value.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		*data		The data to be returned
 *
 * Returns:
 *	AUDIO_SUCCESS		Reading the codec register successfully
 *	AUDIO_FAILURE		Failed to read the register
 */
static int
audio810_read_ac97(audio810_state_t *statep, int reg, uint16_t *data)
{
	if (audio810_codec_sync(statep) != AUDIO_SUCCESS) {
		*data = 0xffff;
		return (AUDIO_FAILURE);
	}
	*data = I810_AM_GET16(reg);
	statep->codec_shadow[I810_CODEC_REG(reg)] = *data;

	return (AUDIO_SUCCESS);

}	/* audio810_read_ac97() */

/*
 * audio810_reset_ac97()
 *
 * Description:
 *	Reset AC97 Codec register.
 *
 * Arguments:
 *	audio810_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Reset the codec successfully
 *	AUDIO_FAILURE		Failed to reset the codec
 */
static int
audio810_reset_ac97(audio810_state_t *statep)
{
	uint16_t	tmp;

	if (audio810_read_ac97(statep,
	    AC97_POWERDOWN_CTRL_STAT_REGISTER, &tmp) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	if (audio810_write_ac97(statep, AC97_RESET_REGISTER, 1) !=
	    AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	if (audio810_read_ac97(statep, AC97_RESET_REGISTER, &tmp) !=
	    AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audio810_reset_ac97() */

/*
 * audio810_fill_play_buf()
 *
 * Description:
 *	This routine is called by i810_ad_start_play() and the interrupt
 *	handler. It fills playback samples into the DMA memory, sets the
 *	BDL entries, and starts the playback DMA engine.
 *
 * Arguments:
 *	audio810_state_t *statep	The device's state structure
 *
 * Returns:
 * 	AUDIO_SUCCESS		Starting PCM out engine successfully
 * 	AUDIO_FAILURE		Failed to start PCM out engine.
 */
static int
audio810_fill_play_buf(audio810_state_t *statep)
{
	i810_bdlist_chunk_t	*chunk;
	i810_sample_buf_t	*buf;
	i810_bd_entry_t		*bdesc;
	int			samples;
	int			rs;
	uint8_t			cr;

	buf = &statep->play_buf;

	if (!buf->io_started) {
		/*
		 * ready to start PCM out engine
		 */
		I810_BM_PUT8(I810_PCM_OUT_CR, 0);
		I810_BM_PUT8(I810_PCM_OUT_CR, I810_BM_CR_RST |I810_BM_CR_IOCE);
		I810_BM_PUT8(I810_PCM_OUT_LVI, 0);
		I810_BM_PUT32(I810_PCM_OUT_BD_BASE, statep->bdl_phys_pout);
		buf->head = 0;
		buf->tail = 0;
		buf->avail = 2;	/* have only two buffers for playback */
	}

	if (buf->avail == 0) {
		return (AUDIO_SUCCESS);
	}

	samples = statep->i810_psample_rate * statep->i810_pchannels /
	    statep->ad_info.ad_play.ad_int_rate;

	/* if not an even number of samples we panic! */
	if ((samples & 1) != 0) {
		samples++;
	}

	while (buf->avail > 0) {
		chunk = &(buf->chunk[buf->tail & 1]);
		mutex_exit(&statep->inst_lock);
		rs = am_get_audio(statep->audio_handle,
		    (char *)(chunk->data_buf), AUDIO_NO_CHANNEL, samples);
		mutex_enter(&statep->inst_lock);

		if (((statep->flags & I810_DMA_PLAY_STARTED) == 0) &&
		    (buf->io_started)) {
			return (AUDIO_FAILURE);
		}

		if (rs <= 0) {
			if (statep->flags & I810_DMA_PLAY_EMPTY) {

				/*
				 * Clear the flag so if audio is restarted while
				 * in am_play_shutdown() we can detect it and
				 * not mess things up.
				 */
				statep->flags &= ~I810_DMA_PLAY_STARTED;

				/* shutdown the mixer */
				mutex_exit(&statep->inst_lock);
				am_play_shutdown(statep->audio_handle, NULL);
				mutex_enter(&statep->inst_lock);

				/*
				 * Make sure playing wasn't restarted when lock
				 * lost if reopened, should return success
				 */
				if (statep->flags & I810_DMA_PLAY_STARTED) {
					return (AUDIO_SUCCESS);
				}

				/* Finished playing, then stop it */
				I810_BM_PUT8(I810_PCM_OUT_CR, 0);
				I810_BM_PUT8(I810_PCM_OUT_CR, I810_BM_CR_RST);
				buf->io_started = B_FALSE;

				/* clr the flags getting ready for next start */
				statep->flags &= ~(I810_DMA_PLAY_PAUSED |
				    I810_DMA_PLAY_EMPTY);

				/* return the value for i810_ad_start_play() */
				return (AUDIO_FAILURE);
			} else {
				/*
				 * this time, we use one BD entry with empty
				 * buffer next time we shut down, if no sound
				 * again
				 */
				statep->flags |= I810_DMA_PLAY_EMPTY;
			}
		} else {
			/* we got at least one sample */
			statep->flags &= ~I810_DMA_PLAY_EMPTY;
			(void) ddi_dma_sync(chunk->dma_handle, 0, rs << 1,
			    DDI_DMA_SYNC_FORDEV);
		}

		/* put the samples into buffer descriptor list entry */
		bdesc = &(statep->bdl_virt_pout[buf->tail]);
		bdesc->buf_base = chunk->addr_phy;
		bdesc->buf_len = (uint16_t)rs;
		bdesc->cmd_bup = 0;
		bdesc->reserved = 0;
		bdesc->cmd_ioc = 1;
		I810_BM_PUT8(I810_PCM_OUT_LVI, buf->tail);
		buf->tail++;
		buf->avail--;

		if (buf->tail >= I810_BD_NUMS) {
			buf->tail = 0;
		}
	}

	cr = I810_BM_GET8(I810_PCM_OUT_CR);

	if (!buf->io_started) {
		cr &= ~(I810_BM_CR_FEIE|I810_BM_CR_LVBIE);
		cr |= I810_BM_CR_IOCE;
		buf->io_started = B_TRUE;
	}

	/* start PCM out engine */
	cr |= I810_BM_CR_RUN;
	I810_BM_PUT8(I810_PCM_OUT_CR, cr);

	return (AUDIO_SUCCESS);

}	/* audio810_fill_play_buf() */

/*
 * audio810_prepare_record_buf()
 *
 * Description:
 *	This routine is called by audio810_ad_start_record(). It prepares DMA
 *	memory for PCM in engine, sets the buffer descriptor entries for PCM
 *	in engine, and starts PCM in engine for recording.
 *
 * Arguments:
 *	audio810_state_t	*statep		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Started PCM in  engine successfully
 *	AUDIO_FAILURE		Failed to start PCM in engine.
 *
 */
static int
audio810_prepare_record_buf(audio810_state_t *statep)
{
	i810_bdlist_chunk_t	*chunk;
	i810_sample_buf_t	*buf;
	i810_bd_entry_t		*bdesc;
	int			samples;
	uint8_t			cr;

	buf = &statep->record_buf;

	if (!buf->io_started) {
		/* pause PCM in DMA engine */
		I810_BM_PUT8(I810_PCM_IN_CR, I810_BM_CR_PAUSE);

		/* reset PCM in DMA engine */
		I810_BM_PUT8(I810_PCM_IN_CR, I810_BM_CR_RST |I810_BM_CR_IOCE);

		/* set last valid index to 0 */
		I810_BM_PUT8(I810_PCM_IN_LVI, 0);

		/* buffer base */
		I810_BM_PUT32(I810_PCM_IN_BD_BASE, statep->bdl_phys_pin);
		buf->head = 0;
		buf->tail = 0;
		buf->avail = 2;
	}

	if (buf->avail == 0) {
		return (AUDIO_SUCCESS);
	}

	samples = statep->i810_csample_rate * statep->i810_cchannels /
	    statep->ad_info.ad_record.ad_int_rate;

	/* if not an even number of samples we panic! */
	if ((samples & 1) != 0) {
		samples++;
	}

	statep->i810_csamples = samples;
	while (buf->avail > 0) {
		chunk = &buf->chunk[buf->tail & 1];
		bdesc = &(statep->bdl_virt_pin[buf->tail]);
		bdesc->buf_len = (uint16_t)samples;
		bdesc->cmd_bup = 0;
		bdesc->reserved = 0;
		bdesc->cmd_ioc = 1;
		bdesc->buf_base = chunk->addr_phy;
		I810_BM_PUT8(I810_PCM_IN_LVI, buf->tail);
		buf->tail++;
		buf->avail--;
		if (buf->tail >= I810_BD_NUMS) {
			buf->tail = 0;
		}
	}
	cr = I810_BM_GET8(I810_PCM_IN_CR);

	if (!buf->io_started) {
		cr &= ~(I810_BM_CR_FEIE|I810_BM_CR_LVBIE);
		cr |= I810_BM_CR_IOCE;
		buf->io_started = B_TRUE;
	}

	if (buf->avail < 2) {
		cr |= I810_BM_CR_RUN;
	}

	I810_BM_PUT8(I810_PCM_IN_CR, cr);
	cr = I810_BM_GET8(I810_PCM_IN_CR);

	if ((cr & (I810_BM_CR_RUN | I810_BM_CR_IOCE)) !=
	    (I810_BM_CR_RUN | I810_BM_CR_IOCE)) {
		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audio810_prepare_record_buf() */

/*
 * audio810_reclaim_record_buf()
 *
 * Description:
 *	This routine is called by the interrupt handler. It sends the PCM
 *	samples (record data) up to the mixer module by calling am_send_audio(),
 *	and reclaims the buffer descriptor entries for PCM in engine.
 *
 * Arguments:
 *	audio810_state_t	*statep		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio810_reclaim_record_buf(audio810_state_t *statep)
{
	i810_bdlist_chunk_t 	*chunk;
	i810_sample_buf_t	*buf;
	int16_t		bmciv;
	int		samples;

	buf = &statep->record_buf;
	bmciv = I810_BM_GET8(I810_PCM_IN_CIV);
	samples = statep->i810_csamples;

	while ((buf->head != bmciv) && (buf->avail < 2)) {
		chunk = &buf->chunk[buf->head & 1];
		(void) ddi_dma_sync(chunk->dma_handle, 0,
		    chunk->real_len, DDI_DMA_SYNC_FORCPU);
		mutex_exit(&statep->inst_lock);
		am_send_audio(statep->audio_handle, chunk->data_buf,
		    AUDIO_NO_CHANNEL, samples);
		mutex_enter(&statep->inst_lock);
		buf->avail++;
		buf->head++;

		if (buf->head >= I810_BD_NUMS) {
			buf->head = 0;
		}
		if ((statep->flags & I810_DMA_RECD_STARTED) == 0) {
			break;
		}
	}

}	/* audio810_reclaim_record_buf() */
