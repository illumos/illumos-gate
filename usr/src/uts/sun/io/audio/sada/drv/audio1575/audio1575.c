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
 * audio1575 Audio Driver
 *
 * The driver is primarily targeted at providing audio support for
 * those sparc systems which use the Uli M1575 audio core
 * and the Analog Devices AD1981 codec.
 *
 * This driver uses the mixer Audio Personality Module to implement
 * audio(7I) and mixer(7I) semantics. Both play and record are single
 * streaming.
 *
 * The M1575 audio core, in AC'97 controller mode, has independent
 * channels for PCM in, PCM out, mic in, modem in, and modem out.
 *
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
 * the process is reversed. So we define the struct, m1575_sample_buf,
 * to handle the BD. The software uses the head, tail and avail fields of
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
 * We allocate N blocks of DMA memory, say A and B, for every DMA
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
 * we use this saved state to restore codec's state in audio1575_chip_init()
 *
 * TODO: System power management is not yet supported by the driver.
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
#include <sys/audio/impl/audio1575_impl.h>
#include <sys/audio/audio1575.h>
#include <sys/cpuvar.h>

/*
 * Module linkage routines for the kernel
 */
static int audio1575_getinfo(dev_info_t *, ddi_info_cmd_t, void*, void**);
static int audio1575_attach(dev_info_t *, ddi_attach_cmd_t);
static int audio1575_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Entry point routine prototypes
 */
static int audio1575_ad_set_config(audiohdl_t, int, int, int, int, int);
static int audio1575_ad_set_format(audiohdl_t, int, int, int, int, int, int);
static int audio1575_ad_start_play(audiohdl_t, int);
static void audio1575_ad_pause_play(audiohdl_t, int);
static void audio1575_ad_stop_play(audiohdl_t, int);
static int audio1575_ad_start_record(audiohdl_t, int);
static void audio1575_ad_stop_record(audiohdl_t, int);

/*
 * interrupt handler
 */
static uint_t	audio1575_intr(caddr_t);

/*
 * Local Routine Prototypes
 */
static int audio1575_init_ac97(audio1575_state_t *, int);
static int audio1575_reset_ac97(audio1575_state_t *);
static int audio1575_codec_sync(audio1575_state_t *);
static int audio1575_write_ac97(audio1575_state_t *, int, uint16_t);
static int audio1575_read_ac97(audio1575_state_t *, int, uint16_t *);
static int audio1575_and_ac97(audio1575_state_t *, int, uint16_t);
static int audio1575_or_ac97(audio1575_state_t *, int, uint16_t);
static int audio1575_chip_init(audio1575_state_t *, int);
static int audio1575_init_state(audio1575_state_t *, dev_info_t *);
static int audio1575_map_regs(dev_info_t *, audio1575_state_t *);
static void audio1575_unmap_regs(audio1575_state_t *);
static int audio1575_alloc_sample_buf(audio1575_state_t *, int, int);
static void audio1575_free_sample_buf(audio1575_state_t *, int);
static void audio1575_dma_stop(audio1575_state_t *);
static int audio1575_fill_play_buf(audio1575_state_t *);
static void audio1575_reclaim_play_buf(audio1575_state_t *);
static int audio1575_prepare_record_buf(audio1575_state_t *);
static void audio1575_reclaim_record_buf(audio1575_state_t *);
static int audio1575_set_gain(audio1575_state_t *, int, int, int);
static int audio1575_set_port(audio1575_state_t *, int, int);
static int audio1575_set_monitor_gain(audio1575_state_t *, int);
static void audio1575_pci_enable(audio1575_state_t *);
static void audio1575_pci_disable(audio1575_state_t *);
static int audio1575_dma_pause(audio1575_state_t *, int);
static int audio1575_dma_resume(audio1575_state_t *, int);
static int audio1575_dma_reset(audio1575_state_t *, int);

/*
 * Global variables, but used only by this file.
 */

/* anchor for soft state structures */
static void	*audio1575_statep;

/* driver name, so we don't have to call ddi_driver_name() or hard code strs */
static char	*audio1575_name = M1575_NAME;

/*
 * STREAMS structures
 */

/* STREAMS driver id and limit value struct */
static struct module_info audio1575_modinfo = {
	M1575_IDNUM,		/* module ID number */
	M1575_NAME,		/* module name */
	M1575_MINPACKET,	/* minimum packet size */
	M1575_MAXPACKET,	/* maximum packet size */
	M1575_HIWATER,		/* high water mark */
	M1575_LOWATER,		/* low water mark */
};

/* STREAMS queue processing procedures structures */
/* read queue */
static struct qinit audio1575_rqueue = {
	audio_sup_rput,		/* put procedure */
	audio_sup_rsvc,		/* service procedure */
	audio_sup_open,		/* open procedure */
	audio_sup_close,	/* close procedure */
	NULL,			/* unused */
	&audio1575_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* write queue */
static struct qinit audio1575_wqueue = {
	audio_sup_wput,		/* write procedure */
	audio_sup_wsvc,		/* service procedure */
	NULL,			/* open procedure */
	NULL,			/* close procedure */
	NULL,			/* unused */
	&audio1575_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* STREAMS entity declaration structure */
static struct streamtab audio1575_str_info = {
	&audio1575_rqueue,	/* read queue */
	&audio1575_wqueue,	/* write queue */
	NULL,			/* mux lower read queue */
	NULL,			/* mux lower write queue */
};

/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops audio1575_cb_ops = {
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
	&audio1575_str_info,	/* cb_str */
	D_NEW | D_MP | D_64BIT, /* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

/* Device operations structure */
static struct dev_ops audio1575_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	audio1575_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audio1575_attach,	/* devo_attach */
	audio1575_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&audio1575_cb_ops,	/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv audio1575_modldrv = {
	&mod_driverops,		/* drv_modops */
	M1575_MOD_NAME,		/* drv_linkinfo */
	&audio1575_dev_ops,	/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage audio1575_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&audio1575_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};

static uint_t audio1575_mixer_srs[] = {
	M1575_SAMPR5510,
	M1575_SAMPR48000,
	0
};

static uint_t audio1575_compat_srs [] = {
	M1575_SAMPR8000, M1575_SAMPR9600, M1575_SAMPR11025,
	M1575_SAMPR16000, M1575_SAMPR18900, M1575_SAMPR22050,
	M1575_SAMPR27420, M1575_SAMPR32000, M1575_SAMPR33075,
	M1575_SAMPR37800, M1575_SAMPR44100, M1575_SAMPR48000,
	0
};

static am_ad_sample_rates_t audio1575_mixer_sample_rates = {
	MIXER_SRS_FLAG_SR_LIMITS,
	audio1575_mixer_srs
};

static am_ad_sample_rates_t audio1575_compat_sample_rates = {
	MIXER_SRS_FLAG_SR_NOT_LIMITS,
	audio1575_compat_srs
};

static uint_t audio1575_channels[] = {
	AUDIO_CHANNELS_STEREO,
	0
};

static am_ad_cap_comb_t audio1575_combinations[] = {
	{ AUDIO_PRECISION_16, AUDIO_ENCODING_LINEAR },
	{ 0 }
};

/* AD1981B Equalization Biquad IIR Filter coefficient address table */
static m1575_biquad_t filters[] = {
	{0x1b, 0x0f}, {0x1a, 0x00}, {0x19, 0x00}, {0x1d, 0x00}, {0x1c, 0x00},
	{0x20, 0x0f}, {0x1f, 0x00}, {0x1e, 0x00}, {0x22, 0x00}, {0x21, 0x00},
	{0x25, 0x0f}, {0x24, 0x00}, {0x23, 0x00}, {0x27, 0x00}, {0x26, 0x00},
	{0x2a, 0x0f}, {0x29, 0x00}, {0x28, 0x00}, {0x2c, 0x00}, {0x2b, 0x00},
	{0x2f, 0x0f}, {0x2e, 0x00}, {0x2d, 0x00}, {0x31, 0x00}, {0x30, 0x00},
	{0x34, 0x0f}, {0x33, 0x00}, {0x32, 0x00}, {0x36, 0x00}, {0x35, 0x00},
	{0x39, 0x0f}, {0x38, 0x00}, {0x37, 0x00}, {0x3b, 0x00}, {0x3a, 0x00},
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
static ddi_dma_attr_t bdlist_dma_attr = {
	DMA_ATTR_V0,	/* version */
	0x0000000000000000LL,		/* dlim_addr_lo */
	0x00000000ffffffffLL,		/* dlim_addr_hi */
	0x000000000000ffffLL,		/* DMA counter register - 64 bits */
	0x0000000000000008LL,		/* DMA address align must be 8-bytes */
	0x0000003c,			/* 1 through 64 byte burst sizes */
	0x00000008,			/* min xfer DMA size BDList entry */
	0x00000000000ffffLL,		/* max xfer size, 64K */
	0x000000000001fffLL,		/* seg, set to PAGESIZE */
	0x00000001,			/* s/g list length, no s/g */
	0x00000008,			/* granularity of device minxfer */
	0				/* DMA flags use virtual address */
};

/*
 * DMA attributes of buffers to be used to receive/send audio data
 */
static ddi_dma_attr_t	sample_buf_dma_attr = {
	DMA_ATTR_V0,
	0x0000000000000000LL,		/* dlim_addr_lo */
	0x00000000ffffffffLL,		/* dlim_addr_hi */
	0x000000000001fffeLL,		/* DMA counter register - 16 bits */
	0x0000000000000002LL,		/* DMA address align 2-byte boundary */
	0x0000003c,			/* 1 through 60 byte burst sizes */
	0x00000004,			/* min xfer DMA size BDList entry */
	0x000000000001ffffLL,		/* max xfer size, 64K */
	0x000000000001ffffLL,		/* seg, set to 64K */
	0x00000001,			/* s/g list length, no s/g */
	0x00000004,			/* granularity of device minxfer */
	0				/* DMA flags use virtual address */
};

static am_ad_entry_t audio1575_entry = {
	NULL,				/* ad_setup() */
	NULL,				/* ad_teardown() */
	audio1575_ad_set_config,	/* ad_set_config() */
	audio1575_ad_set_format,	/* ad_set_format() */
	audio1575_ad_start_play,	/* ad_start_play() */
	audio1575_ad_pause_play,	/* ad_pause_play() */
	audio1575_ad_stop_play,		/* ad_stop_play() */
	audio1575_ad_start_record,	/* ad_start_record() */
	audio1575_ad_stop_record,	/* ad_stop_record() */
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

	ATRACE("audio1575 _init() entering", NULL);

	if ((error = ddi_soft_state_init(&audio1575_statep,
	    sizeof (audio1575_state_t), 1)) != 0) {
		ATRACE("audio1575 ddi_soft_state_init() failure",
		    error);

		return (error);
	}

	if ((error = mod_install(&audio1575_modlinkage)) != 0) {
		ddi_soft_state_fini(&audio1575_statep);
	}

	ATRACE("audio1575 _init() returning", error);

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

	ATRACE("audio1575 _fini() entering", audio1575_statep);

	if ((error = mod_remove(&audio1575_modlinkage)) != 0) {

		return (error);
	}

	ddi_soft_state_fini(&audio1575_statep);

	ATRACE("audio1575 _fini() returning", error);

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

	ATRACE("audio1575 _info() entering", NULL);

	error = mod_info(&audio1575_modlinkage, modinfop);

	ATRACE("audio1575 _info() returning", error);

	return (error);

}	/* _info() */


/* ******************* Driver Entry Points ********************************* */

/*
 * audio1575_getinfo()
 */
static int
audio1575_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	audio1575_state_t	*statep;
	int 			instance;
	int 			error = DDI_FAILURE;

	ATRACE("audio1575_getinfo() entering", dip);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = audio_sup_devt_to_instance((dev_t)arg);
		if ((statep = ddi_get_soft_state(audio1575_statep,
		    instance)) != NULL) {
			*result = statep->m1575_dip;
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

	ATRACE("audio1575_getinfo() returning", error);

	return (error);

}	/* audio1575_getinfo() */

/*
 * audio1575_attach()
 *
 * Description:
 *	Attach an instance of the audio1575 driver. This routine does the
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
audio1575_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audio1575_state_t	*statep;
	uint32_t		intrsr;
	uint32_t		intrcr;
	int 			instance;
	audio_sup_reg_data_t	data;

	ATRACE("audio1575_attach() entering", dip);

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		ATRACE("audio1575_attach() DDI_ATTACH", NULL);
		break;
	case DDI_RESUME:
		ATRACE("audio1575_attach() DDI_RESUME", NULL);

		/* we've already allocated the state structure so get ptr */
		if ((statep = ddi_get_soft_state(audio1575_statep, instance)) ==
		    NULL) {
			audio_sup_log(NULL, CE_WARN,
			    "!%s%d: attach() RESUME get soft state failure",
			    audio1575_name, instance);

			return (DDI_FAILURE);
		}

		ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

		mutex_enter(&statep->m1575_intr_mutex);

		ASSERT((statep->m1575_flags & M1575_DMA_SUSPENDED) ==
		    M1575_DMA_SUSPENDED);

		statep->m1575_flags &= ~M1575_DMA_SUSPENDED;

		mutex_exit(&statep->m1575_intr_mutex);

		/*
		 * Restore the audio1575 chip's state and
		 * put the DMA Engines in a known state
		 */
		if ((audio1575_chip_init(statep, M1575_INIT_RESTORE)) ==
		    AUDIO_FAILURE) {
			ATRACE("audio1575_attach()chip init failure",
			    DDI_FAILURE);

			return (DDI_FAILURE);
		}

		/*
		 * Start playing and recording, if not needed they'll stop
		 * on their own. But, we don't start them if the hardware has
		 * failed.
		 */
		if (audio_sup_restore_state(statep->m1575_ahandle,
		    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(statep->m1575_ahandle, CE_WARN,
			    "!attach() audio restart failure");
		}

		ATRACE("audio1575_attach() DDI_RESUME done", NULL);

		ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

		return (DDI_SUCCESS);

	default:
		ATRACE("audio1575_attach() unknown command", cmd);
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() unknown command: 0x%x",
		    audio1575_name, instance, cmd);

		return (DDI_FAILURE);
	}

	/* allocate the soft state structure */
	if (ddi_soft_state_zalloc(audio1575_statep, instance) != DDI_SUCCESS) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() soft state allocate failure",
		    audio1575_name, instance);
		goto error_state;
	}

	/* get the state structure */
	if ((statep = ddi_get_soft_state(audio1575_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() ddi_get_soft_state() failure",
		    audio1575_name, instance);
		goto error_state;
	}

	statep->m1575_inst = instance;

	/* call audiosup module registration routine */
	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;

	/* register the driver with the audio support module */
	if ((statep->m1575_ahandle = audio_sup_register(dip, &data)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: attach() audio_sup_register() failure",
		    audio1575_name, instance);
		goto error_state;
	}

	/* map in the audio registers */
	if (audio1575_map_regs(dip, statep) != AUDIO_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!attach() couldn't map registers");
		goto error_audiosup;
	}

	/* Enable PCI I/O and Memory Spaces */
	audio1575_pci_enable(statep);

	/*
	 * clear the interrupt control and status register
	 * READ/WRITE/READ workaround required
	 * for buggy hardware
	 */

	intrcr = 0L;
	M1575_AM_PUT32(M1575_INTRCR_REG, intrcr);
	intrcr = M1575_AM_GET32(M1575_INTRCR_REG);

	intrsr = M1575_AM_GET32(M1575_INTRSR_REG);
	M1575_AM_PUT32(M1575_INTRSR_REG, (intrsr & M1575_INTR_MASK));
	intrsr = M1575_AM_GET32(M1575_INTRSR_REG);

	/* initialize the audio state structures */
	if ((audio1575_init_state(statep, dip)) != AUDIO_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!attach() init state structure failure");
		goto error_pci_disable;
	}

	/* from here on, must destroy the mutex on error */
	mutex_init(&statep->m1575_intr_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(statep->m1575_intr_pri));

	/* allocate play and record sample buffers */
	if ((audio1575_alloc_sample_buf(statep, M1575_DMA_PCM_OUT,
	    statep->m1575_play_buf_size) == AUDIO_FAILURE) ||
	    (audio1575_alloc_sample_buf(statep, M1575_DMA_PCM_IN,
	    statep->m1575_record_buf_size) == AUDIO_FAILURE)) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!attach() couldn't alloc sample buffers");
		goto error_destroy;
	}

	/* initialize audio controller and AC97 codec */
	if (audio1575_chip_init(statep, M1575_INIT_NO_RESTORE) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle,  CE_WARN,
		    "!attach() failure to init chip");
		goto error_dealloc;
	}

	/* save private state */
	audio_sup_set_private(statep->m1575_ahandle, statep);

	/* call the mixer attach() routine */
	if (am_attach(statep->m1575_ahandle, cmd, &statep->m1575_ad_info) !=
	    AUDIO_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!attach() am_attach() failure");
		goto error_dealloc;
	}

	/* set up kernel statistics */
	if ((statep->m1575_ksp = kstat_create(M1575_NAME, instance,
	    M1575_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->m1575_ksp);
	}

	/* now add our interrupt handler */
	if (ddi_intr_add_handler(statep->m1575_h_table[0],
	    (ddi_intr_handler_t *)audio1575_intr, (caddr_t)statep, NULL)) {
		audio_sup_log(statep->m1575_ahandle,
		    CE_WARN, "!attach() ddi_intr_add_handler() failure");
		ATRACE("audio1575_attach() ddi_intr_add_handler() failure",
		    NULL);
		goto error_kstat;
	}

	/* Enable PCI Interrupts */
	M1575_PCI_PUT8(M1575_PCIMISC_REG, M1575_PCIMISC_INTENB);

	/* enable audio interrupts */
	if (ddi_intr_enable(statep->m1575_h_table[0]) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!attach() - ddi_intr_enable() failure");
		ATRACE("audio1575_attach() ddi_add_intr failure", NULL);
		goto error_intr_enable;
	}

	/* everything worked out, so report the device */
	ddi_report_dev(dip);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	ATRACE("audio1575_attach() returning DDI_SUCCESS", NULL);

	return (DDI_SUCCESS);

error_intr_enable:
	ATRACE("audio1575_attach() error_intr_enable", NULL)
	/* Disable PCI Interrupts */
	M1575_PCI_PUT8(M1575_PCIMISC_REG, 0);
	(void) ddi_intr_remove_handler(statep->m1575_h_table[0]);

error_kstat:
	ATRACE("audio1575_attach() error_kstat", NULL);
	if (statep->m1575_ksp) {
		kstat_delete(statep->m1575_ksp);
	}

	(void) am_detach(statep->m1575_ahandle, DDI_DETACH);

error_dealloc:
	ATRACE("audio1575_attach() error_dealloc", NULL);
	audio1575_free_sample_buf(statep, M1575_DMA_PCM_IN);
	audio1575_free_sample_buf(statep, M1575_DMA_PCM_OUT);

error_destroy:
	ATRACE("audio1575_attach() error_destroy", statep);
	(void) ddi_intr_free(statep->m1575_h_table[0]);
	kmem_free(statep->m1575_h_table, sizeof (ddi_intr_handle_t));
	mutex_destroy(&statep->m1575_intr_mutex);

error_pci_disable:
	ATRACE("audio1575_attach() error_pci_disable", NULL)
	audio1575_pci_disable(statep);

error_unmap:
	ATRACE("audio1575_attach() error_unmap", NULL);
	audio1575_unmap_regs(statep);

error_audiosup:
	ATRACE("audio1575_attach() error_audiosup", statep);
	(void) audio_sup_unregister(statep->m1575_ahandle);

error_state:
	ATRACE("audio1575_attach() error_state", statep);
	ddi_soft_state_free(audio1575_statep, instance);

	ATRACE("audio1575_attach() returning DDI_FAILURE", NULL);

	return (DDI_FAILURE);

}	/* audio1575_attach() */

/*
 * audio1575_detach()
 *
 * Description:
 *	Detach an instance of the audio1575 driver. After the Codec is detached
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
audio1575_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audio1575_state_t	*statep;
	int			instance;

	instance = ddi_get_instance(dip);

	ATRACE("audio1575_detach() entering", instance);

	if ((statep = ddi_get_soft_state(audio1575_statep, instance)) == NULL) {
		audio_sup_log(NULL, CE_WARN,
		    "!%s%d: detach() get soft state failure",
		    audio1575_name, instance);
		ATRACE("audio1575_detach() get soft state failure", instance);

		return (DDI_FAILURE);
	}

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		ATRACE("audio1575_detach() DDI_SUSPEND", NULL);

		mutex_enter(&statep->m1575_intr_mutex);

		ASSERT((statep->m1575_flags & M1575_DMA_SUSPENDED) !=
		    M1575_DMA_SUSPENDED);

		/* stop all new operations */
		statep->m1575_flags |= M1575_DMA_SUSPENDED;

		/*
		 * stop all DMA operations
		 */
		(void) audio1575_dma_stop(statep);

		/*
		 * Save the controller state. The Codec's state is
		 * already in codec_shadow[].
		 */
		if (audio_sup_save_state(statep->m1575_ahandle,
		    AUDIO_ALL_DEVICES, AUDIO_BOTH) == AUDIO_FAILURE) {
			audio_sup_log(statep->m1575_ahandle, CE_WARN,
			    "!detach() audio save failure");
		}

		mutex_exit(&statep->m1575_intr_mutex);

		ATRACE("audio1575_detach() SUSPEND successful", statep);

		ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

		return (DDI_SUCCESS);

	default:
		ATRACE("audio1575_detach() unknown command", cmd);

		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!%s%d: detach() unknown command: 0x%x",
		    audio1575_name, instance, cmd);

		return (DDI_FAILURE);
	}

	/* stop DMA engines */
	mutex_enter(&statep->m1575_intr_mutex);
	audio1575_dma_stop(statep);
	mutex_exit(&statep->m1575_intr_mutex);

	/* disable interrupts */
	(void) ddi_intr_disable(statep->m1575_h_table[0]);

	/* Remove the interrupt handler */
	(void) ddi_intr_remove_handler(statep->m1575_h_table[0]);

	mutex_enter(&statep->m1575_intr_mutex);

	/* reset the AD1981B codec */
	M1575_AM_PUT32(M1575_SCR_REG, M1575_SCR_COLDRST);

	/* turn off the AC_LINK clock */
	M1575_PCI_PUT8(M1575_PCIACD_REG, 0);
	M1575_PCI_PUT8(M1575_PCIACD_REG, 4);
	M1575_PCI_PUT8(M1575_PCIACD_REG, 0);

	mutex_exit(&statep->m1575_intr_mutex);

	/* detach audio mixer */
	(void) am_detach(statep->m1575_ahandle, cmd);

	/*
	 * call the audio support module's detach routine to remove this
	 * driver completely from the audio driver architecture.
	 */
	(void) audio_sup_unregister(statep->m1575_ahandle);

	/* free the interrupt handle */
	(void) ddi_intr_free(statep->m1575_h_table[0]);

	/* free memory */
	kmem_free(statep->m1575_h_table, sizeof (ddi_intr_handle_t));

	/* free DMA memory */
	audio1575_free_sample_buf(statep, M1575_DMA_PCM_IN);
	audio1575_free_sample_buf(statep, M1575_DMA_PCM_OUT);

	/* free the kernel statistics structure */
	if (statep->m1575_ksp) {
		kstat_delete(statep->m1575_ksp);
	}

	/* Disable PCI I/O and Memory Spaces */
	audio1575_pci_disable(statep);

	/* unmap the registers */
	audio1575_unmap_regs(statep);

	/* destroy the state mutex */
	mutex_destroy(&statep->m1575_intr_mutex);

	/* free the memory for the state pointer */
	ddi_soft_state_free(audio1575_statep, instance);

	ATRACE("audio1575_detach() returning success", NULL);

	return (DDI_SUCCESS);

}	/* audio1575_detach */

/*
 * audio1575_intr()
 *
 * Description:
 *	Interrupt service routine for both play and record. For play we
 *	get the next buffers worth of audio. For record we send it on to
 *	the mixer.
 *
 *	Each of buffer descriptor has a field IOC(interrupt on completion)
 *	When both this and the IOC bit of correspondent dma control register
 *	is set, it means that the controller should issue an interrupt upon
 *	completion of this buffer. Note that in the clearing of the interrupts
 *	below that the PCM IN and PCM out interrupts ar cleared by their
 *	respective control registers and not by writing a '1' to the INTRSR
 *	the interrupt status register. Only CPRINTR,SPINTR,and GPIOINTR
 *	require a '1' written to the INTRSR register to clear those
 *	interrupts. See comments below.
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
audio1575_intr(caddr_t arg)
{
	audio1575_state_t	*statep = (audio1575_state_t *)arg;
	uint32_t		intrsr;
	uint16_t		sr;

	ATRACE("in audio1575_intr()", statep);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	mutex_enter(&statep->m1575_intr_mutex);

	intrsr = M1575_AM_GET32(M1575_INTRSR_REG);

	/* check if device is interrupting */
	if (intrsr == 0) {
		if (statep->m1575_ksp) {
			/* increment the spurious ino5 interrupt cnt */
			M1575_KIOP(statep)->intrs[KSTAT_INTR_SPURIOUS]++;
		}

		mutex_exit(&statep->m1575_intr_mutex);

		ATRACE("audio1575_intr() not our interrupt", intrsr);

		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * The Uli M1575 generates an interrupt for each interrupt
	 * type. therefore we only process one interrupt type
	 * per invocation of the audio1575_intr() routine.
	 * WARNING: DO NOT attempt to optimize this by looping
	 * until the INTRSR register is clear as this will
	 * generate spurious ino5 interrupts.
	 */
	if (intrsr & M1575_INTRSR_PCMIINTR) {
		/* Clear PCM IN interrupt */
		ATRACE("audio1575_intr() PCMIINTR", intrsr);
		sr = M1575_AM_GET16(M1575_PCMISR_REG);
		M1575_AM_PUT16(M1575_PCMISR_REG, sr & M1575_STATUS_CLR);
		/*
		 * Note: This interrupt is not cleared by writing a '1'
		 * to the M1575_INTRSR_REG according to the M1575 Super I/O
		 * data sheet on page 189.
		 */

		if (statep->m1575_flags & M1575_DMA_RECD_STARTED) {
			audio1575_reclaim_record_buf(statep);
			(void) audio1575_prepare_record_buf(statep);
		}
	} else if (intrsr & M1575_INTRSR_PCMOINTR) {
		/* Clear PCM OUT interrupt */
		ATRACE("audio1575_intr() PCMOINTR", intrsr);
		sr = M1575_AM_GET16(M1575_PCMOSR_REG);
		M1575_AM_PUT16(M1575_PCMOSR_REG, sr & M1575_STATUS_CLR);
		/*
		 * Note: This interrupt is not cleared by writing a '1'
		 * to the M1575_INTRSR_REG according to the M1575 Super I/O
		 * data sheet on page 189.
		 */

		if (statep->m1575_flags & M1575_DMA_PLAY_STARTED) {
			audio1575_reclaim_play_buf(statep);
			(void) audio1575_fill_play_buf(statep);
		}
	} else if (intrsr & M1575_INTRSR_SPRINTR) {
		/* Clear Status Register Available Interrupt */
		ATRACE("audio1575_intr() SPRINTR", intrsr);
		M1575_AM_PUT32(M1575_INTRSR_REG, M1575_INTRSR_SPRINTR);

	} else if (intrsr & M1575_INTRSR_CPRINTR) {
		/* Clear Command Register Available Interrupt */
		ATRACE("audio1575_intr() CPRINTR", intrsr);
		M1575_AM_PUT32(M1575_INTRSR_REG, M1575_INTRSR_CPRINTR);
	} else if (intrsr & M1575_INTRSR_GPIOINTR) {
		/* Clear General Purpose I/O Register Interrupt */
		ATRACE("audio1575_intr() GPIOINTR", intrsr);
		M1575_AM_PUT32(M1575_INTRSR_REG, M1575_INTRSR_GPIOINTR);
	} else {
		/* Clear Unknown Interrupt */
		ATRACE("audio1575_intr() Unknown Interrupt", intrsr);
		M1575_AM_PUT32(M1575_INTRSR_REG, (intrsr & M1575_INTR_MASK));
	}

	/* update the kernel interrupt statistics */
	if (statep->m1575_ksp) {
		M1575_KIOP(statep)->intrs[KSTAT_INTR_HARD]++;
	}

	mutex_exit(&statep->m1575_intr_mutex);

	ATRACE("audio1575_intr() done", statep);

	return (DDI_INTR_CLAIMED);

}	/* audio1575_intr() */


/* *********************** Mixer Entry Point Routines ******************* */

/*
 * audio1575_ad_set_config()
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
audio1575_ad_set_config(audiohdl_t ahandle, int stream, int command,
    int dir, int arg1, int arg2)
{
	audio1575_state_t	*statep;
	int 			rc = AUDIO_FAILURE;

	ATRACE("audio1575_ad_set_config() entering", stream);
	ATRACE("audio1575_ad_set_config() command", command);
	ATRACE("audio1575_ad_set_config() dir", dir);
	ATRACE("audio1575_ad_set_config() arg1", arg1);
	ATRACE("audio1575_ad_set_config() arg2", arg2);

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	mutex_enter(&statep->m1575_intr_mutex);

	/*
	 * CAUTION: From here on we must goto done to exit.
	 */
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
		rc = audio1575_set_gain(statep, dir, arg1, arg2);
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
		rc = audio1575_set_port(statep, dir, arg1);
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
		rc = audio1575_set_monitor_gain(statep, arg1);
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
			(void) audio1575_or_ac97(statep,
			    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE);
			(void) audio1575_or_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER, HPVR_MUTE);
			(void) audio1575_or_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MMVR_MUTE);
			rc = AUDIO_SUCCESS;
		} else {	/* not muted */
			/* by setting the port we unmute only active ports */
			rc = audio1575_set_port(statep,
			    AUDIO_PLAY, statep->m1575_output_port);
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
			(void) audio1575_or_ac97(statep,
			    AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
			statep->m1575_ad_info.ad_add_mode |=
			    AM_ADD_MODE_MIC_BOOST;
		} else {	/* disable */
			(void) audio1575_and_ac97(statep,
			    AC97_MIC_VOLUME_REGISTER,
			    (uint16_t)~MICVR_20dB_BOOST);
			statep->m1575_ad_info.ad_add_mode &=
			    ~AM_ADD_MODE_MIC_BOOST;
		}

		rc = AUDIO_SUCCESS;
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
		ATRACE("audio1575_ad_set_config() unsupported cmd", command);
		break;
	}

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ATRACE("audio1575_ad_set_config() returning", rc);

	return (rc);

}	/* audio1575_ad_set_config() */

/*
 * audio1575_ad_set_format()
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
audio1575_ad_set_format(audiohdl_t ahandle, int stream, int dir,
    int sample_rate, int channels, int precision, int encoding)
{
	audio1575_state_t	*statep;
	int			rc = AUDIO_FAILURE;

	ASSERT(precision == AUDIO_PRECISION_16);
	ASSERT(channels == AUDIO_CHANNELS_STEREO);

	ATRACE("audio1575_ad_set_format() entering", stream);
	ATRACE("audio1575_ad_set_format() dir", dir);
	ATRACE("audio1575_ad_set_format() sample_rate", sample_rate);
	ATRACE("audio1575_ad_set_format() channels", channels);
	ATRACE("audio1575_ad_set_format() precision", precision);
	ATRACE("audio1575_ad_set_format() encoding", encoding);

	if (encoding != AUDIO_ENCODING_LINEAR) {
		ATRACE("audio1575_ad_set_format() bad encoding", encoding);
		return (rc);
	}

	/* get the soft state structure */
	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));
	mutex_enter(&statep->m1575_intr_mutex);

	switch (sample_rate) {
	case M1575_SAMPR8000:
	case M1575_SAMPR9600:
	case M1575_SAMPR11025:
	case M1575_SAMPR16000:
	case M1575_SAMPR18900:
	case M1575_SAMPR22050:
	case M1575_SAMPR27420:
	case M1575_SAMPR32000:
	case M1575_SAMPR33075:
	case M1575_SAMPR37800:
	case M1575_SAMPR44100:
	case M1575_SAMPR48000:
		rc = AUDIO_SUCCESS;
		break;

	default:
		ATRACE("audio1575_ad_set_format() bad sample rate",
		    sample_rate);
		goto done;
	}

	switch (dir) {
	case AUDIO_PLAY:
		rc = audio1575_write_ac97(statep,
		    AC97_EXTENDED_FRONT_DAC_RATE_REGISTER, sample_rate);
		statep->m1575_psample_rate = sample_rate;
		statep->m1575_pchannels = channels;
		statep->m1575_pprecision = precision;
		break;

	case AUDIO_RECORD:
		rc = audio1575_write_ac97(statep,
		    AC97_EXTENDED_LR_DAC_RATE_REGISTER, sample_rate);
		statep->m1575_csample_rate = sample_rate;
		statep->m1575_cchannels = channels;
		statep->m1575_cprecision = precision;
		break;

	default:
		rc = AUDIO_FAILURE;
		ATRACE("audio1575_set_format() bad audio dir", dir);
		break;
	}

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ATRACE("audio1575_ad_set_format() returning", rc);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	return (rc);

}	/* audio1575_ad_set_format() */

/*
 * audio1575_ad_start_play()
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
audio1575_ad_start_play(audiohdl_t ahandle, int stream)
{
	audio1575_state_t	*statep;
	m1575_sample_buf_t	*buf;
	uint8_t			pcmocr;
	int			rc = AUDIO_FAILURE;

	ATRACE("audio1575_ad_start_play() stream", stream);

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));
	mutex_enter(&statep->m1575_intr_mutex);

	/* get ptr to play buffer */
	buf = &statep->m1575_play_buf;

	/* we are already PLAYING audio */
	if (statep->m1575_flags & M1575_DMA_PLAY_STARTED) {
		rc = AUDIO_SUCCESS;
		goto done;
	}

	/* If play was PAUSED then Start Playing */
	if (statep->m1575_flags & M1575_DMA_PLAY_PAUSED) {
		if ((audio1575_dma_resume(statep, M1575_DMA_PCM_OUT)) ==
		    AUDIO_FAILURE) {
			statep->m1575_flags &= ~M1575_DMA_PLAY_STARTED;
			goto done;
		}

		statep->m1575_flags &= ~M1575_DMA_PLAY_PAUSED;
		statep->m1575_flags |= M1575_DMA_PLAY_STARTED;
		rc = AUDIO_SUCCESS;
		goto done;
	}

	/* we are here for the first time to play audio */
	if (!buf->io_started) {
		/* Prepare the DMA Engine */
		if ((audio1575_dma_pause(statep, M1575_DMA_PCM_OUT)) ==
		    AUDIO_FAILURE) {
			statep->m1575_flags &= ~M1575_DMA_PLAY_STARTED;
			goto done;
		}
		if ((audio1575_dma_reset(statep, M1575_DMA_PCM_OUT)) ==
		    AUDIO_FAILURE) {
			statep->m1575_flags &= ~M1575_DMA_PLAY_STARTED;
			goto done;
		}
		/* set last valid index to zero	*/
		M1575_AM_PUT8(M1575_PCMOLVIV_REG, 0);

		/* set the buffer base */
		M1575_AM_PUT32(M1575_PCMOBDBAR_REG,
		    statep->m1575_bdl_phys_pout);
		buf->head = 0;
		buf->tail = 0;
		buf->avail = M1575_PLAY_BUFS;

		/* Set the IOCE bit */
		pcmocr = M1575_AM_GET8(M1575_PCMOCR_REG);
		pcmocr |= M1575_PCMOCR_IOCE;
		M1575_AM_PUT8(M1575_PCMOCR_REG, pcmocr);
	}

	if ((audio1575_fill_play_buf(statep)) ==
	    AUDIO_FAILURE) {
		statep->m1575_flags &= ~M1575_DMA_PLAY_STARTED;
	} else {
		buf->io_started = B_TRUE;
		statep->m1575_flags |= M1575_DMA_PLAY_STARTED;
		rc = AUDIO_SUCCESS;
	}

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	ATRACE("audio1575_ad_start_play() returning", rc);

	return (rc);

}	/* audio1575_ad_start_play() */

/*
 * audio1575_ad_pause_play()
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
audio1575_ad_pause_play(audiohdl_t ahandle, int stream)
{
	audio1575_state_t	*statep;
	uint32_t		dmacr;

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	ATRACE("audio1575_ad_pause_play() entering", ahandle);
	ATRACE("audio1575_ad_pause_play() stream", stream);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));
	mutex_enter(&statep->m1575_intr_mutex);

	/* do nothing if not running */
	if ((statep->m1575_flags & M1575_DMA_PLAY_STARTED) == 0) {
		dmacr = M1575_AM_GET32(M1575_DMACR_REG);
		if ((dmacr & M1575_DMACR_PCMOSTART) !=
		    M1575_DMACR_PCMOSTART) {
			ATRACE("audio1575_pause_play() DMA engine "
			    "already stopped", statep);
			goto done;
		}
	}

	/* Stop the DMA and set DMA pause flag */
	if ((audio1575_dma_pause(statep, M1575_DMA_PCM_OUT)) ==
	    AUDIO_FAILURE) {
		statep->m1575_flags &= ~M1575_DMA_PLAY_PAUSED;
		ATRACE("audio1575_ad_pause_play() failure", NULL);
		goto done;
	}

	statep->m1575_flags &= ~M1575_DMA_PLAY_STARTED;
	statep->m1575_flags |= M1575_DMA_PLAY_PAUSED;

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ATRACE("audio1575_ad_pause_play() returning", NULL);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

}	/* audio1575_ad_pause_play() */

/*
 * audio1575_ad_stop_play()
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
audio1575_ad_stop_play(audiohdl_t ahandle, int stream)
{
	audio1575_state_t	*statep;
	m1575_sample_buf_t	*buf;

	ATRACE("audio1575_ad_stop_play() entering", ahandle);
	ATRACE("audio1575_ad_stop_play() stream", stream);

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));
	mutex_enter(&statep->m1575_intr_mutex);

	/* reset the DMA Play engine */
	if ((audio1575_dma_reset(statep, M1575_DMA_PCM_OUT)) ==
	    AUDIO_FAILURE) {
		ATRACE("audio1575_ad_stop_play() failure", NULL);
		goto done;
	}

	/* Clear the PCM Out Control Register */
	M1575_AM_PUT8(M1575_PCMOCR_REG, 0);

	/* clear the play started and paused flags */
	buf = &statep->m1575_play_buf;
	buf->io_started = B_FALSE;
	statep->m1575_flags &= ~(M1575_DMA_PLAY_STARTED | \
	    M1575_DMA_PLAY_PAUSED | M1575_DMA_PLAY_EMPTY);

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	ATRACE("audio1575_ad_stop_play() returning", NULL);

}	/* audio1575_ad_stop_play() */

/*
 * audio1575_ad_start_record()
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
audio1575_ad_start_record(audiohdl_t ahandle, int stream)
{
	audio1575_state_t	*statep;
	m1575_sample_buf_t	*buf;
	uint8_t			pcmicr;
	int			rc = AUDIO_FAILURE;

	ATRACE("audio1575_ad_start_record() entering", ahandle);
	ATRACE("audio1575_ad_start_record() stream", stream);

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));
	mutex_enter(&statep->m1575_intr_mutex);

	/* get our record buffer ptr */
	buf = &statep->m1575_record_buf;

	if (statep->m1575_flags & M1575_DMA_RECD_STARTED) {
		rc = AUDIO_SUCCESS;
		goto done;
	}

	/* Prepare DMA engine */
	if ((audio1575_dma_reset(statep, M1575_DMA_PCM_IN)) ==
	    AUDIO_FAILURE) {
		statep->m1575_flags &= ~M1575_DMA_RECD_STARTED;
		goto done;
	}

	/* DMA Engine reset was successful */
	buf->head = 0;
	buf->tail = 0;
	buf->avail = M1575_REC_BUFS;

	/* Set the IOCE bit */
	pcmicr = M1575_AM_GET8(M1575_PCMICR_REG);
	pcmicr |= M1575_PCMICR_IOCE;
	M1575_AM_PUT8(M1575_PCMICR_REG, pcmicr);

	/* set last valid index to 0 */
	M1575_AM_PUT8(M1575_PCMILVIV_REG, 0);

	/* setup the Base Address Register */
	M1575_AM_PUT32(M1575_PCMIBDBAR_REG, statep->m1575_bdl_phys_pin);

	if ((audio1575_prepare_record_buf(statep)) ==
	    AUDIO_SUCCESS) {
		statep->m1575_flags |= M1575_DMA_RECD_STARTED;
		rc = AUDIO_SUCCESS;
	} else {
		statep->m1575_flags &= ~M1575_DMA_RECD_STARTED;
	}

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	ATRACE("audio1575_ad_start_record() returning", rc);

	return (rc);

}	/* audio1575_ad_start_record() */

/*
 * audio1575_ad_stop_record()
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
audio1575_ad_stop_record(audiohdl_t ahandle, int stream)
{
	audio1575_state_t	*statep;
	m1575_sample_buf_t	*buf;

	ATRACE("audio1575_ad_stop_record() entering", ahandle);
	ATRACE("audio1575_ad_stop_record() stream", stream);

	statep = audio_sup_get_private(ahandle);
	ASSERT(statep);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));
	mutex_enter(&statep->m1575_intr_mutex);

	/* reset the DMA input registers */
	if ((audio1575_dma_reset(statep, M1575_DMA_PCM_IN)) ==
	    AUDIO_FAILURE) {
		ATRACE("audio1575_ad_stop_record() failure", NULL);
		goto done;
	}

	/* clear the PCM In Control Register */
	M1575_AM_PUT8(M1575_PCMICR_REG, 0);

	/* clear the record started flag */
	statep->m1575_flags &= ~M1575_DMA_RECD_STARTED;
	buf = &statep->m1575_record_buf;
	buf->io_started = B_FALSE;

done:
	mutex_exit(&statep->m1575_intr_mutex);

	ASSERT(!mutex_owned(&statep->m1575_intr_mutex));

	ATRACE("audio1575_ad_stop_record() returning", NULL);

}	/* audio1575_ad_stop_record() */


/* *********************** Local Routines *************************** */

/*
 * audio1575_init_state()
 *
 * Description:
 *	This routine initializes the audio driver's state structure
 *
 *	CAUTION: This routine cannot allocate resources, unless it frees
 *		them before returning from an error. Also, error_destroy:
 *		in audio1575_attach() would need to be fixed as well.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	dev_info_t		*dip		Pointer to the device's
 *						dev_info struct
 * Returns:
 *	AUDIO_SUCCESS		State structure initialized
 *	AUDIO_FAILURE		State structure not initialized
 */
static int
audio1575_init_state(audio1575_state_t *statep, dev_info_t *dip)
{
	int 		rints;
	int 		pints;
	int		count = 0;
	int		actual = 0;
	int		rc = AUDIO_SUCCESS;

	ATRACE("audio1575_init_state() entering", NULL);

	statep->m1575_dip = dip;

	/* default to 5 bit volume */
	statep->m1575_vol_bits_mask = 5;

	/* see if we support internal CDROM */
	statep->m1575_cdrom = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cdrom", 0);

	/* get the mode from the .conf file */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mixer-mode", AM_MIXER_MODE)) {
		statep->m1575_mode = AM_MIXER_MODE;
	} else {
		statep->m1575_mode = AM_COMPAT_MODE;
	}

	/* get play interrupts */
	pints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "play-interrupts", M1575_INTS);
	if (pints > M1575_MAX_INTS) {
		ATRACE("audio1575_init_state() "
		    "play interrupt rate too high, resetting", pints);
		audio_sup_log(statep->m1575_ahandle, CE_NOTE,
		    "init_state() "
		    "play interrupt rate set too high, %d, resetting to %d",
		    pints, M1575_INTS);
		pints = M1575_INTS;
	} else if (pints < M1575_MIN_INTS) {
		ATRACE("audio1575_init_state() "
		    "play interrupt rate too low, resetting", pints);
		audio_sup_log(statep->m1575_ahandle, CE_NOTE,
		    "init_state() "
		    "play interrupt rate set too low, %d, resetting to %d",
		    pints, M1575_INTS);
		pints = M1575_INTS;
	}

	/* get record interrupts */
	rints = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "record-interrupts", M1575_INTS);
	if (rints > M1575_MAX_INTS) {
		ATRACE("audio1575_init_state() "
		    "record interrupt rate too high, resetting", rints);
		audio_sup_log(statep->m1575_ahandle, CE_NOTE,
		    "init_state() "
		    "record interrupt rate set too high, %d, resetting to %d",
		    rints, M1575_INTS);
		rints = M1575_INTS;
	} else if (rints < M1575_MIN_INTS) {
		ATRACE("audio1575_init_state() "
		    "record interrupt rate too low, resetting", rints);
		audio_sup_log(statep->m1575_ahandle, CE_NOTE,
		    "init_state() "
		    "record interrupt rate set too low, %d "
		    "resetting to %d", rints, M1575_INTS);
		rints = M1575_INTS;
	}

	/* get supported interrupt types */
	rc = ddi_intr_get_supported_types(dip, &statep->m1575_intr_type);

	if ((rc != DDI_SUCCESS) ||
	    (!(statep->m1575_intr_type & DDI_INTR_TYPE_FIXED))) {
		audio_sup_log(statep->m1575_ahandle,
		    CE_WARN, "!init_state() Fixed type interrupts not "
		    "supported");
		ATRACE("audio1575_init_state() fixed type INTR not supported",
		    NULL);
		goto error_intr;
	}

	/* make sure we only have one fixed type interrupt */
	rc = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &count);

	if ((rc != DDI_SUCCESS) || (count != 1)) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!init_state() no fixed interrupts");
		ATRACE("audio1575_init_state() no fixed interrupts",
		    NULL);
		goto error_intr;
	}

	/* allocate interrupt table */
	statep->m1575_h_table = kmem_zalloc(sizeof (ddi_intr_handle_t),
	    KM_SLEEP);

	rc = ddi_intr_alloc(dip, statep->m1575_h_table, DDI_INTR_TYPE_FIXED, 0,
	    count, &actual, DDI_INTR_ALLOC_NORMAL);
	if ((rc != DDI_SUCCESS) || (actual != 1)) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!init_state() ddi_intr_alloc() failure");
		ATRACE("audio1575_init_state() ddi_intr_alloc failure", actual);
		goto error_alloc;
	}

	ASSERT(count == actual);
	/* Get the interrupt priority for initializing the m1575_intr_mutex */
	if ((ddi_intr_get_pri(statep->m1575_h_table[0],
	    &statep->m1575_intr_pri)) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!init_state() ddi_intr_get_pri() failure");
		ATRACE("audio1575_init_state() ddi_intr_get_pri() failure",
		    NULL);
		goto error_free;
	}

	/* test for a high level interrupt */
	if (statep->m1575_intr_pri >= ddi_intr_get_hilevel_pri()) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!init_state() unsupported high level interrupt");
		ATRACE("audio1575_init_state() high level interrupt not "
		    "supported", NULL);
		goto error_free;
	}

	/* fill in the device default state */
	statep->m1575_defaults.play.sample_rate = M1575_DEFAULT_SR;
	statep->m1575_defaults.play.channels = M1575_DEFAULT_CH;
	statep->m1575_defaults.play.precision = M1575_DEFAULT_PREC;
	statep->m1575_defaults.play.encoding = M1575_DEFAULT_ENC;
	statep->m1575_defaults.play.gain = M1575_DEFAULT_PGAIN;
	statep->m1575_defaults.play.port = AUDIO_SPEAKER;
	statep->m1575_defaults.play.avail_ports =
	    AUDIO_SPEAKER | AUDIO_LINE_OUT | AUDIO_HEADPHONE;
	statep->m1575_defaults.play.mod_ports =
	    AUDIO_SPEAKER | AUDIO_LINE_OUT | AUDIO_HEADPHONE;
	statep->m1575_defaults.play.buffer_size = M1575_BSIZE;
	statep->m1575_defaults.play.balance = M1575_DEFAULT_BAL;
	statep->m1575_defaults.record.sample_rate = M1575_DEFAULT_SR;
	statep->m1575_defaults.record.channels = M1575_DEFAULT_CH;
	statep->m1575_defaults.record.precision = M1575_DEFAULT_PREC;
	statep->m1575_defaults.record.encoding = M1575_DEFAULT_ENC;
	statep->m1575_defaults.record.gain = M1575_DEFAULT_RGAIN;
	statep->m1575_defaults.record.port = AUDIO_MICROPHONE;
	statep->m1575_defaults.record.avail_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	statep->m1575_defaults.record.mod_ports =
	    AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CODEC_LOOPB_IN;
	statep->m1575_defaults.record.buffer_size = M1575_BSIZE;
	statep->m1575_defaults.record.balance = M1575_DEFAULT_BAL;

	statep->m1575_defaults.monitor_gain = M1575_DEFAULT_MONITOR_GAIN;
	statep->m1575_defaults.output_muted = B_FALSE;
	statep->m1575_defaults.ref_cnt = B_FALSE;
	statep->m1575_defaults.hw_features =
	    AUDIO_HWFEATURE_DUPLEX|AUDIO_HWFEATURE_PLAY|
	    AUDIO_HWFEATURE_IN2OUT|AUDIO_HWFEATURE_RECORD;
	statep->m1575_defaults.sw_features = AUDIO_SWFEATURE_MIXER;

	if (statep->m1575_cdrom) {
		statep->m1575_defaults.record.avail_ports |= AUDIO_CD;
		statep->m1575_defaults.record.mod_ports |= AUDIO_CD;
	}

	statep->m1575_psample_rate = statep->m1575_defaults.play.sample_rate;
	statep->m1575_pchannels = statep->m1575_defaults.play.channels;
	statep->m1575_pprecision = statep->m1575_defaults.play.precision;
	statep->m1575_csample_rate = statep->m1575_defaults.record.sample_rate;
	statep->m1575_cchannels = statep->m1575_defaults.record.channels;
	statep->m1575_cprecision = statep->m1575_defaults.record.precision;

	/*
	 * fill in the ad_info structure
	 */
	statep->m1575_ad_info.ad_mode = statep->m1575_mode;
	statep->m1575_ad_info.ad_int_vers = AM_VERSION;
	statep->m1575_ad_info.ad_add_mode = NULL;
	statep->m1575_ad_info.ad_codec_type = AM_TRAD_CODEC;
	statep->m1575_ad_info.ad_defaults = &statep->m1575_defaults;
	statep->m1575_ad_info.ad_play_comb = audio1575_combinations;
	statep->m1575_ad_info.ad_rec_comb = audio1575_combinations;
	statep->m1575_ad_info.ad_entry = &audio1575_entry;
	statep->m1575_ad_info.ad_dev_info = &statep->m1575_dev_info;
	statep->m1575_ad_info.ad_diag_flags = AM_DIAG_INTERNAL_LOOP;
	statep->m1575_ad_info.ad_diff_flags =
	    AM_DIFF_SR | AM_DIFF_CH | AM_DIFF_PREC | AM_DIFF_ENC;
	statep->m1575_ad_info.ad_assist_flags = AM_ASSIST_MIC;
	statep->m1575_ad_info.ad_misc_flags = AM_MISC_RP_EXCL;
	statep->m1575_ad_info.ad_misc_flags |= AM_MISC_MONO_DUP;
	statep->m1575_ad_info.ad_translate_flags = AM_MISC_8_R_TRANSLATE;
	statep->m1575_ad_info.ad_num_mics = 1;

	/* play capabilities */
	statep->m1575_ad_info.ad_play.ad_mixer_srs =
	    audio1575_mixer_sample_rates;
	statep->m1575_ad_info.ad_play.ad_compat_srs =
	    audio1575_compat_sample_rates;
	statep->m1575_ad_info.ad_play.ad_conv = &am_src2;
	statep->m1575_ad_info.ad_play.ad_sr_info = NULL;
	statep->m1575_ad_info.ad_play.ad_chs = audio1575_channels;
	statep->m1575_ad_info.ad_play.ad_int_rate = pints;
	statep->m1575_ad_info.ad_play.ad_max_chs = M1575_MAX_OUT_CHANNELS;
	statep->m1575_ad_info.ad_play.ad_bsize = M1575_BSIZE;

	/* record capabilities */
	statep->m1575_ad_info.ad_record.ad_mixer_srs =
	    audio1575_mixer_sample_rates;
	statep->m1575_ad_info.ad_record.ad_compat_srs =
	    audio1575_compat_sample_rates;
	statep->m1575_ad_info.ad_record.ad_conv = &am_src2;
	statep->m1575_ad_info.ad_record.ad_sr_info = NULL;
	statep->m1575_ad_info.ad_record.ad_chs = audio1575_channels;
	statep->m1575_ad_info.ad_record.ad_int_rate = rints;
	statep->m1575_ad_info.ad_record.ad_max_chs = M1575_MAX_CHANNELS;
	statep->m1575_ad_info.ad_record.ad_bsize = M1575_BSIZE;

	/* fill in device info strings */
	(void) strcpy(statep->m1575_dev_info.name, M1575_DEV_NAME);
	(void) strcpy(statep->m1575_dev_info.config, M1575_DEV_CONFIG);
	(void) strcpy(statep->m1575_dev_info.version, M1575_DEV_VERSION);

	/* compute play and record buffer sizes */
	statep->m1575_play_buf_size = M1575_SAMPR48000 *
	    AUDIO_CHANNELS_STEREO * (AUDIO_PRECISION_16 >>
	    AUDIO_PRECISION_SHIFT) / pints;
	statep->m1575_play_buf_size += M1575_MOD_SIZE -
	    (statep->m1575_play_buf_size % M1575_MOD_SIZE);
	statep->m1575_record_buf_size = M1575_SAMPR48000 *
	    AUDIO_CHANNELS_STEREO * (AUDIO_PRECISION_16 >>
	    AUDIO_PRECISION_SHIFT) / rints;
	statep->m1575_record_buf_size += M1575_MOD_SIZE -
	    (statep->m1575_record_buf_size % M1575_MOD_SIZE);

	statep->m1575_flags = 0;

	ATRACE("audio1575_init_state() returning", NULL);

	return (AUDIO_SUCCESS);

error_free:
	(void) ddi_intr_free(statep->m1575_h_table[0]);
error_alloc:
	kmem_free(statep->m1575_h_table, sizeof (ddi_intr_handle_t));
error_intr:
	ATRACE("audio1575_init_state() failure", NULL);

	return (AUDIO_FAILURE);

}	/* audio1575_init_state() */

/*
 * audio1575_map_regs()
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
audio1575_map_regs(dev_info_t *dip, audio1575_state_t *statep)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;

	ATRACE("in audio1575_map_regs() entering", statep);

	statep->m1575_res_flags = 0;

	/* Check for fault management capabilities */
	if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(dip))) {
		dev_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	/* map the M1575 Audio PCI Cfg Space */
	if ((ddi_regs_map_setup(dip, M1575_AUDIO_PCICFG_SPACE,
	    (caddr_t *)&statep->m1575_pci_regs, 0, 0, &dev_attr,
	    &statep->m1575_pci_regs_handle)) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!audio1575_map_regs() PCI Config mapping failure");
		ATRACE("audio1575_map_regs() PCI Cfg Space failure", NULL);
		goto error;
	}
	statep->m1575_res_flags |= M1575_RS_PCI_REGS;

	/* map the M1575 Audio registers in PCI IO Space */
	if ((ddi_regs_map_setup(dip, M1575_AUDIO_IO_SPACE,
	    (caddr_t *)&statep->m1575_am_regs, 0, 0, &dev_attr,
	    &statep->m1575_am_regs_handle)) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!audio1575_map_regs() Audio IO mapping failure");
		ATRACE("audio1575_map_regs() PCI IO Space failure", NULL);
		goto error;
	}
	statep->m1575_res_flags |= M1575_RS_AM_REGS;

	/* map the M1575 Audio registers in PCI MEM32 Space */
	if ((ddi_regs_map_setup(dip, M1575_AUDIO_MEM_SPACE,
	    (caddr_t *)&statep->m1575_bm_regs, 0, 0, &dev_attr,
	    &statep->m1575_bm_regs_handle)) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!audio1575_map_regs() Audio MEM32 mapping failure");
		ATRACE("audio1575_map_regs() PCI MEM32 Space failure", NULL);
		goto error;
	}
	statep->m1575_res_flags |= M1575_RS_BM_REGS;

	/*
	 * Here we allocate DMA memory for the buffer descriptor list.
	 * we allocate adjacent DMA memory for all DMA engines.
	 */
	if (ddi_dma_alloc_handle(dip, &bdlist_dma_attr, DDI_DMA_SLEEP,
	    (caddr_t)0, &statep->m1575_bdl_dma_handle) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!audio1575_map_regs() ddi_dma_alloc_handle "
		    "(bdlist) failure");
		ATRACE("audio1575_map_regs() ddi_dma_alloc_handle() failure",
		    NULL);
		goto error;
	}
	statep->m1575_res_flags |= M1575_RS_DMA_BDL_HANDLE;

	/*
	 * we allocate all buffer descriptors lists in contiguous dma memory.
	 */
	if (ddi_dma_mem_alloc(statep->m1575_bdl_dma_handle,
	    sizeof (m1575_bd_entry_t) * M1575_BD_NUMS * 2,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&statep->m1575_bdl_virtual, &statep->m1575_bdl_size,
	    &statep->m1575_bdl_acc_handle) != DDI_SUCCESS) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!audio1575_map_regs() ddi_dma_mem_alloc(bdlist) failure");
		ATRACE("audio1575_map_regs() ddi_dma_mem_alloc(bdlist) failure",
		    NULL);
		goto error;
	}
	statep->m1575_res_flags |= M1575_RS_DMA_BDL_MEM;

	if (ddi_dma_addr_bind_handle(statep->m1575_bdl_dma_handle, NULL,
	    (caddr_t)statep->m1575_bdl_virtual, statep->m1575_bdl_size,
	    DDI_DMA_RDWR|DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &cookie,
	    &count) != DDI_DMA_MAPPED) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!audio1575_map_regs() addr_bind_handle failure");
		ATRACE("audio1575_map_regs() ddi_dma_addr_bind_handle failure",
		    NULL);
		goto error;
	}

	statep->m1575_bdl_virt_pin =
	    (m1575_bd_entry_t *)(statep->m1575_bdl_virtual);
	statep->m1575_bdl_virt_pout =
	    statep->m1575_bdl_virt_pin + M1575_BD_NUMS;
	statep->m1575_bdl_phys_pin = (uint32_t)(cookie.dmac_address);
	statep->m1575_bdl_phys_pout = statep->m1575_bdl_phys_pin +
	    sizeof (m1575_bd_entry_t) * M1575_BD_NUMS;
	statep->m1575_res_flags |= M1575_RS_DMA_BDL_BIND;

	ATRACE("audio1575_map_regs() returning", AUDIO_SUCCESS);

	return (AUDIO_SUCCESS);

error:
	audio1575_unmap_regs(statep);

	ATRACE("audio1575_map_regs() returning AUDIO_FAILURE", NULL);

	return (AUDIO_FAILURE);

}	/* audio1575_map_regs() */

/*
 * audio1575_unmap_regs()
 *
 * Description:
 *	This routine unbinds the play and record DMA handles, frees
 *	the DMA buffers and the unmaps control registers.
 *
 * Arguments:
 *	audio1575_state_t	*state	The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio1575_unmap_regs(audio1575_state_t *statep)
{
	if (statep->m1575_res_flags & M1575_RS_DMA_BDL_BIND) {
		statep->m1575_res_flags &= ~M1575_RS_DMA_BDL_BIND;
		(void) ddi_dma_unbind_handle(statep->m1575_bdl_dma_handle);
	}

	if (statep->m1575_res_flags & M1575_RS_DMA_BDL_MEM) {
		statep->m1575_res_flags &= ~M1575_RS_DMA_BDL_MEM;
		ddi_dma_mem_free(&statep->m1575_bdl_acc_handle);
	}

	if (statep->m1575_res_flags & M1575_RS_DMA_BDL_HANDLE) {
		statep->m1575_res_flags &= ~M1575_RS_DMA_BDL_HANDLE;
		ddi_dma_free_handle(&statep->m1575_bdl_dma_handle);
	}

	if (statep->m1575_res_flags & M1575_RS_BM_REGS) {
		statep->m1575_res_flags &= ~M1575_RS_BM_REGS;
		ddi_regs_map_free(&statep->m1575_bm_regs_handle);
	}

	if (statep->m1575_res_flags & M1575_RS_AM_REGS) {
		statep->m1575_res_flags &= ~M1575_RS_AM_REGS;
		ddi_regs_map_free(&statep->m1575_am_regs_handle);
	}

	if (statep->m1575_res_flags & M1575_RS_PCI_REGS) {
		statep->m1575_res_flags &= ~M1575_RS_PCI_REGS;
		pci_config_teardown(&statep->m1575_pci_regs_handle);
	}

}	/* audio1575_unmap_regs() */

/*
 * audio1575_alloc_sample_buf()
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
 *	audio1575_state_t	*state	The device's state structure
 *	int			which	Which sample buffer, PCM in or PCM out
 *					M1575_DMA_PCM_IN ---PCM in DMA engine
 *					M1575_DMA_PCM_OUT---PCM out DMA engine
 *	int			len	The length of the DMA buffers
 *
 * Returns:
 *	AUDIO_SUCCESS	 Allocating DMA buffers successfully
 *	AUDIO_FAILURE	 Failed to allocate dma buffers
 */
static int
audio1575_alloc_sample_buf(audio1575_state_t *statep, int which, int len)
{
	m1575_sample_buf_t	*buf;
	m1575_bdlist_chunk_t	*chunk;
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			i;
	int			j;
	int			handle_cnt = 0;
	int			buf_cnt = 0;
	int			bind_cnt = 0;

	ATRACE("audio1575_alloc_sample_buf() entering", which);

	switch (which) {
	case M1575_DMA_PCM_OUT:
		buf = &statep->m1575_play_buf;
		for (i = 0; i < M1575_PLAY_BUFS; i++) {
			chunk = &(buf->chunk[i]);
			if (ddi_dma_alloc_handle(statep->m1575_dip,
			    &sample_buf_dma_attr,
			    DDI_DMA_SLEEP, NULL,
			    &chunk->dma_handle) != DDI_SUCCESS) {
				goto error;
			}
			handle_cnt++;

			if (ddi_dma_mem_alloc(chunk->dma_handle, len,
			    &dev_attr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			    NULL, &chunk->data_buf,
			    &chunk->real_len, &chunk->acc_handle) !=
			    DDI_SUCCESS) {
				goto error;
			}
			buf_cnt++;

			if (ddi_dma_addr_bind_handle(chunk->dma_handle,
			    NULL, chunk->data_buf, chunk->real_len,
			    DDI_DMA_WRITE|DDI_DMA_STREAMING,
			    DDI_DMA_SLEEP, NULL, &cookie, &count) !=
			    DDI_DMA_MAPPED) {
				goto error;
			}
			bind_cnt++;

			chunk->addr_phy = (uint32_t)cookie.dmac_address;
		}
		break;

	case M1575_DMA_PCM_IN:
		buf = &statep->m1575_record_buf;
		for (i = 0; i < M1575_REC_BUFS; i++) {
			chunk = &(buf->chunk[i]);
			if (ddi_dma_alloc_handle(statep->m1575_dip,
			    &sample_buf_dma_attr, DDI_DMA_SLEEP,
			    NULL, &chunk->dma_handle) !=
			    DDI_SUCCESS) {
				goto error;
			}
			handle_cnt++;

			if (ddi_dma_mem_alloc(chunk->dma_handle, len,
			    &dev_attr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			    NULL, &chunk->data_buf, &chunk->real_len,
			    &chunk->acc_handle) != DDI_SUCCESS) {
				goto error;
			}
			buf_cnt++;

			if (ddi_dma_addr_bind_handle(chunk->dma_handle, NULL,
			    chunk->data_buf, chunk->real_len,
			    DDI_DMA_READ|DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			    NULL, &cookie, &count) != DDI_DMA_MAPPED) {
				goto error;
			}
			bind_cnt++;

			chunk->addr_phy = (uint32_t)cookie.dmac_address;
		}
		break;

	default:
		ATRACE("audio1575_alloc_sample_buf() unknown buffer type",
		    which);

		return (AUDIO_FAILURE);
	}

	ATRACE("audio1575_alloc_sample_buf() returning", AUDIO_SUCCESS);

	return (AUDIO_SUCCESS);

error:
	for (j = 0; j < bind_cnt; j++) {
		(void) ddi_dma_unbind_handle((buf->chunk[j].dma_handle));
	}
	for (j = 0; j < buf_cnt; j++) {
		ddi_dma_mem_free(&(buf->chunk[j].acc_handle));
	}
	for (j = 0; j < handle_cnt; j++) {
		ddi_dma_free_handle(&(buf->chunk[j].dma_handle));
	}

	ATRACE("audio1575_alloc_sample_buf() returning", AUDIO_FAILURE);

	return (AUDIO_FAILURE);

}	/* audio1575_alloc_sample_buf() */

/*
 * audio1575_free_sample_buf()
 *
 * Description:
 *	This routine frees the DMA buffers of the sample buffer. The DMA
 *	buffers were allocated by calling audio1575_alloc_sample_buf().
 *
 * Arguments:
 *	audio1575_state_t	*state	The device's state structure
 *	int			which	Which sample buffer, PCM in or PCM out
 *
 * Returns:
 *	void
 */
static void
audio1575_free_sample_buf(audio1575_state_t *statep, int which)
{
	m1575_sample_buf_t	*buf;
	m1575_bdlist_chunk_t	*chunk;
	int			i;

	ATRACE("audio1575_free_sample_buf() entering", statep);

	switch (which) {
	case M1575_DMA_PCM_IN:
		buf = &statep->m1575_record_buf;
		for (i = 0; i < M1575_REC_BUFS; i++) {
			chunk = &(buf->chunk[i]);
			(void) ddi_dma_unbind_handle(chunk->dma_handle);
			ddi_dma_mem_free(&chunk->acc_handle);
			ddi_dma_free_handle(&chunk->dma_handle);
		}
		break;

	case M1575_DMA_PCM_OUT:
		buf = &statep->m1575_play_buf;
		for (i = 0; i < M1575_PLAY_BUFS; i++) {
			chunk = &(buf->chunk[i]);
			(void) ddi_dma_unbind_handle(chunk->dma_handle);
			ddi_dma_mem_free(&chunk->acc_handle);
			ddi_dma_free_handle(&chunk->dma_handle);
		}
		break;

	default:
		ATRACE("audio1575_free_sample() unknown buffer type",
		    which);
		break;
	}

	ATRACE("audio1575_free_sample_buf() returning", NULL);

}	/* audio1575_free_sample_buf() */

/*
 * audio1575_reclaim_play_buf()
 *
 * Description:
 *	When the audio controller finishes fetching the data from DMA
 *	buffers, this routine will be called by interrupt handler to
 *	reclaim the DMA buffers.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio1575_reclaim_play_buf(audio1575_state_t *statep)
{
	m1575_sample_buf_t	*buf;
	int16_t			pcmociv;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	/* get the play buf ptr */
	buf = &statep->m1575_play_buf;

	/* get out current index value */
	pcmociv	= M1575_AM_GET8(M1575_PCMOCIV_REG);

	while (buf->head != pcmociv) {
		buf->avail++;
		buf->head++;
		buf->head &= M1575_BD_MSK;
	}

}	/* audio1575_reclaim_play_buf() */

/*
 * audio1575_init_ac97()
 *
 * Description:
 *	This routine initializes the AC97 codec.
 *	The AC97 codec registers are programmed from codec_shadow[].
 *	If we are not doing a restore, we initialize codec_shadow[], otherwise
 *	we use the current values of shadow
 *
 * Arguments:
 *	audio1575_state_t	*state	The device's state structure
 *	int			restore	If M1575_INIT_RESTORE then
 *					restore	from codec_shadow[]
 * Returns:
 *	AUDIO_SUCCESS	The hardware was initialized properly
 *	AUDIO_FAILURE	The hardware couldn't be initialized properly
 */
static int
audio1575_init_ac97(audio1575_state_t *statep, int restore)
{
	uint16_t	sr;
	uint16_t	*shadow;
	uint16_t	tmp;
	uint16_t	addr;
	int 		i;
	clock_t		ticks;

	ATRACE("audio1575_init_ac97() entering", NULL);

	mutex_enter(&statep->m1575_intr_mutex);

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	ticks = drv_usectohz(AD1981_POWERON_DELAY_USEC);

	/* AC97 register reset */
	if (audio1575_reset_ac97(statep) != AUDIO_SUCCESS) {
		ATRACE("audio1575_ac97_init() codec not reset", NULL);
		mutex_exit(&statep->m1575_intr_mutex);
		return (AUDIO_FAILURE);
	}

	/* turn on the AD1981B codec power and wait for analog i/o be ready */
	(void) audio1575_read_ac97(statep,
	    AC97_POWERDOWN_CTRL_STAT_REGISTER, &sr);
	(void) audio1575_write_ac97(statep,
	    AC97_POWERDOWN_CTRL_STAT_REGISTER, sr & 0x00ff);

	/*
	 * Wait 1 sec for the analog section to power up
	 * checking every 10 ms.
	 */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		(void) audio1575_read_ac97(statep,
		    AC97_POWERDOWN_CTRL_STAT_REGISTER, &sr);
		if ((sr & PCSR_POWERD_UP) == PCSR_POWERD_UP) {
			break;
		}
#ifndef __lock_lint
		delay(ticks);
#endif
	}

	/* return failure if the codec did not power up */
	if (i >= M1575_LOOP_CTR) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!failure to power up the AC97 Codec");
		ATRACE("audio1575_ac97_init() codec not powered up", sr);
		mutex_exit(&statep->m1575_intr_mutex);
		return (AUDIO_FAILURE);
	}

	/* point to our codec shadow registers */
	shadow = statep->m1575_codec_shadow;

	if (restore == M1575_INIT_NO_RESTORE) {
		for (i = 0; i < M1575_LAST_AC_REG; i += 2) {
			(void) audio1575_read_ac97(statep, i,
			    &(shadow[M1575_CODEC_REG(i)]));
		}

		/* 02h - set master line out volume, muted, 0dB */
		shadow[M1575_CODEC_REG(AC97_MASTER_VOLUME_REGISTER)] =
		    MVR_MUTE;

		/* 04h - set alternate line out volume, muted, 0dB */
		shadow[M1575_CODEC_REG(AC97_HEADPHONE_VOLUME_REGISTER)] =
		    HPVR_MUTE;

		/* 06h - set master mono volume, muted, 0dB */
		shadow[M1575_CODEC_REG(AC97_MONO_MASTER_VOLUME_REGSITER)] =
		    MMVR_MUTE | MMVR_0dB_ATTEN;

		/* 0ch - set phone input, mute, 0dB attenuation */
		shadow[M1575_CODEC_REG(AC97_PHONE_VOLUME_REGISTER)] =
		    PVR_MUTE|PVR_0dB_GAIN;

		/*
		 * 0eh - set mic input, mute, +20dB attenuation
		 * actually this is 30dB when MICVR_20dB_Boost
		 * is set. (see misc. register 0x76 setting
		 * of MIC_30dB_GAIN below.)
		 */
		shadow[M1575_CODEC_REG(AC97_MIC_VOLUME_REGISTER)] =
		    MICVR_MUTE | MICVR_20dB_BOOST | MICVR_0dB_GAIN;
		statep->m1575_ad_info.ad_add_mode |= AM_ADD_MODE_MIC_BOOST;

		/* 10h - set line input, mute, 0dB attenuation */
		shadow[M1575_CODEC_REG(AC97_LINE_IN_VOLUME_REGISTER)] =
		    LIVR_MUTE|LIVR_RIGHT_0dB_GAIN|LIVR_LEFT_0dB_GAIN;

		/* 12h - set cd input, mute, 0dB attenuation */
		shadow[M1575_CODEC_REG(AC97_CD_VOLUME_REGISTER)] =
		    CDVR_MUTE|CDVR_RIGHT_0dB_GAIN|CDVR_LEFT_0dB_GAIN;

		/* 16h - set aux input, mute, 0dB attenuation */
		shadow[M1575_CODEC_REG(AC97_AUX_VOLUME_REGISTER)] =
		    AUXVR_MUTE|AUXVR_RIGHT_0dB_GAIN|AUXVR_LEFT_0dB_GAIN;

		/* 18h - set PCM out input, NOT muted, 0dB gain */
		shadow[M1575_CODEC_REG(AC97_PCM_OUT_VOLUME_REGISTER)] =
		    PCMOVR_RIGHT_0dB_GAIN|PCMOVR_LEFT_0dB_GAIN;

		/* 1ah - set input device as mic */
		shadow[M1575_CODEC_REG(AC97_RECORD_SELECT_CTRL_REGISTER)] =
		    RSCR_R_MIC|RSCR_L_MIC;

		/* 1ch - set record gain to 0dB and not muted */
		shadow[M1575_CODEC_REG(AC97_RECORD_GAIN_REGISTER)] =
		    RGR_RIGHT_0db_GAIN|RGR_LEFT_0db_GAIN;

		/* 20h - set GP register, mic 1, everything else off */
		shadow[M1575_CODEC_REG(AC97_GENERAL_PURPOSE_REGISTER)] =
		    GPR_MS_MIC1|GPR_MONO_MIX_IN;

		/* 28h - set to use Primary Codec channels 1 & 2 */
		shadow[M1575_CODEC_REG(AC97_EXTENDED_AUDIO_REGISTER)] =
		    EAR_PRIMARY_CODEC;

		/* 2ah - set to use Primary Codec channels 1 & 2 */
		shadow[M1575_CODEC_REG(AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER)]
		    = 0;

		/* 2ch - PCM Front DAC Sample Rate */
		shadow[M1575_CODEC_REG(AC97_EXTENDED_FRONT_DAC_RATE_REGISTER)] =
		    AC97_SAMPLE_RATE_48000;

		/* 32h - PCM ADC Sample Rate */
		shadow[M1575_CODEC_REG(AC97_EXTENDED_LR_DAC_RATE_REGISTER)] =
		    AC97_SAMPLE_RATE_48000;

		/* 64h - Mixer ADC Gain Register */
		shadow[M1575_CODEC_REG(AC97_MIXER_ADC_GAIN_REGISTER)] =
		    RGR_RIGHT_0db_GAIN|RGR_LEFT_0db_GAIN|RGR_MUTE;

		/* 76h - Misc. Control Bit  Register */
		shadow[M1575_CODEC_REG(AC97_MISC_CONTROL_BIT_REGISTER)] =
		    MIC_30dB_GAIN | C1MIC;
	}

	/* Now we set the AC97 codec registers to the saved values */
	for (i = 2; i <= M1575_LAST_AC_REG; i += 2) {
		(void) audio1575_write_ac97(statep, i,
		    shadow[M1575_CODEC_REG(i)]);
	}

	/*
	 * Now we setup the EQ register to scale 16 bit linear pcm
	 * values into 20 bit DAC values.
	 */

	/* 60h - EQ Control Register */

	/*
	 * Here we set up the 6 biquad IIR filters to use
	 * coefficient a0 as our scaling factor. The equation for
	 * this filter is:
	 *
	 * Y(n) = a0(a1(y(n-1))+a2(y(n-2))+b2(x(n-2))+b1(x(n-1)))
	 * we use the following coefficient values:
	 *
	 *  a0 = 0x000f;
	 *  a1 = 0x0001;
	 *  a2 = 0x0001;
	 *  b1 = 0x0001;
	 *  b2 = 0x0001;
	 */
	for (i = 0; i < AD1981_MAX_FILTERS; i++) {
		addr = filters[i].addr | AD1981_EQCTRL_SYM | AD1981_EQCTRL_EQM;
		tmp = filters[i].coeff;
		(void) audio1575_write_ac97(statep, AD1981_EQCTRL_REG, addr);
		(void) audio1575_write_ac97(statep, AD1981_EQDATA_REG, tmp);
	}

	/* The AD1981B Codec only implements 5 bit volume register */
	(void) audio1575_read_ac97(statep, AC97_MASTER_VOLUME_REGISTER, &tmp);
	if ((tmp & 0x7fff) != (MVR_RIGHT_MASK | MVR_LEFT_MASK)) {
		statep->m1575_vol_bits_mask = 6;
	}

	/* resume the master volume to mute */
	(void) audio1575_write_ac97(statep, AC97_MASTER_VOLUME_REGISTER,
	    MVR_MUTE);

	/*
	 * if the codec chip do support variable sample rate,
	 * we set the sample rate to 48K
	 */
	(void) audio1575_read_ac97(statep, AC97_EXTENDED_AUDIO_REGISTER, &tmp);
	if (!(tmp & EAR_VRA)) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!AD8191B codec does not support VRA");
		ATRACE("audio1575_ac97_init() AD1981 EAR_VRA not set", tmp);
		mutex_exit(&statep->m1575_intr_mutex);

		return (AUDIO_FAILURE);

	} else {
		/* set variable sample rate mode */
		(void) audio1575_write_ac97(statep,
		    AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER, EASCR_VRA);
	}

	ATRACE("audio1575_ac97_init() sample rate",
	    statep->m1575_defaults.play.sample_rate);

	ATRACE("audio1575_ac97_init() returning", AUDIO_SUCCESS);

	mutex_exit(&statep->m1575_intr_mutex);

	return (AUDIO_SUCCESS);

}	/* audio1575_init_ac97() */

/*
 * audio1575_chip_init()
 *
 * Description:
 *	This routine initializes the M1575 AC97 audio controller and the AC97
 *	codec.	The AC97 codec registers are programmed from codec_shadow[].
 *	If we are not doing a restore, we initialize codec_shadow[], otherwise
 *	we use the current values of shadow.	This routine expects that the
 *	PCI IO and Memory spaces have been mapped and enabled already.
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	int			restore		If M1575_INIT_RESTORE then
 *						restore	from codec_shadow[]
 * Returns:
 *	AUDIO_SUCCESS	The hardware was initialized properly
 *	AUDIO_FAILURE	The hardware couldn't be initialized properly
 */
static int
audio1575_chip_init(audio1575_state_t *statep, int restore)
{
	uint32_t	scr;
	uint32_t	ssr;
	uint32_t	rtsr;
	uint32_t	intfcr;
	int 		i;
	int		j;
	int		rc;
	uint8_t		clk_detect;
	clock_t		ticks;

	ATRACE("audio1575_chip_init() entering", NULL);

	mutex_enter(&statep->m1575_intr_mutex);

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	ticks = drv_usectohz(M1575_LOOP_CTR);

	/*
	 * SADA only supports stereo, so we set the channel bits
	 * to "00" to select 2 channels.
	 * will also set the following:
	 *
	 * Disable double rate enable
	 * no SPDIF output selected
	 * 16 bit audio record mode
	 * 16 bit pcm out mode
	 * PCM Out 6 chan mode FL FR CEN BL BR LFE
	 * PCM Out 2 channel mode (00)
	 */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		/* Reset the AC97 Codec	and default to 2 channel 16 bit mode */
		M1575_AM_PUT32(M1575_SCR_REG, M1575_SCR_COLDRST);
#ifndef __lock_lint
		delay(ticks<<1);
#endif
		/* Read the System Status Reg */
		ssr = M1575_AM_GET32(M1575_SSR_REG);

		/* make sure and release the blocked reset bit */
		if (ssr & M1575_SSR_RSTBLK) {
			ATRACE("audio1575_chip_init()! RSTBLK detected", ssr);
			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			intfcr |= M1575_INTFCR_RSTREL;
			M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);
#ifndef __lock_lint
			delay(ticks);
#endif
			/* Read the System Status Reg */
			ssr = M1575_AM_GET32(M1575_SSR_REG);

			/* make sure and release the blocked reset bit */
			if (ssr & M1575_SSR_RSTBLK) {
				ATRACE("audio1575_chip_init()! RSTBLK failure",
				    ssr);
				mutex_exit(&statep->m1575_intr_mutex);
				return (AUDIO_FAILURE);
			}

			/* Reset the controller */
			M1575_AM_PUT32(M1575_SCR_REG, M1575_SCR_COLDRST);
#ifndef __lock_lint
			delay(ticks);
#endif
		}

		/* according AC'97 spec, wait for codec reset */
		for (j = 0; j < M1575_LOOP_CTR; j++) {
			scr = M1575_AM_GET32(M1575_SCR_REG);
			if ((scr & M1575_SCR_COLDRST) == 0) {
				break;
			}
#ifndef __lock_lint
			delay(ticks);
#endif
		}

		/* codec reset failed */
		if (j >= M1575_LOOP_CTR) {
			audio_sup_log(statep->m1575_ahandle, CE_WARN,
			    "!failure to reset codec");
			ATRACE("audio1575_chip_init() "
			    "!AC97 COLDRST failure", scr);
			mutex_exit(&statep->m1575_intr_mutex);
			return (AUDIO_FAILURE);
		}

		/*
		 * Wait for FACRDY First codec ready. The hardware can
		 * provide the state of
		 * codec ready bit on SDATA_IN[0] and as reflected in
		 * the Recv Tag Slot Reg.
		 */
		rtsr = M1575_AM_GET32(M1575_RTSR_REG);
		if (rtsr & M1575_RTSR_FACRDY) {
			break;
		} else { /* reset the status and wait for new status to set */
			rtsr |= M1575_RTSR_FACRDY;
			M1575_AM_PUT32(M1575_RTSR_REG, rtsr);
			drv_usecwait(10);
		}
	}

	/* if we could not reset the AC97 codec then report failure */
	if (i >= M1575_LOOP_CTR) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!chip_init() no codec ready signal received");
		ATRACE("audio1575_chip_init() AC97 Codec init "
		    "failure - BAD Board", rtsr);
		mutex_exit(&statep->m1575_intr_mutex);

		return (AUDIO_FAILURE);
	}

	/* Magic code from ULi to Turn on the AC_LINK clock */
	M1575_PCI_PUT8(M1575_PCIACD_REG, 0);
	M1575_PCI_PUT8(M1575_PCIACD_REG, 4);
	M1575_PCI_PUT8(M1575_PCIACD_REG, 0);
	(void) M1575_PCI_GET8(M1575_PCIACD_REG);
	M1575_PCI_PUT8(M1575_PCIACD_REG, 2);
	M1575_PCI_PUT8(M1575_PCIACD_REG, 0);
	clk_detect = M1575_PCI_GET8(M1575_PCIACD_REG);

	if (clk_detect != 1) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!chip_init() No AC97 Clock Detected");
		ATRACE("audio1575_chip_init() no AC97 Clock detected",
		    clk_detect);
		mutex_exit(&statep->m1575_intr_mutex);
		return (AUDIO_FAILURE);
	}

	/* Magic code from Uli to Init FIFO1 and FIFO2 */
	M1575_AM_PUT32(M1575_FIFOCR1_REG, 0x81818181);
	M1575_AM_PUT32(M1575_FIFOCR2_REG, 0x81818181);
	M1575_AM_PUT32(M1575_FIFOCR3_REG, 0x81818181);

	/* Disable SPDIF Output */
	M1575_AM_PUT8(M1575_CSPOCR_REG, 0);

	/* Disable Everyone */
	M1575_AM_PUT32(M1575_INTFCR_REG, 0L);

	audio1575_dma_stop(statep);

	mutex_exit(&statep->m1575_intr_mutex);

	/* now initialize the AC97 codec */
	rc = audio1575_init_ac97(statep, restore);

	ATRACE("audio1575_chip_init() returning", rc);

	return (rc);

}	/* audio1575_chip_init() */

/*
 * audio1575_dma_stop()
 *
 * Description:
 *	This routine is used to put each DMA engine into the quiet state.
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio1575_dma_stop(audio1575_state_t *statep)
{
	uint32_t	dmacr;
	uint32_t	intrsr;
	uint32_t	intrcr;
	uint16_t	sr;
	int		i;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	ATRACE("audio1575_dma_stop() entering", NULL);

	/* pause bus master (needed for the following reset register) */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		dmacr = M1575_AM_GET32(M1575_DMACR_REG);
		dmacr |= M1575_DMACR_PAUSE_ALL;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		dmacr = M1575_AM_GET32(M1575_DMACR_REG);
		if (dmacr & M1575_DMACR_PAUSE_ALL) {
			break;
		}
		drv_usecwait(10);
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
	}

	if (i >= M1575_LOOP_CTR) {
		audio_sup_log(statep->m1575_ahandle, CE_WARN,
		    "!dma_stop() failed to stop DMA engines");
		ATRACE("audio1575_dma_stop() failure "
		    "to stop DMA engines", dmacr);
		return;
	}

	/* Pause bus master (needed for the following reset register) */
	M1575_AM_PUT8(M1575_PCMICR_REG, 0);
	M1575_AM_PUT8(M1575_PCMOCR_REG, 0);
	M1575_AM_PUT8(M1575_MICICR_REG, 0);
	M1575_AM_PUT8(M1575_CSPOCR_REG, 0);
	M1575_AM_PUT8(M1575_PCMI2CR_RR, 0);
	M1575_AM_PUT8(M1575_MICI2CR_RR, 0);

	/* Reset the bus master registers for all DMA engines */
	M1575_AM_PUT8(M1575_PCMICR_REG, M1575_PCMICR_RR);
	M1575_AM_PUT8(M1575_PCMOCR_REG, M1575_PCMOCR_RR);
	M1575_AM_PUT8(M1575_MICICR_REG, M1575_MICICR_RR);
	M1575_AM_PUT8(M1575_CSPOCR_REG, M1575_CSPOCR_RR);
	M1575_AM_PUT8(M1575_PCMI2CR_REG, M1575_PCMI2CR_RR);
	M1575_AM_PUT8(M1575_MICI2CR_REG, M1575_MICI2CR_RR);

	/* Reset FIFOS */
	M1575_AM_PUT32(M1575_FIFOCR1_REG, 0x81818181);
	M1575_AM_PUT32(M1575_FIFOCR2_REG, 0x81818181);
	M1575_AM_PUT32(M1575_FIFOCR3_REG, 0x81818181);

	/* Clear Interrupts */
	sr = M1575_AM_GET16(M1575_PCMISR_REG) | M1575_STATUS_CLR;
	M1575_AM_PUT16(M1575_PCMISR_REG, sr);

	sr = M1575_AM_GET16(M1575_PCMOSR_REG) | M1575_STATUS_CLR;
	M1575_AM_PUT16(M1575_PCMOSR_REG, sr);

	sr = M1575_AM_GET16(M1575_MICISR_REG) | M1575_STATUS_CLR;
	M1575_AM_PUT16(M1575_MICISR_REG, sr);

	sr = M1575_AM_GET16(M1575_CSPOSR_REG) | M1575_STATUS_CLR;
	M1575_AM_PUT16(M1575_CSPOSR_REG, sr);

	sr = M1575_AM_GET16(M1575_PCMI2SR_REG) | M1575_STATUS_CLR;
	M1575_AM_PUT16(M1575_PCMI2SR_REG, sr);

	sr = M1575_AM_GET16(M1575_MICI2SR_REG) | M1575_STATUS_CLR;
	M1575_AM_PUT16(M1575_MICI2SR_REG, sr);

	/*
	 * clear the interrupt control and status register
	 * READ/WRITE/READ workaround required
	 * for buggy hardware
	 */

	intrcr = 0L;
	M1575_AM_PUT32(M1575_INTRCR_REG, intrcr);
	intrcr = M1575_AM_GET32(M1575_INTRCR_REG);

	intrsr = M1575_AM_GET32(M1575_INTRSR_REG);
	M1575_AM_PUT32(M1575_INTRSR_REG, (intrsr & M1575_INTR_MASK));
	intrsr = M1575_AM_GET32(M1575_INTRSR_REG);

	/* clear all flags except DMA suspend flag */
	statep->m1575_flags &= M1575_DMA_SUSPENDED;

	ATRACE("audio1575_stop_dma() returning", NULL);

}	/* audio1575_dma_stop() */

/*
 * audio1575_set_gain()
 *
 * Description:
 *	Set the play/record gain.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	int			dir		AUDIO_PLAY or AUDIO_RECORD, if
 *						direction is important
 *	int			arg1		The gain to set
 *	int			arg2		The channel, 0 == left
 *						or 1 == right
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
static int
audio1575_set_gain(audio1575_state_t *statep, int dir, int gain, int channel)
{
	uint16_t	tmp;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	if (gain > AUDIO_MAX_GAIN) {
		gain = AUDIO_MAX_GAIN;
	} else if (gain < AUDIO_MIN_GAIN) {
		gain = AUDIO_MIN_GAIN;
	}

	switch (dir) {
	case AUDIO_PLAY:
		/*
		 * For play we use PCM so all volumes change with just
		 * one write. This way we get line out, headphone and
		 * internal speaker in one shot.
		 *
		 * The AC97 Codec goes from -34.5 dB (11111) to 0 dB
		 * (01000) to +12.0 dB (00000). We turn gain into attenuation
		 * The AD1981B codec uses attenuation instead of gain as well.
		 * abs(-34.5dB)+12.dB = 46.5dB of dynamic range/1.5dB per bit
		 * gives a range of 0x00-0x1f (0-31) values.
		 */

		/* read the play gain register */
		(void) audio1575_read_ac97(statep, AC97_PCM_OUT_VOLUME_REGISTER,
		    &tmp);
		tmp &= ~PCMOVR_MUTE;

		if (channel == 0) {	/* left channel */
			tmp &= ~PCMOVR_LEFT_GAIN_MASK;
			tmp |= (((AUDIO_MAX_GAIN - gain) >>
			    M1575_GAIN_SHIFT3) << M1575_BYTE_SHIFT) &
			    PCMOVR_LEFT_GAIN_MASK;
		} else {		/* right channel */
			ASSERT(channel == 1);
			tmp &= ~PCMOVR_RIGHT_GAIN_MASK;
			tmp |= ((AUDIO_MAX_GAIN - gain) >>
			    M1575_GAIN_SHIFT3) & PCMOVR_RIGHT_GAIN_MASK;
		}

		/* update the play gain register */
		(void) audio1575_write_ac97(statep,
		    AC97_PCM_OUT_VOLUME_REGISTER, tmp);
		(void) audio1575_read_ac97(statep, AC97_PCM_OUT_VOLUME_REGISTER,
		    &tmp);
		break;

	case AUDIO_RECORD:
		/*
		 * For record we use the master record gain with all
		 * of the inputs set to 0dB.
		 * The AC97 Codec goes from 0 dB (0000) to +22.5 dB
		 * (1111) 22.5 dB/1.5dB per bit = range of 0x0-0xf;
		 * Note: this is gain not attenuation.
		 */

		/* read the record gain register */
		(void) audio1575_read_ac97(statep,
		    AC97_RECORD_GAIN_REGISTER, &tmp);

		if (channel == 0) {	/* left channel */
			tmp &= ~RGR_LEFT_MASK;
			tmp |= (gain << M1575_GAIN_SHIFT4) & RGR_LEFT_MASK;
		} else {		/* right channel */
			ASSERT(channel == 1);
			tmp &= ~RGR_RIGHT_MASK;
			tmp |= (gain >> M1575_GAIN_SHIFT4) & RGR_RIGHT_MASK;
		}

		/* update the record gain register */
		(void) audio1575_write_ac97(statep,
		    AC97_RECORD_GAIN_REGISTER, tmp);
		(void) audio1575_read_ac97(statep,
		    AC97_RECORD_GAIN_REGISTER, &tmp);
		break;

	default:
		ATRACE("audio1575_set_gain() Unknown audio direction", dir);

		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audio1575_set_gain() */

/*
 * audio1575_set_port()
 *
 * Description:
 *	Set the play/record port.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *						which is not how we program
 *						the device for now.
 *	int			dir		AUDIO_PLAY or AUDIO_RECORD,
 *						if direction is important
 *	int			port		The port to set:
 *				AUDIO_SPEAKER	output to built-in speaker
 *				AUDIO_HEADPHONE	output to headphone
 *				AUDIO_LINE_OUT	output to line out
 *
 *				AUDIO_MICROPHONE	input from microphone
 *				AUDIO_LINE_IN		input from line in
 *				AUDIO_CD 		input from internal CD
 *				AUDIO_CODEC_LOOPB_IN	input from Codec
 *							internal loopback
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The port could not been set
 */
static int
audio1575_set_port(audio1575_state_t *statep, int dir, int port)
{
	uint16_t	tmp = 0;
	uint16_t	reg = 0;
	uint32_t	intfcr = 0;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	switch (dir) {
	case AUDIO_PLAY: /* output port */
		if (port == M1575_PORT_UNMUTE) {
			port = statep->m1575_output_port;
		}

		if (port & AUDIO_SPEAKER) {
			(void) audio1575_and_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_SPEAKER;
		} else {
			(void) audio1575_or_ac97(statep,
			    AC97_MONO_MASTER_VOLUME_REGSITER, MVR_MUTE);
		}

		if (port & AUDIO_LINE_OUT) {
			(void) audio1575_and_ac97(statep,
			    AC97_MASTER_VOLUME_REGISTER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_LINE_OUT;
		} else {
			(void) audio1575_or_ac97(statep,
			    AC97_MASTER_VOLUME_REGISTER, MVR_MUTE);
		}

		if (port & AUDIO_HEADPHONE) {
			(void) audio1575_and_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER,
			    (uint16_t)~MVR_MUTE);
			tmp |= AUDIO_HEADPHONE;
		} else {
			(void) audio1575_or_ac97(statep,
			    AC97_HEADPHONE_VOLUME_REGISTER, MVR_MUTE);
		}

		intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
		intfcr |= (M1575_INTFCR_PCMOENB);
		M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);

		ATRACE("audio1575_set_port() out port", tmp);
		statep->m1575_output_port = tmp;
		if (tmp != port) {
			ATRACE("audio1575_set_port() bad out port", port);

			return (AUDIO_FAILURE);
		}
		break;

	case AUDIO_RECORD: /* input port */
		switch (port) {
		case AUDIO_NONE:
			/* set to an unused input */
			tmp = RSCR_R_PHONE | RSCR_L_PHONE;
			ATRACE("audio1575_set_port() AUDIO_NONE", NULL);

			/* mute the master record input */
			(void) audio1575_or_ac97(statep,
			    AC97_RECORD_GAIN_REGISTER, RGR_MUTE);

			if (statep->m1575_monitor_gain) {
				if (statep->m1575_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio1575_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_LINE_IN) {
					(void) audio1575_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_CD) {
					(void) audio1575_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER, CDVR_MUTE);
				}
			}

			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			intfcr &= ~(M1575_INTFCR_PCMIENB|M1575_INTFCR_MICENB);
			M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);
			break;

		case AUDIO_MICROPHONE:
			/* set to the mic input */
			tmp = RSCR_R_MIC | RSCR_L_MIC;
			if (statep->m1575_monitor_gain) {
				if (statep->m1575_input_port == AUDIO_LINE_IN) {
					(void) audio1575_or_ac97(statep,
					    AC97_LINE_IN_VOLUME_REGISTER,
					    LIVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_CD) {
					(void) audio1575_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
			(void) audio1575_write_ac97(statep,
			    AC97_MIC_VOLUME_REGISTER,
			    statep->m1575_monitor_gain);
			}

			/* Enable the MIC input on AC Link Channel 3 */
			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			intfcr |= (M1575_INTFCR_PCMIENB);
			intfcr &= ~(M1575_INTFCR_MICISEL|M1575_INTFCR_MICENB |
			    M1575_INTFCR_MICI2SEL| M1575_INTFCR_MICI2ENB);
			M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);
			break;

		case AUDIO_LINE_IN:
			/* set to the line in input */
			tmp = RSCR_R_LINE_IN | RSCR_L_LINE_IN;
			ATRACE("audio1575_set_port() LINE_IN", tmp);
			/* see if we need to update monitor loopback */
			if (statep->m1575_monitor_gain) {
				if (statep->m1575_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio1575_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_CD) {
					(void) audio1575_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER,
					    CDVR_MUTE);
				}
				(void) audio1575_write_ac97(statep,
				    AC97_LINE_IN_VOLUME_REGISTER,
				    statep->m1575_monitor_gain);
			}

			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			intfcr &= ~(M1575_INTFCR_MICENB);
			intfcr |= (M1575_INTFCR_PCMIENB);
			M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);
			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			break;

		case AUDIO_CD:
			/* set to the line in input */
			tmp = RSCR_R_CD|RSCR_L_CD;
			/* see if we need to update monitor loopback */
			if (statep->m1575_monitor_gain) {
				reg = AC97_LINE_IN_VOLUME_REGISTER;
				if (statep->m1575_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio1575_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_LINE_IN) {
					(void) audio1575_or_ac97(statep,
					    reg, LIVR_MUTE);
				}
				(void) audio1575_write_ac97(statep,
				    AC97_CD_VOLUME_REGISTER,
				    statep->m1575_monitor_gain);
			}
			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			intfcr &= ~(M1575_INTFCR_MICENB);
			intfcr |= (M1575_INTFCR_PCMIENB);
			M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);
			break;

		case AUDIO_CODEC_LOOPB_IN:
			/* set to the loopback input */
			tmp = RSCR_R_STEREO_MIX | RSCR_L_STEREO_MIX;
			ATRACE("audio1575_set_port() LPBK", tmp);
			if (statep->m1575_monitor_gain) {
				if (statep->m1575_input_port == AUDIO_LINE_IN) {
				(void) audio1575_or_ac97(statep,
				    AC97_LINE_IN_VOLUME_REGISTER, LIVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_MICROPHONE) {
					(void) audio1575_or_ac97(statep,
					    AC97_MIC_VOLUME_REGISTER,
					    MICVR_MUTE);
				} else if (statep->m1575_input_port ==
				    AUDIO_CD) {
					(void) audio1575_or_ac97(statep,
					    AC97_CD_VOLUME_REGISTER, CDVR_MUTE);
				}
			}
			intfcr = M1575_AM_GET32(M1575_INTFCR_REG);
			intfcr &= ~(M1575_INTFCR_MICENB | M1575_INTFCR_MICISEL);
			intfcr |= (M1575_INTFCR_PCMIENB);
			M1575_AM_PUT32(M1575_INTFCR_REG, intfcr);
			break;

		default:
			ATRACE("audio1575_set_port bad in port", port);

			return (AUDIO_FAILURE);
		}

		/* select the input */
		(void) audio1575_write_ac97(statep,
		    AC97_RECORD_SELECT_CTRL_REGISTER, tmp);

		if ((port != AUDIO_NONE) &&
		    (statep->m1575_codec_shadow[M1575_CODEC_REG(
		    AC97_RECORD_GAIN_REGISTER)] & RGR_MUTE)) {
			(void) audio1575_and_ac97(statep,
			    AC97_RECORD_GAIN_REGISTER,
			    (uint16_t)~RGR_MUTE);
		}
		statep->m1575_input_port = port;
		break;
	}

	ATRACE("audio1575_set_port() returning", port);

	return (AUDIO_SUCCESS);

}	/* audio1575_set_port() */

/*
 * audio1575_set_monitor_gain()
 *
 * Description:
 *	Set the monitor gain.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	int			gain		The gain to set
 *
 * Returns:
 * 	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The gain has not been set
 */
static int
audio1575_set_monitor_gain(audio1575_state_t *statep, int gain)
{
	uint16_t	tmp_short;
	int		rc = AUDIO_SUCCESS;

	ATRACE("audio1575_set_monitor_gain() entering", statep);

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));
	if (gain > AUDIO_MAX_GAIN) {	/* sanity check */
		gain = AUDIO_MAX_GAIN;
	}

	if (gain == 0) {
		/* disable loopbacks when gain == 0 */
		tmp_short = MVR_MUTE;
	} else {
		/* Adjust the value of gain to the requirement of AC'97 */
		tmp_short = (((AUDIO_MAX_GAIN - gain) >> M1575_GAIN_SHIFT3) <<
		    M1575_BYTE_SHIFT) & PCMOVR_LEFT_GAIN_MASK;
		tmp_short |= ((AUDIO_MAX_GAIN - gain) >> M1575_GAIN_SHIFT3) &
		    PCMOVR_RIGHT_GAIN_MASK;
	}

	switch (statep->m1575_input_port) {
	case AUDIO_NONE:
		/*
		 * It is possible to set the value of gain before any input
		 * is selected. So, we just save the gain and then return
		 * SUCCESS.
		 */
		break;

	case AUDIO_MICROPHONE:
		tmp_short |= statep->m1575_codec_shadow[M1575_CODEC_REG(
		    AC97_MIC_VOLUME_REGISTER)] & MICVR_20dB_BOOST;
		(void) audio1575_write_ac97(statep,
		    AC97_MIC_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_LINE_IN:
		(void) audio1575_write_ac97(statep,
		    AC97_LINE_IN_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_CD:
		(void) audio1575_write_ac97(statep,
		    AC97_CD_VOLUME_REGISTER, tmp_short);
		break;

	case AUDIO_CODEC_LOOPB_IN:
		/* we already are setting the loopback, so done */
		goto done;

	default:
		/* this should never happen! */
		ATRACE("audio1575_ad_set_config() monitor gain bad device",
		    statep->m1575_input_port);
		rc = AUDIO_FAILURE;
		goto done;
	}

	if (gain == 0) {
		statep->m1575_monitor_gain = 0;
	} else {
		statep->m1575_monitor_gain = tmp_short;
	}

done:
	ATRACE("audio1575_set_monitor_gain() returning", rc);

	return (rc);

}	/* audio1575_set_monitor_gain() */

/*
 * audio1575_codec_sync()
 *
 * Description:
 *	Serialize access to the AC97 audio mixer registers.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Ready for an I/O access to the codec
 *	AUDIO_FAILURE		An I/O access is currently in progress, can't
 *				perform another I/O access.
 */
static int
audio1575_codec_sync(audio1575_state_t *statep)
{
	int 		i;
	int 		j;
	uint32_t	casr;
	uint32_t	cspsr;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	/* do the Uli Shuffle ... */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		/* Read the semaphore */
		casr = M1575_AM_GET32(M1575_CASR_REG);
		/* loop till we own the semaphore */
		if ((casr & 1) == 0) {
			for (j = 0; j < M1575_LOOP_CTR; j++) {
				/* Wait for CWRSUCC 0x8 */
				cspsr = M1575_AM_GET32(M1575_CSPSR_REG);
				if ((cspsr & M1575_CSPSR_SUCC) ==
				    M1575_CSPSR_SUCC) {
					return (AUDIO_SUCCESS);
				}
				drv_usecwait(1);
			}
		}
		drv_usecwait(10);
	}

	return (AUDIO_FAILURE);

}	/* audio1575_codec_sync() */

/*
 * audio1575_and_ac97()
 *
 * Description:
 *	Logically AND the value with the specified ac97 codec register
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The value to AND
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audio1575_and_ac97(audio1575_state_t *statep, int reg, uint16_t data)
{
	uint16_t	tmp;

	if ((audio1575_write_ac97(statep, reg, data &
	    statep->m1575_codec_shadow[M1575_CODEC_REG(reg)])) ==
	    AUDIO_FAILURE) {
		return (AUDIO_FAILURE);
	}

	(void) audio1575_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audio1575_and_ac97() */

/*
 * audio1575_or_ac97()
 *
 * Description:
 *	Logically OR the value with the specified ac97 codec register
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The value to OR
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audio1575_or_ac97(audio1575_state_t *statep, int reg, uint16_t data)
{
	uint16_t	tmp;

	if ((audio1575_write_ac97(statep, reg, data |
	    statep->m1575_codec_shadow[M1575_CODEC_REG(reg)])) ==
	    AUDIO_FAILURE) {
		return (AUDIO_FAILURE);
	}

	(void) audio1575_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audio1575_or_ac97() */

/*
 * audio1575_write_ac97()
 *
 * Description:
 *	Set the specific AC97 Codec register.
 *
 * Arguments:
 *	audio1575_state_t	 *state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		data		The data want to be set
 *
 * Returns:
 *	AUDIO_SUCCESS		The Codec parameter has been set
 *	AUDIO_FAILURE		The Codec parameter has not been set
 */
static int
audio1575_write_ac97(audio1575_state_t *statep, int reg, uint16_t data)
{
	uint32_t	cspsr;
	uint16_t	tmp;
	int		i;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	if (audio1575_codec_sync(statep) != AUDIO_SUCCESS) {
		return (AUDIO_FAILURE);
	}

	/* write the data to WRITE to the lo word of the CPR register */
	M1575_AM_PUT16(M1575_CPR_REG, data);

	/* write the address to WRITE to the hi word of the CPR register */
	M1575_AM_PUT16(M1575_CPR_REG+2, reg);

	/* wait until command is completed sucessfully */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		/* Wait for Write Ready	0x01 */
		cspsr = M1575_AM_GET32(M1575_CSPSR_REG);
		if ((cspsr & M1575_CSPSR_WRRDY) == M1575_CSPSR_WRRDY) {
			break;
		}
		drv_usecwait(1);
	}

	if (i >= M1575_LOOP_CTR) {
		ATRACE("audio1575_write_ac97() failure", i);

		return (AUDIO_FAILURE);
	}

	(void) audio1575_read_ac97(statep, reg, &tmp);

	return (AUDIO_SUCCESS);

}	/* audio1575_write_ac97() */

/*
 * audio1575_read_ac97()
 *
 * Description:
 *	Get the specific AC97 Codec register. It also updates codec_shadow[]
 *	with the register value.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *	int			reg		AC97 register number
 *	uint16_t		*data		The data to be returned
 *
 * Returns:
 *	AUDIO_SUCCESS		Reading the codec register successfully
 *	AUDIO_FAILURE		Failed to read the register
 */
static int
audio1575_read_ac97(audio1575_state_t *statep, int reg, uint16_t *data)
{
	uint32_t	cspsr;
	uint16_t	addr = 0;
	int		i;

	ATRACE("audio1575_read_ac97() entering", NULL);
	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	if ((audio1575_codec_sync(statep)) != AUDIO_SUCCESS) {
		*data = 0xffff;
		ATRACE("audio1575_read_ac97() sync failure", NULL);

		return (AUDIO_FAILURE);
	}

	/*
	 * at this point we has the CASR semaphore
	 * and the codec is r/w ready
	 * OR in the READ opcode into the address field
	 */

	addr = (reg | M1575_CPR_READ);

	/* write the address to READ to the hi word of the CPR register */
	M1575_AM_PUT16(M1575_CPR_REG+2, addr);

	/* wait until command is completed sucessfully */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		/* Wait for Read Ready	0x02 */
		cspsr = M1575_AM_GET32(M1575_CSPSR_REG);
		if ((cspsr & M1575_CSPSR_RDRDY) == M1575_CSPSR_RDRDY) {
			break;
		}
		drv_usecwait(1);
	}

	if (i >= M1575_LOOP_CTR) {
		*data = 0xffff;
		ATRACE("audio1575_read_ac97() CSPSR NOT READY", cspsr);

		return (AUDIO_FAILURE);
	}

	/* read back the data and address */
	*data = M1575_AM_GET16(M1575_SPR_REG);
	addr = M1575_AM_GET16(M1575_SPR_REG+2);

	if (addr != reg) {
		ATRACE("audio1575_read_ac97() bad read address", addr);

		return (AUDIO_FAILURE);
	}

	/* store new value in codec shadow register */
	statep->m1575_codec_shadow[M1575_CODEC_REG(reg)] = *data;

	ATRACE("audio1575_read_ac97() returning successfully", NULL);

	return (AUDIO_SUCCESS);

}	/* audio1575_read_ac97() */

/*
 * audio1575_reset_ac97()
 *
 * Description:
 *	Reset AC97 Codec register.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Reset the codec successfully
 *	AUDIO_FAILURE		Failed to reset the codec
 */
static int
audio1575_reset_ac97(audio1575_state_t *statep)
{
	uint16_t	tmp;

	if (audio1575_read_ac97(statep,
	    AC97_POWERDOWN_CTRL_STAT_REGISTER, &tmp) != AUDIO_SUCCESS) {

		return (AUDIO_FAILURE);
	}

	if (audio1575_write_ac97(statep, AC97_RESET_REGISTER, 0xffff) !=
	    AUDIO_SUCCESS) {

		return (AUDIO_FAILURE);
	}

	if (audio1575_read_ac97(statep, AC97_RESET_REGISTER, &tmp) !=
	    AUDIO_SUCCESS) {

		return (AUDIO_FAILURE);
	}

	return (AUDIO_SUCCESS);

}	/* audio1575_reset_ac97() */

/*
 * audio1575_fill_play_buf()
 *
 * Description:
 *	This routine is called by m1575_ad_start_play() and the interrupt
 *	handler. It fills playback samples into the DMA memory, sets the
 *	BDL entries, and starts the playback DMA engine.
 *	the m1575_intr_mutex must be held on entry.
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 *
 * Returns:
 * 	AUDIO_SUCCESS		Starting PCM out engine successfully
 * 	AUDIO_FAILURE		Failed to start PCM out engine.
 */
static int
audio1575_fill_play_buf(audio1575_state_t *statep)
{
	m1575_bdlist_chunk_t	*chunk;
	m1575_sample_buf_t	*buf;
	m1575_bd_entry_t	*bdesc;
	int			samples;
	uint32_t		dmacr;
	int			rs;
	int			bufcount = 0;
	int			rc = AUDIO_SUCCESS;

	ASSERT(mutex_owned(&statep->m1575_intr_mutex));

	/* get the play buffer pointer */
	buf = &statep->m1575_play_buf;

	if (buf->avail == 0) {
		return (AUDIO_SUCCESS);
	}

	/* compute number of samples */
	samples = statep->m1575_psample_rate * statep->m1575_pchannels /
	    statep->m1575_ad_info.ad_play.ad_int_rate;

	/* if not an even number of samples we panic! */
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples & 1) != 0) {
		samples++;
	}

	while (buf->avail > 0) {
		chunk = &(buf->chunk[buf->tail & M1575_PLAY_BUF_MSK]);
		mutex_exit(&statep->m1575_intr_mutex);
		rs = am_get_audio(statep->m1575_ahandle,
		    (char *)(chunk->data_buf), AUDIO_NO_CHANNEL, samples);
		mutex_enter(&statep->m1575_intr_mutex);

		if (((statep->m1575_flags & M1575_DMA_PLAY_STARTED) == 0) &&
		    (buf->io_started)) {
			audio_sup_log(statep->m1575_ahandle, CE_WARN,
			    "!fill_play_buf() Err:PLAY started and IO started");
			ATRACE("audio1575_fill_play_buf() Err:PLAY STARTED "
			    "and IO STARTED", NULL);

			return (AUDIO_FAILURE);
		}
		/* no more samples to play */
		if (rs <= 0) {
			if (statep->m1575_flags & M1575_DMA_PLAY_EMPTY) {
				if (bufcount != 0) {
					break;
				}
				/*
				 * Clear the flag so if audio is restarted while
				 * in am_play_shutdown() we can detect it and
				 * not mess things up.
				 */
				statep->m1575_flags &= ~M1575_DMA_PLAY_STARTED;

				/* shutdown the mixer */
				mutex_exit(&statep->m1575_intr_mutex);
				am_play_shutdown(statep->m1575_ahandle, NULL);
				mutex_enter(&statep->m1575_intr_mutex);

				/*
				 * Make sure playing wasn't restarted when lock
				 * lost if reopened, should return success
				 */
				if (statep->m1575_flags &
				    M1575_DMA_PLAY_STARTED) {
					return (AUDIO_SUCCESS);
				}

				/* Finished playing, then stop it */
				rc = audio1575_dma_reset(statep,
				    M1575_DMA_PCM_OUT);
				if (rc == AUDIO_FAILURE) {
					ATRACE("audio1575_fill_play_buf() "
					    "dma_reset failure", rc);
					return (rc);
				}

				/* clear the PCM Out ctrl reg */
				M1575_AM_PUT8(M1575_PCMOCR_REG, 0);
				buf->io_started = B_FALSE;

				/* clr the flags getting ready for next start */
				statep->m1575_flags &= ~(M1575_DMA_PLAY_PAUSED |
				    M1575_DMA_PLAY_EMPTY);

				/* return the value for m1575_ad_start_play() */
				return (AUDIO_FAILURE);

			} else {
				/* M1575_DMA_PLAY_EMPTY */
				statep->m1575_flags |= M1575_DMA_PLAY_EMPTY;
			}
		} else {
			/* !M1575_DMA_PLAY_EMPTY */
			statep->m1575_flags &= ~M1575_DMA_PLAY_EMPTY;
			bufcount++;
			(void) ddi_dma_sync(chunk->dma_handle, 0, rs << 1,
			    DDI_DMA_SYNC_FORDEV);
		}

		/* put the samples into buffer descriptor list entry */
		bdesc = &(statep->m1575_bdl_virt_pout[buf->tail]);
		bdesc->buf_base = chunk->addr_phy;
		bdesc->buf_len = (uint16_t)rs;
		bdesc->buf_cmd |= IOC;
		M1575_AM_PUT8(M1575_PCMOLVIV_REG, buf->tail);
		buf->tail++;
		buf->tail &= M1575_BD_MSK;
		buf->avail--;
	}

	/* start PCM out engine */
	dmacr = M1575_AM_GET32(M1575_DMACR_REG);
	if (buf->avail < M1575_PLAY_BUFS &&
	    !(dmacr & M1575_DMACR_PCMOSTART)) {
		dmacr |= M1575_DMACR_PCMOSTART;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		ATRACE("audio1575_fill_play_buf() PLAY DMA STARTED", dmacr);
	}

	return (AUDIO_SUCCESS);

}	/* audio1575_fill_play_buf() */

/*
 * audio1575_prepare_record_buf()
 *
 * Description:
 *	This routine is called by audio1575_ad_start_record(). It prepares DMA
 *	memory for PCM in engine, sets the buffer descriptor entries for PCM
 *	in engine, and starts PCM in engine for recording.
 *
 * Arguments:
 *	audio1575_state_t *statep	 The device's state structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Started PCM in engine successfully
 *	AUDIO_FAILURE		Failed to start PCM in engine.
 */
static int
audio1575_prepare_record_buf(audio1575_state_t *statep)
{
	m1575_bdlist_chunk_t	*chunk;
	m1575_sample_buf_t	*buf;
	m1575_bd_entry_t	*bdesc;
	uint32_t		dmacr;
	int			samples;

	/* get the record buf ptr */
	buf = &statep->m1575_record_buf;

	if (buf->avail == 0) {
		return (AUDIO_SUCCESS);
	}

	samples = statep->m1575_csample_rate * statep->m1575_cchannels /
	    statep->m1575_ad_info.ad_record.ad_int_rate;

	/* if not an even number of samples we panic! */
	/* if stereo & sr = 11025 & ints = 50 then 441 samples, bad! - so fix */
	if ((samples & 1) != 0) {
		samples++;
	}

	statep->m1575_csamples = samples;

	while (buf->avail > 0) {
		chunk = &buf->chunk[buf->tail & M1575_REC_BUF_MSK];
		bdesc = &(statep->m1575_bdl_virt_pin[buf->tail]);
		bdesc->buf_base = chunk->addr_phy;
		bdesc->buf_len = (uint16_t)samples;
		bdesc->buf_cmd |= IOC;
		M1575_AM_PUT8(M1575_PCMILVIV_REG, buf->tail);
		buf->tail++;
		buf->tail &= M1575_BD_MSK;
		buf->avail--;
	}

	if (!buf->io_started) {
		buf->io_started = B_TRUE;
	}

	dmacr = M1575_AM_GET32(M1575_DMACR_REG);
	if ((buf->avail < M1575_REC_BUFS) && !(dmacr & M1575_DMACR_PCMISTART)) {
		/* start PCM In engine */
		dmacr |= M1575_DMACR_PCMISTART;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		ATRACE("audio1575_prepare_record_buf() "
		    "RECORD DMA STARTED", dmacr);
	}

	return (AUDIO_SUCCESS);

}	/* audio1575_prepare_record_buf() */

/*
 * audio1575_reclaim_record_buf()
 *
 * Description:
 *	This routine is called by the interrupt handler. It sends the PCM
 *	samples (record data) up to the mixer module by calling am_send_audio(),
 *	and reclaims the buffer descriptor entries for PCM in engine.
 *
 * Arguments:
 *	audio1575_state_t *statep	 The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio1575_reclaim_record_buf(audio1575_state_t *statep)
{
	m1575_bdlist_chunk_t 	*chunk;
	m1575_sample_buf_t	*buf;
	int16_t			pcmiciv;
	int			samples;

	/* get record buf ptr */
	buf = &statep->m1575_record_buf;

	/* get our current index value */
	pcmiciv = M1575_AM_GET8(M1575_PCMICIV_REG);

	/* get number of samples */
	samples = statep->m1575_csamples;

	/* While we have record buffers to process */
	while ((buf->head != pcmiciv && buf->avail < M1575_REC_BUFS)) {
		chunk = &buf->chunk[buf->head & M1575_REC_BUF_MSK];
		(void) ddi_dma_sync(chunk->dma_handle, 0,
		    chunk->real_len, DDI_DMA_SYNC_FORCPU);
		mutex_exit(&statep->m1575_intr_mutex);
		am_send_audio(statep->m1575_ahandle, chunk->data_buf,
		    AUDIO_NO_CHANNEL, samples);
		mutex_enter(&statep->m1575_intr_mutex);
		buf->avail++;
		buf->head++;
		buf->head &= M1575_BD_MSK;
		if ((statep->m1575_flags & M1575_DMA_RECD_STARTED) == 0) {
			break;
		}
	}

}	/* audio1575_reclaim_record_buf() */

/*
 * audio1575_pci_enable()
 *
 * Description:
 *	This routine Enables all PCI IO and MEMORY accesses
 *
 * Arguments:
 *	audio1575_state_t *statep	 The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio1575_pci_enable(audio1575_state_t *statep)
{
	uint16_t pcics_reg;

	ATRACE("audio1575_pci_enable() entering", statep);

	pcics_reg = pci_config_get16(statep->m1575_pci_regs_handle,
	    PCI_CONF_COMM);
	ATRACE("audio1575_pci_enable() PCICS Reg ", pcics_reg);
	pcics_reg |= (PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);
	pci_config_put16(statep->m1575_pci_regs_handle, PCI_CONF_COMM,
	    pcics_reg);

	ATRACE("audio1575_pci_enable() returning", pcics_reg);

}	/* audio1575_pci_enable() */

/*
 * audio1575_pci_disable()
 *
 * Description:
 *	This routine Disables all PCI IO and MEMORY accesses
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 *
 * Returns:
 *	void
 */
static void
audio1575_pci_disable(audio1575_state_t *statep)
{
	uint16_t pcics_reg;

	ATRACE("audio1575_pci_disable() entering", statep);

	pcics_reg = pci_config_get16(statep->m1575_pci_regs_handle,
	    PCI_CONF_COMM);
	pcics_reg &= ~(PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);
	pci_config_put16(statep->m1575_pci_regs_handle, PCI_CONF_COMM,
	    pcics_reg);

	ATRACE("audio1575_pci_disable() returning", pcics_reg);

}	/* audio1575_pci_disable() */

/*
 * audio1575_dma_pause()
 *
 * Description:
 *	This routine pauses DMA on a particular channel
 *	It does not reset andy registers so play/record can be resumed.
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 *	int 	chan			The DMA channel PCM_IN,PCM_OUT,MIC_IN
 *
 * Returns:
 *	AUDIO_SUCCESS		DMA paused successfully
 *	AUDIO_FAILURE		DMA failed to pause
 */
static int
audio1575_dma_pause(audio1575_state_t *statep, int chan)
{
	uint32_t dmacr;

	ATRACE("audio1575_dma_pause() entering", NULL);

	dmacr = M1575_AM_GET32(M1575_DMACR_REG);

	switch (chan) {
	case M1575_DMA_PCM_IN:
		dmacr |= M1575_DMACR_PCMIPAUSE;
		break;

	case M1575_DMA_PCM_OUT:
		dmacr |= M1575_DMACR_PCMOPAUSE;
		break;

	default:
		ATRACE("audio1575_dma_pause() bad channel", chan);

		return (AUDIO_FAILURE);
	}

	M1575_AM_PUT32(M1575_DMACR_REG, dmacr);

	ATRACE("audio1575_dma_pause() returning", AUDIO_SUCCESS);

	return (AUDIO_SUCCESS);

}	/* audio1575_dma_pause() */

/*
 * audio1575_dma_resume()
 *
 * Description:
 *	This routine resumes DMA on a particular channel
 *	It does not resume if the BDL list is empty.
 *
 * Arguments:
 *	audio1575_state_t	*statep	The device's state structure
 *	int 	chan		The DMA channel
 *				PCM_IN,PCM_OUT,MIC_IN
 *
 * Returns:
 *	AUDIO_SUCCESS		DMA resumed successfully
 *	AUDIO_FAILURE		DMA failed to resume
 */
static int
audio1575_dma_resume(audio1575_state_t *statep, int chan)
{
	uint32_t dmacr;
	uint32_t fifocr1;

	ATRACE("audio1575_dma_resume() entering", NULL);

	dmacr = M1575_AM_GET32(M1575_DMACR_REG);

	switch (chan) {
	case M1575_DMA_PCM_IN:
		/* ULi says do fifo resets here */
		fifocr1 = M1575_AM_GET32(M1575_FIFOCR1_REG);
		fifocr1 |= M1575_FIFOCR1_PCMIRST;
		M1575_AM_PUT32(M1575_FIFOCR1_REG, fifocr1);
		dmacr &= ~M1575_DMACR_PCMIPAUSE;
		dmacr |= M1575_DMACR_PCMISTART;
		break;

	case M1575_DMA_PCM_OUT:
		dmacr &= ~M1575_DMACR_PCMOPAUSE;
		dmacr |= M1575_DMACR_PCMOSTART;
		break;
	default:
		ATRACE("audio1575_dma_resume() bad channel", chan);

		return (AUDIO_FAILURE);
	}

	M1575_AM_PUT32(M1575_DMACR_REG, dmacr);

	ATRACE("audio1575_dma_resume() returning", AUDIO_SUCCESS);

	return (AUDIO_SUCCESS);

}	/* audio1575_dma_resume() */

/*
 * audio1575_dma reset()
 *
 * Description:
 *	This routine resets the DMA on a particular channel
 *	All DMA registers are RESET.
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 *	int chan			The DMA channel PCM_IN,PCM_OUT,MIC_IN
 *
 * Returns:
 *	AUDIO_SUCCESS		DMA reset successfully
 *	AUDIO_FAILURE		DMA failed to reset
 */
static int
audio1575_dma_reset(audio1575_state_t *statep, int chan)
{
	uint8_t		cr;
	uint32_t	fifocr1;
	uint32_t	dmacr;

	ATRACE("audio1575_dma_reset() entering", NULL);

	dmacr = M1575_AM_GET32(M1575_DMACR_REG);
	fifocr1 = M1575_AM_GET32(M1575_FIFOCR1_REG);

	switch (chan) {
	case M1575_DMA_PCM_IN:
		/* Uli FIFO madness ... */
		fifocr1 = M1575_AM_GET32(M1575_FIFOCR1_REG);
		fifocr1 |= M1575_FIFOCR1_PCMIRST;
		M1575_AM_PUT32(M1575_FIFOCR1_REG, fifocr1);
		dmacr |= M1575_DMACR_PCMIPAUSE;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		cr = M1575_AM_GET8(M1575_PCMICR_REG);
		cr |= M1575_PCMICR_RR;
		M1575_AM_PUT8(M1575_PCMICR_REG, cr);
		dmacr &= ~M1575_DMACR_PCMIPAUSE;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		break;

	case M1575_DMA_PCM_OUT:
		/* Uli FIFO madness ... */
		fifocr1 = M1575_AM_GET32(M1575_FIFOCR1_REG);
		fifocr1 |= M1575_FIFOCR1_PCMORST;
		M1575_AM_PUT32(M1575_FIFOCR1_REG, fifocr1);
		dmacr |= M1575_DMACR_PCMOPAUSE;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		cr = M1575_AM_GET8(M1575_PCMOCR_REG);
		cr |= M1575_PCMOCR_RR;
		M1575_AM_PUT8(M1575_PCMOCR_REG, cr);
		dmacr &= ~M1575_DMACR_PCMOPAUSE;
		M1575_AM_PUT32(M1575_DMACR_REG, dmacr);
		break;

	default:
		ATRACE("audio1575_dma_reset() bad channel", chan);

		return (AUDIO_FAILURE);
	}

	ATRACE("audio1575_dma_reset() returning", AUDIO_SUCCESS);

	return (AUDIO_SUCCESS);

}	/* audio1575_dma_reset() */
