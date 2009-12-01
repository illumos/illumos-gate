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
 * audioixp Audio Driver
 *
 * This driver supports audio hardware integrated in ATI IXP400 chipset.
 *
 * The IXP400 audio core is an AC'97 controller, which has independent
 * channels for PCM in, PCM out. The AC'97 controller is a PCI bus master
 * with scatter/gather support. Each channel has a DMA engine. Currently,
 * we use only the PCM in and PCM out channels. Each DMA engine uses one
 * buffer descriptor list.  Each entry contains a pointer to a data buffer,
 * status, length of the buffer being pointed to and the pointer to the next
 * entry. Length of the buffer is in number of bytes. Interrupt will be
 * triggered each time a entry is processed by hardware.
 *
 * System power management is not yet supported by the driver.
 *
 * 	NOTE:
 * 	This driver depends on the misc/ac97 and drv/audio modules being
 *	loaded first.
 */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>
#include "audioixp.h"

/*
 * Module linkage routines for the kernel
 */
static int audioixp_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int audioixp_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int audioixp_quiesce(dev_info_t *);
static int audioixp_resume(dev_info_t *);
static int audioixp_suspend(dev_info_t *);

/*
 * Entry point routine prototypes
 */
static int audioixp_open(void *, int, unsigned *, unsigned *, caddr_t *);
static void audioixp_close(void *);
static int audioixp_start(void *);
static void audioixp_stop(void *);
static int audioixp_format(void *);
static int audioixp_channels(void *);
static int audioixp_rate(void *);
static uint64_t audioixp_count(void *);
static void audioixp_sync(void *, unsigned);

static audio_engine_ops_t audioixp_engine_ops = {
	AUDIO_ENGINE_VERSION,
	audioixp_open,
	audioixp_close,
	audioixp_start,
	audioixp_stop,
	audioixp_count,
	audioixp_format,
	audioixp_channels,
	audioixp_rate,
	audioixp_sync,
	NULL,
	NULL,
	NULL
};


/*
 * interrupt handler
 */
static uint_t	audioixp_intr(caddr_t);

/*
 * Local Routine Prototypes
 */
static int audioixp_attach(dev_info_t *);
static int audioixp_detach(dev_info_t *);
static int audioixp_alloc_port(audioixp_state_t *, int);
static void audioixp_start_port(audioixp_port_t *);
static void audioixp_stop_port(audioixp_port_t *);
static void audioixp_reset_port(audioixp_port_t *);
static void audioixp_update_port(audioixp_port_t *);

static int audioixp_codec_sync(audioixp_state_t *);
static void audioixp_wr97(void *, uint8_t, uint16_t);
static uint16_t audioixp_rd97(void *, uint8_t);
static int audioixp_reset_ac97(audioixp_state_t *);
static int audioixp_map_regs(audioixp_state_t *);
static void audioixp_unmap_regs(audioixp_state_t *);
static int audioixp_chip_init(audioixp_state_t *);
static void audioixp_destroy(audioixp_state_t *);

/*
 * Global variables, but used only by this file.
 */

/*
 * DDI Structures
 */

/* Device operations structure */
static struct dev_ops audioixp_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audioixp_ddi_attach,	/* devo_attach */
	audioixp_ddi_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	audioixp_quiesce,	/* devo_quiesce */
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

/*
 * device access attributes for register mapping
 */
static struct ddi_device_acc_attr dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};
static struct ddi_device_acc_attr buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
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
	4,		/* align, data buffer is aligned on a 2-byte boundary */
	0x3c,		/* burstsize */
	4,		/* minxfer, set to the size of a sample data */
	0x0001ffff,	/* maxxfer */
	0x0001ffff,	/* seg */
	1,		/* sgllen, no scatter-gather */
	4,		/* granular, set to the value of minxfer */
	0,		/* flags, use virtual address */
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

	audio_init_ops(&audioixp_dev_ops, IXP_NAME);

	if ((error = mod_install(&audioixp_modlinkage)) != 0) {
		audio_fini_ops(&audioixp_dev_ops);
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

	if ((error = mod_remove(&audioixp_modlinkage)) != 0) {
		return (error);
	}

	audio_fini_ops(&audioixp_dev_ops);

	return (0);
}

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
	return (mod_info(&audioixp_modlinkage, modinfop));
}


/* ******************* Driver Entry Points ********************************* */

/*
 * audioixp_ddi_attach()
 *
 * Description:
 *	Attach an instance of the audioixp driver.
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
audioixp_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (audioixp_attach(dip));

	/*
	 * now, no suspend/resume supported. we'll do it in the future.
	 */
	case DDI_RESUME:
		return (audioixp_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

/*
 * audioixp_ddi_detach()
 *
 * Description:
 *	Detach an instance of the audioixp driver.
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
audioixp_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (audioixp_detach(dip));

	/*
	 * now, no suspend/resume supported. we'll do it in the future.
	 */
	case DDI_SUSPEND:
		return (audioixp_suspend(dip));

	default:
		return (DDI_FAILURE);
	}
}

static void
audioixp_stop_dma(audioixp_state_t *statep)
{
	CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT_DMA);
	CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN_DMA);
}

static void
audioixp_disable_intr(audioixp_state_t *statep)
{
	PUT32(IXP_AUDIO_INT, GET32(IXP_AUDIO_INT));
	PUT32(IXP_AUDIO_INT_EN, 0);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
audioixp_quiesce(dev_info_t *dip)
{
	audioixp_state_t		*statep;

	statep = ddi_get_driver_private(dip);
	ASSERT(statep != NULL);

	/* disable HW interrupt */
	audioixp_disable_intr(statep);

	/* stop DMA engines */
	audioixp_stop_dma(statep);

	return (DDI_SUCCESS);
}

static int
audioixp_suspend(dev_info_t *dip)
{
	audioixp_state_t		*statep;

	statep = ddi_get_driver_private(dip);
	ASSERT(statep != NULL);

	ac97_suspend(statep->ac97);
	mutex_enter(&statep->inst_lock);

	statep->suspended = B_TRUE;

	audioixp_disable_intr(statep);
	audioixp_stop_dma(statep);

	mutex_exit(&statep->inst_lock);
	return (DDI_SUCCESS);
}

static void
audioixp_resume_port(audioixp_port_t *port)
{
	if (port != NULL) {
		if (port->engine != NULL) {
			audio_engine_reset(port->engine);
		}
	}
	audioixp_reset_port(port);
	if (port->started) {
		audioixp_start_port(port);
	} else {
		audioixp_stop_port(port);
	}
}

static int
audioixp_resume(dev_info_t *dip)
{
	audioixp_state_t		*statep;
	audio_dev_t			*adev;
	audioixp_port_t			*rec_port, *play_port;

	statep = ddi_get_driver_private(dip);
	adev = statep->adev;
	ASSERT(statep != NULL);

	if (audioixp_chip_init(statep) != DDI_SUCCESS) {
		audio_dev_warn(adev, "DDI_RESUME failed to init chip");
		return (DDI_SUCCESS);
	}

	ac97_resume(statep->ac97);
	mutex_enter(&statep->inst_lock);
	statep->suspended = B_FALSE;

	rec_port = statep->rec_port;
	play_port = statep->play_port;

	audioixp_resume_port(rec_port);
	audioixp_resume_port(play_port);

	mutex_exit(&statep->inst_lock);
	return (DDI_SUCCESS);
}
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
	int			claimed = DDI_INTR_UNCLAIMED;

	statep = (void *)arg;
	mutex_enter(&statep->inst_lock);

	sr = GET32(IXP_AUDIO_INT);

	/* PCM in interrupt */
	if (sr & IXP_AUDIO_INT_IN_DMA) {
		claimed = DDI_INTR_CLAIMED;
		PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_IN_DMA);
	}

	/* PCM out interrupt */
	if (sr & IXP_AUDIO_INT_OUT_DMA) {
		claimed = DDI_INTR_CLAIMED;
		PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_OUT_DMA);
	}

	/* system is too busy to process the input stream, ignore it */
	if (sr & IXP_AUDIO_INT_IN_DMA_OVERFLOW) {
		claimed = DDI_INTR_CLAIMED;
		PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_IN_DMA_OVERFLOW);
	}

	/* System is too busy, ignore it */
	if (sr & IXP_AUDIO_INT_OUT_DMA_UNDERFLOW) {
		claimed = DDI_INTR_CLAIMED;
		PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_OUT_DMA_UNDERFLOW);
	}

	/* update the kernel interrupt statistics */
	if ((claimed == DDI_INTR_CLAIMED) && statep->ksp) {
		IXP_KIOP(statep)->intrs[KSTAT_INTR_HARD]++;
	}

	mutex_exit(&statep->inst_lock);

	if (sr & IXP_AUDIO_INT_IN_DMA) {
		audio_engine_produce(statep->rec_port->engine);
	}
	if (sr & IXP_AUDIO_INT_OUT_DMA) {
		audio_engine_consume(statep->play_port->engine);
	}

	return (claimed);
}

/*
 * audioixp_open()
 *
 * Description:
 *	Opens a DMA engine for use.
 *
 * Arguments:
 *	void		*arg		The DMA engine to set up
 *	int		flag		Open flags
 *	unsigned	*fragfrp	Receives number of frames per fragment
 *	unsigned	*nfragsp	Receives number of fragments
 *	caddr_t		*bufp		Receives kernel data buffer
 *
 * Returns:
 *	0	on success
 *	errno	on failure
 */
static int
audioixp_open(void *arg, int flag,
    unsigned *fragfrp, unsigned *nfragsp, caddr_t *bufp)
{
	audioixp_port_t	*port = arg;

	_NOTE(ARGUNUSED(flag));

	port->started = B_FALSE;
	port->count = 0;
	port->offset = 0;
	*fragfrp = port->fragfr;
	*nfragsp = IXP_BD_NUMS;
	*bufp = port->samp_kaddr;

	mutex_enter(&port->statep->inst_lock);
	audioixp_reset_port(port);
	mutex_exit(&port->statep->inst_lock);

	return (0);
}

/*
 * audioixp_close()
 *
 * Description:
 *	Closes an audio DMA engine that was previously opened.  Since
 *	nobody is using it, we take this opportunity to possibly power
 *	down the entire device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to shut down
 */
static void
audioixp_close(void *arg)
{
	audioixp_port_t		*port = arg;
	audioixp_state_t	*statep = port->statep;

	mutex_enter(&statep->inst_lock);
	audioixp_stop_port(port);
	port->started = B_FALSE;
	mutex_exit(&statep->inst_lock);
}

/*
 * audioixp_stop()
 *
 * Description:
 *	This is called by the framework to stop a port that is
 *	transferring data.
 *
 * Arguments:
 *	void	*arg		The DMA engine to stop
 */
static void
audioixp_stop(void *arg)
{
	audioixp_port_t		*port = arg;
	audioixp_state_t	*statep = port->statep;

	mutex_enter(&statep->inst_lock);
	if (port->started) {
		audioixp_stop_port(port);
	}
	port->started = B_FALSE;
	mutex_exit(&statep->inst_lock);
}

/*
 * audioixp_start()
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
audioixp_start(void *arg)
{
	audioixp_port_t		*port = arg;
	audioixp_state_t	*statep = port->statep;

	mutex_enter(&statep->inst_lock);
	if (!port->started) {
		audioixp_start_port(port);
		port->started = B_TRUE;
	}
	mutex_exit(&statep->inst_lock);
	return (0);
}

/*
 * audioixp_format()
 *
 * Description:
 *	This is called by the framework to query the format for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	AUDIO_FORMAT_S16_LE
 */
static int
audioixp_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

/*
 * audioixp_channels()
 *
 * Description:
 *	This is called by the framework to query the channels for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	Number of channels for the device.
 */
static int
audioixp_channels(void *arg)
{
	audioixp_port_t *port = arg;

	return (port->nchan);
}

/*
 * audioixp_rate()
 *
 * Description:
 *	This is called by the framework to query the rate of the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	48000
 */
static int
audioixp_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

/*
 * audioixp_count()
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
audioixp_count(void *arg)
{
	audioixp_port_t		*port = arg;
	audioixp_state_t	*statep = port->statep;
	uint64_t		val;

	mutex_enter(&statep->inst_lock);
	audioixp_update_port(port);
	val = port->count;
	mutex_exit(&statep->inst_lock);

	return (val);
}

/*
 * audioixp_sync()
 *
 * Description:
 *	This is called by the framework to synchronize DMA caches.
 *
 * Arguments:
 *	void	*arg		The DMA engine to sync
 */
static void
audioixp_sync(void *arg, unsigned nframes)
{
	audioixp_port_t *port = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->samp_dmah, 0, 0, port->sync_dir);
}

/* *********************** Local Routines *************************** */

/*
 * audioixp_alloc_port()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use.  It also configures the BDL lists properly
 *	for use.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's devinfo
 *
 * Returns:
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
audioixp_alloc_port(audioixp_state_t *statep, int num)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	unsigned		caps;
	char			*prop;
	audio_dev_t		*adev;
	audioixp_port_t		*port;
	uint32_t		paddr;
	int			rc;
	dev_info_t		*dip;
	audioixp_bd_entry_t	*bdentry;

	adev = statep->adev;
	dip = statep->dip;

	port = kmem_zalloc(sizeof (*port), KM_SLEEP);
	port->statep = statep;
	port->started = B_FALSE;
	port->num = num;

	switch (num) {
	case IXP_REC:
		statep->rec_port = port;
		prop = "record-interrupts";
		dir = DDI_DMA_READ;
		caps = ENGINE_INPUT_CAP;
		port->sync_dir = DDI_DMA_SYNC_FORKERNEL;
		port->nchan = 2;
		break;
	case IXP_PLAY:
		statep->play_port = port;
		prop = "play-interrupts";
		dir = DDI_DMA_WRITE;
		caps = ENGINE_OUTPUT_CAP;
		port->sync_dir = DDI_DMA_SYNC_FORDEV;
		/* This could possibly be conditionalized */
		port->nchan = 6;
		break;
	default:
		audio_dev_warn(adev, "bad port number (%d)!", num);
		return (DDI_FAILURE);
	}

	port->intrs = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, prop, IXP_INTS);

	/* make sure the values are good */
	if (port->intrs < IXP_MIN_INTS) {
		audio_dev_warn(adev, "%s too low, %d, resetting to %d",
		    prop, port->intrs, IXP_INTS);
		port->intrs = IXP_INTS;
	} else if (port->intrs > IXP_MAX_INTS) {
		audio_dev_warn(adev, "%s too high, %d, resetting to %d",
		    prop, port->intrs, IXP_INTS);
		port->intrs = IXP_INTS;
	}

	/*
	 * Figure out how much space we need.  Sample rate is 48kHz, and
	 * we need to store 8 chunks.  (Note that this means that low
	 * interrupt frequencies will require more RAM.)
	 */
	port->fragfr = 48000 / port->intrs;
	port->fragfr = IXP_ROUNDUP(port->fragfr, IXP_MOD_SIZE);
	port->fragsz = port->fragfr * port->nchan * 2;
	port->samp_size = port->fragsz * IXP_BD_NUMS;

	/* allocate dma handle */
	rc = ddi_dma_alloc_handle(dip, &sample_buf_dma_attr, DDI_DMA_SLEEP,
	    NULL, &port->samp_dmah);
	if (rc != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_dma_alloc_handle failed: %d", rc);
		return (DDI_FAILURE);
	}
	/* allocate DMA buffer */
	rc = ddi_dma_mem_alloc(port->samp_dmah, port->samp_size, &buf_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &port->samp_kaddr,
	    &port->samp_size, &port->samp_acch);
	if (rc == DDI_FAILURE) {
		audio_dev_warn(adev, "dma_mem_alloc failed");
		return (DDI_FAILURE);
	}

	/* bind DMA buffer */
	rc = ddi_dma_addr_bind_handle(port->samp_dmah, NULL,
	    port->samp_kaddr, port->samp_size, dir|DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &cookie, &count);
	if ((rc != DDI_DMA_MAPPED) || (count != 1)) {
		audio_dev_warn(adev,
		    "ddi_dma_addr_bind_handle failed: %d", rc);
		return (DDI_FAILURE);
	}
	port->samp_paddr = cookie.dmac_address;

	/*
	 * now, from here we allocate DMA memory for buffer descriptor list.
	 * we allocate adjacent DMA memory for all DMA engines.
	 */
	rc = ddi_dma_alloc_handle(dip, &bdlist_dma_attr, DDI_DMA_SLEEP,
	    NULL, &port->bdl_dmah);
	if (rc != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_dma_alloc_handle(bdlist) failed");
		return (DDI_FAILURE);
	}

	/*
	 * we allocate all buffer descriptors lists in continuous dma memory.
	 */
	port->bdl_size = sizeof (audioixp_bd_entry_t) * IXP_BD_NUMS;
	rc = ddi_dma_mem_alloc(port->bdl_dmah, port->bdl_size,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &port->bdl_kaddr, &port->bdl_size, &port->bdl_acch);
	if (rc != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_dma_mem_alloc(bdlist) failed");
		return (DDI_FAILURE);
	}

	rc = ddi_dma_addr_bind_handle(port->bdl_dmah, NULL, port->bdl_kaddr,
	    port->bdl_size, DDI_DMA_WRITE|DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &cookie, &count);
	if ((rc != DDI_DMA_MAPPED) || (count != 1)) {
		audio_dev_warn(adev, "addr_bind_handle failed");
		return (DDI_FAILURE);
	}
	port->bdl_paddr = cookie.dmac_address;

	/*
	 * Wire up the BD list.
	 */
	paddr = port->samp_paddr;
	bdentry = (void *)port->bdl_kaddr;

	for (int i = 0; i < IXP_BD_NUMS; i++) {

		/* set base address of buffer */
		ddi_put32(port->bdl_acch, &bdentry->buf_base, paddr);
		ddi_put16(port->bdl_acch, &bdentry->status, 0);
		ddi_put16(port->bdl_acch, &bdentry->buf_len, port->fragsz / 4);
		ddi_put32(port->bdl_acch, &bdentry->next, port->bdl_paddr +
		    (((i + 1) % IXP_BD_NUMS) * sizeof (audioixp_bd_entry_t)));
		paddr += port->fragsz;
		bdentry++;
	}
	(void) ddi_dma_sync(port->bdl_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	port->engine = audio_engine_alloc(&audioixp_engine_ops, caps);
	if (port->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(port->engine, port);
	audio_dev_add_engine(adev, port->engine);

	return (DDI_SUCCESS);
}

/*
 * audioixp_free_port()
 *
 * Description:
 *	This routine unbinds the DMA cookies, frees the DMA buffers,
 *	deallocates the DMA handles.
 *
 * Arguments:
 *	audioixp_port_t	*port	The port structure for a DMA engine.
 */
static void
audioixp_free_port(audioixp_port_t *port)
{
	if (port == NULL)
		return;

	if (port->engine) {
		audio_dev_remove_engine(port->statep->adev, port->engine);
		audio_engine_free(port->engine);
	}
	if (port->bdl_paddr) {
		(void) ddi_dma_unbind_handle(port->bdl_dmah);
	}
	if (port->bdl_acch) {
		ddi_dma_mem_free(&port->bdl_acch);
	}
	if (port->bdl_dmah) {
		ddi_dma_free_handle(&port->bdl_dmah);
	}
	if (port->samp_paddr) {
		(void) ddi_dma_unbind_handle(port->samp_dmah);
	}
	if (port->samp_acch) {
		ddi_dma_mem_free(&port->samp_acch);
	}
	if (port->samp_dmah) {
		ddi_dma_free_handle(&port->samp_dmah);
	}
	kmem_free(port, sizeof (*port));
}

/*
 * audioixp_start_port()
 *
 * Description:
 *	This routine starts the DMA engine.
 *
 * Arguments:
 *	audioixp_port_t	*port		Port of DMA engine to start.
 */
static void
audioixp_start_port(audioixp_port_t *port)
{
	audioixp_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->inst_lock));

	/* if suspended, then do nothing else */
	if (statep->suspended) {
		return;
	}

	if (port->num == IXP_REC) {
		SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN);
	} else {
		SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT);
	}
}

/*
 * audioixp_stop_port()
 *
 * Description:
 *	This routine stops the DMA engine.
 *
 * Arguments:
 *	audioixp_port_t	*port		Port of DMA engine to stop.
 */
static void
audioixp_stop_port(audioixp_port_t *port)
{
	audioixp_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->inst_lock));

	/* if suspended, then do nothing else */
	if (statep->suspended) {
		return;
	}
	if (port->num == IXP_REC) {
		CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN);
	} else {
		CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT);
	}
}

/*
 * audioixp_reset_port()
 *
 * Description:
 *	This routine resets the DMA engine pareparing it for work.
 *
 * Arguments:
 *	audioixp_port_t	*port		Port of DMA engine to reset.
 */
static void
audioixp_reset_port(audioixp_port_t *port)
{
	audioixp_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->inst_lock));

	/*
	 * XXX: reset counters.
	 */
	port->count = 0;

	if (statep->suspended)
		return;

	/*
	 * Perform full reset of the engine, and enable its interrupts
	 * but leave it turned off.
	 */
	if (port->num == IXP_REC) {
		PUT32(IXP_AUDIO_FIFO_FLUSH, IXP_AUDIO_FIFO_FLUSH_IN);
		SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_INTER_IN);

		SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN_DMA);
		PUT32(IXP_AUDIO_IN_DMA_LINK_P,
		    port->bdl_paddr | IXP_AUDIO_IN_DMA_LINK_P_EN);

	} else {
		uint32_t slot = GET32(IXP_AUDIO_OUT_DMA_SLOT_EN_THRESHOLD);
		PUT32(IXP_AUDIO_FIFO_FLUSH, IXP_AUDIO_FIFO_FLUSH_OUT);
		/* clear all slots */
		slot &= ~ (IXP_AUDIO_OUT_DMA_SLOT_3 |
		    IXP_AUDIO_OUT_DMA_SLOT_4 |
		    IXP_AUDIO_OUT_DMA_SLOT_5 |
		    IXP_AUDIO_OUT_DMA_SLOT_6 |
		    IXP_AUDIO_OUT_DMA_SLOT_7 |
		    IXP_AUDIO_OUT_DMA_SLOT_8 |
		    IXP_AUDIO_OUT_DMA_SLOT_9 |
		    IXP_AUDIO_OUT_DMA_SLOT_10 |
		    IXP_AUDIO_OUT_DMA_SLOT_11 |
		    IXP_AUDIO_OUT_DMA_SLOT_12);
		/* enable 6 channel out, unconditional for now */
		slot |= IXP_AUDIO_OUT_DMA_SLOT_3 |
		    IXP_AUDIO_OUT_DMA_SLOT_4 |
		    IXP_AUDIO_OUT_DMA_SLOT_6 |
		    IXP_AUDIO_OUT_DMA_SLOT_9 |
		    IXP_AUDIO_OUT_DMA_SLOT_7 |
		    IXP_AUDIO_OUT_DMA_SLOT_8;

		PUT32(IXP_AUDIO_OUT_DMA_SLOT_EN_THRESHOLD, slot);

		SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_INTER_OUT);

		SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT_DMA);
		PUT32(IXP_AUDIO_OUT_DMA_LINK_P,
		    port->bdl_paddr | IXP_AUDIO_OUT_DMA_LINK_P_EN);
	}
}

/*
 * audioixp_update_port()
 *
 * Description:
 *	This routine updates the ports frame counter from hardware, and
 *	gracefully handles wraps.
 *
 * Arguments:
 *	audioixp_port_t	*port		The port to update.
 */
static void
audioixp_update_port(audioixp_port_t *port)
{
	audioixp_state_t	*statep = port->statep;
	unsigned		regoff;
	unsigned		n;
	int			loop;
	uint32_t		offset;
	uint32_t		paddr;

	if (statep->suspended) {
		return;
	}
	if (port->num == IXP_REC) {
		regoff = IXP_AUDIO_IN_DMA_DT_CUR;
	} else {
		regoff = IXP_AUDIO_OUT_DMA_DT_CUR;
	}

	/*
	 * Apparently it may take several tries to get an update on the
	 * position.  Is this a hardware bug?
	 */
	for (loop = 100; loop; loop--) {
		paddr = GET32(regoff);

		/* make sure address is reasonable */
		if ((paddr < port->samp_paddr) ||
		    (paddr >= (port->samp_paddr + port->samp_size))) {
			continue;
		}

		offset = paddr - port->samp_paddr;

		if (offset >= port->offset) {
			n = offset - port->offset;
		} else {
			n = offset + (port->samp_size - port->offset);
		}
		port->offset = offset;
		port->count += (n / (port->nchan * sizeof (uint16_t)));
		return;
	}

	audio_dev_warn(statep->adev, "Unable to update count (h/w bug?)");
}


/*
 * audioixp_map_regs()
 *
 * Description:
 *	The registers are mapped in.
 *
 * Arguments:
 *	audioixp_state_t	*state		  The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
audioixp_map_regs(audioixp_state_t *statep)
{
	dev_info_t		*dip = statep->dip;

	/* map PCI config space */
	if (pci_config_setup(statep->dip, &statep->pcih) == DDI_FAILURE) {
		audio_dev_warn(statep->adev, "unable to map PCI config space");
		return (DDI_FAILURE);
	}

	/* map audio mixer register */
	if ((ddi_regs_map_setup(dip, IXP_IO_AM_REGS, &statep->regsp, 0, 0,
	    &dev_attr, &statep->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "unable to map audio registers");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * audioixp_unmap_regs()
 *
 * Description:
 *	This routine unmaps control registers.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 */
static void
audioixp_unmap_regs(audioixp_state_t *statep)
{
	if (statep->regsh) {
		ddi_regs_map_free(&statep->regsh);
	}

	if (statep->pcih) {
		pci_config_teardown(&statep->pcih);
	}
}

/*
 * audioixp_codec_ready()
 *
 * Description:
 *	This routine checks the state of codecs.  It checks the flag to confirm
 *	that primary codec is ready.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS	 codec is ready
 *	DDI_FAILURE	 codec is not ready
 */
static int
audioixp_codec_ready(audioixp_state_t *statep)
{
	uint32_t	sr;

	PUT32(IXP_AUDIO_INT, 0xffffffff);
	drv_usecwait(1000);

	sr = GET32(IXP_AUDIO_INT);
	if (sr & IXP_AUDIO_INT_CODEC0_NOT_READY) {
		PUT32(IXP_AUDIO_INT, IXP_AUDIO_INT_CODEC0_NOT_READY);
		audio_dev_warn(statep->adev, "primary codec not ready");

		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
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
 *	DDI_SUCCESS		Ready for an I/O access to the codec
 *	DDI_FAILURE		An I/O access is currently in progress, can't
 *				perform another I/O access.
 */
static int
audioixp_codec_sync(audioixp_state_t *statep)
{
	int 		i;
	uint32_t	cmd;

	for (i = 0; i < 300; i++) {
		cmd = GET32(IXP_AUDIO_OUT_PHY_ADDR_DATA);
		if (!(cmd & IXP_AUDIO_OUT_PHY_EN)) {
			return (DDI_SUCCESS);
		}
		drv_usecwait(10);
	}

	audio_dev_warn(statep->adev, "unable to synchronize codec");
	return (DDI_FAILURE);
}

/*
 * audioixp_rd97()
 *
 * Description:
 *	Get the specific AC97 Codec register.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint8_t		reg		AC97 register number
 *
 * Returns:
 *	Register value.
 */
static uint16_t
audioixp_rd97(void *arg, uint8_t reg)
{
	audioixp_state_t	*statep = arg;
	uint32_t		value;
	uint32_t		result;

	if (audioixp_codec_sync(statep) != DDI_SUCCESS)
		return (0xffff);

	value = IXP_AUDIO_OUT_PHY_PRIMARY_CODEC |
	    IXP_AUDIO_OUT_PHY_READ |
	    IXP_AUDIO_OUT_PHY_EN |
	    ((unsigned)reg << IXP_AUDIO_OUT_PHY_ADDR_SHIFT);
	PUT32(IXP_AUDIO_OUT_PHY_ADDR_DATA, value);

	if (audioixp_codec_sync(statep) != DDI_SUCCESS)
		return (0xffff);

	for (int i = 0; i < 300; i++) {
		result = GET32(IXP_AUDIO_IN_PHY_ADDR_DATA);
		if (result & IXP_AUDIO_IN_PHY_READY)	{
			return (result >> IXP_AUDIO_IN_PHY_DATA_SHIFT);
		}
		drv_usecwait(10);
	}

done:
	audio_dev_warn(statep->adev, "time out reading codec reg %d", reg);
	return (0xffff);
}

/*
 * audioixp_wr97()
 *
 * Description:
 *	Set the specific AC97 Codec register.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint8_t		reg		AC97 register number
 *	uint16_t	data		The data want to be set
 */
static void
audioixp_wr97(void *arg, uint8_t reg, uint16_t data)
{
	audioixp_state_t	*statep = arg;
	uint32_t		value;

	if (audioixp_codec_sync(statep) != DDI_SUCCESS) {
		return;
	}

	value = IXP_AUDIO_OUT_PHY_PRIMARY_CODEC |
	    IXP_AUDIO_OUT_PHY_WRITE |
	    IXP_AUDIO_OUT_PHY_EN |
	    ((unsigned)reg << IXP_AUDIO_OUT_PHY_ADDR_SHIFT) |
	    ((unsigned)data << IXP_AUDIO_OUT_PHY_DATA_SHIFT);
	PUT32(IXP_AUDIO_OUT_PHY_ADDR_DATA, value);

	(void) audioixp_rd97(statep, reg);
}

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
 *	DDI_SUCCESS		Reset the codec successfully
 *	DDI_FAILURE		Failed to reset the codec
 */
static int
audioixp_reset_ac97(audioixp_state_t *statep)
{
	uint32_t	cmd;
	int i;

	CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_POWER_DOWN);
	drv_usecwait(10);

	/* register reset */
	SET32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_AC_SOFT_RESET);
	/* force a read to flush caches */
	(void) GET32(IXP_AUDIO_CMD);

	drv_usecwait(10);
	CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_AC_SOFT_RESET);

	/* cold reset */
	for (i = 0; i < 300; i++) {
		cmd = GET32(IXP_AUDIO_CMD);
		if (cmd & IXP_AUDIO_CMD_AC_ACTIVE) {
			cmd |= IXP_AUDIO_CMD_AC_RESET | IXP_AUDIO_CMD_AC_SYNC;
			PUT32(IXP_AUDIO_CMD, cmd);
			return (DDI_SUCCESS);
		}
		cmd &= ~IXP_AUDIO_CMD_AC_RESET;
		cmd |= IXP_AUDIO_CMD_AC_SYNC;
		PUT32(IXP_AUDIO_CMD, cmd);
		(void) GET32(IXP_AUDIO_CMD);
		drv_usecwait(10);
		cmd |= IXP_AUDIO_CMD_AC_RESET;
		PUT32(IXP_AUDIO_CMD, cmd);
		drv_usecwait(10);
	}

	audio_dev_warn(statep->adev, "AC'97 reset timed out");
	return (DDI_FAILURE);
}

/*
 * audioixp_chip_init()
 *
 * Description:
 *	This routine initializes ATI IXP audio controller and the AC97
 *	codec.
 *
 * Arguments:
 *	audioixp_state_t	*state		The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS	The hardware was initialized properly
 *	DDI_FAILURE	The hardware couldn't be initialized properly
 */
static int
audioixp_chip_init(audioixp_state_t *statep)
{
	/*
	 * put the audio controller into quiet state, everything off
	 */
	CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT_DMA);
	CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN_DMA);

	/* AC97 reset */
	if (audioixp_reset_ac97(statep) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "AC97 codec reset failed");
		return (DDI_FAILURE);
	}

	if (audioixp_codec_ready(statep) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "AC97 codec not ready");
		return (DDI_FAILURE);
	}

	/* enable interrupts */
	PUT32(IXP_AUDIO_INT, 0xffffffff);
	PUT32(
	    IXP_AUDIO_INT_EN,
	    IXP_AUDIO_INT_EN_IN_DMA_OVERFLOW |
	    IXP_AUDIO_INT_EN_STATUS |
	    IXP_AUDIO_INT_EN_OUT_DMA_UNDERFLOW);
	return (DDI_SUCCESS);

}	/* audioixp_chip_init() */

/*
 * audioixp_attach()
 *
 * Description:
 *	Attach an instance of the audioixp driver. This routine does
 * 	the device dependent attach tasks.
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
audioixp_attach(dev_info_t *dip)
{
	uint16_t		cmdeg;
	audioixp_state_t	*statep;
	audio_dev_t		*adev;
	uint32_t		devid;
	const char		*name;
	const char		*rev;

	/* we don't support high level interrupts in the driver */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		cmn_err(CE_WARN,
		    "!%s%d: unsupported high level interrupt",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/* allocate the soft state structure */
	statep = kmem_zalloc(sizeof (*statep), KM_SLEEP);
	statep->dip = dip;
	ddi_set_driver_private(dip, statep);

	if (ddi_get_iblock_cookie(dip, 0, &statep->iblock) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s%d: cannot get iblock cookie",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		kmem_free(statep, sizeof (*statep));
		return (DDI_FAILURE);
	}
	mutex_init(&statep->inst_lock, NULL, MUTEX_DRIVER, statep->iblock);

	/* allocate framework audio device */
	if ((adev = audio_dev_alloc(dip, 0)) == NULL) {
		cmn_err(CE_WARN, "!%s%d: unable to allocate audio dev",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto error;
	}
	statep->adev = adev;

	/* map in the registers */
	if (audioixp_map_regs(statep) != DDI_SUCCESS) {
		audio_dev_warn(adev, "couldn't map registers");
		goto error;
	}

	/* set device information -- this could be smarter */
	devid = ((pci_config_get16(statep->pcih, PCI_CONF_VENID)) << 16) |
	    pci_config_get16(statep->pcih, PCI_CONF_DEVID);

	name = "ATI AC'97";
	switch (devid) {
	case IXP_PCI_ID_200:
		rev = "IXP150";
		break;
	case IXP_PCI_ID_300:
		rev = "SB300";
		break;
	case IXP_PCI_ID_400:
		if (pci_config_get8(statep->pcih, PCI_CONF_REVID) & 0x80) {
			rev = "SB450";
		} else {
			rev = "SB400";
		}
		break;
	case IXP_PCI_ID_SB600:
		rev = "SB600";
		break;
	default:
		rev = "Unknown";
		break;
	}
	audio_dev_set_description(adev, name);
	audio_dev_set_version(adev, rev);

	/* allocate port structures */
	if ((audioixp_alloc_port(statep, IXP_PLAY) != DDI_SUCCESS) ||
	    (audioixp_alloc_port(statep, IXP_REC) != DDI_SUCCESS)) {
		goto error;
	}

	statep->ac97 = ac97_alloc(dip, audioixp_rd97, audioixp_wr97, statep);
	if (statep->ac97 == NULL) {
		audio_dev_warn(adev, "failed to allocate ac97 handle");
		goto error;
	}

	/* set PCI command register */
	cmdeg = pci_config_get16(statep->pcih, PCI_CONF_COMM);
	pci_config_put16(statep->pcih, PCI_CONF_COMM,
	    cmdeg | PCI_COMM_IO | PCI_COMM_MAE);

	/* set up kernel statistics */
	if ((statep->ksp = kstat_create(IXP_NAME, ddi_get_instance(dip),
	    IXP_NAME, "controller", KSTAT_TYPE_INTR, 1,
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->ksp);
	}


	if (audioixp_chip_init(statep) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "failed to init chip");
		goto error;
	}

	/* initialize the AC'97 part */
	if (ac97_init(statep->ac97, adev) != DDI_SUCCESS) {
		audio_dev_warn(adev, "ac'97 initialization failed");
		goto error;
	}

	/* set up the interrupt handler */
	if (ddi_add_intr(dip, 0, &statep->iblock, NULL, audioixp_intr,
	    (caddr_t)statep) != DDI_SUCCESS) {
		audio_dev_warn(adev, "bad interrupt specification");
	}
	statep->intr_added = B_TRUE;

	if (audio_dev_register(adev) != DDI_SUCCESS) {
		audio_dev_warn(adev, "unable to register with framework");
		goto error;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	audioixp_destroy(statep);
	return (DDI_FAILURE);
}

/*
 * audioixp_detach()
 *
 * Description:
 *	Detach an instance of the audioixp driver.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS	The driver was detached
 *	DDI_FAILURE	The driver couldn't be detached
 */
static int
audioixp_detach(dev_info_t *dip)
{
	audioixp_state_t	*statep;

	statep = ddi_get_driver_private(dip);

	if (audio_dev_unregister(statep->adev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	audioixp_destroy(statep);
	return (DDI_SUCCESS);
}

/*
 * audioixp_destroy()
 *
 * Description:
 *	This routine releases all resources held by the device instance,
 *	as part of either detach or a failure in attach.
 *
 * Arguments:
 *	audioixp_state_t	*state	The device soft state.
 */
void
audioixp_destroy(audioixp_state_t *statep)
{
	if (!statep->suspended) {
		PUT32(IXP_AUDIO_INT, GET32(IXP_AUDIO_INT));
		PUT32(IXP_AUDIO_INT_EN, 0);

		/*
		 * put the audio controller into quiet state, everything off
		 */
		CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_OUT_DMA);
		CLR32(IXP_AUDIO_CMD, IXP_AUDIO_CMD_EN_IN_DMA);
	}

	if (statep->intr_added) {
		ddi_remove_intr(statep->dip, 0, statep->iblock);
	}
	if (statep->ksp) {
		kstat_delete(statep->ksp);
	}

	audioixp_free_port(statep->play_port);
	audioixp_free_port(statep->rec_port);

	audioixp_unmap_regs(statep);

	if (statep->ac97) {
		ac97_free(statep->ac97);
	}

	if (statep->adev) {
		audio_dev_free(statep->adev);
	}

	mutex_destroy(&statep->inst_lock);
	kmem_free(statep, sizeof (*statep));
}
