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
 * audio1575 Audio Driver
 *
 * The driver is primarily targeted at providing audio support for
 * those systems which use the Uli M1575 audio core.
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
 * 	NOTE:
 * 	This driver depends on the drv/audio, misc/ac97
 * 	modules being loaded first.
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
#include "audio1575.h"

/*
 * Module linkage routines for the kernel
 */
static int audio1575_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int audio1575_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int audio1575_ddi_quiesce(dev_info_t *);

/*
 * Entry point routine prototypes
 */
static int audio1575_open(void *, int, unsigned *, unsigned *, caddr_t *);
static void audio1575_close(void *);
static int audio1575_start(void *);
static void audio1575_stop(void *);
static int audio1575_format(void *);
static int audio1575_channels(void *);
static int audio1575_rate(void *);
static uint64_t audio1575_count(void *);
static void audio1575_sync(void *, unsigned);

static audio_engine_ops_t audio1575_engine_ops = {
	AUDIO_ENGINE_VERSION,
	audio1575_open,
	audio1575_close,
	audio1575_start,
	audio1575_stop,
	audio1575_count,
	audio1575_format,
	audio1575_channels,
	audio1575_rate,
	audio1575_sync,
	NULL,
	NULL,
	NULL
};

/*
 * interrupt handler
 */
static uint_t	audio1575_intr(caddr_t, caddr_t);

/*
 * Local Routine Prototypes
 */
static int audio1575_attach(dev_info_t *);
static int audio1575_resume(dev_info_t *);
static int audio1575_detach(dev_info_t *);
static int audio1575_suspend(dev_info_t *);

static int audio1575_alloc_port(audio1575_state_t *, int, uint8_t);
static void audio1575_free_port(audio1575_port_t *);
static void audio1575_start_port(audio1575_port_t *);
static void audio1575_stop_port(audio1575_port_t *);
static void audio1575_reset_port(audio1575_port_t *);
static void audio1575_update_port(audio1575_port_t *);

static int audio1575_setup_intr(audio1575_state_t *);
static int audio1575_codec_sync(audio1575_state_t *);
static void audio1575_write_ac97(void *, uint8_t, uint16_t);
static uint16_t audio1575_read_ac97(void *, uint8_t);
static int audio1575_chip_init(audio1575_state_t *);
static int audio1575_map_regs(audio1575_state_t *);
static void audio1575_unmap_regs(audio1575_state_t *);
static void audio1575_dma_stop(audio1575_state_t *, boolean_t);
static void audio1575_pci_enable(audio1575_state_t *);
static void audio1575_pci_disable(audio1575_state_t *);

static void audio1575_destroy(audio1575_state_t *);

/*
 * Global variables, but used only by this file.
 */

/*
 * DDI Structures
 */


/* Device operations structure */
static struct dev_ops audio1575_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe */
	audio1575_ddi_attach,	/* devo_attach */
	audio1575_ddi_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devi_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	audio1575_ddi_quiesce,	/* devo_quiesce */
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
	0x0000000000000004LL,		/* DMA address align 2-byte boundary */
	0x0000003c,			/* 1 through 60 byte burst sizes */
	0x00000004,			/* min xfer DMA size BDList entry */
	0x000000000001ffffLL,		/* max xfer size, 64K */
	0x000000000001ffffLL,		/* seg, set to 64K */
	0x00000001,			/* s/g list length, no s/g */
	0x00000004,			/* granularity of device minxfer */
	0				/* DMA flags use virtual address */
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
 *	mod_install() status, see mod_install(9f)
 */
int
_init(void)
{
	int	error;

	audio_init_ops(&audio1575_dev_ops, M1575_NAME);

	if ((error = mod_install(&audio1575_modlinkage)) != 0) {
		audio_fini_ops(&audio1575_dev_ops);
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

	if ((error = mod_remove(&audio1575_modlinkage)) != 0) {
		return (error);
	}

	/* clean up ops */
	audio_fini_ops(&audio1575_dev_ops);

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
	return (mod_info(&audio1575_modlinkage, modinfop));
}


/* ******************* Driver Entry Points ********************************* */

/*
 * audio1575_ddi_attach()
 *
 * Description:
 *	Implements the DDI attach(9e) entry point.
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
audio1575_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (audio1575_attach(dip));

	case DDI_RESUME:
		return (audio1575_resume(dip));
	}
	return (DDI_FAILURE);
}

/*
 * audio1575_ddi_detach()
 *
 * Description:
 *	Implements the detach(9e) entry point.
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
audio1575_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (audio1575_detach(dip));

	case DDI_SUSPEND:
		return (audio1575_suspend(dip));
	}
	return (DDI_FAILURE);
}

/*
 * audio1575_ddi_quiesce()
 *
 * Description:
 *	Implements the quiesce(9e) entry point.
 *
 * Arguments:
 *	dev_info_t		*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS	The driver was quiesced
 *	DDI_FAILURE	The driver couldn't be quiesced
 */
static int
audio1575_ddi_quiesce(dev_info_t *dip)
{
	audio1575_state_t	*statep;

	if ((statep = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	audio1575_dma_stop(statep, B_TRUE);
	return (DDI_SUCCESS);
}


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
audio1575_intr(caddr_t arg, caddr_t dontcare)
{
	audio1575_state_t	*statep = (void *)arg;
	uint32_t		intrsr;
	uint8_t			index;
	audio1575_port_t	*consume = NULL;
	audio1575_port_t	*produce = NULL;

	_NOTE(ARGUNUSED(dontcare));

	mutex_enter(&statep->lock);

	intrsr = GET32(M1575_INTRSR_REG);

	/* check if device is interrupting */
	if (intrsr == 0) {
		if (statep->ksp) {
			/* increment the spurious ino5 interrupt cnt */
			M1575_KIOP(statep)->intrs[KSTAT_INTR_SPURIOUS]++;
		}

		mutex_exit(&statep->lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* update the kernel interrupt statistics */
	if (statep->ksp) {
		M1575_KIOP(statep)->intrs[KSTAT_INTR_HARD]++;
	}

	/*
	 * The Uli M1575 generates an interrupt for each interrupt
	 * type. therefore we only process one interrupt type
	 * per invocation of the audio1575_intr() routine.
	 * WARNING: DO NOT attempt to optimize this by looping
	 * until the INTRSR register is clear as this will
	 * generate spurious ino5 interrupts.
	 */
	if (GET16(M1575_PCMISR_REG) & M1575_PCMISR_BCIS) {
		/* Clear PCM IN interrupt */
		PUT16(M1575_PCMISR_REG, M1575_SR_CLR);
		/*
		 * Note: This interrupt is not cleared by writing a '1'
		 * to the M1575_INTRSR_REG according to the M1575 Super I/O
		 * data sheet on page 189.
		 */

		/* update the LVI -- we just set it to the current value - 1 */
		index = GET8(M1575_PCMICIV_REG);
		index = (index - 1) % M1575_BD_NUMS;
		PUT8(M1575_PCMILVIV_REG, index);
		produce = statep->ports[M1575_REC];

	} else if (GET16(M1575_PCMOSR_REG) & M1575_PCMOSR_BCIS) {
		/* Clear PCM OUT interrupt */
		PUT16(M1575_PCMOSR_REG, M1575_SR_CLR);
		/*
		 * Note: This interrupt is not cleared by writing a '1'
		 * to the M1575_INTRSR_REG according to the M1575 Super I/O
		 * data sheet on page 189.
		 */

		/* update the LVI -- we just set it to the current value - 1 */
		index = GET8(M1575_PCMOCIV_REG);
		index = (index - 1) % M1575_BD_NUMS;
		PUT8(M1575_PCMOLVIV_REG, index);
		consume = statep->ports[M1575_PLAY];

	} else {
		/* Clear other interrupts (there should not be any) */
		PUT32(M1575_INTRSR_REG, (intrsr & M1575_INTR_MASK));
	}

	mutex_exit(&statep->lock);

	if (produce) {
		audio_engine_produce(produce->engine);
	}
	if (consume) {
		audio_engine_consume(consume->engine);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * audio1575_open()
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
audio1575_open(void *arg, int flag,
    unsigned *fragfrp, unsigned *nfragsp, caddr_t *bufp)
{
	audio1575_port_t	*port = arg;

	_NOTE(ARGUNUSED(flag));

	port->started = B_FALSE;
	port->count = 0;
	*fragfrp = port->fragfr;
	*nfragsp = M1575_BD_NUMS;
	*bufp = port->samp_kaddr;

	mutex_enter(&port->statep->lock);
	audio1575_reset_port(port);
	mutex_exit(&port->statep->lock);

	return (0);
}


/*
 * audio1575_close()
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
audio1575_close(void *arg)
{
	audio1575_port_t	*port = arg;
	audio1575_state_t	*statep = port->statep;

	mutex_enter(&statep->lock);
	audio1575_stop_port(port);
	port->started = B_FALSE;
	mutex_exit(&statep->lock);
}

/*
 * audio1575_stop()
 *
 * Description:
 *	This is called by the framework to stop a port that is
 *	transferring data.
 *
 * Arguments:
 *	void	*arg		The DMA engine to stop
 */
static void
audio1575_stop(void *arg)
{
	audio1575_port_t	*port = arg;
	audio1575_state_t	*statep = port->statep;

	mutex_enter(&statep->lock);
	if (port->started) {
		audio1575_stop_port(port);
	}
	port->started = B_FALSE;
	mutex_exit(&statep->lock);
}

/*
 * audio1575_start()
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
audio1575_start(void *arg)
{
	audio1575_port_t	*port = arg;
	audio1575_state_t	*statep = port->statep;

	mutex_enter(&statep->lock);
	if (!port->started) {
		audio1575_start_port(port);
		port->started = B_TRUE;
	}
	mutex_exit(&statep->lock);
	return (0);
}

/*
 * audio1575_format()
 *
 * Description:
 *	Called by the framework to query the format for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	AUDIO_FORMAT_S16_LE
 */
static int
audio1575_format(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (AUDIO_FORMAT_S16_LE);
}

/*
 * audio1575_channels()
 *
 * Description:
 *	Called by the framework to query the channels for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	Number of channels for the device
 */
static int
audio1575_channels(void *arg)
{
	audio1575_port_t *port = arg;

	return (port->nchan);
}

/*
 * audio1575_rate()
 *
 * Description:
 *	Called by the framework to query the sample rate for the device.
 *
 * Arguments:
 *	void	*arg		The DMA engine to query
 *
 * Returns:
 *	48000
 */
static int
audio1575_rate(void *arg)
{
	_NOTE(ARGUNUSED(arg));

	return (48000);
}

/*
 * audio1575_count()
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
audio1575_count(void *arg)
{
	audio1575_port_t	*port = arg;
	audio1575_state_t	*statep = port->statep;
	uint64_t		val;

	mutex_enter(&statep->lock);
	audio1575_update_port(port);
	val = port->count + (port->picb / port->nchan);
	mutex_exit(&statep->lock);

	return (val);
}

/*
 * audio1575_sync()
 *
 * Description:
 *	This is called by the framework to synchronize DMA caches.
 *
 * Arguments:
 *	void	*arg		The DMA engine to sync
 */
static void
audio1575_sync(void *arg, unsigned nframes)
{
	audio1575_port_t *port = arg;
	_NOTE(ARGUNUSED(nframes));

	(void) ddi_dma_sync(port->samp_dmah, 0, 0, port->sync_dir);
}

/*
 * audio1575_start_port()
 *
 * Description:
 *	This routine starts the DMA engine.
 *
 * Arguments:
 *	audio1575_port_t	*port	Port of DMA engine to start.
 */
static void
audio1575_start_port(audio1575_port_t *port)
{
	audio1575_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->lock));

	/* if suspended, then do nothing else */
	if (statep->suspended) {
		return;
	}

	if (port->num == M1575_REC) {
		/* ULi says do fifo resets here */
		SET32(M1575_FIFOCR1_REG, M1575_FIFOCR1_PCMIRST);
		CLR32(M1575_DMACR_REG, M1575_DMACR_PCMIPAUSE);
		PUT8(M1575_PCMICR_REG, M1575_PCMICR_IOCE);
		SET32(M1575_DMACR_REG, M1575_DMACR_PCMISTART);
	} else {
		CLR32(M1575_DMACR_REG, M1575_DMACR_PCMOPAUSE);
		PUT8(M1575_PCMOCR_REG, M1575_PCMOCR_IOCE);
		SET32(M1575_DMACR_REG, M1575_DMACR_PCMOSTART);
	}
}

/*
 * audio1575_stop_port()
 *
 * Description:
 *	This routine stops the DMA engine.
 *
 * Arguments:
 *	audio1575_port_t	*port	Port of DMA engine to stop.
 */
static void
audio1575_stop_port(audio1575_port_t *port)
{
	audio1575_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->lock));

	/* if suspended, then do nothing else */
	if (statep->suspended) {
		return;
	}

	if (port->num == M1575_REC) {
		SET32(M1575_DMACR_REG, M1575_DMACR_PCMIPAUSE);
	} else {
		SET32(M1575_DMACR_REG, M1575_DMACR_PCMOPAUSE);
	}
}

/*
 * audio1575_reset_port()
 *
 * Description:
 *	This routine resets the DMA engine pareparing it for work.
 *
 * Arguments:
 *	audio1575_port_t	*port	Port of DMA engine to reset.
 */
static void
audio1575_reset_port(audio1575_port_t *port)
{
	audio1575_state_t	*statep = port->statep;

	ASSERT(mutex_owned(&statep->lock));

	port->civ = 0;
	port->picb = 0;

	if (statep->suspended)
		return;

	if (port->num == M1575_REC) {
		/* Uli FIFO madness ... */
		SET32(M1575_FIFOCR1_REG, M1575_FIFOCR1_PCMIRST);
		SET32(M1575_DMACR_REG, M1575_DMACR_PCMIPAUSE);

		PUT8(M1575_PCMICR_REG, 0);
		PUT8(M1575_PCMICR_REG, M1575_CR_RR | M1575_CR_IOCE);

		PUT32(M1575_PCMIBDBAR_REG, port->bdl_paddr);
		PUT8(M1575_PCMILVIV_REG, M1575_BD_NUMS - 1);

		CLR32(M1575_DMACR_REG, M1575_DMACR_PCMIPAUSE);

	} else {

		uint32_t	scr;

		/* Uli FIFO madness ... */
		SET32(M1575_FIFOCR1_REG, M1575_FIFOCR1_PCMORST);
		SET32(M1575_DMACR_REG, M1575_DMACR_PCMOPAUSE);

		/* configure the number of channels properly */
		scr = GET32(M1575_SCR_REG);
		scr &= ~(M1575_SCR_6CHL_MASK | M1575_SCR_CHAMOD_MASK);
		scr |= M1575_SCR_6CHL_2;	/* select our proper ordering */
		switch (port->nchan) {
		case 2:
			scr |= M1575_SCR_CHAMOD_2;
			break;
		case 4:
			scr |= M1575_SCR_CHAMOD_4;
			break;
		case 6:
			scr |= M1575_SCR_CHAMOD_6;
			break;
		}
		PUT32(M1575_SCR_REG, scr);

		PUT8(M1575_PCMOCR_REG, 0);
		PUT8(M1575_PCMOCR_REG, M1575_CR_RR | M1575_CR_IOCE);

		PUT32(M1575_PCMOBDBAR_REG, port->bdl_paddr);
		PUT8(M1575_PCMOLVIV_REG, M1575_BD_NUMS - 1);

		CLR32(M1575_DMACR_REG, M1575_DMACR_PCMOPAUSE);
	}
}

/*
 * audio1575_update_port()
 *
 * Description:
 *	This routine updates the ports frame counter from hardware, and
 *	gracefully handles wraps.
 *
 * Arguments:
 *	audio1575_port_t	*port		The port to update.
 */
static void
audio1575_update_port(audio1575_port_t *port)
{
	audio1575_state_t	*statep = port->statep;
	uint8_t			civ;
	uint16_t		picb;
	unsigned		n;
	int			civoff;
	int			picoff;

	if (port->num == M1575_REC) {
		civoff = M1575_PCMICIV_REG;
		picoff = M1575_PCMIPICB_REG;
	} else {
		civoff = M1575_PCMOCIV_REG;
		picoff = M1575_PCMOPICB_REG;
	}

	if (statep->suspended) {
		civ = 0;
		picb = 0;
	} else {
		/*
		 * We read the position counters, but we're careful to avoid
		 * the situation where the position counter resets at the end
		 * of a buffer.
		 */
		for (int i = 0; i < 2; i++) {
			civ = GET8(civoff);
			picb = GET16(picoff);
			if (GET8(civoff) == civ) {
				/*
				 * Chip did not start a new index, so
				 * the picb is valid.
				 */
				break;
			}
		}
		if (civ >= port->civ) {
			n = civ - port->civ;
		} else {
			n = civ + (M1575_BD_NUMS - port->civ);
		}
		port->count += (n * port->fragfr);
	}
	port->civ = civ;
	port->picb = picb;
}

/*
 * audio1575_attach()
 *
 * Description:
 *	Attach an instance of the audio1575 driver. This routine does the
 * 	device dependent attach tasks. When it is completed, it registers
 *	with the audio framework.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was initialized properly
 *	DDI_FAILURE		The driver couldn't be initialized properly
 */
static int
audio1575_attach(dev_info_t *dip)
{
	audio1575_state_t	*statep;
	audio_dev_t		*adev;
	uint32_t		devid;
	const char		*name;
	const char		*rev;
	int			maxch;

	/* allocate the soft state structure */
	statep = kmem_zalloc(sizeof (*statep), KM_SLEEP);
	ddi_set_driver_private(dip, statep);
	statep->dip = dip;

	/*
	 * We want the micboost enabled by default as well.
	 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, AC97_PROP_MICBOOST, 1);

	/* allocate common audio dev structure */
	adev = audio_dev_alloc(dip, 0);
	if (adev == NULL) {
		audio_dev_warn(NULL, "unable to allocate audio dev");
		goto error;
	}
	statep->adev = adev;

	/* map in the audio registers */
	if (audio1575_map_regs(statep) != DDI_SUCCESS) {
		audio_dev_warn(adev, "couldn't map registers");
		goto error;
	}

	if (audio1575_setup_intr(statep) != DDI_SUCCESS) {
		/* message already noted */
		goto error;
	}

	/* Enable PCI I/O and Memory Spaces */
	audio1575_pci_enable(statep);

	devid = (pci_config_get16(statep->pcih, PCI_CONF_VENID) << 16) |
	    pci_config_get16(statep->pcih, PCI_CONF_DEVID);
	switch (devid) {
	case 0x10b95455:
		name = "Uli M1575 AC'97";
		rev = "M5455";
		break;
	default:
		name = "Uli AC'97";
		rev = "Unknown";
		break;
	}
	/* set device information -- this should check PCI config space */
	audio_dev_set_description(adev, name);
	audio_dev_set_version(adev, rev);

	statep->ac97 = ac97_alloc(dip, audio1575_read_ac97,
	    audio1575_write_ac97, statep);
	ASSERT(statep->ac97 != NULL);

	/*
	 * Override "max-channels" property to prevent configuration
	 * of 4 or 6 (or possibly even 8!) channel audio.  The default
	 * is to support as many channels as the hardware can do.
	 */
	maxch = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "max-channels", ac97_num_channels(statep->ac97));
	if (maxch < 2) {
		maxch = 2;
	}

	statep->maxch = min(maxch, 6) & ~1;

	/* allocate port structures */
	if ((audio1575_alloc_port(statep, M1575_PLAY, statep->maxch) !=
	    DDI_SUCCESS) ||
	    (audio1575_alloc_port(statep, M1575_REC, 2) != DDI_SUCCESS)) {
		goto error;
	}

	if (audio1575_chip_init(statep) != DDI_SUCCESS) {
		audio_dev_warn(adev, "failed to init chip");
		goto error;
	}

	if (ac97_init(statep->ac97, adev) != DDI_SUCCESS) {
		audio_dev_warn(adev, "ac'97 initialization failed");
		goto error;
	}

	/* set up kernel statistics */
	if ((statep->ksp = kstat_create(M1575_NAME,
	    ddi_get_instance(dip), M1575_NAME, "controller",
	    KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT)) != NULL) {
		kstat_install(statep->ksp);
	}

	/* Enable PCI Interrupts */
	pci_config_put8(statep->pcih, M1575_PCIMISC_REG, M1575_PCIMISC_INTENB);

	/* enable audio interrupts */
	if (ddi_intr_enable(statep->ih) != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_intr_enable() failure");
		goto error;
	}

	/* register with the framework */
	if (audio_dev_register(adev) != DDI_SUCCESS) {
		audio_dev_warn(adev, "unable to register with framework");
		goto error;
	}

	/* everything worked out, so report the device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error:
	audio1575_destroy(statep);
	return (DDI_FAILURE);
}

/*
 * audio1575_detach()
 *
 * Description:
 *	Detach an instance of the audio1575 driver.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS	The driver was detached
 *	DDI_FAILURE	The driver couldn't be detached
 */
static int
audio1575_detach(dev_info_t *dip)
{
	audio1575_state_t	*statep;

	statep = ddi_get_driver_private(dip);

	if (audio_dev_unregister(statep->adev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	audio1575_destroy(statep);
	return (DDI_SUCCESS);
}

/* *********************** Local Routines *************************** */

/*
 * audio1575_setup_intr()
 *
 * Description:
 *	This routine initializes the audio driver's interrupt handle and
 *	mutex.
 *
 * Arguments:
 *	audio1575_state_t	*state		The device's state structure
 *
 * Returns:
 *	DDI_SUCCESS		Interrupt handle & mutex initialized
 *	DDI_FAILURE		Interrupt handle & mutex not initialized
 */
int
audio1575_setup_intr(audio1575_state_t *statep)
{
	audio_dev_t		*adev;
	dev_info_t		*dip;
	uint_t			ipri;
	int			actual;
	int			rv;
	int			itype;
	int			count;
	ddi_intr_handle_t	ih = NULL;

	dip = statep->dip;
	adev = statep->adev;

	/* get supported interrupt types */
	rv = ddi_intr_get_supported_types(dip, &itype);
	if ((rv != DDI_SUCCESS) || (!(itype & DDI_INTR_TYPE_FIXED))) {
		audio_dev_warn(adev, "Fixed type interrupts not supported");
		return (DDI_FAILURE);
	}

	/* make sure we only have one fixed type interrupt */
	rv = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &count);
	if ((rv != DDI_SUCCESS) || (count != 1)) {
		audio_dev_warn(adev, "No fixed interrupts");
		return (DDI_FAILURE);
	}

	rv = ddi_intr_alloc(statep->dip, &ih, DDI_INTR_TYPE_FIXED,
	    0, 1, &actual, DDI_INTR_ALLOC_STRICT);
	if ((rv != DDI_SUCCESS) || (actual != 1)) {
		audio_dev_warn(adev, "Can't alloc interrupt handle");
		return (DDI_FAILURE);
	}

	/* test for a high level interrupt */
	if (ddi_intr_get_pri(ih, &ipri) != DDI_SUCCESS) {
		audio_dev_warn(adev, "Can't get interrupt priority");
		(void) ddi_intr_free(ih);
		return (DDI_FAILURE);
	}
	if (ipri >= ddi_intr_get_hilevel_pri()) {
		audio_dev_warn(adev, "Unsupported high level interrupt");
		(void) ddi_intr_free(ih);
		return (DDI_FAILURE);
	}

	if (ddi_intr_add_handler(ih, audio1575_intr, statep, NULL) !=
	    DDI_SUCCESS) {
		audio_dev_warn(adev, "Can't add interrupt handler");
		(void) ddi_intr_free(ih);
		return (DDI_FAILURE);
	}

	statep->ih = ih;
	mutex_init(&statep->lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));
	mutex_init(&statep->ac_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));

	return (DDI_SUCCESS);
}

/*
 * audio1575_alloc_port()
 *
 * Description:
 *	This routine allocates the DMA handles and the memory for the
 *	DMA engines to use.  It also configures the BDL lists properly
 *	for use.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's devinfo
 *	int		num	M1575_PLAY or M1575_REC
 *	uint8_t		nchan	Number of channels (2 = stereo, 6 = 5.1, etc.)
 *
 * Returns:
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
audio1575_alloc_port(audio1575_state_t *statep, int num, uint8_t nchan)
{
	ddi_dma_cookie_t	cookie;
	uint_t			count;
	int			dir;
	unsigned		caps;
	char			*prop;
	audio_dev_t		*adev;
	audio1575_port_t	*port;
	uint32_t		*kaddr;
	uint32_t		paddr;
	int			rc;
	dev_info_t		*dip;

	adev = statep->adev;
	dip = statep->dip;

	port = kmem_zalloc(sizeof (*port), KM_SLEEP);
	statep->ports[num] = port;
	port->num = num;
	port->statep = statep;
	port->started = B_FALSE;
	port->nchan = nchan;

	if (num == M1575_REC) {
		prop = "record-interrupts";
		dir = DDI_DMA_READ;
		caps = ENGINE_INPUT_CAP;
		port->sync_dir = DDI_DMA_SYNC_FORKERNEL;
	} else {
		prop = "play-interrupts";
		dir = DDI_DMA_WRITE;
		caps = ENGINE_OUTPUT_CAP;
		port->sync_dir = DDI_DMA_SYNC_FORDEV;
	}

	port->intrs = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, prop, M1575_INTS);

	/* make sure the values are good */
	if (port->intrs < M1575_MIN_INTS) {
		audio_dev_warn(adev, "%s too low, %d, resetting to %d",
		    prop, port->intrs, M1575_INTS);
		port->intrs = M1575_INTS;
	} else if (port->intrs > M1575_MAX_INTS) {
		audio_dev_warn(adev, "%s too high, %d, resetting to %d",
		    prop, port->intrs, M1575_INTS);
		port->intrs = M1575_INTS;
	}

	/*
	 * Figure out how much space we need.  Sample rate is 48kHz, and
	 * we need to store 32 chunks.  (Note that this means that low
	 * interrupt frequencies will require more RAM.  We could probably
	 * do some cleverness to use a shorter BD list.)
	 */
	port->fragfr = 48000 / port->intrs;
	port->fragfr = M1575_ROUNDUP(port->fragfr, M1575_MOD_SIZE);
	port->samp_size = port->fragfr * port->nchan * 2;
	port->samp_size *= M1575_BD_NUMS;

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
	port->bdl_size = sizeof (m1575_bd_entry_t) * M1575_BD_NUMS;
	rc = ddi_dma_mem_alloc(port->bdl_dmah, port->bdl_size,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &port->bdl_kaddr, &port->bdl_size, &port->bdl_acch);
	if (rc != DDI_SUCCESS) {
		audio_dev_warn(adev, "ddi_dma_mem_alloc(bdlist) failed");
		return (DDI_FAILURE);
	}

	/*
	 * Wire up the BD list.  We do this *before* binding the BD list
	 * so that we don't have to do an extra ddi_dma_sync.
	 */
	paddr = port->samp_paddr;
	kaddr = (void *)port->bdl_kaddr;
	for (int i = 0; i < M1575_BD_NUMS; i++) {

		/* set base address of buffer */
		ddi_put32(port->bdl_acch, kaddr, paddr);
		kaddr++;

		/* set size in frames, and enable IOC interrupt */
		ddi_put32(port->bdl_acch, kaddr,
		    ((port->fragfr * port->nchan) | (1U << 31)));
		kaddr++;

		paddr += (port->fragfr * port->nchan * 2);
	}

	rc = ddi_dma_addr_bind_handle(port->bdl_dmah, NULL, port->bdl_kaddr,
	    port->bdl_size, DDI_DMA_WRITE|DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &cookie, &count);
	if ((rc != DDI_DMA_MAPPED) || (count != 1)) {
		audio_dev_warn(adev, "addr_bind_handle failed");
		return (DDI_FAILURE);
	}
	port->bdl_paddr = cookie.dmac_address;

	port->engine = audio_engine_alloc(&audio1575_engine_ops, caps);
	if (port->engine == NULL) {
		audio_dev_warn(adev, "audio_engine_alloc failed");
		return (DDI_FAILURE);
	}

	audio_engine_set_private(port->engine, port);
	audio_dev_add_engine(adev, port->engine);

	return (DDI_SUCCESS);
}

/*
 * audio1575_free_port()
 *
 * Description:
 *	This routine unbinds the DMA cookies, frees the DMA buffers,
 *	deallocates the DMA handles.
 *
 * Arguments:
 *	audio810_port_t	*port	The port structure for a DMA engine.
 */
static void
audio1575_free_port(audio1575_port_t *port)
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
 * audio1575_map_regs()
 *
 * Description:
 *	The registers are mapped in.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's devinfo
 *
 * Returns:
 *	DDI_SUCCESS		Registers successfully mapped
 *	DDI_FAILURE		Registers not successfully mapped
 */
static int
audio1575_map_regs(audio1575_state_t *statep)
{
	dev_info_t		*dip = statep->dip;

	/* Check for fault management capabilities */
	if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(dip))) {
		dev_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	/* map the M1575 Audio PCI Cfg Space */
	if (pci_config_setup(dip, &statep->pcih) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "PCI config map failure");
		goto error;
	}

	/* map the M1575 Audio registers in PCI IO Space */
	if ((ddi_regs_map_setup(dip, M1575_AUDIO_IO_SPACE, &statep->regsp,
	    0, 0, &dev_attr, &statep->regsh)) != DDI_SUCCESS) {
		audio_dev_warn(statep->adev, "Audio IO mapping failure");
		goto error;
	}
	return (DDI_SUCCESS);

error:
	audio1575_unmap_regs(statep);

	return (DDI_FAILURE);
}

/*
 * audio1575_unmap_regs()
 *
 * Description:
 *	This routine unmaps control registers.
 *
 * Arguments:
 *	audio1575_state_t	*state	The device's state structure
 */
static void
audio1575_unmap_regs(audio1575_state_t *statep)
{
	if (statep->regsh) {
		ddi_regs_map_free(&statep->regsh);
	}

	if (statep->pcih) {
		pci_config_teardown(&statep->pcih);
	}
}

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
 *						restore	from codec_shadow[]
 * Returns:
 *	DDI_SUCCESS	The hardware was initialized properly
 *	DDI_FAILURE	The hardware couldn't be initialized properly
 */
static int
audio1575_chip_init(audio1575_state_t *statep)
{
	uint32_t		ssr;
	uint32_t		rtsr;
	uint32_t		intrsr;
	int 			i;
	int			j;
#ifdef	__sparc
	uint8_t			clk_detect;
	ddi_acc_handle_t	pcih;
#endif
	clock_t			ticks;

	/*
	 * clear the interrupt control and status register
	 * READ/WRITE/READ workaround required
	 * for buggy hardware
	 */

	PUT32(M1575_INTRCR_REG, 0);
	(void) GET32(M1575_INTRCR_REG);

	intrsr = GET32(M1575_INTRSR_REG);
	PUT32(M1575_INTRSR_REG, (intrsr & M1575_INTR_MASK));
	(void) GET32(M1575_INTRSR_REG);

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
		PUT32(M1575_SCR_REG, M1575_SCR_COLDRST);
		delay(ticks<<1);

		/* Read the System Status Reg */
		ssr = GET32(M1575_SSR_REG);

		/* make sure and release the blocked reset bit */
		if (ssr & M1575_SSR_RSTBLK) {
			SET32(M1575_INTFCR_REG, M1575_INTFCR_RSTREL);
			delay(ticks);

			/* Read the System Status Reg */
			ssr = GET32(M1575_SSR_REG);

			/* make sure and release the blocked reset bit */
			if (ssr & M1575_SSR_RSTBLK) {
				return (DDI_FAILURE);
			}

			/* Reset the controller */
			PUT32(M1575_SCR_REG, M1575_SCR_COLDRST);
			delay(ticks);
		}

		/* according AC'97 spec, wait for codec reset */
		for (j = 0; j < M1575_LOOP_CTR; j++) {
			if ((GET32(M1575_SCR_REG) & M1575_SCR_COLDRST) == 0) {
				break;
			}
			delay(ticks);
		}

		/* codec reset failed */
		if (j >= M1575_LOOP_CTR) {
			audio_dev_warn(statep->adev,
			    "failure to reset codec");
			return (DDI_FAILURE);
		}

		/*
		 * Wait for FACRDY First codec ready. The hardware can
		 * provide the state of
		 * codec ready bit on SDATA_IN[0] and as reflected in
		 * the Recv Tag Slot Reg.
		 */
		rtsr = GET32(M1575_RTSR_REG);
		if (rtsr & M1575_RTSR_FACRDY) {
			break;
		} else { /* reset the status and wait for new status to set */
			rtsr |= M1575_RTSR_FACRDY;
			PUT32(M1575_RTSR_REG, rtsr);
			drv_usecwait(10);
		}
	}

	/* if we could not reset the AC97 codec then report failure */
	if (i >= M1575_LOOP_CTR) {
		audio_dev_warn(statep->adev,
		    "no codec ready signal received");
		return (DDI_FAILURE);
	}

#ifdef	__sparc
	/* Magic code from ULi to Turn on the AC_LINK clock */
	pcih = statep->pcih;
	pci_config_put8(pcih, M1575_PCIACD_REG, 0);
	pci_config_put8(pcih, M1575_PCIACD_REG, 4);
	pci_config_put8(pcih, M1575_PCIACD_REG, 0);
	(void) pci_config_get8(pcih, M1575_PCIACD_REG);
	pci_config_put8(pcih, M1575_PCIACD_REG, 2);
	pci_config_put8(pcih, M1575_PCIACD_REG, 0);
	clk_detect = pci_config_get8(pcih, M1575_PCIACD_REG);

	if (clk_detect != 1) {
		audio_dev_warn(statep->adev, "No AC97 Clock Detected");
		return (DDI_FAILURE);
	}
#endif

	/* Magic code from Uli to Init FIFO1 and FIFO2 */
	PUT32(M1575_FIFOCR1_REG, 0x81818181);
	PUT32(M1575_FIFOCR2_REG, 0x81818181);
	PUT32(M1575_FIFOCR3_REG, 0x81818181);

	/* Make sure that PCM in and PCM out are enabled */
	SET32(M1575_INTFCR_REG, (M1575_INTFCR_PCMIENB | M1575_INTFCR_PCMOENB));

	audio1575_dma_stop(statep, B_FALSE);

	return (DDI_SUCCESS);
}

/*
 * audio1575_dma_stop()
 *
 * Description:
 *	This routine is used to put each DMA engine into the quiet state.
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 */
static void
audio1575_dma_stop(audio1575_state_t *statep, boolean_t quiesce)
{
	uint32_t	intrsr;
	int		i;

	if (statep->regsh == NULL) {
		return;
	}

	/* pause bus master (needed for the following reset register) */
	for (i = 0; i < M1575_LOOP_CTR; i++) {

		SET32(M1575_DMACR_REG, M1575_DMACR_PAUSE_ALL);
		if (GET32(M1575_DMACR_REG) & M1575_DMACR_PAUSE_ALL) {
			break;
		}
		drv_usecwait(10);
	}

	if (i >= M1575_LOOP_CTR) {
		if (!quiesce)
			audio_dev_warn(statep->adev, "failed to stop DMA");
		return;
	}

	/* Pause bus master (needed for the following reset register) */
	PUT8(M1575_PCMICR_REG, 0);
	PUT8(M1575_PCMOCR_REG, 0);
	PUT8(M1575_MICICR_REG, 0);
	PUT8(M1575_CSPOCR_REG, 0);
	PUT8(M1575_PCMI2CR_RR, 0);
	PUT8(M1575_MICI2CR_RR, 0);

	/* Reset the bus master registers for all DMA engines */
	PUT8(M1575_PCMICR_REG, M1575_PCMICR_RR);
	PUT8(M1575_PCMOCR_REG, M1575_PCMOCR_RR);
	PUT8(M1575_MICICR_REG, M1575_MICICR_RR);
	PUT8(M1575_CSPOCR_REG, M1575_CSPOCR_RR);
	PUT8(M1575_PCMI2CR_REG, M1575_PCMI2CR_RR);
	PUT8(M1575_MICI2CR_REG, M1575_MICI2CR_RR);

	/* Reset FIFOS */
	PUT32(M1575_FIFOCR1_REG, 0x81818181);
	PUT32(M1575_FIFOCR2_REG, 0x81818181);
	PUT32(M1575_FIFOCR3_REG, 0x81818181);

	/* Clear Interrupts */
	SET16(M1575_PCMISR_REG, M1575_SR_CLR);
	SET16(M1575_PCMOSR_REG, M1575_SR_CLR);
	SET16(M1575_MICISR_REG, M1575_SR_CLR);
	SET16(M1575_CSPOSR_REG, M1575_SR_CLR);
	SET16(M1575_PCMI2SR_REG, M1575_SR_CLR);
	SET16(M1575_MICI2SR_REG, M1575_SR_CLR);

	/*
	 * clear the interrupt control and status register
	 * READ/WRITE/READ workaround required
	 * for buggy hardware
	 */

	PUT32(M1575_INTRCR_REG, 0);
	(void) GET32(M1575_INTRCR_REG);

	intrsr = GET32(M1575_INTRSR_REG);
	PUT32(M1575_INTRSR_REG, (intrsr & M1575_INTR_MASK));
	(void) GET32(M1575_INTRSR_REG);
}

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
 *	DDI_SUCCESS		Ready for an I/O access to the codec
 *	DDI_FAILURE		An I/O access is currently in progress, can't
 *				perform another I/O access.
 */
static int
audio1575_codec_sync(audio1575_state_t *statep)
{
	/* do the Uli Shuffle ... */
	for (int i = 0; i < M1575_LOOP_CTR; i++) {
		/* Read the semaphore, and loop till we own it */
		if ((GET32(M1575_CASR_REG) & 1) == 0) {
			for (int j = 0; j < M1575_LOOP_CTR; j++) {
				/* Wait for CWRSUCC 0x8 */
				if (GET32(M1575_CSPSR_REG) &
				    M1575_CSPSR_SUCC) {
					return (DDI_SUCCESS);
				}
				drv_usecwait(1);
			}
		}
		drv_usecwait(10);
	}

	return (DDI_FAILURE);
}

/*
 * audio1575_write_ac97()
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
audio1575_write_ac97(void *arg, uint8_t reg, uint16_t data)
{
	audio1575_state_t	*statep = arg;
	int			i;

	mutex_enter(&statep->ac_lock);

	if (audio1575_codec_sync(statep) != DDI_SUCCESS) {
		mutex_exit(&statep->ac_lock);
		return;
	}

	/* write the data to WRITE to the lo word of the CPR register */
	PUT16(M1575_CPR_REG, data);

	/* write the address to WRITE to the hi word of the CPR register */
	PUT16(M1575_CPR_REG+2, reg);

	/* wait until command is completed sucessfully */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		/* Wait for Write Ready	0x01 */
		if (GET32(M1575_CSPSR_REG) & M1575_CSPSR_WRRDY) {
			break;
		}
		drv_usecwait(1);
	}

	mutex_exit(&statep->ac_lock);

	if (i < M1575_LOOP_CTR) {
		(void) audio1575_read_ac97(statep, reg);
	}
}

/*
 * audio1575_read_ac97()
 *
 * Description:
 *	Get the specific AC97 Codec register. It also updates codec_shadow[]
 *	with the register value.
 *
 * Arguments:
 *	void		*arg		The device's state structure
 *	uint8_t		reg		AC97 register number
 *
 * Returns:
 *	Value of AC97 register.  (0xffff in failure situations).
 */
static uint16_t
audio1575_read_ac97(void *arg, uint8_t reg)
{
	audio1575_state_t	*statep = arg;
	uint16_t		addr = 0;
	uint16_t		data = 0xffff;
	int			i;

	mutex_enter(&statep->ac_lock);
	if ((audio1575_codec_sync(statep)) != DDI_SUCCESS) {
		mutex_exit(&statep->ac_lock);
		return (data);
	}

	/*
	 * at this point we have the CASR semaphore
	 * and the codec is r/w ready
	 * OR in the READ opcode into the address field
	 */

	addr = (reg | M1575_CPR_READ);

	/* write the address to READ to the hi word of the CPR register */
	PUT16(M1575_CPR_REG+2, addr);

	/* wait until command is completed sucessfully */
	for (i = 0; i < M1575_LOOP_CTR; i++) {
		/* Wait for Read Ready	0x02 */
		if (GET32(M1575_CSPSR_REG) & M1575_CSPSR_RDRDY) {
			break;
		}
		drv_usecwait(1);
	}

	if (i < M1575_LOOP_CTR) {
		/* read back the data and address */
		data = GET16(M1575_SPR_REG);
		addr = GET16(M1575_SPR_REG+2);
		if (addr != reg) {
			data = 0xffff;
		}
	}

	mutex_exit(&statep->ac_lock);
	return (data);
}

/*
 * audio1575_pci_enable()
 *
 * Description:
 *	This routine Enables all PCI IO and MEMORY accesses
 *
 * Arguments:
 *	audio1575_state_t *statep	 The device's state structure
 */
static void
audio1575_pci_enable(audio1575_state_t *statep)
{
	uint16_t pcics_reg;

	pcics_reg = pci_config_get16(statep->pcih, PCI_CONF_COMM);
	pcics_reg |= (PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);
	pci_config_put16(statep->pcih, PCI_CONF_COMM, pcics_reg);
}

/*
 * audio1575_pci_disable()
 *
 * Description:
 *	This routine Disables all PCI IO and MEMORY accesses
 *
 * Arguments:
 *	audio1575_state_t *statep	The device's state structure
 */
static void
audio1575_pci_disable(audio1575_state_t *statep)
{
	uint16_t pcics_reg;

	if (statep->pcih == NULL)
		return;
	pcics_reg = pci_config_get16(statep->pcih, PCI_CONF_COMM);
	pcics_reg &= ~(PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);
	pci_config_put16(statep->pcih, PCI_CONF_COMM, pcics_reg);
}

/*
 * audio1575_resume()
 *
 * Description:
 *	Resume operation of the device after sleeping or hibernating.
 *	Note that this should never fail, even if hardware goes wonky,
 *	because the current PM framework will panic if it does.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS		The driver was resumed
 */
static int
audio1575_resume(dev_info_t *dip)
{
	audio1575_state_t	*statep;
	audio_dev_t		*adev;

	/* we've already allocated the state structure so get ptr */
	statep = ddi_get_driver_private(dip);
	adev = statep->adev;
	ASSERT(!mutex_owned(&statep->lock));

	if (audio1575_chip_init(statep) != DDI_SUCCESS) {
		/*
		 * Note that PM gurus say we should return
		 * success here.  Failure of audio shouldn't
		 * be considered FATAL to the system.  The
		 * upshot is that audio will not progress.
		 */
		audio_dev_warn(adev, "DDI_RESUME failed to init chip");
		return (DDI_SUCCESS);
	}

	/* allow ac97 operations again */
	ac97_resume(statep->ac97);

	mutex_enter(&statep->lock);

	ASSERT(statep->suspended);
	statep->suspended = B_FALSE;

	for (int i = 0; i < M1575_NUM_PORTS; i++) {

		audio1575_port_t *port = statep->ports[i];

		if (port != NULL) {
			/* reset framework DMA engine buffer */
			if (port->engine != NULL) {
				audio_engine_reset(port->engine);
			}

			/* reset and initialize hardware ports */
			audio1575_reset_port(port);
			if (port->started) {
				audio1575_start_port(port);
			} else {
				audio1575_stop_port(port);
			}
		}
	}
	mutex_exit(&statep->lock);

	return (DDI_SUCCESS);
}

/*
 * audio1575_suspend()
 *
 * Description:
 *	Suspend an instance of the audio1575 driver.
 *
 * Arguments:
 *	dev_info_t	*dip	Pointer to the device's dev_info struct
 *
 * Returns:
 *	DDI_SUCCESS	The driver was suspended
 */
static int
audio1575_suspend(dev_info_t *dip)
{
	audio1575_state_t	*statep;

	statep = ddi_get_driver_private(dip);

	ac97_suspend(statep->ac97);

	mutex_enter(&statep->lock);

	statep->suspended = B_TRUE;

	/*
	 * stop all DMA operations
	 */
	audio1575_dma_stop(statep, B_FALSE);

	mutex_exit(&statep->lock);

	return (DDI_SUCCESS);
}

/*
 * audio1575_destroy()
 *
 * Description:
 *	This routine releases all resources held by the device instance,
 *	as part of either detach or a failure in attach.
 *
 * Arguments:
 *	audio1575_state_t	*state	The device soft state.
 *
 * Returns:
 *	None
 */
void
audio1575_destroy(audio1575_state_t *statep)
{
	ddi_acc_handle_t	pcih;

	/* stop DMA engines */
	audio1575_dma_stop(statep, B_FALSE);

	if (statep->regsh != NULL) {
		/* reset the codec */
		PUT32(M1575_SCR_REG, M1575_SCR_COLDRST);
	}

	if ((pcih = statep->pcih) != NULL) {
		/* turn off the AC_LINK clock */
		pci_config_put8(pcih, M1575_PCIACD_REG, 0);
		pci_config_put8(pcih, M1575_PCIACD_REG, 4);
		pci_config_put8(pcih, M1575_PCIACD_REG, 0);
	}

	/* Disable PCI I/O and Memory Spaces */
	audio1575_pci_disable(statep);

	if (statep->ih != NULL) {
		(void) ddi_intr_disable(statep->ih);
		(void) ddi_intr_remove_handler(statep->ih);
		(void) ddi_intr_free(statep->ih);
		mutex_destroy(&statep->lock);
		mutex_destroy(&statep->ac_lock);
	}

	if (statep->ksp != NULL) {
		kstat_delete(statep->ksp);
	}

	audio1575_free_port(statep->ports[M1575_PLAY]);
	audio1575_free_port(statep->ports[M1575_REC]);

	audio1575_unmap_regs(statep);

	if (statep->ac97 != NULL) {
		ac97_free(statep->ac97);
	}

	if (statep->adev != NULL) {
		audio_dev_free(statep->adev);
	}

	kmem_free(statep, sizeof (*statep));
}
