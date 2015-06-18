/*
 *
 *  skd.c: Solaris 11/10 Driver for sTec, Inc. S112x PCIe SSD card
 *
 *  Solaris driver is based on the Linux driver authored by:
 *
 *  Authors/Alphabetical:	Dragan Stancevic <dstancevic@stec-inc.com>
 *				Gordon Waidhofer <gwaidhofer@stec-inc.com>
 *				John Hamilton	 <jhamilton@stec-inc.com>
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 STEC, Inc.  All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/cmn_err.h>
#include	<sys/kmem.h>
#include	<sys/file.h>
#include	<sys/buf.h>
#include	<sys/uio.h>
#include	<sys/cred.h>
#include	<sys/modctl.h>
#include 	<sys/debug.h>
#include 	<sys/modctl.h>
#include 	<sys/list.h>
#include 	<sys/sysmacros.h>
#include 	<sys/errno.h>
#include 	<sys/pcie.h>
#include 	<sys/pci.h>
#include	<sys/ddi.h>
#include	<sys/dditypes.h>
#include	<sys/sunddi.h>
#include	<sys/atomic.h>
#include	<sys/mutex.h>
#include	<sys/param.h>
#include 	<sys/devops.h>
#include	<sys/blkdev.h>
#include	<sys/queue.h>

#include	"skd_s1120.h"
#include	"skd.h"

int		skd_dbg_level	  = 0;

void		*skd_state	  = NULL;
int		skd_disable_msi	  = 0;
int		skd_disable_msix  = 0;

/* Initialized in _init() and tunable, see _init(). */
clock_t		skd_timer_ticks;

/* I/O DMA attributes structures. */
static ddi_dma_attr_t skd_64bit_io_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	SKD_DMA_LOW_ADDRESS,		/* low DMA address range */
	SKD_DMA_HIGH_64BIT_ADDRESS,	/* high DMA address range */
	SKD_DMA_XFER_COUNTER,		/* DMA counter register */
	SKD_DMA_ADDRESS_ALIGNMENT,	/* DMA address alignment */
	SKD_DMA_BURSTSIZES,		/* DMA burstsizes */
	SKD_DMA_MIN_XFER_SIZE,		/* min effective DMA size */
	SKD_DMA_MAX_XFER_SIZE,		/* max DMA xfer size */
	SKD_DMA_SEGMENT_BOUNDARY,	/* segment boundary */
	SKD_DMA_SG_LIST_LENGTH,		/* s/g list length */
	SKD_DMA_GRANULARITY,		/* granularity of device */
	SKD_DMA_XFER_FLAGS		/* DMA transfer flags */
};

int skd_isr_type = -1;

#define	SKD_MAX_QUEUE_DEPTH	    255
#define	SKD_MAX_QUEUE_DEPTH_DEFAULT 64
int skd_max_queue_depth = SKD_MAX_QUEUE_DEPTH_DEFAULT;

#define	SKD_MAX_REQ_PER_MSG	    14
#define	SKD_MAX_REQ_PER_MSG_DEFAULT 1
int skd_max_req_per_msg = SKD_MAX_REQ_PER_MSG_DEFAULT;

#define	SKD_MAX_N_SG_PER_REQ	    4096
int skd_sgs_per_request = SKD_N_SG_PER_REQ_DEFAULT;

static int skd_sys_quiesce_dev(dev_info_t *);
static int skd_quiesce_dev(skd_device_t *);
static int skd_list_skmsg(skd_device_t *, int);
static int skd_list_skreq(skd_device_t *, int);
static int skd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int skd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int skd_format_internal_skspcl(struct skd_device *skdev);
static void skd_start(skd_device_t *);
static void skd_destroy_mutex(skd_device_t *skdev);
static void skd_enable_interrupts(struct skd_device *);
static void skd_request_fn_not_online(skd_device_t *skdev);
static void skd_send_internal_skspcl(struct skd_device *,
    struct skd_special_context *, uint8_t);
static void skd_queue(skd_device_t *, skd_buf_private_t *);
static void *skd_alloc_dma_mem(skd_device_t *, dma_mem_t *, uint8_t);
static void skd_release_intr(skd_device_t *skdev);
static void skd_isr_fwstate(struct skd_device *skdev);
static void skd_isr_msg_from_dev(struct skd_device *skdev);
static void skd_soft_reset(struct skd_device *skdev);
static void skd_refresh_device_data(struct skd_device *skdev);
static void skd_update_props(skd_device_t *, dev_info_t *);
static void skd_end_request_abnormal(struct skd_device *, skd_buf_private_t *,
    int, int);
static char *skd_pci_info(struct skd_device *skdev, char *str, size_t len);

static skd_buf_private_t *skd_get_queued_pbuf(skd_device_t *);

static void skd_bd_driveinfo(void *arg, bd_drive_t *drive);
static int  skd_bd_mediainfo(void *arg, bd_media_t *media);
static int  skd_bd_read(void *arg,  bd_xfer_t *xfer);
static int  skd_bd_write(void *arg, bd_xfer_t *xfer);
static int  skd_devid_init(void *arg, dev_info_t *, ddi_devid_t *);


static bd_ops_t skd_bd_ops = {
	BD_OPS_VERSION_0,
	skd_bd_driveinfo,
	skd_bd_mediainfo,
	skd_devid_init,
	NULL,			/* sync_cache */
	skd_bd_read,
	skd_bd_write,
};

static ddi_device_acc_attr_t	dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Solaris module loading/unloading structures
 */
struct dev_ops skd_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* refcnt */
	ddi_no_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	skd_attach,			/* attach */
	skd_detach,			/* detach */
	nodev,				/* reset */
	NULL,				/* char/block ops */
	NULL,				/* bus operations */
	NULL,				/* power management */
	skd_sys_quiesce_dev		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* type of module: driver */
	"sTec skd v" DRV_VER_COMPL,	/* name of module */
	&skd_dev_ops			/* driver dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * sTec-required wrapper for debug printing.
 */
/*PRINTFLIKE2*/
static inline void
Dcmn_err(int lvl, const char *fmt, ...)
{
	va_list ap;

	if (skd_dbg_level == 0)
		return;

	va_start(ap, fmt);
	vcmn_err(lvl, fmt, ap);
	va_end(ap);
}

/*
 * Solaris module loading/unloading routines
 */

/*
 *
 * Name:	_init, performs initial installation
 *
 * Inputs:	None.
 *
 * Returns:	Returns the value returned by the ddi_softstate_init function
 *		on a failure to create the device state structure or the result
 *		of the module install routines.
 *
 */
int
_init(void)
{
	int		rval = 0;
	int		tgts = 0;

	tgts |= 0x02;
	tgts |= 0x08;	/* In #ifdef NEXENTA block from original sTec drop. */

	/*
	 * drv_usectohz() is a function, so can't initialize it at
	 * instantiation.
	 */
	skd_timer_ticks = drv_usectohz(1000000);

	Dcmn_err(CE_NOTE,
	    "<# Installing skd Driver dbg-lvl=%d %s %x>",
	    skd_dbg_level, DRV_BUILD_ID, tgts);

	rval = ddi_soft_state_init(&skd_state, sizeof (skd_device_t), 0);
	if (rval != DDI_SUCCESS)
		return (rval);

	bd_mod_init(&skd_dev_ops);

	rval = mod_install(&modlinkage);
	if (rval != DDI_SUCCESS) {
		ddi_soft_state_fini(&skd_state);
		bd_mod_fini(&skd_dev_ops);
	}

	return (rval);
}

/*
 *
 * Name: 	_info, returns information about loadable module.
 *
 * Inputs: 	modinfo, pointer to module information structure.
 *
 * Returns: 	Value returned by mod_info().
 *
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * _fini 	Prepares a module for unloading. It is called when the system
 *		wants to unload a module. If the module determines that it can
 *		be unloaded, then _fini() returns the value returned by
 *		mod_remove(). Upon successful return from _fini() no other
 *		routine in the module will be called before _init() is called.
 *
 * Inputs:	None.
 *
 * Returns: 	DDI_SUCCESS or DDI_FAILURE.
 *
 */
int
_fini(void)
{
	int rval;

	rval = mod_remove(&modlinkage);
	if (rval == DDI_SUCCESS) {
		ddi_soft_state_fini(&skd_state);
		bd_mod_fini(&skd_dev_ops);
	}

	return (rval);
}

/*
 * Solaris Register read/write routines
 */

/*
 *
 * Name:	skd_reg_write64, writes a 64-bit value to specified address
 *
 * Inputs:	skdev		- device state structure.
 *		val		- 64-bit value to be written.
 *		offset		- offset from PCI base address.
 *
 * Returns:	Nothing.
 *
 */
/*
 * Local vars are to keep lint silent.  Any compiler worth its weight will
 * optimize it all right out...
 */
static inline void
skd_reg_write64(struct skd_device *skdev, uint64_t val, uint32_t offset)
{
	uint64_t *addr;

	ASSERT((offset & 0x7) == 0);
	/* LINTED */
	addr = (uint64_t *)(skdev->dev_iobase + offset);
	ddi_put64(skdev->dev_handle, addr, val);
}

/*
 *
 * Name:	skd_reg_read32, reads a 32-bit value to specified address
 *
 * Inputs:	skdev		- device state structure.
 *		offset		- offset from PCI base address.
 *
 * Returns:	val, 32-bit value read from specified PCI address.
 *
 */
static inline uint32_t
skd_reg_read32(struct skd_device *skdev, uint32_t offset)
{
	uint32_t *addr;

	ASSERT((offset & 0x3) == 0);
	/* LINTED */
	addr = (uint32_t *)(skdev->dev_iobase + offset);
	return (ddi_get32(skdev->dev_handle, addr));
}

/*
 *
 * Name:	skd_reg_write32, writes a 32-bit value to specified address
 *
 * Inputs:	skdev		- device state structure.
 *		val		- value to be written.
 *		offset		- offset from PCI base address.
 *
 * Returns:	Nothing.
 *
 */
static inline void
skd_reg_write32(struct skd_device *skdev, uint32_t val, uint32_t offset)
{
	uint32_t *addr;

	ASSERT((offset & 0x3) == 0);
	/* LINTED */
	addr = (uint32_t *)(skdev->dev_iobase + offset);
	ddi_put32(skdev->dev_handle, addr, val);
}


/*
 * Solaris skd routines
 */

/*
 *
 * Name:	skd_name, generates the name of the driver.
 *
 * Inputs:	skdev	- device state structure
 *
 * Returns:	char pointer to generated driver name.
 *
 */
static const char *
skd_name(struct skd_device *skdev)
{
	(void) snprintf(skdev->id_str, sizeof (skdev->id_str), "%s:", DRV_NAME);

	return (skdev->id_str);
}

/*
 *
 * Name:	skd_pci_find_capability, searches the PCI capability
 *		list for the specified capability.
 *
 * Inputs:	skdev		- device state structure.
 *		cap		- capability sought.
 *
 * Returns:	Returns position where capability was found.
 *		If not found, returns zero.
 *
 */
static int
skd_pci_find_capability(struct skd_device *skdev, int cap)
{
	uint16_t status;
	uint8_t	 pos, id, hdr;
	int	 ttl = 48;

	status = pci_config_get16(skdev->pci_handle, PCI_CONF_STAT);

	if (!(status & PCI_STAT_CAP))
		return (0);

	hdr = pci_config_get8(skdev->pci_handle, PCI_CONF_HEADER);

	if ((hdr & PCI_HEADER_TYPE_M) != 0)
		return (0);

	pos = pci_config_get8(skdev->pci_handle, PCI_CONF_CAP_PTR);

	while (ttl-- && pos >= 0x40) {
		pos &= ~3;
		id = pci_config_get8(skdev->pci_handle, pos+PCI_CAP_ID);
		if (id == 0xff)
			break;
		if (id == cap)
			return (pos);
		pos = pci_config_get8(skdev->pci_handle, pos+PCI_CAP_NEXT_PTR);
	}

	return (0);
}

/*
 *
 * Name:	skd_io_done, called to conclude an I/O operation.
 *
 * Inputs:	skdev		- device state structure.
 *		pbuf		- I/O request
 *		error		- contain error value.
 *		mode		- debug only.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_io_done(skd_device_t *skdev, skd_buf_private_t *pbuf,
    int error, int mode)
{
	bd_xfer_t *xfer;

	ASSERT(pbuf != NULL);

	xfer = pbuf->x_xfer;

	switch (mode) {
	case SKD_IODONE_WIOC:
		skdev->iodone_wioc++;
		break;
	case SKD_IODONE_WNIOC:
		skdev->iodone_wnioc++;
		break;
	case SKD_IODONE_WDEBUG:
		skdev->iodone_wdebug++;
		break;
	default:
		skdev->iodone_unknown++;
	}

	if (error) {
		skdev->ios_errors++;
		cmn_err(CE_WARN,
		    "!%s:skd_io_done:ERR=%d %lld-%ld %s", skdev->name,
		    error, xfer->x_blkno, xfer->x_nblks,
		    (pbuf->dir & B_READ) ? "Read" : "Write");
	}

	kmem_free(pbuf, sizeof (skd_buf_private_t));

	bd_xfer_done(xfer,  error);
}

/*
 * QUIESCE DEVICE
 */

/*
 *
 * Name:	skd_sys_quiesce_dev, quiets the device
 *
 * Inputs:	dip		- dev info strucuture
 *
 * Returns:	Zero.
 *
 */
static int
skd_sys_quiesce_dev(dev_info_t *dip)
{
	skd_device_t	*skdev;

	skdev = ddi_get_soft_state(skd_state, ddi_get_instance(dip));

	/* make sure Dcmn_err() doesn't actually print anything */
	skd_dbg_level = 0;

	skd_disable_interrupts(skdev);
	skd_soft_reset(skdev);

	return (0);
}

/*
 *
 * Name:	skd_quiesce_dev, quiets the device, but doesn't really do much.
 *
 * Inputs:	skdev		- Device state.
 *
 * Returns:	-EINVAL if device is not in proper state otherwise
 *		returns zero.
 *
 */
static int
skd_quiesce_dev(skd_device_t *skdev)
{
	int rc = 0;

	if (skd_dbg_level)
		Dcmn_err(CE_NOTE, "skd_quiece_dev:");

	switch (skdev->state) {
	case SKD_DRVR_STATE_BUSY:
	case SKD_DRVR_STATE_BUSY_IMMINENT:
		Dcmn_err(CE_NOTE, "%s: stopping queue", skdev->name);
		break;
	case SKD_DRVR_STATE_ONLINE:
	case SKD_DRVR_STATE_STOPPING:
	case SKD_DRVR_STATE_SYNCING:
	case SKD_DRVR_STATE_PAUSING:
	case SKD_DRVR_STATE_PAUSED:
	case SKD_DRVR_STATE_STARTING:
	case SKD_DRVR_STATE_RESTARTING:
	case SKD_DRVR_STATE_RESUMING:
	default:
		rc = -EINVAL;
		cmn_err(CE_NOTE, "state [%d] not implemented", skdev->state);
	}

	return (rc);
}

/*
 * UNQUIESCE DEVICE:
 * Note: Assumes lock is held to protect device state.
 */
/*
 *
 * Name:	skd_unquiesce_dev, awkens the device
 *
 * Inputs:	skdev		- Device state.
 *
 * Returns:	-EINVAL if device is not in proper state otherwise
 *		returns zero.
 *
 */
static int
skd_unquiesce_dev(struct skd_device *skdev)
{
	Dcmn_err(CE_NOTE, "skd_unquiece_dev:");

	skd_log_skdev(skdev, "unquiesce");
	if (skdev->state == SKD_DRVR_STATE_ONLINE) {
		Dcmn_err(CE_NOTE, "**** device already ONLINE");

		return (0);
	}
	if (skdev->drive_state != FIT_SR_DRIVE_ONLINE) {
		/*
		 * If there has been an state change to other than
		 * ONLINE, we will rely on controller state change
		 * to come back online and restart the queue.
		 * The BUSY state means that driver is ready to
		 * continue normal processing but waiting for controller
		 * to become available.
		 */
		skdev->state = SKD_DRVR_STATE_BUSY;
		Dcmn_err(CE_NOTE, "drive BUSY state\n");

		return (0);
	}
	/*
	 * Drive just come online, driver is either in startup,
	 * paused performing a task, or bust waiting for hardware.
	 */
	switch (skdev->state) {
	case SKD_DRVR_STATE_PAUSED:
	case SKD_DRVR_STATE_BUSY:
	case SKD_DRVR_STATE_BUSY_IMMINENT:
	case SKD_DRVR_STATE_BUSY_ERASE:
	case SKD_DRVR_STATE_STARTING:
	case SKD_DRVR_STATE_RESTARTING:
	case SKD_DRVR_STATE_FAULT:
	case SKD_DRVR_STATE_IDLE:
	case SKD_DRVR_STATE_LOAD:
		skdev->state = SKD_DRVR_STATE_ONLINE;
		Dcmn_err(CE_NOTE, "%s: sTec s1120 ONLINE", skdev->name);
		Dcmn_err(CE_NOTE, "%s: Starting request queue", skdev->name);
		Dcmn_err(CE_NOTE,
		    "%s: queue depth limit=%d hard=%d soft=%d lowat=%d",
		    skdev->name,
		    skdev->queue_depth_limit,
		    skdev->hard_queue_depth_limit,
		    skdev->soft_queue_depth_limit,
		    skdev->queue_depth_lowat);

		skdev->gendisk_on = 1;
		cv_signal(&skdev->cv_waitq);
		break;
	case SKD_DRVR_STATE_DISAPPEARED:
	default:
		cmn_err(CE_NOTE, "**** driver state %d, not implemented \n",
		    skdev->state);
		return (-EBUSY);
	}

	return (0);
}

/*
 * READ/WRITE REQUESTS
 */

/*
 *
 * Name:	skd_blkdev_preop_sg_list, builds the S/G list from info
 *		passed in by the blkdev driver.
 *
 * Inputs:	skdev		- device state structure.
 *		skreq		- request structure.
 *		sg_byte_count	- data transfer byte count.
 *
 * Returns:	Nothing.
 *
 */
/*ARGSUSED*/
static void
skd_blkdev_preop_sg_list(struct skd_device *skdev,
    struct skd_request_context *skreq, uint32_t *sg_byte_count)
{
	bd_xfer_t		*xfer;
	skd_buf_private_t 	*pbuf;
	int 			i, bcount = 0;
	uint_t 			n_sg;

	*sg_byte_count = 0;

	ASSERT(skreq->sg_data_dir == SKD_DATA_DIR_HOST_TO_CARD ||
	    skreq->sg_data_dir == SKD_DATA_DIR_CARD_TO_HOST);

	pbuf = skreq->pbuf;
	ASSERT(pbuf != NULL);

	xfer = pbuf->x_xfer;
	n_sg = xfer->x_ndmac;

	ASSERT(n_sg <= skdev->sgs_per_request);

	skreq->n_sg = n_sg;

	skreq->io_dma_handle = xfer->x_dmah;

	skreq->total_sg_bcount = 0;

	for (i = 0; i < n_sg; i++) {
		ddi_dma_cookie_t *cookiep = &xfer->x_dmac;
		struct fit_sg_descriptor *sgd;
		uint32_t cnt = (uint32_t)cookiep->dmac_size;

		bcount += cnt;

		sgd			= &skreq->sksg_list[i];
		sgd->control		= FIT_SGD_CONTROL_NOT_LAST;
		sgd->byte_count		= cnt;
		sgd->host_side_addr	= cookiep->dmac_laddress;
		sgd->dev_side_addr	= 0; /* not used */
		*sg_byte_count		+= cnt;

		skreq->total_sg_bcount += cnt;

		if ((i + 1) != n_sg)
			ddi_dma_nextcookie(skreq->io_dma_handle, &xfer->x_dmac);
	}

	skreq->sksg_list[n_sg - 1].next_desc_ptr = 0LL;
	skreq->sksg_list[n_sg - 1].control = FIT_SGD_CONTROL_LAST;

	(void) ddi_dma_sync(skreq->sksg_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
}

/*
 *
 * Name:	skd_blkdev_postop_sg_list, deallocates DMA
 *
 * Inputs:	skdev		- device state structure.
 *		skreq		- skreq data structure.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static void
skd_blkdev_postop_sg_list(struct skd_device *skdev,
    struct skd_request_context *skreq)
{
	/*
	 * restore the next ptr for next IO request so we
	 * don't have to set it every time.
	 */
	skreq->sksg_list[skreq->n_sg - 1].next_desc_ptr =
	    skreq->sksg_dma_address.cookies->dmac_laddress +
	    ((skreq->n_sg) * sizeof (struct fit_sg_descriptor));
}

/*
 *
 * Name:	skd_start, initiates an I/O.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	EAGAIN if devicfe is not ONLINE.
 *		On error, if the caller is the blkdev driver, return
 *		the error value. Otherwise, return zero.
 *
 */
/* Upstream common source with other platforms. */
static void
skd_start(skd_device_t *skdev)
{
	struct skd_fitmsg_context	*skmsg = NULL;
	struct fit_msg_hdr		*fmh = NULL;
	struct skd_request_context	*skreq = NULL;
	struct waitqueue		*waitq = &skdev->waitqueue;
	struct skd_scsi_request		*scsi_req;
	skd_buf_private_t		*pbuf = NULL;
	int				bcount;

	uint32_t			lba;
	uint32_t			count;
	uint32_t			timo_slot;
	void				*cmd_ptr;
	uint32_t			sg_byte_count = 0;

	/*
	 * Stop conditions:
	 *  - There are no more native requests
	 *  - There are already the maximum number of requests is progress
	 *  - There are no more skd_request_context entries
	 *  - There are no more FIT msg buffers
	 */
	for (;;) {
		/* Are too many requests already in progress? */
		if (skdev->queue_depth_busy >= skdev->queue_depth_limit) {
			Dcmn_err(CE_NOTE, "qdepth %d, limit %d\n",
			    skdev->queue_depth_busy,
			    skdev->queue_depth_limit);
			break;
		}

		WAITQ_LOCK(skdev);
		if (SIMPLEQ_EMPTY(waitq)) {
			WAITQ_UNLOCK(skdev);
			break;
		}

		/* Is a skd_request_context available? */
		skreq = skdev->skreq_free_list;
		if (skreq == NULL) {
			WAITQ_UNLOCK(skdev);
			break;
		}

		ASSERT(skreq->state == SKD_REQ_STATE_IDLE);
		ASSERT((skreq->id & SKD_ID_INCR) == 0);

		skdev->skreq_free_list = skreq->next;

		skreq->state = SKD_REQ_STATE_BUSY;
		skreq->id += SKD_ID_INCR;

		/* Start a new FIT msg if there is none in progress. */
		if (skmsg == NULL) {
			/* Are there any FIT msg buffers available? */
			skmsg = skdev->skmsg_free_list;
			if (skmsg == NULL) {
				WAITQ_UNLOCK(skdev);
				break;
			}

			ASSERT(skmsg->state == SKD_MSG_STATE_IDLE);
			ASSERT((skmsg->id & SKD_ID_INCR) == 0);

			skdev->skmsg_free_list = skmsg->next;

			skmsg->state = SKD_MSG_STATE_BUSY;
			skmsg->id += SKD_ID_INCR;

			/* Initialize the FIT msg header */
			fmh = (struct fit_msg_hdr *)skmsg->msg_buf64;
			bzero(fmh, sizeof (*fmh)); /* Too expensive */
			fmh->protocol_id = FIT_PROTOCOL_ID_SOFIT;
			skmsg->length = sizeof (struct fit_msg_hdr);
		}

		/*
		 * At this point we are committed to either start or reject
		 * the native request. Note that a FIT msg may have just been
		 * started but contains no SoFIT requests yet.
		 * Now - dequeue pbuf.
		 */
		pbuf = skd_get_queued_pbuf(skdev);
		WAITQ_UNLOCK(skdev);

		skreq->pbuf = pbuf;
		lba = pbuf->x_xfer->x_blkno;
		count = pbuf->x_xfer->x_nblks;
		skreq->did_complete = 0;

		skreq->fitmsg_id = skmsg->id;

		Dcmn_err(CE_NOTE,
		    "pbuf=%p lba=%u(0x%x) count=%u(0x%x) dir=%x\n",
		    (void *)pbuf, lba, lba, count, count, pbuf->dir);

		/*
		 * Transcode the request.
		 */
		cmd_ptr = &skmsg->msg_buf[skmsg->length];
		bzero(cmd_ptr, 32); /* This is too expensive */

		scsi_req = cmd_ptr;
		scsi_req->hdr.tag = skreq->id;
		scsi_req->hdr.sg_list_dma_address =
		    cpu_to_be64(skreq->sksg_dma_address.cookies->dmac_laddress);
		scsi_req->cdb[1] = 0;
		scsi_req->cdb[2] = (lba & 0xff000000) >> 24;
		scsi_req->cdb[3] = (lba & 0xff0000) >> 16;
		scsi_req->cdb[4] = (lba & 0xff00) >> 8;
		scsi_req->cdb[5] = (lba & 0xff);
		scsi_req->cdb[6] = 0;
		scsi_req->cdb[7] = (count & 0xff00) >> 8;
		scsi_req->cdb[8] = count & 0xff;
		scsi_req->cdb[9] = 0;

		if (pbuf->dir & B_READ) {
			scsi_req->cdb[0] = 0x28;
			skreq->sg_data_dir = SKD_DATA_DIR_CARD_TO_HOST;
		} else {
			scsi_req->cdb[0] = 0x2a;
			skreq->sg_data_dir = SKD_DATA_DIR_HOST_TO_CARD;
		}

		skd_blkdev_preop_sg_list(skdev, skreq, &sg_byte_count);

		scsi_req->hdr.sg_list_len_bytes = cpu_to_be32(sg_byte_count);

		bcount = (sg_byte_count + 511) / 512;
		scsi_req->cdb[7] = (bcount & 0xff00) >> 8;
		scsi_req->cdb[8] =  bcount & 0xff;

		Dcmn_err(CE_NOTE,
		    "skd_start: pbuf=%p skreq->id=%x opc=%x ====>>>>>",
		    (void *)pbuf, skreq->id, *scsi_req->cdb);

		skmsg->length += sizeof (struct skd_scsi_request);
		fmh->num_protocol_cmds_coalesced++;

		/*
		 * Update the active request counts.
		 * Capture the timeout timestamp.
		 */
		skreq->timeout_stamp = skdev->timeout_stamp;
		timo_slot = skreq->timeout_stamp & SKD_TIMEOUT_SLOT_MASK;

		atomic_inc_32(&skdev->timeout_slot[timo_slot]);
		atomic_inc_32(&skdev->queue_depth_busy);

		Dcmn_err(CE_NOTE, "req=0x%x busy=%d timo_slot=%d",
		    skreq->id, skdev->queue_depth_busy, timo_slot);
		/*
		 * If the FIT msg buffer is full send it.
		 */
		if (skmsg->length >= SKD_N_FITMSG_BYTES ||
		    fmh->num_protocol_cmds_coalesced >= skd_max_req_per_msg) {

			atomic_inc_64(&skdev->active_cmds);
			pbuf->skreq = skreq;

			skdev->fitmsg_sent1++;
			skd_send_fitmsg(skdev, skmsg);

			skmsg = NULL;
			fmh = NULL;
		}
	}

	/*
	 * Is a FIT msg in progress? If it is empty put the buffer back
	 * on the free list. If it is non-empty send what we got.
	 * This minimizes latency when there are fewer requests than
	 * what fits in a FIT msg.
	 */
	if (skmsg != NULL) {
		ASSERT(skmsg->length > sizeof (struct fit_msg_hdr));
		Dcmn_err(CE_NOTE, "sending msg=%p, len %d",
		    (void *)skmsg, skmsg->length);

		skdev->active_cmds++;

		skdev->fitmsg_sent2++;
		skd_send_fitmsg(skdev, skmsg);
	}
}

/*
 *
 * Name:	skd_end_request
 *
 * Inputs:	skdev		- device state structure.
 *		skreq		- request structure.
 *		error		- I/O error value.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_end_request(struct skd_device *skdev,
    struct skd_request_context *skreq, int error)
{
	skdev->ios_completed++;
	skd_io_done(skdev, skreq->pbuf, error, SKD_IODONE_WIOC);
	skreq->pbuf = NULL;
	skreq->did_complete = 1;
}

/*
 *
 * Name:	skd_end_request_abnormal
 *
 * Inputs:	skdev		- device state structure.
 *		pbuf		- I/O request.
 *		error		- I/O error value.
 *		mode		- debug
 *
 * Returns:	Nothing.
 *
 */
static void
skd_end_request_abnormal(skd_device_t *skdev, skd_buf_private_t *pbuf,
    int error, int mode)
{
	skd_io_done(skdev, pbuf, error, mode);
}

/*
 *
 * Name:	skd_request_fn_not_online, handles the condition
 *		of the device not being online.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	nothing (void).
 *
 */
static void
skd_request_fn_not_online(skd_device_t *skdev)
{
	int error;
	skd_buf_private_t *pbuf;

	ASSERT(skdev->state != SKD_DRVR_STATE_ONLINE);

	skd_log_skdev(skdev, "req_not_online");

	switch (skdev->state) {
	case SKD_DRVR_STATE_PAUSING:
	case SKD_DRVR_STATE_PAUSED:
	case SKD_DRVR_STATE_STARTING:
	case SKD_DRVR_STATE_RESTARTING:
	case SKD_DRVR_STATE_WAIT_BOOT:
		/*
		 * In case of starting, we haven't started the queue,
		 * so we can't get here... but requests are
		 * possibly hanging out waiting for us because we
		 * reported the dev/skd/0 already.  They'll wait
		 * forever if connect doesn't complete.
		 * What to do??? delay dev/skd/0 ??
		 */
	case SKD_DRVR_STATE_BUSY:
	case SKD_DRVR_STATE_BUSY_IMMINENT:
	case SKD_DRVR_STATE_BUSY_ERASE:
	case SKD_DRVR_STATE_DRAINING_TIMEOUT:
		return;

	case SKD_DRVR_STATE_BUSY_SANITIZE:
	case SKD_DRVR_STATE_STOPPING:
	case SKD_DRVR_STATE_SYNCING:
	case SKD_DRVR_STATE_FAULT:
	case SKD_DRVR_STATE_DISAPPEARED:
	default:
		error = -EIO;
		break;
	}

	/*
	 * If we get here, terminate all pending block requeusts
	 * with EIO and any scsi pass thru with appropriate sense
	 */
	ASSERT(WAITQ_LOCK_HELD(skdev));
	if (SIMPLEQ_EMPTY(&skdev->waitqueue))
		return;

	while ((pbuf = skd_get_queued_pbuf(skdev)))
		skd_end_request_abnormal(skdev, pbuf, error, SKD_IODONE_WNIOC);

	cv_signal(&skdev->cv_waitq);
}

/*
 * TIMER
 */

static void skd_timer_tick_not_online(struct skd_device *skdev);

/*
 *
 * Name:	skd_timer_tick, monitors requests for timeouts.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_timer_tick(skd_device_t *skdev)
{
	uint32_t timo_slot;

	skdev->timer_active = 1;

	if (skdev->state != SKD_DRVR_STATE_ONLINE) {
		skd_timer_tick_not_online(skdev);
		goto timer_func_out;
	}

	skdev->timeout_stamp++;
	timo_slot = skdev->timeout_stamp & SKD_TIMEOUT_SLOT_MASK;

	/*
	 * All requests that happened during the previous use of
	 * this slot should be done by now. The previous use was
	 * over 7 seconds ago.
	 */
	if (skdev->timeout_slot[timo_slot] == 0) {
		goto timer_func_out;
	}

	/* Something is overdue */
	Dcmn_err(CE_NOTE, "found %d timeouts, draining busy=%d",
	    skdev->timeout_slot[timo_slot],
	    skdev->queue_depth_busy);
	skdev->timer_countdown = SKD_TIMER_SECONDS(3);
	skdev->state = SKD_DRVR_STATE_DRAINING_TIMEOUT;
	skdev->timo_slot = timo_slot;

timer_func_out:
	skdev->timer_active = 0;
}

/*
 *
 * Name:	skd_timer_tick_not_online, handles various device
 *		state transitions.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_timer_tick_not_online(struct skd_device *skdev)
{
	Dcmn_err(CE_NOTE, "skd_skd_timer_tick_not_online: state=%d tmo=%d",
	    skdev->state, skdev->timer_countdown);

	ASSERT(skdev->state != SKD_DRVR_STATE_ONLINE);

	switch (skdev->state) {
	case SKD_DRVR_STATE_IDLE:
	case SKD_DRVR_STATE_LOAD:
		break;
	case SKD_DRVR_STATE_BUSY_SANITIZE:
		cmn_err(CE_WARN, "!drive busy sanitize[%x], driver[%x]\n",
		    skdev->drive_state, skdev->state);
		break;

	case SKD_DRVR_STATE_BUSY:
	case SKD_DRVR_STATE_BUSY_IMMINENT:
	case SKD_DRVR_STATE_BUSY_ERASE:
		Dcmn_err(CE_NOTE, "busy[%x], countdown=%d\n",
		    skdev->state, skdev->timer_countdown);
		if (skdev->timer_countdown > 0) {
			skdev->timer_countdown--;
			return;
		}
		cmn_err(CE_WARN, "!busy[%x], timedout=%d, restarting device.",
		    skdev->state, skdev->timer_countdown);
		skd_restart_device(skdev);
		break;

	case SKD_DRVR_STATE_WAIT_BOOT:
	case SKD_DRVR_STATE_STARTING:
		if (skdev->timer_countdown > 0) {
			skdev->timer_countdown--;
			return;
		}
		/*
		 * For now, we fault the drive.  Could attempt resets to
		 * revcover at some point.
		 */
		skdev->state = SKD_DRVR_STATE_FAULT;

		cmn_err(CE_WARN, "!(%s): DriveFault Connect Timeout (%x)",
		    skd_name(skdev), skdev->drive_state);

		/* start the queue so we can respond with error to requests */
		skd_start(skdev);

		/* wakeup anyone waiting for startup complete */
		skdev->gendisk_on = -1;

		cv_signal(&skdev->cv_waitq);
		break;


	case SKD_DRVR_STATE_PAUSING:
	case SKD_DRVR_STATE_PAUSED:
		break;

	case SKD_DRVR_STATE_DRAINING_TIMEOUT:
		cmn_err(CE_WARN,
		    "!%s: draining busy [%d] tick[%d] qdb[%d] tmls[%d]\n",
		    skdev->name,
		    skdev->timo_slot,
		    skdev->timer_countdown,
		    skdev->queue_depth_busy,
		    skdev->timeout_slot[skdev->timo_slot]);
		/* if the slot has cleared we can let the I/O continue */
		if (skdev->timeout_slot[skdev->timo_slot] == 0) {
			Dcmn_err(CE_NOTE, "Slot drained, starting queue.");
			skdev->state = SKD_DRVR_STATE_ONLINE;
			skd_start(skdev);
			return;
		}
		if (skdev->timer_countdown > 0) {
			skdev->timer_countdown--;
			return;
		}
		skd_restart_device(skdev);
		break;

	case SKD_DRVR_STATE_RESTARTING:
		if (skdev->timer_countdown > 0) {
			skdev->timer_countdown--;

			return;
		}
		/*
		 * For now, we fault the drive. Could attempt resets to
		 * revcover at some point.
		 */
		skdev->state = SKD_DRVR_STATE_FAULT;
		cmn_err(CE_WARN, "!(%s): DriveFault Reconnect Timeout (%x)\n",
		    skd_name(skdev), skdev->drive_state);

		/*
		 * Recovering does two things:
		 * 1. completes IO with error
		 * 2. reclaims dma resources
		 * When is it safe to recover requests?
		 * - if the drive state is faulted
		 * - if the state is still soft reset after out timeout
		 * - if the drive registers are dead (state = FF)
		 */

		if ((skdev->drive_state == FIT_SR_DRIVE_SOFT_RESET) ||
		    (skdev->drive_state == FIT_SR_DRIVE_FAULT) ||
		    (skdev->drive_state == FIT_SR_DRIVE_STATE_MASK)) {
			/*
			 * It never came out of soft reset. Try to
			 * recover the requests and then let them
			 * fail. This is to mitigate hung processes.
			 *
			 * Acquire the interrupt lock since these lists are
			 * manipulated by interrupt handlers.
			 */
			ASSERT(!WAITQ_LOCK_HELD(skdev));
			INTR_LOCK(skdev);
			skd_recover_requests(skdev);
			INTR_UNLOCK(skdev);
		}
		/* start the queue so we can respond with error to requests */
		skd_start(skdev);
		/* wakeup anyone waiting for startup complete */
		skdev->gendisk_on = -1;
		cv_signal(&skdev->cv_waitq);
		break;

	case SKD_DRVR_STATE_RESUMING:
	case SKD_DRVR_STATE_STOPPING:
	case SKD_DRVR_STATE_SYNCING:
	case SKD_DRVR_STATE_FAULT:
	case SKD_DRVR_STATE_DISAPPEARED:
	default:
		break;
	}
}

/*
 *
 * Name:	skd_timer, kicks off the timer processing.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_timer(void *arg)
{
	skd_device_t *skdev = (skd_device_t *)arg;

	/* Someone set us to 0, don't bother rescheduling. */
	ADAPTER_STATE_LOCK(skdev);
	if (skdev->skd_timer_timeout_id != 0) {
		ADAPTER_STATE_UNLOCK(skdev);
		/* Pardon the drop-and-then-acquire logic here. */
		skd_timer_tick(skdev);
		ADAPTER_STATE_LOCK(skdev);
		/* Restart timer, if not being stopped. */
		if (skdev->skd_timer_timeout_id != 0) {
			skdev->skd_timer_timeout_id =
			    timeout(skd_timer, arg, skd_timer_ticks);
		}
	}
	ADAPTER_STATE_UNLOCK(skdev);
}

/*
 *
 * Name:	skd_start_timer, kicks off the 1-second timer.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Zero.
 *
 */
static void
skd_start_timer(struct skd_device *skdev)
{
	/* Start one second driver timer. */
	ADAPTER_STATE_LOCK(skdev);
	ASSERT(skdev->skd_timer_timeout_id == 0);

	/*
	 * Do first "timeout tick" right away, but not in this
	 * thread.
	 */
	skdev->skd_timer_timeout_id = timeout(skd_timer, skdev, 1);
	ADAPTER_STATE_UNLOCK(skdev);
}

/*
 * INTERNAL REQUESTS -- generated by driver itself
 */

/*
 *
 * Name:	skd_format_internal_skspcl, setups the internal
 *		FIT request message.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	One.
 *
 */
static int
skd_format_internal_skspcl(struct skd_device *skdev)
{
	struct skd_special_context *skspcl = &skdev->internal_skspcl;
	struct fit_sg_descriptor *sgd = &skspcl->req.sksg_list[0];
	struct fit_msg_hdr *fmh;
	uint64_t dma_address;
	struct skd_scsi_request *scsi;

	fmh = (struct fit_msg_hdr *)&skspcl->msg_buf64[0];
	fmh->protocol_id = FIT_PROTOCOL_ID_SOFIT;
	fmh->num_protocol_cmds_coalesced = 1;

	/* Instead of 64-bytes in, use 8-(64-bit-words) for linted alignment. */
	scsi = (struct skd_scsi_request *)&skspcl->msg_buf64[8];
	bzero(scsi, sizeof (*scsi));
	dma_address = skspcl->req.sksg_dma_address.cookies->_dmu._dmac_ll;
	scsi->hdr.sg_list_dma_address = cpu_to_be64(dma_address);
	sgd->control = FIT_SGD_CONTROL_LAST;
	sgd->byte_count = 0;
	sgd->host_side_addr = skspcl->db_dma_address.cookies->_dmu._dmac_ll;
	sgd->dev_side_addr = 0; /* not used */
	sgd->next_desc_ptr = 0LL;

	return (1);
}

/*
 *
 * Name:	skd_send_internal_skspcl, send internal requests to
 *		the hardware.
 *
 * Inputs:	skdev		- device state structure.
 *		skspcl		- request structure
 *		opcode		- just what it says
 *
 * Returns:	Nothing.
 *
 */
void
skd_send_internal_skspcl(struct skd_device *skdev,
    struct skd_special_context *skspcl, uint8_t opcode)
{
	struct fit_sg_descriptor *sgd = &skspcl->req.sksg_list[0];
	struct skd_scsi_request *scsi;

	if (SKD_REQ_STATE_IDLE != skspcl->req.state) {
		/*
		 * A refresh is already in progress.
		 * Just wait for it to finish.
		 */
		return;
	}

	ASSERT(0 == (skspcl->req.id & SKD_ID_INCR));
	skspcl->req.state = SKD_REQ_STATE_BUSY;
	skspcl->req.id += SKD_ID_INCR;

	/* Instead of 64-bytes in, use 8-(64-bit-words) for linted alignment. */
	scsi = (struct skd_scsi_request *)&skspcl->msg_buf64[8];
	scsi->hdr.tag = skspcl->req.id;

	Dcmn_err(CE_NOTE, "internal skspcl: opcode=%x req.id=%x ==========>",
	    opcode, skspcl->req.id);

	switch (opcode) {
	case TEST_UNIT_READY:
		scsi->cdb[0] = TEST_UNIT_READY;
		scsi->cdb[1] = 0x00;
		scsi->cdb[2] = 0x00;
		scsi->cdb[3] = 0x00;
		scsi->cdb[4] = 0x00;
		scsi->cdb[5] = 0x00;
		sgd->byte_count = 0;
		scsi->hdr.sg_list_len_bytes = 0;
		break;
	case READ_CAPACITY_EXT:
		scsi->cdb[0]  = READ_CAPACITY_EXT;
		scsi->cdb[1]  = 0x10;
		scsi->cdb[2]  = 0x00;
		scsi->cdb[3]  = 0x00;
		scsi->cdb[4]  = 0x00;
		scsi->cdb[5]  = 0x00;
		scsi->cdb[6]  = 0x00;
		scsi->cdb[7]  = 0x00;
		scsi->cdb[8]  = 0x00;
		scsi->cdb[9]  = 0x00;
		scsi->cdb[10] = 0x00;
		scsi->cdb[11] = 0x00;
		scsi->cdb[12] = 0x00;
		scsi->cdb[13] = 0x20;
		scsi->cdb[14] = 0x00;
		scsi->cdb[15] = 0x00;
		sgd->byte_count = SKD_N_READ_CAP_EXT_BYTES;
		scsi->hdr.sg_list_len_bytes = cpu_to_be32(sgd->byte_count);
		break;
	case 0x28:
		(void) memset(skspcl->data_buf, 0x65, SKD_N_INTERNAL_BYTES);

		scsi->cdb[0] = 0x28;
		scsi->cdb[1] = 0x00;
		scsi->cdb[2] = 0x00;
		scsi->cdb[3] = 0x00;
		scsi->cdb[4] = 0x00;
		scsi->cdb[5] = 0x00;
		scsi->cdb[6] = 0x00;
		scsi->cdb[7] = 0x00;
		scsi->cdb[8] = 0x01;
		scsi->cdb[9] = 0x00;
		sgd->byte_count = SKD_N_INTERNAL_BYTES;
		scsi->hdr.sg_list_len_bytes = cpu_to_be32(SKD_N_INTERNAL_BYTES);
		break;
	case INQUIRY:
		scsi->cdb[0] = INQUIRY;
		scsi->cdb[1] = 0x01; /* evpd */
		scsi->cdb[2] = 0x80; /* serial number page */
		scsi->cdb[3] = 0x00;
		scsi->cdb[4] = 0x10;
		scsi->cdb[5] = 0x00;
		sgd->byte_count = 16; /* SKD_N_INQ_BYTES */;
		scsi->hdr.sg_list_len_bytes = cpu_to_be32(sgd->byte_count);
		break;
	case INQUIRY2:
		scsi->cdb[0] = INQUIRY;
		scsi->cdb[1] = 0x00;
		scsi->cdb[2] = 0x00; /* serial number page */
		scsi->cdb[3] = 0x00;
		scsi->cdb[4] = 0x24;
		scsi->cdb[5] = 0x00;
		sgd->byte_count = 36; /* SKD_N_INQ_BYTES */;
		scsi->hdr.sg_list_len_bytes = cpu_to_be32(sgd->byte_count);
		break;
	case SYNCHRONIZE_CACHE:
		scsi->cdb[0] = SYNCHRONIZE_CACHE;
		scsi->cdb[1] = 0x00;
		scsi->cdb[2] = 0x00;
		scsi->cdb[3] = 0x00;
		scsi->cdb[4] = 0x00;
		scsi->cdb[5] = 0x00;
		scsi->cdb[6] = 0x00;
		scsi->cdb[7] = 0x00;
		scsi->cdb[8] = 0x00;
		scsi->cdb[9] = 0x00;
		sgd->byte_count = 0;
		scsi->hdr.sg_list_len_bytes = 0;
		break;
	default:
		ASSERT("Don't know what to send");
		return;

	}

	skd_send_special_fitmsg(skdev, skspcl);
}

/*
 *
 * Name:	skd_refresh_device_data, sends a TUR command.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_refresh_device_data(struct skd_device *skdev)
{
	struct skd_special_context *skspcl = &skdev->internal_skspcl;

	Dcmn_err(CE_NOTE, "refresh_device_data: state=%d", skdev->state);

	skd_send_internal_skspcl(skdev, skspcl, TEST_UNIT_READY);
}

/*
 *
 * Name:	skd_complete_internal, handles the completion of
 *		driver-initiated I/O requests.
 *
 * Inputs:	skdev		- device state structure.
 *		skcomp		- completion structure.
 *		skerr		- error structure.
 *		skspcl		- request structure.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static void
skd_complete_internal(struct skd_device *skdev,
    volatile struct fit_completion_entry_v1 *skcomp,
    volatile struct fit_comp_error_info *skerr,
    struct skd_special_context *skspcl)
{
	uint8_t *buf = skspcl->data_buf;
	uint8_t status = 2;
	int i;
	/* Instead of 64-bytes in, use 8-(64-bit-words) for linted alignment. */
	struct skd_scsi_request *scsi =
	    (struct skd_scsi_request *)&skspcl->msg_buf64[8];

	ASSERT(skspcl == &skdev->internal_skspcl);

	(void) ddi_dma_sync(skspcl->db_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);
	(void) ddi_dma_sync(skspcl->mb_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	Dcmn_err(CE_NOTE, "complete internal %x", scsi->cdb[0]);

	skspcl->req.completion = *skcomp;
	skspcl->req.state = SKD_REQ_STATE_IDLE;
	skspcl->req.id += SKD_ID_INCR;

	status = skspcl->req.completion.status;

	Dcmn_err(CE_NOTE, "<<<<====== complete_internal: opc=%x", *scsi->cdb);

	switch (scsi->cdb[0]) {
	case TEST_UNIT_READY:
		if (SAM_STAT_GOOD == status) {
			skd_send_internal_skspcl(skdev, skspcl,
			    READ_CAPACITY_EXT);
		} else {
			if (skdev->state == SKD_DRVR_STATE_STOPPING) {
				cmn_err(CE_WARN,
				    "!%s: TUR failed, don't send anymore"
				    "state 0x%x", skdev->name, skdev->state);

				return;
			}

			Dcmn_err(CE_NOTE, "%s: TUR failed, retry skerr",
			    skdev->name);
			skd_send_internal_skspcl(skdev, skspcl, 0x00);
		}
		break;
	case READ_CAPACITY_EXT: {
		uint64_t cap, Nblocks;
		uint64_t xbuf[1];

		skdev->read_cap_is_valid = 0;
		if (SAM_STAT_GOOD == status) {
			bcopy(buf, xbuf, 8);
			cap = be64_to_cpu(*xbuf);
			skdev->read_cap_last_lba = cap;
			skdev->read_cap_blocksize =
			    (buf[8] << 24) | (buf[9] << 16) |
			    (buf[10] << 8) | buf[11];

			cap *= skdev->read_cap_blocksize;
			Dcmn_err(CE_NOTE, "  Last LBA: %" PRIu64 " (0x%" PRIx64
			    "), blk sz: %d, Capacity: %" PRIu64 "GB\n",
			    skdev->read_cap_last_lba,
			    skdev->read_cap_last_lba,
			    skdev->read_cap_blocksize,
			    cap >> 30ULL);

			Nblocks = skdev->read_cap_last_lba + 1;

			skdev->Nblocks = Nblocks;
			skdev->read_cap_is_valid = 1;

			skd_send_internal_skspcl(skdev, skspcl,	INQUIRY2);

		} else {
			Dcmn_err(CE_NOTE, "**** READCAP failed, retry TUR");
			skd_send_internal_skspcl(skdev, skspcl,
			    TEST_UNIT_READY);
		}
		break;
	}
	case INQUIRY:
		skdev->inquiry_is_valid = 0;
		if (SAM_STAT_GOOD == status) {
			skdev->inquiry_is_valid = 1;

			if (scsi->cdb[1] == 0x1) {
				bcopy(&buf[4], skdev->inq_serial_num, 12);
				skdev->inq_serial_num[12] = '\0';
			} else {
				char *tmp = skdev->inq_vendor_id;

				bcopy(&buf[8], tmp, 8);
				tmp[8] = '\0';
				for (i = 7; i >= 0 && tmp[i] != '\0'; i--)
					if (tmp[i] == ' ')
						tmp[i] = '\0';

				tmp = skdev->inq_product_id;
				bcopy(&buf[16], tmp, 16);
				tmp[16] = '\0';

				for (i = 15; i >= 0 && tmp[i] != '\0'; i--)
					if (tmp[i] == ' ')
						tmp[i] = '\0';

				tmp = skdev->inq_product_rev;
				bcopy(&buf[32], tmp, 4);
				tmp[4] = '\0';
			}
		}

		if (skdev->state != SKD_DRVR_STATE_ONLINE)
			if (skd_unquiesce_dev(skdev) < 0)
				cmn_err(CE_NOTE, "** failed, to ONLINE device");
		break;
	case SYNCHRONIZE_CACHE:
		skdev->sync_done = (SAM_STAT_GOOD == status) ? 1 : -1;

		cv_signal(&skdev->cv_waitq);
		break;

	default:
		ASSERT("we didn't send this");
	}
}

/*
 * FIT MESSAGES
 */

/*
 *
 * Name:	skd_send_fitmsg, send a FIT message to the hardware.
 *
 * Inputs:	skdev		- device state structure.
 *		skmsg		- FIT message structure.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static void
skd_send_fitmsg(struct skd_device *skdev,
    struct skd_fitmsg_context *skmsg)
{
	uint64_t qcmd;
	struct fit_msg_hdr *fmh;

	Dcmn_err(CE_NOTE, "msgbuf's DMA addr: 0x%" PRIx64 ", qdepth_busy=%d",
	    skmsg->mb_dma_address.cookies->dmac_laddress,
	    skdev->queue_depth_busy);

	Dcmn_err(CE_NOTE, "msg_buf 0x%p, offset %x", (void *)skmsg->msg_buf,
	    skmsg->offset);

	qcmd = skmsg->mb_dma_address.cookies->dmac_laddress;
	qcmd |= FIT_QCMD_QID_NORMAL;

	fmh = (struct fit_msg_hdr *)skmsg->msg_buf64;
	skmsg->outstanding = fmh->num_protocol_cmds_coalesced;

	if (skdev->dbg_level > 1) {
		uint8_t *bp = skmsg->msg_buf;
		int i;

		for (i = 0; i < skmsg->length; i += 8) {
			Dcmn_err(CE_NOTE, "  msg[%2d] %02x %02x %02x %02x "
			    "%02x %02x %02x %02x",
			    i, bp[i + 0], bp[i + 1], bp[i + 2],
			    bp[i + 3], bp[i + 4], bp[i + 5],
			    bp[i + 6], bp[i + 7]);
			if (i == 0) i = 64 - 8;
		}
	}

	(void) ddi_dma_sync(skmsg->mb_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	ASSERT(skmsg->length > sizeof (struct fit_msg_hdr));
	if (skmsg->length > 256) {
		qcmd |= FIT_QCMD_MSGSIZE_512;
	} else if (skmsg->length > 128) {
		qcmd |= FIT_QCMD_MSGSIZE_256;
	} else if (skmsg->length > 64) {
		qcmd |= FIT_QCMD_MSGSIZE_128;
	}

	skdev->ios_started++;

	SKD_WRITEQ(skdev, qcmd, FIT_Q_COMMAND);
}

/*
 *
 * Name:	skd_send_special_fitmsg, send a special FIT message
 *		to the hardware used driver-originated I/O requests.
 *
 * Inputs:	skdev		- device state structure.
 *		skspcl		- skspcl structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_send_special_fitmsg(struct skd_device *skdev,
    struct skd_special_context *skspcl)
{
	uint64_t qcmd;

	Dcmn_err(CE_NOTE, "send_special_fitmsg: pt 1");

	if (skdev->dbg_level > 1) {
		uint8_t *bp = skspcl->msg_buf;
		int i;

		for (i = 0; i < SKD_N_SPECIAL_FITMSG_BYTES; i += 8) {
			cmn_err(CE_NOTE,
			    "  spcl[%2d] %02x %02x %02x %02x  "
			    "%02x %02x %02x %02x\n", i,
			    bp[i + 0], bp[i + 1], bp[i + 2], bp[i + 3],
			    bp[i + 4], bp[i + 5], bp[i + 6], bp[i + 7]);
			if (i == 0) i = 64 - 8;
		}

		for (i = 0; i < skspcl->req.n_sg; i++) {
			struct fit_sg_descriptor *sgd =
			    &skspcl->req.sksg_list[i];

			cmn_err(CE_NOTE, "  sg[%d] count=%u ctrl=0x%x "
			    "addr=0x%" PRIx64 " next=0x%" PRIx64,
			    i, sgd->byte_count, sgd->control,
			    sgd->host_side_addr, sgd->next_desc_ptr);
		}
	}

	(void) ddi_dma_sync(skspcl->mb_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(skspcl->db_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Special FIT msgs are always 128 bytes: a 64-byte FIT hdr
	 * and one 64-byte SSDI command.
	 */
	qcmd = skspcl->mb_dma_address.cookies->dmac_laddress;

	qcmd |= FIT_QCMD_QID_NORMAL + FIT_QCMD_MSGSIZE_128;

	SKD_WRITEQ(skdev, qcmd, FIT_Q_COMMAND);
}

/*
 * COMPLETION QUEUE
 */

static void skd_complete_other(struct skd_device *skdev,
    volatile struct fit_completion_entry_v1 *skcomp,
    volatile struct fit_comp_error_info *skerr);

struct sns_info {
	uint8_t type;
	uint8_t stat;
	uint8_t key;
	uint8_t asc;
	uint8_t ascq;
	uint8_t mask;
	enum skd_check_status_action action;
};

static struct sns_info skd_chkstat_table[] = {
	/* Good */
	{0x70, 0x02, RECOVERED_ERROR, 0, 0, 0x1c, SKD_CHECK_STATUS_REPORT_GOOD},

	/* Smart alerts */
	{0x70, 0x02, NO_SENSE, 0x0B, 0x00, 0x1E, /* warnings */
	    SKD_CHECK_STATUS_REPORT_SMART_ALERT},
	{0x70, 0x02, NO_SENSE, 0x5D, 0x00, 0x1E, /* thresholds */
	    SKD_CHECK_STATUS_REPORT_SMART_ALERT},
	{0x70, 0x02, RECOVERED_ERROR, 0x0B, 0x01, 0x1F, /* temp over trigger */
	    SKD_CHECK_STATUS_REPORT_SMART_ALERT},

	/* Retry (with limits) */
	{0x70, 0x02, ABORTED_COMMAND, 0, 0, 0x1C, /* DMA errors */
	    SKD_CHECK_STATUS_REQUEUE_REQUEST},
	{0x70, 0x02, UNIT_ATTENTION, 0x0B, 0x00, 0x1E, /* warnings */
	    SKD_CHECK_STATUS_REQUEUE_REQUEST},
	{0x70, 0x02, UNIT_ATTENTION, 0x5D, 0x00, 0x1E, /* thresholds */
	    SKD_CHECK_STATUS_REQUEUE_REQUEST},
	{0x70, 0x02, UNIT_ATTENTION, 0x80, 0x30, 0x1F, /* backup power */
	    SKD_CHECK_STATUS_REQUEUE_REQUEST},

	/* Busy (or about to be) */
	{0x70, 0x02, UNIT_ATTENTION, 0x3f, 0x01, 0x1F, /* fw changed */
	    SKD_CHECK_STATUS_BUSY_IMMINENT},
};

/*
 *
 * Name:	skd_check_status, checks the return status from a
 *		completed I/O request.
 *
 * Inputs:	skdev		- device state structure.
 *		cmp_status	- SCSI status byte.
 *		skerr		- the error data structure.
 *
 * Returns:	Depending on the error condition, return the action
 *		to be taken as specified in the skd_chkstat_table.
 *		If no corresponding value is found in the table
 *		return SKD_CHECK_STATUS_REPORT_GOOD is no error otherwise
 *		return SKD_CHECK_STATUS_REPORT_ERROR.
 *
 */
static enum skd_check_status_action
skd_check_status(struct skd_device *skdev, uint8_t cmp_status,
    volatile struct fit_comp_error_info *skerr)
{
	/*
	 * Look up status and sense data to decide how to handle the error
	 * from the device.
	 * mask says which fields must match e.g., mask=0x18 means check
	 * type and stat, ignore key, asc, ascq.
	 */
	int i, n;

	Dcmn_err(CE_NOTE, "(%s): key/asc/ascq %02x/%02x/%02x",
	    skd_name(skdev), skerr->key, skerr->code, skerr->qual);

	Dcmn_err(CE_NOTE, "stat: t=%02x stat=%02x k=%02x c=%02x q=%02x",
	    skerr->type, cmp_status, skerr->key, skerr->code, skerr->qual);

	/* Does the info match an entry in the good category? */
	n = sizeof (skd_chkstat_table) / sizeof (skd_chkstat_table[0]);
	for (i = 0; i < n; i++) {
		struct sns_info *sns = &skd_chkstat_table[i];

		if (sns->mask & 0x10)
			if (skerr->type != sns->type) continue;

		if (sns->mask & 0x08)
			if (cmp_status != sns->stat) continue;

		if (sns->mask & 0x04)
			if (skerr->key != sns->key) continue;

		if (sns->mask & 0x02)
			if (skerr->code != sns->asc) continue;

		if (sns->mask & 0x01)
			if (skerr->qual != sns->ascq) continue;

		if (sns->action == SKD_CHECK_STATUS_REPORT_SMART_ALERT) {
			cmn_err(CE_WARN, "!(%s):SMART Alert: sense key/asc/ascq"
			    " %02x/%02x/%02x",
			    skd_name(skdev), skerr->key,
			    skerr->code, skerr->qual);
		}

		Dcmn_err(CE_NOTE, "skd_check_status: returning %x",
		    sns->action);

		return (sns->action);
	}

	/*
	 * No other match, so nonzero status means error,
	 * zero status means good
	 */
	if (cmp_status) {
		cmn_err(CE_WARN,
		    "!%s: status check: qdepth=%d skmfl=%p (%d) skrfl=%p (%d)",
		    skdev->name,
		    skdev->queue_depth_busy,
		    (void *)skdev->skmsg_free_list, skd_list_skmsg(skdev, 0),
		    (void *)skdev->skreq_free_list, skd_list_skreq(skdev, 0));

		cmn_err(CE_WARN, "!%s: t=%02x stat=%02x k=%02x c=%02x q=%02x",
		    skdev->name, skerr->type, cmp_status, skerr->key,
		    skerr->code, skerr->qual);

		return (SKD_CHECK_STATUS_REPORT_ERROR);
	}

	Dcmn_err(CE_NOTE, "status check good default");

	return (SKD_CHECK_STATUS_REPORT_GOOD);
}

/*
 *
 * Name:	skd_isr_completion_posted, handles I/O completions.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_isr_completion_posted(struct skd_device *skdev)
{
	volatile struct fit_completion_entry_v1 *skcmp = NULL;
	volatile struct fit_comp_error_info  *skerr;
	struct skd_fitmsg_context 	*skmsg;
	struct skd_request_context 	*skreq;
	skd_buf_private_t		*pbuf;
	uint16_t req_id;
	uint32_t req_slot;
	uint32_t timo_slot;
	uint32_t msg_slot;
	uint16_t cmp_cntxt = 0;
	uint8_t cmp_status = 0;
	uint8_t cmp_cycle = 0;
	uint32_t cmp_bytes = 0;

	(void) ddi_dma_sync(skdev->cq_dma_address.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	for (;;) {
		ASSERT(skdev->skcomp_ix < SKD_N_COMPLETION_ENTRY);

		WAITQ_LOCK(skdev);

		skcmp = &skdev->skcomp_table[skdev->skcomp_ix];
		cmp_cycle = skcmp->cycle;
		cmp_cntxt = skcmp->tag;
		cmp_status = skcmp->status;
		cmp_bytes = be32_to_cpu(skcmp->num_returned_bytes);

		skerr = &skdev->skerr_table[skdev->skcomp_ix];

		Dcmn_err(CE_NOTE,
		    "cycle=%d ix=%d got cycle=%d cmdctxt=0x%x stat=%d "
		    "qdepth_busy=%d rbytes=0x%x proto=%d",
		    skdev->skcomp_cycle, skdev->skcomp_ix,
		    cmp_cycle, cmp_cntxt, cmp_status,
		    skdev->queue_depth_busy, cmp_bytes, skdev->proto_ver);

		if (cmp_cycle != skdev->skcomp_cycle) {
			Dcmn_err(CE_NOTE, "%s:end of completions", skdev->name);

			WAITQ_UNLOCK(skdev);
			break;
		}


		skdev->n_req++;

		/*
		 * Update the completion queue head index and possibly
		 * the completion cycle count.
		 */
		skdev->skcomp_ix++;
		if (skdev->skcomp_ix >= SKD_N_COMPLETION_ENTRY) {
			skdev->skcomp_ix = 0;
			skdev->skcomp_cycle++; /* 8-bit wrap-around */
		}


		/*
		 * The command context is a unique 32-bit ID. The low order
		 * bits help locate the request. The request is usually a
		 * r/w request (see skd_start() above) or a special request.
		 */
		req_id   = cmp_cntxt;
		req_slot = req_id & SKD_ID_SLOT_AND_TABLE_MASK;

		Dcmn_err(CE_NOTE,
		    "<<<< completion_posted 1: req_id=%x req_slot=%x",
		    req_id, req_slot);

		/* Is this other than a r/w request? */
		if (req_slot >= skdev->num_req_context) {
			/*
			 * This is not a completion for a r/w request.
			 */
			skd_complete_other(skdev, skcmp, skerr);
			WAITQ_UNLOCK(skdev);
			continue;
		}

		skreq    = &skdev->skreq_table[req_slot];

		/*
		 * Make sure the request ID for the slot matches.
		 */
		ASSERT(skreq->id == req_id);

		if (SKD_REQ_STATE_ABORTED == skreq->state) {
			Dcmn_err(CE_NOTE, "reclaim req %p id=%04x\n",
			    (void *)skreq, skreq->id);
			/*
			 * a previously timed out command can
			 * now be cleaned up
			 */
			msg_slot = skreq->fitmsg_id & SKD_ID_SLOT_MASK;
			ASSERT(msg_slot < skdev->num_fitmsg_context);
			skmsg = &skdev->skmsg_table[msg_slot];
			if (skmsg->id == skreq->fitmsg_id) {
				ASSERT(skmsg->outstanding > 0);
				skmsg->outstanding--;
				if (skmsg->outstanding == 0) {
					ASSERT(SKD_MSG_STATE_BUSY ==
					    skmsg->state);
					skmsg->state = SKD_MSG_STATE_IDLE;
					skmsg->id += SKD_ID_INCR;
					skmsg->next = skdev->skmsg_free_list;
					skdev->skmsg_free_list = skmsg;
				}
			}
			/*
			 * Reclaim the skd_request_context
			 */
			skreq->state = SKD_REQ_STATE_IDLE;
			skreq->id += SKD_ID_INCR;
			skreq->next = skdev->skreq_free_list;
			skdev->skreq_free_list = skreq;
			WAITQ_UNLOCK(skdev);
			continue;
		}

		skreq->completion.status = cmp_status;

		pbuf = skreq->pbuf;
		ASSERT(pbuf != NULL);

		Dcmn_err(CE_NOTE, "<<<< completion_posted 2: pbuf=%p "
		    "req_id=%x req_slot=%x", (void *)pbuf, req_id, req_slot);
		if (cmp_status && skdev->disks_initialized) {
			cmn_err(CE_WARN, "!%s: "
			    "I/O err: pbuf=%p blkno=%lld (%llx) nbklks=%ld ",
			    skdev->name, (void *)pbuf, pbuf->x_xfer->x_blkno,
			    pbuf->x_xfer->x_blkno, pbuf->x_xfer->x_nblks);
		}

		ASSERT(skdev->active_cmds);
		atomic_dec_64(&skdev->active_cmds);

		if (SAM_STAT_GOOD == cmp_status) {
			/* Release DMA resources for the request. */
			if (pbuf->x_xfer->x_nblks != 0)
					skd_blkdev_postop_sg_list(skdev, skreq);
			WAITQ_UNLOCK(skdev);
			skd_end_request(skdev, skreq, 0);
			WAITQ_LOCK(skdev);
		} else {
			switch (skd_check_status(skdev, cmp_status, skerr)) {
			case SKD_CHECK_STATUS_REPORT_GOOD:
			case SKD_CHECK_STATUS_REPORT_SMART_ALERT:
				WAITQ_UNLOCK(skdev);
				skd_end_request(skdev, skreq, 0);
				WAITQ_LOCK(skdev);
				break;

			case SKD_CHECK_STATUS_BUSY_IMMINENT:
				skd_log_skreq(skdev, skreq, "retry(busy)");
				skd_queue(skdev, pbuf);
				skdev->state = SKD_DRVR_STATE_BUSY_IMMINENT;
				skdev->timer_countdown = SKD_TIMER_MINUTES(20);

				(void) skd_quiesce_dev(skdev);
				break;

				/* FALLTHRU */
			case SKD_CHECK_STATUS_REPORT_ERROR:
				/* fall thru to report error */
			default:
				/*
				 * Save the entire completion
				 * and error entries for
				 * later error interpretation.
				 */
				skreq->completion = *skcmp;
				skreq->err_info = *skerr;
				WAITQ_UNLOCK(skdev);
				skd_end_request(skdev, skreq, -EIO);
				WAITQ_LOCK(skdev);
				break;
			}
		}

		/*
		 * Reclaim the FIT msg buffer if this is
		 * the first of the requests it carried to
		 * be completed. The FIT msg buffer used to
		 * send this request cannot be reused until
		 * we are sure the s1120 card has copied
		 * it to its memory. The FIT msg might have
		 * contained several requests. As soon as
		 * any of them are completed we know that
		 * the entire FIT msg was transferred.
		 * Only the first completed request will
		 * match the FIT msg buffer id. The FIT
		 * msg buffer id is immediately updated.
		 * When subsequent requests complete the FIT
		 * msg buffer id won't match, so we know
		 * quite cheaply that it is already done.
		 */
		msg_slot = skreq->fitmsg_id & SKD_ID_SLOT_MASK;

		ASSERT(msg_slot < skdev->num_fitmsg_context);
		skmsg = &skdev->skmsg_table[msg_slot];
		if (skmsg->id == skreq->fitmsg_id) {
			ASSERT(SKD_MSG_STATE_BUSY == skmsg->state);
			skmsg->state = SKD_MSG_STATE_IDLE;
			skmsg->id += SKD_ID_INCR;
			skmsg->next = skdev->skmsg_free_list;
			skdev->skmsg_free_list = skmsg;
		}

		/*
		 * Decrease the number of active requests.
		 * This also decrements the count in the
		 * timeout slot.
		 */
		timo_slot = skreq->timeout_stamp & SKD_TIMEOUT_SLOT_MASK;
		ASSERT(skdev->timeout_slot[timo_slot] > 0);
		ASSERT(skdev->queue_depth_busy > 0);

		atomic_dec_32(&skdev->timeout_slot[timo_slot]);
		atomic_dec_32(&skdev->queue_depth_busy);

		/*
		 * Reclaim the skd_request_context
		 */
		skreq->state = SKD_REQ_STATE_IDLE;
		skreq->id += SKD_ID_INCR;
		skreq->next = skdev->skreq_free_list;
		skdev->skreq_free_list = skreq;

		WAITQ_UNLOCK(skdev);

		/*
		 * make sure the lock is held by caller.
		 */
		if ((skdev->state == SKD_DRVR_STATE_PAUSING) &&
		    (0 == skdev->queue_depth_busy)) {
			skdev->state = SKD_DRVR_STATE_PAUSED;
			cv_signal(&skdev->cv_waitq);
		}
	} /* for(;;) */
}

/*
 *
 * Name:	skd_complete_other, handle the completion of a
 *		non-r/w request.
 *
 * Inputs:	skdev		- device state structure.
 *		skcomp		- FIT completion structure.
 *		skerr		- error structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_complete_other(struct skd_device *skdev,
    volatile struct fit_completion_entry_v1 *skcomp,
    volatile struct fit_comp_error_info *skerr)
{
	uint32_t req_id = 0;
	uint32_t req_table;
	uint32_t req_slot;
	struct skd_special_context *skspcl;

	req_id = skcomp->tag;
	req_table = req_id & SKD_ID_TABLE_MASK;
	req_slot = req_id & SKD_ID_SLOT_MASK;

	Dcmn_err(CE_NOTE, "complete_other: table=0x%x id=0x%x slot=%d",
	    req_table, req_id, req_slot);

	/*
	 * Based on the request id, determine how to dispatch this completion.
	 * This swich/case is finding the good cases and forwarding the
	 * completion entry. Errors are reported below the switch.
	 */
	ASSERT(req_table == SKD_ID_INTERNAL);
	ASSERT(req_slot == 0);

	skspcl = &skdev->internal_skspcl;
	ASSERT(skspcl->req.id == req_id);
	ASSERT(skspcl->req.state == SKD_REQ_STATE_BUSY);

	Dcmn_err(CE_NOTE, "<<<<== complete_other: ID_INTERNAL");
	skd_complete_internal(skdev, skcomp, skerr, skspcl);
}

/*
 *
 * Name:	skd_reset_skcomp, does what it says, resetting completion
 *		tables.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_reset_skcomp(struct skd_device *skdev)
{
	uint32_t nbytes;

	nbytes =  sizeof (struct fit_completion_entry_v1) *
	    SKD_N_COMPLETION_ENTRY;
	nbytes += sizeof (struct fit_comp_error_info) * SKD_N_COMPLETION_ENTRY;

	if (skdev->skcomp_table)
		bzero(skdev->skcomp_table, nbytes);

	skdev->skcomp_ix = 0;
	skdev->skcomp_cycle = 1;
}



/*
 * INTERRUPTS
 */

/*
 *
 * Name:	skd_isr_aif, handles the device interrupts.
 *
 * Inputs:	arg		- skdev device state structure.
 *		intvec		- not referenced
 *
 * Returns:	DDI_INTR_CLAIMED if interrupt is handled otherwise
 *		return DDI_INTR_UNCLAIMED.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static uint_t
skd_isr_aif(caddr_t arg, caddr_t intvec)
{
	uint32_t	  intstat;
	uint32_t	  ack;
	int		  rc = DDI_INTR_UNCLAIMED;
	struct skd_device *skdev;

	skdev = (skd_device_t *)(uintptr_t)arg;

	ASSERT(skdev != NULL);

	skdev->intr_cntr++;

	Dcmn_err(CE_NOTE, "skd_isr_aif: intr=%" PRId64 "\n", skdev->intr_cntr);

	for (;;) {

		ASSERT(!WAITQ_LOCK_HELD(skdev));
		INTR_LOCK(skdev);

		intstat = SKD_READL(skdev, FIT_INT_STATUS_HOST);

		ack = FIT_INT_DEF_MASK;
		ack &= intstat;

		Dcmn_err(CE_NOTE, "intstat=0x%x ack=0x%x", intstat, ack);

		/*
		 * As long as there is an int pending on device, keep
		 * running loop.  When none, get out, but if we've never
		 * done any processing, call completion handler?
		 */
		if (ack == 0) {
			/*
			 * No interrupts on device, but run the completion
			 * processor anyway?
			 */
			if (rc == DDI_INTR_UNCLAIMED &&
			    skdev->state == SKD_DRVR_STATE_ONLINE) {
				Dcmn_err(CE_NOTE,
				    "1: Want isr_comp_posted call");
				skd_isr_completion_posted(skdev);
			}
			INTR_UNLOCK(skdev);

			break;
		}
		rc = DDI_INTR_CLAIMED;

		SKD_WRITEL(skdev, ack, FIT_INT_STATUS_HOST);

		if ((skdev->state != SKD_DRVR_STATE_LOAD) &&
		    (skdev->state != SKD_DRVR_STATE_STOPPING)) {
			if (intstat & FIT_ISH_COMPLETION_POSTED) {
				Dcmn_err(CE_NOTE,
				    "2: Want isr_comp_posted call");
				skd_isr_completion_posted(skdev);
			}

			if (intstat & FIT_ISH_FW_STATE_CHANGE) {
				Dcmn_err(CE_NOTE, "isr: fwstate change");

				skd_isr_fwstate(skdev);
				if (skdev->state == SKD_DRVR_STATE_FAULT ||
				    skdev->state ==
				    SKD_DRVR_STATE_DISAPPEARED) {
					INTR_UNLOCK(skdev);

					return (rc);
				}
			}

			if (intstat & FIT_ISH_MSG_FROM_DEV) {
				Dcmn_err(CE_NOTE, "isr: msg_from_dev change");
				skd_isr_msg_from_dev(skdev);
			}
		}

		INTR_UNLOCK(skdev);
	}

	if (!SIMPLEQ_EMPTY(&skdev->waitqueue))
		skd_start(skdev);

	return (rc);
}

/*
 *
 * Name:	skd_drive_fault, set the drive state to DRV_STATE_FAULT.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_drive_fault(struct skd_device *skdev)
{
	skdev->state = SKD_DRVR_STATE_FAULT;
	cmn_err(CE_WARN, "!(%s): Drive FAULT\n",
	    skd_name(skdev));
}

/*
 *
 * Name:	skd_drive_disappeared, set the drive state to DISAPPEARED..
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_drive_disappeared(struct skd_device *skdev)
{
	skdev->state = SKD_DRVR_STATE_DISAPPEARED;
	cmn_err(CE_WARN, "!(%s): Drive DISAPPEARED\n",
	    skd_name(skdev));
}

/*
 *
 * Name:	skd_isr_fwstate, handles the various device states.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_isr_fwstate(struct skd_device *skdev)
{
	uint32_t sense;
	uint32_t state;
	int prev_driver_state;
	uint32_t mtd;

	prev_driver_state = skdev->state;

	sense = SKD_READL(skdev, FIT_STATUS);
	state = sense & FIT_SR_DRIVE_STATE_MASK;

	Dcmn_err(CE_NOTE, "s1120 state %s(%d)=>%s(%d)",
	    skd_drive_state_to_str(skdev->drive_state), skdev->drive_state,
	    skd_drive_state_to_str(state), state);

	skdev->drive_state = state;

	switch (skdev->drive_state) {
	case FIT_SR_DRIVE_INIT:
		if (skdev->state == SKD_DRVR_STATE_PROTOCOL_MISMATCH) {
			skd_disable_interrupts(skdev);
			break;
		}
		if (skdev->state == SKD_DRVR_STATE_RESTARTING) {
			skd_recover_requests(skdev);
		}
		if (skdev->state == SKD_DRVR_STATE_WAIT_BOOT) {
			skdev->timer_countdown =
			    SKD_TIMER_SECONDS(SKD_STARTING_TO);
			skdev->state = SKD_DRVR_STATE_STARTING;
			skd_soft_reset(skdev);
			break;
		}
		mtd = FIT_MXD_CONS(FIT_MTD_FITFW_INIT, 0, 0);
		SKD_WRITEL(skdev, mtd, FIT_MSG_TO_DEVICE);
		skdev->last_mtd = mtd;
		break;

	case FIT_SR_DRIVE_ONLINE:
		skdev->queue_depth_limit = skdev->soft_queue_depth_limit;
		if (skdev->queue_depth_limit > skdev->hard_queue_depth_limit) {
			skdev->queue_depth_limit =
			    skdev->hard_queue_depth_limit;
		}

		skdev->queue_depth_lowat = skdev->queue_depth_limit * 2 / 3 + 1;
		if (skdev->queue_depth_lowat < 1)
			skdev->queue_depth_lowat = 1;
		Dcmn_err(CE_NOTE,
		    "%s queue depth limit=%d hard=%d soft=%d lowat=%d",
		    DRV_NAME,
		    skdev->queue_depth_limit,
		    skdev->hard_queue_depth_limit,
		    skdev->soft_queue_depth_limit,
		    skdev->queue_depth_lowat);

		skd_refresh_device_data(skdev);
		break;
	case FIT_SR_DRIVE_BUSY:
		skdev->state = SKD_DRVR_STATE_BUSY;
		skdev->timer_countdown = SKD_TIMER_MINUTES(20);
		(void) skd_quiesce_dev(skdev);
		break;
	case FIT_SR_DRIVE_BUSY_SANITIZE:
		skdev->state = SKD_DRVR_STATE_BUSY_SANITIZE;
		skd_start(skdev);
		break;
	case FIT_SR_DRIVE_BUSY_ERASE:
		skdev->state = SKD_DRVR_STATE_BUSY_ERASE;
		skdev->timer_countdown = SKD_TIMER_MINUTES(20);
		break;
	case FIT_SR_DRIVE_OFFLINE:
		skdev->state = SKD_DRVR_STATE_IDLE;
		break;
	case FIT_SR_DRIVE_SOFT_RESET:
		skdev->state = SKD_DRVR_STATE_RESTARTING;

		switch (skdev->state) {
		case SKD_DRVR_STATE_STARTING:
		case SKD_DRVR_STATE_RESTARTING:
			break;
		default:
			skdev->state = SKD_DRVR_STATE_RESTARTING;
			break;
		}
		break;
	case FIT_SR_DRIVE_FW_BOOTING:
		Dcmn_err(CE_NOTE,
		    "ISR FIT_SR_DRIVE_FW_BOOTING %s", skdev->name);
		skdev->state = SKD_DRVR_STATE_WAIT_BOOT;
		skdev->timer_countdown = SKD_TIMER_SECONDS(SKD_WAIT_BOOT_TO);
		break;

	case FIT_SR_DRIVE_DEGRADED:
	case FIT_SR_PCIE_LINK_DOWN:
	case FIT_SR_DRIVE_NEED_FW_DOWNLOAD:
		break;

	case FIT_SR_DRIVE_FAULT:
		skd_drive_fault(skdev);
		skd_recover_requests(skdev);
		skd_start(skdev);
		break;

	case 0xFF:
		skd_drive_disappeared(skdev);
		skd_recover_requests(skdev);
		skd_start(skdev);
		break;
	default:
		/*
		 * Uknown FW State. Wait for a state we recognize.
		 */
		break;
	}

	Dcmn_err(CE_NOTE, "Driver state %s(%d)=>%s(%d)",
	    skd_skdev_state_to_str(prev_driver_state), prev_driver_state,
	    skd_skdev_state_to_str(skdev->state), skdev->state);
}

/*
 *
 * Name:	skd_recover_requests, attempts to recover requests.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_recover_requests(struct skd_device *skdev)
{
	int i;

	ASSERT(INTR_LOCK_HELD(skdev));

	for (i = 0; i < skdev->num_req_context; i++) {
		struct skd_request_context *skreq = &skdev->skreq_table[i];

		if (skreq->state == SKD_REQ_STATE_BUSY) {
			skd_log_skreq(skdev, skreq, "requeue");

			ASSERT(0 != (skreq->id & SKD_ID_INCR));
			ASSERT(skreq->pbuf != NULL);
			/* Release DMA resources for the request. */
			skd_blkdev_postop_sg_list(skdev, skreq);

			skd_end_request(skdev, skreq, EAGAIN);
			skreq->pbuf = NULL;
			skreq->state = SKD_REQ_STATE_IDLE;
			skreq->id += SKD_ID_INCR;
		}
		if (i > 0) {
			skreq[-1].next = skreq;
		}
		skreq->next = NULL;
	}

	WAITQ_LOCK(skdev);
	skdev->skreq_free_list = skdev->skreq_table;
	WAITQ_UNLOCK(skdev);

	for (i = 0; i < skdev->num_fitmsg_context; i++) {
		struct skd_fitmsg_context *skmsg = &skdev->skmsg_table[i];

		if (skmsg->state == SKD_MSG_STATE_BUSY) {
			skd_log_skmsg(skdev, skmsg, "salvaged");
			ASSERT((skmsg->id & SKD_ID_INCR) != 0);
			skmsg->state = SKD_MSG_STATE_IDLE;
			skmsg->id &= ~SKD_ID_INCR;
		}
		if (i > 0) {
			skmsg[-1].next = skmsg;
		}
		skmsg->next = NULL;
	}
	WAITQ_LOCK(skdev);
	skdev->skmsg_free_list = skdev->skmsg_table;
	WAITQ_UNLOCK(skdev);

	for (i = 0; i < SKD_N_TIMEOUT_SLOT; i++) {
		skdev->timeout_slot[i] = 0;
	}
	skdev->queue_depth_busy = 0;
}

/*
 *
 * Name:	skd_isr_msg_from_dev, handles a message from the device.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_isr_msg_from_dev(struct skd_device *skdev)
{
	uint32_t mfd;
	uint32_t mtd;

	Dcmn_err(CE_NOTE, "skd_isr_msg_from_dev:");

	mfd = SKD_READL(skdev, FIT_MSG_FROM_DEVICE);

	Dcmn_err(CE_NOTE, "mfd=0x%x last_mtd=0x%x\n", mfd, skdev->last_mtd);

	/*
	 * ignore any mtd that is an ack for something we didn't send
	 */
	if (FIT_MXD_TYPE(mfd) != FIT_MXD_TYPE(skdev->last_mtd)) {
		return;
	}

	switch (FIT_MXD_TYPE(mfd)) {
	case FIT_MTD_FITFW_INIT:
		skdev->proto_ver = FIT_PROTOCOL_MAJOR_VER(mfd);

		if (skdev->proto_ver != FIT_PROTOCOL_VERSION_1) {
			cmn_err(CE_WARN, "!(%s): protocol mismatch\n",
			    skdev->name);
			cmn_err(CE_WARN, "!(%s):   got=%d support=%d\n",
			    skdev->name, skdev->proto_ver,
			    FIT_PROTOCOL_VERSION_1);
			cmn_err(CE_WARN, "!(%s):   please upgrade driver\n",
			    skdev->name);
			skdev->state = SKD_DRVR_STATE_PROTOCOL_MISMATCH;
			skd_soft_reset(skdev);
			break;
		}
		mtd = FIT_MXD_CONS(FIT_MTD_GET_CMDQ_DEPTH, 0, 0);
		SKD_WRITEL(skdev, mtd, FIT_MSG_TO_DEVICE);
		skdev->last_mtd = mtd;
		break;

	case FIT_MTD_GET_CMDQ_DEPTH:
		skdev->hard_queue_depth_limit = FIT_MXD_DATA(mfd);
		mtd = FIT_MXD_CONS(FIT_MTD_SET_COMPQ_DEPTH, 0,
		    SKD_N_COMPLETION_ENTRY);
		SKD_WRITEL(skdev, mtd, FIT_MSG_TO_DEVICE);
		skdev->last_mtd = mtd;
		break;

	case FIT_MTD_SET_COMPQ_DEPTH:
		SKD_WRITEQ(skdev, skdev->cq_dma_address.cookies->dmac_laddress,
		    FIT_MSG_TO_DEVICE_ARG);
		mtd = FIT_MXD_CONS(FIT_MTD_SET_COMPQ_ADDR, 0, 0);
		SKD_WRITEL(skdev, mtd, FIT_MSG_TO_DEVICE);
		skdev->last_mtd = mtd;
		break;

	case FIT_MTD_SET_COMPQ_ADDR:
		skd_reset_skcomp(skdev);
		mtd = FIT_MXD_CONS(FIT_MTD_ARM_QUEUE, 0, 0);
		SKD_WRITEL(skdev, mtd, FIT_MSG_TO_DEVICE);
		skdev->last_mtd = mtd;
		break;

	case FIT_MTD_ARM_QUEUE:
		skdev->last_mtd = 0;
		/*
		 * State should be, or soon will be, FIT_SR_DRIVE_ONLINE.
		 */
		break;

	default:
		break;
	}
}


/*
 *
 * Name:	skd_disable_interrupts, issues command to disable
 *		device interrupts.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_disable_interrupts(struct skd_device *skdev)
{
	uint32_t sense;

	Dcmn_err(CE_NOTE, "skd_disable_interrupts:");

	sense = SKD_READL(skdev, FIT_CONTROL);
	sense &= ~FIT_CR_ENABLE_INTERRUPTS;
	SKD_WRITEL(skdev, sense, FIT_CONTROL);

	Dcmn_err(CE_NOTE, "sense 0x%x", sense);

	/*
	 * Note that the 1s is written. A 1-bit means
	 * disable, a 0 means enable.
	 */
	SKD_WRITEL(skdev, ~0, FIT_INT_MASK_HOST);
}

/*
 *
 * Name:	skd_enable_interrupts, issues command to enable
 *		device interrupts.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_enable_interrupts(struct skd_device *skdev)
{
	uint32_t val;

	Dcmn_err(CE_NOTE, "skd_enable_interrupts:");

	/* unmask interrupts first */
	val = FIT_ISH_FW_STATE_CHANGE +
	    FIT_ISH_COMPLETION_POSTED +
	    FIT_ISH_MSG_FROM_DEV;

	/*
	 * Note that the compliment of mask is written. A 1-bit means
	 * disable, a 0 means enable.
	 */
	SKD_WRITEL(skdev, ~val, FIT_INT_MASK_HOST);

	Dcmn_err(CE_NOTE, "interrupt mask=0x%x", ~val);

	val = SKD_READL(skdev, FIT_CONTROL);
	val |= FIT_CR_ENABLE_INTERRUPTS;

	Dcmn_err(CE_NOTE, "control=0x%x", val);

	SKD_WRITEL(skdev, val, FIT_CONTROL);
}

/*
 *
 * Name:	skd_soft_reset, issues a soft reset to the hardware.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_soft_reset(struct skd_device *skdev)
{
	uint32_t val;

	Dcmn_err(CE_NOTE, "skd_soft_reset:");

	val = SKD_READL(skdev, FIT_CONTROL);
	val |= (FIT_CR_SOFT_RESET);

	Dcmn_err(CE_NOTE, "soft_reset: control=0x%x", val);

	SKD_WRITEL(skdev, val, FIT_CONTROL);
}

/*
 *
 * Name:	skd_start_device, gets the device going.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_start_device(struct skd_device *skdev)
{
	uint32_t state;
	int delay_action = 0;

	Dcmn_err(CE_NOTE, "skd_start_device:");

	/* ack all ghost interrupts */
	SKD_WRITEL(skdev, FIT_INT_DEF_MASK, FIT_INT_STATUS_HOST);

	state = SKD_READL(skdev, FIT_STATUS);

	Dcmn_err(CE_NOTE, "initial status=0x%x", state);

	state &= FIT_SR_DRIVE_STATE_MASK;
	skdev->drive_state = state;
	skdev->last_mtd = 0;

	skdev->state = SKD_DRVR_STATE_STARTING;
	skdev->timer_countdown = SKD_TIMER_SECONDS(SKD_STARTING_TO);

	skd_enable_interrupts(skdev);

	switch (skdev->drive_state) {
	case FIT_SR_DRIVE_OFFLINE:
		Dcmn_err(CE_NOTE, "(%s): Drive offline...",
		    skd_name(skdev));
		break;

	case FIT_SR_DRIVE_FW_BOOTING:
		Dcmn_err(CE_NOTE, "FIT_SR_DRIVE_FW_BOOTING %s\n", skdev->name);
		skdev->state = SKD_DRVR_STATE_WAIT_BOOT;
		skdev->timer_countdown = SKD_TIMER_SECONDS(SKD_WAIT_BOOT_TO);
		break;

	case FIT_SR_DRIVE_BUSY_SANITIZE:
		Dcmn_err(CE_NOTE, "(%s): Start: BUSY_SANITIZE\n",
		    skd_name(skdev));
		skdev->state = SKD_DRVR_STATE_BUSY_SANITIZE;
		skdev->timer_countdown = SKD_TIMER_SECONDS(60);
		break;

	case FIT_SR_DRIVE_BUSY_ERASE:
		Dcmn_err(CE_NOTE, "(%s): Start: BUSY_ERASE\n",
		    skd_name(skdev));
		skdev->state = SKD_DRVR_STATE_BUSY_ERASE;
		skdev->timer_countdown = SKD_TIMER_SECONDS(60);
		break;

	case FIT_SR_DRIVE_INIT:
	case FIT_SR_DRIVE_ONLINE:
		skd_soft_reset(skdev);

		break;

	case FIT_SR_DRIVE_BUSY:
		Dcmn_err(CE_NOTE, "(%s): Drive Busy...\n",
		    skd_name(skdev));
		skdev->state = SKD_DRVR_STATE_BUSY;
		skdev->timer_countdown = SKD_TIMER_SECONDS(60);
		break;

	case FIT_SR_DRIVE_SOFT_RESET:
		Dcmn_err(CE_NOTE, "(%s) drive soft reset in prog\n",
		    skd_name(skdev));
		break;

	case FIT_SR_DRIVE_FAULT:
		/*
		 * Fault state is bad...soft reset won't do it...
		 * Hard reset, maybe, but does it work on device?
		 * For now, just fault so the system doesn't hang.
		 */
		skd_drive_fault(skdev);

		delay_action = 1;
		break;

	case 0xFF:
		skd_drive_disappeared(skdev);

		delay_action = 1;
		break;

	default:
		Dcmn_err(CE_NOTE, "(%s) Start: unknown state %x\n",
		    skd_name(skdev), skdev->drive_state);
		break;
	}

	state = SKD_READL(skdev, FIT_CONTROL);
	Dcmn_err(CE_NOTE, "FIT Control Status=0x%x\n", state);

	state = SKD_READL(skdev, FIT_INT_STATUS_HOST);
	Dcmn_err(CE_NOTE, "Intr Status=0x%x\n", state);

	state = SKD_READL(skdev, FIT_INT_MASK_HOST);
	Dcmn_err(CE_NOTE, "Intr Mask=0x%x\n", state);

	state = SKD_READL(skdev, FIT_MSG_FROM_DEVICE);
	Dcmn_err(CE_NOTE, "Msg from Dev=0x%x\n", state);

	state = SKD_READL(skdev, FIT_HW_VERSION);
	Dcmn_err(CE_NOTE, "HW version=0x%x\n", state);

	if (delay_action) {
		/* start the queue so we can respond with error to requests */
		Dcmn_err(CE_NOTE, "Starting %s queue\n", skdev->name);
		skd_start(skdev);
		skdev->gendisk_on = -1;
		cv_signal(&skdev->cv_waitq);
	}
}

/*
 *
 * Name:	skd_restart_device, restart the hardware.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_restart_device(struct skd_device *skdev)
{
	uint32_t state;

	Dcmn_err(CE_NOTE, "skd_restart_device:");

	/* ack all ghost interrupts */
	SKD_WRITEL(skdev, FIT_INT_DEF_MASK, FIT_INT_STATUS_HOST);

	state = SKD_READL(skdev, FIT_STATUS);

	Dcmn_err(CE_NOTE, "skd_restart_device: drive status=0x%x\n", state);

	state &= FIT_SR_DRIVE_STATE_MASK;
	skdev->drive_state = state;
	skdev->last_mtd = 0;

	skdev->state = SKD_DRVR_STATE_RESTARTING;
	skdev->timer_countdown = SKD_TIMER_MINUTES(4);

	skd_soft_reset(skdev);
}

/*
 *
 * Name:	skd_stop_device, stops the device.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_stop_device(struct skd_device *skdev)
{
	clock_t	cur_ticks, tmo;
	int secs;
	struct skd_special_context *skspcl = &skdev->internal_skspcl;

	if (SKD_DRVR_STATE_ONLINE != skdev->state) {
		Dcmn_err(CE_NOTE, "(%s): skd_stop_device not online no sync\n",
		    skdev->name);
		goto stop_out;
	}

	if (SKD_REQ_STATE_IDLE != skspcl->req.state) {
		Dcmn_err(CE_NOTE, "(%s): skd_stop_device no special\n",
		    skdev->name);
		goto stop_out;
	}

	skdev->state = SKD_DRVR_STATE_SYNCING;
	skdev->sync_done = 0;

	skd_send_internal_skspcl(skdev, skspcl, SYNCHRONIZE_CACHE);

	secs = 10;
	mutex_enter(&skdev->skd_internalio_mutex);
	while (skdev->sync_done == 0) {
		cur_ticks = ddi_get_lbolt();
		tmo = cur_ticks + drv_usectohz(1000000 * secs);
		if (cv_timedwait(&skdev->cv_waitq,
		    &skdev->skd_internalio_mutex, tmo) == -1) {
			/* Oops - timed out */

			Dcmn_err(CE_NOTE, "stop_device - %d secs TMO", secs);
		}
	}

	mutex_exit(&skdev->skd_internalio_mutex);

	switch (skdev->sync_done) {
	case 0:
		Dcmn_err(CE_NOTE, "(%s): skd_stop_device no sync\n",
		    skdev->name);
		break;
	case 1:
		Dcmn_err(CE_NOTE, "(%s): skd_stop_device sync done\n",
		    skdev->name);
		break;
	default:
		Dcmn_err(CE_NOTE, "(%s): skd_stop_device sync error\n",
		    skdev->name);
	}


stop_out:
	skdev->state = SKD_DRVR_STATE_STOPPING;

	skd_disable_interrupts(skdev);

	/* ensure all ints on device are cleared */
	SKD_WRITEL(skdev, FIT_INT_DEF_MASK, FIT_INT_STATUS_HOST);
	/* soft reset the device to unload with a clean slate */
	SKD_WRITEL(skdev, FIT_CR_SOFT_RESET, FIT_CONTROL);
}

/*
 * CONSTRUCT
 */

static int skd_cons_skcomp(struct skd_device *);
static int skd_cons_skmsg(struct skd_device *);
static int skd_cons_skreq(struct skd_device *);
static int skd_cons_sksb(struct skd_device *);
static struct fit_sg_descriptor *skd_cons_sg_list(struct skd_device *, uint32_t,
    dma_mem_t *);

/*
 *
 * Name:	skd_construct, calls other routines to build device
 *		interface structures.
 *
 * Inputs:	skdev		- device state structure.
 *		instance	- DDI instance number.
 *
 * Returns:	Returns DDI_FAILURE on any failure otherwise returns
 *		DDI_SUCCESS.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static int
skd_construct(skd_device_t *skdev, int instance)
{
	int rc = 0;

	skdev->state = SKD_DRVR_STATE_LOAD;
	skdev->irq_type = skd_isr_type;
	skdev->soft_queue_depth_limit = skd_max_queue_depth;
	skdev->hard_queue_depth_limit = 10; /* until GET_CMDQ_DEPTH */

	skdev->num_req_context = skd_max_queue_depth;
	skdev->num_fitmsg_context = skd_max_queue_depth;

	skdev->queue_depth_limit = skdev->hard_queue_depth_limit;
	skdev->queue_depth_lowat = 1;
	skdev->proto_ver = 99; /* initialize to invalid value */
	skdev->sgs_per_request = skd_sgs_per_request;
	skdev->dbg_level = skd_dbg_level;

	rc = skd_cons_skcomp(skdev);
	if (rc < 0) {
		goto err_out;
	}

	rc = skd_cons_skmsg(skdev);
	if (rc < 0) {
		goto err_out;
	}

	rc = skd_cons_skreq(skdev);
	if (rc < 0) {
		goto err_out;
	}

	rc = skd_cons_sksb(skdev);
	if (rc < 0) {
		goto err_out;
	}

	Dcmn_err(CE_NOTE, "CONSTRUCT VICTORY");

	return (DDI_SUCCESS);

err_out:
	Dcmn_err(CE_NOTE, "construct failed\n");
	skd_destruct(skdev);

	return (DDI_FAILURE);
}

/*
 *
 * Name:	skd_free_phys, frees DMA memory.
 *
 * Inputs:	skdev		- device state structure.
 *		mem		- DMA info.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_free_phys(skd_device_t *skdev, dma_mem_t *mem)
{
	_NOTE(ARGUNUSED(skdev));

	if (mem == NULL || mem->dma_handle == NULL)
		return;

	(void) ddi_dma_unbind_handle(mem->dma_handle);

	if (mem->acc_handle != NULL) {
		ddi_dma_mem_free(&mem->acc_handle);
		mem->acc_handle = NULL;
	}

	mem->bp = NULL;
	ddi_dma_free_handle(&mem->dma_handle);
	mem->dma_handle = NULL;
}

/*
 *
 * Name:	skd_alloc_dma_mem, allocates DMA memory.
 *
 * Inputs:	skdev		- device state structure.
 *		mem		- DMA data structure.
 *		sleep		- indicates whether called routine can sleep.
 *		atype		- specified 32 or 64 bit allocation.
 *
 * Returns:	Void pointer to mem->bp on success else NULL.
 *		NOTE:  There are some failure modes even if sleep is set
 *		to KM_SLEEP, so callers MUST check the return code even
 *		if KM_SLEEP is passed in.
 *
 */
static void *
skd_alloc_dma_mem(skd_device_t *skdev, dma_mem_t *mem, uint8_t atype)
{
	size_t		rlen;
	uint_t		cnt;
	ddi_dma_attr_t	dma_attr = skd_64bit_io_dma_attr;
	ddi_device_acc_attr_t acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC
	};

	if (atype == ATYPE_32BIT)
		dma_attr.dma_attr_addr_hi = SKD_DMA_HIGH_32BIT_ADDRESS;

	dma_attr.dma_attr_sgllen = 1;

	/*
	 * Allocate DMA memory.
	 */
	if (ddi_dma_alloc_handle(skdev->dip, &dma_attr, DDI_DMA_SLEEP, NULL,
	    &mem->dma_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!alloc_dma_mem-1, failed");

		mem->dma_handle = NULL;

		return (NULL);
	}

	if (ddi_dma_mem_alloc(mem->dma_handle, mem->size, &acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, (caddr_t *)&mem->bp, &rlen,
	    &mem->acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!skd_alloc_dma_mem-2, failed");
		ddi_dma_free_handle(&mem->dma_handle);
		mem->dma_handle = NULL;
		mem->acc_handle = NULL;
		mem->bp = NULL;

		return (NULL);
	}
	bzero(mem->bp, mem->size);

	if (ddi_dma_addr_bind_handle(mem->dma_handle, NULL, mem->bp,
	    mem->size, (DDI_DMA_CONSISTENT | DDI_DMA_RDWR), DDI_DMA_SLEEP, NULL,
	    &mem->cookie, &cnt) != DDI_DMA_MAPPED) {
		cmn_err(CE_WARN, "!skd_alloc_dma_mem-3, failed");
		ddi_dma_mem_free(&mem->acc_handle);
		ddi_dma_free_handle(&mem->dma_handle);

		return (NULL);
	}

	if (cnt > 1) {
		(void) ddi_dma_unbind_handle(mem->dma_handle);
		cmn_err(CE_WARN, "!skd_alloc_dma_mem-4, failed, "
		    "cookie_count %d > 1", cnt);
		skd_free_phys(skdev, mem);

		return (NULL);
	}
	mem->cookies = &mem->cookie;
	mem->cookies->dmac_size = mem->size;

	return (mem->bp);
}

/*
 *
 * Name:	skd_cons_skcomp, allocates space for the skcomp table.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	-ENOMEM if no memory otherwise NULL.
 *
 */
static int
skd_cons_skcomp(struct skd_device *skdev)
{
	uint64_t	*dma_alloc;
	struct fit_completion_entry_v1 *skcomp;
	int 		rc = 0;
	uint32_t 		nbytes;
	dma_mem_t	*mem;

	nbytes = sizeof (*skcomp) * SKD_N_COMPLETION_ENTRY;
	nbytes += sizeof (struct fit_comp_error_info) * SKD_N_COMPLETION_ENTRY;

	Dcmn_err(CE_NOTE, "cons_skcomp: nbytes=%d,entries=%d", nbytes,
	    SKD_N_COMPLETION_ENTRY);

	mem 			= &skdev->cq_dma_address;
	mem->size 		= nbytes;

	dma_alloc = skd_alloc_dma_mem(skdev, mem, ATYPE_64BIT);
	skcomp = (struct fit_completion_entry_v1 *)dma_alloc;
	if (skcomp == NULL) {
		rc = -ENOMEM;
		goto err_out;
	}

	bzero(skcomp, nbytes);

	Dcmn_err(CE_NOTE, "cons_skcomp: skcomp=%p nbytes=%d",
	    (void *)skcomp, nbytes);

	skdev->skcomp_table = skcomp;
	skdev->skerr_table = (struct fit_comp_error_info *)(dma_alloc +
	    (SKD_N_COMPLETION_ENTRY * sizeof (*skcomp) / sizeof (uint64_t)));

err_out:
	return (rc);
}

/*
 *
 * Name:	skd_cons_skmsg, allocates space for the skmsg table.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	-ENOMEM if no memory otherwise NULL.
 *
 */
static int
skd_cons_skmsg(struct skd_device *skdev)
{
	dma_mem_t	*mem;
	int 		rc = 0;
	uint32_t 		i;

	Dcmn_err(CE_NOTE, "skmsg_table kzalloc, struct %lu, count %u total %lu",
	    (ulong_t)sizeof (struct skd_fitmsg_context),
	    skdev->num_fitmsg_context,
	    (ulong_t)(sizeof (struct skd_fitmsg_context) *
	    skdev->num_fitmsg_context));

	skdev->skmsg_table = (struct skd_fitmsg_context *)kmem_zalloc(
	    sizeof (struct skd_fitmsg_context) * skdev->num_fitmsg_context,
	    KM_SLEEP);

	for (i = 0; i < skdev->num_fitmsg_context; i++) {
		struct skd_fitmsg_context *skmsg;

		skmsg = &skdev->skmsg_table[i];

		skmsg->id = i + SKD_ID_FIT_MSG;

		skmsg->state = SKD_MSG_STATE_IDLE;

		mem = &skmsg->mb_dma_address;
		mem->size = SKD_N_FITMSG_BYTES + 64;

		skmsg->msg_buf = skd_alloc_dma_mem(skdev, mem, ATYPE_64BIT);

		if (NULL == skmsg->msg_buf) {
			rc = -ENOMEM;
			i++;
			break;
		}

		skmsg->offset = 0;

		bzero(skmsg->msg_buf, SKD_N_FITMSG_BYTES);

		skmsg->next = &skmsg[1];
	}

	/* Free list is in order starting with the 0th entry. */
	skdev->skmsg_table[i - 1].next = NULL;
	skdev->skmsg_free_list = skdev->skmsg_table;

	return (rc);
}

/*
 *
 * Name:	skd_cons_skreq, allocates space for the skreq table.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	-ENOMEM if no memory otherwise NULL.
 *
 */
static int
skd_cons_skreq(struct skd_device *skdev)
{
	int 	rc = 0;
	uint32_t 	i;

	Dcmn_err(CE_NOTE,
	    "skreq_table kmem_zalloc, struct %lu, count %u total %lu",
	    (ulong_t)sizeof (struct skd_request_context),
	    skdev->num_req_context,
	    (ulong_t) (sizeof (struct skd_request_context) *
	    skdev->num_req_context));

	skdev->skreq_table = (struct skd_request_context *)kmem_zalloc(
	    sizeof (struct skd_request_context) * skdev->num_req_context,
	    KM_SLEEP);

	for (i = 0; i < skdev->num_req_context; i++) {
		struct skd_request_context *skreq;

		skreq = &skdev->skreq_table[i];

		skreq->id = (uint16_t)(i + SKD_ID_RW_REQUEST);
		skreq->state = SKD_REQ_STATE_IDLE;

		skreq->sksg_list = skd_cons_sg_list(skdev,
		    skdev->sgs_per_request,
		    &skreq->sksg_dma_address);

		if (NULL == skreq->sksg_list) {
			rc = -ENOMEM;
			goto err_out;
		}

		skreq->next = &skreq[1];
	}

	/* Free list is in order starting with the 0th entry. */
	skdev->skreq_table[i - 1].next = NULL;
	skdev->skreq_free_list = skdev->skreq_table;

err_out:
	return (rc);
}

/*
 *
 * Name:	skd_cons_sksb, allocates space for the skspcl msg buf
 *		and data buf.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	-ENOMEM if no memory otherwise NULL.
 *
 */
static int
skd_cons_sksb(struct skd_device *skdev)
{
	int 				rc = 0;
	struct skd_special_context 	*skspcl;
	dma_mem_t			*mem;
	uint32_t 				nbytes;

	skspcl = &skdev->internal_skspcl;

	skspcl->req.id = 0 + SKD_ID_INTERNAL;
	skspcl->req.state = SKD_REQ_STATE_IDLE;

	nbytes = SKD_N_INTERNAL_BYTES;

	mem 			= &skspcl->db_dma_address;
	mem->size 		= nbytes;

	/* data_buf's DMA pointer is skspcl->db_dma_address */
	skspcl->data_buf = skd_alloc_dma_mem(skdev, mem, ATYPE_64BIT);
	if (skspcl->data_buf == NULL) {
		rc = -ENOMEM;
		goto err_out;
	}

	bzero(skspcl->data_buf, nbytes);

	nbytes = SKD_N_SPECIAL_FITMSG_BYTES;

	mem 			= &skspcl->mb_dma_address;
	mem->size 		= nbytes;

	/* msg_buf DMA pointer is skspcl->mb_dma_address */
	skspcl->msg_buf = skd_alloc_dma_mem(skdev, mem, ATYPE_64BIT);
	if (skspcl->msg_buf == NULL) {
		rc = -ENOMEM;
		goto err_out;
	}


	bzero(skspcl->msg_buf, nbytes);

	skspcl->req.sksg_list = skd_cons_sg_list(skdev, 1,
	    &skspcl->req.sksg_dma_address);


	if (skspcl->req.sksg_list == NULL) {
		rc = -ENOMEM;
		goto err_out;
	}

	if (skd_format_internal_skspcl(skdev) == 0) {
		rc = -EINVAL;
		goto err_out;
	}

err_out:
	return (rc);
}

/*
 *
 * Name:	skd_cons_sg_list, allocates the S/G list.
 *
 * Inputs:	skdev		- device state structure.
 *		n_sg		- Number of scatter-gather entries.
 *		ret_dma_addr	- S/G list DMA pointer.
 *
 * Returns:	A list of FIT message descriptors.
 *
 */
static struct fit_sg_descriptor
*skd_cons_sg_list(struct skd_device *skdev,
    uint32_t n_sg, dma_mem_t *ret_dma_addr)
{
	struct fit_sg_descriptor *sg_list;
	uint32_t nbytes;
	dma_mem_t *mem;

	nbytes = sizeof (*sg_list) * n_sg;

	mem 			= ret_dma_addr;
	mem->size 		= nbytes;

	/* sg_list's DMA pointer is *ret_dma_addr */
	sg_list = skd_alloc_dma_mem(skdev, mem, ATYPE_32BIT);

	if (sg_list != NULL) {
		uint64_t dma_address = ret_dma_addr->cookie.dmac_laddress;
		uint32_t i;

		bzero(sg_list, nbytes);

		for (i = 0; i < n_sg - 1; i++) {
			uint64_t ndp_off;
			ndp_off = (i + 1) * sizeof (struct fit_sg_descriptor);

			sg_list[i].next_desc_ptr = dma_address + ndp_off;
		}
		sg_list[i].next_desc_ptr = 0LL;
	}

	return (sg_list);
}

/*
 * DESTRUCT (FREE)
 */

static void skd_free_skcomp(struct skd_device *skdev);
static void skd_free_skmsg(struct skd_device *skdev);
static void skd_free_skreq(struct skd_device *skdev);
static void skd_free_sksb(struct skd_device *skdev);

static void skd_free_sg_list(struct skd_device *skdev,
    struct fit_sg_descriptor *sg_list,
    uint32_t n_sg, dma_mem_t dma_addr);

/*
 *
 * Name:	skd_destruct, call various rouines to deallocate
 *		space acquired during initialization.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_destruct(struct skd_device *skdev)
{
	if (skdev == NULL) {
		return;
	}

	Dcmn_err(CE_NOTE, "destruct sksb");
	skd_free_sksb(skdev);

	Dcmn_err(CE_NOTE, "destruct skreq");
	skd_free_skreq(skdev);

	Dcmn_err(CE_NOTE, "destruct skmsg");
	skd_free_skmsg(skdev);

	Dcmn_err(CE_NOTE, "destruct skcomp");
	skd_free_skcomp(skdev);

	Dcmn_err(CE_NOTE, "DESTRUCT VICTORY");
}

/*
 *
 * Name:	skd_free_skcomp, deallocates skcomp table DMA resources.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_free_skcomp(struct skd_device *skdev)
{
	if (skdev->skcomp_table != NULL) {
		skd_free_phys(skdev, &skdev->cq_dma_address);
	}

	skdev->skcomp_table = NULL;
}

/*
 *
 * Name:	skd_free_skmsg, deallocates skmsg table DMA resources.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_free_skmsg(struct skd_device *skdev)
{
	uint32_t 		i;

	if (NULL == skdev->skmsg_table)
		return;

	for (i = 0; i < skdev->num_fitmsg_context; i++) {
		struct skd_fitmsg_context *skmsg;

		skmsg = &skdev->skmsg_table[i];

		if (skmsg->msg_buf != NULL) {
			skd_free_phys(skdev, &skmsg->mb_dma_address);
		}


		skmsg->msg_buf = NULL;
	}

	kmem_free(skdev->skmsg_table, sizeof (struct skd_fitmsg_context) *
	    skdev->num_fitmsg_context);

	skdev->skmsg_table = NULL;

}

/*
 *
 * Name:	skd_free_skreq, deallocates skspcl table DMA resources.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_free_skreq(struct skd_device *skdev)
{
	uint32_t i;

	if (NULL == skdev->skreq_table)
		return;

	for (i = 0; i < skdev->num_req_context; i++) {
		struct skd_request_context *skreq;

		skreq = &skdev->skreq_table[i];

		skd_free_sg_list(skdev, skreq->sksg_list,
		    skdev->sgs_per_request, skreq->sksg_dma_address);

		skreq->sksg_list = NULL;
	}

	kmem_free(skdev->skreq_table, sizeof (struct skd_request_context) *
	    skdev->num_req_context);

	skdev->skreq_table = NULL;

}

/*
 *
 * Name:	skd_free_sksb, deallocates skspcl data buf and
 *		msg buf DMA resources.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_free_sksb(struct skd_device *skdev)
{
	struct skd_special_context *skspcl;

	skspcl = &skdev->internal_skspcl;

	if (skspcl->data_buf != NULL) {
		skd_free_phys(skdev, &skspcl->db_dma_address);
	}

	skspcl->data_buf = NULL;

	if (skspcl->msg_buf != NULL) {
		skd_free_phys(skdev, &skspcl->mb_dma_address);
	}

	skspcl->msg_buf = NULL;

	skd_free_sg_list(skdev, skspcl->req.sksg_list, 1,
	    skspcl->req.sksg_dma_address);

	skspcl->req.sksg_list = NULL;
}

/*
 *
 * Name:	skd_free_sg_list, deallocates S/G DMA resources.
 *
 * Inputs:	skdev		- device state structure.
 *		sg_list		- S/G list itself.
 *		n_sg		- nukmber of segments
 *		dma_addr	- S/G list DMA address.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static void
skd_free_sg_list(struct skd_device *skdev,
    struct fit_sg_descriptor *sg_list,
    uint32_t n_sg, dma_mem_t dma_addr)
{
	if (sg_list != NULL) {
		skd_free_phys(skdev, &dma_addr);
	}
}

/*
 *
 * Name:	skd_queue, queues the I/O request.
 *
 * Inputs:	skdev		- device state structure.
 *		pbuf		- I/O request
 *
 * Returns:	Nothing.
 *
 */
static void
skd_queue(skd_device_t *skdev, skd_buf_private_t *pbuf)
{
	struct waitqueue *waitq;

	ASSERT(skdev != NULL);
	ASSERT(pbuf != NULL);

	ASSERT(WAITQ_LOCK_HELD(skdev));

	waitq = &skdev->waitqueue;

	if (SIMPLEQ_EMPTY(waitq))
		SIMPLEQ_INSERT_HEAD(waitq, pbuf, sq);
	else
		SIMPLEQ_INSERT_TAIL(waitq, pbuf, sq);
}

/*
 *
 * Name:	skd_list_skreq, displays the skreq table entries.
 *
 * Inputs:	skdev		- device state structure.
 *		list		- flag, if true displays the entry address.
 *
 * Returns:	Returns number of skmsg entries found.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static int
skd_list_skreq(skd_device_t *skdev, int list)
{
	int	inx = 0;
	struct skd_request_context *skreq;

	if (list) {
		Dcmn_err(CE_NOTE, "skreq_table[0]\n");

		skreq = &skdev->skreq_table[0];
		while (skreq) {
			if (list)
				Dcmn_err(CE_NOTE,
				    "%d: skreq=%p state=%d id=%x fid=%x "
				    "pbuf=%p dir=%d comp=%d\n",
				    inx, (void *)skreq, skreq->state,
				    skreq->id, skreq->fitmsg_id,
				    (void *)skreq->pbuf,
				    skreq->sg_data_dir, skreq->did_complete);
			inx++;
			skreq = skreq->next;
		}
	}

	inx = 0;
	skreq = skdev->skreq_free_list;

	if (list)
		Dcmn_err(CE_NOTE, "skreq_free_list\n");
	while (skreq) {
		if (list)
			Dcmn_err(CE_NOTE, "%d: skreq=%p state=%d id=%x fid=%x "
			    "pbuf=%p dir=%d\n", inx, (void *)skreq,
			    skreq->state, skreq->id, skreq->fitmsg_id,
			    (void *)skreq->pbuf, skreq->sg_data_dir);
		inx++;
		skreq = skreq->next;
	}

	return (inx);
}

/*
 *
 * Name:	skd_list_skmsg, displays the skmsg table entries.
 *
 * Inputs:	skdev		- device state structure.
 *		list		- flag, if true displays the entry address.
 *
 * Returns:	Returns number of skmsg entries found.
 *
 */
static int
skd_list_skmsg(skd_device_t *skdev, int list)
{
	int	inx = 0;
	struct skd_fitmsg_context *skmsgp;

	skmsgp = &skdev->skmsg_table[0];

	if (list) {
		Dcmn_err(CE_NOTE, "skmsg_table[0]\n");

		while (skmsgp) {
			if (list)
				Dcmn_err(CE_NOTE, "%d: skmsgp=%p id=%x outs=%d "
				    "l=%d o=%d nxt=%p\n", inx, (void *)skmsgp,
				    skmsgp->id, skmsgp->outstanding,
				    skmsgp->length, skmsgp->offset,
				    (void *)skmsgp->next);
			inx++;
			skmsgp = skmsgp->next;
		}
	}

	inx = 0;
	if (list)
		Dcmn_err(CE_NOTE, "skmsg_free_list\n");
	skmsgp = skdev->skmsg_free_list;
	while (skmsgp) {
		if (list)
			Dcmn_err(CE_NOTE, "%d: skmsgp=%p id=%x outs=%d l=%d "
			    "o=%d nxt=%p\n",
			    inx, (void *)skmsgp, skmsgp->id,
			    skmsgp->outstanding, skmsgp->length,
			    skmsgp->offset, (void *)skmsgp->next);
		inx++;
		skmsgp = skmsgp->next;
	}

	return (inx);
}

/*
 *
 * Name:	skd_get_queue_pbuf, retrieves top of queue entry and
 *		delinks entry from the queue.
 *
 * Inputs:	skdev		- device state structure.
 *		drive		- device number
 *
 * Returns:	Returns the top of the job queue entry.
 *
 */
static skd_buf_private_t
*skd_get_queued_pbuf(skd_device_t *skdev)
{
	skd_buf_private_t *pbuf;

	ASSERT(WAITQ_LOCK_HELD(skdev));
	pbuf = SIMPLEQ_FIRST(&skdev->waitqueue);
	if (pbuf != NULL)
		SIMPLEQ_REMOVE_HEAD(&skdev->waitqueue, sq);
	return (pbuf);
}

/*
 * PCI DRIVER GLUE
 */

/*
 *
 * Name:	skd_pci_info, logs certain device PCI info.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	str which contains the device speed info..
 *
 */
static char *
skd_pci_info(struct skd_device *skdev, char *str, size_t len)
{
	int pcie_reg;

	str[0] = '\0';

	pcie_reg = skd_pci_find_capability(skdev, PCI_CAP_ID_EXP);

	if (pcie_reg) {
		uint16_t lstat, lspeed, lwidth;

		pcie_reg += 0x12;
		lstat  = pci_config_get16(skdev->pci_handle, pcie_reg);
		lspeed = lstat & (0xF);
		lwidth = (lstat & 0x3F0) >> 4;

		(void) snprintf(str, len, "PCIe (%s rev %d)",
		    lspeed == 1 ? "2.5GT/s" :
		    lspeed == 2 ? "5.0GT/s" : "<unknown>",
		    lwidth);
	}

	return (str);
}

/*
 * MODULE GLUE
 */

/*
 *
 * Name:	skd_init, initializes certain values.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Zero.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static int
skd_init(skd_device_t *skdev)
{
	Dcmn_err(CE_NOTE, "skd_init: v%s-b%s\n", DRV_VERSION, DRV_BUILD_ID);

	if (skd_max_queue_depth < 1 ||
	    skd_max_queue_depth > SKD_MAX_QUEUE_DEPTH) {
		cmn_err(CE_NOTE, "skd_max_q_depth %d invalid, re-set to %d\n",
		    skd_max_queue_depth, SKD_MAX_QUEUE_DEPTH_DEFAULT);
		skd_max_queue_depth = SKD_MAX_QUEUE_DEPTH_DEFAULT;
	}

	if (skd_max_req_per_msg < 1 || skd_max_req_per_msg > 14) {
		cmn_err(CE_NOTE, "skd_max_req_per_msg %d invalid, set to %d\n",
		    skd_max_req_per_msg, SKD_MAX_REQ_PER_MSG_DEFAULT);
		skd_max_req_per_msg = SKD_MAX_REQ_PER_MSG_DEFAULT;
	}


	if (skd_sgs_per_request < 1 || skd_sgs_per_request > 4096) {
		cmn_err(CE_NOTE, "skd_sg_per_request %d invalid, set to %d\n",
		    skd_sgs_per_request, SKD_N_SG_PER_REQ_DEFAULT);
		skd_sgs_per_request = SKD_N_SG_PER_REQ_DEFAULT;
	}

	if (skd_dbg_level < 0 || skd_dbg_level > 2) {
		cmn_err(CE_NOTE, "skd_dbg_level %d invalid, re-set to %d\n",
		    skd_dbg_level, 0);
		skd_dbg_level = 0;
	}

	return (0);
}

/*
 *
 * Name:	skd_exit, exits the driver & logs the fact.
 *
 * Inputs:	none.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_exit(void)
{
	cmn_err(CE_NOTE, "skd v%s unloading", DRV_VERSION);
}

/*
 *
 * Name:	skd_drive_state_to_str, converts binary drive state
 *		to its corresponding string value.
 *
 * Inputs:	Drive state.
 *
 * Returns:	String representing drive state.
 *
 */
const char *
skd_drive_state_to_str(int state)
{
	switch (state) {
	case FIT_SR_DRIVE_OFFLINE:	return ("OFFLINE");
	case FIT_SR_DRIVE_INIT:		return ("INIT");
	case FIT_SR_DRIVE_ONLINE:	return ("ONLINE");
	case FIT_SR_DRIVE_BUSY:		return ("BUSY");
	case FIT_SR_DRIVE_FAULT:	return ("FAULT");
	case FIT_SR_DRIVE_DEGRADED:	return ("DEGRADED");
	case FIT_SR_PCIE_LINK_DOWN:	return ("LINK_DOWN");
	case FIT_SR_DRIVE_SOFT_RESET:	return ("SOFT_RESET");
	case FIT_SR_DRIVE_NEED_FW_DOWNLOAD: return ("NEED_FW");
	case FIT_SR_DRIVE_INIT_FAULT:	return ("INIT_FAULT");
	case FIT_SR_DRIVE_BUSY_SANITIZE:return ("BUSY_SANITIZE");
	case FIT_SR_DRIVE_BUSY_ERASE:	return ("BUSY_ERASE");
	case FIT_SR_DRIVE_FW_BOOTING:	return ("FW_BOOTING");
	default:			return ("???");
	}
}

/*
 *
 * Name:	skd_skdev_state_to_str, converts binary driver state
 *		to its corresponding string value.
 *
 * Inputs:	Driver state.
 *
 * Returns:	String representing driver state.
 *
 */
static const char *
skd_skdev_state_to_str(enum skd_drvr_state state)
{
	switch (state) {
	case SKD_DRVR_STATE_LOAD:	return ("LOAD");
	case SKD_DRVR_STATE_IDLE:	return ("IDLE");
	case SKD_DRVR_STATE_BUSY:	return ("BUSY");
	case SKD_DRVR_STATE_STARTING:	return ("STARTING");
	case SKD_DRVR_STATE_ONLINE:	return ("ONLINE");
	case SKD_DRVR_STATE_PAUSING:	return ("PAUSING");
	case SKD_DRVR_STATE_PAUSED:	return ("PAUSED");
	case SKD_DRVR_STATE_DRAINING_TIMEOUT: return ("DRAINING_TIMEOUT");
	case SKD_DRVR_STATE_RESTARTING:	return ("RESTARTING");
	case SKD_DRVR_STATE_RESUMING:	return ("RESUMING");
	case SKD_DRVR_STATE_STOPPING:	return ("STOPPING");
	case SKD_DRVR_STATE_SYNCING:	return ("SYNCING");
	case SKD_DRVR_STATE_FAULT:	return ("FAULT");
	case SKD_DRVR_STATE_DISAPPEARED: return ("DISAPPEARED");
	case SKD_DRVR_STATE_BUSY_ERASE:	return ("BUSY_ERASE");
	case SKD_DRVR_STATE_BUSY_SANITIZE:return ("BUSY_SANITIZE");
	case SKD_DRVR_STATE_BUSY_IMMINENT: return ("BUSY_IMMINENT");
	case SKD_DRVR_STATE_WAIT_BOOT:  return ("WAIT_BOOT");

	default:			return ("???");
	}
}

/*
 *
 * Name:	skd_skmsg_state_to_str, converts binary driver state
 *		to its corresponding string value.
 *
 * Inputs:	Msg state.
 *
 * Returns:	String representing msg state.
 *
 */
static const char *
skd_skmsg_state_to_str(enum skd_fit_msg_state state)
{
	switch (state) {
	case SKD_MSG_STATE_IDLE:	return ("IDLE");
	case SKD_MSG_STATE_BUSY:	return ("BUSY");
	default:			return ("???");
	}
}

/*
 *
 * Name:	skd_skreq_state_to_str, converts binary req state
 *		to its corresponding string value.
 *
 * Inputs:	Req state.
 *
 * Returns:	String representing req state.
 *
 */
static const char *
skd_skreq_state_to_str(enum skd_req_state state)
{
	switch (state) {
	case SKD_REQ_STATE_IDLE:	return ("IDLE");
	case SKD_REQ_STATE_SETUP:	return ("SETUP");
	case SKD_REQ_STATE_BUSY:	return ("BUSY");
	case SKD_REQ_STATE_COMPLETED:	return ("COMPLETED");
	case SKD_REQ_STATE_TIMEOUT:	return ("TIMEOUT");
	case SKD_REQ_STATE_ABORTED:	return ("ABORTED");
	default:			return ("???");
	}
}

/*
 *
 * Name:	skd_log_skdev, logs device state & parameters.
 *
 * Inputs:	skdev		- device state structure.
 *		event		- event (string) to log.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_log_skdev(struct skd_device *skdev, const char *event)
{
	Dcmn_err(CE_NOTE, "log_skdev(%s) skdev=%p event='%s'",
	    skdev->name, (void *)skdev, event);
	Dcmn_err(CE_NOTE, "  drive_state=%s(%d) driver_state=%s(%d)",
	    skd_drive_state_to_str(skdev->drive_state), skdev->drive_state,
	    skd_skdev_state_to_str(skdev->state), skdev->state);
	Dcmn_err(CE_NOTE, "  busy=%d limit=%d soft=%d hard=%d lowat=%d",
	    skdev->queue_depth_busy, skdev->queue_depth_limit,
	    skdev->soft_queue_depth_limit, skdev->hard_queue_depth_limit,
	    skdev->queue_depth_lowat);
	Dcmn_err(CE_NOTE, "  timestamp=0x%x cycle=%d cycle_ix=%d",
	    skdev->timeout_stamp, skdev->skcomp_cycle, skdev->skcomp_ix);
}

/*
 *
 * Name:	skd_log_skmsg, logs the skmsg event.
 *
 * Inputs:	skdev		- device state structure.
 *		skmsg		- FIT message structure.
 *		event		- event string to log.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_log_skmsg(struct skd_device *skdev,
    struct skd_fitmsg_context *skmsg, const char *event)
{
	Dcmn_err(CE_NOTE, "log_skmsg:(%s) skmsg=%p event='%s'",
	    skdev->name, (void *)skmsg, event);
	Dcmn_err(CE_NOTE, "  state=%s(%d) id=0x%04x length=%d",
	    skd_skmsg_state_to_str(skmsg->state), skmsg->state,
	    skmsg->id, skmsg->length);
}

/*
 *
 * Name:	skd_log_skreq, logs the skreq event.
 *
 * Inputs:	skdev		- device state structure.
 *		skreq		-skreq structure.
 *		event		- event string to log.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_log_skreq(struct skd_device *skdev,
    struct skd_request_context *skreq, const char *event)
{
	skd_buf_private_t *pbuf;

	Dcmn_err(CE_NOTE, "log_skreq: (%s) skreq=%p pbuf=%p event='%s'",
	    skdev->name, (void *)skreq, (void *)skreq->pbuf, event);

	Dcmn_err(CE_NOTE, "  state=%s(%d) id=0x%04x fitmsg=0x%04x",
	    skd_skreq_state_to_str(skreq->state), skreq->state,
	    skreq->id, skreq->fitmsg_id);
	Dcmn_err(CE_NOTE, "  timo=0x%x sg_dir=%d n_sg=%d",
	    skreq->timeout_stamp, skreq->sg_data_dir, skreq->n_sg);

	if ((pbuf = skreq->pbuf) != NULL) {
		uint32_t lba, count;
		lba = pbuf->x_xfer->x_blkno;
		count = pbuf->x_xfer->x_nblks;
		Dcmn_err(CE_NOTE, "  pbuf=%p lba=%u(0x%x) count=%u(0x%x) ",
		    (void *)pbuf, lba, lba, count, count);
		Dcmn_err(CE_NOTE, "  dir=%s "
		    " intrs=%" PRId64 " qdepth=%d",
		    (pbuf->dir & B_READ) ? "Read" : "Write",
		    skdev->intr_cntr, skdev->queue_depth_busy);
	} else {
		Dcmn_err(CE_NOTE, "  req=NULL\n");
	}
}

/*
 *
 * Name:	skd_init_mutex, initializes all mutexes.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	DDI_FAILURE on failure otherwise DDI_SUCCESS.
 *
 */
static int
skd_init_mutex(skd_device_t *skdev)
{
	void	*intr;

	Dcmn_err(CE_CONT, "(%s%d): init_mutex flags=%x", DRV_NAME,
	    skdev->instance, skdev->flags);

	intr = (void *)(uintptr_t)skdev->intr_pri;

	if (skdev->flags & SKD_MUTEX_INITED)
		cmn_err(CE_NOTE, "init_mutex: Oh-Oh - already INITED");

	/* mutexes to protect the adapter state structure. */
	mutex_init(&skdev->skd_lock_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(intr));
	mutex_init(&skdev->skd_intr_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(intr));
	mutex_init(&skdev->waitqueue_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(intr));
	mutex_init(&skdev->skd_internalio_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(intr));

	cv_init(&skdev->cv_waitq, NULL, CV_DRIVER, NULL);

	skdev->flags |= SKD_MUTEX_INITED;
	if (skdev->flags & SKD_MUTEX_DESTROYED)
		skdev->flags &= ~SKD_MUTEX_DESTROYED;

	Dcmn_err(CE_CONT, "init_mutex (%s%d): done, flags=%x", DRV_NAME,
	    skdev->instance, skdev->flags);

	return (DDI_SUCCESS);
}

/*
 *
 * Name:	skd_destroy_mutex, destroys all mutexes.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_destroy_mutex(skd_device_t *skdev)
{
	if ((skdev->flags & SKD_MUTEX_DESTROYED) == 0) {
		if (skdev->flags & SKD_MUTEX_INITED) {
			mutex_destroy(&skdev->waitqueue_mutex);
			mutex_destroy(&skdev->skd_intr_mutex);
			mutex_destroy(&skdev->skd_lock_mutex);
			mutex_destroy(&skdev->skd_internalio_mutex);

			cv_destroy(&skdev->cv_waitq);

			skdev->flags |= SKD_MUTEX_DESTROYED;

			if (skdev->flags & SKD_MUTEX_INITED)
				skdev->flags &= ~SKD_MUTEX_INITED;
		}
	}
}

/*
 *
 * Name:	skd_setup_intr, setup the interrupt handling
 *
 * Inputs:	skdev		- device state structure.
 *		intr_type	- requested DDI interrupt type.
 *
 * Returns:	DDI_FAILURE on failure otherwise DDI_SUCCESS.
 *
 */
static int
skd_setup_intr(skd_device_t *skdev, int intr_type)
{
	int32_t		count = 0;
	int32_t		avail = 0;
	int32_t		actual = 0;
	int32_t		ret;
	uint32_t	i;

	Dcmn_err(CE_CONT, "(%s%d): setup_intr", DRV_NAME, skdev->instance);

	/* Get number of interrupts the platform h/w supports */
	if (((ret = ddi_intr_get_nintrs(skdev->dip, intr_type, &count)) !=
	    DDI_SUCCESS) || count == 0) {
		cmn_err(CE_WARN, "!intr_setup failed, nintrs ret=%xh, cnt=%xh",
		    ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of available system interrupts */
	if (((ret = ddi_intr_get_navail(skdev->dip, intr_type, &avail)) !=
	    DDI_SUCCESS) || avail == 0) {
		cmn_err(CE_WARN, "!intr_setup failed, navail ret=%xh, "
		    "avail=%xh", ret, avail);

		return (DDI_FAILURE);
	}

	if (intr_type == DDI_INTR_TYPE_MSIX && avail < SKD_MSIX_MAXAIF) {
		cmn_err(CE_WARN, "!intr_setup failed, min MSI-X h/w vectors "
		    "req'd: %d, avail: %d",
		    SKD_MSIX_MAXAIF, count);

		return (DDI_FAILURE);
	}

	/* Allocate space for interrupt handles */
	skdev->hsize = sizeof (ddi_intr_handle_t) * avail;
	skdev->htable = kmem_zalloc(skdev->hsize, KM_SLEEP);

	/* Allocate the interrupts */
	if ((ret = ddi_intr_alloc(skdev->dip, skdev->htable, intr_type,
	    0, count, &actual, 0)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!intr_setup failed, intr_alloc ret=%xh, "
		    "count = %xh, " "actual=%xh", ret, count, actual);

		skd_release_intr(skdev);

		return (DDI_FAILURE);
	}

	skdev->intr_cnt = actual;

	if (intr_type == DDI_INTR_TYPE_FIXED)
		(void) ddi_intr_set_pri(skdev->htable[0], 10);

	/* Get interrupt priority */
	if ((ret = ddi_intr_get_pri(skdev->htable[0], &skdev->intr_pri)) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "!intr_setup failed, get_pri ret=%xh", ret);
		skd_release_intr(skdev);

		return (ret);
	}

	/* Add the interrupt handlers */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(skdev->htable[i],
		    skd_isr_aif, (void *)skdev, (void *)((ulong_t)i))) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "!intr_setup failed, addh#=%xh, "
			    "act=%xh, ret=%xh", i, actual, ret);
			skd_release_intr(skdev);

			return (ret);
		}
	}

	/* Setup mutexes */
	if ((ret = skd_init_mutex(skdev)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!intr_setup failed, mutex init ret=%xh", ret);
		skd_release_intr(skdev);

		return (ret);
	}

	/* Get the capabilities */
	(void) ddi_intr_get_cap(skdev->htable[0], &skdev->intr_cap);

	/* Enable interrupts */
	if (skdev->intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(skdev->htable,
		    skdev->intr_cnt)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!failed, intr_setup block enable, "
			    "ret=%xh", ret);
			skd_destroy_mutex(skdev);
			skd_release_intr(skdev);

			return (ret);
		}
	} else {
		for (i = 0; i < skdev->intr_cnt; i++) {
			if ((ret = ddi_intr_enable(skdev->htable[i])) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "!intr_setup failed, "
				    "intr enable, ret=%xh", ret);
				skd_destroy_mutex(skdev);
				skd_release_intr(skdev);

				return (ret);
			}
		}
	}

	if (intr_type == DDI_INTR_TYPE_FIXED)
		(void) ddi_intr_clr_mask(skdev->htable[0]);

	skdev->irq_type = intr_type;

	return (DDI_SUCCESS);
}

/*
 *
 * Name:	skd_disable_intr, disable interrupt handling.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_disable_intr(skd_device_t *skdev)
{
	uint32_t	i, rval;

	if (skdev->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Remove AIF block interrupts (MSI/MSI-X) */
		if ((rval = ddi_intr_block_disable(skdev->htable,
		    skdev->intr_cnt)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!failed intr block disable, rval=%x",
			    rval);
		}
	} else {
		/* Remove AIF non-block interrupts (fixed).  */
		for (i = 0; i < skdev->intr_cnt; i++) {
			if ((rval = ddi_intr_disable(skdev->htable[i])) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "!failed intr disable, "
				    "intr#=%xh, " "rval=%xh", i, rval);
			}
		}
	}
}

/*
 *
 * Name:	skd_release_intr, disables interrupt handling.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_release_intr(skd_device_t *skdev)
{
	int32_t 	i;
	int		rval;


	Dcmn_err(CE_CONT, "REL_INTR intr_cnt=%d", skdev->intr_cnt);

	if (skdev->irq_type == 0) {
		Dcmn_err(CE_CONT, "release_intr: (%s%d): done",
		    DRV_NAME, skdev->instance);
		return;
	}

	if (skdev->htable != NULL && skdev->hsize > 0) {
		i = (int32_t)skdev->hsize / (int32_t)sizeof (ddi_intr_handle_t);

		while (i-- > 0) {
			if (skdev->htable[i] == 0) {
				Dcmn_err(CE_NOTE, "htable[%x]=0h", i);
				continue;
			}

			if ((rval = ddi_intr_disable(skdev->htable[i])) !=
			    DDI_SUCCESS)
				Dcmn_err(CE_NOTE, "release_intr: intr_disable "
				    "htable[%d], rval=%d", i, rval);

			if (i < skdev->intr_cnt) {
				if ((rval = ddi_intr_remove_handler(
				    skdev->htable[i])) != DDI_SUCCESS)
					cmn_err(CE_WARN, "!release_intr: "
					    "intr_remove_handler FAILED, "
					    "rval=%d", rval);

				Dcmn_err(CE_NOTE, "release_intr: "
				    "remove_handler htable[%d]", i);
			}

			if ((rval = ddi_intr_free(skdev->htable[i])) !=
			    DDI_SUCCESS)
				cmn_err(CE_WARN, "!release_intr: intr_free "
				    "FAILED, rval=%d", rval);
			Dcmn_err(CE_NOTE, "release_intr: intr_free htable[%d]",
			    i);
		}

		kmem_free(skdev->htable, skdev->hsize);
		skdev->htable = NULL;
	}

	skdev->hsize    = 0;
	skdev->intr_cnt = 0;
	skdev->intr_pri = 0;
	skdev->intr_cap = 0;
	skdev->irq_type = 0;
}

/*
 *
 * Name:	skd_dealloc_resources, deallocate resources allocated
 *		during attach.
 *
 * Inputs:	dip		- DDI device info pointer.
 *		skdev		- device state structure.
 * 		seq		- bit flag representing allocated item.
 *		instance	- device instance.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static void
skd_dealloc_resources(dev_info_t *dip, skd_device_t *skdev,
    uint32_t seq, int instance)
{

	if (skdev == NULL)
		return;

	if (seq & SKD_CONSTRUCTED)
		skd_destruct(skdev);

	if (seq & SKD_INTR_ADDED) {
		skd_disable_intr(skdev);
		skd_release_intr(skdev);
	}

	if (seq & SKD_DEV_IOBASE_MAPPED)
		ddi_regs_map_free(&skdev->dev_handle);

	if (seq & SKD_IOMAP_IOBASE_MAPPED)
		ddi_regs_map_free(&skdev->iomap_handle);

	if (seq & SKD_REGS_MAPPED)
		ddi_regs_map_free(&skdev->iobase_handle);

	if (seq & SKD_CONFIG_SPACE_SETUP)
		pci_config_teardown(&skdev->pci_handle);

	if (seq & SKD_SOFT_STATE_ALLOCED)  {
		if (skdev->pathname &&
		    (skdev->flags & SKD_PATHNAME_ALLOCED)) {
			kmem_free(skdev->pathname,
			    strlen(skdev->pathname)+1);
		}
	}

	if (skdev->s1120_devid)
		ddi_devid_free(skdev->s1120_devid);
}

/*
 *
 * Name:	skd_setup_interrupt, sets up the appropriate interrupt type
 *		msi, msix, or fixed.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	DDI_FAILURE on failure otherwise DDI_SUCCESS.
 *
 */
static int
skd_setup_interrupts(skd_device_t *skdev)
{
	int32_t		rval = DDI_FAILURE;
	int32_t		i;
	int32_t		itypes = 0;

	/*
	 * See what types of interrupts this adapter and platform support
	 */
	if ((i = ddi_intr_get_supported_types(skdev->dip, &itypes)) !=
	    DDI_SUCCESS) {
		cmn_err(CE_NOTE, "intr supported types failed, rval=%xh, ", i);
		return (DDI_FAILURE);
	}

	Dcmn_err(CE_NOTE, "%s:supported interrupts types: %x",
	    skdev->name, itypes);

	itypes &= skdev->irq_type;

	if (!skd_disable_msix && (itypes & DDI_INTR_TYPE_MSIX) &&
	    (rval = skd_setup_intr(skdev, DDI_INTR_TYPE_MSIX)) == DDI_SUCCESS) {
		cmn_err(CE_NOTE, "!%s: successful MSI-X setup",
		    skdev->name);
	} else if (!skd_disable_msi && (itypes & DDI_INTR_TYPE_MSI) &&
	    (rval = skd_setup_intr(skdev, DDI_INTR_TYPE_MSI)) == DDI_SUCCESS) {
		cmn_err(CE_NOTE, "!%s: successful MSI setup",
		    skdev->name);
	} else if ((itypes & DDI_INTR_TYPE_FIXED) &&
	    (rval = skd_setup_intr(skdev, DDI_INTR_TYPE_FIXED))
	    == DDI_SUCCESS) {
		cmn_err(CE_NOTE, "!%s: successful fixed intr setup",
		    skdev->name);
	} else {
		cmn_err(CE_WARN, "!%s: no supported interrupt types",
		    skdev->name);
		return (DDI_FAILURE);
	}

	Dcmn_err(CE_CONT, "%s: setup interrupts done", skdev->name);

	return (rval);
}

/*
 *
 * Name:	skd_get_properties, retrieves properties from skd.conf.
 *
 * Inputs:	skdev		- device state structure.
 *		dip		- dev_info data structure.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static void
skd_get_properties(dev_info_t *dip, skd_device_t *skdev)
{
	int	prop_value;

	skd_isr_type =  ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "intr-type-cap", -1);

	prop_value =  ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "max-scsi-reqs", -1);
	if (prop_value >= 1 && prop_value <= SKD_MAX_QUEUE_DEPTH)
		skd_max_queue_depth = prop_value;

	prop_value =  ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "max-scsi-reqs-per-msg", -1);
	if (prop_value >= 1 && prop_value <= SKD_MAX_REQ_PER_MSG)
		skd_max_req_per_msg = prop_value;

	prop_value =  ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "max-sgs-per-req", -1);
	if (prop_value >= 1 && prop_value <= SKD_MAX_N_SG_PER_REQ)
		skd_sgs_per_request = prop_value;

	prop_value =  ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "dbg-level", -1);
	if (prop_value >= 1 && prop_value <= 2)
		skd_dbg_level = prop_value;
}

/*
 *
 * Name:	skd_wait_for_s1120, wait for device to finish
 *		its initialization.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	DDI_SUCCESS or DDI_FAILURE.
 *
 */
static int
skd_wait_for_s1120(skd_device_t *skdev)
{
	clock_t	cur_ticks, tmo;
	int	loop_cntr = 0;
	int	rc = DDI_FAILURE;

	mutex_enter(&skdev->skd_internalio_mutex);

	while (skdev->gendisk_on == 0) {
		cur_ticks = ddi_get_lbolt();
		tmo = cur_ticks + drv_usectohz(MICROSEC);
		if (cv_timedwait(&skdev->cv_waitq,
		    &skdev->skd_internalio_mutex, tmo) == -1) {
			/* Oops - timed out */
			if (loop_cntr++ > 10)
				break;
		}
	}

	mutex_exit(&skdev->skd_internalio_mutex);

	if (skdev->gendisk_on == 1)
		rc = DDI_SUCCESS;

	return (rc);
}

/*
 *
 * Name:	skd_update_props, updates certain device properties.
 *
 * Inputs:	skdev		- device state structure.
 *		dip		- dev info structure
 *
 * Returns:	Nothing.
 *
 */
static void
skd_update_props(skd_device_t *skdev, dev_info_t *dip)
{
	int	blksize = 512;

	if ((ddi_prop_update_int64(DDI_DEV_T_NONE, dip, "device-nblocks",
	    skdev->Nblocks) != DDI_SUCCESS) ||
	    (ddi_prop_update_int(DDI_DEV_T_NONE,   dip, "device-blksize",
	    blksize) != DDI_SUCCESS)) {
		cmn_err(CE_NOTE, "%s: FAILED to create driver properties",
		    skdev->name);
	}
}

/*
 *
 * Name:	skd_setup_devid, sets up device ID info.
 *
 * Inputs:	skdev		- device state structure.
 *		devid		- Device ID for the DDI.
 *
 * Returns:	DDI_SUCCESS or DDI_FAILURE.
 *
 */
static int
skd_setup_devid(skd_device_t *skdev, ddi_devid_t *devid)
{
	int  rc, sz_model, sz_sn, sz;

	sz_model = strlen(skdev->inq_product_id);
	sz_sn = strlen(skdev->inq_serial_num);
	sz = sz_model + sz_sn + 1;

	(void) snprintf(skdev->devid_str, sizeof (skdev->devid_str), "%s=%s",
	    skdev->inq_product_id, skdev->inq_serial_num);
	rc = ddi_devid_init(skdev->dip, DEVID_SCSI_SERIAL, sz,
	    skdev->devid_str, devid);

	if (rc != DDI_SUCCESS)
		cmn_err(CE_WARN, "!%s: devid_init FAILED", skdev->name);

	return (rc);

}

/*
 *
 * Name:	skd_bd_attach, attach to blkdev driver
 *
 * Inputs:	skdev		- device state structure.
 *        	dip		- device info structure.
 *
 * Returns:	DDI_SUCCESS or DDI_FAILURE.
 *
 */
static int
skd_bd_attach(dev_info_t *dip, skd_device_t *skdev)
{
	int		rv;

	skdev->s_bdh = bd_alloc_handle(skdev, &skd_bd_ops,
	    &skd_64bit_io_dma_attr, KM_SLEEP);

	if (skdev->s_bdh == NULL) {
		cmn_err(CE_WARN, "!skd_bd_attach: FAILED");

		return (DDI_FAILURE);
	}

	rv = bd_attach_handle(dip, skdev->s_bdh);

	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!bd_attach_handle FAILED\n");
	} else {
		Dcmn_err(CE_NOTE, "bd_attach_handle OK\n");
		skdev->bd_attached++;
	}

	return (rv);
}

/*
 *
 * Name:	skd_bd_detach, detach from the blkdev driver.
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_bd_detach(skd_device_t *skdev)
{
	if (skdev->bd_attached)
		(void) bd_detach_handle(skdev->s_bdh);

	bd_free_handle(skdev->s_bdh);
}

/*
 *
 * Name:	skd_attach, attach sdk device driver
 *
 * Inputs:	dip		- device info structure.
 *		cmd		- DDI attach argument (ATTACH, RESUME, etc.)
 *
 * Returns:	DDI_SUCCESS or DDI_FAILURE.
 *
 */
static int
skd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	int			nregs;
	skd_device_t   		*skdev = NULL;
	int			inx;
	uint16_t 		cmd_reg;
	int			progress = 0;
	char			name[MAXPATHLEN];
	off_t			regsize;
	char 			pci_str[32];
	char 			fw_version[8];

	instance = ddi_get_instance(dip);

	(void) ddi_get_parent_data(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/* Re-enable timer */
		skd_start_timer(skdev);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	Dcmn_err(CE_NOTE, "sTec S1120 Driver v%s Instance: %d",
	    VERSIONSTR, instance);

	/*
	 * Check that hardware is installed in a DMA-capable slot
	 */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s%d: installed in a "
		    "slot that isn't DMA-capable slot", DRV_NAME, instance);
		return (DDI_FAILURE);
	}

	/*
	 * No support for high-level interrupts
	 */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		cmn_err(CE_WARN, "!%s%d: High level interrupt not supported",
		    DRV_NAME, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate our per-device-instance structure
	 */
	if (ddi_soft_state_zalloc(skd_state, instance) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s%d: soft state zalloc failed ",
		    DRV_NAME, instance);
		return (DDI_FAILURE);
	}

	progress |= SKD_SOFT_STATE_ALLOCED;

	skdev = ddi_get_soft_state(skd_state, instance);
	if (skdev == NULL) {
		cmn_err(CE_WARN, "!%s%d: Unable to get soft state structure",
		    DRV_NAME, instance);
		goto skd_attach_failed;
	}

	(void) snprintf(skdev->name, sizeof (skdev->name),
	    DRV_NAME "%d", instance);

	skdev->dip	   = dip;
	skdev->instance	   = instance;

	ddi_set_driver_private(dip, skdev);

	(void) ddi_pathname(dip, name);
	for (inx = strlen(name); inx; inx--) {
		if (name[inx] == ',') {
			name[inx] = '\0';
			break;
		}
		if (name[inx] == '@') {
			break;
		}
	}

	skdev->pathname = kmem_zalloc(strlen(name) + 1, KM_SLEEP);
	(void) strlcpy(skdev->pathname, name, strlen(name) + 1);

	progress	|= SKD_PATHNAME_ALLOCED;
	skdev->flags	|= SKD_PATHNAME_ALLOCED;

	if (pci_config_setup(dip, &skdev->pci_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s%d: pci_config_setup FAILED",
		    DRV_NAME, instance);
		goto skd_attach_failed;
	}

	progress |= SKD_CONFIG_SPACE_SETUP;

	/* Save adapter path. */

	(void) ddi_dev_nregs(dip, &nregs);

	/*
	 *	0x0   Configuration Space
	 *	0x1   I/O Space
	 *	0x2   s1120 register space
	 */
	if (ddi_dev_regsize(dip, 1, &regsize) != DDI_SUCCESS ||
	    ddi_regs_map_setup(dip, 1, &skdev->iobase, 0, regsize,
	    &dev_acc_attr, &skdev->iobase_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s%d: regs_map_setup(mem) failed",
		    DRV_NAME, instance);
		goto skd_attach_failed;
	}
	progress |= SKD_REGS_MAPPED;

		skdev->iomap_iobase = skdev->iobase;
		skdev->iomap_handle = skdev->iobase_handle;

	Dcmn_err(CE_NOTE, "%s: PCI iobase=%ph, iomap=%ph, regnum=%d, "
	    "regsize=%ld", skdev->name, (void *)skdev->iobase,
	    (void *)skdev->iomap_iobase, 1, regsize);

	if (ddi_dev_regsize(dip, 2, &regsize) != DDI_SUCCESS ||
	    ddi_regs_map_setup(dip, 2, &skdev->dev_iobase, 0, regsize,
	    &dev_acc_attr, &skdev->dev_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s%d: regs_map_setup(mem) failed",
		    DRV_NAME, instance);

		goto skd_attach_failed;
	}

	skdev->dev_memsize = (int)regsize;

	Dcmn_err(CE_NOTE, "%s: DEV iobase=%ph regsize=%d",
	    skdev->name, (void *)skdev->dev_iobase,
	    skdev->dev_memsize);

	progress |= SKD_DEV_IOBASE_MAPPED;

	cmd_reg = pci_config_get16(skdev->pci_handle, PCI_CONF_COMM);
	cmd_reg |= (PCI_COMM_ME | PCI_COMM_INTX_DISABLE);
	cmd_reg &= ~PCI_COMM_PARITY_DETECT;
	pci_config_put16(skdev->pci_handle, PCI_CONF_COMM, cmd_reg);

	/* Get adapter PCI device information. */
	skdev->vendor_id = pci_config_get16(skdev->pci_handle, PCI_CONF_VENID);
	skdev->device_id = pci_config_get16(skdev->pci_handle, PCI_CONF_DEVID);

	Dcmn_err(CE_NOTE, "%s: %x-%x card detected",
	    skdev->name, skdev->vendor_id, skdev->device_id);

	skd_get_properties(dip, skdev);

	(void) skd_init(skdev);

	if (skd_construct(skdev, instance)) {
		cmn_err(CE_WARN, "!%s: construct FAILED", skdev->name);
		goto skd_attach_failed;
	}

	progress |= SKD_PROBED;
	progress |= SKD_CONSTRUCTED;

	SIMPLEQ_INIT(&skdev->waitqueue);

	/*
	 * Setup interrupt handler
	 */
	if (skd_setup_interrupts(skdev) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: Unable to add interrupt",
		    skdev->name);
		goto skd_attach_failed;
	}

	progress |= SKD_INTR_ADDED;

	ADAPTER_STATE_LOCK(skdev);
	skdev->flags |= SKD_ATTACHED;
	ADAPTER_STATE_UNLOCK(skdev);

	skdev->d_blkshift = 9;
	progress |= SKD_ATTACHED;


	skd_start_device(skdev);

	ADAPTER_STATE_LOCK(skdev);
	skdev->progress = progress;
	ADAPTER_STATE_UNLOCK(skdev);

	/*
	 * Give the board a chance to
	 * complete its initialization.
	 */
	if (skdev->gendisk_on != 1)
		(void) skd_wait_for_s1120(skdev);

	if (skdev->gendisk_on != 1) {
		cmn_err(CE_WARN, "!%s: s1120 failed to come ONLINE",
		    skdev->name);
		goto skd_attach_failed;
	}

	ddi_report_dev(dip);

	skd_send_internal_skspcl(skdev, &skdev->internal_skspcl, INQUIRY);

	skdev->disks_initialized++;

	(void) strcpy(fw_version, "???");
	(void) skd_pci_info(skdev, pci_str, sizeof (pci_str));
	Dcmn_err(CE_NOTE, " sTec S1120 Driver(%s) version %s-b%s",
	    DRV_NAME, DRV_VERSION, DRV_BUILD_ID);

	Dcmn_err(CE_NOTE, " sTec S1120 %04x:%04x %s 64 bit",
	    skdev->vendor_id, skdev->device_id, pci_str);

	Dcmn_err(CE_NOTE, " sTec S1120 %s\n", skdev->pathname);

	if (*skdev->inq_serial_num)
		Dcmn_err(CE_NOTE, " sTec S1120 serial#=%s",
		    skdev->inq_serial_num);

	if (*skdev->inq_product_id &&
	    *skdev->inq_product_rev)
		Dcmn_err(CE_NOTE, " sTec S1120 prod ID=%s prod rev=%s",
		    skdev->inq_product_id, skdev->inq_product_rev);

	Dcmn_err(CE_NOTE, "%s: intr-type-cap:        %d",
	    skdev->name, skdev->irq_type);
	Dcmn_err(CE_NOTE, "%s: max-scsi-reqs:        %d",
	    skdev->name, skd_max_queue_depth);
	Dcmn_err(CE_NOTE, "%s: max-sgs-per-req:      %d",
	    skdev->name, skd_sgs_per_request);
	Dcmn_err(CE_NOTE, "%s: max-scsi-req-per-msg: %d",
	    skdev->name, skd_max_req_per_msg);

	if (skd_bd_attach(dip, skdev) == DDI_FAILURE)
		goto skd_attach_failed;

	skd_update_props(skdev, dip);

	/* Enable timer */
	skd_start_timer(skdev);

	ADAPTER_STATE_LOCK(skdev);
	skdev->progress = progress;
	ADAPTER_STATE_UNLOCK(skdev);

	skdev->attached = 1;
	return (DDI_SUCCESS);

skd_attach_failed:
	skd_dealloc_resources(dip, skdev, progress, instance);

	if ((skdev->flags & SKD_MUTEX_DESTROYED) == 0) {
		skd_destroy_mutex(skdev);
	}

	ddi_soft_state_free(skd_state, instance);

	cmn_err(CE_WARN, "!skd_attach FAILED: progress=%x", progress);
	return (DDI_FAILURE);
}

/*
 *
 * Name:	skd_halt
 *
 * Inputs:	skdev		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_halt(skd_device_t *skdev)
{
	Dcmn_err(CE_NOTE, "%s: halt/suspend ......", skdev->name);
}

/*
 *
 * Name:	skd_detach, detaches driver from the system.
 *
 * Inputs:	dip		- device info structure.
 *
 * Returns:	DDI_SUCCESS on successful detach otherwise DDI_FAILURE.
 *
 */
static int
skd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	skd_buf_private_t *pbuf;
	skd_device_t   	*skdev;
	int		instance;
	timeout_id_t	timer_id = NULL;
	int		rv1 = DDI_SUCCESS;
	struct skd_special_context *skspcl;

	instance = ddi_get_instance(dip);

	skdev = ddi_get_soft_state(skd_state, instance);
	if (skdev == NULL) {
		cmn_err(CE_WARN, "!detach failed: NULL skd state");

		return (DDI_FAILURE);
	}

	Dcmn_err(CE_CONT, "skd_detach(%d): entered", instance);

	switch (cmd) {
	case DDI_DETACH:
		/* Test for packet cache inuse. */
		ADAPTER_STATE_LOCK(skdev);

		/* Stop command/event processing. */
		skdev->flags |= (SKD_SUSPENDED | SKD_CMD_ABORT_TMO);

		/* Disable driver timer if no adapters. */
		if (skdev->skd_timer_timeout_id != 0) {
			timer_id = skdev->skd_timer_timeout_id;
			skdev->skd_timer_timeout_id = 0;
		}
		ADAPTER_STATE_UNLOCK(skdev);

		if (timer_id != 0) {
			(void) untimeout(timer_id);
		}

#ifdef	SKD_PM
		if (skdev->power_level != LOW_POWER_LEVEL) {
			skd_halt(skdev);
			skdev->power_level = LOW_POWER_LEVEL;
		}
#endif
		skspcl = &skdev->internal_skspcl;
		skd_send_internal_skspcl(skdev, skspcl, SYNCHRONIZE_CACHE);

		skd_stop_device(skdev);

		/*
		 * Clear request queue.
		 */
		while (!SIMPLEQ_EMPTY(&skdev->waitqueue)) {
			pbuf = skd_get_queued_pbuf(skdev);
			skd_end_request_abnormal(skdev, pbuf, ECANCELED,
			    SKD_IODONE_WNIOC);
			Dcmn_err(CE_NOTE,
			    "detach: cancelled pbuf %p %ld <%s> %lld\n",
			    (void *)pbuf, pbuf->x_xfer->x_nblks,
			    (pbuf->dir & B_READ) ? "Read" : "Write",
			    pbuf->x_xfer->x_blkno);
		}

		skd_bd_detach(skdev);

		skd_dealloc_resources(dip, skdev, skdev->progress, instance);

		if ((skdev->flags & SKD_MUTEX_DESTROYED) == 0) {
			skd_destroy_mutex(skdev);
		}

		ddi_soft_state_free(skd_state, instance);

		skd_exit();

		break;

	case DDI_SUSPEND:
		/* Block timer. */

		ADAPTER_STATE_LOCK(skdev);
		skdev->flags |= SKD_SUSPENDED;

		/* Disable driver timer if last adapter. */
		if (skdev->skd_timer_timeout_id != 0) {
			timer_id = skdev->skd_timer_timeout_id;
			skdev->skd_timer_timeout_id = 0;
		}
		ADAPTER_STATE_UNLOCK(skdev);

		if (timer_id != 0) {
			(void) untimeout(timer_id);
		}

		ddi_prop_remove_all(dip);

		skd_halt(skdev);

		break;
	default:
		rv1 = DDI_FAILURE;
		break;
	}

	if (rv1 != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!skd_detach, failed, rv1=%x", rv1);
	} else {
		Dcmn_err(CE_CONT, "skd_detach: exiting");
	}

	if (rv1 != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (rv1);
}

/*
 *
 * Name:	skd_devid_init, calls skd_setup_devid to setup
 *		the device's devid structure.
 *
 * Inputs:	arg		- device state structure.
 *		dip		- dev_info structure.
 *		devid		- devid structure.
 *
 * Returns:	Nothing.
 *
 */
/* ARGSUSED */	/* Upstream common source with other platforms. */
static int
skd_devid_init(void *arg, dev_info_t *dip, ddi_devid_t *devid)
{
	skd_device_t	*skdev = arg;

	(void) skd_setup_devid(skdev, devid);

	return (0);
}

/*
 *
 * Name:	skd_bd_driveinfo, retrieves device's info.
 *
 * Inputs:	drive		- drive data structure.
 *		arg		- device state structure.
 *
 * Returns:	Nothing.
 *
 */
static void
skd_bd_driveinfo(void *arg, bd_drive_t *drive)
{
	skd_device_t	*skdev = arg;

	drive->d_qsize		= (skdev->queue_depth_limit * 4) / 5;
	drive->d_maxxfer	= SKD_DMA_MAXXFER;
	drive->d_removable	= B_FALSE;
	drive->d_hotpluggable	= B_FALSE;
	drive->d_target		= 0;
	drive->d_lun		= 0;

	if (skdev->inquiry_is_valid != 0) {
		drive->d_vendor = skdev->inq_vendor_id;
		drive->d_vendor_len = strlen(drive->d_vendor);

		drive->d_product = skdev->inq_product_id;
		drive->d_product_len = strlen(drive->d_product);

		drive->d_serial = skdev->inq_serial_num;
		drive->d_serial_len = strlen(drive->d_serial);

		drive->d_revision = skdev->inq_product_rev;
		drive->d_revision_len = strlen(drive->d_revision);
	}
}

/*
 *
 * Name:	skd_bd_mediainfo, retrieves device media info.
 *
 * Inputs:	arg		- device state structure.
 *		media		- container for media info.
 *
 * Returns:	Zero.
 *
 */
static int
skd_bd_mediainfo(void *arg, bd_media_t *media)
{
	skd_device_t	*skdev = arg;

	media->m_nblks    = skdev->Nblocks;
	media->m_blksize  = 512;
	media->m_pblksize = 4096;
	media->m_readonly = B_FALSE;
	media->m_solidstate = B_TRUE;

	return (0);
}

/*
 *
 * Name:	skd_rw, performs R/W requests for blkdev driver.
 *
 * Inputs:	skdev		- device state structure.
 *		xfer		- tranfer structure.
 *		dir		- I/O direction.
 *
 * Returns:	EAGAIN if device is not online.  EIO if blkdev wants us to
 *		be a dump device (for now).
 *		Value returned by skd_start().
 *
 */
static int
skd_rw(skd_device_t *skdev, bd_xfer_t *xfer, int dir)
{
	skd_buf_private_t 	*pbuf;

	/*
	 * The x_flags structure element is not defined in Oracle Solaris
	 */
	/* We'll need to fix this in order to support dump on this device. */
	if (xfer->x_flags & BD_XFER_POLL)
		return (EIO);

	if (skdev->state != SKD_DRVR_STATE_ONLINE) {
		Dcmn_err(CE_NOTE, "Device - not ONLINE");

		skd_request_fn_not_online(skdev);

		return (EAGAIN);
	}

	pbuf = kmem_zalloc(sizeof (skd_buf_private_t), KM_NOSLEEP);
	if (pbuf == NULL)
		return (ENOMEM);

	WAITQ_LOCK(skdev);
	pbuf->dir = dir;
	pbuf->x_xfer = xfer;

	skd_queue(skdev, pbuf);
	skdev->ios_queued++;
	WAITQ_UNLOCK(skdev);

	skd_start(skdev);

	return (0);
}

/*
 *
 * Name:	skd_bd_read, performs blkdev read requests.
 *
 * Inputs:	arg		- device state structure.
 *		xfer		- tranfer request structure.
 *
 * Returns:	Value return by skd_rw().
 *
 */
static int
skd_bd_read(void *arg, bd_xfer_t *xfer)
{
	return (skd_rw(arg, xfer, B_READ));
}

/*
 *
 * Name:	skd_bd_write, performs blkdev write requests.
 *
 * Inputs:	arg		- device state structure.
 *		xfer		- tranfer request structure.
 *
 * Returns:	Value return by skd_rw().
 *
 */
static int
skd_bd_write(void *arg, bd_xfer_t *xfer)
{
	return (skd_rw(arg, xfer, B_WRITE));
}
