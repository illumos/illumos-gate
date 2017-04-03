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
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 Tegile Systems, Inc. All rights reserved.
 * Copyright (c) 2016 The MathWorks, Inc.  All rights reserved.
 */

/*
 * blkdev driver for NVMe compliant storage devices
 *
 * This driver was written to conform to version 1.2.1 of the NVMe
 * specification.  It may work with newer versions, but that is completely
 * untested and disabled by default.
 *
 * The driver has only been tested on x86 systems and will not work on big-
 * endian systems without changes to the code accessing registers and data
 * structures used by the hardware.
 *
 *
 * Interrupt Usage:
 *
 * The driver will use a FIXED interrupt while configuring the device as the
 * specification requires. Later in the attach process it will switch to MSI-X
 * or MSI if supported. The driver wants to have one interrupt vector per CPU,
 * but it will work correctly if less are available. Interrupts can be shared
 * by queues, the interrupt handler will iterate through the I/O queue array by
 * steps of n_intr_cnt. Usually only the admin queue will share an interrupt
 * with one I/O queue. The interrupt handler will retrieve completed commands
 * from all queues sharing an interrupt vector and will post them to a taskq
 * for completion processing.
 *
 *
 * Command Processing:
 *
 * NVMe devices can have up to 65536 I/O queue pairs, with each queue holding up
 * to 65536 I/O commands. The driver will configure one I/O queue pair per
 * available interrupt vector, with the queue length usually much smaller than
 * the maximum of 65536. If the hardware doesn't provide enough queues, fewer
 * interrupt vectors will be used.
 *
 * Additionally the hardware provides a single special admin queue pair that can
 * hold up to 4096 admin commands.
 *
 * From the hardware perspective both queues of a queue pair are independent,
 * but they share some driver state: the command array (holding pointers to
 * commands currently being processed by the hardware) and the active command
 * counter. Access to the submission side of a queue pair and the shared state
 * is protected by nq_mutex. The completion side of a queue pair does not need
 * that protection apart from its access to the shared state; it is called only
 * in the interrupt handler which does not run concurrently for the same
 * interrupt vector.
 *
 * When a command is submitted to a queue pair the active command counter is
 * incremented and a pointer to the command is stored in the command array. The
 * array index is used as command identifier (CID) in the submission queue
 * entry. Some commands may take a very long time to complete, and if the queue
 * wraps around in that time a submission may find the next array slot to still
 * be used by a long-running command. In this case the array is sequentially
 * searched for the next free slot. The length of the command array is the same
 * as the configured queue length.
 *
 *
 * Namespace Support:
 *
 * NVMe devices can have multiple namespaces, each being a independent data
 * store. The driver supports multiple namespaces and creates a blkdev interface
 * for each namespace found. Namespaces can have various attributes to support
 * thin provisioning and protection information. This driver does not support
 * any of this and ignores namespaces that have these attributes.
 *
 * As of NVMe 1.1 namespaces can have an 64bit Extended Unique Identifier
 * (EUI64). This driver uses the EUI64 if present to generate the devid and
 * passes it to blkdev to use it in the device node names. As this is currently
 * untested namespaces with EUI64 are ignored by default.
 *
 *
 * Blkdev Interface:
 *
 * This driver uses blkdev to do all the heavy lifting involved with presenting
 * a disk device to the system. As a result, the processing of I/O requests is
 * relatively simple as blkdev takes care of partitioning, boundary checks, DMA
 * setup, and splitting of transfers into manageable chunks.
 *
 * I/O requests coming in from blkdev are turned into NVM commands and posted to
 * an I/O queue. The queue is selected by taking the CPU id modulo the number of
 * queues. There is currently no timeout handling of I/O commands.
 *
 * Blkdev also supports querying device/media information and generating a
 * devid. The driver reports the best block size as determined by the namespace
 * format back to blkdev as physical block size to support partition and block
 * alignment. The devid is either based on the namespace EUI64, if present, or
 * composed using the device vendor ID, model number, serial number, and the
 * namespace ID.
 *
 *
 * Error Handling:
 *
 * Error handling is currently limited to detecting fatal hardware errors,
 * either by asynchronous events, or synchronously through command status or
 * admin command timeouts. In case of severe errors the device is fenced off,
 * all further requests will return EIO. FMA is then called to fault the device.
 *
 * The hardware has a limit for outstanding asynchronous event requests. Before
 * this limit is known the driver assumes it is at least 1 and posts a single
 * asynchronous request. Later when the limit is known more asynchronous event
 * requests are posted to allow quicker reception of error information. When an
 * asynchronous event is posted by the hardware the driver will parse the error
 * status fields and log information or fault the device, depending on the
 * severity of the asynchronous event. The asynchronous event request is then
 * reused and posted to the admin queue again.
 *
 * On command completion the command status is checked for errors. In case of
 * errors indicating a driver bug the driver panics. Almost all other error
 * status values just cause EIO to be returned.
 *
 * Command timeouts are currently detected for all admin commands except
 * asynchronous event requests. If a command times out and the hardware appears
 * to be healthy the driver attempts to abort the command. If this fails the
 * driver assumes the device to be dead, fences it off, and calls FMA to retire
 * it. In general admin commands are issued at attach time only. No timeout
 * handling of normal I/O commands is presently done.
 *
 * In some cases it may be possible that the ABORT command times out, too. In
 * that case the device is also declared dead and fenced off.
 *
 *
 * Quiesce / Fast Reboot:
 *
 * The driver currently does not support fast reboot. A quiesce(9E) entry point
 * is still provided which is used to send a shutdown notification to the
 * device.
 *
 *
 * Driver Configuration:
 *
 * The following driver properties can be changed to control some aspects of the
 * drivers operation:
 * - strict-version: can be set to 0 to allow devices conforming to newer
 *   versions or namespaces with EUI64 to be used
 * - ignore-unknown-vendor-status: can be set to 1 to not handle any vendor
 *   specific command status as a fatal error leading device faulting
 * - admin-queue-len: the maximum length of the admin queue (16-4096)
 * - io-queue-len: the maximum length of the I/O queues (16-65536)
 * - async-event-limit: the maximum number of asynchronous event requests to be
 *   posted by the driver
 * - volatile-write-cache-enable: can be set to 0 to disable the volatile write
 *   cache
 * - min-phys-block-size: the minimum physical block size to report to blkdev,
 *   which is among other things the basis for ZFS vdev ashift
 *
 *
 * TODO:
 * - figure out sane default for I/O queue depth reported to blkdev
 * - polled I/O support to support kernel core dumping
 * - FMA handling of media errors
 * - support for devices supporting very large I/O requests using chained PRPs
 * - support for querying log pages from user space
 * - support for configuring hardware parameters like interrupt coalescing
 * - support for media formatting and hard partitioning into namespaces
 * - support for big-endian systems
 * - support for fast reboot
 * - support for firmware updates
 * - support for NVMe Subsystem Reset (1.1)
 * - support for Scatter/Gather lists (1.1)
 * - support for Reservations (1.1)
 * - support for power management
 */

#include <sys/byteorder.h>
#ifdef _BIG_ENDIAN
#error nvme driver needs porting for big-endian platforms
#endif

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/blkdev.h>
#include <sys/atomic.h>
#include <sys/archsystm.h>
#include <sys/sata/sata_hba.h>

#ifdef __x86
#include <sys/x86_archext.h>
#endif

#include "nvme_reg.h"
#include "nvme_var.h"


/* NVMe spec version supported */
static const int nvme_version_major = 1;
static const int nvme_version_minor = 2;

/* tunable for admin command timeout in seconds, default is 1s */
static volatile int nvme_admin_cmd_timeout = 1;

static int nvme_attach(dev_info_t *, ddi_attach_cmd_t);
static int nvme_detach(dev_info_t *, ddi_detach_cmd_t);
static int nvme_quiesce(dev_info_t *);
static int nvme_fm_errcb(dev_info_t *, ddi_fm_error_t *, const void *);
static int nvme_setup_interrupts(nvme_t *, int, int);
static void nvme_release_interrupts(nvme_t *);
static uint_t nvme_intr(caddr_t, caddr_t);

static void nvme_shutdown(nvme_t *, int, boolean_t);
static boolean_t nvme_reset(nvme_t *, boolean_t);
static int nvme_init(nvme_t *);
static nvme_cmd_t *nvme_alloc_cmd(nvme_t *, int);
static void nvme_free_cmd(nvme_cmd_t *);
static nvme_cmd_t *nvme_create_nvm_cmd(nvme_namespace_t *, uint8_t,
    bd_xfer_t *);
static int nvme_admin_cmd(nvme_cmd_t *, int);
static int nvme_submit_cmd(nvme_qpair_t *, nvme_cmd_t *);
static nvme_cmd_t *nvme_retrieve_cmd(nvme_t *, nvme_qpair_t *);
static boolean_t nvme_wait_cmd(nvme_cmd_t *, uint_t);
static void nvme_wakeup_cmd(void *);
static void nvme_async_event_task(void *);

static int nvme_check_unknown_cmd_status(nvme_cmd_t *);
static int nvme_check_vendor_cmd_status(nvme_cmd_t *);
static int nvme_check_integrity_cmd_status(nvme_cmd_t *);
static int nvme_check_specific_cmd_status(nvme_cmd_t *);
static int nvme_check_generic_cmd_status(nvme_cmd_t *);
static inline int nvme_check_cmd_status(nvme_cmd_t *);

static void nvme_abort_cmd(nvme_cmd_t *);
static int nvme_async_event(nvme_t *);
static void *nvme_get_logpage(nvme_t *, uint8_t, ...);
static void *nvme_identify(nvme_t *, uint32_t);
static boolean_t nvme_set_features(nvme_t *, uint32_t, uint8_t, uint32_t,
    uint32_t *);
static boolean_t nvme_write_cache_set(nvme_t *, boolean_t);
static int nvme_set_nqueues(nvme_t *, uint16_t);

static void nvme_free_dma(nvme_dma_t *);
static int nvme_zalloc_dma(nvme_t *, size_t, uint_t, ddi_dma_attr_t *,
    nvme_dma_t **);
static int nvme_zalloc_queue_dma(nvme_t *, uint32_t, uint16_t, uint_t,
    nvme_dma_t **);
static void nvme_free_qpair(nvme_qpair_t *);
static int nvme_alloc_qpair(nvme_t *, uint32_t, nvme_qpair_t **, int);
static int nvme_create_io_qpair(nvme_t *, nvme_qpair_t *, uint16_t);

static inline void nvme_put64(nvme_t *, uintptr_t, uint64_t);
static inline void nvme_put32(nvme_t *, uintptr_t, uint32_t);
static inline uint64_t nvme_get64(nvme_t *, uintptr_t);
static inline uint32_t nvme_get32(nvme_t *, uintptr_t);

static boolean_t nvme_check_regs_hdl(nvme_t *);
static boolean_t nvme_check_dma_hdl(nvme_dma_t *);

static int nvme_fill_prp(nvme_cmd_t *, bd_xfer_t *);

static void nvme_bd_xfer_done(void *);
static void nvme_bd_driveinfo(void *, bd_drive_t *);
static int nvme_bd_mediainfo(void *, bd_media_t *);
static int nvme_bd_cmd(nvme_namespace_t *, bd_xfer_t *, uint8_t);
static int nvme_bd_read(void *, bd_xfer_t *);
static int nvme_bd_write(void *, bd_xfer_t *);
static int nvme_bd_sync(void *, bd_xfer_t *);
static int nvme_bd_devid(void *, dev_info_t *, ddi_devid_t *);

static int nvme_prp_dma_constructor(void *, void *, int);
static void nvme_prp_dma_destructor(void *, void *);

static void nvme_prepare_devid(nvme_t *, uint32_t);

static void *nvme_state;
static kmem_cache_t *nvme_cmd_cache;

/*
 * DMA attributes for queue DMA memory
 *
 * Queue DMA memory must be page aligned. The maximum length of a queue is
 * 65536 entries, and an entry can be 64 bytes long.
 */
static ddi_dma_attr_t nvme_queue_dma_attr = {
	.dma_attr_version	= DMA_ATTR_V0,
	.dma_attr_addr_lo	= 0,
	.dma_attr_addr_hi	= 0xffffffffffffffffULL,
	.dma_attr_count_max	= (UINT16_MAX + 1) * sizeof (nvme_sqe_t) - 1,
	.dma_attr_align		= 0x1000,
	.dma_attr_burstsizes	= 0x7ff,
	.dma_attr_minxfer	= 0x1000,
	.dma_attr_maxxfer	= (UINT16_MAX + 1) * sizeof (nvme_sqe_t),
	.dma_attr_seg		= 0xffffffffffffffffULL,
	.dma_attr_sgllen	= 1,
	.dma_attr_granular	= 1,
	.dma_attr_flags		= 0,
};

/*
 * DMA attributes for transfers using Physical Region Page (PRP) entries
 *
 * A PRP entry describes one page of DMA memory using the page size specified
 * in the controller configuration's memory page size register (CC.MPS). It uses
 * a 64bit base address aligned to this page size. There is no limitation on
 * chaining PRPs together for arbitrarily large DMA transfers.
 */
static ddi_dma_attr_t nvme_prp_dma_attr = {
	.dma_attr_version	= DMA_ATTR_V0,
	.dma_attr_addr_lo	= 0,
	.dma_attr_addr_hi	= 0xffffffffffffffffULL,
	.dma_attr_count_max	= 0xfff,
	.dma_attr_align		= 0x1000,
	.dma_attr_burstsizes	= 0x7ff,
	.dma_attr_minxfer	= 0x1000,
	.dma_attr_maxxfer	= 0x1000,
	.dma_attr_seg		= 0xfff,
	.dma_attr_sgllen	= -1,
	.dma_attr_granular	= 1,
	.dma_attr_flags		= 0,
};

/*
 * DMA attributes for transfers using scatter/gather lists
 *
 * A SGL entry describes a chunk of DMA memory using a 64bit base address and a
 * 32bit length field. SGL Segment and SGL Last Segment entries require the
 * length to be a multiple of 16 bytes.
 */
static ddi_dma_attr_t nvme_sgl_dma_attr = {
	.dma_attr_version	= DMA_ATTR_V0,
	.dma_attr_addr_lo	= 0,
	.dma_attr_addr_hi	= 0xffffffffffffffffULL,
	.dma_attr_count_max	= 0xffffffffUL,
	.dma_attr_align		= 1,
	.dma_attr_burstsizes	= 0x7ff,
	.dma_attr_minxfer	= 0x10,
	.dma_attr_maxxfer	= 0xfffffffffULL,
	.dma_attr_seg		= 0xffffffffffffffffULL,
	.dma_attr_sgllen	= -1,
	.dma_attr_granular	= 0x10,
	.dma_attr_flags		= 0
};

static ddi_device_acc_attr_t nvme_reg_acc_attr = {
	.devacc_attr_version	= DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder	= DDI_STRICTORDER_ACC
};

static struct dev_ops nvme_dev_ops = {
	.devo_rev	= DEVO_REV,
	.devo_refcnt	= 0,
	.devo_getinfo	= ddi_no_info,
	.devo_identify	= nulldev,
	.devo_probe	= nulldev,
	.devo_attach	= nvme_attach,
	.devo_detach	= nvme_detach,
	.devo_reset	= nodev,
	.devo_cb_ops	= NULL,
	.devo_bus_ops	= NULL,
	.devo_power	= NULL,
	.devo_quiesce	= nvme_quiesce,
};

static struct modldrv nvme_modldrv = {
	.drv_modops	= &mod_driverops,
	.drv_linkinfo	= "NVMe v1.1b",
	.drv_dev_ops	= &nvme_dev_ops
};

static struct modlinkage nvme_modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= { &nvme_modldrv, NULL }
};

static bd_ops_t nvme_bd_ops = {
	.o_version	= BD_OPS_VERSION_0,
	.o_drive_info	= nvme_bd_driveinfo,
	.o_media_info	= nvme_bd_mediainfo,
	.o_devid_init	= nvme_bd_devid,
	.o_sync_cache	= nvme_bd_sync,
	.o_read		= nvme_bd_read,
	.o_write	= nvme_bd_write,
};

int
_init(void)
{
	int error;

	error = ddi_soft_state_init(&nvme_state, sizeof (nvme_t), 1);
	if (error != DDI_SUCCESS)
		return (error);

	nvme_cmd_cache = kmem_cache_create("nvme_cmd_cache",
	    sizeof (nvme_cmd_t), 64, NULL, NULL, NULL, NULL, NULL, 0);

	bd_mod_init(&nvme_dev_ops);

	error = mod_install(&nvme_modlinkage);
	if (error != DDI_SUCCESS) {
		ddi_soft_state_fini(&nvme_state);
		bd_mod_fini(&nvme_dev_ops);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&nvme_modlinkage);
	if (error == DDI_SUCCESS) {
		ddi_soft_state_fini(&nvme_state);
		kmem_cache_destroy(nvme_cmd_cache);
		bd_mod_fini(&nvme_dev_ops);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&nvme_modlinkage, modinfop));
}

static inline void
nvme_put64(nvme_t *nvme, uintptr_t reg, uint64_t val)
{
	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x7) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	ddi_put64(nvme->n_regh, (uint64_t *)(nvme->n_regs + reg), val);
}

static inline void
nvme_put32(nvme_t *nvme, uintptr_t reg, uint32_t val)
{
	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x3) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	ddi_put32(nvme->n_regh, (uint32_t *)(nvme->n_regs + reg), val);
}

static inline uint64_t
nvme_get64(nvme_t *nvme, uintptr_t reg)
{
	uint64_t val;

	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x7) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	val = ddi_get64(nvme->n_regh, (uint64_t *)(nvme->n_regs + reg));

	return (val);
}

static inline uint32_t
nvme_get32(nvme_t *nvme, uintptr_t reg)
{
	uint32_t val;

	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x3) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	val = ddi_get32(nvme->n_regh, (uint32_t *)(nvme->n_regs + reg));

	return (val);
}

static boolean_t
nvme_check_regs_hdl(nvme_t *nvme)
{
	ddi_fm_error_t error;

	ddi_fm_acc_err_get(nvme->n_regh, &error, DDI_FME_VERSION);

	if (error.fme_status != DDI_FM_OK)
		return (B_TRUE);

	return (B_FALSE);
}

static boolean_t
nvme_check_dma_hdl(nvme_dma_t *dma)
{
	ddi_fm_error_t error;

	if (dma == NULL)
		return (B_FALSE);

	ddi_fm_dma_err_get(dma->nd_dmah, &error, DDI_FME_VERSION);

	if (error.fme_status != DDI_FM_OK)
		return (B_TRUE);

	return (B_FALSE);
}

static void
nvme_free_dma_common(nvme_dma_t *dma)
{
	if (dma->nd_dmah != NULL)
		(void) ddi_dma_unbind_handle(dma->nd_dmah);
	if (dma->nd_acch != NULL)
		ddi_dma_mem_free(&dma->nd_acch);
	if (dma->nd_dmah != NULL)
		ddi_dma_free_handle(&dma->nd_dmah);
}

static void
nvme_free_dma(nvme_dma_t *dma)
{
	nvme_free_dma_common(dma);
	kmem_free(dma, sizeof (*dma));
}

/* ARGSUSED */
static void
nvme_prp_dma_destructor(void *buf, void *private)
{
	nvme_dma_t *dma = (nvme_dma_t *)buf;

	nvme_free_dma_common(dma);
}

static int
nvme_alloc_dma_common(nvme_t *nvme, nvme_dma_t *dma,
    size_t len, uint_t flags, ddi_dma_attr_t *dma_attr)
{
	if (ddi_dma_alloc_handle(nvme->n_dip, dma_attr, DDI_DMA_SLEEP, NULL,
	    &dma->nd_dmah) != DDI_SUCCESS) {
		/*
		 * Due to DDI_DMA_SLEEP this can't be DDI_DMA_NORESOURCES, and
		 * the only other possible error is DDI_DMA_BADATTR which
		 * indicates a driver bug which should cause a panic.
		 */
		dev_err(nvme->n_dip, CE_PANIC,
		    "!failed to get DMA handle, check DMA attributes");
		return (DDI_FAILURE);
	}

	/*
	 * ddi_dma_mem_alloc() can only fail when DDI_DMA_NOSLEEP is specified
	 * or the flags are conflicting, which isn't the case here.
	 */
	(void) ddi_dma_mem_alloc(dma->nd_dmah, len, &nvme->n_reg_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &dma->nd_memp,
	    &dma->nd_len, &dma->nd_acch);

	if (ddi_dma_addr_bind_handle(dma->nd_dmah, NULL, dma->nd_memp,
	    dma->nd_len, flags | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dma->nd_cookie, &dma->nd_ncookie) != DDI_DMA_MAPPED) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to bind DMA memory");
		atomic_inc_32(&nvme->n_dma_bind_err);
		nvme_free_dma_common(dma);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
nvme_zalloc_dma(nvme_t *nvme, size_t len, uint_t flags,
    ddi_dma_attr_t *dma_attr, nvme_dma_t **ret)
{
	nvme_dma_t *dma = kmem_zalloc(sizeof (nvme_dma_t), KM_SLEEP);

	if (nvme_alloc_dma_common(nvme, dma, len, flags, dma_attr) !=
	    DDI_SUCCESS) {
		*ret = NULL;
		kmem_free(dma, sizeof (nvme_dma_t));
		return (DDI_FAILURE);
	}

	bzero(dma->nd_memp, dma->nd_len);

	*ret = dma;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
nvme_prp_dma_constructor(void *buf, void *private, int flags)
{
	nvme_dma_t *dma = (nvme_dma_t *)buf;
	nvme_t *nvme = (nvme_t *)private;

	dma->nd_dmah = NULL;
	dma->nd_acch = NULL;

	if (nvme_alloc_dma_common(nvme, dma, nvme->n_pagesize,
	    DDI_DMA_READ, &nvme->n_prp_dma_attr) != DDI_SUCCESS) {
		return (-1);
	}

	ASSERT(dma->nd_ncookie == 1);

	dma->nd_cached = B_TRUE;

	return (0);
}

static int
nvme_zalloc_queue_dma(nvme_t *nvme, uint32_t nentry, uint16_t qe_len,
    uint_t flags, nvme_dma_t **dma)
{
	uint32_t len = nentry * qe_len;
	ddi_dma_attr_t q_dma_attr = nvme->n_queue_dma_attr;

	len = roundup(len, nvme->n_pagesize);

	q_dma_attr.dma_attr_minxfer = len;

	if (nvme_zalloc_dma(nvme, len, flags, &q_dma_attr, dma)
	    != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to get DMA memory for queue");
		goto fail;
	}

	if ((*dma)->nd_ncookie != 1) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!got too many cookies for queue DMA");
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	if (*dma) {
		nvme_free_dma(*dma);
		*dma = NULL;
	}

	return (DDI_FAILURE);
}

static void
nvme_free_qpair(nvme_qpair_t *qp)
{
	int i;

	mutex_destroy(&qp->nq_mutex);

	if (qp->nq_sqdma != NULL)
		nvme_free_dma(qp->nq_sqdma);
	if (qp->nq_cqdma != NULL)
		nvme_free_dma(qp->nq_cqdma);

	if (qp->nq_active_cmds > 0)
		for (i = 0; i != qp->nq_nentry; i++)
			if (qp->nq_cmd[i] != NULL)
				nvme_free_cmd(qp->nq_cmd[i]);

	if (qp->nq_cmd != NULL)
		kmem_free(qp->nq_cmd, sizeof (nvme_cmd_t *) * qp->nq_nentry);

	kmem_free(qp, sizeof (nvme_qpair_t));
}

static int
nvme_alloc_qpair(nvme_t *nvme, uint32_t nentry, nvme_qpair_t **nqp,
    int idx)
{
	nvme_qpair_t *qp = kmem_zalloc(sizeof (*qp), KM_SLEEP);

	mutex_init(&qp->nq_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(nvme->n_intr_pri));

	if (nvme_zalloc_queue_dma(nvme, nentry, sizeof (nvme_sqe_t),
	    DDI_DMA_WRITE, &qp->nq_sqdma) != DDI_SUCCESS)
		goto fail;

	if (nvme_zalloc_queue_dma(nvme, nentry, sizeof (nvme_cqe_t),
	    DDI_DMA_READ, &qp->nq_cqdma) != DDI_SUCCESS)
		goto fail;

	qp->nq_sq = (nvme_sqe_t *)qp->nq_sqdma->nd_memp;
	qp->nq_cq = (nvme_cqe_t *)qp->nq_cqdma->nd_memp;
	qp->nq_nentry = nentry;

	qp->nq_sqtdbl = NVME_REG_SQTDBL(nvme, idx);
	qp->nq_cqhdbl = NVME_REG_CQHDBL(nvme, idx);

	qp->nq_cmd = kmem_zalloc(sizeof (nvme_cmd_t *) * nentry, KM_SLEEP);
	qp->nq_next_cmd = 0;

	*nqp = qp;
	return (DDI_SUCCESS);

fail:
	nvme_free_qpair(qp);
	*nqp = NULL;

	return (DDI_FAILURE);
}

static nvme_cmd_t *
nvme_alloc_cmd(nvme_t *nvme, int kmflag)
{
	nvme_cmd_t *cmd = kmem_cache_alloc(nvme_cmd_cache, kmflag);

	if (cmd == NULL)
		return (cmd);

	bzero(cmd, sizeof (nvme_cmd_t));

	cmd->nc_nvme = nvme;

	mutex_init(&cmd->nc_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(nvme->n_intr_pri));
	cv_init(&cmd->nc_cv, NULL, CV_DRIVER, NULL);

	return (cmd);
}

static void
nvme_free_cmd(nvme_cmd_t *cmd)
{
	if (cmd->nc_dma) {
		if (cmd->nc_dma->nd_cached)
			kmem_cache_free(cmd->nc_nvme->n_prp_cache,
			    cmd->nc_dma);
		else
			nvme_free_dma(cmd->nc_dma);
		cmd->nc_dma = NULL;
	}

	cv_destroy(&cmd->nc_cv);
	mutex_destroy(&cmd->nc_mutex);

	kmem_cache_free(nvme_cmd_cache, cmd);
}

static int
nvme_submit_cmd(nvme_qpair_t *qp, nvme_cmd_t *cmd)
{
	nvme_reg_sqtdbl_t tail = { 0 };

	mutex_enter(&qp->nq_mutex);

	if (qp->nq_active_cmds == qp->nq_nentry) {
		mutex_exit(&qp->nq_mutex);
		return (DDI_FAILURE);
	}

	cmd->nc_completed = B_FALSE;

	/*
	 * Try to insert the cmd into the active cmd array at the nq_next_cmd
	 * slot. If the slot is already occupied advance to the next slot and
	 * try again. This can happen for long running commands like async event
	 * requests.
	 */
	while (qp->nq_cmd[qp->nq_next_cmd] != NULL)
		qp->nq_next_cmd = (qp->nq_next_cmd + 1) % qp->nq_nentry;
	qp->nq_cmd[qp->nq_next_cmd] = cmd;

	qp->nq_active_cmds++;

	cmd->nc_sqe.sqe_cid = qp->nq_next_cmd;
	bcopy(&cmd->nc_sqe, &qp->nq_sq[qp->nq_sqtail], sizeof (nvme_sqe_t));
	(void) ddi_dma_sync(qp->nq_sqdma->nd_dmah,
	    sizeof (nvme_sqe_t) * qp->nq_sqtail,
	    sizeof (nvme_sqe_t), DDI_DMA_SYNC_FORDEV);
	qp->nq_next_cmd = (qp->nq_next_cmd + 1) % qp->nq_nentry;

	tail.b.sqtdbl_sqt = qp->nq_sqtail = (qp->nq_sqtail + 1) % qp->nq_nentry;
	nvme_put32(cmd->nc_nvme, qp->nq_sqtdbl, tail.r);

	mutex_exit(&qp->nq_mutex);
	return (DDI_SUCCESS);
}

static nvme_cmd_t *
nvme_retrieve_cmd(nvme_t *nvme, nvme_qpair_t *qp)
{
	nvme_reg_cqhdbl_t head = { 0 };

	nvme_cqe_t *cqe;
	nvme_cmd_t *cmd;

	(void) ddi_dma_sync(qp->nq_cqdma->nd_dmah, 0,
	    sizeof (nvme_cqe_t) * qp->nq_nentry, DDI_DMA_SYNC_FORKERNEL);

	cqe = &qp->nq_cq[qp->nq_cqhead];

	/* Check phase tag of CQE. Hardware inverts it for new entries. */
	if (cqe->cqe_sf.sf_p == qp->nq_phase)
		return (NULL);

	ASSERT(nvme->n_ioq[cqe->cqe_sqid] == qp);
	ASSERT(cqe->cqe_cid < qp->nq_nentry);

	mutex_enter(&qp->nq_mutex);
	cmd = qp->nq_cmd[cqe->cqe_cid];
	qp->nq_cmd[cqe->cqe_cid] = NULL;
	qp->nq_active_cmds--;
	mutex_exit(&qp->nq_mutex);

	ASSERT(cmd != NULL);
	ASSERT(cmd->nc_nvme == nvme);
	ASSERT(cmd->nc_sqid == cqe->cqe_sqid);
	ASSERT(cmd->nc_sqe.sqe_cid == cqe->cqe_cid);
	bcopy(cqe, &cmd->nc_cqe, sizeof (nvme_cqe_t));

	qp->nq_sqhead = cqe->cqe_sqhd;

	head.b.cqhdbl_cqh = qp->nq_cqhead = (qp->nq_cqhead + 1) % qp->nq_nentry;

	/* Toggle phase on wrap-around. */
	if (qp->nq_cqhead == 0)
		qp->nq_phase = qp->nq_phase ? 0 : 1;

	nvme_put32(cmd->nc_nvme, qp->nq_cqhdbl, head.r);

	return (cmd);
}

static int
nvme_check_unknown_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	dev_err(cmd->nc_nvme->n_dip, CE_WARN,
	    "!unknown command status received: opc = %x, sqid = %d, cid = %d, "
	    "sc = %x, sct = %x, dnr = %d, m = %d", cmd->nc_sqe.sqe_opc,
	    cqe->cqe_sqid, cqe->cqe_cid, cqe->cqe_sf.sf_sc, cqe->cqe_sf.sf_sct,
	    cqe->cqe_sf.sf_dnr, cqe->cqe_sf.sf_m);

	bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);

	if (cmd->nc_nvme->n_strict_version) {
		cmd->nc_nvme->n_dead = B_TRUE;
		ddi_fm_service_impact(cmd->nc_nvme->n_dip, DDI_SERVICE_LOST);
	}

	return (EIO);
}

static int
nvme_check_vendor_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	dev_err(cmd->nc_nvme->n_dip, CE_WARN,
	    "!unknown command status received: opc = %x, sqid = %d, cid = %d, "
	    "sc = %x, sct = %x, dnr = %d, m = %d", cmd->nc_sqe.sqe_opc,
	    cqe->cqe_sqid, cqe->cqe_cid, cqe->cqe_sf.sf_sc, cqe->cqe_sf.sf_sct,
	    cqe->cqe_sf.sf_dnr, cqe->cqe_sf.sf_m);
	if (!cmd->nc_nvme->n_ignore_unknown_vendor_status) {
		cmd->nc_nvme->n_dead = B_TRUE;
		ddi_fm_service_impact(cmd->nc_nvme->n_dip, DDI_SERVICE_LOST);
	}

	return (EIO);
}

static int
nvme_check_integrity_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	switch (cqe->cqe_sf.sf_sc) {
	case NVME_CQE_SC_INT_NVM_WRITE:
		/* write fail */
		/* TODO: post ereport */
		bd_error(cmd->nc_xfer, BD_ERR_MEDIA);
		return (EIO);

	case NVME_CQE_SC_INT_NVM_READ:
		/* read fail */
		/* TODO: post ereport */
		bd_error(cmd->nc_xfer, BD_ERR_MEDIA);
		return (EIO);

	default:
		return (nvme_check_unknown_cmd_status(cmd));
	}
}

static int
nvme_check_generic_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	switch (cqe->cqe_sf.sf_sc) {
	case NVME_CQE_SC_GEN_SUCCESS:
		return (0);

	/*
	 * Errors indicating a bug in the driver should cause a panic.
	 */
	case NVME_CQE_SC_GEN_INV_OPC:
		/* Invalid Command Opcode */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "invalid opcode in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_GEN_INV_FLD:
		/* Invalid Field in Command */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "invalid field in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_GEN_ID_CNFL:
		/* Command ID Conflict */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "cmd ID conflict in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_GEN_INV_NS:
		/* Invalid Namespace or Format */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "invalid NS/format in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_GEN_NVM_LBA_RANGE:
		/* LBA Out Of Range */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "LBA out of range in cmd %p", (void *)cmd);
		return (0);

	/*
	 * Non-fatal errors, handle gracefully.
	 */
	case NVME_CQE_SC_GEN_DATA_XFR_ERR:
		/* Data Transfer Error (DMA) */
		/* TODO: post ereport */
		atomic_inc_32(&cmd->nc_nvme->n_data_xfr_err);
		bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	case NVME_CQE_SC_GEN_INTERNAL_ERR:
		/*
		 * Internal Error. The spec (v1.0, section 4.5.1.2) says
		 * detailed error information is returned as async event,
		 * so we pretty much ignore the error here and handle it
		 * in the async event handler.
		 */
		atomic_inc_32(&cmd->nc_nvme->n_internal_err);
		bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	case NVME_CQE_SC_GEN_ABORT_REQUEST:
		/*
		 * Command Abort Requested. This normally happens only when a
		 * command times out.
		 */
		/* TODO: post ereport or change blkdev to handle this? */
		atomic_inc_32(&cmd->nc_nvme->n_abort_rq_err);
		return (ECANCELED);

	case NVME_CQE_SC_GEN_ABORT_PWRLOSS:
		/* Command Aborted due to Power Loss Notification */
		ddi_fm_service_impact(cmd->nc_nvme->n_dip, DDI_SERVICE_LOST);
		cmd->nc_nvme->n_dead = B_TRUE;
		return (EIO);

	case NVME_CQE_SC_GEN_ABORT_SQ_DEL:
		/* Command Aborted due to SQ Deletion */
		atomic_inc_32(&cmd->nc_nvme->n_abort_sq_del);
		return (EIO);

	case NVME_CQE_SC_GEN_NVM_CAP_EXC:
		/* Capacity Exceeded */
		atomic_inc_32(&cmd->nc_nvme->n_nvm_cap_exc);
		bd_error(cmd->nc_xfer, BD_ERR_MEDIA);
		return (EIO);

	case NVME_CQE_SC_GEN_NVM_NS_NOTRDY:
		/* Namespace Not Ready */
		atomic_inc_32(&cmd->nc_nvme->n_nvm_ns_notrdy);
		bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	default:
		return (nvme_check_unknown_cmd_status(cmd));
	}
}

static int
nvme_check_specific_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	switch (cqe->cqe_sf.sf_sc) {
	case NVME_CQE_SC_SPC_INV_CQ:
		/* Completion Queue Invalid */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_SQUEUE);
		atomic_inc_32(&cmd->nc_nvme->n_inv_cq_err);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_QID:
		/* Invalid Queue Identifier */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_SQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_DELETE_SQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_CQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_DELETE_CQUEUE);
		atomic_inc_32(&cmd->nc_nvme->n_inv_qid_err);
		return (EINVAL);

	case NVME_CQE_SC_SPC_MAX_QSZ_EXC:
		/* Max Queue Size Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_SQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_CQUEUE);
		atomic_inc_32(&cmd->nc_nvme->n_max_qsz_exc);
		return (EINVAL);

	case NVME_CQE_SC_SPC_ABRT_CMD_EXC:
		/* Abort Command Limit Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_ABORT);
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "abort command limit exceeded in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_SPC_ASYNC_EVREQ_EXC:
		/* Async Event Request Limit Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_ASYNC_EVENT);
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "async event request limit exceeded in cmd %p",
		    (void *)cmd);
		return (0);

	case NVME_CQE_SC_SPC_INV_INT_VECT:
		/* Invalid Interrupt Vector */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_CQUEUE);
		atomic_inc_32(&cmd->nc_nvme->n_inv_int_vect);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_LOG_PAGE:
		/* Invalid Log Page */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_GET_LOG_PAGE);
		atomic_inc_32(&cmd->nc_nvme->n_inv_log_page);
		bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_FORMAT:
		/* Invalid Format */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_FORMAT);
		atomic_inc_32(&cmd->nc_nvme->n_inv_format);
		bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_Q_DEL:
		/* Invalid Queue Deletion */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_DELETE_CQUEUE);
		atomic_inc_32(&cmd->nc_nvme->n_inv_q_del);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NVM_CNFL_ATTR:
		/* Conflicting Attributes */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_DSET_MGMT ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_READ ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_WRITE);
		atomic_inc_32(&cmd->nc_nvme->n_cnfl_attr);
		bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NVM_INV_PROT:
		/* Invalid Protection Information */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_COMPARE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_READ ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_WRITE);
		atomic_inc_32(&cmd->nc_nvme->n_inv_prot);
		bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NVM_READONLY:
		/* Write to Read Only Range */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_WRITE);
		atomic_inc_32(&cmd->nc_nvme->n_readonly);
		bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EROFS);

	default:
		return (nvme_check_unknown_cmd_status(cmd));
	}
}

static inline int
nvme_check_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	/* take a shortcut if everything is alright */
	if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC &&
	    cqe->cqe_sf.sf_sc == NVME_CQE_SC_GEN_SUCCESS)
		return (0);

	if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC)
		return (nvme_check_generic_cmd_status(cmd));
	else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_SPECIFIC)
		return (nvme_check_specific_cmd_status(cmd));
	else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_INTEGRITY)
		return (nvme_check_integrity_cmd_status(cmd));
	else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_VENDOR)
		return (nvme_check_vendor_cmd_status(cmd));

	return (nvme_check_unknown_cmd_status(cmd));
}

/*
 * nvme_abort_cmd_cb -- replaces nc_callback of aborted commands
 *
 * This functions takes care of cleaning up aborted commands. The command
 * status is checked to catch any fatal errors.
 */
static void
nvme_abort_cmd_cb(void *arg)
{
	nvme_cmd_t *cmd = arg;

	/*
	 * Grab the command mutex. Once we have it we hold the last reference
	 * to the command and can safely free it.
	 */
	mutex_enter(&cmd->nc_mutex);
	(void) nvme_check_cmd_status(cmd);
	mutex_exit(&cmd->nc_mutex);

	nvme_free_cmd(cmd);
}

static void
nvme_abort_cmd(nvme_cmd_t *abort_cmd)
{
	nvme_t *nvme = abort_cmd->nc_nvme;
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	nvme_abort_cmd_t ac = { 0 };

	sema_p(&nvme->n_abort_sema);

	ac.b.ac_cid = abort_cmd->nc_sqe.sqe_cid;
	ac.b.ac_sqid = abort_cmd->nc_sqid;

	/*
	 * Drop the mutex of the aborted command. From this point on
	 * we must assume that the abort callback has freed the command.
	 */
	mutex_exit(&abort_cmd->nc_mutex);

	cmd->nc_sqid = 0;
	cmd->nc_sqe.sqe_opc = NVME_OPC_ABORT;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_cdw10 = ac.r;

	/*
	 * Send the ABORT to the hardware. The ABORT command will return _after_
	 * the aborted command has completed (aborted or otherwise).
	 */
	if (nvme_admin_cmd(cmd, nvme_admin_cmd_timeout) != DDI_SUCCESS) {
		sema_v(&nvme->n_abort_sema);
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_admin_cmd failed for ABORT");
		atomic_inc_32(&nvme->n_abort_failed);
		return;
	}
	sema_v(&nvme->n_abort_sema);

	if (nvme_check_cmd_status(cmd)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!ABORT failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		atomic_inc_32(&nvme->n_abort_failed);
	} else {
		atomic_inc_32(&nvme->n_cmd_aborted);
	}

	nvme_free_cmd(cmd);
}

/*
 * nvme_wait_cmd -- wait for command completion or timeout
 *
 * Returns B_TRUE if the command completed normally.
 *
 * Returns B_FALSE if the command timed out and an abort was attempted. The
 * command mutex will be dropped and the command must be considered freed. The
 * freeing of the command is normally done by the abort command callback.
 *
 * In case of a serious error or a timeout of the abort command the hardware
 * will be declared dead and FMA will be notified.
 */
static boolean_t
nvme_wait_cmd(nvme_cmd_t *cmd, uint_t sec)
{
	clock_t timeout = ddi_get_lbolt() + drv_usectohz(sec * MICROSEC);
	nvme_t *nvme = cmd->nc_nvme;
	nvme_reg_csts_t csts;

	ASSERT(mutex_owned(&cmd->nc_mutex));

	while (!cmd->nc_completed) {
		if (cv_timedwait(&cmd->nc_cv, &cmd->nc_mutex, timeout) == -1)
			break;
	}

	if (cmd->nc_completed)
		return (B_TRUE);

	/*
	 * The command timed out. Change the callback to the cleanup function.
	 */
	cmd->nc_callback = nvme_abort_cmd_cb;

	/*
	 * Check controller for fatal status, any errors associated with the
	 * register or DMA handle, or for a double timeout (abort command timed
	 * out). If necessary log a warning and call FMA.
	 */
	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	dev_err(nvme->n_dip, CE_WARN, "!command timeout, "
	    "OPC = %x, CFS = %d", cmd->nc_sqe.sqe_opc, csts.b.csts_cfs);
	atomic_inc_32(&nvme->n_cmd_timeout);

	if (csts.b.csts_cfs ||
	    nvme_check_regs_hdl(nvme) ||
	    nvme_check_dma_hdl(cmd->nc_dma) ||
	    cmd->nc_sqe.sqe_opc == NVME_OPC_ABORT) {
		ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
		nvme->n_dead = B_TRUE;
		mutex_exit(&cmd->nc_mutex);
	} else {
		/*
		 * Try to abort the command. The command mutex is released by
		 * nvme_abort_cmd().
		 * If the abort succeeds it will have freed the aborted command.
		 * If the abort fails for other reasons we must assume that the
		 * command may complete at any time, and the callback will free
		 * it for us.
		 */
		nvme_abort_cmd(cmd);
	}

	return (B_FALSE);
}

static void
nvme_wakeup_cmd(void *arg)
{
	nvme_cmd_t *cmd = arg;

	mutex_enter(&cmd->nc_mutex);
	/*
	 * There is a slight chance that this command completed shortly after
	 * the timeout was hit in nvme_wait_cmd() but before the callback was
	 * changed. Catch that case here and clean up accordingly.
	 */
	if (cmd->nc_callback == nvme_abort_cmd_cb) {
		mutex_exit(&cmd->nc_mutex);
		nvme_abort_cmd_cb(cmd);
		return;
	}

	cmd->nc_completed = B_TRUE;
	cv_signal(&cmd->nc_cv);
	mutex_exit(&cmd->nc_mutex);
}

static void
nvme_async_event_task(void *arg)
{
	nvme_cmd_t *cmd = arg;
	nvme_t *nvme = cmd->nc_nvme;
	nvme_error_log_entry_t *error_log = NULL;
	nvme_health_log_t *health_log = NULL;
	nvme_async_event_t event;
	int ret;

	/*
	 * Check for errors associated with the async request itself. The only
	 * command-specific error is "async event limit exceeded", which
	 * indicates a programming error in the driver and causes a panic in
	 * nvme_check_cmd_status().
	 *
	 * Other possible errors are various scenarios where the async request
	 * was aborted, or internal errors in the device. Internal errors are
	 * reported to FMA, the command aborts need no special handling here.
	 */
	if (nvme_check_cmd_status(cmd)) {
		dev_err(cmd->nc_nvme->n_dip, CE_WARN,
		    "!async event request returned failure, sct = %x, "
		    "sc = %x, dnr = %d, m = %d", cmd->nc_cqe.cqe_sf.sf_sct,
		    cmd->nc_cqe.cqe_sf.sf_sc, cmd->nc_cqe.cqe_sf.sf_dnr,
		    cmd->nc_cqe.cqe_sf.sf_m);

		if (cmd->nc_cqe.cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC &&
		    cmd->nc_cqe.cqe_sf.sf_sc == NVME_CQE_SC_GEN_INTERNAL_ERR) {
			cmd->nc_nvme->n_dead = B_TRUE;
			ddi_fm_service_impact(cmd->nc_nvme->n_dip,
			    DDI_SERVICE_LOST);
		}
		nvme_free_cmd(cmd);
		return;
	}


	event.r = cmd->nc_cqe.cqe_dw0;

	/* Clear CQE and re-submit the async request. */
	bzero(&cmd->nc_cqe, sizeof (nvme_cqe_t));
	ret = nvme_submit_cmd(nvme->n_adminq, cmd);

	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to resubmit async event request");
		atomic_inc_32(&nvme->n_async_resubmit_failed);
		nvme_free_cmd(cmd);
	}

	switch (event.b.ae_type) {
	case NVME_ASYNC_TYPE_ERROR:
		if (event.b.ae_logpage == NVME_LOGPAGE_ERROR) {
			error_log = (nvme_error_log_entry_t *)
			    nvme_get_logpage(nvme, event.b.ae_logpage);
		} else {
			dev_err(nvme->n_dip, CE_WARN, "!wrong logpage in "
			    "async event reply: %d", event.b.ae_logpage);
			atomic_inc_32(&nvme->n_wrong_logpage);
		}

		switch (event.b.ae_info) {
		case NVME_ASYNC_ERROR_INV_SQ:
			dev_err(nvme->n_dip, CE_PANIC, "programming error: "
			    "invalid submission queue");
			return;

		case NVME_ASYNC_ERROR_INV_DBL:
			dev_err(nvme->n_dip, CE_PANIC, "programming error: "
			    "invalid doorbell write value");
			return;

		case NVME_ASYNC_ERROR_DIAGFAIL:
			dev_err(nvme->n_dip, CE_WARN, "!diagnostic failure");
			ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
			nvme->n_dead = B_TRUE;
			atomic_inc_32(&nvme->n_diagfail_event);
			break;

		case NVME_ASYNC_ERROR_PERSISTENT:
			dev_err(nvme->n_dip, CE_WARN, "!persistent internal "
			    "device error");
			ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
			nvme->n_dead = B_TRUE;
			atomic_inc_32(&nvme->n_persistent_event);
			break;

		case NVME_ASYNC_ERROR_TRANSIENT:
			dev_err(nvme->n_dip, CE_WARN, "!transient internal "
			    "device error");
			/* TODO: send ereport */
			atomic_inc_32(&nvme->n_transient_event);
			break;

		case NVME_ASYNC_ERROR_FW_LOAD:
			dev_err(nvme->n_dip, CE_WARN,
			    "!firmware image load error");
			atomic_inc_32(&nvme->n_fw_load_event);
			break;
		}
		break;

	case NVME_ASYNC_TYPE_HEALTH:
		if (event.b.ae_logpage == NVME_LOGPAGE_HEALTH) {
			health_log = (nvme_health_log_t *)
			    nvme_get_logpage(nvme, event.b.ae_logpage, -1);
		} else {
			dev_err(nvme->n_dip, CE_WARN, "!wrong logpage in "
			    "async event reply: %d", event.b.ae_logpage);
			atomic_inc_32(&nvme->n_wrong_logpage);
		}

		switch (event.b.ae_info) {
		case NVME_ASYNC_HEALTH_RELIABILITY:
			dev_err(nvme->n_dip, CE_WARN,
			    "!device reliability compromised");
			/* TODO: send ereport */
			atomic_inc_32(&nvme->n_reliability_event);
			break;

		case NVME_ASYNC_HEALTH_TEMPERATURE:
			dev_err(nvme->n_dip, CE_WARN,
			    "!temperature above threshold");
			/* TODO: send ereport */
			atomic_inc_32(&nvme->n_temperature_event);
			break;

		case NVME_ASYNC_HEALTH_SPARE:
			dev_err(nvme->n_dip, CE_WARN,
			    "!spare space below threshold");
			/* TODO: send ereport */
			atomic_inc_32(&nvme->n_spare_event);
			break;
		}
		break;

	case NVME_ASYNC_TYPE_VENDOR:
		dev_err(nvme->n_dip, CE_WARN, "!vendor specific async event "
		    "received, info = %x, logpage = %x", event.b.ae_info,
		    event.b.ae_logpage);
		atomic_inc_32(&nvme->n_vendor_event);
		break;

	default:
		dev_err(nvme->n_dip, CE_WARN, "!unknown async event received, "
		    "type = %x, info = %x, logpage = %x", event.b.ae_type,
		    event.b.ae_info, event.b.ae_logpage);
		atomic_inc_32(&nvme->n_unknown_event);
		break;
	}

	if (error_log)
		kmem_free(error_log, sizeof (nvme_error_log_entry_t) *
		    nvme->n_error_log_len);

	if (health_log)
		kmem_free(health_log, sizeof (nvme_health_log_t));
}

static int
nvme_admin_cmd(nvme_cmd_t *cmd, int sec)
{
	int ret;

	mutex_enter(&cmd->nc_mutex);
	ret = nvme_submit_cmd(cmd->nc_nvme->n_adminq, cmd);

	if (ret != DDI_SUCCESS) {
		mutex_exit(&cmd->nc_mutex);
		dev_err(cmd->nc_nvme->n_dip, CE_WARN,
		    "!nvme_submit_cmd failed");
		atomic_inc_32(&cmd->nc_nvme->n_admin_queue_full);
		nvme_free_cmd(cmd);
		return (DDI_FAILURE);
	}

	if (nvme_wait_cmd(cmd, sec) == B_FALSE) {
		/*
		 * The command timed out. An abort command was posted that
		 * will take care of the cleanup.
		 */
		return (DDI_FAILURE);
	}
	mutex_exit(&cmd->nc_mutex);

	return (DDI_SUCCESS);
}

static int
nvme_async_event(nvme_t *nvme)
{
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	int ret;

	cmd->nc_sqid = 0;
	cmd->nc_sqe.sqe_opc = NVME_OPC_ASYNC_EVENT;
	cmd->nc_callback = nvme_async_event_task;

	ret = nvme_submit_cmd(nvme->n_adminq, cmd);

	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_submit_cmd failed for ASYNCHRONOUS EVENT");
		nvme_free_cmd(cmd);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void *
nvme_get_logpage(nvme_t *nvme, uint8_t logpage, ...)
{
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	void *buf = NULL;
	nvme_getlogpage_t getlogpage = { 0 };
	size_t bufsize;
	va_list ap;

	va_start(ap, logpage);

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_GET_LOG_PAGE;

	getlogpage.b.lp_lid = logpage;

	switch (logpage) {
	case NVME_LOGPAGE_ERROR:
		cmd->nc_sqe.sqe_nsid = (uint32_t)-1;
		bufsize = nvme->n_error_log_len *
		    sizeof (nvme_error_log_entry_t);
		break;

	case NVME_LOGPAGE_HEALTH:
		cmd->nc_sqe.sqe_nsid = va_arg(ap, uint32_t);
		bufsize = sizeof (nvme_health_log_t);
		break;

	case NVME_LOGPAGE_FWSLOT:
		cmd->nc_sqe.sqe_nsid = (uint32_t)-1;
		bufsize = sizeof (nvme_fwslot_log_t);
		break;

	default:
		dev_err(nvme->n_dip, CE_WARN, "!unknown log page requested: %d",
		    logpage);
		atomic_inc_32(&nvme->n_unknown_logpage);
		goto fail;
	}

	va_end(ap);

	getlogpage.b.lp_numd = bufsize / sizeof (uint32_t) - 1;

	cmd->nc_sqe.sqe_cdw10 = getlogpage.r;

	if (nvme_zalloc_dma(nvme, getlogpage.b.lp_numd * sizeof (uint32_t),
	    DDI_DMA_READ, &nvme->n_prp_dma_attr, &cmd->nc_dma) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_zalloc_dma failed for GET LOG PAGE");
		goto fail;
	}

	if (cmd->nc_dma->nd_ncookie > 2) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!too many DMA cookies for GET LOG PAGE");
		atomic_inc_32(&nvme->n_too_many_cookies);
		goto fail;
	}

	cmd->nc_sqe.sqe_dptr.d_prp[0] = cmd->nc_dma->nd_cookie.dmac_laddress;
	if (cmd->nc_dma->nd_ncookie > 1) {
		ddi_dma_nextcookie(cmd->nc_dma->nd_dmah,
		    &cmd->nc_dma->nd_cookie);
		cmd->nc_sqe.sqe_dptr.d_prp[1] =
		    cmd->nc_dma->nd_cookie.dmac_laddress;
	}

	if (nvme_admin_cmd(cmd, nvme_admin_cmd_timeout) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_admin_cmd failed for GET LOG PAGE");
		return (NULL);
	}

	if (nvme_check_cmd_status(cmd)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!GET LOG PAGE failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		goto fail;
	}

	buf = kmem_alloc(bufsize, KM_SLEEP);
	bcopy(cmd->nc_dma->nd_memp, buf, bufsize);

fail:
	nvme_free_cmd(cmd);

	return (buf);
}

static void *
nvme_identify(nvme_t *nvme, uint32_t nsid)
{
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	void *buf = NULL;

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_IDENTIFY;
	cmd->nc_sqe.sqe_nsid = nsid;
	cmd->nc_sqe.sqe_cdw10 = nsid ? NVME_IDENTIFY_NSID : NVME_IDENTIFY_CTRL;

	if (nvme_zalloc_dma(nvme, NVME_IDENTIFY_BUFSIZE, DDI_DMA_READ,
	    &nvme->n_prp_dma_attr, &cmd->nc_dma) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_zalloc_dma failed for IDENTIFY");
		goto fail;
	}

	if (cmd->nc_dma->nd_ncookie > 2) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!too many DMA cookies for IDENTIFY");
		atomic_inc_32(&nvme->n_too_many_cookies);
		goto fail;
	}

	cmd->nc_sqe.sqe_dptr.d_prp[0] = cmd->nc_dma->nd_cookie.dmac_laddress;
	if (cmd->nc_dma->nd_ncookie > 1) {
		ddi_dma_nextcookie(cmd->nc_dma->nd_dmah,
		    &cmd->nc_dma->nd_cookie);
		cmd->nc_sqe.sqe_dptr.d_prp[1] =
		    cmd->nc_dma->nd_cookie.dmac_laddress;
	}

	if (nvme_admin_cmd(cmd, nvme_admin_cmd_timeout) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_admin_cmd failed for IDENTIFY");
		return (NULL);
	}

	if (nvme_check_cmd_status(cmd)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!IDENTIFY failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		goto fail;
	}

	buf = kmem_alloc(NVME_IDENTIFY_BUFSIZE, KM_SLEEP);
	bcopy(cmd->nc_dma->nd_memp, buf, NVME_IDENTIFY_BUFSIZE);

fail:
	nvme_free_cmd(cmd);

	return (buf);
}

static boolean_t
nvme_set_features(nvme_t *nvme, uint32_t nsid, uint8_t feature, uint32_t val,
    uint32_t *res)
{
	_NOTE(ARGUNUSED(nsid));
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	boolean_t ret = B_FALSE;

	ASSERT(res != NULL);

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_SET_FEATURES;
	cmd->nc_sqe.sqe_cdw10 = feature;
	cmd->nc_sqe.sqe_cdw11 = val;

	switch (feature) {
	case NVME_FEAT_WRITE_CACHE:
		if (!nvme->n_write_cache_present)
			goto fail;
		break;

	case NVME_FEAT_NQUEUES:
		break;

	default:
		goto fail;
	}

	if (nvme_admin_cmd(cmd, nvme_admin_cmd_timeout) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_admin_cmd failed for SET FEATURES");
		return (ret);
	}

	if (nvme_check_cmd_status(cmd)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!SET FEATURES %d failed with sct = %x, sc = %x",
		    feature, cmd->nc_cqe.cqe_sf.sf_sct,
		    cmd->nc_cqe.cqe_sf.sf_sc);
		goto fail;
	}

	*res = cmd->nc_cqe.cqe_dw0;
	ret = B_TRUE;

fail:
	nvme_free_cmd(cmd);
	return (ret);
}

static boolean_t
nvme_write_cache_set(nvme_t *nvme, boolean_t enable)
{
	nvme_write_cache_t nwc = { 0 };

	if (enable)
		nwc.b.wc_wce = 1;

	if (!nvme_set_features(nvme, 0, NVME_FEAT_WRITE_CACHE, nwc.r, &nwc.r))
		return (B_FALSE);

	return (B_TRUE);
}

static int
nvme_set_nqueues(nvme_t *nvme, uint16_t nqueues)
{
	nvme_nqueue_t nq = { 0 };

	nq.b.nq_nsq = nq.b.nq_ncq = nqueues - 1;

	if (!nvme_set_features(nvme, 0, NVME_FEAT_NQUEUES, nq.r, &nq.r)) {
		return (0);
	}

	/*
	 * Always use the same number of submission and completion queues, and
	 * never use more than the requested number of queues.
	 */
	return (MIN(nqueues, MIN(nq.b.nq_nsq, nq.b.nq_ncq) + 1));
}

static int
nvme_create_io_qpair(nvme_t *nvme, nvme_qpair_t *qp, uint16_t idx)
{
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	nvme_create_queue_dw10_t dw10 = { 0 };
	nvme_create_cq_dw11_t c_dw11 = { 0 };
	nvme_create_sq_dw11_t s_dw11 = { 0 };

	dw10.b.q_qid = idx;
	dw10.b.q_qsize = qp->nq_nentry - 1;

	c_dw11.b.cq_pc = 1;
	c_dw11.b.cq_ien = 1;
	c_dw11.b.cq_iv = idx % nvme->n_intr_cnt;

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_CREATE_CQUEUE;
	cmd->nc_sqe.sqe_cdw10 = dw10.r;
	cmd->nc_sqe.sqe_cdw11 = c_dw11.r;
	cmd->nc_sqe.sqe_dptr.d_prp[0] = qp->nq_cqdma->nd_cookie.dmac_laddress;

	if (nvme_admin_cmd(cmd, nvme_admin_cmd_timeout) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_admin_cmd failed for CREATE CQUEUE");
		return (DDI_FAILURE);
	}

	if (nvme_check_cmd_status(cmd)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!CREATE CQUEUE failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		nvme_free_cmd(cmd);
		return (DDI_FAILURE);
	}

	nvme_free_cmd(cmd);

	s_dw11.b.sq_pc = 1;
	s_dw11.b.sq_cqid = idx;

	cmd = nvme_alloc_cmd(nvme, KM_SLEEP);
	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_CREATE_SQUEUE;
	cmd->nc_sqe.sqe_cdw10 = dw10.r;
	cmd->nc_sqe.sqe_cdw11 = s_dw11.r;
	cmd->nc_sqe.sqe_dptr.d_prp[0] = qp->nq_sqdma->nd_cookie.dmac_laddress;

	if (nvme_admin_cmd(cmd, nvme_admin_cmd_timeout) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_admin_cmd failed for CREATE SQUEUE");
		return (DDI_FAILURE);
	}

	if (nvme_check_cmd_status(cmd)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!CREATE SQUEUE failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		nvme_free_cmd(cmd);
		return (DDI_FAILURE);
	}

	nvme_free_cmd(cmd);

	return (DDI_SUCCESS);
}

static boolean_t
nvme_reset(nvme_t *nvme, boolean_t quiesce)
{
	nvme_reg_csts_t csts;
	int i;

	nvme_put32(nvme, NVME_REG_CC, 0);

	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	if (csts.b.csts_rdy == 1) {
		nvme_put32(nvme, NVME_REG_CC, 0);
		for (i = 0; i != nvme->n_timeout * 10; i++) {
			csts.r = nvme_get32(nvme, NVME_REG_CSTS);
			if (csts.b.csts_rdy == 0)
				break;

			if (quiesce)
				drv_usecwait(50000);
			else
				delay(drv_usectohz(50000));
		}
	}

	nvme_put32(nvme, NVME_REG_AQA, 0);
	nvme_put32(nvme, NVME_REG_ASQ, 0);
	nvme_put32(nvme, NVME_REG_ACQ, 0);

	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	return (csts.b.csts_rdy == 0 ? B_TRUE : B_FALSE);
}

static void
nvme_shutdown(nvme_t *nvme, int mode, boolean_t quiesce)
{
	nvme_reg_cc_t cc;
	nvme_reg_csts_t csts;
	int i;

	ASSERT(mode == NVME_CC_SHN_NORMAL || mode == NVME_CC_SHN_ABRUPT);

	cc.r = nvme_get32(nvme, NVME_REG_CC);
	cc.b.cc_shn = mode & 0x3;
	nvme_put32(nvme, NVME_REG_CC, cc.r);

	for (i = 0; i != 10; i++) {
		csts.r = nvme_get32(nvme, NVME_REG_CSTS);
		if (csts.b.csts_shst == NVME_CSTS_SHN_COMPLETE)
			break;

		if (quiesce)
			drv_usecwait(100000);
		else
			delay(drv_usectohz(100000));
	}
}


static void
nvme_prepare_devid(nvme_t *nvme, uint32_t nsid)
{
	/*
	 * Section 7.7 of the spec describes how to get a unique ID for
	 * the controller: the vendor ID, the model name and the serial
	 * number shall be unique when combined.
	 *
	 * If a namespace has no EUI64 we use the above and add the hex
	 * namespace ID to get a unique ID for the namespace.
	 */
	char model[sizeof (nvme->n_idctl->id_model) + 1];
	char serial[sizeof (nvme->n_idctl->id_serial) + 1];

	bcopy(nvme->n_idctl->id_model, model, sizeof (nvme->n_idctl->id_model));
	bcopy(nvme->n_idctl->id_serial, serial,
	    sizeof (nvme->n_idctl->id_serial));

	model[sizeof (nvme->n_idctl->id_model)] = '\0';
	serial[sizeof (nvme->n_idctl->id_serial)] = '\0';

	nvme->n_ns[nsid - 1].ns_devid = kmem_asprintf("%4X-%s-%s-%X",
	    nvme->n_idctl->id_vid, model, serial, nsid);
}

static int
nvme_init(nvme_t *nvme)
{
	nvme_reg_cc_t cc = { 0 };
	nvme_reg_aqa_t aqa = { 0 };
	nvme_reg_asq_t asq = { 0 };
	nvme_reg_acq_t acq = { 0 };
	nvme_reg_cap_t cap;
	nvme_reg_vs_t vs;
	nvme_reg_csts_t csts;
	int i = 0;
	int nqueues;
	char model[sizeof (nvme->n_idctl->id_model) + 1];
	char *vendor, *product;

	/* Check controller version */
	vs.r = nvme_get32(nvme, NVME_REG_VS);
	nvme->n_version.v_major = vs.b.vs_mjr;
	nvme->n_version.v_minor = vs.b.vs_mnr;
	dev_err(nvme->n_dip, CE_CONT, "?NVMe spec version %d.%d",
	    nvme->n_version.v_major, nvme->n_version.v_minor);

	if (NVME_VERSION_HIGHER(&nvme->n_version,
	    nvme_version_major, nvme_version_minor)) {
		dev_err(nvme->n_dip, CE_WARN, "!no support for version > %d.%d",
		    nvme_version_major, nvme_version_minor);
		if (nvme->n_strict_version)
			goto fail;
	}

	/* retrieve controller configuration */
	cap.r = nvme_get64(nvme, NVME_REG_CAP);

	if ((cap.b.cap_css & NVME_CAP_CSS_NVM) == 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!NVM command set not supported by hardware");
		goto fail;
	}

	nvme->n_nssr_supported = cap.b.cap_nssrs;
	nvme->n_doorbell_stride = 4 << cap.b.cap_dstrd;
	nvme->n_timeout = cap.b.cap_to;
	nvme->n_arbitration_mechanisms = cap.b.cap_ams;
	nvme->n_cont_queues_reqd = cap.b.cap_cqr;
	nvme->n_max_queue_entries = cap.b.cap_mqes + 1;

	/*
	 * The MPSMIN and MPSMAX fields in the CAP register use 0 to specify
	 * the base page size of 4k (1<<12), so add 12 here to get the real
	 * page size value.
	 */
	nvme->n_pageshift = MIN(MAX(cap.b.cap_mpsmin + 12, PAGESHIFT),
	    cap.b.cap_mpsmax + 12);
	nvme->n_pagesize = 1UL << (nvme->n_pageshift);

	/*
	 * Set up Queue DMA to transfer at least 1 page-aligned page at a time.
	 */
	nvme->n_queue_dma_attr.dma_attr_align = nvme->n_pagesize;
	nvme->n_queue_dma_attr.dma_attr_minxfer = nvme->n_pagesize;

	/*
	 * Set up PRP DMA to transfer 1 page-aligned page at a time.
	 * Maxxfer may be increased after we identified the controller limits.
	 */
	nvme->n_prp_dma_attr.dma_attr_maxxfer = nvme->n_pagesize;
	nvme->n_prp_dma_attr.dma_attr_minxfer = nvme->n_pagesize;
	nvme->n_prp_dma_attr.dma_attr_align = nvme->n_pagesize;
	nvme->n_prp_dma_attr.dma_attr_seg = nvme->n_pagesize - 1;

	/*
	 * Reset controller if it's still in ready state.
	 */
	if (nvme_reset(nvme, B_FALSE) == B_FALSE) {
		dev_err(nvme->n_dip, CE_WARN, "!unable to reset controller");
		ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
		nvme->n_dead = B_TRUE;
		goto fail;
	}

	/*
	 * Create the admin queue pair.
	 */
	if (nvme_alloc_qpair(nvme, nvme->n_admin_queue_len, &nvme->n_adminq, 0)
	    != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!unable to allocate admin qpair");
		goto fail;
	}
	nvme->n_ioq = kmem_alloc(sizeof (nvme_qpair_t *), KM_SLEEP);
	nvme->n_ioq[0] = nvme->n_adminq;

	nvme->n_progress |= NVME_ADMIN_QUEUE;

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "admin-queue-len", nvme->n_admin_queue_len);

	aqa.b.aqa_asqs = aqa.b.aqa_acqs = nvme->n_admin_queue_len - 1;
	asq = nvme->n_adminq->nq_sqdma->nd_cookie.dmac_laddress;
	acq = nvme->n_adminq->nq_cqdma->nd_cookie.dmac_laddress;

	ASSERT((asq & (nvme->n_pagesize - 1)) == 0);
	ASSERT((acq & (nvme->n_pagesize - 1)) == 0);

	nvme_put32(nvme, NVME_REG_AQA, aqa.r);
	nvme_put64(nvme, NVME_REG_ASQ, asq);
	nvme_put64(nvme, NVME_REG_ACQ, acq);

	cc.b.cc_ams = 0;	/* use Round-Robin arbitration */
	cc.b.cc_css = 0;	/* use NVM command set */
	cc.b.cc_mps = nvme->n_pageshift - 12;
	cc.b.cc_shn = 0;	/* no shutdown in progress */
	cc.b.cc_en = 1;		/* enable controller */
	cc.b.cc_iosqes = 6;	/* submission queue entry is 2^6 bytes long */
	cc.b.cc_iocqes = 4;	/* completion queue entry is 2^4 bytes long */

	nvme_put32(nvme, NVME_REG_CC, cc.r);

	/*
	 * Wait for the controller to become ready.
	 */
	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	if (csts.b.csts_rdy == 0) {
		for (i = 0; i != nvme->n_timeout * 10; i++) {
			delay(drv_usectohz(50000));
			csts.r = nvme_get32(nvme, NVME_REG_CSTS);

			if (csts.b.csts_cfs == 1) {
				dev_err(nvme->n_dip, CE_WARN,
				    "!controller fatal status at init");
				ddi_fm_service_impact(nvme->n_dip,
				    DDI_SERVICE_LOST);
				nvme->n_dead = B_TRUE;
				goto fail;
			}

			if (csts.b.csts_rdy == 1)
				break;
		}
	}

	if (csts.b.csts_rdy == 0) {
		dev_err(nvme->n_dip, CE_WARN, "!controller not ready");
		ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
		nvme->n_dead = B_TRUE;
		goto fail;
	}

	/*
	 * Assume an abort command limit of 1. We'll destroy and re-init
	 * that later when we know the true abort command limit.
	 */
	sema_init(&nvme->n_abort_sema, 1, NULL, SEMA_DRIVER, NULL);

	/*
	 * Setup initial interrupt for admin queue.
	 */
	if ((nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSIX, 1)
	    != DDI_SUCCESS) &&
	    (nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSI, 1)
	    != DDI_SUCCESS) &&
	    (nvme_setup_interrupts(nvme, DDI_INTR_TYPE_FIXED, 1)
	    != DDI_SUCCESS)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to setup initial interrupt");
		goto fail;
	}

	/*
	 * Post an asynchronous event command to catch errors.
	 */
	if (nvme_async_event(nvme) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to post async event");
		goto fail;
	}

	/*
	 * Identify Controller
	 */
	nvme->n_idctl = nvme_identify(nvme, 0);
	if (nvme->n_idctl == NULL) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to identify controller");
		goto fail;
	}

	/*
	 * Get Vendor & Product ID
	 */
	bcopy(nvme->n_idctl->id_model, model, sizeof (nvme->n_idctl->id_model));
	model[sizeof (nvme->n_idctl->id_model)] = '\0';
	sata_split_model(model, &vendor, &product);

	if (vendor == NULL)
		nvme->n_vendor = strdup("NVMe");
	else
		nvme->n_vendor = strdup(vendor);

	nvme->n_product = strdup(product);

	/*
	 * Get controller limits.
	 */
	nvme->n_async_event_limit = MAX(NVME_MIN_ASYNC_EVENT_LIMIT,
	    MIN(nvme->n_admin_queue_len / 10,
	    MIN(nvme->n_idctl->id_aerl + 1, nvme->n_async_event_limit)));

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "async-event-limit", nvme->n_async_event_limit);

	nvme->n_abort_command_limit = nvme->n_idctl->id_acl + 1;

	/*
	 * Reinitialize the semaphore with the true abort command limit
	 * supported by the hardware. It's not necessary to disable interrupts
	 * as only command aborts use the semaphore, and no commands are
	 * executed or aborted while we're here.
	 */
	sema_destroy(&nvme->n_abort_sema);
	sema_init(&nvme->n_abort_sema, nvme->n_abort_command_limit - 1, NULL,
	    SEMA_DRIVER, NULL);

	nvme->n_progress |= NVME_CTRL_LIMITS;

	if (nvme->n_idctl->id_mdts == 0)
		nvme->n_max_data_transfer_size = nvme->n_pagesize * 65536;
	else
		nvme->n_max_data_transfer_size =
		    1ull << (nvme->n_pageshift + nvme->n_idctl->id_mdts);

	nvme->n_error_log_len = nvme->n_idctl->id_elpe + 1;

	/*
	 * Limit n_max_data_transfer_size to what we can handle in one PRP.
	 * Chained PRPs are currently unsupported.
	 *
	 * This is a no-op on hardware which doesn't support a transfer size
	 * big enough to require chained PRPs.
	 */
	nvme->n_max_data_transfer_size = MIN(nvme->n_max_data_transfer_size,
	    (nvme->n_pagesize / sizeof (uint64_t) * nvme->n_pagesize));

	nvme->n_prp_dma_attr.dma_attr_maxxfer = nvme->n_max_data_transfer_size;

	/*
	 * Make sure the minimum/maximum queue entry sizes are not
	 * larger/smaller than the default.
	 */

	if (((1 << nvme->n_idctl->id_sqes.qes_min) > sizeof (nvme_sqe_t)) ||
	    ((1 << nvme->n_idctl->id_sqes.qes_max) < sizeof (nvme_sqe_t)) ||
	    ((1 << nvme->n_idctl->id_cqes.qes_min) > sizeof (nvme_cqe_t)) ||
	    ((1 << nvme->n_idctl->id_cqes.qes_max) < sizeof (nvme_cqe_t)))
		goto fail;

	/*
	 * Check for the presence of a Volatile Write Cache. If present,
	 * enable or disable based on the value of the property
	 * volatile-write-cache-enable (default is enabled).
	 */
	nvme->n_write_cache_present =
	    nvme->n_idctl->id_vwc.vwc_present == 0 ? B_FALSE : B_TRUE;

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "volatile-write-cache-present",
	    nvme->n_write_cache_present ? 1 : 0);

	if (!nvme->n_write_cache_present) {
		nvme->n_write_cache_enabled = B_FALSE;
	} else if (!nvme_write_cache_set(nvme, nvme->n_write_cache_enabled)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to %sable volatile write cache",
		    nvme->n_write_cache_enabled ? "en" : "dis");
		/*
		 * Assume the cache is (still) enabled.
		 */
		nvme->n_write_cache_enabled = B_TRUE;
	}

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "volatile-write-cache-enable",
	    nvme->n_write_cache_enabled ? 1 : 0);

	/*
	 * Grab a copy of all mandatory log pages.
	 *
	 * TODO: should go away once user space tool exists to print logs
	 */
	nvme->n_error_log = (nvme_error_log_entry_t *)
	    nvme_get_logpage(nvme, NVME_LOGPAGE_ERROR);
	nvme->n_health_log = (nvme_health_log_t *)
	    nvme_get_logpage(nvme, NVME_LOGPAGE_HEALTH, -1);
	nvme->n_fwslot_log = (nvme_fwslot_log_t *)
	    nvme_get_logpage(nvme, NVME_LOGPAGE_FWSLOT);

	/*
	 * Identify Namespaces
	 */
	nvme->n_namespace_count = nvme->n_idctl->id_nn;
	nvme->n_ns = kmem_zalloc(sizeof (nvme_namespace_t) *
	    nvme->n_namespace_count, KM_SLEEP);

	for (i = 0; i != nvme->n_namespace_count; i++) {
		nvme_identify_nsid_t *idns;
		int last_rp;

		nvme->n_ns[i].ns_nvme = nvme;
		nvme->n_ns[i].ns_idns = idns = nvme_identify(nvme, i + 1);

		if (idns == NULL) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!failed to identify namespace %d", i + 1);
			goto fail;
		}

		nvme->n_ns[i].ns_id = i + 1;
		nvme->n_ns[i].ns_block_count = idns->id_nsize;
		nvme->n_ns[i].ns_block_size =
		    1 << idns->id_lbaf[idns->id_flbas.lba_format].lbaf_lbads;
		nvme->n_ns[i].ns_best_block_size = nvme->n_ns[i].ns_block_size;

		/*
		 * Get the EUI64 if present. If not present prepare the devid
		 * from other device data.
		 */
		if (NVME_VERSION_ATLEAST(&nvme->n_version, 1, 1))
			bcopy(idns->id_eui64, nvme->n_ns[i].ns_eui64,
			    sizeof (nvme->n_ns[i].ns_eui64));

		/*LINTED: E_BAD_PTR_CAST_ALIGN*/
		if (*(uint64_t *)nvme->n_ns[i].ns_eui64 == 0) {
			nvme_prepare_devid(nvme, nvme->n_ns[i].ns_id);
		} else {
			/*
			 * Until EUI64 support is tested on real hardware we
			 * will ignore namespaces with an EUI64. This can
			 * be overriden by setting strict-version=0 in nvme.conf
			 */
			if (nvme->n_strict_version)
				nvme->n_ns[i].ns_ignore = B_TRUE;
		}

		/*
		 * Find the LBA format with no metadata and the best relative
		 * performance. A value of 3 means "degraded", 0 is best.
		 */
		last_rp = 3;
		for (int j = 0; j <= idns->id_nlbaf; j++) {
			if (idns->id_lbaf[j].lbaf_lbads == 0)
				break;
			if (idns->id_lbaf[j].lbaf_ms != 0)
				continue;
			if (idns->id_lbaf[j].lbaf_rp >= last_rp)
				continue;
			last_rp = idns->id_lbaf[j].lbaf_rp;
			nvme->n_ns[i].ns_best_block_size =
			    1 << idns->id_lbaf[j].lbaf_lbads;
		}

		if (nvme->n_ns[i].ns_best_block_size < nvme->n_min_block_size)
			nvme->n_ns[i].ns_best_block_size =
			    nvme->n_min_block_size;

		/*
		 * We currently don't support namespaces that use either:
		 * - thin provisioning
		 * - protection information
		 */
		if (idns->id_nsfeat.f_thin ||
		    idns->id_dps.dp_pinfo) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!ignoring namespace %d, unsupported features: "
			    "thin = %d, pinfo = %d", i + 1,
			    idns->id_nsfeat.f_thin, idns->id_dps.dp_pinfo);
			nvme->n_ns[i].ns_ignore = B_TRUE;
		}
	}

	/*
	 * Try to set up MSI/MSI-X interrupts.
	 */
	if ((nvme->n_intr_types & (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX))
	    != 0) {
		nvme_release_interrupts(nvme);

		nqueues = MIN(UINT16_MAX, ncpus);

		if ((nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSIX,
		    nqueues) != DDI_SUCCESS) &&
		    (nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSI,
		    nqueues) != DDI_SUCCESS)) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!failed to setup MSI/MSI-X interrupts");
			goto fail;
		}
	}

	nqueues = nvme->n_intr_cnt;

	/*
	 * Create I/O queue pairs.
	 */
	nvme->n_ioq_count = nvme_set_nqueues(nvme, nqueues);
	if (nvme->n_ioq_count == 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to set number of I/O queues to %d", nqueues);
		goto fail;
	}

	/*
	 * Reallocate I/O queue array
	 */
	kmem_free(nvme->n_ioq, sizeof (nvme_qpair_t *));
	nvme->n_ioq = kmem_zalloc(sizeof (nvme_qpair_t *) *
	    (nvme->n_ioq_count + 1), KM_SLEEP);
	nvme->n_ioq[0] = nvme->n_adminq;

	/*
	 * If we got less queues than we asked for we might as well give
	 * some of the interrupt vectors back to the system.
	 */
	if (nvme->n_ioq_count < nqueues) {
		nvme_release_interrupts(nvme);

		if (nvme_setup_interrupts(nvme, nvme->n_intr_type,
		    nvme->n_ioq_count) != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!failed to reduce number of interrupts");
			goto fail;
		}
	}

	/*
	 * Alloc & register I/O queue pairs
	 */
	nvme->n_io_queue_len =
	    MIN(nvme->n_io_queue_len, nvme->n_max_queue_entries);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip, "io-queue-len",
	    nvme->n_io_queue_len);

	for (i = 1; i != nvme->n_ioq_count + 1; i++) {
		if (nvme_alloc_qpair(nvme, nvme->n_io_queue_len,
		    &nvme->n_ioq[i], i) != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!unable to allocate I/O qpair %d", i);
			goto fail;
		}

		if (nvme_create_io_qpair(nvme, nvme->n_ioq[i], i)
		    != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!unable to create I/O qpair %d", i);
			goto fail;
		}
	}

	/*
	 * Post more asynchronous events commands to reduce event reporting
	 * latency as suggested by the spec.
	 */
	for (i = 1; i != nvme->n_async_event_limit; i++) {
		if (nvme_async_event(nvme) != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!failed to post async event %d", i);
			goto fail;
		}
	}

	return (DDI_SUCCESS);

fail:
	(void) nvme_reset(nvme, B_FALSE);
	return (DDI_FAILURE);
}

static uint_t
nvme_intr(caddr_t arg1, caddr_t arg2)
{
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	nvme_t *nvme = (nvme_t *)arg1;
	int inum = (int)(uintptr_t)arg2;
	int ccnt = 0;
	int qnum;
	nvme_cmd_t *cmd;

	if (inum >= nvme->n_intr_cnt)
		return (DDI_INTR_UNCLAIMED);

	/*
	 * The interrupt vector a queue uses is calculated as queue_idx %
	 * intr_cnt in nvme_create_io_qpair(). Iterate through the queue array
	 * in steps of n_intr_cnt to process all queues using this vector.
	 */
	for (qnum = inum;
	    qnum < nvme->n_ioq_count + 1 && nvme->n_ioq[qnum] != NULL;
	    qnum += nvme->n_intr_cnt) {
		while ((cmd = nvme_retrieve_cmd(nvme, nvme->n_ioq[qnum]))) {
			taskq_dispatch_ent((taskq_t *)cmd->nc_nvme->n_cmd_taskq,
			    cmd->nc_callback, cmd, TQ_NOSLEEP, &cmd->nc_tqent);
			ccnt++;
		}
	}

	return (ccnt > 0 ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

static void
nvme_release_interrupts(nvme_t *nvme)
{
	int i;

	for (i = 0; i < nvme->n_intr_cnt; i++) {
		if (nvme->n_inth[i] == NULL)
			break;

		if (nvme->n_intr_cap & DDI_INTR_FLAG_BLOCK)
			(void) ddi_intr_block_disable(&nvme->n_inth[i], 1);
		else
			(void) ddi_intr_disable(nvme->n_inth[i]);

		(void) ddi_intr_remove_handler(nvme->n_inth[i]);
		(void) ddi_intr_free(nvme->n_inth[i]);
	}

	kmem_free(nvme->n_inth, nvme->n_inth_sz);
	nvme->n_inth = NULL;
	nvme->n_inth_sz = 0;

	nvme->n_progress &= ~NVME_INTERRUPTS;
}

static int
nvme_setup_interrupts(nvme_t *nvme, int intr_type, int nqpairs)
{
	int nintrs, navail, count;
	int ret;
	int i;

	if (nvme->n_intr_types == 0) {
		ret = ddi_intr_get_supported_types(nvme->n_dip,
		    &nvme->n_intr_types);
		if (ret != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!%s: ddi_intr_get_supported types failed",
			    __func__);
			return (ret);
		}
#ifdef __x86
		if (get_hwenv() == HW_VMWARE)
			nvme->n_intr_types &= ~DDI_INTR_TYPE_MSIX;
#endif
	}

	if ((nvme->n_intr_types & intr_type) == 0)
		return (DDI_FAILURE);

	ret = ddi_intr_get_nintrs(nvme->n_dip, intr_type, &nintrs);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_get_nintrs failed",
		    __func__);
		return (ret);
	}

	ret = ddi_intr_get_navail(nvme->n_dip, intr_type, &navail);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_get_navail failed",
		    __func__);
		return (ret);
	}

	/* We want at most one interrupt per queue pair. */
	if (navail > nqpairs)
		navail = nqpairs;

	nvme->n_inth_sz = sizeof (ddi_intr_handle_t) * navail;
	nvme->n_inth = kmem_zalloc(nvme->n_inth_sz, KM_SLEEP);

	ret = ddi_intr_alloc(nvme->n_dip, nvme->n_inth, intr_type, 0, navail,
	    &count, 0);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_alloc failed",
		    __func__);
		goto fail;
	}

	nvme->n_intr_cnt = count;

	ret = ddi_intr_get_pri(nvme->n_inth[0], &nvme->n_intr_pri);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_get_pri failed",
		    __func__);
		goto fail;
	}

	for (i = 0; i < count; i++) {
		ret = ddi_intr_add_handler(nvme->n_inth[i], nvme_intr,
		    (void *)nvme, (void *)(uintptr_t)i);
		if (ret != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!%s: ddi_intr_add_handler failed", __func__);
			goto fail;
		}
	}

	(void) ddi_intr_get_cap(nvme->n_inth[0], &nvme->n_intr_cap);

	for (i = 0; i < count; i++) {
		if (nvme->n_intr_cap & DDI_INTR_FLAG_BLOCK)
			ret = ddi_intr_block_enable(&nvme->n_inth[i], 1);
		else
			ret = ddi_intr_enable(nvme->n_inth[i]);

		if (ret != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!%s: enabling interrupt %d failed", __func__, i);
			goto fail;
		}
	}

	nvme->n_intr_type = intr_type;

	nvme->n_progress |= NVME_INTERRUPTS;

	return (DDI_SUCCESS);

fail:
	nvme_release_interrupts(nvme);

	return (ret);
}

static int
nvme_fm_errcb(dev_info_t *dip, ddi_fm_error_t *fm_error, const void *arg)
{
	_NOTE(ARGUNUSED(arg));

	pci_ereport_post(dip, fm_error, NULL);
	return (fm_error->fme_status);
}

static int
nvme_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	nvme_t *nvme;
	int instance;
	int nregs;
	off_t regsize;
	int i;
	char name[32];

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(nvme_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	nvme = ddi_get_soft_state(nvme_state, instance);
	ddi_set_driver_private(dip, nvme);
	nvme->n_dip = dip;

	nvme->n_strict_version = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "strict-version", 1) == 1 ? B_TRUE : B_FALSE;
	nvme->n_ignore_unknown_vendor_status = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, "ignore-unknown-vendor-status", 0) == 1 ?
	    B_TRUE : B_FALSE;
	nvme->n_admin_queue_len = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "admin-queue-len", NVME_DEFAULT_ADMIN_QUEUE_LEN);
	nvme->n_io_queue_len = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "io-queue-len", NVME_DEFAULT_IO_QUEUE_LEN);
	nvme->n_async_event_limit = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "async-event-limit",
	    NVME_DEFAULT_ASYNC_EVENT_LIMIT);
	nvme->n_write_cache_enabled = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "volatile-write-cache-enable", 1) != 0 ?
	    B_TRUE : B_FALSE;
	nvme->n_min_block_size = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "min-phys-block-size",
	    NVME_DEFAULT_MIN_BLOCK_SIZE);

	if (!ISP2(nvme->n_min_block_size) ||
	    (nvme->n_min_block_size < NVME_DEFAULT_MIN_BLOCK_SIZE)) {
		dev_err(dip, CE_WARN, "!min-phys-block-size %s, "
		    "using default %d", ISP2(nvme->n_min_block_size) ?
		    "too low" : "not a power of 2",
		    NVME_DEFAULT_MIN_BLOCK_SIZE);
		nvme->n_min_block_size = NVME_DEFAULT_MIN_BLOCK_SIZE;
	}

	if (nvme->n_admin_queue_len < NVME_MIN_ADMIN_QUEUE_LEN)
		nvme->n_admin_queue_len = NVME_MIN_ADMIN_QUEUE_LEN;
	else if (nvme->n_admin_queue_len > NVME_MAX_ADMIN_QUEUE_LEN)
		nvme->n_admin_queue_len = NVME_MAX_ADMIN_QUEUE_LEN;

	if (nvme->n_io_queue_len < NVME_MIN_IO_QUEUE_LEN)
		nvme->n_io_queue_len = NVME_MIN_IO_QUEUE_LEN;

	if (nvme->n_async_event_limit < 1)
		nvme->n_async_event_limit = NVME_DEFAULT_ASYNC_EVENT_LIMIT;

	nvme->n_reg_acc_attr = nvme_reg_acc_attr;
	nvme->n_queue_dma_attr = nvme_queue_dma_attr;
	nvme->n_prp_dma_attr = nvme_prp_dma_attr;
	nvme->n_sgl_dma_attr = nvme_sgl_dma_attr;

	/*
	 * Setup FMA support.
	 */
	nvme->n_fm_cap = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	ddi_fm_init(dip, &nvme->n_fm_cap, &nvme->n_fm_ibc);

	if (nvme->n_fm_cap) {
		if (nvme->n_fm_cap & DDI_FM_ACCCHK_CAPABLE)
			nvme->n_reg_acc_attr.devacc_attr_access =
			    DDI_FLAGERR_ACC;

		if (nvme->n_fm_cap & DDI_FM_DMACHK_CAPABLE) {
			nvme->n_prp_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
			nvme->n_sgl_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		}

		if (DDI_FM_EREPORT_CAP(nvme->n_fm_cap) ||
		    DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			pci_ereport_setup(dip);

		if (DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			ddi_fm_handler_register(dip, nvme_fm_errcb,
			    (void *)nvme);
	}

	nvme->n_progress |= NVME_FMA_INIT;

	/*
	 * The spec defines several register sets. Only the controller
	 * registers (set 1) are currently used.
	 */
	if (ddi_dev_nregs(dip, &nregs) == DDI_FAILURE ||
	    nregs < 2 ||
	    ddi_dev_regsize(dip, 1, &regsize) == DDI_FAILURE)
		goto fail;

	if (ddi_regs_map_setup(dip, 1, &nvme->n_regs, 0, regsize,
	    &nvme->n_reg_acc_attr, &nvme->n_regh) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to map regset 1");
		goto fail;
	}

	nvme->n_progress |= NVME_REGS_MAPPED;

	/*
	 * Create taskq for command completion.
	 */
	(void) snprintf(name, sizeof (name), "%s%d_cmd_taskq",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	nvme->n_cmd_taskq = ddi_taskq_create(dip, name, MIN(UINT16_MAX, ncpus),
	    TASKQ_DEFAULTPRI, 0);
	if (nvme->n_cmd_taskq == NULL) {
		dev_err(dip, CE_WARN, "!failed to create cmd taskq");
		goto fail;
	}

	/*
	 * Create PRP DMA cache
	 */
	(void) snprintf(name, sizeof (name), "%s%d_prp_cache",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	nvme->n_prp_cache = kmem_cache_create(name, sizeof (nvme_dma_t),
	    0, nvme_prp_dma_constructor, nvme_prp_dma_destructor,
	    NULL, (void *)nvme, NULL, 0);

	if (nvme_init(nvme) != DDI_SUCCESS)
		goto fail;

	/*
	 * Attach the blkdev driver for each namespace.
	 */
	for (i = 0; i != nvme->n_namespace_count; i++) {
		if (nvme->n_ns[i].ns_ignore)
			continue;

		nvme->n_ns[i].ns_bd_hdl = bd_alloc_handle(&nvme->n_ns[i],
		    &nvme_bd_ops, &nvme->n_prp_dma_attr, KM_SLEEP);

		if (nvme->n_ns[i].ns_bd_hdl == NULL) {
			dev_err(dip, CE_WARN,
			    "!failed to get blkdev handle for namespace %d", i);
			goto fail;
		}

		if (bd_attach_handle(dip, nvme->n_ns[i].ns_bd_hdl)
		    != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "!failed to attach blkdev handle for namespace %d",
			    i);
			goto fail;
		}
	}

	return (DDI_SUCCESS);

fail:
	/* attach successful anyway so that FMA can retire the device */
	if (nvme->n_dead)
		return (DDI_SUCCESS);

	(void) nvme_detach(dip, DDI_DETACH);

	return (DDI_FAILURE);
}

static int
nvme_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance, i;
	nvme_t *nvme;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	nvme = ddi_get_soft_state(nvme_state, instance);

	if (nvme == NULL)
		return (DDI_FAILURE);

	if (nvme->n_ns) {
		for (i = 0; i != nvme->n_namespace_count; i++) {
			if (nvme->n_ns[i].ns_bd_hdl) {
				(void) bd_detach_handle(
				    nvme->n_ns[i].ns_bd_hdl);
				bd_free_handle(nvme->n_ns[i].ns_bd_hdl);
			}

			if (nvme->n_ns[i].ns_idns)
				kmem_free(nvme->n_ns[i].ns_idns,
				    sizeof (nvme_identify_nsid_t));
			if (nvme->n_ns[i].ns_devid)
				strfree(nvme->n_ns[i].ns_devid);
		}

		kmem_free(nvme->n_ns, sizeof (nvme_namespace_t) *
		    nvme->n_namespace_count);
	}

	if (nvme->n_progress & NVME_INTERRUPTS)
		nvme_release_interrupts(nvme);

	if (nvme->n_cmd_taskq)
		ddi_taskq_wait(nvme->n_cmd_taskq);

	if (nvme->n_ioq_count > 0) {
		for (i = 1; i != nvme->n_ioq_count + 1; i++) {
			if (nvme->n_ioq[i] != NULL) {
				/* TODO: send destroy queue commands */
				nvme_free_qpair(nvme->n_ioq[i]);
			}
		}

		kmem_free(nvme->n_ioq, sizeof (nvme_qpair_t *) *
		    (nvme->n_ioq_count + 1));
	}

	if (nvme->n_prp_cache != NULL) {
		kmem_cache_destroy(nvme->n_prp_cache);
	}

	if (nvme->n_progress & NVME_REGS_MAPPED) {
		nvme_shutdown(nvme, NVME_CC_SHN_NORMAL, B_FALSE);
		(void) nvme_reset(nvme, B_FALSE);
	}

	if (nvme->n_cmd_taskq)
		ddi_taskq_destroy(nvme->n_cmd_taskq);

	if (nvme->n_progress & NVME_CTRL_LIMITS)
		sema_destroy(&nvme->n_abort_sema);

	if (nvme->n_progress & NVME_ADMIN_QUEUE)
		nvme_free_qpair(nvme->n_adminq);

	if (nvme->n_idctl)
		kmem_free(nvme->n_idctl, sizeof (nvme_identify_ctrl_t));

	if (nvme->n_progress & NVME_REGS_MAPPED)
		ddi_regs_map_free(&nvme->n_regh);

	if (nvme->n_progress & NVME_FMA_INIT) {
		if (DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			ddi_fm_handler_unregister(nvme->n_dip);

		if (DDI_FM_EREPORT_CAP(nvme->n_fm_cap) ||
		    DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			pci_ereport_teardown(nvme->n_dip);

		ddi_fm_fini(nvme->n_dip);
	}

	if (nvme->n_vendor != NULL)
		strfree(nvme->n_vendor);

	if (nvme->n_product != NULL)
		strfree(nvme->n_product);

	ddi_soft_state_free(nvme_state, instance);

	return (DDI_SUCCESS);
}

static int
nvme_quiesce(dev_info_t *dip)
{
	int instance;
	nvme_t *nvme;

	instance = ddi_get_instance(dip);

	nvme = ddi_get_soft_state(nvme_state, instance);

	if (nvme == NULL)
		return (DDI_FAILURE);

	nvme_shutdown(nvme, NVME_CC_SHN_ABRUPT, B_TRUE);

	(void) nvme_reset(nvme, B_TRUE);

	return (DDI_FAILURE);
}

static int
nvme_fill_prp(nvme_cmd_t *cmd, bd_xfer_t *xfer)
{
	nvme_t *nvme = cmd->nc_nvme;
	int nprp_page, nprp;
	uint64_t *prp;

	if (xfer->x_ndmac == 0)
		return (DDI_FAILURE);

	cmd->nc_sqe.sqe_dptr.d_prp[0] = xfer->x_dmac.dmac_laddress;
	ddi_dma_nextcookie(xfer->x_dmah, &xfer->x_dmac);

	if (xfer->x_ndmac == 1) {
		cmd->nc_sqe.sqe_dptr.d_prp[1] = 0;
		return (DDI_SUCCESS);
	} else if (xfer->x_ndmac == 2) {
		cmd->nc_sqe.sqe_dptr.d_prp[1] = xfer->x_dmac.dmac_laddress;
		return (DDI_SUCCESS);
	}

	xfer->x_ndmac--;

	nprp_page = nvme->n_pagesize / sizeof (uint64_t) - 1;
	ASSERT(nprp_page > 0);
	nprp = (xfer->x_ndmac + nprp_page - 1) / nprp_page;

	/*
	 * We currently don't support chained PRPs and set up our DMA
	 * attributes to reflect that. If we still get an I/O request
	 * that needs a chained PRP something is very wrong.
	 */
	VERIFY(nprp == 1);

	cmd->nc_dma = kmem_cache_alloc(nvme->n_prp_cache, KM_SLEEP);
	bzero(cmd->nc_dma->nd_memp, cmd->nc_dma->nd_len);

	cmd->nc_sqe.sqe_dptr.d_prp[1] = cmd->nc_dma->nd_cookie.dmac_laddress;

	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	for (prp = (uint64_t *)cmd->nc_dma->nd_memp;
	    xfer->x_ndmac > 0;
	    prp++, xfer->x_ndmac--) {
		*prp = xfer->x_dmac.dmac_laddress;
		ddi_dma_nextcookie(xfer->x_dmah, &xfer->x_dmac);
	}

	(void) ddi_dma_sync(cmd->nc_dma->nd_dmah, 0, cmd->nc_dma->nd_len,
	    DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
}

static nvme_cmd_t *
nvme_create_nvm_cmd(nvme_namespace_t *ns, uint8_t opc, bd_xfer_t *xfer)
{
	nvme_t *nvme = ns->ns_nvme;
	nvme_cmd_t *cmd;

	/*
	 * Blkdev only sets BD_XFER_POLL when dumping, so don't sleep.
	 */
	cmd = nvme_alloc_cmd(nvme, (xfer->x_flags & BD_XFER_POLL) ?
	    KM_NOSLEEP : KM_SLEEP);

	if (cmd == NULL)
		return (NULL);

	cmd->nc_sqe.sqe_opc = opc;
	cmd->nc_callback = nvme_bd_xfer_done;
	cmd->nc_xfer = xfer;

	switch (opc) {
	case NVME_OPC_NVM_WRITE:
	case NVME_OPC_NVM_READ:
		VERIFY(xfer->x_nblks <= 0x10000);

		cmd->nc_sqe.sqe_nsid = ns->ns_id;

		cmd->nc_sqe.sqe_cdw10 = xfer->x_blkno & 0xffffffffu;
		cmd->nc_sqe.sqe_cdw11 = (xfer->x_blkno >> 32);
		cmd->nc_sqe.sqe_cdw12 = (uint16_t)(xfer->x_nblks - 1);

		if (nvme_fill_prp(cmd, xfer) != DDI_SUCCESS)
			goto fail;
		break;

	case NVME_OPC_NVM_FLUSH:
		cmd->nc_sqe.sqe_nsid = ns->ns_id;
		break;

	default:
		goto fail;
	}

	return (cmd);

fail:
	nvme_free_cmd(cmd);
	return (NULL);
}

static void
nvme_bd_xfer_done(void *arg)
{
	nvme_cmd_t *cmd = arg;
	bd_xfer_t *xfer = cmd->nc_xfer;
	int error = 0;

	error = nvme_check_cmd_status(cmd);
	nvme_free_cmd(cmd);

	bd_xfer_done(xfer, error);
}

static void
nvme_bd_driveinfo(void *arg, bd_drive_t *drive)
{
	nvme_namespace_t *ns = arg;
	nvme_t *nvme = ns->ns_nvme;

	/*
	 * blkdev maintains one queue size per instance (namespace),
	 * but all namespace share the I/O queues.
	 * TODO: need to figure out a sane default, or use per-NS I/O queues,
	 * or change blkdev to handle EAGAIN
	 */
	drive->d_qsize = nvme->n_ioq_count * nvme->n_io_queue_len
	    / nvme->n_namespace_count;

	/*
	 * d_maxxfer is not set, which means the value is taken from the DMA
	 * attributes specified to bd_alloc_handle.
	 */

	drive->d_removable = B_FALSE;
	drive->d_hotpluggable = B_FALSE;

	bcopy(ns->ns_eui64, drive->d_eui64, sizeof (drive->d_eui64));
	drive->d_target = ns->ns_id;
	drive->d_lun = 0;

	drive->d_model = nvme->n_idctl->id_model;
	drive->d_model_len = sizeof (nvme->n_idctl->id_model);
	drive->d_vendor = nvme->n_vendor;
	drive->d_vendor_len = strlen(nvme->n_vendor);
	drive->d_product = nvme->n_product;
	drive->d_product_len = strlen(nvme->n_product);
	drive->d_serial = nvme->n_idctl->id_serial;
	drive->d_serial_len = sizeof (nvme->n_idctl->id_serial);
	drive->d_revision = nvme->n_idctl->id_fwrev;
	drive->d_revision_len = sizeof (nvme->n_idctl->id_fwrev);
}

static int
nvme_bd_mediainfo(void *arg, bd_media_t *media)
{
	nvme_namespace_t *ns = arg;

	media->m_nblks = ns->ns_block_count;
	media->m_blksize = ns->ns_block_size;
	media->m_readonly = B_FALSE;
	media->m_solidstate = B_TRUE;

	media->m_pblksize = ns->ns_best_block_size;

	return (0);
}

static int
nvme_bd_cmd(nvme_namespace_t *ns, bd_xfer_t *xfer, uint8_t opc)
{
	nvme_t *nvme = ns->ns_nvme;
	nvme_cmd_t *cmd;

	if (nvme->n_dead)
		return (EIO);

	/* No polling for now */
	if (xfer->x_flags & BD_XFER_POLL)
		return (EIO);

	cmd = nvme_create_nvm_cmd(ns, opc, xfer);
	if (cmd == NULL)
		return (ENOMEM);

	cmd->nc_sqid = (CPU->cpu_id % nvme->n_ioq_count) + 1;
	ASSERT(cmd->nc_sqid <= nvme->n_ioq_count);

	if (nvme_submit_cmd(nvme->n_ioq[cmd->nc_sqid], cmd)
	    != DDI_SUCCESS)
		return (EAGAIN);

	return (0);
}

static int
nvme_bd_read(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_READ));
}

static int
nvme_bd_write(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_WRITE));
}

static int
nvme_bd_sync(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	if (ns->ns_nvme->n_dead)
		return (EIO);

	/*
	 * If the volatile write cache is not present or not enabled the FLUSH
	 * command is a no-op, so we can take a shortcut here.
	 */
	if (!ns->ns_nvme->n_write_cache_present) {
		bd_xfer_done(xfer, ENOTSUP);
		return (0);
	}

	if (!ns->ns_nvme->n_write_cache_enabled) {
		bd_xfer_done(xfer, 0);
		return (0);
	}

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_FLUSH));
}

static int
nvme_bd_devid(void *arg, dev_info_t *devinfo, ddi_devid_t *devid)
{
	nvme_namespace_t *ns = arg;

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	if (*(uint64_t *)ns->ns_eui64 != 0) {
		return (ddi_devid_init(devinfo, DEVID_SCSI3_WWN,
		    sizeof (ns->ns_eui64), ns->ns_eui64, devid));
	} else {
		return (ddi_devid_init(devinfo, DEVID_ENCAP,
		    strlen(ns->ns_devid), ns->ns_devid, devid));
	}
}
