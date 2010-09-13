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
 * Portions Copyright (c) 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/ddi.h>
#include <sys/archsystm.h>
#include <vm/hat_i86.h>
#include <sys/types.h>
#include <sys/cpu.h>
#include <sys/sysmacros.h>
#include <sys/immu.h>

/* invalidation queue table entry size */
#define	QINV_ENTRY_SIZE		0x10

/* max value of Queue Size field of Invalidation Queue Address Register */
#define	QINV_MAX_QUEUE_SIZE	0x7

/* status data size of invalidation wait descriptor */
#define	QINV_SYNC_DATA_SIZE	0x4

/* invalidation queue head and tail */
#define	QINV_IQA_HEAD(QH)	BITX((QH), 18, 4)
#define	QINV_IQA_TAIL_SHIFT	4

/* invalidation queue entry structure */
typedef struct qinv_inv_dsc {
	uint64_t	lo;
	uint64_t	hi;
} qinv_dsc_t;

/* physical contigous pages for invalidation queue */
typedef struct qinv_mem {
	kmutex_t	   qinv_mem_lock;
	ddi_dma_handle_t   qinv_mem_dma_hdl;
	ddi_acc_handle_t   qinv_mem_acc_hdl;
	caddr_t		   qinv_mem_vaddr;
	paddr_t		   qinv_mem_paddr;
	uint_t		   qinv_mem_size;
	uint16_t	   qinv_mem_head;
	uint16_t	   qinv_mem_tail;
} qinv_mem_t;


/*
 * invalidation queue state
 *   This structure describes the state information of the
 *   invalidation queue table and related status memeory for
 *   invalidation wait descriptor
 *
 * qinv_table		- invalidation queue table
 * qinv_sync		- sync status memory for invalidation wait descriptor
 */
typedef struct qinv {
	qinv_mem_t		qinv_table;
	qinv_mem_t		qinv_sync;
} qinv_t;

static void immu_qinv_inv_wait(immu_inv_wait_t *iwp);

static struct immu_flushops immu_qinv_flushops = {
	immu_qinv_context_fsi,
	immu_qinv_context_dsi,
	immu_qinv_context_gbl,
	immu_qinv_iotlb_psi,
	immu_qinv_iotlb_dsi,
	immu_qinv_iotlb_gbl,
	immu_qinv_inv_wait
};

/* helper macro for making queue invalidation descriptor */
#define	INV_DSC_TYPE(dsc)	((dsc)->lo & 0xF)
#define	CC_INV_DSC_HIGH		(0)
#define	CC_INV_DSC_LOW(fm, sid, did, g)	(((uint64_t)(fm) << 48) | \
	((uint64_t)(sid) << 32) | \
	((uint64_t)(did) << 16) | \
	((uint64_t)(g) << 4) | \
	1)

#define	IOTLB_INV_DSC_HIGH(addr, ih, am) (((uint64_t)(addr)) | \
	((uint64_t)(ih) << 6) |	\
	((uint64_t)(am)))

#define	IOTLB_INV_DSC_LOW(did, dr, dw, g) (((uint64_t)(did) << 16) | \
	((uint64_t)(dr) << 7) | \
	((uint64_t)(dw) << 6) | \
	((uint64_t)(g) << 4) | \
	2)

#define	DEV_IOTLB_INV_DSC_HIGH(addr, s) (((uint64_t)(addr)) | (s))

#define	DEV_IOTLB_INV_DSC_LOW(sid, max_invs_pd) ( \
	((uint64_t)(sid) << 32) | \
	((uint64_t)(max_invs_pd) << 16) | \
	3)

#define	IEC_INV_DSC_HIGH (0)
#define	IEC_INV_DSC_LOW(idx, im, g) (((uint64_t)(idx) << 32) | \
	((uint64_t)(im) << 27) | \
	((uint64_t)(g) << 4) | \
	4)

#define	INV_WAIT_DSC_HIGH(saddr) ((uint64_t)(saddr))

#define	INV_WAIT_DSC_LOW(sdata, fn, sw, iflag) (((uint64_t)(sdata) << 32) | \
	((uint64_t)(fn) << 6) | \
	((uint64_t)(sw) << 5) | \
	((uint64_t)(iflag) << 4) | \
	5)

/*
 * QS field of Invalidation Queue Address Register
 * the size of invalidation queue is 1 << (qinv_iqa_qs + 8)
 */
static uint_t qinv_iqa_qs = 6;

/*
 * the invalidate desctiptor type of queued invalidation interface
 */
static char *qinv_dsc_type[] = {
	"Reserved",
	"Context Cache Invalidate Descriptor",
	"IOTLB Invalidate Descriptor",
	"Device-IOTLB Invalidate Descriptor",
	"Interrupt Entry Cache Invalidate Descriptor",
	"Invalidation Wait Descriptor",
	"Incorrect queue invalidation type"
};

#define	QINV_MAX_DSC_TYPE	(sizeof (qinv_dsc_type) / sizeof (char *))

/*
 * the queued invalidation interface functions
 */
static void qinv_submit_inv_dsc(immu_t *immu, qinv_dsc_t *dsc);
static void qinv_context_common(immu_t *immu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, ctt_inv_g_t type);
static void qinv_iotlb_common(immu_t *immu, uint_t domain_id,
    uint64_t addr, uint_t am, uint_t hint, tlb_inv_g_t type);
static void qinv_iec_common(immu_t *immu, uint_t iidx,
    uint_t im, uint_t g);
static void immu_qinv_inv_wait(immu_inv_wait_t *iwp);
static void qinv_wait_sync(immu_t *immu, immu_inv_wait_t *iwp);
/*LINTED*/
static void qinv_dev_iotlb_common(immu_t *immu, uint16_t sid,
    uint64_t addr, uint_t size, uint_t max_invs_pd);


/* submit invalidation request descriptor to invalidation queue */
static void
qinv_submit_inv_dsc(immu_t *immu, qinv_dsc_t *dsc)
{
	qinv_t *qinv;
	qinv_mem_t *qinv_table;
	uint_t tail;
#ifdef DEBUG
	uint_t count = 0;
#endif

	qinv = (qinv_t *)immu->immu_qinv;
	qinv_table = &(qinv->qinv_table);

	mutex_enter(&qinv_table->qinv_mem_lock);
	tail = qinv_table->qinv_mem_tail;
	qinv_table->qinv_mem_tail++;

	if (qinv_table->qinv_mem_tail == qinv_table->qinv_mem_size)
		qinv_table->qinv_mem_tail = 0;

	while (qinv_table->qinv_mem_head == qinv_table->qinv_mem_tail) {
#ifdef DEBUG
		count++;
#endif
		/*
		 * inv queue table exhausted, wait hardware to fetch
		 * next descriptor
		 */
		qinv_table->qinv_mem_head = QINV_IQA_HEAD(
		    immu_regs_get64(immu, IMMU_REG_INVAL_QH));
	}

	IMMU_DPROBE3(immu__qinv__sub, uint64_t, dsc->lo, uint64_t, dsc->hi,
	    uint_t, count);

	bcopy(dsc, qinv_table->qinv_mem_vaddr + tail * QINV_ENTRY_SIZE,
	    QINV_ENTRY_SIZE);

	immu_regs_put64(immu, IMMU_REG_INVAL_QT,
	    qinv_table->qinv_mem_tail << QINV_IQA_TAIL_SHIFT);

	mutex_exit(&qinv_table->qinv_mem_lock);
}

/* queued invalidation interface -- invalidate context cache */
static void
qinv_context_common(immu_t *immu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, ctt_inv_g_t type)
{
	qinv_dsc_t dsc;

	dsc.lo = CC_INV_DSC_LOW(function_mask, source_id, domain_id, type);
	dsc.hi = CC_INV_DSC_HIGH;

	qinv_submit_inv_dsc(immu, &dsc);
}

/* queued invalidation interface -- invalidate iotlb */
static void
qinv_iotlb_common(immu_t *immu, uint_t domain_id,
    uint64_t addr, uint_t am, uint_t hint, tlb_inv_g_t type)
{
	qinv_dsc_t dsc;
	uint8_t dr = 0;
	uint8_t dw = 0;

	if (IMMU_CAP_GET_DRD(immu->immu_regs_cap))
		dr = 1;
	if (IMMU_CAP_GET_DWD(immu->immu_regs_cap))
		dw = 1;

	switch (type) {
	case TLB_INV_G_PAGE:
		if (!IMMU_CAP_GET_PSI(immu->immu_regs_cap) ||
		    am > IMMU_CAP_GET_MAMV(immu->immu_regs_cap) ||
		    addr & IMMU_PAGEOFFSET) {
			type = TLB_INV_G_DOMAIN;
			goto qinv_ignore_psi;
		}
		dsc.lo = IOTLB_INV_DSC_LOW(domain_id, dr, dw, type);
		dsc.hi = IOTLB_INV_DSC_HIGH(addr, hint, am);
		break;

	qinv_ignore_psi:
	case TLB_INV_G_DOMAIN:
		dsc.lo = IOTLB_INV_DSC_LOW(domain_id, dr, dw, type);
		dsc.hi = 0;
		break;

	case TLB_INV_G_GLOBAL:
		dsc.lo = IOTLB_INV_DSC_LOW(0, dr, dw, type);
		dsc.hi = 0;
		break;
	default:
		ddi_err(DER_WARN, NULL, "incorrect iotlb flush type");
		return;
	}

	qinv_submit_inv_dsc(immu, &dsc);
}

/* queued invalidation interface -- invalidate dev_iotlb */
static void
qinv_dev_iotlb_common(immu_t *immu, uint16_t sid,
    uint64_t addr, uint_t size, uint_t max_invs_pd)
{
	qinv_dsc_t dsc;

	dsc.lo = DEV_IOTLB_INV_DSC_LOW(sid, max_invs_pd);
	dsc.hi = DEV_IOTLB_INV_DSC_HIGH(addr, size);

	qinv_submit_inv_dsc(immu, &dsc);
}

/* queued invalidation interface -- invalidate interrupt entry cache */
static void
qinv_iec_common(immu_t *immu, uint_t iidx, uint_t im, uint_t g)
{
	qinv_dsc_t dsc;

	dsc.lo = IEC_INV_DSC_LOW(iidx, im, g);
	dsc.hi = IEC_INV_DSC_HIGH;

	qinv_submit_inv_dsc(immu, &dsc);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   wait until the invalidation request finished
 */
static void
qinv_wait_sync(immu_t *immu, immu_inv_wait_t *iwp)
{
	qinv_dsc_t dsc;
	volatile uint32_t *status;
	uint64_t paddr;
#ifdef DEBUG
	uint_t count;
#endif

	status = &iwp->iwp_vstatus;
	paddr = iwp->iwp_pstatus;

	*status = IMMU_INV_DATA_PENDING;
	membar_producer();

	/*
	 * sdata = IMMU_INV_DATA_DONE, fence = 1, sw = 1, if = 0
	 * indicate the invalidation wait descriptor completion by
	 * performing a coherent DWORD write to the status address,
	 * not by generating an invalidation completion event
	 */
	dsc.lo = INV_WAIT_DSC_LOW(IMMU_INV_DATA_DONE, 1, 1, 0);
	dsc.hi = INV_WAIT_DSC_HIGH(paddr);

	qinv_submit_inv_dsc(immu, &dsc);

	if (iwp->iwp_sync) {
#ifdef DEBUG
		count = 0;
		while (*status != IMMU_INV_DATA_DONE) {
			count++;
			ht_pause();
		}
		DTRACE_PROBE2(immu__wait__sync, const char *, iwp->iwp_name,
		    uint_t, count);
#else
		while (*status != IMMU_INV_DATA_DONE)
			ht_pause();
#endif
	}
}

static void
immu_qinv_inv_wait(immu_inv_wait_t *iwp)
{
	volatile uint32_t *status = &iwp->iwp_vstatus;
#ifdef DEBUG
	uint_t count;

	count = 0;
	while (*status != IMMU_INV_DATA_DONE) {
		count++;
		ht_pause();
	}
	DTRACE_PROBE2(immu__wait__async, const char *, iwp->iwp_name,
	    uint_t, count);
#else

	while (*status != IMMU_INV_DATA_DONE)
		ht_pause();
#endif
}

/*
 * call ddi_dma_mem_alloc to allocate physical contigous
 * pages for invalidation queue table
 */
static int
qinv_setup(immu_t *immu)
{
	qinv_t *qinv;
	size_t size;

	ddi_dma_attr_t qinv_dma_attr = {
		DMA_ATTR_V0,
		0U,
		0xffffffffffffffffULL,
		0xffffffffU,
		MMU_PAGESIZE, /* page aligned */
		0x1,
		0x1,
		0xffffffffU,
		0xffffffffffffffffULL,
		1,
		4,
		0
	};

	ddi_device_acc_attr_t qinv_acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC
	};

	mutex_init(&(immu->immu_qinv_lock), NULL, MUTEX_DRIVER, NULL);


	mutex_enter(&(immu->immu_qinv_lock));

	immu->immu_qinv = NULL;
	if (!IMMU_ECAP_GET_QI(immu->immu_regs_excap) ||
	    immu_qinv_enable == B_FALSE) {
		mutex_exit(&(immu->immu_qinv_lock));
		return (DDI_SUCCESS);
	}

	if (qinv_iqa_qs > QINV_MAX_QUEUE_SIZE)
		qinv_iqa_qs = QINV_MAX_QUEUE_SIZE;

	qinv = kmem_zalloc(sizeof (qinv_t), KM_SLEEP);

	if (ddi_dma_alloc_handle(root_devinfo,
	    &qinv_dma_attr, DDI_DMA_SLEEP, NULL,
	    &(qinv->qinv_table.qinv_mem_dma_hdl)) != DDI_SUCCESS) {
		ddi_err(DER_WARN, root_devinfo,
		    "alloc invalidation queue table handler failed");
		goto queue_table_handle_failed;
	}

	if (ddi_dma_alloc_handle(root_devinfo,
	    &qinv_dma_attr, DDI_DMA_SLEEP, NULL,
	    &(qinv->qinv_sync.qinv_mem_dma_hdl)) != DDI_SUCCESS) {
		ddi_err(DER_WARN, root_devinfo,
		    "alloc invalidation queue sync mem handler failed");
		goto sync_table_handle_failed;
	}

	qinv->qinv_table.qinv_mem_size = (1 << (qinv_iqa_qs + 8));
	size = qinv->qinv_table.qinv_mem_size * QINV_ENTRY_SIZE;

	/* alloc physical contiguous pages for invalidation queue */
	if (ddi_dma_mem_alloc(qinv->qinv_table.qinv_mem_dma_hdl,
	    size,
	    &qinv_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(qinv->qinv_table.qinv_mem_vaddr),
	    &size,
	    &(qinv->qinv_table.qinv_mem_acc_hdl)) != DDI_SUCCESS) {
		ddi_err(DER_WARN, root_devinfo,
		    "alloc invalidation queue table failed");
		goto queue_table_mem_failed;
	}

	ASSERT(!((uintptr_t)qinv->qinv_table.qinv_mem_vaddr & MMU_PAGEOFFSET));
	bzero(qinv->qinv_table.qinv_mem_vaddr, size);

	/* get the base physical address of invalidation request queue */
	qinv->qinv_table.qinv_mem_paddr = pfn_to_pa(
	    hat_getpfnum(kas.a_hat, qinv->qinv_table.qinv_mem_vaddr));

	qinv->qinv_table.qinv_mem_head = qinv->qinv_table.qinv_mem_tail = 0;

	qinv->qinv_sync.qinv_mem_size = qinv->qinv_table.qinv_mem_size;
	size = qinv->qinv_sync.qinv_mem_size * QINV_SYNC_DATA_SIZE;

	/* alloc status memory for invalidation wait descriptor */
	if (ddi_dma_mem_alloc(qinv->qinv_sync.qinv_mem_dma_hdl,
	    size,
	    &qinv_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(qinv->qinv_sync.qinv_mem_vaddr),
	    &size,
	    &(qinv->qinv_sync.qinv_mem_acc_hdl)) != DDI_SUCCESS) {
		ddi_err(DER_WARN, root_devinfo,
		    "alloc invalidation queue sync mem failed");
		goto sync_table_mem_failed;
	}

	ASSERT(!((uintptr_t)qinv->qinv_sync.qinv_mem_vaddr & MMU_PAGEOFFSET));
	bzero(qinv->qinv_sync.qinv_mem_vaddr, size);
	qinv->qinv_sync.qinv_mem_paddr = pfn_to_pa(
	    hat_getpfnum(kas.a_hat, qinv->qinv_sync.qinv_mem_vaddr));

	qinv->qinv_sync.qinv_mem_head = qinv->qinv_sync.qinv_mem_tail = 0;

	mutex_init(&(qinv->qinv_table.qinv_mem_lock), NULL, MUTEX_DRIVER, NULL);
	mutex_init(&(qinv->qinv_sync.qinv_mem_lock), NULL, MUTEX_DRIVER, NULL);

	immu->immu_qinv = qinv;

	mutex_exit(&(immu->immu_qinv_lock));

	return (DDI_SUCCESS);

sync_table_mem_failed:
	ddi_dma_mem_free(&(qinv->qinv_table.qinv_mem_acc_hdl));

queue_table_mem_failed:
	ddi_dma_free_handle(&(qinv->qinv_sync.qinv_mem_dma_hdl));

sync_table_handle_failed:
	ddi_dma_free_handle(&(qinv->qinv_table.qinv_mem_dma_hdl));

queue_table_handle_failed:
	kmem_free(qinv, sizeof (qinv_t));

	mutex_exit(&(immu->immu_qinv_lock));

	return (DDI_FAILURE);
}

/*
 * ###########################################################################
 *
 * Functions exported by immu_qinv.c
 *
 * ###########################################################################
 */

/*
 * initialize invalidation request queue structure.
 */
int
immu_qinv_setup(list_t *listp)
{
	immu_t *immu;
	int nerr;

	if (immu_qinv_enable == B_FALSE) {
		return (DDI_FAILURE);
	}

	nerr = 0;
	immu = list_head(listp);
	for (; immu; immu = list_next(listp, immu)) {
		if (qinv_setup(immu) == DDI_SUCCESS) {
			immu->immu_qinv_setup = B_TRUE;
		} else {
			nerr++;
			break;
		}
	}

	return (nerr > 0 ? DDI_FAILURE : DDI_SUCCESS);
}

void
immu_qinv_startup(immu_t *immu)
{
	qinv_t *qinv;
	uint64_t qinv_reg_value;

	if (immu->immu_qinv_setup == B_FALSE) {
		return;
	}

	qinv = (qinv_t *)immu->immu_qinv;
	qinv_reg_value = qinv->qinv_table.qinv_mem_paddr | qinv_iqa_qs;
	immu_regs_qinv_enable(immu, qinv_reg_value);
	immu->immu_flushops = &immu_qinv_flushops;
	immu->immu_qinv_running = B_TRUE;
}

/*
 * queued invalidation interface
 *   function based context cache invalidation
 */
void
immu_qinv_context_fsi(immu_t *immu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, immu_inv_wait_t *iwp)
{
	qinv_context_common(immu, function_mask, source_id,
	    domain_id, CTT_INV_G_DEVICE);
	qinv_wait_sync(immu, iwp);
}

/*
 * queued invalidation interface
 *   domain based context cache invalidation
 */
void
immu_qinv_context_dsi(immu_t *immu, uint_t domain_id, immu_inv_wait_t *iwp)
{
	qinv_context_common(immu, 0, 0, domain_id, CTT_INV_G_DOMAIN);
	qinv_wait_sync(immu, iwp);
}

/*
 * queued invalidation interface
 *   invalidation global context cache
 */
void
immu_qinv_context_gbl(immu_t *immu, immu_inv_wait_t *iwp)
{
	qinv_context_common(immu, 0, 0, 0, CTT_INV_G_GLOBAL);
	qinv_wait_sync(immu, iwp);
}

/*
 * queued invalidation interface
 *   paged based iotlb invalidation
 */
void
immu_qinv_iotlb_psi(immu_t *immu, uint_t domain_id,
	uint64_t dvma, uint_t count, uint_t hint, immu_inv_wait_t *iwp)
{
	uint_t am = 0;
	uint_t max_am;

	max_am = IMMU_CAP_GET_MAMV(immu->immu_regs_cap);

	/* choose page specified invalidation */
	if (IMMU_CAP_GET_PSI(immu->immu_regs_cap)) {
		while (am <= max_am) {
			if ((ADDR_AM_OFFSET(IMMU_BTOP(dvma), am) + count)
			    <= ADDR_AM_MAX(am)) {
				qinv_iotlb_common(immu, domain_id,
				    dvma, am, hint, TLB_INV_G_PAGE);
				break;
			}
			am++;
		}
		if (am > max_am) {
			qinv_iotlb_common(immu, domain_id,
			    dvma, 0, hint, TLB_INV_G_DOMAIN);
		}

	/* choose domain invalidation */
	} else {
		qinv_iotlb_common(immu, domain_id, dvma,
		    0, hint, TLB_INV_G_DOMAIN);
	}

	qinv_wait_sync(immu, iwp);
}

/*
 * queued invalidation interface
 *   domain based iotlb invalidation
 */
void
immu_qinv_iotlb_dsi(immu_t *immu, uint_t domain_id, immu_inv_wait_t *iwp)
{
	qinv_iotlb_common(immu, domain_id, 0, 0, 0, TLB_INV_G_DOMAIN);
	qinv_wait_sync(immu, iwp);
}

/*
 * queued invalidation interface
 *    global iotlb invalidation
 */
void
immu_qinv_iotlb_gbl(immu_t *immu, immu_inv_wait_t *iwp)
{
	qinv_iotlb_common(immu, 0, 0, 0, 0, TLB_INV_G_GLOBAL);
	qinv_wait_sync(immu, iwp);
}

/* queued invalidation interface -- global invalidate interrupt entry cache */
void
immu_qinv_intr_global(immu_t *immu, immu_inv_wait_t *iwp)
{
	qinv_iec_common(immu, 0, 0, IEC_INV_GLOBAL);
	qinv_wait_sync(immu, iwp);
}

/* queued invalidation interface -- invalidate single interrupt entry cache */
void
immu_qinv_intr_one_cache(immu_t *immu, uint_t iidx, immu_inv_wait_t *iwp)
{
	qinv_iec_common(immu, iidx, 0, IEC_INV_INDEX);
	qinv_wait_sync(immu, iwp);
}

/* queued invalidation interface -- invalidate interrupt entry caches */
void
immu_qinv_intr_caches(immu_t *immu, uint_t iidx, uint_t cnt,
    immu_inv_wait_t *iwp)
{
	uint_t	i, mask = 0;

	ASSERT(cnt != 0);

	/* requested interrupt count is not a power of 2 */
	if (!ISP2(cnt)) {
		for (i = 0; i < cnt; i++) {
			qinv_iec_common(immu, iidx + cnt, 0, IEC_INV_INDEX);
		}
		qinv_wait_sync(immu, iwp);
		return;
	}

	while ((2 << mask) < cnt) {
		mask++;
	}

	if (mask > IMMU_ECAP_GET_MHMV(immu->immu_regs_excap)) {
		for (i = 0; i < cnt; i++) {
			qinv_iec_common(immu, iidx + cnt, 0, IEC_INV_INDEX);
		}
		qinv_wait_sync(immu, iwp);
		return;
	}

	qinv_iec_common(immu, iidx, mask, IEC_INV_INDEX);

	qinv_wait_sync(immu, iwp);
}

void
immu_qinv_report_fault(immu_t *immu)
{
	uint16_t head;
	qinv_dsc_t *dsc;
	qinv_t *qinv;

	/* access qinv data */
	mutex_enter(&(immu->immu_qinv_lock));

	qinv = (qinv_t *)(immu->immu_qinv);

	head = QINV_IQA_HEAD(
	    immu_regs_get64(immu, IMMU_REG_INVAL_QH));

	dsc = (qinv_dsc_t *)(qinv->qinv_table.qinv_mem_vaddr
	    + (head * QINV_ENTRY_SIZE));

	/* report the error */
	ddi_err(DER_WARN, immu->immu_dip,
	    "generated a fault when fetching a descriptor from the"
	    "\tinvalidation queue, or detects that the fetched"
	    "\tdescriptor is invalid. The head register is "
	    "0x%" PRIx64
	    "\tthe type is %s",
	    head,
	    qinv_dsc_type[MIN(INV_DSC_TYPE(dsc), QINV_MAX_DSC_TYPE)]);

	mutex_exit(&(immu->immu_qinv_lock));
}
