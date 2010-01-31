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
 * Portions Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/ddi.h>
#include <sys/archsystm.h>
#include <vm/hat_i86.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/immu.h>

/* invalidation queue table entry size */
#define	QINV_ENTRY_SIZE		0x10

/* max value of Queue Size field of Invalidation Queue Address Register */
#define	QINV_MAX_QUEUE_SIZE	0x7

/* status data size of invalidation wait descriptor */
#define	QINV_SYNC_DATA_SIZE	0x4

/* status data value of invalidation wait descriptor */
#define	QINV_SYNC_DATA_FENCE	1
#define	QINV_SYNC_DATA_UNFENCE	2

/* invalidation queue head and tail */
#define	QINV_IQA_HEAD(QH)	BITX((QH), 18, 4)
#define	QINV_IQA_TAIL_SHIFT	4

/* invalidation queue entry structure */
typedef struct qinv_inv_dsc {
	uint64_t	lo;
	uint64_t	hi;
} qinv_dsc_t;

/*
 * struct iotlb_cache_node
 *   the pending data for iotlb flush
 */
typedef struct iotlb_pend_node {
	dvcookie_t	*icn_dvcookies;  /* ptr to dvma cookie array */
	uint_t		icn_count;  /* valid cookie count */
	uint_t		icn_array_size;  /* array size */
	list_node_t	node;
} qinv_iotlb_pend_node_t;

/*
 * struct iotlb_cache_head
 *   the pending head for the iotlb flush
 */
typedef struct iotlb_pend_head {
	/* the pending node cache list */
	kmutex_t	ich_mem_lock;
	list_t		ich_mem_list;
} qinv_iotlb_pend_head_t;

/*
 * qinv_iotlb_t
 *   pending data for qiueued invalidation iotlb flush
 */
typedef struct qinv_iotlb {
	dvcookie_t	*qinv_iotlb_dvcookies;
	uint_t		qinv_iotlb_count;
	uint_t		qinv_iotlb_size;
	list_node_t	qinv_iotlb_node;
} qinv_iotlb_t;

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
 * qinv_iotlb_pend_node	- pending iotlb node
 */
typedef struct qinv {
	qinv_mem_t		qinv_table;
	qinv_mem_t		qinv_sync;
	qinv_iotlb_pend_head_t qinv_pend_head;
	qinv_iotlb_pend_node_t  **qinv_iotlb_pend_node;
} qinv_t;


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
static uint_t qinv_alloc_sync_mem_entry(immu_t *immu);
static void qinv_wait_async_unfence(immu_t *immu,
    qinv_iotlb_pend_node_t *node);
static void qinv_wait_sync(immu_t *immu);
static int qinv_wait_async_finish(immu_t *immu, int *count);
/*LINTED*/
static void qinv_wait_async_fence(immu_t *immu);
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

	qinv = (qinv_t *)immu->immu_qinv;
	qinv_table = &(qinv->qinv_table);

	mutex_enter(&qinv_table->qinv_mem_lock);
	tail = qinv_table->qinv_mem_tail;
	qinv_table->qinv_mem_tail++;

	if (qinv_table->qinv_mem_tail == qinv_table->qinv_mem_size)
		qinv_table->qinv_mem_tail = 0;

	while (qinv_table->qinv_mem_head == qinv_table->qinv_mem_tail) {
		/*
		 * inv queue table exhausted, wait hardware to fetch
		 * next descriptor
		 */
		qinv_table->qinv_mem_head = QINV_IQA_HEAD(
		    immu_regs_get64(immu, IMMU_REG_INVAL_QH));
	}

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
 * alloc free entry from sync status table
 */
static uint_t
qinv_alloc_sync_mem_entry(immu_t *immu)
{
	qinv_mem_t *sync_mem;
	uint_t tail;
	qinv_t *qinv;

	qinv = (qinv_t *)immu->immu_qinv;
	sync_mem = &qinv->qinv_sync;

sync_mem_exhausted:
	mutex_enter(&sync_mem->qinv_mem_lock);
	tail = sync_mem->qinv_mem_tail;
	sync_mem->qinv_mem_tail++;
	if (sync_mem->qinv_mem_tail == sync_mem->qinv_mem_size)
		sync_mem->qinv_mem_tail = 0;

	if (sync_mem->qinv_mem_head == sync_mem->qinv_mem_tail) {
		/* should never happen */
		ddi_err(DER_WARN, NULL, "sync mem exhausted");
		sync_mem->qinv_mem_tail = tail;
		mutex_exit(&sync_mem->qinv_mem_lock);
		delay(IMMU_ALLOC_RESOURCE_DELAY);
		goto sync_mem_exhausted;
	}
	mutex_exit(&sync_mem->qinv_mem_lock);

	return (tail);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   fence flag not set, need status data to indicate the invalidation
 *   wait descriptor completion
 */
static void
qinv_wait_async_unfence(immu_t *immu, qinv_iotlb_pend_node_t *node)
{
	qinv_dsc_t dsc;
	qinv_mem_t *sync_mem;
	uint64_t saddr;
	uint_t tail;
	qinv_t *qinv;

	qinv = (qinv_t *)immu->immu_qinv;
	sync_mem = &qinv->qinv_sync;
	tail = qinv_alloc_sync_mem_entry(immu);

	/* plant an iotlb pending node */
	qinv->qinv_iotlb_pend_node[tail] = node;

	saddr = sync_mem->qinv_mem_paddr + tail * QINV_SYNC_DATA_SIZE;

	/*
	 * sdata = QINV_SYNC_DATA_UNFENCE, fence = 0, sw = 1, if = 0
	 * indicate the invalidation wait descriptor completion by
	 * performing a coherent DWORD write to the status address,
	 * not by generating an invalidation completion event
	 */
	dsc.lo = INV_WAIT_DSC_LOW(QINV_SYNC_DATA_UNFENCE, 0, 1, 0);
	dsc.hi = INV_WAIT_DSC_HIGH(saddr);

	qinv_submit_inv_dsc(immu, &dsc);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   fence flag set, indicate descriptors following the invalidation
 *   wait descriptor must be processed by hardware only after the
 *   invalidation wait descriptor completes.
 */
static void
qinv_wait_async_fence(immu_t *immu)
{
	qinv_dsc_t dsc;

	/* sw = 0, fence = 1, iflag = 0 */
	dsc.lo = INV_WAIT_DSC_LOW(0, 1, 0, 0);
	dsc.hi = 0;
	qinv_submit_inv_dsc(immu, &dsc);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   wait until the invalidation request finished
 */
static void
qinv_wait_sync(immu_t *immu)
{
	qinv_dsc_t dsc;
	qinv_mem_t *sync_mem;
	uint64_t saddr;
	uint_t tail;
	qinv_t *qinv;
	volatile uint32_t *status;

	qinv = (qinv_t *)immu->immu_qinv;
	sync_mem = &qinv->qinv_sync;
	tail = qinv_alloc_sync_mem_entry(immu);
	saddr = sync_mem->qinv_mem_paddr + tail * QINV_SYNC_DATA_SIZE;
	status = (uint32_t *)(sync_mem->qinv_mem_vaddr + tail *
	    QINV_SYNC_DATA_SIZE);

	/*
	 * sdata = QINV_SYNC_DATA_FENCE, fence = 1, sw = 1, if = 0
	 * indicate the invalidation wait descriptor completion by
	 * performing a coherent DWORD write to the status address,
	 * not by generating an invalidation completion event
	 */
	dsc.lo = INV_WAIT_DSC_LOW(QINV_SYNC_DATA_FENCE, 1, 1, 0);
	dsc.hi = INV_WAIT_DSC_HIGH(saddr);

	qinv_submit_inv_dsc(immu, &dsc);

	while ((*status) != QINV_SYNC_DATA_FENCE)
		iommu_cpu_nop();
	*status = QINV_SYNC_DATA_UNFENCE;
}

/* get already completed invalidation wait requests */
static int
qinv_wait_async_finish(immu_t *immu, int *cnt)
{
	qinv_mem_t *sync_mem;
	int index;
	qinv_t *qinv;
	volatile uint32_t *value;

	ASSERT((*cnt) == 0);

	qinv = (qinv_t *)immu->immu_qinv;
	sync_mem = &qinv->qinv_sync;

	mutex_enter(&sync_mem->qinv_mem_lock);
	index = sync_mem->qinv_mem_head;
	value = (uint32_t *)(sync_mem->qinv_mem_vaddr + index
	    * QINV_SYNC_DATA_SIZE);
	while (*value == QINV_SYNC_DATA_UNFENCE) {
		*value = 0;
		(*cnt)++;
		sync_mem->qinv_mem_head++;
		if (sync_mem->qinv_mem_head == sync_mem->qinv_mem_size) {
			sync_mem->qinv_mem_head = 0;
			value = (uint32_t *)(sync_mem->qinv_mem_vaddr);
		} else
			value = (uint32_t *)((char *)value +
			    QINV_SYNC_DATA_SIZE);
	}

	mutex_exit(&sync_mem->qinv_mem_lock);
	if ((*cnt) > 0)
		return (index);
	else
		return (-1);
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
		0xffffffffU,
		0xffffffffU,
		MMU_PAGESIZE, /* page aligned */
		0x1,
		0x1,
		0xffffffffU,
		0xffffffffU,
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

	/*
	 * init iotlb pend node for submitting invalidation iotlb
	 * queue request
	 */
	qinv->qinv_iotlb_pend_node = (qinv_iotlb_pend_node_t **)
	    kmem_zalloc(qinv->qinv_sync.qinv_mem_size
	    * sizeof (qinv_iotlb_pend_node_t *), KM_SLEEP);

	/* set invalidation queue structure */
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
void
immu_qinv_setup(list_t *listp)
{
	immu_t *immu;

	if (immu_qinv_enable == B_FALSE) {
		return;
	}

	immu = list_head(listp);
	for (; immu; immu = list_next(listp, immu)) {
		if (qinv_setup(immu) == DDI_SUCCESS) {
			immu->immu_qinv_setup = B_TRUE;
		}
	}
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
	immu->immu_qinv_running = B_TRUE;
}

/*
 * queued invalidation interface
 *   function based context cache invalidation
 */
void
immu_qinv_context_fsi(immu_t *immu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id)
{
	qinv_context_common(immu, function_mask, source_id,
	    domain_id, CTT_INV_G_DEVICE);
	qinv_wait_sync(immu);
}

/*
 * queued invalidation interface
 *   domain based context cache invalidation
 */
void
immu_qinv_context_dsi(immu_t *immu, uint_t domain_id)
{
	qinv_context_common(immu, 0, 0, domain_id, CTT_INV_G_DOMAIN);
	qinv_wait_sync(immu);
}

/*
 * queued invalidation interface
 *   invalidation global context cache
 */
void
immu_qinv_context_gbl(immu_t *immu)
{
	qinv_context_common(immu, 0, 0, 0, CTT_INV_G_GLOBAL);
	qinv_wait_sync(immu);
}

/*
 * queued invalidation interface
 *   paged based iotlb invalidation
 */
void
immu_inv_iotlb_psi(immu_t *immu, uint_t domain_id,
	uint64_t dvma, uint_t count, uint_t hint)
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
}

/*
 * queued invalidation interface
 *   domain based iotlb invalidation
 */
void
immu_qinv_iotlb_dsi(immu_t *immu, uint_t domain_id)
{
	qinv_iotlb_common(immu, domain_id, 0, 0, 0, TLB_INV_G_DOMAIN);
	qinv_wait_sync(immu);
}

/*
 * queued invalidation interface
 *    global iotlb invalidation
 */
void
immu_qinv_iotlb_gbl(immu_t *immu)
{
	qinv_iotlb_common(immu, 0, 0, 0, 0, TLB_INV_G_GLOBAL);
	qinv_wait_sync(immu);
}



/*
 * the plant wait operation for queued invalidation interface
 */
void
immu_qinv_plant(immu_t *immu, dvcookie_t *dvcookies,
	uint_t count, uint_t array_size)
{
	qinv_t *qinv;
	qinv_iotlb_pend_node_t *node = NULL;
	qinv_iotlb_pend_head_t *head;

	qinv = (qinv_t *)immu->immu_qinv;

	head = &(qinv->qinv_pend_head);
	mutex_enter(&(head->ich_mem_lock));
	node = list_head(&(head->ich_mem_list));
	if (node) {
		list_remove(&(head->ich_mem_list), node);
	}
	mutex_exit(&(head->ich_mem_lock));

	/* no cache, alloc one */
	if (node == NULL) {
		node = kmem_zalloc(sizeof (qinv_iotlb_pend_node_t), KM_SLEEP);
	}
	node->icn_dvcookies = dvcookies;
	node->icn_count = count;
	node->icn_array_size = array_size;

	/* plant an invalidation wait descriptor, not wait its completion */
	qinv_wait_async_unfence(immu, node);
}

/*
 * the reap wait operation for queued invalidation interface
 */
void
immu_qinv_reap(immu_t *immu)
{
	int index, cnt = 0;
	qinv_iotlb_pend_node_t *node;
	qinv_iotlb_pend_head_t *head;
	qinv_t *qinv;

	qinv = (qinv_t *)immu->immu_qinv;
	head = &(qinv->qinv_pend_head);

	index = qinv_wait_async_finish(immu, &cnt);

	while (cnt--) {
		node = qinv->qinv_iotlb_pend_node[index];
		if (node == NULL)
			continue;
		mutex_enter(&(head->ich_mem_lock));
		list_insert_head(&(head->ich_mem_list), node);
		mutex_exit(&(head->ich_mem_lock));
		qinv->qinv_iotlb_pend_node[index] = NULL;
		index++;
		if (index == qinv->qinv_sync.qinv_mem_size)
			index = 0;
	}
}


/* queued invalidation interface -- global invalidate interrupt entry cache */
void
immu_qinv_intr_global(immu_t *immu)
{
	qinv_iec_common(immu, 0, 0, IEC_INV_GLOBAL);
	qinv_wait_sync(immu);
}

/* queued invalidation interface -- invalidate single interrupt entry cache */
void
immu_qinv_intr_one_cache(immu_t *immu, uint_t iidx)
{
	qinv_iec_common(immu, iidx, 0, IEC_INV_INDEX);
	qinv_wait_sync(immu);
}

/* queued invalidation interface -- invalidate interrupt entry caches */
void
immu_qinv_intr_caches(immu_t *immu, uint_t iidx, uint_t cnt)
{
	uint_t	i, mask = 0;

	ASSERT(cnt != 0);

	/* requested interrupt count is not a power of 2 */
	if (!ISP2(cnt)) {
		for (i = 0; i < cnt; i++) {
			qinv_iec_common(immu, iidx + cnt, 0, IEC_INV_INDEX);
		}
		qinv_wait_sync(immu);
		return;
	}

	while ((2 << mask) < cnt) {
		mask++;
	}

	if (mask > IMMU_ECAP_GET_MHMV(immu->immu_regs_excap)) {
		for (i = 0; i < cnt; i++) {
			qinv_iec_common(immu, iidx + cnt, 0, IEC_INV_INDEX);
		}
		qinv_wait_sync(immu);
		return;
	}

	qinv_iec_common(immu, iidx, mask, IEC_INV_INDEX);

	qinv_wait_sync(immu);
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
