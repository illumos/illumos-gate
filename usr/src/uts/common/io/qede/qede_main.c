/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/


#include "qede.h"

ddi_device_acc_attr_t qede_regs_acc_attr = {					
	DDI_DEVICE_ATTR_V1,     // devacc_attr_version;				
	DDI_STRUCTURE_LE_ACC,   // devacc_attr_endian_flags;				
	DDI_STRICTORDER_ACC,    // devacc_attr_dataorder;				
	DDI_FLAGERR_ACC         // devacc_attr_access;
};

ddi_device_acc_attr_t qede_desc_acc_attr = {
	DDI_DEVICE_ATTR_V0,    // devacc_attr_version;		
	DDI_STRUCTURE_LE_ACC,  // devacc_attr_endian_flags;
	DDI_STRICTORDER_ACC    // devacc_attr_dataorder;		
};

/*
 * DMA access attributes for BUFFERS.
 */
ddi_device_acc_attr_t qede_buf_acc_attr = 
{					
	DDI_DEVICE_ATTR_V0,   // devacc_attr_version;						
	DDI_NEVERSWAP_ACC,    // devacc_attr_endian_flags;				
	DDI_STRICTORDER_ACC   // devacc_attr_dataorder;						
};																


ddi_dma_attr_t qede_desc_dma_attr = 
{
	DMA_ATTR_V0,
	0x0000000000000000ull,
	0xFFFFFFFFFFFFFFFFull,
	0x00000000FFFFFFFFull,
	QEDE_PAGE_ALIGNMENT,
	0x00000FFF,
	0x00000001,
	0x00000000FFFFFFFFull,
	0xFFFFFFFFFFFFFFFFull,
	1,
	0x00000001,
	DDI_DMA_FLAGERR
};

ddi_dma_attr_t qede_gen_buf_dma_attr = 
{
	DMA_ATTR_V0,
	0x0000000000000000ull,
	0xFFFFFFFFFFFFFFFFull,
	0x00000000FFFFFFFFull,
	QEDE_PAGE_ALIGNMENT,
	0x00000FFF,
	0x00000001,
	0x00000000FFFFFFFFull,
	0xFFFFFFFFFFFFFFFFull,
	1,
	0x00000001,
	DDI_DMA_FLAGERR
};

/*
 * DMA attributes for transmit.
 */
ddi_dma_attr_t qede_tx_buf_dma_attr = 
{
	DMA_ATTR_V0,
	0x0000000000000000ull,
	0xFFFFFFFFFFFFFFFFull,
	0x00000000FFFFFFFFull,
	1,
	0x00000FFF,
	0x00000001,
	0x00000000FFFFFFFFull,
	0xFFFFFFFFFFFFFFFFull,
	ETH_TX_MAX_BDS_PER_NON_LSO_PACKET - 1,
	0x00000001,
	DDI_DMA_FLAGERR
};


ddi_dma_attr_t qede_dma_attr_desc = 
{
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffffull,	/* dma_attr_addr_hi */
	0x000fffffull,		/* dma_attr_count_max */
	4096,			/* dma_attr_align */
	0x000fffffull,		/* dma_attr_burstsizes */
	4,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer */
	0xffffffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	DDI_DMA_FLAGERR		/* dma_attr_flags */
};

static ddi_dma_attr_t qede_dma_attr_txbuf = 
{
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffffull,	/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,	/* dma_attr_count_max */
	QEDE_PAGE_ALIGNMENT, /* dma_attr_align */
	0xfff8ull,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

ddi_dma_attr_t qede_dma_attr_rxbuf = 
{
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffffull,	/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,	/* dma counter max */
	QEDE_PAGE_ALIGNMENT,	/* dma_attr_align */
	0xfff8ull,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	DDI_DMA_RELAXED_ORDERING	/* dma_attr_flags */
};

/* LINTED E_STATIC_UNUSED */
static ddi_dma_attr_t qede_dma_attr_cmddesc = 
{
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffffull,	/* dma_attr_addr_hi */
	0xffffffffull,		/* dma_attr_count_max */
	1,			/* dma_attr_align */
	0xfff8ull,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffff,		/* dma_attr_maxxfer */
	0xffffffff,		/* dma_attr_seg */
	ETH_TX_MAX_BDS_PER_NON_LSO_PACKET,	/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};



/*
 * Generic dma attribute for single sg
 */
/* LINTED E_STATIC_UNUSED */
static ddi_dma_attr_t qede_gen_dma_attr_desc = 
{
	DMA_ATTR_V0,            /* dma_attr_version */
	0,                      /* dma_attr_addr_lo */
	0xffffffffffffffffull,	/* dma_attr_addr_hi */
	0x000fffffull,          /* dma_attr_count_max */
	4096,                   /* dma_attr_align */
	0x000fffffull,          /* dma_attr_burstsizes */
	4,                      /* dma_attr_minxfer */
	0xffffffffull,          /* dma_attr_maxxfer */
	0xffffffffull,          /* dma_attr_seg */
	1,                      /* dma_attr_sgllen */
	1,                      /* dma_attr_granular */
	DDI_DMA_FLAGERR         /* dma_attr_flags */
};

ddi_dma_attr_t qede_buf2k_dma_attr_txbuf = 
{
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffffull,	/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,	/* dma_attr_count_max */
	BUF_2K_ALIGNMENT,	/* dma_attr_align */
	0xfff8ull,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	1,			/* dma_attr_sgllen */
	0x00000001,		/* dma_attr_granular */
	0			/* dma_attr_flags */
};

char * 
qede_get_ddi_fail(int status)
{
	switch (status) {
	case DDI_FAILURE:
		return ("DDI_FAILURE");
	case DDI_NOT_WELL_FORMED:
		return ("DDI_NOT_WELL_FORMED");
	case DDI_EAGAIN:
		return ("DDI_EAGAIN");
	case DDI_EINVAL:
		return ("DDI_EINVAL");
	case DDI_ENOTSUP:
		return ("DDI_ENOTSUP");
	case DDI_EPENDING:
		return ("DDI_EPENDING");
	case DDI_EALREADY:
		return ("DDI_EALREADY");
	case DDI_ENOMEM:
		return ("DDI_ENOMEM");
	case DDI_EBUSY:
		return ("DDI_EBUSY");
	case DDI_ETRANSPORT:
		return ("DDI_ETRANSPORT");
	case DDI_ECONTEXT:
		return ("DDI_ECONTEXT");
	default:
		return ("ERROR CODE NOT FOUND!");
	}
}

char *
qede_get_ecore_fail(int status)
{
	switch (status) {
	case ECORE_UNKNOWN_ERROR:
		return ("ECORE_UNKNOWN_ERROR");
	case ECORE_NORESOURCES:
		return ("ECORE_NORESOURCES");
	case ECORE_NODEV:
		return ("ECORE_NODEV");
	case ECORE_ABORTED:
		return ("ECORE_ABORTED");
	case ECORE_AGAIN:
		return ("ECORE_AGAIN");
	case ECORE_NOTIMPL:
		return ("ECORE_NOTIMPL");
	case ECORE_EXISTS:
		return ("ECORE_EXISTS");
	case ECORE_IO:
		return ("ECORE_IO");
	case ECORE_TIMEOUT:
		return ("ECORE_TIMEOUT");
	case ECORE_INVAL:
		return ("ECORE_INVAL");
	case ECORE_BUSY:
		return ("ECORE_BUSY");
	case ECORE_NOMEM:
		return ("ECORE_NOMEM");
	case ECORE_SUCCESS:
		return ("ECORE_SUCCESS");
	case ECORE_PENDING:
		return ("ECORE_PENDING");
	default:
		return ("ECORE ERROR CODE NOT FOUND!");
	}
}

#define QEDE_CHIP_NUM(_p)\
 (((_p)->edev.chip_num) & 0xffff)

char *
qede_chip_name(qede_t *qede)
{
    switch (QEDE_CHIP_NUM(qede)) {
        case 0x1634: 
		return ("BCM57980E");

        case 0x1629: 
		return ("BCM57980S");

        case 0x1630: 
		return ("BCM57940_KR2");

	case 0x8070: 
		return ("ARROWHEAD");

	case 0x8071: 
		return ("ARROWHEAD");

	case 0x8072: 
		return ("ARROWHEAD");	     

	case 0x8073: 
		return ("ARROWHEAD");	     

        default:     
		return ("UNKNOWN");
    }
}

	


static void
qede_destroy_locks(qede_t *qede)
{
	qede_fastpath_t *fp = &qede->fp_array[0];
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;
	int i, j;

	mutex_destroy(&qede->drv_lock);
	mutex_destroy(&qede->watch_lock);

	for (i = 0; i < qede->num_fp; i++, fp++) {
		mutex_destroy(&fp->fp_lock);

		rx_ring = fp->rx_ring;
		mutex_destroy(&rx_ring->rx_lock);
		mutex_destroy(&rx_ring->rx_replen_lock);

		for (j = 0; j < qede->num_tc; j++) {
			tx_ring = fp->tx_ring[j];
			mutex_destroy(&tx_ring->tx_lock);
		}
	}
	mutex_destroy(&qede->gld_lock);
	mutex_destroy(&qede->kstat_lock);
}

static void
qede_init_locks(qede_t *qede)
{
	qede_intr_context_t *intr_ctx = &qede->intr_ctx;
	qede_fastpath_t *fp = &qede->fp_array[0];
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;
	int i, tc;

	mutex_init(&qede->drv_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));
	mutex_init(&qede->watch_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));

	for (i = 0; i < qede->num_fp; i++, fp++) {
		mutex_init(&fp->fp_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));

		rx_ring = fp->rx_ring;
		mutex_init(&rx_ring->rx_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));
		mutex_init(&rx_ring->rx_replen_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));

		for (tc = 0; tc < qede->num_tc; tc++) {
			tx_ring = fp->tx_ring[tc];
			mutex_init(&tx_ring->tx_lock, NULL,
		    	    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));
		}
	}

	mutex_init(&qede->gld_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));
	mutex_init(&qede->kstat_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(intr_ctx->intr_pri));
}

/* LINTED E_FUNC_ARG_UNUSED */
static void qede_free_io_structs(qede_t *qede)
{
}

static int
qede_alloc_io_structs(qede_t *qede)
{
	qede_fastpath_t *fp;
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_array, *tx_ring;
	int i, tc;

	/*
	 * Put rx ring + tx_ring pointers paired
	 * into the fp data structure array
	 */
	for (i = 0; i < qede->num_fp; i++) {
		fp = &qede->fp_array[i];
		rx_ring = &qede->rx_array[i];

		for (tc = 0; tc < qede->num_tc; tc++) {
			tx_array = qede->tx_array[tc];
			tx_ring = &tx_array[i];
			fp->tx_ring[tc] = tx_ring;
		}

		fp->rx_ring = rx_ring;
		rx_ring->group_index = 0;
	}
	
	return (DDI_SUCCESS);
}

static int
qede_get_config_params(qede_t *qede)
{
	struct ecore_dev *edev = &qede->edev;

	qede_cfg_init(qede);

	qede->num_tc = DEFAULT_TRFK_CLASS_COUNT;
	qede->num_hwfns = edev->num_hwfns;
	qede->rx_buf_count = qede->rx_ring_size;
	qede->rx_buf_size = DEFAULT_RX_BUF_SIZE;
	qede_print("!%s:%d: qede->num_fp = %d\n", __func__, qede->instance, 
		qede->num_fp);
	qede_print("!%s:%d: qede->rx_ring_size = %d\n", __func__, 
		qede->instance, qede->rx_ring_size);
	qede_print("!%s:%d: qede->rx_buf_count = %d\n", __func__, 
		qede->instance, qede->rx_buf_count);
	qede_print("!%s:%d: qede->rx_buf_size = %d\n", __func__, 
		qede->instance, qede->rx_buf_size);
	qede_print("!%s:%d: qede->rx_copy_threshold = %d\n", __func__, 
		qede->instance, qede->rx_copy_threshold);
	qede_print("!%s:%d: qede->tx_ring_size = %d\n", __func__, 
		qede->instance, qede->tx_ring_size);
	qede_print("!%s:%d: qede->tx_copy_threshold = %d\n", __func__, 
		qede->instance, qede->tx_bcopy_threshold);
	qede_print("!%s:%d: qede->lso_enable = %d\n", __func__, 
		qede->instance, qede->lso_enable);
	qede_print("!%s:%d: qede->lro_enable = %d\n", __func__, 
		qede->instance, qede->lro_enable);
	qede_print("!%s:%d: qede->jumbo_enable = %d\n", __func__, 
		qede->instance, qede->jumbo_enable);
	qede_print("!%s:%d: qede->log_enable = %d\n", __func__, 
		qede->instance, qede->log_enable);
	qede_print("!%s:%d: qede->checksum = %d\n", __func__, 
		qede->instance, qede->checksum);
	qede_print("!%s:%d: qede->debug_level = 0x%x\n", __func__, 
		qede->instance, qede->ecore_debug_level);
	qede_print("!%s:%d: qede->num_hwfns = %d\n", __func__, 
		qede->instance,qede->num_hwfns);

	//qede->tx_buf_size = qede->mtu + QEDE_MAX_ETHER_HDR;
	qede->tx_buf_size = BUF_2K_SIZE;
	return (DDI_SUCCESS);
}

void 
qede_config_debug(qede_t *qede)
{

	struct ecore_dev *edev = &qede->edev;
	u32 dp_level = 0;
	u8 dp_module = 0;

	dp_level = qede->ecore_debug_level;
	dp_module = qede->ecore_debug_module;
	ecore_init_dp(edev, dp_module, dp_level, NULL);
}



static int
qede_set_operating_params(qede_t *qede)
{
	int status = 0;
	qede_intr_context_t *intr_ctx = &qede->intr_ctx;

	/* Get qede.conf paramters from user */
	status = qede_get_config_params(qede);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	/* config debug level */
	qede_config_debug(qede);


	intr_ctx->intr_vect_to_request = 
		qede->num_fp + qede->num_hwfns; 
	intr_ctx->intr_fp_vector_count = qede->num_fp - qede->num_hwfns;

	/* set max number of Unicast list */
	qede->ucst_total = QEDE_MAX_UCST_CNT;
	qede->ucst_avail = QEDE_MAX_UCST_CNT;
	bzero(&qede->ucst_mac[0], sizeof (qede_mac_addr_t) * qede->ucst_total);
	qede->params.multi_promisc_fl = B_FALSE;
	qede->params.promisc_fl = B_FALSE;
	qede->mc_cnt = 0;
	qede->rx_low_buffer_threshold = RX_LOW_BUFFER_THRESHOLD;

	return (status);
}

/* Resume the interface */
static int
qede_resume(qede_t *qede)
{
	mutex_enter(&qede->drv_lock);
	cmn_err(CE_NOTE, "%s:%d Enter\n", __func__, qede->instance);
	qede->qede_state = QEDE_STATE_ATTACHED;
	mutex_exit(&qede->drv_lock);
	return (DDI_FAILURE);
}

/*
 * Write dword to doorbell from tx_path
 * Avoid use of qede_t * pointer
 */
#pragma inline(qede_bar2_write32_tx_doorbell)
void 
qede_bar2_write32_tx_doorbell(qede_tx_ring_t *tx_ring, u32 val)
{
	u64 addr = (u64)tx_ring->doorbell_addr;
	ddi_put32(tx_ring->doorbell_handle, (u32 *)addr, val);
}

static void
qede_unconfig_pci(qede_t *qede)
{
	if (qede->doorbell_handle != NULL) {
		ddi_regs_map_free(&(qede->doorbell_handle));
		qede->doorbell_handle = NULL;
	}

	if (qede->regs_handle != NULL) {
		ddi_regs_map_free(&qede->regs_handle);
		qede->regs_handle = NULL;
	}
	if (qede->pci_cfg_handle != NULL) {
		pci_config_teardown(&qede->pci_cfg_handle);
		qede->pci_cfg_handle = NULL;
	}
}

static int
qede_config_pci(qede_t *qede)
{
	int ret;

	ret = pci_config_setup(qede->dip, &qede->pci_cfg_handle);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "%s:%d Failed to get PCI config handle\n", 
			__func__, qede->instance);
		return (DDI_FAILURE);
	}

	/* get register size */
	ret = ddi_dev_regsize(qede->dip, 1, &qede->regview_size);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to read reg size for bar0",
			__func__, qede->instance);
		goto err_exit;
	}

	/* get doorbell size */
	ret = ddi_dev_regsize(qede->dip, 3, &qede->doorbell_size);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to read doorbell size for bar2",
			__func__, qede->instance);
		goto err_exit;
	}

	/* map register space */
	ret = ddi_regs_map_setup(
	/* Pointer to the device's dev_info structure. */
	    qede->dip,
	/*
	 * Index number to the register address space  set.
	 * A  value of 0 indicates PCI configuration space,
	 * while a value of 1 indicates the real  start  of
	 * device register sets.
	 */
	    1,
	/*
	 * A platform-dependent value that, when  added  to
	 * an  offset that is less than or equal to the len
	 * parameter (see below), is used for the  dev_addr
	 * argument   to   the  ddi_get,  ddi_mem_get,  and
	 * ddi_io_get/put routines.
	 */
	    &qede->regview,
	/*
	 * Offset into the register address space.
	 */
	    0,
	/* Length to be mapped. */
	    qede->regview_size,
	/*
	 * Pointer to a device access  attribute  structure
	 * of this mapping.
	 */
	    &qede_regs_acc_attr,
	/* Pointer to a data access handle. */
	    &qede->regs_handle);

	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!qede(%d): failed to map registers, err %d",
		    qede->instance, ret);
		goto err_exit;
	}

	qede->pci_bar0_base = (unsigned long)qede->regview;

	/* map doorbell space */
	ret = ddi_regs_map_setup(qede->dip,
	    2,
	    &qede->doorbell,
	    0,
	    qede->doorbell_size,
	    &qede_regs_acc_attr,
	    &qede->doorbell_handle);
	
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qede%d: failed to map doorbell, err %d",
		    qede->instance, ret);
		goto err_exit;
	}

	qede->pci_bar2_base = (unsigned long)qede->doorbell;

	return (ret);
err_exit:
	qede_unconfig_pci(qede);
	return (DDI_FAILURE);
}

static uint_t
qede_sp_handler(caddr_t arg1, caddr_t arg2)
{
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	struct ecore_hwfn *p_hwfn = (struct ecore_hwfn *)arg1;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	qede_vector_info_t *vect_info = (qede_vector_info_t *)arg2;
	struct ecore_dev *edev = p_hwfn->p_dev;
	qede_t *qede = (qede_t *)edev;

	if ((arg1 == NULL) || (arg2 == NULL)) {
		cmn_err(CE_WARN, "qede_sp_handler: invalid parameters");
		/*
		 * MSIX intr should always
		 * return DDI_INTR_CLAIMED
		 */
        	return (DDI_INTR_CLAIMED);
	}


	vect_info->in_isr = B_TRUE;

	atomic_add_64((volatile uint64_t *)&qede->intrFired, 1);
	qede->intrSbCnt[vect_info->vect_index]++;


	ecore_int_sp_dpc((osal_int_ptr_t)p_hwfn);

	vect_info->in_isr = B_FALSE;

    	return (DDI_INTR_CLAIMED);
}

void
qede_enable_hw_intr(qede_fastpath_t *fp)
{
	ecore_sb_ack(fp->sb_info, IGU_INT_ENABLE, 1);
	ddi_dma_sync(fp->sb_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);
}

void
qede_disable_hw_intr(qede_fastpath_t *fp)
{
	ddi_dma_sync(fp->sb_dma_handle, 0, 0, DDI_DMA_SYNC_FORKERNEL);
	ecore_sb_ack(fp->sb_info, IGU_INT_DISABLE, 0);
}


static uint_t
qede_fp_handler(caddr_t arg1, caddr_t arg2)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */ 
	qede_vector_info_t *vect_info = (qede_vector_info_t *)arg1;
	/* LINTED E_BAD_PTR_CAST_ALIGN */ 
	qede_t *qede = (qede_t *)arg2;
	qede_fastpath_t *fp;
	qede_rx_ring_t *rx_ring;
	mblk_t *mp;
	int work_done = 0;

	if ((vect_info == NULL) || (vect_info->fp == NULL)) {
		cmn_err(CE_WARN, "qede_fp_handler: invalid parameters");
        	return (DDI_INTR_UNCLAIMED);
	}

	fp = (qede_fastpath_t *)vect_info->fp;
	rx_ring = fp->rx_ring;

	mutex_enter(&fp->fp_lock);

	atomic_add_64((volatile uint64_t *)&qede->intrFired, 1);
	qede->intrSbCnt[vect_info->vect_index]++;

	mutex_enter(&fp->qede->drv_lock);
	qede_disable_hw_intr(fp);
	mutex_exit(&fp->qede->drv_lock);

	mp = qede_process_fastpath(fp, QEDE_POLL_ALL,
	    QEDE_MAX_RX_PKTS_PER_INTR, &work_done);

	if (mp)
#ifndef NO_CROSSBOW
	{
		mac_rx_ring(rx_ring->qede->mac_handle,
		    rx_ring->mac_ring_handle,
		    mp,
		    rx_ring->mr_gen_num);
	}
#else
	{
		mac_rx(qede->mac_handle, NULL, mp);
	}
#endif
       else if (!mp && (work_done == 0)) {
		qede->intrSbNoChangeCnt[vect_info->vect_index]++;
	}


	mutex_enter(&fp->qede->drv_lock);
	/*
	 * The mac layer may disabled interrupts
	 * in the context of the mac_rx_ring call
	 * above while readying for poll process.
	 * In this case we do not want to 
	 * enable them here.
	 */
	if (fp->disabled_by_poll == 0) {
		qede_enable_hw_intr(fp);
	}
	mutex_exit(&fp->qede->drv_lock);

	mutex_exit(&fp->fp_lock);

	return (work_done ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

static int
qede_disable_intr(qede_t *qede, uint32_t index)
{
	int status;
	qede_intr_context_t *intr_ctx = &qede->intr_ctx;

	status = ddi_intr_disable(intr_ctx->intr_hdl_array[index]);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qede:%s: Failed ddi_intr_enable with %s"
		    " for index %d\n",
		    __func__, qede_get_ddi_fail(status), index);
		return (status);
	}									  
	atomic_and_32(&intr_ctx->intr_state, ~(1 << index));

	return (status);
}

static int
qede_enable_intr(qede_t *qede, int index)
{
	int status = 0;

	qede_intr_context_t *intr_ctx = &qede->intr_ctx;

	status = ddi_intr_enable(intr_ctx->intr_hdl_array[index]);
	
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qede:%s: Failed ddi_intr_enable with %s"
		    " for index %d\n",
		    __func__, qede_get_ddi_fail(status), index);
		return (status);
	}
	
	atomic_or_32(&intr_ctx->intr_state, (1 << index));
	
	return (status);
}

static int
qede_disable_all_fastpath_intrs(qede_t *qede)
{
	int i, status;

	for (i = qede->num_hwfns; i <= qede->num_fp; i++) {
		status = qede_disable_intr(qede, i);
		if (status != DDI_SUCCESS) {
			return (status);
		}
	}
	return (DDI_SUCCESS);
}

static int
qede_enable_all_fastpath_intrs(qede_t *qede)
{
	int status = 0, i;

	for (i = qede->num_hwfns; i <= qede->num_fp; i++) {
		status = qede_enable_intr(qede, i);
		if (status != DDI_SUCCESS) {
			return (status);
		}
	}
	return (DDI_SUCCESS);
}

static int
qede_disable_slowpath_intrs(qede_t *qede)
{
	int i, status;

	for (i = 0; i < qede->num_hwfns; i++) {
		status = qede_disable_intr(qede, i);
		if (status != DDI_SUCCESS) {
			return (status);
		}
	}
	return (DDI_SUCCESS);
}

static int
qede_enable_slowpath_intrs(qede_t *qede)
{
	int i, status;

	for (i = 0; i < qede->num_hwfns; i++) {
		status = qede_enable_intr(qede, i);
		if (status != DDI_SUCCESS) {
			return (status);
		}
	}
	return (DDI_SUCCESS);
}

static int
qede_prepare_edev(qede_t *qede)
{
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hw_prepare_params p_params;

	/*
	 * Setup the bar0 and bar2 base address
	 * in ecore_device
	 */
	edev->regview = (void *)qede->regview;
	edev->doorbells = (void *)qede->doorbell;

	/* LINTED E_FUNC_RET_MAYBE_IGNORED2 */
	strcpy(edev->name, qede->name);
	ecore_init_struct(edev);
	
	p_params.personality = ECORE_PCI_ETH;
	p_params.drv_resc_alloc = 0;
	p_params.chk_reg_fifo = 1;
	p_params.initiate_pf_flr = 1; 
	//p_params->epoch = time(&epoch);
	p_params.allow_mdump = 1;
	p_params.b_relaxed_probe = 0;
	return (ecore_hw_prepare(edev, &p_params));
}

static int
qede_config_edev(qede_t *qede)
{
	int status, i;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_pf_params *params;

	for (i = 0; i < qede->num_hwfns; i++) {
		struct ecore_hwfn *p_hwfn = &edev->hwfns[i];
		params = &p_hwfn->pf_params; 
		memset((void *)params, 0, sizeof (struct ecore_pf_params));
		params->eth_pf_params.num_cons = 32;
	}
	status = ecore_resc_alloc(edev);
	if (status != ECORE_SUCCESS) {
		cmn_err(CE_NOTE, "%s: Could not allocate ecore resources\n",
		 __func__);
		return (DDI_ENOMEM);
	}
	ecore_resc_setup(edev);
	return (DDI_SUCCESS);
}

static void
qede_unconfig_intrs(qede_t *qede)
{
	qede_intr_context_t *intr_ctx = &qede->intr_ctx;
	qede_vector_info_t *vect_info;
	int i, status = 0;

	for (i = 0; i < intr_ctx->intr_vect_allocated; i++) {
		vect_info = &intr_ctx->intr_vect_info[i];
		if (intr_ctx->intr_vect_info[i].handler_added == B_TRUE) {
			status = ddi_intr_remove_handler(
				intr_ctx->intr_hdl_array[i]);
			if (status != DDI_SUCCESS) {
				cmn_err(CE_WARN, "qede:%s: Failed" 
					" ddi_intr_remove_handler with %s"
					" for index %d\n",
				__func__, qede_get_ddi_fail(
				status), i);
			}
		
			(void) ddi_intr_free(intr_ctx->intr_hdl_array[i]);

			vect_info->handler_added = B_FALSE;
			intr_ctx->intr_hdl_array[i] = NULL;
		}
	}
}

static int
qede_config_intrs(qede_t *qede)
{
	qede_intr_context_t *intr_ctx = &qede->intr_ctx;
	qede_vector_info_t *vect_info;
	struct ecore_dev *edev = &qede->edev;
	int i, status = DDI_FAILURE;
	ddi_intr_handler_t *handler;
	void *arg1, *arg2;

	/*
	 * Set up the interrupt handler argument
	 * for the slowpath
	 */
	for (i = 0; i < intr_ctx->intr_vect_allocated; i++) {
		vect_info = &intr_ctx->intr_vect_info[i];
		/* Store the table index */
		vect_info->vect_index = i;
		vect_info->qede = qede;
		/* 
		 * Store the interrupt handler's argument.
		 * This will be the a pointer to ecore_dev->hwfns
		 * for slowpath, a pointer to the fastpath
		 * structure for fastpath.
		 */
		if (i < qede->num_hwfns) {
		   	vect_info->fp = (void *)&edev->hwfns[i];
			handler = qede_sp_handler; 
			arg1 = (caddr_t)&qede->edev.hwfns[i];
			arg2 = (caddr_t)vect_info;
		} else {
			/* 
			 * loop index includes hwfns
			 * so they need to be subtracked
			 * for fp_array
			 */
			vect_info->fp =
			    (void *)&qede->fp_array[i - qede->num_hwfns];
			handler = qede_fp_handler; 
			arg1 = (caddr_t)vect_info;
			arg2 = (caddr_t)qede;
		}

		status = ddi_intr_add_handler(
		    intr_ctx->intr_hdl_array[i],
		    handler,
		    arg1,
		    arg2);
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, "qede:%s: Failed "
			    " ddi_intr_add_handler with %s"
			    " for index %d\n",
			    __func__, qede_get_ddi_fail(
			    status), i);
			qede_unconfig_intrs(qede);
			return (DDI_FAILURE);
		}
		vect_info->handler_added = B_TRUE;
	}
		
	return (status);
}

static void
qede_free_intrs(qede_t *qede)
{
	qede_intr_context_t *intr_ctx;
	int i, status;

	ASSERT(qede != NULL);
	intr_ctx = &qede->intr_ctx;
	ASSERT(intr_ctx != NULL);

	if (intr_ctx->intr_hdl_array) {
		for (i = 0; i < intr_ctx->intr_vect_allocated; i++) {
			if (intr_ctx->intr_hdl_array[i]) {
				status = 
				    ddi_intr_free(intr_ctx->intr_hdl_array[i]);
				if (status != DDI_SUCCESS) {
					cmn_err(CE_NOTE, 
					    "qede:%s: Failed ddi_intr_free"
					    " with %s\n",
					    __func__, 
					    qede_get_ddi_fail(status));
				}
			}
		}
		intr_ctx->intr_hdl_array = NULL;
	}

	if (intr_ctx->intr_hdl_array) {
		kmem_free(intr_ctx->intr_hdl_array, 
		    intr_ctx->intr_hdl_array_size);
		intr_ctx->intr_hdl_array = NULL;
	}

	if (intr_ctx->intr_vect_info) {
		kmem_free(intr_ctx->intr_vect_info, 
		    intr_ctx->intr_vect_info_array_size);
		intr_ctx->intr_vect_info = NULL;
	}
}

static int
qede_alloc_intrs(qede_t *qede)
{
	int status, type_supported, num_supported;
	int actual, num_available, num_to_request;
	dev_info_t *dip;
	qede_intr_context_t *intr_ctx = &qede->intr_ctx;

	dip = qede->dip;

	status = ddi_intr_get_supported_types(dip, &type_supported);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, 
		    "qede:%s: Failed ddi_intr_get_supported_types with %s\n",
		    __func__, qede_get_ddi_fail(status));
		return (status);
	}
	intr_ctx->intr_types_available = type_supported;

	if (type_supported & DDI_INTR_TYPE_MSIX) {
		intr_ctx->intr_type_in_use = DDI_INTR_TYPE_MSIX;

		/* 
		 * get the total number of vectors 
		 * supported by the device 
		 */
		status = ddi_intr_get_nintrs(qede->dip, 
		             DDI_INTR_TYPE_MSIX, &num_supported);
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed ddi_intr_get_nintrs with %s\n",
			    __func__, qede_get_ddi_fail(status));
			return (status);
		}
		intr_ctx->intr_vect_supported = num_supported;

		/* 
		 * get the total number of vectors 
		 * available for this instance 
		 */
		status = ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSIX, 
		             &num_available);
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed ddi_intr_get_navail with %s\n",
			    __func__, qede_get_ddi_fail(status));
			return (status);
		}

                if ((num_available < intr_ctx->intr_vect_to_request) && 
			(num_available >= 2)) {
			qede->num_fp = num_available - qede->num_hwfns;
			cmn_err(CE_NOTE, 
			    "qede:%s: allocated %d interrupts"
			    " requested was %d\n",
			    __func__, num_available, 
			    intr_ctx->intr_vect_to_request);
			intr_ctx->intr_vect_to_request = num_available;
		} else if(num_available < 2) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed ddi_intr_get_navail with %s\n",
				__func__, qede_get_ddi_fail(status));
			return (DDI_FAILURE);
		}

		intr_ctx->intr_vect_available = num_available;
		num_to_request = intr_ctx->intr_vect_to_request;
		intr_ctx->intr_hdl_array_size = num_to_request *
		    sizeof (ddi_intr_handle_t);
		intr_ctx->intr_vect_info_array_size = num_to_request *
		    sizeof (qede_vector_info_t);

		/* Allocate an array big enough for maximum supported */
		intr_ctx->intr_hdl_array = kmem_zalloc(
		    intr_ctx->intr_hdl_array_size, KM_SLEEP);
		if (intr_ctx->intr_hdl_array == NULL) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed to allocate"
			    " intr_ctx->intr_hdl_array\n",
				__func__);
			return (status);
		}
		intr_ctx->intr_vect_info = kmem_zalloc(
		    intr_ctx->intr_vect_info_array_size, KM_SLEEP);
		if (intr_ctx->intr_vect_info_array_size == NULL) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed to allocate"
			    " intr_ctx->vect_info_array_size\n",
				__func__);
			goto err_exit;
		}

		/* 
		 * Use strict allocation. It will fail if we do not get
		 * exactly what we want.  Later we can shift through with
		 * power of two like this:
		 *   for (i = intr_ctx->intr_requested; i > 0; i >>= 1)
		 * (Though we would need to account for the slowpath vector)
		 */
		status = ddi_intr_alloc(qede->dip, 
			intr_ctx->intr_hdl_array, 
			DDI_INTR_TYPE_MSIX,
			0, 
			num_to_request,
			&actual,
			DDI_INTR_ALLOC_STRICT);
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed to allocate"
			    " %d interrupts with %s\n",
			    __func__, num_to_request, 
			    qede_get_ddi_fail(status));
			cmn_err(CE_WARN, 
			    "qede:%s: Only %d interrupts available.\n",
			    __func__, actual);
			goto err_exit;
		}
		intr_ctx->intr_vect_allocated = num_to_request;

		status = ddi_intr_get_pri(intr_ctx->intr_hdl_array[0], 
			    &intr_ctx->intr_pri);
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed ddi_intr_get_pri with %s\n",
			    __func__, qede_get_ddi_fail(status));
			goto err_exit;
		}

		status = ddi_intr_get_cap(intr_ctx->intr_hdl_array[0], 
			    &intr_ctx->intr_cap);
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, 
			    "qede:%s: Failed ddi_intr_get_cap with %s\n",
				__func__, qede_get_ddi_fail(status));
			goto err_exit;
		}

	} else {
		/* For now we only support type MSIX */
		cmn_err(CE_WARN, 
		    "qede:%s: Failed to allocate intr_ctx->intr_hdl_array\n",
			__func__);
		return (DDI_FAILURE);
	}
	
	intr_ctx->intr_mode = ECORE_INT_MODE_MSIX;	
	return (status);
err_exit:
	qede_free_intrs(qede);
	return (status);
}

static void
/* LINTED E_FUNC_ARG_UNUSED */
qede_unconfig_fm(qede_t *qede)
{
}

/* LINTED E_FUNC_ARG_UNUSED */
static int
qede_fm_err_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data)
{
        pci_ereport_post(dip, err, NULL);
        return (err->fme_status);
}


static int
qede_config_fm(qede_t * qede)
{
        ddi_iblock_cookie_t iblk;

        cmn_err(CE_NOTE, "Entered qede_config_fm\n");
        qede_regs_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
        qede_desc_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
        qede_buf_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
        qede_desc_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_gen_buf_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_tx_buf_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_dma_attr_desc.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_dma_attr_txbuf.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_dma_attr_rxbuf.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_dma_attr_cmddesc.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_gen_dma_attr_desc.dma_attr_flags = DDI_DMA_FLAGERR;
        qede_buf2k_dma_attr_txbuf.dma_attr_flags = DDI_DMA_FLAGERR;

        ddi_fm_init(qede->dip, &qede->fm_cap, &iblk);

        if (DDI_FM_EREPORT_CAP(qede->fm_cap) ||
            DDI_FM_ERRCB_CAP(qede->fm_cap)) {
                pci_ereport_setup(qede->dip);
        }

        if (DDI_FM_ERRCB_CAP(qede->fm_cap)) {
                ddi_fm_handler_register(qede->dip,
                    qede_fm_err_cb, (void *)qede);
        }
        return (DDI_SUCCESS);

}

int
qede_dma_mem_alloc(qede_t *qede,
    int size, uint_t dma_flags, caddr_t *address, ddi_dma_cookie_t *cookie,
    ddi_dma_handle_t *dma_handle, ddi_acc_handle_t *handlep,
    ddi_dma_attr_t *dma_attr, ddi_device_acc_attr_t *dev_acc_attr)
{
	int err;
	uint32_t ncookies;
	size_t ring_len;

	*dma_handle = NULL;

	if (size <= 0) {
		return (DDI_ENOMEM);
	}

	err = ddi_dma_alloc_handle(qede->dip,
	    dma_attr,
	    DDI_DMA_DONTWAIT, NULL, dma_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!qede(%d): pci_alloc_consistent: "
		    "ddi_dma_alloc_handle FAILED: %d", qede->instance, err);
		*dma_handle = NULL;
		return (DDI_ENOMEM);
	}

	err = ddi_dma_mem_alloc(*dma_handle,
	    size, dev_acc_attr,
	    dma_flags,
	    DDI_DMA_DONTWAIT, NULL, address, &ring_len,
	    handlep);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!qede(%d): pci_alloc_consistent: "
		    "ddi_dma_mem_alloc FAILED: %d, request size: %d",
		    qede->instance, err, size);
		ddi_dma_free_handle(dma_handle);
		*dma_handle = NULL;
		*handlep = NULL;
		return (DDI_ENOMEM);
	}

	if (ring_len < size) {
		cmn_err(CE_WARN, "!qede(%d): pci_alloc_consistent: "
		    "could not allocate required: %d, request size: %d",
		    qede->instance, err, size);
		ddi_dma_mem_free(handlep);
		ddi_dma_free_handle(dma_handle);
		*dma_handle = NULL;
		*handlep = NULL;
		return (DDI_FAILURE);
	}

	(void) memset(*address, 0, size);

	if (((err = ddi_dma_addr_bind_handle(*dma_handle,
	    NULL, *address, ring_len,
	    dma_flags,
	    DDI_DMA_DONTWAIT, NULL,
	    cookie, &ncookies)) != DDI_DMA_MAPPED) ||
	    (ncookies != 1)) {
		cmn_err(CE_WARN, "!qede(%d): pci_alloc_consistent: "
		    "ddi_dma_addr_bind_handle Failed: %d",
		    qede->instance, err);
		ddi_dma_mem_free(handlep);
		ddi_dma_free_handle(dma_handle);
		*dma_handle = NULL;
		*handlep = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
qede_pci_free_consistent(ddi_dma_handle_t *dma_handle,
    ddi_acc_handle_t *acc_handle)
{
	int err;

	if (*dma_handle != NULL) {
		err = ddi_dma_unbind_handle(*dma_handle);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!pci_free_consistent: "
			    "Error unbinding memory, err %d", err);
			return;
		}
	} else {
		goto exit;
	}
	ddi_dma_mem_free(acc_handle);
	ddi_dma_free_handle(dma_handle);
exit:
	*dma_handle = NULL;
	*acc_handle = NULL;
}

static int
qede_vport_stop(qede_t *qede)
{
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *p_hwfn;
	int i, status = ECORE_BUSY; 

	for (i = 0; i < edev->num_hwfns; i++) {
		p_hwfn = &edev->hwfns[i];

		if (qede->vport_state[i] !=
		    QEDE_VPORT_STARTED) {
			qede_info(qede, "vport %d not started", i);
			continue;
		}

		status = ecore_sp_vport_stop(p_hwfn,
			p_hwfn->hw_info.opaque_fid,
			i); /* vport needs fix */
		if (status != ECORE_SUCCESS) {
			cmn_err(CE_WARN, "!qede_vport_stop: "
			    "FAILED for hwfn%d ", i);
			return (DDI_FAILURE);
		}
		cmn_err(CE_WARN, "!qede_vport_stop: "
		    "SUCCESS for hwfn%d ", i);

		qede->vport_state[i] =
		    QEDE_VPORT_STOPPED;
	}

	return (status);
}

static uint8_t
qede_get_active_rss_params(qede_t *qede, u8 hwfn_id)
{
	struct ecore_rss_params rss_params;
	qede_fastpath_t *fp;
	int i;
	const uint64_t hash_key[] = 
	{ 
		0xbeac01fa6a42b73bULL, 0x8030f20c77cb2da3ULL,
		0xae7b30b4d0ca2bcbULL, 0x43a38fb04167253dULL,
		0x255b0ec26d5a56daULL 
	};
	uint8_t enable_rss = 0;

	bzero(&rss_params, sizeof (rss_params));
	if (qede->num_fp > 1) {
		qede_info(qede, "Configuring RSS parameters");
		enable_rss = 1;
	} else {
		qede_info(qede, "RSS configuration not needed");
		enable_rss = 0;
		goto exit;
	}

	rss_params.update_rss_config = 1;
	rss_params.rss_enable = 1;
	rss_params.update_rss_capabilities = 1;
	rss_params.update_rss_ind_table = 1;
	rss_params.update_rss_key = 1;

	rss_params.rss_caps = ECORE_RSS_IPV4 |
	    ECORE_RSS_IPV6 |
	    ECORE_RSS_IPV4_TCP |
	    ECORE_RSS_IPV6_TCP |
	    ECORE_RSS_IPV4_UDP |
	    ECORE_RSS_IPV6_UDP;

	rss_params.rss_table_size_log = 7; /* 2^7 = 128 */

	bcopy(&hash_key[0], &rss_params.rss_key[0], 
		sizeof (rss_params.rss_key));

	for (i = 0; i < ECORE_RSS_IND_TABLE_SIZE; i++) {
		fp = &qede->fp_array[i % qede->num_fp];
		rss_params.rss_ind_table[i] = (void *)(fp->rx_ring->p_cid);
	}
exit:
	bcopy(&rss_params, &qede->rss_params[hwfn_id], sizeof (rss_params));
	return (enable_rss);
}

static int
qede_vport_update(qede_t *qede,
    enum qede_vport_state state)
{
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *p_hwfn;
	struct ecore_sp_vport_update_params *vport_params;
	struct ecore_sge_tpa_params tpa_params;
	int  status = DDI_SUCCESS;
	bool new_state;
	uint8_t i;

	cmn_err(CE_NOTE, "qede_vport_update: "
	    "Enter, state = %s%s%s%s%s",
	    state == QEDE_VPORT_STARTED ? "QEDE_VPORT_STARTED" : "",
	    state == QEDE_VPORT_ON ? "QEDE_VPORT_ON" : "",
	    state == QEDE_VPORT_OFF ? "QEDE_VPORT_OFF" : "",
	    state == QEDE_VPORT_STOPPED ? "QEDE_VPORT_STOPPED" : "",
	    state == QEDE_VPORT_UNKNOWN ? "" : "");

	/*
	 * Update only does on and off.
	 * For now we combine TX and RX
	 * together.  Later we can split them
	 * and set other params as well.
	 */
	if (state == QEDE_VPORT_ON) {
	    new_state = B_TRUE;
	} else if (state == QEDE_VPORT_OFF) {
	    new_state = B_FALSE;
	} else {
		cmn_err(CE_WARN, "qede_vport_update: "
		    "invalid, state = %d", state);
		return (DDI_EINVAL);
	}

	for (i = 0; i < edev->num_hwfns; i++) {
		p_hwfn = &edev->hwfns[i];
		vport_params = &qede->vport_params[i];

		vport_params->opaque_fid =
		    p_hwfn->hw_info.opaque_fid;
		vport_params->vport_id =
		    i;

		vport_params->update_vport_active_rx_flg =
		    1;
                if (new_state == B_TRUE)
                        vport_params->vport_active_rx_flg = 1;
                else
                        vport_params->vport_active_rx_flg = 0;

		vport_params->update_vport_active_tx_flg =
		    1;
                if (new_state == B_TRUE)
                        vport_params->vport_active_tx_flg = 1;
                else
                        vport_params->vport_active_tx_flg = 0;

		vport_params->update_inner_vlan_removal_flg =
		    0;
		vport_params->inner_vlan_removal_flg =
		    0;
		vport_params->update_default_vlan_enable_flg =
		    0;
		vport_params->default_vlan_enable_flg =
		    0;
		vport_params->update_default_vlan_flg =
		    1;
		vport_params->default_vlan =
		    0;
		vport_params->update_tx_switching_flg =
		    0;
		vport_params->tx_switching_flg =
		    0;
		vport_params->update_approx_mcast_flg =
		    0;
		vport_params->update_anti_spoofing_en_flg =
		    0;
		vport_params->anti_spoofing_en = 0;
		vport_params->update_accept_any_vlan_flg =
		    1;
		vport_params->accept_any_vlan = 1;

		vport_params->accept_flags.update_rx_mode_config = 1;
		vport_params->accept_flags.update_tx_mode_config = 1;
		vport_params->accept_flags.rx_accept_filter =
		    ECORE_ACCEPT_BCAST |
		    ECORE_ACCEPT_UCAST_UNMATCHED |
		    ECORE_ACCEPT_MCAST_UNMATCHED;
		vport_params->accept_flags.tx_accept_filter =
		    ECORE_ACCEPT_BCAST |
		    ECORE_ACCEPT_UCAST_UNMATCHED |
		    ECORE_ACCEPT_MCAST_UNMATCHED;

		vport_params->sge_tpa_params = NULL;

		if (qede->lro_enable &&
		    (new_state == B_TRUE)) {
			qede_print("!%s(%d): enabling LRO ",
				__func__, qede->instance);

			memset(&tpa_params, 0, 
			    sizeof (struct ecore_sge_tpa_params));
			tpa_params.max_buffers_per_cqe = 5;
			tpa_params.update_tpa_en_flg = 1;
			tpa_params.tpa_ipv4_en_flg = 1;
			tpa_params.tpa_ipv6_en_flg = 1;
			tpa_params.tpa_ipv4_tunn_en_flg = 0;
			tpa_params.tpa_ipv6_tunn_en_flg = 0;
			tpa_params.update_tpa_param_flg = 1;
			tpa_params.tpa_pkt_split_flg = 0;
			tpa_params.tpa_hdr_data_split_flg = 0;
			tpa_params.tpa_gro_consistent_flg = 0;
			tpa_params.tpa_max_aggs_num = ETH_TPA_MAX_AGGS_NUM;
			tpa_params.tpa_max_size = 65535;
			tpa_params.tpa_min_size_to_start = qede->mtu/2;
			tpa_params.tpa_min_size_to_cont = qede->mtu/2;
			vport_params->sge_tpa_params = &tpa_params;
		}

		/* 
		 * Get the rss_params to be configured
		 */
		if (qede_get_active_rss_params(qede, i /* hwfn id */)) {
			vport_params->rss_params = &qede->rss_params[i];
		} else {
			vport_params->rss_params = NULL;
		}

		status = ecore_sp_vport_update(p_hwfn,
		    vport_params,
		    ECORE_SPQ_MODE_EBLOCK,
		    NULL);

		if (status != ECORE_SUCCESS) {
			cmn_err(CE_WARN, "ecore_sp_vport_update: "
			    "FAILED for hwfn%d "
			    " with ", i);
			return (DDI_FAILURE);
		}
		cmn_err(CE_NOTE, "!ecore_sp_vport_update: "
		    "SUCCESS for hwfn%d ", i);

					
	}
	return (DDI_SUCCESS);
}


static int
qede_vport_start(qede_t *qede)
{
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *p_hwfn;
	struct ecore_sp_vport_start_params params;
	uint8_t i;
	int  status = ECORE_BUSY;

	for (i = 0; i < edev->num_hwfns; i++) {
		p_hwfn = &edev->hwfns[i];
		if ((qede->vport_state[i] !=
		    QEDE_VPORT_UNKNOWN) &&
		    (qede->vport_state[i] !=
		    QEDE_VPORT_STOPPED)) {
		    continue;
		}

		params.tpa_mode = ECORE_TPA_MODE_NONE;
		params.remove_inner_vlan = 0;
		params.tx_switching = 0;
		params.handle_ptp_pkts = 0; 
		params.only_untagged = 0;
		params.drop_ttl0 = 1;
		params.max_buffers_per_cqe = 16; 
		params.concrete_fid = p_hwfn->hw_info.concrete_fid;
		params.opaque_fid = p_hwfn->hw_info.opaque_fid;
		params.vport_id = i;
		params.mtu = qede->mtu;
		status = ecore_sp_vport_start(p_hwfn, &params);
		if (status != ECORE_SUCCESS) {
			cmn_err(CE_WARN, "qede_vport_start: "
			    "FAILED for hwfn%d", i);
			return (DDI_FAILURE);
		}
		cmn_err(CE_NOTE, "!ecore_sp_vport_start: "
		    "SUCCESS for hwfn%d ", i);

		ecore_hw_start_fastpath(p_hwfn);
		qede->vport_state[i] = QEDE_VPORT_STARTED;
	}
	ecore_reset_vport_stats(edev);
	return (status);
}

void
qede_update_rx_q_producer(qede_rx_ring_t *rx_ring)
{
	u16 bd_prod = ecore_chain_get_prod_idx(&rx_ring->rx_bd_ring);
	u16 cqe_prod = ecore_chain_get_prod_idx(&rx_ring->rx_cqe_ring);
	/* LINTED E_FUNC_SET_NOT_USED */
        struct eth_rx_prod_data rx_prod_cmd = { 0 };


	rx_prod_cmd.bd_prod = HOST_TO_LE_32(bd_prod);
	rx_prod_cmd.cqe_prod = HOST_TO_LE_32(cqe_prod);
	UPDATE_RX_PROD(rx_ring, rx_prod_cmd);
}

static int
qede_fastpath_stop_queues(qede_t *qede)
{
	int i, j;
	int status = DDI_FAILURE;
	struct ecore_dev *edev;
	struct ecore_hwfn *p_hwfn;
	struct ecore_queue_cid *p_tx_cid, *p_rx_cid;

	qede_fastpath_t *fp;
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;

	ASSERT(qede != NULL);
	/* ASSERT(qede->edev != NULL); */

	edev = &qede->edev;

	status = qede_vport_update(qede, QEDE_VPORT_OFF);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "FAILED to "
		    "update vports");
		return (DDI_FAILURE);
	}

	for (i = 0; i < qede->num_fp; i++) {
		fp = &qede->fp_array[i];
		rx_ring = fp->rx_ring;
		p_hwfn = &edev->hwfns[fp->fp_hw_eng_index];
		for (j = 0; j < qede->num_tc; j++) {
			tx_ring = fp->tx_ring[j];
			if (tx_ring->queue_started == B_TRUE) {
				cmn_err(CE_WARN, "Stopping tx queue "
				    "%d:%d. ", i, j);
				p_tx_cid = tx_ring->p_cid; 
				status = ecore_eth_tx_queue_stop(p_hwfn,
					(void *)p_tx_cid);
				if (status != ECORE_SUCCESS) {
					cmn_err(CE_WARN, "FAILED to "
			    	    	    "stop tx queue %d:%d", i, j);
					return (DDI_FAILURE);
				}
				tx_ring->queue_started = B_FALSE;
				cmn_err(CE_NOTE, "tx_ring %d:%d stopped\n", i, 
				    j);
			}
		}

		if (rx_ring->queue_started == B_TRUE) {
			cmn_err(CE_WARN, "Stopping rx queue "
			    "%d. ", i);
			p_rx_cid = rx_ring->p_cid; 
			status = ecore_eth_rx_queue_stop(p_hwfn, 
			    (void *)p_rx_cid, B_TRUE, B_FALSE);
			if (status != ECORE_SUCCESS) {
				cmn_err(CE_WARN, "FAILED to "
			    	    "stop rx queue %d "
			    	    "with ecore status %s",
				    i, qede_get_ecore_fail(status));
				return (DDI_FAILURE);
			}
			rx_ring->queue_started = B_FALSE;
			cmn_err(CE_NOTE, "rx_ring%d stopped\n", i);
		}
	}

	status = qede_vport_stop(qede);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qede_vport_stop "
		    "FAILED to stop vports");
		return (DDI_FAILURE);
	}

	ecore_hw_stop_fastpath(edev);

	return (DDI_SUCCESS);
}

static int
qede_fastpath_start_queues(qede_t *qede)
{
	int i, j;
	int status = DDI_FAILURE;
	struct ecore_dev *edev;
	struct ecore_hwfn *p_hwfn;
	struct ecore_queue_start_common_params params;
	struct ecore_txq_start_ret_params tx_ret_params;
	struct ecore_rxq_start_ret_params rx_ret_params;
	qede_fastpath_t *fp;
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;
	dma_addr_t p_phys_table;
        u16 page_cnt;

	ASSERT(qede != NULL);
	/* ASSERT(qede->edev != NULL); */
	edev = &qede->edev;

	status = qede_vport_start(qede);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to "
		    "start vports");
		return (DDI_FAILURE);
	}

	for (i = 0; i < qede->num_fp; i++) {
		fp = &qede->fp_array[i];
		rx_ring = fp->rx_ring;
		p_hwfn = &edev->hwfns[fp->fp_hw_eng_index];
		
		params.vport_id = fp->vport_id;
		params.queue_id = fp->rx_queue_index;
		params.stats_id = fp->stats_id;
		params.p_sb = fp->sb_info;
		params.sb_idx = RX_PI;
		p_phys_table = ecore_chain_get_pbl_phys(&rx_ring->rx_cqe_ring);
		page_cnt = ecore_chain_get_page_cnt(&rx_ring->rx_cqe_ring);

		status = ecore_eth_rx_queue_start(p_hwfn,
		    p_hwfn->hw_info.opaque_fid, 
		    &params,
		    qede->rx_buf_size,
		    rx_ring->rx_bd_ring.p_phys_addr,
		    p_phys_table,
		    page_cnt,
		    &rx_ret_params);
	        
		rx_ring->hw_rxq_prod_addr = rx_ret_params.p_prod;	
		rx_ring->p_cid = rx_ret_params.p_handle;
		if (status != DDI_SUCCESS) {
			cmn_err(CE_WARN, "ecore_sp_eth_rx_queue_start "
		            "FAILED for rxq%d", i);
			return (DDI_FAILURE);
		}
		rx_ring->hw_cons_ptr = &fp->sb_info->sb_virt->pi_array[RX_PI];

		OSAL_MSLEEP(20);
		*rx_ring->hw_cons_ptr = 0;

		qede_update_rx_q_producer(rx_ring);
		rx_ring->queue_started = B_TRUE;
		cmn_err(CE_NOTE, "rx_ring%d started\n", i);

		for (j = 0; j < qede->num_tc; j++) {
			tx_ring = fp->tx_ring[j];
			
			params.vport_id = fp->vport_id;
			params.queue_id = tx_ring->tx_queue_index;
			params.stats_id = fp->stats_id;
			params.p_sb = fp->sb_info;
			params.sb_idx = TX_PI(j);

			p_phys_table = ecore_chain_get_pbl_phys(
			    &tx_ring->tx_bd_ring);
			page_cnt = ecore_chain_get_page_cnt(
			    &tx_ring->tx_bd_ring);
			status = ecore_eth_tx_queue_start(p_hwfn,
			    p_hwfn->hw_info.opaque_fid,
			    &params, 
			    0, 
			    p_phys_table,
			    page_cnt, 
			    &tx_ret_params);
			tx_ring->doorbell_addr = tx_ret_params.p_doorbell;
			tx_ring->p_cid = tx_ret_params.p_handle;	
			if (status != DDI_SUCCESS) {
				cmn_err(CE_WARN, "ecore_sp_eth_tx_queue_start "
				    "FAILED for txq%d:%d", i,j);
				return (DDI_FAILURE);
			}
			tx_ring->hw_cons_ptr = 
			    &fp->sb_info->sb_virt->pi_array[TX_PI(j)];
			/* LINTED E_CONSTANT_CONDITION */
			SET_FIELD(tx_ring->tx_db.data.params,
			    ETH_DB_DATA_DEST, DB_DEST_XCM);
			/* LINTED E_CONSTANT_CONDITION */
			SET_FIELD(tx_ring->tx_db.data.params,
			    ETH_DB_DATA_AGG_CMD, DB_AGG_CMD_SET);
			/* LINTED E_CONSTANT_CONDITION */
			SET_FIELD(tx_ring->tx_db.data.params,
			    ETH_DB_DATA_AGG_VAL_SEL, DQ_XCM_ETH_TX_BD_PROD_CMD);
			tx_ring->tx_db.data.agg_flags = DQ_XCM_ETH_DQ_CF_CMD;
			tx_ring->queue_started = B_TRUE;
			cmn_err(CE_NOTE, "tx_ring %d:%d started\n", i, j);
		}
	}

	status = qede_vport_update(qede, QEDE_VPORT_ON);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to "
		    "update vports");
		return (DDI_FAILURE);
	}
	return (status);
}

static void
qede_free_mag_elem(qede_rx_ring_t *rx_ring, qede_rx_buffer_t *rx_buffer,
    struct eth_rx_bd *bd)
{
	int i;

	if (bd != NULL) {
		bzero(bd, sizeof (*bd));
	}

	if (rx_buffer->mp != NULL) {
		freemsg(rx_buffer->mp);
		rx_buffer->mp = NULL;
	}
}

static void
qede_free_lro_rx_buffers(qede_rx_ring_t *rx_ring)
{
	int i, j; 
	qede_lro_info_t *lro_info;

	for (i = 0; i < ETH_TPA_MAX_AGGS_NUM; i++) {
		lro_info = &rx_ring->lro_info[i];
		if (lro_info->agg_state == QEDE_AGG_STATE_NONE) {
			continue;
		}
		for (j = 0; j < QEDE_MAX_BD_PER_AGG; j++) {
			if (lro_info->rx_buffer[j] == NULL) {
				break;
			}
			qede_recycle_copied_rx_buffer(
			    lro_info->rx_buffer[j]);
			lro_info->rx_buffer[j] = NULL;
		}
		lro_info->agg_state = QEDE_AGG_STATE_NONE;
	}
}

static void
qede_free_rx_buffers_legacy(qede_t *qede, qede_rx_buf_area_t *rx_buf_area)
{
	int i, j;
	u32 ref_cnt, bufs_per_page;
	qede_rx_buffer_t *rx_buffer, *first_rx_buf_in_page = 0;
	qede_rx_ring_t *rx_ring = rx_buf_area->rx_ring;
	bool free_rx_buffer;

	bufs_per_page = rx_buf_area->bufs_per_page;
	
	rx_buffer = &rx_buf_area->rx_buf_pool[0];

	if (rx_buf_area) {
		for (i = 0; i < rx_ring->rx_buf_count; i += bufs_per_page) {
			free_rx_buffer = B_TRUE;
			for (j = 0; j < bufs_per_page; j++) {
				if (!j) {
					first_rx_buf_in_page = rx_buffer;
				}
				if (rx_buffer->ref_cnt != 0) {
					ref_cnt = atomic_dec_32_nv(
					    &rx_buffer->ref_cnt);
					if (ref_cnt == 0) {
						/*
						 * Buffer is now 
						 * completely free 
						 */
						if (rx_buffer->mp) {
							freemsg(rx_buffer->mp);
							rx_buffer->mp = NULL;
						}
					} else {
						/*
						 * Since Buffer still 
						 * held up in Stack,
						 * we cant free the whole page
						 */
						free_rx_buffer = B_FALSE;
					}
				}
				rx_buffer++;
			}

			if (free_rx_buffer == B_TRUE) {
				qede_pci_free_consistent(
				    &first_rx_buf_in_page->dma_info.dma_handle,
			    	    &first_rx_buf_in_page->dma_info.acc_handle);
			}
		}

		/* 
		 * If no more buffers are with the stack
		 *  then free the buf pools 
		 */
		if (rx_buf_area->buf_upstream == 0) {
			mutex_destroy(&rx_buf_area->active_buf_list.lock);
			mutex_destroy(&rx_buf_area->passive_buf_list.lock);

			kmem_free(rx_buf_area, sizeof (qede_rx_buf_area_t));
			rx_buf_area = NULL;
			if (atomic_cas_32(&qede->detach_unsafe, 2, 2)) {
				atomic_dec_32(&qede->detach_unsafe);
			}
			
		}
	}
}


static void
qede_free_rx_buffers(qede_t *qede, qede_rx_ring_t *rx_ring)
{
	qede_free_lro_rx_buffers(rx_ring);
	qede_rx_buf_area_t *rx_buf_area = rx_ring->rx_buf_area;
	qede_free_rx_buffers_legacy(qede, rx_buf_area);
}

static void
qede_free_rx_ring_phys(qede_t *qede, qede_fastpath_t *fp)
{
	qede_rx_ring_t *rx_ring;

	ASSERT(qede != NULL);
	ASSERT(fp != NULL);


	rx_ring = fp->rx_ring;
	rx_ring->rx_buf_area->inactive = 1;

	qede_free_rx_buffers(qede, rx_ring);


	if (rx_ring->rx_bd_ring.p_virt_addr) {
		ecore_chain_free(&qede->edev, &rx_ring->rx_bd_ring);
		rx_ring->rx_bd_ring.p_virt_addr = NULL;
	}

	if (rx_ring->rx_cqe_ring.p_virt_addr) {
		ecore_chain_free(&qede->edev, &rx_ring->rx_cqe_ring);
		rx_ring->rx_cqe_ring.p_virt_addr = NULL;
		if (rx_ring->rx_cqe_ring.pbl_sp.p_virt_table) {
			rx_ring->rx_cqe_ring.pbl_sp.p_virt_table = NULL;
		}
	}
	rx_ring->hw_cons_ptr = NULL;
	rx_ring->hw_rxq_prod_addr = NULL;
	rx_ring->sw_rx_cons = 0;
	rx_ring->sw_rx_prod = 0;

}


static int
qede_init_bd(qede_t *qede, qede_rx_ring_t *rx_ring)
{
	struct eth_rx_bd *bd = NULL;
	int ret = DDI_SUCCESS;
	int i;
	qede_rx_buffer_t *rx_buffer;
	qede_rx_buf_area_t *rx_buf_area = rx_ring->rx_buf_area;
	qede_rx_buf_list_t *active_buf_list = &rx_buf_area->active_buf_list;

	for (i = 0; i < rx_ring->rx_buf_count; i++) {
		rx_buffer = &rx_buf_area->rx_buf_pool[i];
		active_buf_list->buf_list[i] = rx_buffer;
		active_buf_list->num_entries++;
		bd = ecore_chain_produce(&rx_ring->rx_bd_ring);
		if (bd == NULL) {
			qede_print_err("!%s(%d): invalid NULL bd in "
			    "rx_bd_ring", __func__, qede->instance);
			ret = DDI_FAILURE;
			goto err;
		}

		bd->addr.lo = HOST_TO_LE_32(U64_LO(
				rx_buffer->dma_info.phys_addr)); 
		bd->addr.hi = HOST_TO_LE_32(U64_HI(
				rx_buffer->dma_info.phys_addr));
	
	}
	active_buf_list->tail = 0;
err:
	return (ret);
}


qede_rx_buffer_t *
qede_get_from_active_list(qede_rx_ring_t *rx_ring,
    uint32_t *num_entries)
{
	qede_rx_buffer_t *rx_buffer;
	qede_rx_buf_list_t *active_buf_list =
	    &rx_ring->rx_buf_area->active_buf_list;
	u16 head = active_buf_list->head;

	rx_buffer = active_buf_list->buf_list[head];
	active_buf_list->buf_list[head] = NULL;
	head = (head + 1) & RX_RING_MASK;

	if (rx_buffer) {
		atomic_dec_32(&active_buf_list->num_entries);
		atomic_inc_32(&rx_ring->rx_buf_area->buf_upstream);
		atomic_inc_32(&rx_buffer->ref_cnt);
		rx_buffer->buf_state = RX_BUF_STATE_WITH_OS;

		if (rx_buffer->mp == NULL) {
			rx_buffer->mp =
			    desballoc(rx_buffer->dma_info.virt_addr,
			    rx_ring->rx_buf_size, 0, &rx_buffer->recycle);
		}
	}

	*num_entries = active_buf_list->num_entries;
	active_buf_list->head = head;

	return (rx_buffer);
}

qede_rx_buffer_t *
qede_get_from_passive_list(qede_rx_ring_t *rx_ring)
{
	qede_rx_buf_list_t *passive_buf_list =
	    &rx_ring->rx_buf_area->passive_buf_list;
	qede_rx_buffer_t *rx_buffer;
	u32 head;
	
	mutex_enter(&passive_buf_list->lock);
	head = passive_buf_list->head;
	if (passive_buf_list->buf_list[head] == NULL) {
		mutex_exit(&passive_buf_list->lock);
		return (NULL);
	}

	rx_buffer = passive_buf_list->buf_list[head];
	passive_buf_list->buf_list[head] = NULL;

	passive_buf_list->head = (passive_buf_list->head + 1) & RX_RING_MASK;
	mutex_exit(&passive_buf_list->lock);

	atomic_dec_32(&passive_buf_list->num_entries);

	return (rx_buffer);
}

void
qede_put_to_active_list(qede_rx_ring_t *rx_ring, qede_rx_buffer_t *rx_buffer)
{
	qede_rx_buf_list_t *active_buf_list =
	    &rx_ring->rx_buf_area->active_buf_list;
	u16 tail = active_buf_list->tail;

	active_buf_list->buf_list[tail] = rx_buffer;
	tail = (tail + 1) & RX_RING_MASK;

	active_buf_list->tail = tail;
	atomic_inc_32(&active_buf_list->num_entries);
}

void
qede_replenish_rx_buffers(qede_rx_ring_t *rx_ring)
{
	qede_rx_buffer_t *rx_buffer;
	int count = 0;
	struct eth_rx_bd *bd;

        /*
         * Only replenish when we have at least
         * 1/4th of the ring to do.  We don't want
         * to incur many lock contentions and
         * cycles for just a few buffers.
         * We don't bother with the passive area lock
         * here because we're just getting an
         * estimate.  Also, we only pull from
         * the passive list in this function.
         */
	
	/*
	 * Use a replenish lock because we can do the
	 * replenish operation at the end of
	 * processing the rx_ring, but also when
	 * we get buffers back from the upper
	 * layers.
	 */
	if (mutex_tryenter(&rx_ring->rx_replen_lock) == 0) {
		qede_info(rx_ring->qede, "!%s(%d): Failed to take"
			" replenish_lock",
			__func__, rx_ring->qede->instance);
		return;
	}

	rx_buffer = qede_get_from_passive_list(rx_ring);

	while (rx_buffer != NULL) {
		bd = ecore_chain_produce(&rx_ring->rx_bd_ring);
		if (bd == NULL) {
			qede_info(rx_ring->qede, "!%s(%d): bd = null",
				__func__, rx_ring->qede->instance);
			qede_put_to_passive_list(rx_ring, rx_buffer);
			break;
		}

		bd->addr.lo = HOST_TO_LE_32(U64_LO(
				rx_buffer->dma_info.phys_addr));
		bd->addr.hi = HOST_TO_LE_32(
				U64_HI(rx_buffer->dma_info.phys_addr));

		/*
		 * Put the buffer in active list since it will be
		 * posted to fw now
		 */
		qede_put_to_active_list(rx_ring, rx_buffer);
		rx_buffer->buf_state = RX_BUF_STATE_WITH_FW;
		count++;
		rx_buffer = qede_get_from_passive_list(rx_ring);
	}
	mutex_exit(&rx_ring->rx_replen_lock);
}

/*
 * Put the rx_buffer to the passive_buf_list
 */
int
qede_put_to_passive_list(qede_rx_ring_t *rx_ring, qede_rx_buffer_t *rx_buffer)
{
	qede_rx_buf_list_t *passive_buf_list =
	    &rx_ring->rx_buf_area->passive_buf_list;
	qede_rx_buf_area_t *rx_buf_area = rx_ring->rx_buf_area;
	int tail = 0;

	mutex_enter(&passive_buf_list->lock);

	tail = passive_buf_list->tail;
	passive_buf_list->tail = (passive_buf_list->tail + 1) & RX_RING_MASK;

	rx_buf_area->passive_buf_list.buf_list[tail] = rx_buffer;
	atomic_inc_32(&passive_buf_list->num_entries);

	if (passive_buf_list->num_entries > rx_ring->rx_buf_count) {
		/* Sanity check */
		qede_info(rx_ring->qede, "ERROR: num_entries (%d)"
		    " > max count (%d)",
		    passive_buf_list->num_entries,
		    rx_ring->rx_buf_count);
	}
	mutex_exit(&passive_buf_list->lock);
	return (passive_buf_list->num_entries);
}

void
qede_recycle_rx_buffer(char *arg)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	qede_rx_buffer_t *rx_buffer = (qede_rx_buffer_t *)arg;
	qede_rx_ring_t *rx_ring = rx_buffer->rx_ring;
	qede_rx_buf_area_t *rx_buf_area = rx_buffer->rx_buf_area;
	qede_t *qede = rx_ring->qede;
	u32 buf_upstream = 0, ref_cnt;
	u32 num_entries;

	if (rx_buffer->ref_cnt == 0) {
		return;
	}

	/*
	 * Since the data buffer associated with the mblk is free'ed
	 * by upper layer, allocate it again to contain proper
	 * free_func pointer
	 */
    	rx_buffer->mp = desballoc(rx_buffer->dma_info.virt_addr,
	    rx_ring->rx_buf_size, 0, &rx_buffer->recycle);

	ref_cnt = atomic_dec_32_nv(&rx_buffer->ref_cnt);
	if (ref_cnt == 1) {
		/* Put the buffer into passive_buf_list to be reused */
		num_entries = qede_put_to_passive_list(rx_ring, rx_buffer);
		if(num_entries >= 32) {
			if(mutex_tryenter(&rx_ring->rx_lock) != 0) {
				qede_replenish_rx_buffers(rx_ring);
				qede_update_rx_q_producer(rx_ring);
				mutex_exit(&rx_ring->rx_lock);
			}
		}
	} else if (ref_cnt == 0) {
		/* 
		 * This is a buffer from a previous load instance of
		 * rx_buf_area. Free the rx_buffer and if no more
		 * buffers are upstream from this rx_buf_area instance
		 * then free the rx_buf_area;
		 */
		if (rx_buffer->mp != NULL) {
			freemsg(rx_buffer->mp);
			rx_buffer->mp = NULL;
		}
		mutex_enter(&qede->drv_lock);

		buf_upstream = atomic_cas_32(&rx_buf_area->buf_upstream, 1, 1);
		if (buf_upstream >= 1) {
			atomic_dec_32(&rx_buf_area->buf_upstream);
		}
		if (rx_buf_area->inactive && (rx_buf_area->buf_upstream == 0)) {
			qede_free_rx_buffers_legacy(qede, rx_buf_area);
		}

		mutex_exit(&qede->drv_lock);
	} else {
		/* Sanity check */
		qede_info(rx_ring->qede, "rx_buffer %p"
		    " ref_cnt %d is invalid",
		    rx_buffer, ref_cnt);
	}
}

void
qede_recycle_copied_rx_buffer(qede_rx_buffer_t *rx_buffer)
{
	qede_rx_ring_t *rx_ring = rx_buffer->rx_ring;
	qede_rx_buf_area_t *rx_buf_area = rx_buffer->rx_buf_area;
	qede_t *qede = rx_ring->qede;
	u32 buf_upstream = 0, ref_cnt;

	if (rx_buffer->ref_cnt == 0) {
		/*
		 * Can happen if the buffer is being free'd
		 * in the stop routine
		 */
		qede_info(qede, "!%s(%d): rx_buffer->ref_cnt = 0",
		    __func__, qede->instance);
		return;
	}

	buf_upstream = atomic_cas_32(&rx_buf_area->buf_upstream, 1, 1);
	if (buf_upstream >= 1) {
		atomic_dec_32(&rx_buf_area->buf_upstream);
	}

	/*
	 * Since the data buffer associated with the mblk is free'ed
	 * by upper layer, allocate it again to contain proper
	 * free_func pointer
	 * Though we could also be recycling a buffer that got copied,
	 * so in that case the mp would still be intact.
	 */

	ref_cnt = atomic_dec_32_nv(&rx_buffer->ref_cnt);
	if (ref_cnt == 1) {
		qede_put_to_passive_list(rx_ring, rx_buffer);
		/* Put the buffer into passive_buf_list to be reused */
	} else if (ref_cnt == 0) {
		/* 
		 * This is a buffer from a previous load instance of
		 * rx_buf_area. Free the rx_buffer and if no more
		 * buffers are upstream from this rx_buf_area instance
		 * then free the rx_buf_area;
		 */
		qede_info(rx_ring->qede, "Free up rx_buffer %p, index %d"
		    " ref_cnt %d from a previous driver iteration",
		    rx_buffer, rx_buffer->index, ref_cnt);
		if (rx_buffer->mp != NULL) {
			freemsg(rx_buffer->mp);
			rx_buffer->mp = NULL;
		}

		if (rx_buf_area->inactive && (rx_buf_area->buf_upstream == 0)) {
			mutex_enter(&qede->drv_lock);
			qede_free_rx_buffers_legacy(qede, rx_buf_area);
			mutex_exit(&qede->drv_lock);
		}
	} else {
		/* Sanity check */
		qede_info(rx_ring->qede, "rx_buffer %p"
		    " ref_cnt %d is invalid",
		    rx_buffer, ref_cnt);
	}
}


static int
qede_alloc_rx_buffers(qede_t *qede, qede_rx_ring_t *rx_ring)
{
	int ret = DDI_SUCCESS, i, j;
	qede_rx_buffer_t *rx_buffer;
	qede_rx_buf_area_t *rx_buf_area = rx_ring->rx_buf_area;
	u32 bufs_per_page, buf_size;
	int page_size = (int)ddi_ptob(qede->dip, 1);
	qede_dma_info_t *dma_info;
	ddi_dma_cookie_t temp_cookie;
	int allocated = 0;
	u64 dma_addr;
	u8 *vaddr;
	ddi_dma_handle_t dma_handle;
	ddi_acc_handle_t acc_handle;

	if (rx_ring->rx_buf_size > page_size) {
		bufs_per_page = 1;
		buf_size = rx_ring->rx_buf_size;
	} else {
		bufs_per_page =
		    (page_size) / DEFAULT_RX_BUF_SIZE;
		buf_size = page_size;
	}

	rx_buffer = &rx_buf_area->rx_buf_pool[0];
	rx_buf_area->bufs_per_page = bufs_per_page;

	mutex_init(&rx_buf_area->active_buf_list.lock, NULL,
	    MUTEX_DRIVER, 0);
	mutex_init(&rx_buf_area->passive_buf_list.lock, NULL,
	    MUTEX_DRIVER, 0);

	for (i = 0; i < rx_ring->rx_buf_count; i += bufs_per_page) {
		dma_info = &rx_buffer->dma_info;

		ret = qede_dma_mem_alloc(qede,
			buf_size,
			DDI_DMA_READ | DDI_DMA_STREAMING | DDI_DMA_CONSISTENT,
			(caddr_t *)&dma_info->virt_addr,
			&temp_cookie,
			&dma_info->dma_handle,
			&dma_info->acc_handle,
			&qede_dma_attr_rxbuf,
			&qede_buf_acc_attr); 
		if (ret != DDI_SUCCESS) {
			goto err;
		}

		allocated++;
		vaddr = dma_info->virt_addr;
		dma_addr = temp_cookie.dmac_laddress;
		dma_handle = dma_info->dma_handle;
		acc_handle = dma_info->acc_handle;
		
		for (j = 0; j < bufs_per_page; j++) {
			dma_info = &rx_buffer->dma_info;
			dma_info->virt_addr = vaddr;
			dma_info->phys_addr = dma_addr;
			dma_info->dma_handle = dma_handle;
			dma_info->acc_handle = acc_handle;
			dma_info->offset = j * rx_ring->rx_buf_size;
			/* Populate the recycle func and arg for the buffer */
			rx_buffer->recycle.free_func = qede_recycle_rx_buffer;
			rx_buffer->recycle.free_arg = (caddr_t)rx_buffer;

			rx_buffer->mp = desballoc(dma_info->virt_addr,
				    	rx_ring->rx_buf_size, 0,
				    	&rx_buffer->recycle);
			if (rx_buffer->mp == NULL) {
				qede_warn(qede, "desballoc() failed, index %d",
				     i);
			}
			rx_buffer->rx_ring = rx_ring;
			rx_buffer->rx_buf_area = rx_buf_area;
			rx_buffer->index = i + j;
			rx_buffer->ref_cnt = 1;
			rx_buffer++;

			vaddr += rx_ring->rx_buf_size;
			dma_addr += rx_ring->rx_buf_size;
		}
		rx_ring->sw_rx_prod++;
	}

	/*
	 * Fill the rx_bd_ring with the allocated
	 * buffers
	 */
	ret = qede_init_bd(qede, rx_ring);
	if (ret != DDI_SUCCESS) {
		goto err;
	}

	rx_buf_area->buf_upstream = 0;

	return (ret);
err:
	qede_free_rx_buffers(qede, rx_ring);
	return (ret);
}

static int
qede_alloc_rx_ring_phys(qede_t *qede, qede_fastpath_t *fp)
{
	qede_rx_ring_t *rx_ring;
	qede_rx_buf_area_t *rx_buf_area;
	size_t size;

	ASSERT(qede != NULL);
	ASSERT(fp != NULL);

	rx_ring = fp->rx_ring;

	atomic_inc_32(&qede->detach_unsafe);
	/*
	 * Allocate rx_buf_area for the plumb instance
	 */
	rx_buf_area = kmem_zalloc(sizeof (*rx_buf_area), KM_SLEEP);
	if (rx_buf_area == NULL) {
		qede_info(qede, "!%s(%d): Cannot alloc rx_buf_area",
			__func__, qede->instance);
		return (DDI_FAILURE);
	}

	rx_buf_area->inactive = 0;
	rx_buf_area->rx_ring = rx_ring;
	rx_ring->rx_buf_area = rx_buf_area;
	/* Rx Buffer descriptor queue */
	if (ecore_chain_alloc(&qede->edev,
			ECORE_CHAIN_USE_TO_CONSUME_PRODUCE,
			ECORE_CHAIN_MODE_NEXT_PTR,
			ECORE_CHAIN_CNT_TYPE_U16,
			qede->rx_ring_size,
			sizeof (struct eth_rx_bd),
			&rx_ring->rx_bd_ring,
			NULL) != ECORE_SUCCESS) {
		cmn_err(CE_WARN, "Failed to allocate "
		    "ecore cqe chain");
		return (DDI_FAILURE);
	}

	/* Rx Completion Descriptor queue */
	if (ecore_chain_alloc(&qede->edev,
			ECORE_CHAIN_USE_TO_CONSUME,
			ECORE_CHAIN_MODE_PBL,
			ECORE_CHAIN_CNT_TYPE_U16,
			qede->rx_ring_size,
			sizeof (union eth_rx_cqe),
			&rx_ring->rx_cqe_ring,
			NULL) != ECORE_SUCCESS) {
		cmn_err(CE_WARN, "Failed to allocate "
		    "ecore bd chain");
		return (DDI_FAILURE);
	}

	/* Rx Data buffers */
	if (qede_alloc_rx_buffers(qede, rx_ring) != DDI_SUCCESS) {
		qede_print_err("!%s(%d): Failed to alloc rx buffers",
		    __func__, qede->instance);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static void
qede_free_tx_bd_ring(qede_t *qede, qede_fastpath_t *fp)
{
	int i;
	qede_tx_ring_t *tx_ring;
	
	ASSERT(qede != NULL);
	ASSERT(fp != NULL);

	for (i = 0; i < qede->num_tc; i++) {
		tx_ring = fp->tx_ring[i];

		if (tx_ring->tx_bd_ring.p_virt_addr) {
			ecore_chain_free(&qede->edev, &tx_ring->tx_bd_ring);
			tx_ring->tx_bd_ring.p_virt_addr = NULL;
		}
		tx_ring->hw_cons_ptr = NULL;
		tx_ring->sw_tx_cons = 0;
		tx_ring->sw_tx_prod = 0;

	}
}

static u32
qede_alloc_tx_bd_ring(qede_t *qede, qede_tx_ring_t *tx_ring)
{
	u32 ret = 0;

	ret = ecore_chain_alloc(&qede->edev,
	    ECORE_CHAIN_USE_TO_CONSUME_PRODUCE,
	    ECORE_CHAIN_MODE_PBL,
	    ECORE_CHAIN_CNT_TYPE_U16,
	    tx_ring->bd_ring_size,
	    sizeof (union eth_tx_bd_types),
	    &tx_ring->tx_bd_ring,
	    NULL);
	if (ret) {
		cmn_err(CE_WARN, "!%s(%d): Failed to alloc tx bd chain",
		    __func__, qede->instance);
		goto error;
	}


error:
	return (ret);
}

static void
qede_free_tx_bcopy_buffers(qede_tx_ring_t *tx_ring)
{
	qede_tx_bcopy_pkt_t *bcopy_pkt;
	int i;

	for (i = 0; i < tx_ring->tx_ring_size; i++) {
		bcopy_pkt = &tx_ring->bcopy_list.bcopy_pool[i];
		if(bcopy_pkt->dma_handle != NULL)
			(void) ddi_dma_unbind_handle(bcopy_pkt->dma_handle);
		if(bcopy_pkt->acc_handle != NULL) {
			ddi_dma_mem_free(&bcopy_pkt->acc_handle);
			bcopy_pkt->acc_handle = NULL;
		}
		if(bcopy_pkt->dma_handle != NULL) {
			ddi_dma_free_handle(&bcopy_pkt->dma_handle);
			bcopy_pkt->dma_handle = NULL;	
		}
		if (bcopy_pkt) {
			if (bcopy_pkt->mp) {
				freemsg(bcopy_pkt->mp);
			}
		}
	}

	if (tx_ring->bcopy_list.bcopy_pool != NULL) {
		kmem_free(tx_ring->bcopy_list.bcopy_pool,
		    tx_ring->bcopy_list.size);
		tx_ring->bcopy_list.bcopy_pool = NULL;
	}

	mutex_destroy(&tx_ring->bcopy_list.lock);
}

static u32
qede_alloc_tx_bcopy_buffers(qede_t *qede, qede_tx_ring_t *tx_ring)
{
	u32 ret = DDI_SUCCESS;
	int page_size = (int)ddi_ptob(qede->dip, 1);
	size_t size;
	qede_tx_bcopy_pkt_t *bcopy_pkt, *bcopy_list;
	int i;
	qede_dma_info_t dma_info;
	ddi_dma_cookie_t temp_cookie;

	/*
	 * If the tx_buffers size if less than the page size
	 * then try to use multiple copy buffers inside the
	 * same page. Otherwise use the whole page (or more)
	 * for the copy buffers
	 */
	if (qede->tx_buf_size > page_size) {
		size = qede->tx_buf_size;
	} else {
		size = page_size;
	}

	size = sizeof (qede_tx_bcopy_pkt_t) * qede->tx_ring_size;
	bcopy_list = kmem_zalloc(size, KM_SLEEP);
	if (bcopy_list == NULL) {
		qede_warn(qede, "!%s(%d): Failed to allocate bcopy_list",
		    __func__, qede->instance);
		ret = DDI_FAILURE;
		goto exit;
	}

	tx_ring->bcopy_list.size = size;
	tx_ring->bcopy_list.bcopy_pool = bcopy_list;
	bcopy_pkt = bcopy_list;

	tx_ring->bcopy_list.head = 0;
	tx_ring->bcopy_list.tail = 0;
	mutex_init(&tx_ring->bcopy_list.lock, NULL, MUTEX_DRIVER, 0);

	for (i = 0; i < qede->tx_ring_size; i++) {

		ret = qede_dma_mem_alloc(qede,
					qede->tx_buf_size,
					DDI_DMA_READ | DDI_DMA_STREAMING | DDI_DMA_CONSISTENT,
					(caddr_t *)&dma_info.virt_addr,
					&temp_cookie,
					&dma_info.dma_handle,
					&dma_info.acc_handle,
					&qede_dma_attr_txbuf,
					&qede_buf_acc_attr);
		if(ret) {
			ret = DDI_FAILURE;
			goto exit;
		}
		
					
		bcopy_pkt->virt_addr = dma_info.virt_addr;
		bcopy_pkt->phys_addr = temp_cookie.dmac_laddress;
		bcopy_pkt->dma_handle = dma_info.dma_handle;
		bcopy_pkt->acc_handle = dma_info.acc_handle;
		
		tx_ring->bcopy_list.free_list[i] = bcopy_pkt;
		bcopy_pkt++;
	}

exit:
	return (ret);
}

static void
qede_free_tx_dma_handles(qede_t *qede, qede_tx_ring_t *tx_ring)
{
	qede_dma_handle_entry_t *dmah_entry;
	int i;

	for (i = 0; i < tx_ring->tx_ring_size; i++) {
		dmah_entry = &tx_ring->dmah_list.dmah_pool[i];
		if (dmah_entry) {
			if (dmah_entry->dma_handle != NULL) {
				ddi_dma_free_handle(&dmah_entry->dma_handle);
				dmah_entry->dma_handle = NULL;
			} else {
				qede_info(qede, "dmah_entry %p, handle is NULL",
				     dmah_entry);
			}
		}
	}

	if (tx_ring->dmah_list.dmah_pool != NULL) {
		kmem_free(tx_ring->dmah_list.dmah_pool,
		    tx_ring->dmah_list.size);
		tx_ring->dmah_list.dmah_pool = NULL;
	}

	mutex_destroy(&tx_ring->dmah_list.lock);
}

static u32
qede_alloc_tx_dma_handles(qede_t *qede, qede_tx_ring_t *tx_ring)
{
	int i;
	size_t size;
	u32 ret = DDI_SUCCESS;
	qede_dma_handle_entry_t *dmah_entry, *dmah_list;

	size = sizeof (qede_dma_handle_entry_t) * qede->tx_ring_size;
	dmah_list = kmem_zalloc(size, KM_SLEEP);
	if (dmah_list == NULL) {
		qede_warn(qede, "!%s(%d): Failed to allocated dmah_list",
		    __func__, qede->instance);
                /* LINTED E_CONST_TRUNCATED_BY_ASSIGN */
		ret = DDI_FAILURE;
		goto exit;
	}

	tx_ring->dmah_list.size = size;
	tx_ring->dmah_list.dmah_pool = dmah_list;
	dmah_entry = dmah_list;

	tx_ring->dmah_list.head = 0;
	tx_ring->dmah_list.tail = 0;
	mutex_init(&tx_ring->dmah_list.lock, NULL, MUTEX_DRIVER, 0);

	/*
	 *
	 */
	for (i = 0; i < qede->tx_ring_size; i++) {
		ret = ddi_dma_alloc_handle(qede->dip,
		    &qede_tx_buf_dma_attr,
		    DDI_DMA_DONTWAIT,
		    NULL,
		    &dmah_entry->dma_handle);
		if (ret != DDI_SUCCESS) {
			qede_print_err("!%s(%d): dma alloc handle failed "
			    "for index %d",
			    __func__, qede->instance, i);
			/* LINTED E_CONST_TRUNCATED_BY_ASSIGN */
			ret = DDI_FAILURE;
			goto exit;
		}

		tx_ring->dmah_list.free_list[i] = dmah_entry;
		dmah_entry++;
	}
exit:
	return (ret);
}

static u32 
qede_alloc_tx_ring_phys(qede_t *qede, qede_fastpath_t *fp)
{
	int i;
	qede_tx_ring_t *tx_ring;
	u32 ret = DDI_SUCCESS;
	size_t size;
	qede_tx_recycle_list_t *recycle_list;

	ASSERT(qede != NULL);
	ASSERT(fp != NULL);

	for (i = 0; i < qede->num_tc; i++) {
		tx_ring = fp->tx_ring[i];
		tx_ring->bd_ring_size = qede->tx_ring_size;

		/*
		 * Allocate the buffer descriptor chain
		 */
		ret = qede_alloc_tx_bd_ring(qede, tx_ring);
		if (ret) {
			cmn_err(CE_WARN, "!%s(%d): failed, %s",
			    __func__, qede->instance, qede_get_ddi_fail(ret));
			return (ret);
		}

		/*
		 * Allocate copy mode buffers
		 */
		ret = qede_alloc_tx_bcopy_buffers(qede, tx_ring);
		if (ret) {
			qede_print_err("!%s(%d): Failed to alloc tx copy "
			    "buffers", __func__, qede->instance);
			/* LINTED E_CONST_TRUNCATED_BY_ASSIGN */
			ret = DDI_FAILURE;
			goto exit;
		}

		/*
		 * Allocate dma handles for mapped mode
		 */
		ret = qede_alloc_tx_dma_handles(qede, tx_ring);
		if (ret) {
			qede_print_err("!%s(%d): Failed to alloc tx dma "
			    "handles", __func__, qede->instance);
			/* LINTED E_CONST_TRUNCATED_BY_ASSIGN */
			ret = DDI_FAILURE;
			goto exit; 
		}

		/* Allocate tx_recycle list */
		size = sizeof (qede_tx_recycle_list_t) * qede->tx_ring_size;
		recycle_list = kmem_zalloc(size, KM_SLEEP);
		if (recycle_list == NULL) {
			qede_warn(qede, "!%s(%d): Failed to allocate"
			    " tx_recycle_list", __func__, qede->instance);
			/* LINTED E_CONST_TRUNCATED_BY_ASSIGN */
			ret = DDI_FAILURE;
			goto exit;
		}

		tx_ring->tx_recycle_list = recycle_list;
	}
exit:
	return (ret);
}

static void
/* LINTED E_FUNC_ARG_UNUSED */
qede_free_sb_phys(qede_t *qede, qede_fastpath_t *fp)
{
	qede_pci_free_consistent(&fp->sb_dma_handle, &fp->sb_acc_handle);
	fp->sb_virt = NULL;
	fp->sb_phys = 0;
}

static int
qede_alloc_sb_phys(qede_t *qede, qede_fastpath_t *fp)
{
	int status;
	int sb_id;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *p_hwfn;
	qede_vector_info_t *vect_info = fp->vect_info;
	ddi_dma_cookie_t sb_cookie;

	ASSERT(qede != NULL);
	ASSERT(fp != NULL);

	/*
	 * In the case of multiple hardware engines,
	 * interrupts are spread across all of them.
	 * In the case of only one engine, all
	 * interrupts are handled by that engine.
	 * In the case of 2 engines, each has half
	 * of the interrupts.
	 */
	sb_id = vect_info->vect_index;
	p_hwfn = &edev->hwfns[sb_id % qede->num_hwfns];

	/* Allocate dma mem. for status_block */
	status = qede_dma_mem_alloc(qede,
	    sizeof (struct status_block),
	    (DDI_DMA_RDWR | DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    (caddr_t *)&fp->sb_virt,
	    &sb_cookie,
	    &fp->sb_dma_handle,
	    &fp->sb_acc_handle,
	    &qede_desc_dma_attr,
	    &qede_desc_acc_attr);

	if (status != DDI_SUCCESS) {
		qede_info(qede, "Failed to allocate status_block dma mem");
		return (status);
	}

	fp->sb_phys = sb_cookie.dmac_laddress;


	status = ecore_int_sb_init(p_hwfn, 
			p_hwfn->p_main_ptt, 
			fp->sb_info,
			(void *)fp->sb_virt,
			fp->sb_phys, 
			fp->fp_index);
	if (status != ECORE_SUCCESS) {
		cmn_err(CE_WARN, "Failed ecore_int_sb_init");
		return (DDI_FAILURE);
	}

	return (status);
}

static void
qede_free_tx_ring_phys(qede_t *qede, qede_fastpath_t *fp)
{
	qede_tx_ring_t *tx_ring;
	int i;

	for (i = 0; i < qede->num_tc; i++) {
		tx_ring = fp->tx_ring[i];
		qede_free_tx_dma_handles(qede, tx_ring);
		qede_free_tx_bcopy_buffers(tx_ring);
		qede_free_tx_bd_ring(qede, fp);

		if (tx_ring->tx_recycle_list) {
			kmem_free(tx_ring->tx_recycle_list,
			    sizeof (qede_tx_recycle_list_t)
			    * qede->tx_ring_size);
		}
	}
}

static void
qede_fastpath_free_phys_mem(qede_t *qede)
{
	int  i;
	qede_fastpath_t *fp;

	for (i = 0; i < qede->num_fp; i++) {
		fp = &qede->fp_array[i];

		qede_free_rx_ring_phys(qede, fp);
		qede_free_tx_ring_phys(qede, fp);
		qede_free_sb_phys(qede, fp);
	}
}

/*
 * Save dma_handles associated with the fastpath elements
 * allocate by ecore for doing dma_sync in the fast_path
 */
static int
qede_save_fp_dma_handles(qede_t *qede, qede_fastpath_t *fp)
{
	int ret, i;
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;

	rx_ring = fp->rx_ring;

	/* Rx bd ring dma_handle */
	ret = qede_osal_find_dma_handle_for_block(qede,
	    (void *)rx_ring->rx_bd_ring.p_phys_addr,
	    &rx_ring->rx_bd_dmah); 
	if (ret != DDI_SUCCESS) {
		qede_print_err("!%s(%d): Cannot find dma_handle for "
		    "rx_bd_ring, addr %p", __func__, qede->instance,
		    rx_ring->rx_bd_ring.p_phys_addr);
		goto exit;
	}

	/* rx cqe ring dma_handle */
	ret = qede_osal_find_dma_handle_for_block(qede,
	    (void *)rx_ring->rx_cqe_ring.p_phys_addr,
	    &rx_ring->rx_cqe_dmah);
	if (ret != DDI_SUCCESS) {
		qede_print_err("!%s(%d): Cannot find dma_handle for "
		    "rx_cqe_ring, addr %p", __func__, qede->instance,
		    rx_ring->rx_cqe_ring.p_phys_addr);
		goto exit;
	}
	/* rx cqe ring pbl */
	ret = qede_osal_find_dma_handle_for_block(qede,
	    (void *)rx_ring->rx_cqe_ring.pbl_sp.p_phys_table,
	    &rx_ring->rx_cqe_pbl_dmah);
	if (ret) {
		qede_print_err("!%s(%d): Cannot find dma_handle for "
		    "rx_cqe pbl, addr %p", __func__, qede->instance,
		    rx_ring->rx_cqe_ring.pbl_sp.p_phys_table);
		goto exit;
	}

	/* tx_bd ring dma_handle(s) */
	for (i = 0; i < qede->num_tc; i++) {
		tx_ring = fp->tx_ring[i];

		ret = qede_osal_find_dma_handle_for_block(qede,
		    (void *)tx_ring->tx_bd_ring.p_phys_addr,
		    &tx_ring->tx_bd_dmah);
		if (ret != DDI_SUCCESS) {
			qede_print_err("!%s(%d): Cannot find dma_handle "
			    "for tx_bd_ring, addr %p", __func__,
			    qede->instance,
			    tx_ring->tx_bd_ring.p_phys_addr);
			goto exit;
		}

		ret = qede_osal_find_dma_handle_for_block(qede,
		    (void *)tx_ring->tx_bd_ring.pbl_sp.p_phys_table,
		    &tx_ring->tx_pbl_dmah);
		if (ret) {
			qede_print_err("!%s(%d): Cannot find dma_handle for "
			    "tx_bd pbl, addr %p", __func__, qede->instance,
			    tx_ring->tx_bd_ring.pbl_sp.p_phys_table);
			goto exit;
		}
	}

exit:
	return (ret);
}

int
qede_fastpath_alloc_phys_mem(qede_t *qede)
{
	int status = 0, i;
	qede_fastpath_t *fp;

	for (i = 0; i < qede->num_fp; i++) {
		fp = &qede->fp_array[i];

		status = qede_alloc_sb_phys(qede, fp);
		if (status != DDI_SUCCESS) {
			goto err;
		}

		status = qede_alloc_rx_ring_phys(qede, fp);
		if (status != DDI_SUCCESS) {
			goto err;
		}

		status = qede_alloc_tx_ring_phys(qede, fp);
		if (status != DDI_SUCCESS) {
			goto err;
		}
		status = qede_save_fp_dma_handles(qede, fp);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}
	return (status);
err:
	qede_fastpath_free_phys_mem(qede);
	return (status);
}

static int
qede_fastpath_config(qede_t *qede)
{
	int i, j;
	qede_fastpath_t *fp;
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;
	qede_vector_info_t *vect_info;
	int num_fp, num_hwfns;

	ASSERT(qede != NULL);

	num_fp = qede->num_fp;
	num_hwfns = qede->num_hwfns;

	vect_info = &qede->intr_ctx.intr_vect_info[num_hwfns];
	fp = &qede->fp_array[0];
	tx_ring = &qede->tx_array[0][0];

	for (i = 0; i < num_fp; i++, fp++, vect_info++) {
		fp->sb_info = &qede->sb_array[i];
		fp->qede = qede;
		fp->fp_index = i;
		/* 
		 * With a single hwfn, all fp's hwfn index should be zero 
		 * for all fp entries. If there are two engines this 
		 * index should altenate between 0 and 1.
		 */
		fp->fp_hw_eng_index = fp->fp_index % num_hwfns;
		fp->vport_id = 0;
		fp->stats_id = 0;
		fp->rss_id = fp->fp_index;
		fp->rx_queue_index = fp->fp_index; 
		fp->vect_info = vect_info; 
		/*
		 * After vport update, interrupts will be
		 * running, so we need to intialize our
		 * enable/disable gate as such.
		 */ 
		fp->disabled_by_poll = 0;

		/* rx_ring setup */
		rx_ring = &qede->rx_array[i];
		fp->rx_ring = rx_ring;
		rx_ring->fp = fp;
		rx_ring->rx_buf_count = qede->rx_buf_count;
		rx_ring->rx_buf_size = qede->rx_buf_size;
		rx_ring->qede = qede;
		rx_ring->sw_rx_cons = 0;
		rx_ring->rx_copy_threshold = qede->rx_copy_threshold;
		rx_ring->rx_low_buffer_threshold =
		    qede->rx_low_buffer_threshold;
		rx_ring->queue_started = B_FALSE;

		/* tx_ring setup */
		for (j = 0; j < qede->num_tc; j++) {
			tx_ring = &qede->tx_array[j][i];
			fp->tx_ring[j] = tx_ring;
			tx_ring->qede = qede;
			tx_ring->fp = fp;
			tx_ring->fp_idx = i;
			tx_ring->tx_queue_index = i * qede->num_fp + 
			    fp->fp_index;
			tx_ring->tx_buf_size = qede->tx_buf_size;
			tx_ring->tx_ring_size = qede->tx_ring_size;
			tx_ring->queue_started = B_FALSE;
#ifdef	DBLK_DMA_PREMAP
			tx_ring->pm_handle = qede->pm_handle;
#endif

			tx_ring->doorbell_addr =
			    qede->doorbell;
			tx_ring->doorbell_handle =
			    qede->doorbell_handle;
		}
	}

	return (DDI_SUCCESS);
}

/*
 * op = 1, Initialize link
 * op = 0, Destroy link
 */
int
qede_configure_link(qede_t *qede, bool op) 
{
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *hwfn;
	struct ecore_ptt *ptt = NULL;
	int i, ret = DDI_SUCCESS;

	for_each_hwfn(edev, i) {
		hwfn = &edev->hwfns[i];
		qede_info(qede, "Configuring link for hwfn#%d", i);

		ptt = ecore_ptt_acquire(hwfn);
		if (ptt == NULL) {
			qede_info(qede, "Cannot reserver ptt from ecore");
			ret = DDI_FAILURE;
			goto exit;
		}

		ret = ecore_mcp_set_link(hwfn, ptt, op);

		ecore_ptt_release(hwfn, ptt);
		if (ret) {
			/* if link config fails, make sure ptt is released */
			goto exit;
		}
	}
exit:
	return (ret);
}

/*
 * drv_lock must be held by the caller.
 */
int
qede_stop(qede_t *qede)
{
	int status;

	ASSERT(mutex_owned(&qede->drv_lock));
	qede->qede_state = QEDE_STATE_STOPPING;

	mac_link_update(qede->mac_handle, LINK_STATE_DOWN);

	qede_disable_all_fastpath_intrs(qede);
	status = qede_configure_link(qede, 0 /* Re-Set */);
	if (status) {
		/* LINTED E_BAD_FORMAT_ARG_TYPE2 */
		cmn_err(CE_NOTE, "!%s(%d): Failed to reset link",
		    __func__, qede->instance);
		return (status);
	}
	qede_clear_filters(qede);
	status = qede_fastpath_stop_queues(qede);
	if (status != DDI_SUCCESS) {
		/* LINTED E_BAD_FORMAT_ARG_TYPE2 */
		cmn_err(CE_WARN, "qede_stop:"
		    " qede_fastpath_stop_queues FAILED "
		    " qede=%p\n",
		    qede);
		return (status);
	}

	qede_fastpath_free_phys_mem(qede);
	
	qede->qede_state = QEDE_STATE_STOPPED;
	/* LINTED E_BAD_FORMAT_ARG_TYPE2 */
	cmn_err(CE_WARN, "qede_stop SUCCESS =%p\n", qede);
	return (DDI_SUCCESS);
}

/*
 * drv_lock must be held by the caller.
 */
int
qede_start(qede_t *qede)
{
	int status;

	ASSERT(mutex_owned(&qede->drv_lock));

	qede->qede_state = QEDE_STATE_STARTING;

	mac_link_update(qede->mac_handle, LINK_STATE_DOWN);

	/* 
	 * Configure the fastpath blocks with
	 * the sb_info, rx_ring and tx_rings
	 */
	if (qede_fastpath_config(qede) != DDI_SUCCESS) {
		/* LINTED E_BAD_FORMAT_ARG_TYPE2 */
		qede_print_err("!%s(%d): qede_fastpath_config failed",
		    __func__, qede->instance);
		return (DDI_FAILURE);
	}

	
	/*
	 * Allocate the physical memory
	 * for fastpath.   
	 */
	status = qede_fastpath_alloc_phys_mem(qede);
	if (status) {
		cmn_err(CE_NOTE, "fastpath_alloc_phys_mem "
		    " failed qede=%p\n", qede);
		return (DDI_FAILURE);
	}
	
	status = qede_fastpath_start_queues(qede);
	if (status) {
		cmn_err(CE_NOTE, "fp_start_queues "
		    " failed qede=%p\n", qede);
		goto err_out1;
	}

	cmn_err(CE_NOTE, "qede_start fp_start_queues qede=%p\n", qede);

	status = qede_configure_link(qede, 1 /* Set */);
	if (status) {
		cmn_err(CE_NOTE, "!%s(%d): Failed to configure link",
		    __func__, qede->instance);
		goto err_out1;
	}

	/*
	 * Put interface in regular mode 
	 */
	if (qede_set_filter_rx_mode(qede, 
		QEDE_FILTER_RX_MODE_REGULAR) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "!%s(%d): Failed to set filter mode",
		    __func__, qede->instance);
		goto err_out1;
	}

	status = qede_enable_all_fastpath_intrs(qede);
	if (status) {
		/* LINTED E_BAD_FORMAT_ARG_TYPE2 */
		cmn_err(CE_NOTE, "!%s(%d): Failed to enable intrs",
		    __func__, qede->instance);
		goto err_out2;
	}
	qede->qede_state = QEDE_STATE_STARTED;
	cmn_err(CE_NOTE, "!%s(%d): SUCCESS",
		    __func__, qede->instance);

	return (status);

err_out2:
	(void) qede_fastpath_stop_queues(qede);
err_out1:
	qede_fastpath_free_phys_mem(qede);
	return (DDI_FAILURE);
}

static void
qede_free_attach_resources(qede_t *qede)
{
	struct ecore_dev *edev;
	int status;	
	
	edev = &qede->edev;

	if (qede->attach_resources & QEDE_ECORE_HW_INIT) {
		if (ecore_hw_stop(edev) != ECORE_SUCCESS) {
			cmn_err(CE_NOTE, "%s(%d): ecore_hw_stop: failed\n",
			    __func__, qede->instance);
		}
		qede->attach_resources &= ~QEDE_ECORE_HW_INIT;
	}
	
	if (qede->attach_resources & QEDE_SP_INTR_ENBL) {
		status = qede_disable_slowpath_intrs(qede);
		if (status != DDI_SUCCESS) {
			qede_print("%s(%d): qede_disable_slowpath_intrs Failed",
			    __func__, qede->instance);
		} 
		qede->attach_resources &= ~QEDE_SP_INTR_ENBL;
	}
	if (qede->attach_resources & QEDE_KSTAT_INIT) {
		qede_kstat_fini(qede);
		qede->attach_resources &= ~QEDE_KSTAT_INIT;
	}
	

	if (qede->attach_resources & QEDE_GLD_INIT) {
		status = mac_unregister(qede->mac_handle);
		if (status != 0) {
			qede_print("%s(%d): mac_unregister Failed",
			    __func__, qede->instance);
		} 
		qede->attach_resources &= ~QEDE_GLD_INIT;
	}

	if (qede->attach_resources & QEDE_EDEV_CONFIG) {
		ecore_resc_free(edev);
		qede->attach_resources &= ~QEDE_EDEV_CONFIG;
	}

	if (qede->attach_resources & QEDE_INTR_CONFIG) {
		qede_unconfig_intrs(qede);
		qede->attach_resources &= ~QEDE_INTR_CONFIG;
	}

	if (qede->attach_resources & QEDE_INTR_ALLOC) {
		qede_free_intrs(qede);
		qede->attach_resources &= ~QEDE_INTR_ALLOC;
	}

	if (qede->attach_resources & QEDE_INIT_LOCKS) {
		qede_destroy_locks(qede);
		qede->attach_resources &= ~QEDE_INIT_LOCKS;
	}

	if (qede->attach_resources & QEDE_IO_STRUCT_ALLOC) {
		qede_free_io_structs(qede);
		qede->attach_resources &= ~QEDE_IO_STRUCT_ALLOC;
	}
#ifdef QEDE_LSR
	if (qede->attach_resources & QEDE_CALLBACK) {


		status = ddi_cb_unregister(qede->callback_hdl);
		if (status != DDI_SUCCESS) {
		} 
		qede->attach_resources &= ~QEDE_CALLBACK;
	}
#endif
	if (qede->attach_resources & QEDE_ECORE_HW_PREP) {
		ecore_hw_remove(edev);
		qede->attach_resources &= ~QEDE_ECORE_HW_PREP;
	}

	if (qede->attach_resources & QEDE_PCI) {
		qede_unconfig_pci(qede);
		qede->attach_resources &= ~QEDE_PCI;
	}

	if (qede->attach_resources & QEDE_FM) {
		qede_unconfig_fm(qede);
		qede->attach_resources &= ~QEDE_FM;
	}

	/*
	 * Check for possible mem. left behind by ecore
	 */
	(void) qede_osal_cleanup(qede);

	if (qede->attach_resources & QEDE_STRUCT_ALLOC) {
		ddi_set_driver_private(qede->dip, NULL);
		qede->attach_resources &= ~QEDE_STRUCT_ALLOC;
		kmem_free(qede, sizeof (qede_t));
	}
}

/*
 * drv_lock must be held by the caller.
 */
static int
qede_suspend(qede_t *qede)
{
	// STUB
	ASSERT(mutex_owned(&qede->drv_lock));
	printf("in qede_suspend\n");
	return (DDI_FAILURE);
}

static int
qede_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
    	qede_t *qede;
	struct ecore_dev *edev;
	int instance;
	uint32_t vendor_id;
	uint32_t device_id;
	struct ecore_hwfn *p_hwfn;
	struct ecore_ptt *p_ptt;
	struct ecore_mcp_link_params *link_params;
	struct ecore_hw_init_params hw_init_params;
	struct ecore_drv_load_params load_params;
	int *props;
       	uint32_t num_props;
	int rc = 0;

    	switch (cmd) {
    	default:
       		return (DDI_FAILURE);
    
	case DDI_RESUME:
	{
       		qede = (qede_t * )ddi_get_driver_private(dip);
        	if (qede == NULL || qede->dip != dip) {
			cmn_err(CE_NOTE, "qede:%s: Could not allocate"
			    " adapter structure\n", __func__);
			return (DDI_FAILURE);
        	}

		mutex_enter(&qede->drv_lock);
		if (qede->qede_state != QEDE_STATE_SUSPENDED) {
			mutex_exit(&qede->drv_lock);
        		return (DDI_FAILURE);
		}
        
		if (qede_resume(qede) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "%s:%d resume operation failure\n",
			    __func__, qede->instance);
			mutex_exit(&qede->drv_lock);
            		return (DDI_FAILURE);
        	}

		qede->qede_state = QEDE_STATE_ATTACHED;
		mutex_exit(&qede->drv_lock);
        	return (DDI_SUCCESS);
	}
	case DDI_ATTACH:
	{
    		instance = ddi_get_instance(dip);
	    	cmn_err(CE_NOTE, "qede_attach(%d): Enter",
		    instance);

    		/* Allocate main structure rounded up to cache line size */
    		if ((qede = kmem_zalloc(sizeof (qede_t), KM_SLEEP)) == NULL) {
			cmn_err(CE_NOTE, "!%s(%d): Could not allocate adapter "
			    "structure\n", __func__, instance);
        		return (DDI_FAILURE);
    		}

		qede->attach_resources |= QEDE_STRUCT_ALLOC;
    		ddi_set_driver_private(dip, qede);
		qede->dip = dip;
   		qede->instance = instance;
    		snprintf(qede->name, sizeof (qede->name), "qede%d", instance);
		edev = &qede->edev;
	
		if (qede_config_fm(qede) != DDI_SUCCESS) {
        		goto exit_with_err;
		}
		qede->attach_resources |= QEDE_FM;

		/* 
		 * Do PCI config setup and map the register 
		 * and doorbell space */
		if (qede_config_pci(qede) != DDI_SUCCESS) {
        		goto exit_with_err;
		}
		qede->attach_resources |= QEDE_PCI;

		/*
		 * Setup OSAL mem alloc related locks.
		 * Do not call any ecore functions without
		 * initializing these locks
		 */
		mutex_init(&qede->mem_list.mem_list_lock, NULL,
		    MUTEX_DRIVER, 0);
		mutex_init(&qede->phys_mem_list.lock, NULL,
		    MUTEX_DRIVER, 0);
		QEDE_INIT_LIST_HEAD(&qede->mem_list.mem_list_head);
		QEDE_INIT_LIST_HEAD(&qede->phys_mem_list.head);
		QEDE_INIT_LIST_HEAD(&qede->mclist.head);


		/*
		 * FIXME: this function calls ecore api, but
		 * dp_level and module are not yet set
		 */
		if (qede_prepare_edev(qede) != ECORE_SUCCESS) {
			// report fma
        		goto exit_with_err;
		}

		qede->num_hwfns = edev->num_hwfns;
		qede->num_tc = 1;
		memcpy(qede->ether_addr, edev->hwfns->hw_info.hw_mac_addr,
		    ETHERADDRL);
		qede_info(qede, "Interface mac_addr : " MAC_STRING,
		    MACTOSTR(qede->ether_addr));
		qede->attach_resources |= QEDE_ECORE_HW_PREP;

		if (qede_set_operating_params(qede) != DDI_SUCCESS) {
        		goto exit_with_err;
		}
		qede->attach_resources |= QEDE_SET_PARAMS;
#ifdef QEDE_LSR
		if (ddi_cb_register(qede->dip,
	    	    qede->callback_flags,
	    	    qede_callback,
		    qede,
	    	    NULL,
	    	    &qede->callback_hdl)) {
			goto exit_with_err;
		}
		qede->attach_resources |= QEDE_CALLBACK;
#endif
		qede_cfg_reset(qede);

		if (qede_alloc_intrs(qede)) {
			cmn_err(CE_NOTE, "%s: Could not allocate interrupts\n",
			    __func__);
        		goto exit_with_err;
		}
	
		qede->attach_resources |= QEDE_INTR_ALLOC;

		if (qede_config_intrs(qede)) {
			cmn_err(CE_NOTE, "%s: Could not allocate interrupts\n",
			    __func__);
        		goto exit_with_err;
		}
		qede->attach_resources |= QEDE_INTR_CONFIG;

    		if (qede_alloc_io_structs(qede) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "%s: Could not allocate data"
			    " path structures\n", __func__);
        		goto exit_with_err;
    		}

		qede->attach_resources |= QEDE_IO_STRUCT_ALLOC;

		/* Lock init cannot fail */
		qede_init_locks(qede);
		qede->attach_resources |= QEDE_INIT_LOCKS;


		if (qede_config_edev(qede)) {
			cmn_err(CE_NOTE, "%s: Could not configure ecore \n",
			    __func__);
			goto exit_with_err;
		}
		qede->attach_resources |= QEDE_EDEV_CONFIG;

		if (qede_kstat_init(qede) == B_FALSE) {
			cmn_err(CE_NOTE, "%s: Could not initialize kstat \n",
			    __func__);
			goto exit_with_err;

		}
		qede->attach_resources |= QEDE_KSTAT_INIT;

		if (qede_gld_init(qede) == B_FALSE) {
			cmn_err(CE_NOTE, "%s: Failed call to qede_gld_init",
			    __func__);
			goto exit_with_err;
		}

		qede->attach_resources |= QEDE_GLD_INIT;

		if (qede_enable_slowpath_intrs(qede)) {
			cmn_err(CE_NOTE, "%s: Could not enable interrupts\n",
			    __func__);
			goto exit_with_err;
		}

		qede->attach_resources |= QEDE_SP_INTR_ENBL;

		cmn_err(CE_NOTE, "qede->attach_resources = %x\n", 
		    qede->attach_resources);			

		memset((void *)&hw_init_params, 0, 
		    sizeof (struct ecore_hw_init_params));
		hw_init_params.p_drv_load_params = &load_params;

		hw_init_params.p_tunn = NULL; 
		hw_init_params.b_hw_start = true;
		hw_init_params.int_mode = qede->intr_ctx.intr_mode;
		hw_init_params.allow_npar_tx_switch = false;
		hw_init_params.bin_fw_data = NULL;
		load_params.is_crash_kernel = false;
		load_params.mfw_timeout_val = 0; 
		load_params.avoid_eng_reset = false;
		load_params.override_force_load = 
		    ECORE_OVERRIDE_FORCE_LOAD_NONE;

		if (ecore_hw_init(edev, &hw_init_params) != ECORE_SUCCESS) {
			cmn_err(CE_NOTE,
			    "%s: Could not initialze ecore block\n",
			     __func__);
			goto exit_with_err;
		}
		qede->attach_resources |= QEDE_ECORE_HW_INIT;
		qede->qede_state = QEDE_STATE_ATTACHED;

		qede->detach_unsafe = 0;

		snprintf(qede->version,
             		sizeof (qede->version),
             		"%d.%d.%d",
             		MAJVERSION,
             		MINVERSION,
             		REVVERSION);

		snprintf(qede->versionFW,
             		sizeof (qede->versionFW),
             		"%d.%d.%d.%d",
             		FW_MAJOR_VERSION,
             		FW_MINOR_VERSION,
             		FW_REVISION_VERSION,
             		FW_ENGINEERING_VERSION);

		p_hwfn = &qede->edev.hwfns[0];
		p_ptt = ecore_ptt_acquire(p_hwfn);
		/*
		 * (test) : saving the default link_input params 
		 */
		link_params = ecore_mcp_get_link_params(p_hwfn);
		memset(&qede->link_input_params, 0, 
		    sizeof (qede_link_input_params_t));
		memcpy(&qede->link_input_params.default_link_params, 
		    link_params,
		    sizeof (struct ecore_mcp_link_params));

		p_hwfn = ECORE_LEADING_HWFN(edev);
        	ecore_mcp_get_mfw_ver(p_hwfn, p_ptt, &qede->mfw_ver, NULL);

		ecore_ptt_release(p_hwfn, p_ptt);

		snprintf(qede->versionMFW,
			sizeof (qede->versionMFW),
			"%d.%d.%d.%d",
			(qede->mfw_ver >> 24) & 0xFF,
	        	(qede->mfw_ver >> 16) & 0xFF,
			(qede->mfw_ver >> 8) & 0xFF,
			qede->mfw_ver & 0xFF);	

		snprintf(qede->chip_name,
             		sizeof (qede->chip_name),
			"%s",
			ECORE_IS_BB(edev) ? "BB" : "AH");

	   	snprintf(qede->chipID,
			sizeof (qede->chipID),
             		"0x%x",
             		qede->edev.chip_num);

		*qede->bus_dev_func = 0;
		vendor_id = 0;
		device_id = 0;


		rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, qede->dip,
					0, "reg", &props, &num_props);
		if((rc == DDI_PROP_SUCCESS) && (num_props > 0)) {

		snprintf(qede->bus_dev_func,
			sizeof (qede->bus_dev_func),
			"%04x:%02x:%02x",
			PCI_REG_BUS_G(props[0]),
			PCI_REG_DEV_G(props[0]),
			PCI_REG_FUNC_G(props[0]));
	
		/* 
		 * This information is used 
		 * in the QEDE_FUNC_INFO ioctl 
		 */
		qede->pci_func = (uint8_t) PCI_REG_FUNC_G(props[0]);

		ddi_prop_free(props);

		}

		rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, qede->dip,
					0, "vendor-id", &props, &num_props);
		if((rc == DDI_PROP_SUCCESS) && (num_props > 0)) {
			vendor_id = props[0];
			ddi_prop_free(props);
		}
		rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, qede->dip,
					0, "device-id", &props, &num_props);
		if((rc == DDI_PROP_SUCCESS) && (num_props > 0)) {
			device_id = props[0];
			ddi_prop_free(props);
		}


		snprintf(qede->vendor_device,
			sizeof (qede->vendor_device),
			"%04x:%04x",
			vendor_id,
			device_id);


		snprintf(qede->intrAlloc,
			sizeof (qede->intrAlloc), "%d %s",
			(qede->intr_ctx.intr_type_in_use == DDI_INTR_TYPE_FIXED)
 			? 1 :
			qede->intr_ctx.intr_vect_allocated,
			(qede->intr_ctx.intr_type_in_use == DDI_INTR_TYPE_MSIX)
			? "MSIX" :
			(qede->intr_ctx.intr_type_in_use == DDI_INTR_TYPE_MSI) 
			? "MSI"  : "Fixed");

	        qede_print("%s(%d): success, addr %p chip %s id %s intr %s\n",
		    __func__, qede->instance, qede, qede->chip_name, 
		    qede->vendor_device,qede->intrAlloc);

	        qede_print("%s(%d): version %s FW %s MFW %s\n",
		    __func__, qede->instance, qede->version,
		    qede->versionFW, qede->versionMFW);

		return (DDI_SUCCESS);
	}
	}
exit_with_err:
	cmn_err(CE_WARN, "%s:%d   failed %x\n", __func__, qede->instance, 
	    qede->attach_resources);			
	(void)qede_free_attach_resources(qede);
	return (DDI_FAILURE);
}

static int
qede_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	qede_t *qede;
	int status;
	uint32_t count = 0;

	qede = (qede_t *)ddi_get_driver_private(dip);
	if ((qede == NULL) || (qede->dip != dip)) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	default:
		return (DDI_FAILURE);
	case DDI_SUSPEND:
		mutex_enter(&qede->drv_lock);
		status = qede_suspend(qede); 
		if (status != DDI_SUCCESS) {
			mutex_exit(&qede->drv_lock);
			return (DDI_FAILURE);
		}

		qede->qede_state = QEDE_STATE_SUSPENDED;
		mutex_exit(&qede->drv_lock);
		return (DDI_SUCCESS);

	case DDI_DETACH:
		mutex_enter(&qede->drv_lock);
		if (qede->qede_state == QEDE_STATE_STARTED) {
			qede->plumbed = 0;
			status = qede_stop(qede);
			if (status != DDI_SUCCESS) {
				qede->qede_state = QEDE_STATE_FAILED;
				mutex_exit(&qede->drv_lock);
				return (DDI_FAILURE);
			}
		}
		mutex_exit(&qede->drv_lock);
                if (qede->detach_unsafe) {
                        /*
                         * wait for rx buffers to be returned from
                         * upper layers
                         */
                        count = 0;
                        while ((qede->detach_unsafe) && (count < 100)) {
                                qede_delay(100);
                                count++;
                        }
                        if (qede->detach_unsafe) {
                                qede_info(qede, "!%s(%d) : Buffers still with"
                                    " OS, failing detach\n",
                                    qede->name, qede->instance);
                                return (DDI_FAILURE);
                        }
                }
		qede_free_attach_resources(qede);
		return (DDI_SUCCESS);
	}
}

static int
/* LINTED E_FUNC_ARG_UNUSED */
qede_quiesce(dev_info_t *dip)
{
	qede_t *qede = (qede_t *)ddi_get_driver_private(dip);
	struct ecore_dev *edev = &qede->edev;
	int status = DDI_SUCCESS;
	struct ecore_hwfn *p_hwfn;
	struct ecore_ptt *p_ptt = NULL;

	mac_link_update(qede->mac_handle, LINK_STATE_DOWN);
	p_hwfn = ECORE_LEADING_HWFN(edev);
	p_ptt = ecore_ptt_acquire(p_hwfn);
	if (p_ptt) {
		status = ecore_start_recovery_process(p_hwfn, p_ptt);
		ecore_ptt_release(p_hwfn, p_ptt);
		OSAL_MSLEEP(5000);
	}
	return (status);

}


DDI_DEFINE_STREAM_OPS(qede_dev_ops, nulldev, nulldev, qede_attach, qede_detach,
    nodev, NULL, D_MP, NULL, qede_quiesce);

static struct modldrv qede_modldrv =
{
    &mod_driverops,    /* drv_modops (must be mod_driverops for drivers) */
    QEDE_PRODUCT_INFO, /* drv_linkinfo (string displayed by modinfo) */
    &qede_dev_ops      /* drv_dev_ops */
};


static struct modlinkage qede_modlinkage =
{
    MODREV_1,        /* ml_rev */
    (&qede_modldrv), /* ml_linkage */
    NULL           /* NULL termination */
};

int 
_init(void)
{
    int rc;

    qede_dev_ops.devo_cb_ops->cb_str = NULL;
    mac_init_ops(&qede_dev_ops, "qede");

    /* Install module information with O/S */
    if ((rc = mod_install(&qede_modlinkage)) != DDI_SUCCESS) {
        mac_fini_ops(&qede_dev_ops);
	cmn_err(CE_NOTE, "mod_install failed");
        return (rc);
    }

    return (rc);
}


int 
_fini(void)
{
    int rc;

    if ((rc = mod_remove(&qede_modlinkage)) == DDI_SUCCESS) {
        mac_fini_ops(&qede_dev_ops);
    }

    return (rc);
}


int
_info(struct modinfo * modinfop)
{
    return (mod_info(&qede_modlinkage, modinfop));
}
