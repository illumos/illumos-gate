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

#ifndef	_SYS_HXGE_HXGE_COMMON_IMPL_H
#define	_SYS_HXGE_HXGE_COMMON_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	HPI_REGH(hpi_handle)		(hpi_handle.regh)
#define	HPI_REGP(hpi_handle)		(hpi_handle.regp)

#define		NO_DEBUG	0x0000000000000000ULL
#define		RX_CTL		0x0000000000000001ULL
#define		TX_CTL		0x0000000000000002ULL
#define		OBP_CTL		0x0000000000000004ULL
#define		VPD_CTL		0x0000000000000008ULL
#define		DDI_CTL		0x0000000000000010ULL
#define		MEM_CTL		0x0000000000000020ULL
#define		IOC_CTL		0x0000000000000040ULL
#define		MOD_CTL		0x0000000000000080ULL
#define		DMA_CTL		0x0000000000000100ULL
#define		STR_CTL		0x0000000000000200ULL
#define		INT_CTL		0x0000000000000400ULL
#define		SYSERR_CTL	0x0000000000000800ULL
#define		KST_CTL		0x0000000000001000ULL
#define		FCRAM_CTL	0x0000000000002000ULL
#define		MAC_CTL		0x0000000000004000ULL
#define		DMA2_CTL	0x0000000000008000ULL
#define		RX2_CTL		0x0000000000010000ULL
#define		TX2_CTL		0x0000000000020000ULL
#define		MEM2_CTL	0x0000000000040000ULL
#define		MEM3_CTL	0x0000000000080000ULL
#define		NEMO_CTL	0x0000000000100000ULL
#define		NDD_CTL		0x0000000000200000ULL
#define		NDD2_CTL	0x0000000000400000ULL
#define		PFC_CTL		0x0000000000800000ULL
#define		CFG_CTL		0x0000000001000000ULL
#define		CFG2_CTL	0x0000000002000000ULL
#define		VIR_CTL		0x0000000004000000ULL
#define		VIR2_CTL	0x0000000008000000ULL
#define		HXGE_NOTE	0x0000000010000000ULL
#define		HXGE_ERR_CTL	0x0000000020000000ULL
#define		MAC_INT_CTL	0x0000000040000000ULL
#define		RX_INT_CTL	0x0000000080000000ULL
#define		TX_ERR_CTL	0x0000000100000000ULL
#define		DDI_INT_CTL	0x0000000200000000ULL
#define		DLADM_CTL	0x0000000400000000ULL
#define		DUMP_ALWAYS	0x2000000000000000ULL

/* HPI Debug and Error defines */
#define		HPI_RDC_CTL	0x0000000000000001ULL
#define		HPI_TDC_CTL	0x0000000000000002ULL
#define		HPI_VMAC_CTL	0x0000000000000004ULL
#define		HPI_PFC_CTL	0x0000000000000008ULL
#define		HPI_VIR_CTL	0x0000000000000010ULL
#define		HPI_PIO_CTL	0x0000000000000020ULL
#define		HPI_VIO_CTL	0x0000000000000040ULL
#define		HPI_REG_CTL	0x0000000000000080ULL
#define		HPI_ERR_CTL	0x0000000000000100ULL

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dditypes.h>
#include <sys/ethernet.h>

#ifdef HXGE_DEBUG
#define	HXGE_DEBUG_MSG(params) hxge_debug_msg params
#else
#define	HXGE_DEBUG_MSG(params)
#endif

#define	HXGE_ERROR_MSG(params)	hxge_debug_msg params

typedef kmutex_t			hxge_os_mutex_t;
typedef	krwlock_t			hxge_os_rwlock_t;

typedef	dev_info_t			hxge_dev_info_t;
typedef	ddi_iblock_cookie_t 		hxge_intr_cookie_t;

typedef ddi_acc_handle_t		hxge_os_acc_handle_t;
typedef	hxge_os_acc_handle_t		hpi_reg_handle_t;
#if defined(__i386)
typedef	uint32_t			hpi_reg_ptr_t;
#else
typedef	uint64_t			hpi_reg_ptr_t;
#endif

typedef ddi_dma_handle_t		hxge_os_dma_handle_t;
typedef struct _hxge_dma_common_t	hxge_os_dma_common_t;
typedef struct _hxge_block_mv_t		hxge_os_block_mv_t;
typedef frtn_t				hxge_os_frtn_t;

#define	HXGE_MUTEX_DRIVER		MUTEX_DRIVER
#define	MUTEX_INIT(lock, name, type, arg)	\
					mutex_init(lock, name, type, arg)
#define	MUTEX_ENTER(lock)		mutex_enter(lock)
#define	MUTEX_TRY_ENTER(lock)		mutex_tryenter(lock)
#define	MUTEX_EXIT(lock)		mutex_exit(lock)
#define	MUTEX_DESTROY(lock)		mutex_destroy(lock)

#define	RW_INIT(lock, name, type, arg)	rw_init(lock, name, type, arg)
#define	RW_ENTER_WRITER(lock)		rw_enter(lock, RW_WRITER)
#define	RW_ENTER_READER(lock)		rw_enter(lock, RW_READER)
#define	RW_TRY_ENTER(lock, type)	rw_tryenter(lock, type)
#define	RW_EXIT(lock)			rw_exit(lock)
#define	RW_DESTROY(lock)		rw_destroy(lock)
#define	KMEM_ALLOC(size, flag)		kmem_alloc(size, flag)
#define	KMEM_ZALLOC(size, flag)		kmem_zalloc(size, flag)
#define	KMEM_FREE(buf, size)		kmem_free(buf, size)

#define	HXGE_DELAY(microseconds)	 (drv_usecwait(microseconds))

/*
 * HXGE_HPI_PIO_READ32 and HXGE_HPI_PIO_READ64 should not be called directly
 * on 32 bit platforms
 */
#define	HXGE_HPI_PIO_READ32(hpi_handle, offset)		\
	(ddi_get32(HPI_REGH(hpi_handle),		\
	(uint32_t *)(HPI_REGP(hpi_handle) + offset)))

#if defined(__i386)
#define	HXGE_HPI_PIO_READ64(hpi_handle, offset)		\
	(ddi_get64(HPI_REGH(hpi_handle),		\
	(uint64_t *)(HPI_REGP(hpi_handle) + (uint32_t)offset)))
#else
#define	HXGE_HPI_PIO_READ64(hpi_handle, offset)		\
	(ddi_get64(HPI_REGH(hpi_handle),		\
	(uint64_t *)(HPI_REGP(hpi_handle) + offset)))
#endif

#if defined(__i386)

#define	HXGE_HPI_PIO_WRITE32(hpi_handle, offset, data) {	\
	MUTEX_ENTER(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
	ddi_put32(HPI_REGH(hpi_handle),				\
	    (uint32_t *)(HPI_REGP(hpi_handle) +			\
	    (uint32_t)offset), data);				\
	MUTEX_EXIT(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
}
#define	HXGE_HPI_PIO_WRITE64(hpi_handle, offset, data) {	\
	MUTEX_ENTER(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
	ddi_put64(HPI_REGH(hpi_handle),				\
	    (uint64_t *)(HPI_REGP(hpi_handle) +			\
	    (uint32_t)offset), data);				\
	MUTEX_EXIT(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
}
#define	HXGE_MEM_PIO_READ64(hpi_handle, val_p) {		\
	MUTEX_ENTER(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
	*(val_p) = ddi_get64(HPI_REGH(hpi_handle),		\
	    (uint64_t *)HPI_REGP(hpi_handle));			\
	MUTEX_EXIT(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
}
#define	HXGE_MEM_PIO_WRITE64(hpi_handle, data) {		\
	MUTEX_ENTER(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
	ddi_put64(HPI_REGH(hpi_handle),				\
	    (uint64_t *)HPI_REGP(hpi_handle), data);		\
	MUTEX_EXIT(&((hxge_t *)hpi_handle.hxgep)->pio_lock);	\
}
#define	HXGE_REG_RD64(handle, offset, val_p) {			\
	MUTEX_ENTER(&((hxge_t *)handle.hxgep)->pio_lock);	\
	*(val_p) = HXGE_HPI_PIO_READ64(handle, offset);		\
	MUTEX_EXIT(&((hxge_t *)handle.hxgep)->pio_lock);	\
}
#define	HXGE_REG_RD32(handle, offset, val_p) {			\
	MUTEX_ENTER(&((hxge_t *)handle.hxgep)->pio_lock);	\
	*(val_p) = HXGE_HPI_PIO_READ32(handle, offset);		\
	MUTEX_EXIT(&((hxge_t *)handle.hxgep)->pio_lock);	\
}

#else

#define	HXGE_HPI_PIO_WRITE32(hpi_handle, offset, data)		\
	(ddi_put32(HPI_REGH(hpi_handle),			\
	(uint32_t *)(HPI_REGP(hpi_handle) + offset), data))
#define	HXGE_HPI_PIO_WRITE64(hpi_handle, offset, data)		\
	(ddi_put64(HPI_REGH(hpi_handle),			\
	(uint64_t *)(HPI_REGP(hpi_handle) + offset), data))
#define	HXGE_MEM_PIO_READ64(hpi_handle, val_p) {		\
	*(val_p) = ddi_get64(HPI_REGH(hpi_handle),		\
		(uint64_t *)HPI_REGP(hpi_handle));		\
}
#define	HXGE_MEM_PIO_WRITE64(hpi_handle, data)			\
	(ddi_put64(HPI_REGH(hpi_handle),			\
		(uint64_t *)HPI_REGP(hpi_handle), data))
#define	HXGE_REG_RD64(handle, offset, val_p) {			\
	*(val_p) = HXGE_HPI_PIO_READ64(handle, offset);		\
}
#define	HXGE_REG_RD32(handle, offset, val_p) {			\
	*(val_p) = HXGE_HPI_PIO_READ32(handle, offset);		\
}

#endif

#define	HXGE_REG_WR64(handle, offset, val) {			\
	HXGE_HPI_PIO_WRITE64(handle, (offset), (val));		\
}
#define	HXGE_REG_WR32(handle, offset, val) {			\
	HXGE_HPI_PIO_WRITE32(handle, (offset), (val));		\
}

#define	FM_SERVICE_RESTORED(hxgep)				\
	if (DDI_FM_EREPORT_CAP(hxgep->fm_capabilities))		\
		ddi_fm_service_impact(hxgep->dip, DDI_SERVICE_RESTORED)
#define	HXGE_FM_REPORT_ERROR(hxgep, chan, ereport_id)		\
	if (DDI_FM_EREPORT_CAP(hxgep->fm_capabilities))		\
		hxge_fm_report_error(hxgep, chan, ereport_id)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_COMMON_IMPL_H */
