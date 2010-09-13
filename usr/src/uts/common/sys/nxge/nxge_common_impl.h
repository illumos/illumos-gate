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

#ifndef	_SYS_NXGE_NXGE_COMMON_IMPL_H
#define	_SYS_NXGE_NXGE_COMMON_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	NPI_REGH(npi_handle)		(npi_handle.regh)
#define	NPI_REGP(npi_handle)		(npi_handle.regp)

#if defined(NXGE_DEBUG_DMA) || defined(NXGE_DEBUG_TXC)
#define	__NXGE_STATIC
#define	__NXGE_INLINE
#else
#define	__NXGE_STATIC			static
#define	__NXGE_INLINE			inline
#endif

#ifdef	AXIS_DEBUG
#define	AXIS_WAIT			(100000)
#define	AXIS_LONG_WAIT			(100000)
#define	AXIS_WAIT_W			(80000)
#define	AXIS_WAIT_R			(100000)
#define	AXIS_WAIT_LOOP			(4000)
#define	AXIS_WAIT_PER_LOOP		(AXIS_WAIT_R/AXIS_WAIT_LOOP)
#endif

#define	NO_DEBUG	0x0000000000000000ULL
#define	MDT_CTL		0x0000000000000001ULL
#define	RX_CTL		0x0000000000000002ULL
#define	TX_CTL		0x0000000000000004ULL
#define	OBP_CTL		0x0000000000000008ULL

#define	VPD_CTL		0x0000000000000010ULL
#define	DDI_CTL		0x0000000000000020ULL
#define	MEM_CTL		0x0000000000000040ULL
#define	SAP_CTL		0x0000000000000080ULL

#define	IOC_CTL		0x0000000000000100ULL
#define	MOD_CTL		0x0000000000000200ULL
#define	DMA_CTL		0x0000000000000400ULL
#define	STR_CTL		0x0000000000000800ULL

#define	INT_CTL		0x0000000000001000ULL
#define	SYSERR_CTL	0x0000000000002000ULL
#define	KST_CTL		0x0000000000004000ULL
#define	PCS_CTL		0x0000000000008000ULL

#define	MII_CTL		0x0000000000010000ULL
#define	MIF_CTL		0x0000000000020000ULL
#define	FCRAM_CTL	0x0000000000040000ULL
#define	MAC_CTL		0x0000000000080000ULL

#define	IPP_CTL		0x0000000000100000ULL
#define	DMA2_CTL	0x0000000000200000ULL
#define	RX2_CTL		0x0000000000400000ULL
#define	TX2_CTL		0x0000000000800000ULL

#define	MEM2_CTL	0x0000000001000000ULL
#define	MEM3_CTL	0x0000000002000000ULL
#define	NXGE_CTL	0x0000000004000000ULL
#define	NDD_CTL		0x0000000008000000ULL
#define	NDD2_CTL	0x0000000010000000ULL

#define	TCAM_CTL	0x0000000020000000ULL
#define	CFG_CTL		0x0000000040000000ULL
#define	CFG2_CTL	0x0000000080000000ULL

#define	FFLP_CTL	TCAM_CTL | FCRAM_CTL

#define	VIR_CTL		0x0000000100000000ULL
#define	VIR2_CTL	0x0000000200000000ULL

#define	HIO_CTL		0x0000000400000000ULL

#define	NXGE_NOTE	0x0000001000000000ULL
#define	NXGE_ERR_CTL	0x0000002000000000ULL

#define	DUMP_ALWAYS	0x2000000000000000ULL

/* NPI Debug and Error defines */
#define	NPI_RDC_CTL	0x0000000000000001ULL
#define	NPI_TDC_CTL	0x0000000000000002ULL
#define	NPI_TXC_CTL	0x0000000000000004ULL
#define	NPI_IPP_CTL	0x0000000000000008ULL

#define	NPI_XPCS_CTL	0x0000000000000010ULL
#define	NPI_PCS_CTL	0x0000000000000020ULL
#define	NPI_ESR_CTL	0x0000000000000040ULL
#define	NPI_BMAC_CTL	0x0000000000000080ULL
#define	NPI_XMAC_CTL	0x0000000000000100ULL
#define	NPI_MAC_CTL	NPI_BMAC_CTL | NPI_XMAC_CTL

#define	NPI_ZCP_CTL	0x0000000000000200ULL
#define	NPI_TCAM_CTL	0x0000000000000400ULL
#define	NPI_FCRAM_CTL	0x0000000000000800ULL
#define	NPI_FFLP_CTL	NPI_TCAM_CTL | NPI_FCRAM_CTL

#define	NPI_VIR_CTL	0x0000000000001000ULL
#define	NPI_PIO_CTL	0x0000000000002000ULL
#define	NPI_VIO_CTL	0x0000000000004000ULL

#define	NPI_REG_CTL	0x0000000040000000ULL
#define	NPI_CTL		0x0000000080000000ULL
#define	NPI_ERR_CTL	0x0000000080000000ULL

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dditypes.h>
#include <sys/ethernet.h>

#ifdef NXGE_DEBUG
#define	NXGE_DEBUG_MSG(params) nxge_debug_msg params
#else
#define	NXGE_DEBUG_MSG(params)
#endif

#define	NXGE_ERROR_MSG(params)	nxge_debug_msg params
#define	NXGE_WARN_MSG(params)	nxge_debug_msg params

typedef kmutex_t			nxge_os_mutex_t;
typedef	krwlock_t			nxge_os_rwlock_t;

typedef	dev_info_t			nxge_dev_info_t;
typedef	ddi_iblock_cookie_t 		nxge_intr_cookie_t;

typedef ddi_acc_handle_t		nxge_os_acc_handle_t;
typedef	nxge_os_acc_handle_t		npi_reg_handle_t;
#if defined(__i386)
typedef	uint32_t			npi_reg_ptr_t;
#else
typedef uint64_t			npi_reg_ptr_t;
#endif

typedef ddi_dma_handle_t		nxge_os_dma_handle_t;
typedef struct _nxge_dma_common_t	nxge_os_dma_common_t;
typedef struct _nxge_block_mv_t		nxge_os_block_mv_t;
typedef frtn_t				nxge_os_frtn_t;

#define	NXGE_MUTEX_DRIVER		MUTEX_DRIVER
#define	MUTEX_INIT(lock, name, type, arg) \
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

#define	NXGE_DELAY(microseconds)	 (drv_usecwait(microseconds))

#define	NXGE_PIO_READ8(handle, devaddr, offset) \
	(ddi_get8(handle, (uint8_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_READ16(handle, devaddr, offset) \
	(ddi_get16(handle, (uint16_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_READ32(handle, devaddr, offset) \
	(ddi_get32(handle, (uint32_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_READ64(handle, devaddr, offset) \
	(ddi_get64(handle, (uint64_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_WRITE8(handle, devaddr, offset, data) \
	(ddi_put8(handle, (uint8_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_PIO_WRITE16(handle, devaddr, offset, data) \
	(ddi_get16(handle, (uint16_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_PIO_WRITE32(handle, devaddr, offset, data)	\
	(ddi_put32(handle, (uint32_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data) \
	(ddi_put64(handle, (uint64_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_NPI_PIO_READ8(npi_handle, offset) \
	(ddi_get8(NPI_REGH(npi_handle),	\
	(uint8_t *)(NPI_REGP(npi_handle) + offset)))

#define	NXGE_NPI_PIO_READ16(npi_handle, offset) \
	(ddi_get16(NPI_REGH(npi_handle), \
	(uint16_t *)(NPI_REGP(npi_handle) + offset)))

#define	NXGE_NPI_PIO_READ32(npi_handle, offset) \
	(ddi_get32(NPI_REGH(npi_handle), \
	(uint32_t *)(NPI_REGP(npi_handle) + offset)))

#if defined(__i386)
#define	NXGE_NPI_PIO_READ64(npi_handle, offset)		\
	(ddi_get64(NPI_REGH(npi_handle),		\
	(uint64_t *)(NPI_REGP(npi_handle) + (uint32_t)offset)))
#else
#define	NXGE_NPI_PIO_READ64(npi_handle, offset)		\
	(ddi_get64(NPI_REGH(npi_handle),		\
	(uint64_t *)(NPI_REGP(npi_handle) + offset)))
#endif

#define	NXGE_NPI_PIO_WRITE8(npi_handle, offset, data)	\
	(ddi_put8(NPI_REGH(npi_handle),			\
	(uint8_t *)(NPI_REGP(npi_handle) + offset), data))

#define	NXGE_NPI_PIO_WRITE16(npi_handle, offset, data)	\
	(ddi_put16(NPI_REGH(npi_handle),		\
	(uint16_t *)(NPI_REGP(npi_handle) + offset), data))

#define	NXGE_NPI_PIO_WRITE32(npi_handle, offset, data)	\
	(ddi_put32(NPI_REGH(npi_handle),		\
	(uint32_t *)(NPI_REGP(npi_handle) + offset), data))

#if defined(__i386)
#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	\
	(ddi_put64(NPI_REGH(npi_handle),		\
	(uint64_t *)(NPI_REGP(npi_handle) + (uint32_t)offset), data))
#else
#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	\
	(ddi_put64(NPI_REGH(npi_handle),		\
	(uint64_t *)(NPI_REGP(npi_handle) + offset), data))
#endif

#define	NXGE_MEM_PIO_READ8(npi_handle)		\
	(ddi_get8(NPI_REGH(npi_handle), (uint8_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ16(npi_handle)		\
	(ddi_get16(NPI_REGH(npi_handle), (uint16_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ32(npi_handle)		\
	(ddi_get32(NPI_REGH(npi_handle), (uint32_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ64(npi_handle)		\
	(ddi_get64(NPI_REGH(npi_handle), (uint64_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_WRITE8(npi_handle, data)	\
	(ddi_put8(NPI_REGH(npi_handle), (uint8_t *)NPI_REGP(npi_handle), data))

#define	NXGE_MEM_PIO_WRITE16(npi_handle, data)	\
		(ddi_put16(NPI_REGH(npi_handle),	\
		(uint16_t *)NPI_REGP(npi_handle), data))

#define	NXGE_MEM_PIO_WRITE32(npi_handle, data)	\
		(ddi_put32(NPI_REGH(npi_handle),	\
		(uint32_t *)NPI_REGP(npi_handle), data))

#define	NXGE_MEM_PIO_WRITE64(npi_handle, data)	\
		(ddi_put64(NPI_REGH(npi_handle),	\
		(uint64_t *)NPI_REGP(npi_handle), data))

#define	SERVICE_LOST		DDI_SERVICE_LOST
#define	SERVICE_DEGRADED	DDI_SERVICE_DEGRADED
#define	SERVICE_UNAFFECTED	DDI_SERVICE_UNAFFECTED
#define	SERVICE_RESTORED	DDI_SERVICE_RESTORED

#define	DATAPATH_FAULT		DDI_DATAPATH_FAULT
#define	DEVICE_FAULT		DDI_DEVICE_FAULT
#define	EXTERNAL_FAULT		DDI_EXTERNAL_FAULT

#define	NOTE_LINK_UP		DL_NOTE_LINK_UP
#define	NOTE_LINK_DOWN		DL_NOTE_LINK_DOWN
#define	NOTE_SPEED		DL_NOTE_SPEED
#define	NOTE_PHYS_ADDR		DL_NOTE_PHYS_ADDR
#define	NOTE_AGGR_AVAIL		DL_NOTE_AGGR_AVAIL
#define	NOTE_AGGR_UNAVAIL	DL_NOTE_AGGR_UNAVAIL

#define	FM_REPORT_FAULT(nxgep, impact, location, msg)\
		ddi_dev_report_fault(nxgep->dip, impact, location, msg)
#define	FM_CHECK_DEV_HANDLE(nxgep)\
		ddi_check_acc_handle(nxgep->dev_regs->nxge_regh)
#define	FM_GET_DEVSTATE(nxgep)\
		ddi_get_devstate(nxgep->dip)
#define	FM_SERVICE_RESTORED(nxgep)\
		ddi_fm_service_impact(nxgep->dip, DDI_SERVICE_RESTORED)
#define	NXGE_FM_REPORT_ERROR(nxgep, portn, chan, ereport_id)\
		nxge_fm_report_error(nxgep, portn, chan, ereport_id)
#define	FM_CHECK_ACC_HANDLE(nxgep, handle)\
		fm_check_acc_handle(handle)
#define	FM_CHECK_DMA_HANDLE(nxgep, handle)\
		fm_check_dma_handle(handle)

#if defined(REG_TRACE)
#define	NXGE_REG_RD64(handle, offset, val_p) {\
	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
	npi_rtrace_update(handle, B_FALSE, &npi_rtracebuf, (uint32_t)offset, \
			(uint64_t)(*(val_p)));\
}
#elif defined(REG_SHOW)
	/*
	 * Send 0xbadbad to tell rs_show_reg that we do not have
	 * a valid RTBUF index to pass
	 */
#define	NXGE_REG_RD64(handle, offset, val_p) {\
	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
	rt_show_reg(0xbadbad, B_FALSE, (uint32_t)offset, (uint64_t)(*(val_p)));\
}
#else
#define	NXGE_REG_RD64(handle, offset, val_p) {\
	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
}
#endif

#if defined(REG_TRACE)
#define	NXGE_REG_WR64(handle, offset, val) {\
	NXGE_NPI_PIO_WRITE64(handle, (offset), (val));\
	npi_rtrace_update(handle, B_TRUE, &npi_rtracebuf, (uint32_t)offset,\
				(uint64_t)(val));\
}
#elif defined(REG_SHOW)
/*
 * Send 0xbadbad to tell rs_show_reg that we do not have
 * a valid RTBUF index to pass
 */
#define	NXGE_REG_WR64(handle, offset, val) {\
	NXGE_NPI_PIO_WRITE64(handle, offset, (val));\
	rt_show_reg(0xbadbad, B_TRUE, (uint32_t)offset, (uint64_t)(val));\
}
#else
#define	NXGE_REG_WR64(handle, offset, val) {\
	NXGE_NPI_PIO_WRITE64(handle, (offset), (val));\
}
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_COMMON_IMPL_H */
