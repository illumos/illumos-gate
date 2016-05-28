/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#ifndef	_SYS_EFSYS_H
#define	_SYS_EFSYS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/sdt.h>
#include <sys/kstat.h>
#include <sys/crc32.h>
#include <sys/note.h>
#include <sys/byteorder.h>

#define	EFSYS_HAS_UINT64 1
#define	EFSYS_USE_UINT64 0
#define	EFSYS_HAS_SSE2_M128 0
#ifdef	_BIG_ENDIAN
#define	EFSYS_IS_BIG_ENDIAN 1
#endif
#ifdef	_LITTLE_ENDIAN
#define	EFSYS_IS_LITTLE_ENDIAN 1
#endif
#include "efx_types.h"

/* Modifiers used for Windows builds */
#define	__in
#define	__in_opt
#define	__in_ecount(_n)
#define	__in_ecount_opt(_n)
#define	__in_bcount(_n)
#define	__in_bcount_opt(_n)

#define	__out
#define	__out_opt
#define	__out_ecount(_n)
#define	__out_ecount_opt(_n)
#define	__out_bcount(_n)
#define	__out_bcount_opt(_n)
#define	__out_bcount_part(_n, _l)
#define	__out_bcount_part_opt(_n, _l)

#define	__deref_out

#define	__inout
#define	__inout_opt
#define	__inout_ecount(_n)
#define	__inout_ecount_opt(_n)
#define	__inout_bcount(_n)
#define	__inout_bcount_opt(_n)
#define	__inout_bcount_full_opt(_n)

#define	__deref_out_bcount_opt(n)

#define	__checkReturn
#define	__success(_x)

#define	__drv_when(_p, _c)

/* Code inclusion options */


#define	EFSYS_OPT_NAMES 1

#define	EFSYS_OPT_SIENA 1
#define	EFSYS_OPT_HUNTINGTON 1
#define	EFSYS_OPT_MEDFORD 0
#if DEBUG
#define	EFSYS_OPT_CHECK_REG 1
#else
#define	EFSYS_OPT_CHECK_REG 0
#endif

#define	EFSYS_OPT_MCDI 1
#define	EFSYS_OPT_MCDI_LOGGING 0
#define	EFSYS_OPT_MCDI_PROXY_AUTH 0

#define	EFSYS_OPT_MAC_STATS 1

#define	EFSYS_OPT_LOOPBACK 1

#define	EFSYS_OPT_MON_MCDI 1
#define	EFSYS_OPT_MON_STATS 1

#define	EFSYS_OPT_PHY_STATS 1
#define	EFSYS_OPT_BIST 1
#define	EFSYS_OPT_PHY_LED_CONTROL 1

#define	EFSYS_OPT_VPD 1
#define	EFSYS_OPT_NVRAM 1
#define	EFSYS_OPT_BOOTCFG 1

#define	EFSYS_OPT_DIAG 0
#define	EFSYS_OPT_WOL 1
#define	EFSYS_OPT_RX_SCALE 1
#define	EFSYS_OPT_QSTATS 1

#define	EFSYS_OPT_EV_PREFETCH 0

#define	EFSYS_OPT_DECODE_INTR_FATAL 1

#define	EFSYS_OPT_FILTER 1

#define	EFSYS_OPT_LICENSING 0

/* ID */

typedef struct __efsys_identifier_s	efsys_identifier_t;

/* DMA */

typedef uint64_t		efsys_dma_addr_t;

typedef struct efsys_mem_s {
	ddi_dma_handle_t	esm_dma_handle; /* DMA memory allocate/bind */
	ddi_acc_handle_t	esm_acc_handle;	/* DMA memory read/write */
	caddr_t			esm_base;
	efsys_dma_addr_t	esm_addr;
	size_t			esm_size;
	size_t			esm_used;
} efsys_mem_t;


#define	EFSYS_MEM_ZERO(_esmp, _size)					\
	(void) bzero((_esmp)->esm_base, (_size))

#define	EFSYS_MEM_READD(_esmp, _offset, _edp)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_dword_t)));	\
									\
		addr = (void *)((_esmp)->esm_base + (_offset));		\
									\
		(_edp)->ed_u32[0] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr);						\
									\
		DTRACE_PROBE2(mem_readd, unsigned int, (_offset),	\
		    uint32_t, (_edp)->ed_u32[0]);			\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_MEM_READQ(_esmp, _offset, _eqp)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_qword_t)));	\
									\
		addr = (void *)((_esmp)->esm_base + (_offset));		\
									\
		(_eqp)->eq_u32[0] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr++);						\
		(_eqp)->eq_u32[1] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr);						\
									\
		DTRACE_PROBE3(mem_readq, unsigned int, (_offset),	\
		    uint32_t, (_eqp)->eq_u32[1],			\
		    uint32_t, (_eqp)->eq_u32[0]);			\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_MEM_READO(_esmp, _offset, _eop)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_oword_t)));	\
									\
		addr = (void *)((_esmp)->esm_base + (_offset));		\
									\
		(_eop)->eo_u32[0] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr++);						\
		(_eop)->eo_u32[1] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr++);						\
		(_eop)->eo_u32[2] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr++);						\
		(_eop)->eo_u32[3] = ddi_get32((_esmp)->esm_acc_handle,	\
		    addr);						\
									\
		DTRACE_PROBE5(mem_reado, unsigned int, (_offset),	\
		    uint32_t, (_eop)->eo_u32[3],			\
		    uint32_t, (_eop)->eo_u32[2],			\
		    uint32_t, (_eop)->eo_u32[1],			\
		    uint32_t, (_eop)->eo_u32[0]);			\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_MEM_WRITED(_esmp, _offset, _edp)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_dword_t)));	\
									\
		DTRACE_PROBE2(mem_writed, unsigned int, (_offset),	\
		    uint32_t, (_edp)->ed_u32[0]);			\
									\
		addr = (void *)((_esmp)->esm_base + (_offset));		\
									\
		ddi_put32((_esmp)->esm_acc_handle, addr,		\
		    (_edp)->ed_u32[0]);					\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_MEM_WRITEQ(_esmp, _offset, _eqp)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_qword_t)));	\
									\
		DTRACE_PROBE3(mem_writeq, unsigned int, (_offset),	\
		    uint32_t, (_eqp)->eq_u32[1],			\
		    uint32_t, (_eqp)->eq_u32[0]);			\
									\
		addr = (void *)((_esmp)->esm_base + (_offset));		\
									\
		ddi_put32((_esmp)->esm_acc_handle, addr++,		\
		    (_eqp)->eq_u32[0]);					\
		ddi_put32((_esmp)->esm_acc_handle, addr,		\
		    (_eqp)->eq_u32[1]);					\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_MEM_WRITEO(_esmp, _offset, _eop)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_oword_t)));	\
									\
		DTRACE_PROBE5(mem_writeo, unsigned int, (_offset),	\
		    uint32_t, (_eop)->eo_u32[3],			\
		    uint32_t, (_eop)->eo_u32[2],			\
		    uint32_t, (_eop)->eo_u32[1],			\
		    uint32_t, (_eop)->eo_u32[0]);			\
									\
		addr = (void *)((_esmp)->esm_base + (_offset));		\
									\
		ddi_put32((_esmp)->esm_acc_handle, addr++,		\
		    (_eop)->eo_u32[0]);					\
		ddi_put32((_esmp)->esm_acc_handle, addr++,		\
		    (_eop)->eo_u32[1]);					\
		ddi_put32((_esmp)->esm_acc_handle, addr++,		\
		    (_eop)->eo_u32[2]);					\
		ddi_put32((_esmp)->esm_acc_handle, addr,		\
		    (_eop)->eo_u32[3]);					\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_MEM_ADDR(_esmp)						\
	((_esmp)->esm_addr)

#define	EFSYS_MEM_IS_NULL(_esmp)					\
	((_esmp)->esm_base == NULL)

/* BAR */

typedef struct efsys_bar_s {
	kmutex_t		esb_lock;
	ddi_acc_handle_t	esb_handle;
	caddr_t			esb_base;
} efsys_bar_t;

#define	EFSYS_BAR_READD(_esbp, _offset, _edp, _lock)			\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_dword_t)));	\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_enter(&((_esbp)->esb_lock));		\
									\
		addr = (void *)((_esbp)->esb_base + (_offset));		\
									\
		(_edp)->ed_u32[0] = ddi_get32((_esbp)->esb_handle,	\
		    addr);						\
									\
		DTRACE_PROBE2(bar_readd, unsigned int, (_offset),	\
		    uint32_t, (_edp)->ed_u32[0]);			\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_exit(&((_esbp)->esb_lock));		\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_BAR_READQ(_esbp, _offset, _eqp)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_qword_t)));	\
									\
		mutex_enter(&((_esbp)->esb_lock));			\
									\
		addr = (void *)((_esbp)->esb_base + (_offset));		\
									\
		(_eqp)->eq_u32[0] = ddi_get32((_esbp)->esb_handle,	\
		    addr++);						\
		(_eqp)->eq_u32[1] = ddi_get32((_esbp)->esb_handle,	\
		    addr);						\
									\
		DTRACE_PROBE3(bar_readq, unsigned int, (_offset),	\
		    uint32_t, (_eqp)->eq_u32[1],			\
		    uint32_t, (_eqp)->eq_u32[0]);			\
									\
		mutex_exit(&((_esbp)->esb_lock));			\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_BAR_READO(_esbp, _offset, _eop, _lock)			\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_oword_t)));	\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_enter(&((_esbp)->esb_lock));		\
									\
		addr = (void *)((_esbp)->esb_base + (_offset));		\
									\
		(_eop)->eo_u32[0] = ddi_get32((_esbp)->esb_handle,	\
		    addr++);						\
		(_eop)->eo_u32[1] = ddi_get32((_esbp)->esb_handle,	\
		    addr++);						\
		(_eop)->eo_u32[2] = ddi_get32((_esbp)->esb_handle,	\
		    addr++);						\
		(_eop)->eo_u32[3] = ddi_get32((_esbp)->esb_handle,	\
		    addr);						\
									\
		DTRACE_PROBE5(bar_reado, unsigned int, (_offset),	\
		    uint32_t, (_eop)->eo_u32[3],			\
		    uint32_t, (_eop)->eo_u32[2],			\
		    uint32_t, (_eop)->eo_u32[1],			\
		    uint32_t, (_eop)->eo_u32[0]);			\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_exit(&((_esbp)->esb_lock));		\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_BAR_WRITED(_esbp, _offset, _edp, _lock)			\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_dword_t)));	\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_enter(&((_esbp)->esb_lock));		\
									\
		DTRACE_PROBE2(bar_writed, unsigned int, (_offset),	\
		    uint32_t, (_edp)->ed_u32[0]);			\
									\
		addr = (void *)((_esbp)->esb_base + (_offset));		\
									\
		ddi_put32((_esbp)->esb_handle, addr,			\
		    (_edp)->ed_u32[0]);					\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_exit(&((_esbp)->esb_lock));		\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_BAR_WRITEQ(_esbp, _offset, _eqp)				\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_qword_t)));	\
									\
		mutex_enter(&((_esbp)->esb_lock));			\
									\
		DTRACE_PROBE3(bar_writeq, unsigned int, (_offset),	\
		    uint32_t, (_eqp)->eq_u32[1],			\
		    uint32_t, (_eqp)->eq_u32[0]);			\
									\
		addr = (void *)((_esbp)->esb_base + (_offset));		\
									\
		ddi_put32((_esbp)->esb_handle, addr++,			\
		    (_eqp)->eq_u32[0]);					\
		ddi_put32((_esbp)->esb_handle, addr,			\
		    (_eqp)->eq_u32[1]);					\
									\
		mutex_exit(&((_esbp)->esb_lock));			\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/*
 * Guarantees 64bit aligned 64bit writes to write combined BAR mapping
 * (required by PIO hardware)
 */
#define	EFSYS_BAR_WC_WRITEQ(_esbp, _offset, _eqp)			\
	do {								\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_qword_t)));	\
									\
		(void) (_esbp);						\
									\
		/* FIXME: Perform a 64-bit write */			\
		EFSYS_ASSERT(0);					\
									\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_BAR_WRITEO(_esbp, _offset, _eop, _lock)			\
	do {								\
		uint32_t *addr;						\
									\
		_NOTE(CONSTANTCONDITION)				\
		ASSERT(IS_P2ALIGNED(_offset, sizeof (efx_oword_t)));	\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_enter(&((_esbp)->esb_lock));		\
									\
		DTRACE_PROBE5(bar_writeo, unsigned int, (_offset),	\
		    uint32_t, (_eop)->eo_u32[3],			\
		    uint32_t, (_eop)->eo_u32[2],			\
		    uint32_t, (_eop)->eo_u32[1],			\
		    uint32_t, (_eop)->eo_u32[0]);			\
									\
		addr = (void *)((_esbp)->esb_base + (_offset));		\
									\
		ddi_put32((_esbp)->esb_handle, addr++,			\
		    (_eop)->eo_u32[0]);					\
		ddi_put32((_esbp)->esb_handle, addr++,			\
		    (_eop)->eo_u32[1]);					\
		ddi_put32((_esbp)->esb_handle, addr++,			\
		    (_eop)->eo_u32[2]);					\
		ddi_put32((_esbp)->esb_handle, addr,			\
		    (_eop)->eo_u32[3]);					\
									\
		_NOTE(CONSTANTCONDITION)				\
		if (_lock)						\
			mutex_exit(&((_esbp)->esb_lock));		\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* Use the standard octo-word write for doorbell writes */
#define	EFSYS_BAR_DOORBELL_WRITEO(_esbp, _offset, _eop)			\
	do {								\
		EFSYS_BAR_WRITEO((_esbp), (_offset), (_eop), B_FALSE);	\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* SPIN */

#define	EFSYS_SPIN(_us)							\
	drv_usecwait(_us)

/* TODO: Perhaps this should use delay(9F)? */
#define	EFSYS_SLEEP	EFSYS_SPIN

/* BARRIERS */

/* Strict ordering guaranteed by devacc.devacc_attr_dataorder */
#define	EFSYS_MEM_READ_BARRIER()	membar_consumer()
/* TODO: Is ddi_put32() properly barriered? */
#define	EFSYS_PIO_WRITE_BARRIER()

/* DMA SYNC */
/*
 * It could be cheaper to sync entire map than calculate offset and
 * size. If so, below macros should be updated to ignore these arguments
 * and sync entire map.
 */
#define	EFSYS_DMA_SYNC_FOR_KERNEL(_esmp, _offset, _size)		\
	(void) ddi_dma_sync((_esmp)->esm_dma_handle,			\
	    (_offset), (_size), DDI_DMA_SYNC_FORKERNEL)

#define	EFSYS_DMA_SYNC_FOR_DEVICE(_esmp, _offset, _size)		\
	(void) ddi_dma_sync((_esmp)->esm_dma_handle,			\
	    (_offset), (_size), DDI_DMA_SYNC_FORDEV)

/* TIMESTAMP */

typedef	clock_t	efsys_timestamp_t;

/* TODO: Arguably this could use gethrtime */
#define	EFSYS_TIMESTAMP(_usp)						\
	do {								\
		*(_usp) = drv_hztousec(ddi_get_lbolt());		\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* KMEM */

#define	EFSYS_KMEM_ALLOC(_esip, _size, _p)				\
	do {								\
		(_esip) = (_esip);					\
		(_p) = kmem_zalloc((_size), KM_NOSLEEP);		\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_KMEM_FREE(_esip, _size, _p)				\
	do {								\
		(_esip) = (_esip);					\
		kmem_free((_p), (_size));				\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* LOCK */

typedef kmutex_t	efsys_lock_t;

#define	EFSYS_LOCK_MAGIC	0x000010c4

#define	EFSYS_LOCK(_lockp, _state)					\
	do {								\
		mutex_enter(_lockp);					\
		(_state) = EFSYS_LOCK_MAGIC;				\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_UNLOCK(_lockp, _state)					\
	do {								\
		if ((_state) != EFSYS_LOCK_MAGIC)			\
			ASSERT(B_FALSE);				\
		mutex_exit(_lockp);					\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* STAT */

typedef kstat_named_t		efsys_stat_t;

#define	EFSYS_STAT_INCR(_knp, _delta) 					\
	do {								\
		((_knp)->value.ui64) += (_delta);			\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_STAT_DECR(_knp, _delta) 					\
	do {								\
		((_knp)->value.ui64) -= (_delta);			\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_STAT_SET(_knp, _val)					\
	do {								\
		((_knp)->value.ui64) = (_val);				\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_STAT_SET_QWORD(_knp, _valp)				\
	do {								\
		((_knp)->value.ui64) = LE_64((_valp)->eq_u64[0]);	\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_STAT_SET_DWORD(_knp, _valp)				\
	do {								\
		((_knp)->value.ui64) = LE_32((_valp)->ed_u32[0]);	\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_STAT_INCR_QWORD(_knp, _valp)				\
	do {								\
		((_knp)->value.ui64) += LE_64((_valp)->eq_u64[0]);	\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

#define	EFSYS_STAT_SUBR_QWORD(_knp, _valp)				\
	do {								\
		((_knp)->value.ui64) -= LE_64((_valp)->eq_u64[0]);	\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* ERR */

extern void	sfxge_err(efsys_identifier_t *, unsigned int,
		    uint32_t, uint32_t);

#if EFSYS_OPT_DECODE_INTR_FATAL
#define	EFSYS_ERR(_esip, _code, _dword0, _dword1)			\
	sfxge_err((_esip), (_code), (_dword0), (_dword1))
#endif

/* PROBE */

#define	EFSYS_PROBE(_name)						\
	DTRACE_PROBE(_name)

#define	EFSYS_PROBE1(_name, _type1, _arg1)				\
	DTRACE_PROBE1(_name, _type1, _arg1)

#define	EFSYS_PROBE2(_name, _type1, _arg1, _type2, _arg2)		\
	DTRACE_PROBE2(_name, _type1, _arg1, _type2, _arg2)

#define	EFSYS_PROBE3(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3)						\
	DTRACE_PROBE3(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3)

#define	EFSYS_PROBE4(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4)				\
	DTRACE_PROBE4(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4)

#define	EFSYS_PROBE5(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4, _type5, _arg5)		\
	DTRACE_PROBE5(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4, _type5, _arg5)

#define	EFSYS_PROBE6(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4, _type5, _arg5,		\
	    _type6, _arg6)						\
	DTRACE_PROBE6(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4, _type5, _arg5,		\
	    _type6, _arg6)

#define	EFSYS_PROBE7(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4, _type5, _arg5,		\
	    _type6, _arg6, _type7, _arg7)				\
	DTRACE_PROBE7(_name, _type1, _arg1, _type2, _arg2,		\
	    _type3, _arg3, _type4, _arg4, _type5, _arg5,		\
	    _type6, _arg6, _type7, _arg7)

/* ASSERT */

#define	EFSYS_ASSERT(_exp)		ASSERT(_exp)
#define	EFSYS_ASSERT3U(_x, _op, _y)	ASSERT3U(_x, _op, _y)
#define	EFSYS_ASSERT3S(_x, _op, _y)	ASSERT3S(_x, _op, _y)
#define	EFSYS_ASSERT3P(_x, _op, _y)	ASSERT3P(_x, _op, _y)

/* ROTATE */

#define	EFSYS_HAS_ROTL_DWORD 0

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EFSYS_H */
