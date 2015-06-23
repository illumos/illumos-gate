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

/*
 *  Copyright (c) 2002-2005 Neterion, Inc.
 *  All right Reserved.
 *
 *  FileName :    xge_osdep.h
 *
 *  Description:  OSPAL - Solaris
 *
 */

#ifndef _SYS_XGE_OSDEP_H
#define	_SYS_XGE_OSDEP_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/int_fmtio.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/nd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------- includes and defines ------------------------- */

#define	XGE_HAL_TX_MULTI_POST_IRQ	1
#define	XGE_HAL_TX_MULTI_RESERVE_IRQ	1
#define	XGE_HAL_TX_MULTI_FREE_IRQ	1
#define	XGE_HAL_DMA_DTR_CONSISTENT	1
#define	XGE_HAL_DMA_STATS_STREAMING	1

#if defined(__sparc)
#define	XGE_OS_DMA_REQUIRES_SYNC	1
#endif

#define	XGE_HAL_ALIGN_XMIT		1

#ifdef _BIG_ENDIAN
#define	XGE_OS_HOST_BIG_ENDIAN		1
#else
#define	XGE_OS_HOST_LITTLE_ENDIAN	1
#endif

#if defined(__sparc)
#define	XGE_OS_HOST_PAGE_SIZE		8192
#else
#define	XGE_OS_HOST_PAGE_SIZE		4096
#endif

#if defined(_LP64)
#define	XGE_OS_PLATFORM_64BIT		1
#else
#define	XGE_OS_PLATFORM_32BIT		1
#endif

#define	XGE_OS_HAS_SNPRINTF		1

/* LRO defines */
#define	XGE_LL_IP_FAST_CSUM(hdr, len)	0 /* ip_ocsum(hdr, len>>1, 0); */

/* ---------------------- fixed size primitive types ----------------------- */

#define	u8			uint8_t
#define	u16			uint16_t
#define	u32			uint32_t
#define	u64			uint64_t
typedef	u64			dma_addr_t;
#define	ulong_t			ulong_t
#define	ptrdiff_t		ptrdiff_t
typedef	kmutex_t		spinlock_t;
typedef dev_info_t		*pci_dev_h;
typedef ddi_acc_handle_t	pci_reg_h;
typedef ddi_acc_handle_t	pci_cfg_h;
typedef uint_t			pci_irq_h;
typedef ddi_dma_handle_t	pci_dma_h;
typedef ddi_acc_handle_t	pci_dma_acc_h;

/* LRO types */
#define	OS_NETSTACK_BUF		mblk_t *
#define	OS_LL_HEADER		uint8_t *
#define	OS_IP_HEADER		uint8_t *
#define	OS_TL_HEADER		uint8_t *

/* -------------------------- "libc" functionality ------------------------- */

#define	xge_os_strlcpy			(void) strlcpy
#define	xge_os_strlen			strlen
#define	xge_os_snprintf			snprintf
#define	xge_os_memzero(addr, size)	bzero(addr, size)
#define	xge_os_memcpy(dst, src, size)	bcopy(src, dst, size)
#define	xge_os_memcmp(src1, src2, size)	bcmp(src1, src2, size)
#define	xge_os_ntohl			ntohl
#define	xge_os_htons			htons
#define	xge_os_ntohs			ntohs

#ifdef __GNUC__
#define	xge_os_printf(fmt...)		cmn_err(CE_CONT, fmt)
#define	xge_os_sprintf(buf, fmt...)	strlen(sprintf(buf, fmt))
#else
#define	xge_os_vaprintf(fmt) { \
	va_list va; \
	va_start(va, fmt); \
	vcmn_err(CE_CONT, fmt, va); \
	va_end(va); \
}

static inline void xge_os_printf(char *fmt, ...) {
	xge_os_vaprintf(fmt);
}

#define	xge_os_vasprintf(buf, fmt) { \
	va_list va; \
	va_start(va, fmt); \
	(void) vsprintf(buf, fmt, va); \
	va_end(va); \
}

static inline int xge_os_sprintf(char *buf, char *fmt, ...) {
	xge_os_vasprintf(buf, fmt);
	return (strlen(buf));
}
#endif

#define	xge_os_timestamp(buf) { \
	todinfo_t todinfo = utc_to_tod(ddi_get_time()); \
	(void) xge_os_sprintf(buf, "%02d/%02d/%02d.%02d:%02d:%02d: ", \
	    todinfo.tod_day, todinfo.tod_month, \
	    (1970 + todinfo.tod_year - 70), \
	    todinfo.tod_hour, todinfo.tod_min, todinfo.tod_sec); \
}

#define	xge_os_println			xge_os_printf

/* -------------------- synchronization primitives ------------------------- */

#define	xge_os_spin_lock_init(lockp, ctxh) \
	mutex_init(lockp, NULL, MUTEX_DRIVER, NULL)
#define	xge_os_spin_lock_init_irq(lockp, irqh) \
	mutex_init(lockp, NULL, MUTEX_DRIVER, DDI_INTR_PRI(irqh))
#define	xge_os_spin_lock_destroy(lockp, cthx) \
	(cthx = cthx, mutex_destroy(lockp))
#define	xge_os_spin_lock_destroy_irq(lockp, cthx) \
	(cthx = cthx, mutex_destroy(lockp))
#define	xge_os_spin_lock(lockp)			mutex_enter(lockp)
#define	xge_os_spin_unlock(lockp)		mutex_exit(lockp)
#define	xge_os_spin_lock_irq(lockp, flags) (flags = flags, mutex_enter(lockp))
#define	xge_os_spin_unlock_irq(lockp, flags)	mutex_exit(lockp)

/* x86 arch will never re-order writes, Sparc can */
#define	xge_os_wmb()				membar_producer()

#define	xge_os_udelay(us)			drv_usecwait(us)
#define	xge_os_mdelay(ms)			drv_usecwait(ms * 1000)

#define	xge_os_cmpxchg(targetp, cmp, newval)		\
	sizeof (*(targetp)) == 4 ?			\
	atomic_cas_32((uint32_t *)targetp, cmp, newval) :	\
	atomic_cas_64((uint64_t *)targetp, cmp, newval)

/* ------------------------- misc primitives ------------------------------- */

#define	xge_os_unlikely(x)		(x)
#define	xge_os_prefetch(a)		(a = a)
#define	xge_os_prefetchw
#ifdef __GNUC__
#define	xge_os_bug(fmt...)		cmn_err(CE_PANIC, fmt)
#else
static inline void xge_os_bug(char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vcmn_err(CE_PANIC, fmt, ap);
	va_end(ap);
}
#endif

/* -------------------------- compiler stuffs ------------------------------ */

#if defined(__i386)
#define	__xge_os_cacheline_size		64 /* L1-cache line size: x86_64 */
#else
#define	__xge_os_cacheline_size		64 /* L1-cache line size: sparcv9 */
#endif

#ifdef __GNUC__
#define	__xge_os_attr_cacheline_aligned	\
	__attribute__((__aligned__(__xge_os_cacheline_size)))
#else
#define	__xge_os_attr_cacheline_aligned
#endif

/* ---------------------- memory primitives -------------------------------- */

static inline void *__xge_os_malloc(pci_dev_h pdev, unsigned long size,
    char *file, int line)
{
	void *vaddr = kmem_alloc(size, KM_SLEEP);

	XGE_OS_MEMORY_CHECK_MALLOC(vaddr, size, file, line);
	return (vaddr);
}

static inline void xge_os_free(pci_dev_h pdev, const void *vaddr,
    unsigned long size)
{
	XGE_OS_MEMORY_CHECK_FREE(vaddr, size);
	kmem_free((void*)vaddr, size);
}

#define	xge_os_malloc(pdev, size) \
	__xge_os_malloc(pdev, size, __FILE__, __LINE__)

static inline void *__xge_os_dma_malloc(pci_dev_h pdev, unsigned long size,
    int dma_flags, pci_dma_h *p_dmah, pci_dma_acc_h *p_dma_acch, char *file,
    int line)
{
	void *vaddr;
	int ret;
	size_t real_size;
	extern ddi_device_acc_attr_t *p_xge_dev_attr;
	extern struct ddi_dma_attr *p_hal_dma_attr;

	ret = ddi_dma_alloc_handle(pdev, p_hal_dma_attr,
	    DDI_DMA_DONTWAIT, 0, p_dmah);
	if (ret != DDI_SUCCESS) {
		return (NULL);
	}

	ret = ddi_dma_mem_alloc(*p_dmah, size, p_xge_dev_attr,
	    (dma_flags & XGE_OS_DMA_CONSISTENT ?
	    DDI_DMA_CONSISTENT : DDI_DMA_STREAMING), DDI_DMA_DONTWAIT, 0,
	    (caddr_t *)&vaddr, &real_size, p_dma_acch);
	if (ret != DDI_SUCCESS) {
		ddi_dma_free_handle(p_dmah);
		return (NULL);
	}

	if (size > real_size) {
		ddi_dma_mem_free(p_dma_acch);
		ddi_dma_free_handle(p_dmah);
		return (NULL);
	}

	XGE_OS_MEMORY_CHECK_MALLOC(vaddr, size, file, line);

	return (vaddr);
}

#define	xge_os_dma_malloc(pdev, size, dma_flags, p_dmah, p_dma_acch) \
	__xge_os_dma_malloc(pdev, size, dma_flags, p_dmah, p_dma_acch, \
	    __FILE__, __LINE__)

static inline void xge_os_dma_free(pci_dev_h pdev, const void *vaddr, int size,
    pci_dma_acc_h *p_dma_acch, pci_dma_h *p_dmah)
{
	XGE_OS_MEMORY_CHECK_FREE(vaddr, 0);
	ddi_dma_mem_free(p_dma_acch);
	ddi_dma_free_handle(p_dmah);
}


/* --------------------------- pci primitives ------------------------------ */

#define	xge_os_pci_read8(pdev, cfgh, where, val)	\
	(*(val) = pci_config_get8(cfgh, where))

#define	xge_os_pci_write8(pdev, cfgh, where, val)	\
	pci_config_put8(cfgh, where, val)

#define	xge_os_pci_read16(pdev, cfgh, where, val)	\
	(*(val) = pci_config_get16(cfgh, where))

#define	xge_os_pci_write16(pdev, cfgh, where, val)	\
	pci_config_put16(cfgh, where, val)

#define	xge_os_pci_read32(pdev, cfgh, where, val)	\
	(*(val) = pci_config_get32(cfgh, where))

#define	xge_os_pci_write32(pdev, cfgh, where, val)	\
	pci_config_put32(cfgh, where, val)

/* --------------------------- io primitives ------------------------------- */

#define	xge_os_pio_mem_read8(pdev, regh, addr)		\
	(ddi_get8(regh, (uint8_t *)(addr)))

#define	xge_os_pio_mem_write8(pdev, regh, val, addr)	\
	(ddi_put8(regh, (uint8_t *)(addr), val))

#define	xge_os_pio_mem_read16(pdev, regh, addr)		\
	(ddi_get16(regh, (uint16_t *)(addr)))

#define	xge_os_pio_mem_write16(pdev, regh, val, addr)	\
	(ddi_put16(regh, (uint16_t *)(addr), val))

#define	xge_os_pio_mem_read32(pdev, regh, addr)		\
	(ddi_get32(regh, (uint32_t *)(addr)))

#define	xge_os_pio_mem_write32(pdev, regh, val, addr)	\
	(ddi_put32(regh, (uint32_t *)(addr), val))

#define	xge_os_pio_mem_read64(pdev, regh, addr)		\
	(ddi_get64(regh, (uint64_t *)(addr)))

#define	xge_os_pio_mem_write64(pdev, regh, val, addr)	\
	(ddi_put64(regh, (uint64_t *)(addr), val))

#define	xge_os_flush_bridge xge_os_pio_mem_read64

/* --------------------------- dma primitives ----------------------------- */

#define	XGE_OS_DMA_DIR_TODEVICE		DDI_DMA_SYNC_FORDEV
#define	XGE_OS_DMA_DIR_FROMDEVICE	DDI_DMA_SYNC_FORKERNEL
#define	XGE_OS_DMA_DIR_BIDIRECTIONAL	-1
#if defined(__x86)
#define	XGE_OS_DMA_USES_IOMMU		0
#else
#define	XGE_OS_DMA_USES_IOMMU		1
#endif

#define	XGE_OS_INVALID_DMA_ADDR		((dma_addr_t)0)

static inline dma_addr_t xge_os_dma_map(pci_dev_h pdev, pci_dma_h dmah,
    void *vaddr, size_t size, int dir, int dma_flags) {
	int ret;
	uint_t flags;
	uint_t ncookies;
	ddi_dma_cookie_t dma_cookie;

	switch (dir) {
	case XGE_OS_DMA_DIR_TODEVICE:
		flags = DDI_DMA_WRITE;
		break;
	case XGE_OS_DMA_DIR_FROMDEVICE:
		flags = DDI_DMA_READ;
		break;
	case XGE_OS_DMA_DIR_BIDIRECTIONAL:
		flags = DDI_DMA_RDWR;
		break;
	default:
		return (0);
	}

	flags |= (dma_flags & XGE_OS_DMA_CONSISTENT) ?
	    DDI_DMA_CONSISTENT : DDI_DMA_STREAMING;

	ret = ddi_dma_addr_bind_handle(dmah, NULL, vaddr, size, flags,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies);
	if (ret != DDI_SUCCESS) {
		return (0);
	}

	if (ncookies != 1 || dma_cookie.dmac_size < size) {
		(void) ddi_dma_unbind_handle(dmah);
		return (0);
	}

	return (dma_cookie.dmac_laddress);
}

static inline void xge_os_dma_unmap(pci_dev_h pdev, pci_dma_h dmah,
    dma_addr_t dma_addr, size_t size, int dir)
{
	(void) ddi_dma_unbind_handle(dmah);
}

static inline void xge_os_dma_sync(pci_dev_h pdev, pci_dma_h dmah,
    dma_addr_t dma_addr, u64 dma_offset, size_t length, int dir)
{
	(void) ddi_dma_sync(dmah, dma_offset, length, dir);
}

#ifdef __cplusplus
}
#endif

#endif /* _SYS_XGE_OSDEP_H */
