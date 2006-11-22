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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_COMMON_IMPL_H
#define	_SYS_NXGE_NXGE_COMMON_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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



#define		NO_DEBUG	0x0000000000000000ULL
#define		MDT_CTL		0x0000000000000001ULL
#define		RX_CTL		0x0000000000000002ULL
#define		TX_CTL		0x0000000000000004ULL
#define		OBP_CTL		0x0000000000000008ULL

#define		VPD_CTL		0x0000000000000010ULL
#define		DDI_CTL		0x0000000000000020ULL
#define		MEM_CTL		0x0000000000000040ULL
#define		SAP_CTL		0x0000000000000080ULL

#define		IOC_CTL		0x0000000000000100ULL
#define		MOD_CTL		0x0000000000000200ULL
#define		DMA_CTL		0x0000000000000400ULL
#define		STR_CTL		0x0000000000000800ULL

#define		INT_CTL		0x0000000000001000ULL
#define		SYSERR_CTL	0x0000000000002000ULL
#define		KST_CTL		0x0000000000004000ULL
#define		PCS_CTL		0x0000000000008000ULL

#define		MII_CTL		0x0000000000010000ULL
#define		MIF_CTL		0x0000000000020000ULL
#define		FCRAM_CTL	0x0000000000040000ULL
#define		MAC_CTL		0x0000000000080000ULL

#define		IPP_CTL		0x0000000000100000ULL
#define		DMA2_CTL	0x0000000000200000ULL
#define		RX2_CTL		0x0000000000400000ULL
#define		TX2_CTL		0x0000000000800000ULL

#define		MEM2_CTL	0x0000000001000000ULL
#define		MEM3_CTL	0x0000000002000000ULL
#define		NXGE_CTL	0x0000000004000000ULL
#define		NDD_CTL		0x0000000008000000ULL
#define		NDD2_CTL	0x0000000010000000ULL

#define		TCAM_CTL	0x0000000020000000ULL
#define		CFG_CTL		0x0000000040000000ULL
#define		CFG2_CTL	0x0000000080000000ULL

#define		FFLP_CTL	TCAM_CTL | FCRAM_CTL

#define		VIR_CTL		0x0000000100000000ULL
#define		VIR2_CTL	0x0000000200000000ULL

#define		NXGE_NOTE	0x0000001000000000ULL
#define		NXGE_ERR_CTL	0x0000002000000000ULL

#define		DUMP_ALWAYS	0x2000000000000000ULL

/* NPI Debug and Error defines */
#define		NPI_RDC_CTL	0x0000000000000001ULL
#define		NPI_TDC_CTL	0x0000000000000002ULL
#define		NPI_TXC_CTL	0x0000000000000004ULL
#define		NPI_IPP_CTL	0x0000000000000008ULL

#define		NPI_XPCS_CTL	0x0000000000000010ULL
#define		NPI_PCS_CTL	0x0000000000000020ULL
#define		NPI_ESR_CTL	0x0000000000000040ULL
#define		NPI_BMAC_CTL	0x0000000000000080ULL
#define		NPI_XMAC_CTL	0x0000000000000100ULL
#define		NPI_MAC_CTL	NPI_BMAC_CTL | NPI_XMAC_CTL

#define		NPI_ZCP_CTL	0x0000000000000200ULL
#define		NPI_TCAM_CTL	0x0000000000000400ULL
#define		NPI_FCRAM_CTL	0x0000000000000800ULL
#define		NPI_FFLP_CTL	NPI_TCAM_CTL | NPI_FCRAM_CTL

#define		NPI_VIR_CTL	0x0000000000001000ULL
#define		NPI_PIO_CTL	0x0000000000002000ULL
#define		NPI_VIO_CTL	0x0000000000004000ULL

#define		NPI_REG_CTL	0x0000000040000000ULL
#define		NPI_CTL		0x0000000080000000ULL
#define		NPI_ERR_CTL	0x0000000080000000ULL

#if	defined(SOLARIS) && defined(_KERNEL)

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

#if	1
#define	NXGE_ERROR_MSG(params)	nxge_debug_msg params
#define	NXGE_WARN_MSG(params)	nxge_debug_msg params
#else
#define	NXGE_ERROR_MSG(params)
#define	NXGE_WARN_MSG(params)

#endif


typedef kmutex_t			nxge_os_mutex_t;
typedef	krwlock_t			nxge_os_rwlock_t;

typedef	dev_info_t			nxge_dev_info_t;
typedef	ddi_iblock_cookie_t 		nxge_intr_cookie_t;

typedef ddi_acc_handle_t		nxge_os_acc_handle_t;
typedef	nxge_os_acc_handle_t		npi_reg_handle_t;
typedef	uint64_t			npi_reg_ptr_t;

typedef ddi_dma_handle_t		nxge_os_dma_handle_t;
typedef struct _nxge_dma_common_t	nxge_os_dma_common_t;
typedef struct _nxge_block_mv_t		nxge_os_block_mv_t;
typedef frtn_t				nxge_os_frtn_t;

#define	NXGE_MUTEX_DRIVER		MUTEX_DRIVER
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

#define	NXGE_DELAY(microseconds)	 (drv_usecwait(microseconds))

#define	NXGE_PIO_READ8(handle, devaddr, offset)		\
	(ddi_get8(handle, (uint8_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_READ16(handle, devaddr, offset)		\
	(ddi_get16(handle, (uint16_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_READ32(handle, devaddr, offset)		\
	(ddi_get32(handle, (uint32_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_READ64(handle, devaddr, offset)		\
	(ddi_get64(handle, (uint64_t *)((caddr_t)devaddr + offset)))

#define	NXGE_PIO_WRITE8(handle, devaddr, offset, data)	\
	(ddi_put8(handle, (uint8_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_PIO_WRITE16(handle, devaddr, offset, data)	\
	(ddi_get16(handle, (uint16_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_PIO_WRITE32(handle, devaddr, offset, data)	\
	(ddi_put32(handle, (uint32_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data)	\
	(ddi_put64(handle, (uint64_t *)((caddr_t)devaddr + offset), data))

#define	NXGE_NPI_PIO_READ8(npi_handle, offset)		\
	(ddi_get8(NPI_REGH(npi_handle),			\
	(uint8_t *)(NPI_REGP(npi_handle) + offset)))

#define	NXGE_NPI_PIO_READ16(npi_handle, offset)		\
	(ddi_get16(NPI_REGH(npi_handle),		\
	(uint16_t *)(NPI_REGP(npi_handle) + offset)))

#define	NXGE_NPI_PIO_READ32(npi_handle, offset)		\
	(ddi_get32(NPI_REGH(npi_handle),		\
	(uint32_t *)(NPI_REGP(npi_handle) + offset)))

#ifdef SW_SIM
#define	NXGE_NPI_PIO_READ64(npi_handle, offset)		\
	(*(uint64_t *)(NPI_REGP(npi_handle) + offset))

#elif AXIS_DEBUG
#define	NXGE_NPI_PIO_READ64(npi_handle, offset)		  \
	ddi_get64(NPI_REGH(npi_handle),		\
	(uint64_t *)(NPI_REGP(npi_handle) + offset));
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

#ifdef SW_SIM
#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	\
	(*((uint64_t *)(NPI_REGP(npi_handle) + (uint64_t)offset)) = \
	(uint64_t)data);
#elif defined(AXIS_DEBUG) && !defined(LEGION)
#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	{ \
	ddi_put64(NPI_REGH(npi_handle),		\
	(uint64_t *)(NPI_REGP(npi_handle) + offset), data); \
}
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
#ifdef	NXGE_FM
#define	FM_SERVICE_RESTORED(nxgep)\
		ddi_fm_service_impact(nxgep->dip, DDI_SERVICE_RESTORED)
#define	NXGE_FM_REPORT_ERROR(nxgep, portn, chan, ereport_id)\
		nxge_fm_report_error(nxgep, portn, chan, ereport_id)
#else
#define	FM_SERVICE_RESTORED(nxgep)
#define	NXGE_FM_REPORT_ERROR(nxgep, portn, chan, ereport_id)
#endif

#elif	defined(LINUX) && defined(__KERNEL_)

#include <linux/config.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/list.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/crc32.h>
#include <linux/random.h>
/* #include <linux/mii.h> */
#include <linux/if_vlan.h>
#include <linux/llc.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/checksum.h>

#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>

typedef unsigned char	uchar_t;
typedef unsigned short	ushort_t;
typedef unsigned int	uint_t;
typedef unsigned long	ulong_t;

#define	uintptr_t	unsigned long

#define	ETHERADDRL ETH_ALEN
/*
 * Ethernet address - 6 octets
 */
struct	ether_addr {
	uchar_t ether_addr_octet[ETHERADDRL];
};

typedef struct ether_addr ether_addr_st, *p_ether_addr_t;

typedef enum {
#undef B_FALSE
	B_FALSE = 0,
#undef B_TRUE
	B_TRUE = 1
} boolean_t;

typedef enum  {
	BKSIZE_4K,
	BKSIZE_8K,
	BKSIZE_16K,
	BKSIZE_32K
} nxge_rx_block_size_t;

#ifdef NXGE_DEBUG
#define	NXGE_DEBUG_MSG(params) nxge_debug_msg params
#define	NXGE_WARN_MSG(params) nxge_debug_msg params
#else
#define	NXGE_DEBUG_MSG(params)
#define	NXGE_WARN_MSG(params)
#endif

#define	NXGE_ERROR_MSG(params) nxge_debug_msg params

#define	NPI_INPUT_ERR(funcname, param, val) \
	printk(KERN_ERR "%s: Invalid Input: %s <0x%x>\n", funcname, param, \
		(int)val);

#define	NPI_HW_ERR(funcname, reg, val) \
	printk(KERN_ERR "%s: HW Error: %s <0x%x>\n", funcname, reg, (int)val);


#define	IS_PORT_NUM_VALID(portn) \
	(portn < 4)


typedef spinlock_t			nxge_os_mutex_t;
typedef	rwlock_t			nxge_os_rwlock_t;

typedef	struct pci_dev			nxge_dev_info_t;
typedef	void * 				nxge_intr_cookie_t;

typedef void *				nxge_os_acc_handle_t;
typedef	nxge_os_acc_handle_t		npi_reg_handle_t;
typedef char				*npi_reg_ptr_t;

typedef void *				nxge_os_dma_handle_t;
typedef void				nxge_os_dma_common_t;
typedef void				nxge_os_block_mv_t;
typedef int				nxge_os_frtn_t;

#define	MUTEX_INIT(lock, nm, tp, arg)	spin_lock_init((lock))
#define	MUTEX_ENTER(lock)		spin_lock((lock))
#define	MUTEX_TRY_ENTER(lock)		spin_trylock((lock))
#define	MUTEX_EXIT(lock)		spin_unlock((lock))
#define	MUTEX_ENTER_INT(lock, flags)	spin_lock_irqsave(lock, flags)
#define	MUTEX_EXIT_INT(lock, flags)	spin_unlock_irqrestore(lock, flags)
#define	MUTEX_DESTROY(lock)

#define	RW_INIT(lock, nm, tp, arg)	rw_lock_init((lock))
#define	RW_ENTER_WRITER(lock)		write_lock(lock)
#define	RW_ENTER_READER(lock)		read_lock(lock)
#define	RW_EXIT(lock)			write_unlock(lock)
#define	RW_EXIT_READ(lock)		read_unlock(lock)
#define	RW_DESTROY(lock)

#define	NXGE_DELAY(microseconds)	(udelay(microseconds))

static inline void * nxge_kzalloc(size_t size, int flag)
{
	void * ptr = kmalloc(size, flag);
	if (ptr != NULL)
		memset(ptr, 0, size);

	return (ptr);
}

#define	KMEM_ALLOC(size, flag)		kmalloc(size, flag)
#define	KMEM_ZALLOC(size, flag)		nxge_kzalloc(size, flag)
#define	KMEM_FREE(buf, size)		kfree(buf)

#ifndef readq
static inline uint64_t readq(void *addr)
{
	uint64_t ret = readl(addr + 4);
	ret <<= 32;
	ret |= readl(addr);

	return (ret);
}
#endif

#ifndef writeq
static inline void writeq(uint64_t val, void *addr)
{
	writel((uint32_t)(val), addr);
	writel((uint32_t)(val >> 32), (addr + 4));
}

/*
 * In 32 bit modes, some registers have to be written in a
 * particular order to expect correct hardware operation. The
 * macro SPECIAL_REG_WRITE is used to perform such ordered
 * writes. Defines UF(Upper First) and LF(Lower First) will
 * be used to specify the required write order.
 */
#define	UF	1
#define	LF	2
static inline void SPECIAL_REG_WRITE(uint64_t val, void *addr, int order)
{
	if (order == LF) {
		writel((uint32_t)(val), addr);
		writel((uint32_t)(val >> 32), (addr + 4));
	} else {
	writel((uint32_t)(val >> 32), (addr + 4));
	writel((uint32_t)(val), addr);
	}
}
#else
#define	SPECIAL_REG_WRITE(val, addr, dummy) writeq(val, addr)
#endif

#define	NXGE_PIO_READ8(handle, devaddr, offset)		\
	(readb((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ16(handle, devaddr, offset)	\
	(readw((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ32(handle, devaddr, offset)	\
	(readl((caddr_t)devaddr + offset))

#ifdef SW_SIM
#define	NXGE_PIO_READ64(handle, devaddr, offset)	\
	(*((uint64_t *)(devaddr + offset)))
#elif AXIS_DEBUG
#define	NXGE_PIO_READ64(handle, devaddr, offset) {	\
	readq((caddr_t)devaddr + offset);		\
	mdelay(100);					\
}
#else
#define	NXGE_PIO_READ64(handle, devaddr, offset)	\
	(readq((caddr_t)devaddr + offset))
#endif

#define	NXGE_PIO_WRITE8(handle, devaddr, offset, data)	\
	(writeb(data, ((caddr_t)devaddr + offset))

#define	NXGE_PIO_WRITE16(handle, devaddr, offset, data)	\
	(writew(data, ((caddr_t)devaddr + offset)))

#define	NXGE_PIO_WRITE32(handle, devaddr, offset, data)	\
	(writel(data, ((caddr_t)devaddr + offset)))

#ifdef SW_SIM
#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data)	\
	(*((uint64_t *)(devaddr + offset)) = \
	(uint64_t)data);
#elif AXIS_DEBUG
#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data) {	\
	mdelay(100);						\
	writeq(data, ((caddr_t)devaddr + offset));		\
}
#else
#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data)	\
	(writeq(data, ((caddr_t)devaddr + offset)))
#endif

#define	NXGE_NPI_PIO_READ8(npi_handle, offset)	\
	(readb(NPI_REGP(npi_handle) + offset))

#define	NXGE_NPI_PIO_READ16(npi_handle, offset)	\
	(readw(NPI_REGP(npi_handle) + offset))

#define	NXGE_NPI_PIO_READ32(npi_handle, offset)	\
	(readl(NPI_REGP(npi_handle) + offset))

#ifndef SW_SIM
#define	NXGE_NPI_PIO_READ64(npi_handle, offset)	\
	(readq(NPI_REGP(npi_handle) + offset))
#else
#define	NXGE_NPI_PIO_READ64(npi_handle, offset)	\
	(*((uint64_t *)(NPI_REGP(npi_handle) + offset)))
#endif /* SW_SIM */

#define	NXGE_NPI_PIO_WRITE8(npi_handle, offset, data)	\
	(writeb(data, NPI_REGP(npi_handle) + offset))

#define	NXGE_NPI_PIO_WRITE16(npi_handle, offset, data)	\
	(writew(data, NPI_REGP(npi_handle) + offset))

#define	NXGE_NPI_PIO_WRITE32(npi_handle, offset, data)	\
	(writel(data, NPI_REGP(npi_handle) + offset))

#ifndef SW_SIM
#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	\
	(writeq(data, NPI_REGP(npi_handle) + offset))
#else
#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	\
	(*((uint64_t *)(NPI_REGP(npi_handle) + (uint64_t)offset)) = \
	(uint64_t)data);
#endif /* SW_SIM */

#define	NXGE_MEM_PIO_READ8(npi_handle)	(*((uint8_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ16(npi_handle)	(*((uint16_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ32(npi_handle)	(*((uint32_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ64(npi_handle)	(*((uint64_t *)NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_WRITE8(npi_handle, data)	\
	(*((uint8_t *)NPI_REGP(npi_handle))) = ((uint8_t)data)

#define	NXGE_MEM_PIO_WRITE16(npi_handle, data)	\
	(*((uint16_t *)NPI_REGP(npi_handle))) = ((uint16_t)data)

#define	NXGE_MEM_PIO_WRITE32(npi_handle, data)	\
	(*((uint32_t *)NPI_REGP(npi_handle))) = ((uint32_t)data)

#define	NXGE_MEM_PIO_WRITE64(npi_handle, data)	\
	(*((uint64_t *)NPI_REGP(npi_handle))) = ((uint64_t)data)

#elif	defined(COSIM)

#include <sys/types.h>
#include <sys/conf.h>
#if	defined(SOLARIS) && !defined(IODIAG)
#include <sys/varargs.h>
#include <ne_sim_solaris.h>
#endif

#ifdef NXGE_DEBUG
#define	NXGE_DEBUG_MSG(params) nxge_debug_msg params
#define	NXGE_ERROR_MSG(params) nxge_debug_msg params
#else
#define	NXGE_DEBUG_MSG(params)
#define	NXGE_ERROR_MSG(params)
#endif

#if !defined(ETHERADDRL)
#define	ETHERADDRL 6

/*
 * Ethernet address - 6 octets
 */
struct	ether_addr {
	uchar_t ether_addr_octet[ETHERADDRL];
};

typedef struct ether_addr ether_addr_st, *p_ether_addr_t;
#endif

#ifdef LINUX
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#ifndef COSIM_LINUX_DEF
#define	COSIM_LINUX_DEF
typedef uint8_t uchar_t;
typedef uint32_t uint_t;
typedef uint64_t dma_addr_t;

typedef enum {
#undef B_FALSE
	B_FALSE = 0,
#undef B_TRUE
	B_TRUE = 1
} boolean_t;

#endif

typedef enum  {
	BKSIZE_4K,
	BKSIZE_8K,
	BKSIZE_16K,
	BKSIZE_32K
} nxge_rx_block_size_t;

#define	IS_PORT_NUM_VALID(portn) \
	(portn < 4)

#define	GFP_KERNEL	0

#endif /* LINUX in COSIM */

#include <ht_client.h>
#include <ht_lib.h>

#include <pthread.h>


typedef pthread_mutex_t		nxge_os_mutex_t;
typedef	unsigned int		nxge_os_rwlock_t;

typedef	void * 			nxge_dev_info_t;
typedef	void * 			nxge_intr_cookie_t;
typedef void *			nxge_os_dma_handle_t;
typedef void *			nxge_os_acc_handle_t;
typedef	nxge_os_acc_handle_t	npi_reg_handle_t;
typedef	uint64_t		npi_reg_ptr_t;

#if defined(IODIAG)
#define	timeout(a, b, c)	()
#define	untimeout(a)	()
#define	drv_usectohz(a)	()
#define	drv_usecwait(a)
#define	ether_cmp(a, b)	(bcmp((caddr_t)a, (caddr_t)b, 6))

typedef int			nxge_os_dma_common_t;
typedef int			nxge_os_block_mv_t;
typedef int			nxge_os_frtn_t;
typedef void *			p_mblk_t;
typedef void *			MBLKP;

#define	NXGE_MUTEX_DRIVER	NULL
#define	MUTEX_INIT(lock, name, type, arg)	pthread_mutex_init(lock, NULL)

#define	MUTEX_ENTER(lock)	pthread_mutex_lock((pthread_mutex_t *)lock)

#define	MUTEX_TRY_ENTER(lock)	pthread_mutex_trylock(lock)

#define	MUTEX_EXIT(lock)	pthread_mutex_unlock(lock)

#define	MUTEX_ENTER_INT(lock, flags)	MUTEX_ENTER(lock)

#define	MUTEX_EXIT_INT(lock, flags)	MUTEX_EXIT(lock)

#define	MUTEX_DESTROY(lock)	pthread_mutex_destroy(lock)

#else
typedef struct _nxge_dma_common_t	nxge_os_dma_common_t;
typedef struct _nxge_block_mv_t		nxge_os_block_mv_t;
typedef frtn_t			nxge_os_frtn_t;

#define	NXGE_MUTEX_DRIVER	NULL
#define	MUTEX_INIT(lock, name, type, arg)
#define	MUTEX_ENTER(lock)
#define	MUTEX_TRY_ENTER(lock)
#define	MUTEX_EXIT(lock)
#define	MUTEX_ENTER_INT(lock, flags)	MUTEX_ENTER(lock)
#define	MUTEX_EXIT_INT(lock, flags)	MUTEX_EXIT(lock)
#define	MUTEX_DESTROY(lock)
#endif

#define	KMEM_ALLOC(size, flag)		malloc(size)
#if defined(IODIAG)
#define	KMEM_ZALLOC(size, flag)		kmem_zalloc(size, flag)
#else
#define	KMEM_ZALLOC(size, flag)		malloc(size)
#endif
#define	KMEM_FREE(buf, size)		free(buf)
#define	RW_INIT(lock, name, type, arg)
#define	RW_ENTER_WRITER(lock)
#define	RW_ENTER_READER(lock)
#define	RW_TRY_ENTER(lock, type)
#define	RW_EXIT(lock)
#define	RW_EXIT_READ(lock)
#define	RW_DESTROY(lock)
#define	NXGE_NOTIFY_NETWORK_STACK(nxgep, event)
#define	FM_REPORT_FAULT(nxgep, impact, location, msg)
#define	FM_CHECK_DEV_HANDLE(nxgep)	NULL
#define	FM_SERVICE_RESTORED(nxgep)
#define	FM_GET_DEVSTATE(nxgep)	NULL
#define	NXGE_FM_REPORT_ERROR(nxgep, portn, chan, ereport_id)
#define	SERVICE_LOST		NULL
#define	SERVICE_DEGRADED	NULL
#define	SERVICE_UNAFFECTED	NULL
#define	SERVICE_RESTORED	NULL

#define	DATAPATH_FAULT		NULL
#define	DEVICE_FAULT		NULL
#define	EXTERNAL_FAULT		NULL

#define	NOTE_LINK_UP		NULL
#define	NOTE_LINK_DOWN		NULL
#define	NOTE_SPEED		NULL
#define	NOTE_PHYS_ADDR		NULL
#define	NOTE_AGGR_AVAIL		NULL
#define	NOTE_AGGR_UNAVAIL	NULL

#define	kmem_free(buf, size) free(buf)


#define	NXGE_DELAY(microseconds)

#define	NXGE_PIO_READ8(handle, devaddr, offset)		\
	(*(uint8_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ16(handle, devaddr, offset)	\
	(*(uint16_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ32(handle, devaddr, offset)	\
	(*(uint32_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ64(handle, devaddr, offset)	\
	(*(uint64_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_WRITE8(handle, devaddr, offset, data)	\
	(*((uint8_t *)((caddr_t)devaddr + offset)) = (uint8_t)data);

#define	NXGE_PIO_WRITE16(handle, devaddr, offset, data)	\
	(*((uint16_t *)((caddr_t)devaddr + offset)) = (uint16_t)data);

#define	NXGE_PIO_WRITE32(handle, devaddr, offset, data)	\
	(*((uint32_t *)((caddr_t)devaddr + offset)) = (uint32_t)data);

#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data)	\
	(*((uint64_t *)((caddr_t)devaddr + offset)) = (uint64_t)data);

#ifdef IODIAG_NEPTUNE
#define	NXGE_NPI_PIO_WRITE64(handle, offset, value) {	\
	htSetQWord((uint64_t)offset, value);		\
	us_delay(100000);				\
}
#else
#define	NXGE_NPI_PIO_WRITE64(handle, offset, value) \
	htSetQWord((uint64_t)offset, value)
#endif

#define	NXGE_NPI_PIO_WRITE32(handle, offset, value) \
	htSetDWord((uint64_t)offset, value)

#define	NXGE_NPI_PIO_READ64(handle, offset) \
	htread64((uint64_t)offset)

#define	NXGE_NPI_PIO_READ32(handle, offset) \
	htread32((uint64_t)offset)

#define	NXGE_MEM_PIO_READ8(npi_handle)	(*(uint8_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ16(npi_handle)	(*(uint16_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ32(npi_handle)	(*(uint32_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ64(npi_handle)	(*(uint64_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_WRITE8(npi_handle, data)	\
	(*((uint8_t *)NPI_REGP(npi_handle)) = (uint8_t)data);

#define	NXGE_MEM_PIO_WRITE16(npi_handle, data)	\
	(*((uint16_t *)NPI_REGP(npi_handle)) = (uint16_t)data);

#define	NXGE_MEM_PIO_WRITE32(npi_handle, data)	\
	(*((uint32_t *)NPI_REGP(npi_handle)) = (uint32_t)data);

#define	NXGE_MEM_PIO_WRITE64(npi_handle, data)	\
	(*((uint64_t *)NPI_REGP(npi_handle)) = (uint64_t)data);

#define	NPI_INPUT_ERR(funcname, param, val) \
	printf("%s: Invalid Input: %s <0x%x>\n", funcname, param, (int)val);

#define	NPI_HW_ERR(funcname, reg, val) \
	printf("%s: HW Error: %s <0x%x>\n", funcname, reg, (int)val);



#elif	defined(SW_SIM)
typedef unsigned int			nxge_os_mutex_t;
typedef	unsigned int			nxge_os_rwlock_t;

typedef	unsigned int			nxge_dev_info_t;
typedef	void * 				nxge_intr_cookie_t;
typedef void *				nxge_os_acc_handle_t;
typedef	nxge_os_acc_handle_t		npi_reg_handle_t;
typedef	uint64_t			npi_reg_ptr_t;

typedef unsigned int			nxge_os_dma_handle_t;
typedef unsigned int			nxge_os_dma_common_t;
typedef unsigned int				nxge_os_block_mv_t;
typedef int				nxge_os_frtn_t;
typedef void *			p_mblk_t;

typedef struct ether_addr ether_addr_st, *p_ether_addr_t;
#define	NXGE_MUTEX_DRIVER		MUTEX_DRIVER
#define	MUTEX_INIT(lock, name, type, arg)	\
					mutex_init(lock, name, type, arg)
#define	MUTEX_ENTER(lock)		mutex_enter(lock)
#define	MUTEX_TRY_ENTER(lock)		mutex_tryenter(lock)
#define	MUTEX_EXIT(lock)		mutex_exit(lock)
#define	MUTEX_DESTROY(lock)		mutex_destroy(lock)

#define	RW_INIT(lock, nm, tp, arg)
#define	RW_ENTER_WRITER(lock)
#define	RW_ENTER_READER(lock)
#define	RW_EXIT(lock)
#define	RW_DESTROY(lock)

#define	NXGE_DELAY(microseconds)

#define	NXGE_PIO_READ8(handle, devaddr, offset)		\
	(*(uint8_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ16(handle, devaddr, offset)	\
	(*(uint16_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ32(handle, devaddr, offset)	\
	(*(uint32_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_READ64(handle, devaddr, offset)	\
	(*(uint64_t *)((caddr_t)devaddr + offset))

#define	NXGE_PIO_WRITE8(handle, devaddr, offset, data)	\
	(*((uint8_t *)((caddr_t)devaddr + offset)) = (uint8_t)data);

#define	NXGE_PIO_WRITE16(handle, devaddr, offset, data)	\
	(*((uint16_t *)((caddr_t)devaddr + offset)) = (uint16_t)data);

#define	NXGE_PIO_WRITE32(handle, devaddr, offset, data)	\
	(*((uint32_t *)((caddr_t)devaddr + offset)) = (uint32_t)data);

#define	NXGE_PIO_WRITE64(handle, devaddr, offset, data)	\
	(*((uint64_t *)((caddr_t)devaddr + offset)) = (uint64_t)data);


#define	NXGE_NPI_PIO_READ8(npi_handle, offset)	\
	(*((uint8_t *)(NPI_REGP(npi_handle) + offset)))

#define	NXGE_NPI_PIO_READ16(npi_handle, offset)	\
	(*((uint16_t *)(NPI_REGP(npi_handle) + offset)))

#define	NXGE_NPI_PIO_READ32(npi_handle, offset)	\
	(*((uint32_t *)(NPI_REGP(npi_handle) + offset)));

#define	NXGE_NPI_PIO_READ64(npi_handle, offset)	\
	(*(uint64_t *)(NPI_REGP(npi_handle) + offset));

#define	NXGE_NPI_PIO_WRITE8(npi_handle, offset, data)	\
	(*((uint8_t *)(NPI_REGP(npi_handle) + offset)) = (uint8_t)data);

#define	NXGE_NPI_PIO_WRITE16(npi_handle, offset, data)	\
	(*((uint16_t *)(NPI_REGP(npi_handle) + offset)) = (uint16_t)data);

#define	NXGE_NPI_PIO_WRITE32(npi_handle, offset, data)	\
	(*((uint32_t *)(NPI_REGP(npi_handle) + offset)) = (uint32_t)data);

#define	NXGE_NPI_PIO_WRITE64(npi_handle, offset, data)	\
	(*((uint64_t *)(NPI_REGP(npi_handle) + (uint64_t)offset)) = \
		(uint64_t)data);

#define	NXGE_MEM_PIO_READ8(npi_handle)	(*(uint8_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ16(npi_handle)	(*(uint16_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ32(npi_handle)	(*(uint32_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_READ64(npi_handle)	(*(uint64_t *)(NPI_REGP(npi_handle)))

#define	NXGE_MEM_PIO_WRITE8(npi_handle, data)	\
	(*((uint8_t *)NPI_REGP(npi_handle)) = (uint8_t)data);

#define	NXGE_MEM_PIO_WRITE16(npi_handle, data)	\
	(*((uint16_t *)NPI_REGP(npi_handle)) = (uint16_t)data);

#define	NXGE_MEM_PIO_WRITE32(npi_handle, data)	\
	(*((uint32_t *)NPI_REGP(npi_handle)) = (uint32_t)data);

#define	NXGE_MEM_PIO_WRITE64(npi_handle, data)	\
	(*((uint64_t *)NPI_REGP(npi_handle)) = (uint64_t)data);


#define	NPI_INPUT_ERR(funcname, param, val) \
	printf("%s: Invalid Input: %s <0x%x>\n", funcname, param, (int)val);

#define	NPI_HW_ERR(funcname, reg, val) \
	printf("%s: HW Error: %s <0x%x>\n", funcname, reg, (int)val);


#endif

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
#elif defined(AXIS_DEBUG) && !defined(LEGION)
#define	NXGE_REG_RD64(handle, offset, val_p) {\
	int	n;				\
	for (n = 0; n < AXIS_WAIT_LOOP; n++) {	\
		*(val_p) = 0;		\
		*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
		if (*(val_p) != (~0)) { \
			break; \
		}	\
		drv_usecwait(AXIS_WAIT_PER_LOOP); \
		if (n < 20) { \
			cmn_err(CE_WARN, "NXGE_REG_RD64: loop %d " \
			"REG 0x%x(0x%llx)", \
			n, offset, *val_p);\
		}	\
	} \
	if (n >= AXIS_WAIT_LOOP) {	\
		cmn_err(CE_WARN, "(FATAL)NXGE_REG_RD64 on offset 0x%x " \
			"with -1!!!", offset); \
	}	\
}
#else

#define	NXGE_REG_RD64(handle, offset, val_p) {\
	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
}
#endif

/*
 *	 In COSIM mode, we could loop for very long time when polling
 *  for the completion of a Clause45 frame MDIO operations. Display
 *  one rtrace line for each poll can result in messy screen.  Add
 *  this MACRO for no rtrace show.
 */
#define	NXGE_REG_RD64_NO_SHOW(handle, offset, val_p) {\
	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
}


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
