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

#ifndef	_BCM_OSAL_H
#define	_BCM_OSAL_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/ksynch.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/dditypes.h>
#include <sys/list_impl.h>
#include <sys/byteorder.h>

#include "qede_types.h"
#include "qede_list.h"

/*

 * Forward Declarations for ecore data structures
 */
struct ecore_dev;
struct ecore_hwfn;

#define nothing do {} while(0)

#define	INLINE	inline
#define	__iomem
#define OSAL_IOMEM	__iomem

#ifndef likely	
#define	likely(expr)		(expr)
#endif

#ifndef	unlikely
#define	unlikely(expr)		(expr)
#endif

/*
 * Memory related OSAL
 */
#define	OSAL_MEM_ZERO(_dest_, _size_) \
	(void) memset(_dest_, 0, _size_)
#define	OSAL_MEMCPY(_dest_, _src_, _size_) \
	memcpy(_dest_, _src_, _size_)
#define OSAL_MEMCMP(_s1_, _s2_, _size_) \
	memcmp(_s1_, _s2_, _size_)
#define OSAL_MEMSET(_dest_, _val_, _size_) \
	memset(_dest_, _val_, _size_)

/*
 * The illumos DDI has sprintf returning a pointer to the resulting character
 * buffer and not the actual length. Therefore we simulate sprintf like the
 * others do.
 */
extern size_t qede_sprintf(char *, const char *, ...);
#define	OSAL_SPRINTF	qede_sprintf
#define OSAL_SNPRINTF	(ssize_t)snprintf
#define	OSAL_STRCMP	strcmp

#define	GFP_KERNEL	KM_SLEEP
#define	GFP_ATOMIC	KM_NOSLEEP

/* Not used in ecore */
#define OSAL_CALLOC(dev, GFP, num, size) OSAL_NULL

void *qede_osal_zalloc(struct ecore_dev *, int, size_t);
#define	OSAL_ZALLOC(_edev, _flags, _size) \
	qede_osal_zalloc(_edev, _flags, _size)
void *qede_osal_alloc(struct ecore_dev *, int, size_t);
#define	OSAL_ALLOC(_edev, _flags, _size) \
	qede_osal_alloc(_edev, _flags, _size)
void qede_osal_free(struct ecore_dev *, void *addr);
#define	OSAL_FREE(_edev, _addr) \
	qede_osal_free(_edev, _addr)

#define OSAL_VALLOC(_edev, _size) \
	qede_osal_alloc(_edev, GFP_KERNEL, _size)

#define OSAL_VFREE(_edev, _addr) \
	qede_osal_free(_edev, _addr)

#define OSAL_VZALLOC(_edev, _size) \
	qede_osal_zalloc(_edev, GFP_KERNEL, _size)

void *qede_osal_dma_alloc_coherent(struct ecore_dev *, dma_addr_t *, size_t);
#define	OSAL_DMA_ALLOC_COHERENT(_edev_, _paddr_, _mem_size_) \
	qede_osal_dma_alloc_coherent(_edev_, _paddr_, _mem_size_)
void qede_osal_dma_free_coherent(struct ecore_dev *, void *, dma_addr_t, size_t);
#define	OSAL_DMA_FREE_COHERENT(_edev_, _vaddr_, _paddr_, _mem_size_) \
	qede_osal_dma_free_coherent(_edev_, _vaddr_, _paddr_, _mem_size_)

/* Combine given 0xhi and 0xlo into a single U64 in format 0xhilo */
#define	HILO_U64(hi, lo)	((((u64)(hi)) << 32) + (lo))

void qede_osal_dma_sync(struct ecore_dev *edev, void* addr, u32 size, bool is_post);
#define OSAL_DMA_SYNC(dev, addr, length, is_post) \
	qede_osal_dma_sync(dev, addr, length, is_post)
/*
 * BAR Access Related OSAL
 */
void qede_osal_pci_write32(struct ecore_hwfn *hwfn, u32 addr, u32 val);
void qede_osal_pci_write16(struct ecore_hwfn *hwfn, u32 addr, u16 val);
u32 qede_osal_pci_read32(struct ecore_hwfn *hwfn, u32 addr);
u32 *qede_osal_reg_addr(struct ecore_hwfn *hwfn, u32 addr);
void qede_osal_pci_bar2_write32(struct ecore_hwfn *hwfn, u32 offset, u32 val);

#define	REG_WR(_hwfn_, _addr_, _value_) \
	qede_osal_pci_write32(_hwfn_, _addr_, _value_)

#define	REG_WR16(_hwfn_, _addr_, _value_) \
	qede_osal_pci_write16(_hwfn_, _addr_, _value_)

#define	REG_RD(_hwfn_, _addr_) \
	qede_osal_pci_read32(_hwfn_, _addr_)

#define OSAL_REG_ADDR(_hwfn_, _addr_)  \
	qede_osal_reg_addr(_hwfn_, _addr_)

#define	DOORBELL(_hwfn_, _addr_, _val_) \
	qede_osal_pci_bar2_write32(_hwfn_, _addr_, _val_)

void qede_osal_direct_reg_write32(struct ecore_hwfn *hwfn, void *addr, u32 value);
u32 qede_osal_direct_reg_read32(struct ecore_hwfn *hwfn, void *addr);
/* FIXME: not correct Writes to the PCI _addr_ directly */
#define	DIRECT_REG_WR(_hwfn, _addr, _val) \
	qede_osal_direct_reg_write32(_hwfn, _addr, _val)
#define	DIRECT_REG_RD(_hwfn, _addr) \
	qede_osal_direct_reg_read32(_hwfn, _addr)

static inline bool OSAL_NVM_IS_ACCESS_ENABLED(void *p_hwfn)
{
	return (1);
}

/*
 * Bit manipulation Helper functions
 */

#define OSAL_BITS_PER_BYTE      (8)
#define OSAL_BITS_PER_UL        (sizeof(unsigned long)*OSAL_BITS_PER_BYTE) /* always a power of 2 */
#define OSAL_BITS_PER_UL_MASK   (OSAL_BITS_PER_UL - 1)

static inline u32 osal_ffsl(unsigned long x)
{
	int r = 1;

	if (!x)
		return (0);

	if (!(x & 0xffffffff)) {
		x >>= 32;
		r += 32;
	}

	if (!(x & 0xffff)) {
		x >>= 16;
		r += 16;
	}

	if (!(x & 0xff)) {
		x >>= 8;
		r += 8;
	}

	if (!(x & 0xf)) {
		x >>= 4;
		r += 4;
	}
	if (!(x & 3)) {
		x >>= 2;
		r += 2;
	}

	if (!(x & 1)) {
		x >>= 1;
		r += 1;
	}

	return (r);
}

static inline u32 osal_ffz(unsigned long word)
{
	unsigned long first_zero;
        
	first_zero = osal_ffsl(~word);
	return first_zero ? (first_zero-1) : OSAL_BITS_PER_UL;
}

static inline void OSAL_SET_BIT(u32 nr, unsigned long *addr)
{
	addr[nr/OSAL_BITS_PER_UL] |= 1UL << (nr & OSAL_BITS_PER_UL_MASK);
}

static inline void OSAL_CLEAR_BIT(u32 nr, unsigned long *addr)
{
	addr[nr/OSAL_BITS_PER_UL] &= ~(1UL << (nr & OSAL_BITS_PER_UL_MASK));
}

static inline bool OSAL_TEST_BIT(u32 nr, unsigned long *addr)
{
	return !!(addr[nr/OSAL_BITS_PER_UL] & (1UL << (nr & OSAL_BITS_PER_UL_MASK)));
}

static inline u32 OSAL_FIND_FIRST_ZERO_BIT(unsigned long *addr, u32 limit)
{
	u32 i;
	u32 nwords = 0;

	ASSERT(limit);	
	nwords = (limit - 1)/OSAL_BITS_PER_UL + 1;
	for (i = 0; i < nwords && ~(addr[i]) == 0; i++);
	return  (i == nwords)  ? limit : i*OSAL_BITS_PER_UL + osal_ffz(addr[i]);
}

static inline u32 OSAL_FIND_FIRST_BIT(unsigned long *addr, u32 limit)
{
	u32     i;
	u32     nwords = (limit+OSAL_BITS_PER_UL-1)/OSAL_BITS_PER_UL;

	for (i = 0; i < nwords ; i++)
	{
		if (addr[i]!=0)
		break;
	}

	if (i == nwords) {
		return limit;
	} else {
		return i*OSAL_BITS_PER_UL + osal_ffz(addr[i]);
	}
}


/*
 * Time related OSAL
 */
#define	OSAL_UDELAY(_usecs_)		drv_usecwait(_usecs_)
#define	OSAL_MSLEEP(_msecs_)		delay(drv_usectohz(_msecs_ * 1000))

/*
 * Synchronization related OSAL
 */
typedef kmutex_t		osal_mutex_t;
typedef	kmutex_t		osal_spinlock_t;

/*
 * MUTEX/SPINLOCK Related NOTES: 
 * 1. Currently initialize all mutex with default intr prio 0.
 * 2. Later do mutex_init in OSAL_MUTEX_ALLOC() instead of
 * OSAL_MUTEX_INIT, and use proper intr prio.
 * 3. Ensure that before calling any ecore api's, intr prio
 * is properly configured.
 */
#define OSAL_MUTEX_ALLOC(hwfn, lock) nothing
#define OSAL_SPIN_LOCK_ALLOC(hwfn, lock) nothing

#define	OSAL_MUTEX_INIT(_lock_) \
	mutex_init(_lock_, NULL, MUTEX_DRIVER, 0)
#define	OSAL_SPIN_LOCK_INIT(lock) \
	mutex_init(lock, NULL, MUTEX_DRIVER, 0)
#define	OSAL_MUTEX_DEALLOC(_lock) \
	mutex_destroy(_lock)
#define OSAL_SPIN_LOCK_DEALLOC(_lock) \
	mutex_destroy(_lock)

#define	OSAL_MUTEX_ACQUIRE(lock) \
	mutex_enter(lock)
#define	OSAL_SPIN_LOCK(lock) \
	mutex_enter(lock)
#define	OSAL_SPIN_LOCK_IRQSAVE(lock, flags) \
	OSAL_SPIN_LOCK(lock)
#define	OSAL_MUTEX_RELEASE(lock) \
	mutex_exit(lock)
#define	OSAL_SPIN_UNLOCK(lock) \
	mutex_exit(lock)
#define	OSAL_SPIN_UNLOCK_IRQSAVE(lock, flags) \
	OSAL_SPIN_UNLOCK(lock)

/*
 * TODO: Implement dpc ISR
 */
#define	OSAL_DPC_ALLOC(hwfn)		OSAL_ALLOC(hwfn->p_dev, GFP_KERNEL, sizeof (u64)) 
#define	OSAL_DPC_INIT(dpc, hwfn)	nothing

/*
 * PF recovery handler
 */
void qede_osal_recovery_handler(struct ecore_hwfn *hwfn);
#define	OSAL_SCHEDULE_RECOVERY_HANDLER(_ptr)	qede_osal_recovery_handler(_ptr)

/*
 * Process DCBX Event
 */
static inline void OSAL_DCBX_AEN(struct ecore_hwfn *p_hwfn, u32 mib_type)
{
}

/*
 * Endianess Related
 */
#define	LE_TO_HOST_32			LE_32
#define	HOST_TO_LE_32			LE_32
#define	HOST_TO_LE_16			LE_16

#define	OSAL_BE32		u32
#ifdef BIG_ENDIAN
#define	OSAL_CPU_TO_BE64(val)	((val))
#define	OSAL_CPU_TO_BE32(val)	((val))
#define	OSAL_BE32_TO_CPU(val)	((val))
#define OSAL_CPU_TO_LE32(val)	BSWAP_32(val)
#define OSAL_CPU_TO_LE16(val)	BSWAP_16(val)
#define OSAL_LE32_TO_CPU(val)	BSWAP_32(val)
#define OSAL_LE16_TO_CPU(val)	BSWAP_16(val)
#define OSAL_CPU_TO_LE64(val)	BSWAP_64(val)
#else
#define	OSAL_CPU_TO_BE64(val)	BSWAP_64(val)
#define	OSAL_CPU_TO_BE32(val)	BSWAP_32(val)
#define	OSAL_BE32_TO_CPU(val)	BSWAP_32(val)
#define OSAL_CPU_TO_LE32(val)	((val))
#define OSAL_CPU_TO_LE16(val)	((val))
#define OSAL_LE32_TO_CPU(val)	((val))
#define OSAL_LE16_TO_CPU(val)	((val))
#endif
/* 
 * Physical Link Handling
 */
void qede_osal_link_update(struct ecore_hwfn *hwfn);
#define	OSAL_LINK_UPDATE(_hwfn_) \
	qede_osal_link_update(_hwfn_)

/*
 * Linked List Related OSAL,
 * and general Link list API's
 * for driver
 */
#ifndef container_of
#define	container_of(ptr, type, member) \
	(type *)((char *)(ptr) - OFFSETOF(type, member))
#endif

typedef u64 osal_size_t; 
typedef u64 osal_int_ptr_t;       
#define OSAL_NULL	NULL

#define	OSAL_LIST_PUSH_HEAD(_entry_at_beg_, _head_) \
	QEDE_LIST_ADD(_entry_at_beg_, _head_)

#define	OSAL_LIST_PUSH_TAIL(_entry_at_end_, _head_) \
	QEDE_LIST_ADD_TAIL(_entry_at_end_, _head_)

#define	qede_list_entry(_entry_ptr_, _type_, _member_) \
	container_of(_entry_ptr_, _type_, _member_)

#define	qede_list_first_entry(_head_, _type_, _member_) \
	qede_list_entry((_head_)->next, _type_, _member_)

#define	OSAL_LIST_FIRST_ENTRY(_list_, _type_, _member_) \
	qede_list_first_entry(_list_, _type_, _member_)

#define	OSAL_LIST_REMOVE_ENTRY(_entry_, _list_) \
	QEDE_LIST_REMOVE(_entry_, _list_)


#define	OSAL_LIST_IS_EMPTY(_head_) \
	QEDE_LIST_IS_EMPTY(_head_)

#define	qede_list_last_entry(_head_, _type_, _member_) \
	qede_list_entry((_head_)->prev, _type_, _member_)

#define qede_list_prev_entry(_entry_, _type_, _member_) \
	qede_list_entry((_entry_)->_member_.prev, _type_, _member_)

#define	qede_list_for_each_entry(_entry_, _head_, _type_, _member_) \
	for (_entry_ = qede_list_last_entry(_head_, _type_, _member_); \
	    &_entry_->_member_ != (_head_); \
	    _entry_ = qede_list_prev_entry(_entry_, _type_, _member_))

#define	OSAL_LIST_FOR_EACH_ENTRY(_entry_, _list_, _member_, _type_) \
	qede_list_for_each_entry(_entry_, _list_, _type_, _member_)

#define	qede_list_next_entry(_entry_, _type_, _member_) \
	qede_list_entry((_entry_)->_member_.next, _type_, _member_)

#define	qede_list_for_each_entry_safe(_entry_, _tmp_, _head_, _type_, _member_) \
	for (_entry_ = qede_list_first_entry(_head_, _type_, _member_), \
	    _tmp_ = qede_list_next_entry(_entry_, _type_, _member_); \
	    &_entry_->_member_ != (_head_); \
	    _entry_ = _tmp_, _tmp_ = qede_list_next_entry(_tmp_, _type_, _member_))

#define	OSAL_LIST_FOR_EACH_ENTRY_SAFE(_entry_, _tmp_, _list_, \
		_member_, _type_) \
	qede_list_for_each_entry_safe(_entry_, _tmp_, _list_, _type_, \
	    _member_)

/*
 * PCI Access Related OSAL
 */
void qede_osal_pci_read_config_byte(struct ecore_dev *, u32, u8 *);
#define	OSAL_PCI_READ_CONFIG_BYTE(_edev_, _addr_, _dst_) \
	qede_osal_pci_read_config_byte(_edev_, _addr_, _dst_)
void qede_osal_pci_read_config_word(struct ecore_dev *, u32, u16 *);
#define	OSAL_PCI_READ_CONFIG_WORD(_edev_, _addr_, _dst_) \
	qede_osal_pci_read_config_word(_edev_, _addr_, _dst_)
void qede_osal_pci_read_config_dword(struct ecore_dev *, u32, u32 *);
#define	OSAL_PCI_READ_CONFIG_DWORD(_edev_, _addr_, _dst_) \
	qede_osal_pci_read_config_dword(_edev_, _addr_, _dst_)

int qede_osal_pci_find_ext_capab(struct ecore_dev *, u16);
#define	OSAL_PCI_FIND_EXT_CAPABILITY(_edev_, _pcie_id_) \
	qede_osal_pci_find_ext_capab(_edev_, _pcie_id_)

void qede_osal_pci_write_config_word(struct ecore_dev *, u32, u16);
#define OSAL_PCI_WRITE_CONFIG_WORD(ecore_dev, address, value)\
		qede_osal_pci_write_config_word(ecore_dev, address, value)

int qede_osal_pci_find_capability(struct ecore_dev *, u16);
#define OSAL_PCI_FIND_CAPABILITY(ecore_dev, pcie_id)\
	qede_osal_pci_find_capability(ecore_dev, pcie_id)
/*
 * TODO : Can this be turned into a macro ??
 */
u32 qede_osal_bar_size(struct ecore_dev *, u8);
#define	OSAL_BAR_SIZE(_edev_, _bar_id_) \
	(((bar_id) == 0)? 0x2000000: \
	 ((bar_id) == 1)? 0x800000: 0)

/*
 * Memory Barriers related OSAL
 */
/*
 * TODO :Need to examine the ecore code using this Mem./IO
 * barriers and find out whether they are needed on Solaris
 */
#define	OSAL_MMIOWB(x)	do {} while (0)
#define	OSAL_BARRIER(x)	do {} while (0)
#define	OSAL_SMP_RMB(x)	do {} while (0)
#define	OSAL_SMP_WMB(x)	do {} while (0)
#define	OSAL_RMB(x)	do {} while (0)
#define	OSAL_WMB(x)	do {} while (0)

/*
 * SR-IOV Related OSAL
 */
#if 0
enum _ecore_status_t qede_osal_iov_vf_acquire(struct ecore_hwfn *p_hwfn, int vf_id);
#define OSAL_IOV_VF_ACQUIRE(p_hwfn, vf_id)	qede_osal_iov_vf_acquire(p_hwfn, vf_id)
#define	OSAL_VF_SEND_MSG2PF()		OSAL_NULL	
#define	OSAL_VF_HANDLE_BULLETIN()	do {} while (0)
#define	OSAL_IOV_CHK_UCAST()	        OSAL_NULL	
#define	OSAL_IOV_GET_OS_TYPE		0
#define OSAL_IOV_VF_CLEANUP(p_hwfn,vf_id)
#define OSAL_IOV_VF_VPORT_UPDATE(p_hwfn, vfid, params, tlvs_accepted) (0)
#define OSAL_IOV_POST_START_VPORT(p_hwfn, vfid, vport_id, opaque_fid) {};



#define	OSAL_VF_FILL_ACQUIRE_RESC_REQ(p_hwfn, req, vf_sw_info)	{}
#define OSAL_VF_UPDATE_ACQUIRE_RESC_RESP(p_hwfn, res) (0)
#else
#define	OSAL_VF_SEND_MSG2PF()		OSAL_NULL	
#define OSAL_IOV_POST_START_VPORT(p_hwfn, vfid, vport_id, opaque_fid) {};
#define OSAL_IOV_CHK_UCAST(hwfn, vfid, params) (0)
#define OSAL_PF_VF_MSG(hwfn, vfid) (0)
#define OSAL_VF_FLR_UPDATE(hw_fn) {}
#define OSAL_IOV_VF_ACQUIRE(p_hwfn, vf_id) (0)
#define OSAL_IOV_VF_CLEANUP(p_hwfn,vf_id)
#define OSAL_IOV_VF_VPORT_UPDATE(p_hwfn, vfid, params, tlvs_accepted) (0)
#define OSAL_VF_FILL_ACQUIRE_RESC_REQ(p_hwfn, req, vf_sw_info) {};

#define OSAL_VF_UPDATE_ACQUIRE_RESC_RESP(p_hwfn, res) (0)

#define	OSAL_IOV_GET_OS_TYPE()	0

#endif
/*
 * Miscellaneous OSAL
 */
#define	OSAL_ASSERT(is_assert)		ASSERT(is_assert)

void qede_print(char *format, ...);
#define OSAL_WARN(is_warn, _fmt, ...) \
     	if(is_warn) { \
		do { \
	       		qede_print("!"_fmt, ##__VA_ARGS__); \
		} while (0); \
	}
unsigned long log2_align(unsigned long n);

/* TODO: Verify this helper */
#define	OSAL_ROUNDUP_POW_OF_TWO		log2_align	

u32 LOG2(u32);
#define	OSAL_LOG2	LOG2

/* Needed if ecore_roce.c is included */
#define	OSAL_NUM_ACTIVE_CPU()			(0)
#define	DIV_ROUND_UP(n, d)		(((n) + (d) - 1) / (d))
#define	ROUNDUP(x, y)			((((x) + ((y) - 1)) / (y)) * (y))


/*
 * @VB: Don't want to include sys/sysmacros.h just
 * for the offsetof macro
 */
#ifndef	OFFSETOF
#define	OFFSETOF(type, member)		((size_t) (&(((type *)0)->member)))
/*#define offsetof(type, member)          ((size_t) (&(((type *)0)->member)))*/
#endif

#ifndef offsetof
#define offsetof(type, member)          ((size_t) (&(((type *)0)->member)))
#endif

void qede_print(char *format, ...);
void qede_print_err(char *format, ...);

#define	PRINT(_dp_ctx, _fmt, ...) \
	do { \
		qede_print("!"_fmt, ##__VA_ARGS__); \
	} while (0);
#define	PRINT_ERR(_dp_ctx, _fmt, ...) \
	do { \
		qede_print_err("!"_fmt, ##__VA_ARGS__); \
	} while (0);

void qede_debug_before_pf_start(struct ecore_dev *edev, u8 id);
void qede_debug_after_pf_stop(void *cdev, u8 my_id);

#define OSAL_BEFORE_PF_START(ptr, id)	qede_debug_before_pf_start(ptr, id)
#define	OSAL_AFTER_PF_STOP(ptr, id)	qede_debug_after_pf_stop(ptr, id)

#define cpu_to_le32(val)	((val))
#define le32_to_cpu(val)	((val))
#define le16_to_cpu(val) 	((val))
#define cpu_to_le16(val) 	((val))
#define OSAL_BUILD_BUG_ON(cond) nothing
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_arr)	(sizeof(_arr) / sizeof((_arr)[0]))
#endif
#define BUILD_BUG_ON(cond)	nothing
#define true 1
#define false 0
#define OSAL_VF_CQE_COMPLETION(_dev_p, _cqe, _protocol) (0)
#define OSAL_INLINE inline
#define OSAL_SPRINTF qede_sprintf
#define OSAL_STRLEN strlen
#define OSAL_STRCPY strcpy
#define OSAL_STRNCPY strncpy
#define OSAL_PAGE_BITS  12
#define OSAL_PAGE_SIZE (1 << OSAL_PAGE_BITS)
#define OSAL_UNLIKELY
#define ARRAY_DECL static const

#define OSAL_BUILD_BUG_ON(cond) nothing

#define OSAL_MIN_T(type, __min1, __min2)        \
        ((type)(__min1) < (type)(__min2) ? (type)(__min1) : (type)(__min2))
#define OSAL_MAX_T(type, __max1, __max2)        \
        ((type)(__max1) > (type)(__max2) ? (type)(__max1) : (type)(__max2))

#define	OSAL_ARRAY_SIZE(arr)	ARRAY_SIZE(arr)

void OSAL_CRC8_POPULATE(u8 * cdu_crc8_table, u8 polynomial);

u8 OSAL_CRC8(u8 * cdu_crc8_table, u8 * data_to_crc, int data_to_crc_len, u8 init_value);

#define OSAL_CACHE_LINE_SIZE 64 
#define OSAL_NUM_CPUS()  (0) 

void OSAL_DPC_SYNC(struct ecore_hwfn *p_hwfn);
/*
 *  * TODO:  Need to implement
 *   * Call from the ecore to get the statististics of a protocol driver. Ecore client
 *    * need to populate the requested statistics. If the PF has more than one function,
 *     * driver should return the statistics sum of all the interfaces under the PF.
 *      */
#define OSAL_GET_PROTOCOL_STATS(_ecore_dev, _type, _stats) \
	;

/*
 *  * TODO:  Need to implement
 *   * Call from ecore to the upper layer driver to request IRQs for the slowpath
 *    * interrupts handling.
 *     */
#define OSAL_SLOWPATH_IRQ_REQ(p_hwfn) \
	(ECORE_SUCCESS)



//void OSAL_HW_ERROR_OCCURRED(struct ecore_hwfn *, enum ecore_hw_err_type);
/*#define OSAL_HW_ERROR_OCCURRED(p_hwfn, err) \
	qede_osal_hw_error_occurred(p_hwfn, err)
*/

#define	OSAL_HW_ERROR_OCCURRED(p_hwfn, err)	nothing

void qede_osal_poll_mode_dpc(struct ecore_hwfn *);
#define OSAL_POLL_MODE_DPC(p_hwfn) \
	qede_osal_poll_mode_dpc(p_hwfn)

int qede_osal_bitmap_weight(unsigned long *, uint32_t);
#define OSAL_BITMAP_WEIGHT(bitmap, nbits) \
	qede_osal_bitmap_weight(bitmap, nbits)

void qede_osal_mfw_tlv_req(struct ecore_hwfn *);
#define OSAL_MFW_TLV_REQ(p_hwfn) \
	qede_osal_mfw_tlv_req(p_hwfn)

u32 qede_osal_crc32(u32, u8 *, u64); 
#define OSAL_CRC32(crc, buf, length) \
        qede_osal_crc32(crc, buf, length)	

void qede_osal_hw_info_change(struct ecore_hwfn *, int);
#define OSAL_HW_INFO_CHANGE(p_hwfn, change) \
	qede_osal_hw_info_change(p_hwfn, change)


#endif /* _BCM_OSAL_H */
