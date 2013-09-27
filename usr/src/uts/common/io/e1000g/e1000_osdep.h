/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#ifndef _E1000_OSDEP_H
#define	_E1000_OSDEP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/atomic.h>
#include <sys/note.h>
#include <sys/mutex.h>
#include <sys/pci_cap.h>
#include "e1000g_debug.h"

#define	usec_delay(x)		drv_usecwait(x)
#define	msec_delay(x)		drv_usecwait(x * 1000)
#define	msec_delay_irq		msec_delay

#ifdef E1000G_DEBUG
#define	DEBUGOUT(S)		\
	E1000G_DEBUGLOG_0(NULL, E1000G_INFO_LEVEL, S)
#define	DEBUGOUT1(S, A)		\
	E1000G_DEBUGLOG_1(NULL, E1000G_INFO_LEVEL, S, A)
#define	DEBUGOUT2(S, A, B)	\
	E1000G_DEBUGLOG_2(NULL, E1000G_INFO_LEVEL, S, A, B)
#define	DEBUGOUT3(S, A, B, C)	\
	E1000G_DEBUGLOG_3(NULL, E1000G_INFO_LEVEL, S, A, B, C)
#define	DEBUGFUNC(F)		\
	E1000G_DEBUGLOG_0(NULL, E1000G_TRACE_LEVEL, F)
#else
#define	DEBUGOUT(S)
#define	DEBUGOUT1(S, A)
#define	DEBUGOUT2(S, A, B)
#define	DEBUGOUT3(S, A, B, C)
#define	DEBUGFUNC(F)
#endif

#define	OS_DEP(hw)		((struct e1000g_osdep *)((hw)->back))

#define	false		0
#define	true		1
#define	FALSE		false
#define	TRUE		true

#define	CMD_MEM_WRT_INVALIDATE	0x0010	/* BIT_4 */
#define	PCI_COMMAND_REGISTER	0x04
#define	PCI_EX_CONF_CAP		0xE0
#define	ADAPTER_REG_SET		1 /* solaris mapping of adapter registers */
#define	ICH_FLASH_REG_SET	2	/* solaris mapping of flash memory */

#define	RECEIVE_BUFFER_ALIGN_SIZE	256
#define	E1000_MDALIGN			4096
#define	E1000_MDALIGN_82546		65536
#define	E1000_ERT_2048			0x100

/* PHY Extended Status Register */
#define	IEEE_ESR_1000T_HD_CAPS	0x1000	/* 1000T HD capable */
#define	IEEE_ESR_1000T_FD_CAPS	0x2000	/* 1000T FD capable */
#define	IEEE_ESR_1000X_HD_CAPS	0x4000	/* 1000X HD capable */
#define	IEEE_ESR_1000X_FD_CAPS	0x8000	/* 1000X FD capable */

/*
 * required by shared code
 */
#define	E1000_WRITE_FLUSH(a)	(void)E1000_READ_REG(a, E1000_STATUS)

#define	E1000_WRITE_REG(hw, reg, value)	\
{\
	if ((hw)->mac.type != e1000_82542) \
		ddi_put32((OS_DEP(hw))->reg_handle, \
		    (uint32_t *)((uintptr_t)(hw)->hw_addr + reg), \
		    value); \
	else \
		ddi_put32((OS_DEP(hw))->reg_handle, \
		    (uint32_t *)((uintptr_t)(hw)->hw_addr + \
		    e1000_translate_register_82542(reg)), \
		    value); \
}

#define	E1000_READ_REG(hw, reg) (\
	((hw)->mac.type != e1000_82542) ? \
	    ddi_get32((OS_DEP(hw))->reg_handle, \
		(uint32_t *)((uintptr_t)(hw)->hw_addr + reg)) : \
	    ddi_get32((OS_DEP(hw))->reg_handle, \
		(uint32_t *)((uintptr_t)(hw)->hw_addr + \
		e1000_translate_register_82542(reg))))

#define	E1000_WRITE_REG_ARRAY(hw, reg, offset, value) \
{\
	if ((hw)->mac.type != e1000_82542) \
		ddi_put32((OS_DEP(hw))->reg_handle, \
		    (uint32_t *)((uintptr_t)(hw)->hw_addr + \
		    reg + ((offset) << 2)),\
		    value); \
	else \
		ddi_put32((OS_DEP(hw))->reg_handle, \
		    (uint32_t *)((uintptr_t)(hw)->hw_addr + \
		    e1000_translate_register_82542(reg) + \
		    ((offset) << 2)), value); \
}

#define	E1000_READ_REG_ARRAY(hw, reg, offset) (\
	((hw)->mac.type != e1000_82542) ? \
	    ddi_get32((OS_DEP(hw))->reg_handle, \
		(uint32_t *)((uintptr_t)(hw)->hw_addr + reg + \
		((offset) << 2))) : \
	    ddi_get32((OS_DEP(hw))->reg_handle, \
		(uint32_t *)((uintptr_t)(hw)->hw_addr + \
		e1000_translate_register_82542(reg) + \
		((offset) << 2))))


#define	E1000_WRITE_REG_ARRAY_DWORD(a, reg, offset, value)	\
	E1000_WRITE_REG_ARRAY(a, reg, offset, value)
#define	E1000_READ_REG_ARRAY_DWORD(a, reg, offset)		\
	E1000_READ_REG_ARRAY(a, reg, offset)


#define	E1000_READ_FLASH_REG(hw, reg)	\
	ddi_get32((OS_DEP(hw))->ich_flash_handle, \
		(uint32_t *)((uintptr_t)(hw)->flash_address + (reg)))

#define	E1000_READ_FLASH_REG16(hw, reg)	\
	ddi_get16((OS_DEP(hw))->ich_flash_handle, \
		(uint16_t *)((uintptr_t)(hw)->flash_address + (reg)))

#define	E1000_WRITE_FLASH_REG(hw, reg, value)	\
	ddi_put32((OS_DEP(hw))->ich_flash_handle, \
		(uint32_t *)((uintptr_t)(hw)->flash_address + (reg)), (value))

#define	E1000_WRITE_FLASH_REG16(hw, reg, value)	\
	ddi_put16((OS_DEP(hw))->ich_flash_handle, \
		(uint16_t *)((uintptr_t)(hw)->flash_address + (reg)), (value))

#define	UNREFERENCED_1PARAMETER(_p)		_NOTE(ARGUNUSED(_p))
#define	UNREFERENCED_2PARAMETER(_p, _q)		_NOTE(ARGUNUSED(_p, _q))
#define	UNREFERENCED_3PARAMETER(_p, _q, _r)	_NOTE(ARGUNUSED(_p, _q, _r))
#define	UNREFERENCED_4PARAMETER(_p, _q, _r, _s)	_NOTE(ARGUNUSED(_p, _q, _r, _s))
#define	UNREFERENCED_5PARAMETER(_p, _q, _r, _s, _t)	\
	_NOTE(ARGUNUSED(_p, _q, _r, _s, _t))

typedef	int8_t		s8;
typedef	int16_t		s16;
typedef	int32_t		s32;
typedef	int64_t		s64;
typedef	uint8_t		u8;
typedef	uint16_t	u16;
typedef	uint32_t	u32;
typedef	uint64_t	u64;
typedef boolean_t	bool;

#define	__le16 u16
#define	__le32 u32
#define	__le64 u64

struct e1000g_osdep {
	ddi_acc_handle_t reg_handle;
	ddi_acc_handle_t cfg_handle;
	ddi_acc_handle_t ich_flash_handle;
	ddi_acc_handle_t io_reg_handle;
	struct e1000g *adapter;
};

/* Shared Code Mutex Defines */
#define	E1000_MUTEX			kmutex_t
#define	E1000_MUTEX_INIT(mutex)		mutex_init(mutex, NULL, \
	MUTEX_DRIVER, NULL)
#define	E1000_MUTEX_DESTROY(mutex)	mutex_destroy(mutex)

#define	E1000_MUTEX_LOCK(mutex)		mutex_enter(mutex)
#define	E1000_MUTEX_TRYLOCK(mutex)	mutex_tryenter(mutex)
#define	E1000_MUTEX_UNLOCK(mutex)	mutex_exit(mutex)

#ifdef __sparc	/* on SPARC, use only memory-mapped routines */
#define	E1000_WRITE_REG_IO	E1000_WRITE_REG
#else	/* on x86, use port io routines */
#define	E1000_WRITE_REG_IO(a, reg, val)	{ \
	ddi_put32((OS_DEP(a))->io_reg_handle, \
	    (uint32_t *)(a)->io_base, \
	    reg); \
	ddi_put32((OS_DEP(a))->io_reg_handle, \
	    (uint32_t *)((a)->io_base + 4), \
	    val); \
}
#endif	/* __sparc */

#ifdef __cplusplus
}
#endif

#endif	/* _E1000_OSDEP_H */
