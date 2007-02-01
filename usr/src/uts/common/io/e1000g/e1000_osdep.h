/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#ifndef _E1000_OSDEP_H
#define	_E1000_OSDEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/*
 * === BEGIN CONTENT FORMERLY IN FXHW.H ===
 */
#define	DelayInMicroseconds(x)	drv_usecwait(x)
#define	DelayInMilliseconds(x)	drv_usecwait(x * 1000)
#define	usec_delay(x)		drv_usecwait(x)
#define	msec_delay(x)		drv_usecwait(x * 1000)

#ifdef e1000g_DEBUG
#define	DEBUGOUT(S)		cmn_err(CE_CONT, S)
#define	DEBUGOUT1(S, A)		cmn_err(CE_CONT, S, A)
#define	DEBUGOUT2(S, A, B)	cmn_err(CE_CONT, S, A, B)
#define	DEBUGOUT3(S, A, B, C)	cmn_err(CE_CONT, S, A, B, C)
#define	DEBUGOUT7(S, A, B, C, D, E, F, G)	\
				cmn_err(CE_CONT, S, A, B, C, D, E, F, G)
#else
#define	DEBUGOUT(S)
#define	DEBUGOUT1(S, A)
#define	DEBUGOUT2(S, A, B)
#define	DEBUGOUT3(S, A, B, C)
#define	DEBUGOUT7(S, A, B, C, D, E, F, G)
#endif

#define	DEBUGFUNC(F)		DEBUGOUT(F)

#define	IN
#define	OUT
#define	FALSE		0
#define	TRUE		1
#define	CMD_MEM_WRT_INVALIDATE	0x0010	/* BIT_4 */
#define	PCI_COMMAND_REGISTER	0x04

#define	E1000_WRITE_FLUSH(a)	/* NOOP */

#define	E1000_WRITE_REG(a, reg, value)	\
{\
	if ((a)->mac_type >= e1000_82543) \
		ddi_put32(((struct e1000g_osdep *)((a)->back))->E1000_handle, \
		    (uint32_t *)((a)->hw_addr + E1000_##reg), \
		    value); \
	else \
		ddi_put32(((struct e1000g_osdep *)((a)->back))->E1000_handle, \
		    (uint32_t *)((a)->hw_addr + E1000_82542_##reg), \
		    value); \
}

#define	E1000_READ_REG(a, reg) (\
	((a)->mac_type >= e1000_82543) ? \
	    ddi_get32(((struct e1000g_osdep *)(a)->back)->E1000_handle, \
		(uint32_t *)((a)->hw_addr + E1000_##reg)) : \
	    ddi_get32(((struct e1000g_osdep *)(a)->back)->E1000_handle, \
		(uint32_t *)((a)->hw_addr + E1000_82542_##reg)))

#define	E1000_WRITE_REG_ARRAY(a, reg, offset, value) \
{\
	if ((a)->mac_type >= e1000_82543) \
		ddi_put32(((struct e1000g_osdep *)((a)->back))->E1000_handle, \
		    (uint32_t *)((a)->hw_addr + E1000_##reg + ((offset) << 2)),\
		    value); \
	else \
		ddi_put32(((struct e1000g_osdep *)((a)->back))->E1000_handle, \
		    (uint32_t *)((a)->hw_addr + E1000_82542_##reg + \
		    ((offset) << 2)), value); \
}

#define	E1000_READ_REG_ARRAY(a, reg, offset) (\
	((a)->mac_type >= e1000_82543) ? \
	    ddi_get32(((struct e1000g_osdep *)(a)->back)->E1000_handle, \
		(uint32_t *)((a)->hw_addr + E1000_##reg + ((offset) << 2))) : \
	    ddi_get32(((struct e1000g_osdep *)(a)->back)->E1000_handle, \
		(uint32_t *)((a)->hw_addr + E1000_82542_##reg + \
		((offset) << 2))))


#define	E1000_WRITE_REG_ARRAY_BYTE(a, reg, offset, value)	NULL
#define	E1000_WRITE_REG_ARRAY_WORD(a, reg, offset, value)	NULL
#define	E1000_WRITE_REG_ARRAY_DWORD(a, reg, offset, value)	NULL
#define	E1000_READ_REG_ARRAY_BYTE(a, reg, offset)		NULL
#define	E1000_READ_REG_ARRAY_WORD(a, reg, offset)		NULL
#define	E1000_READ_REG_ARRAY_DWORD(a, reg, offset)		NULL


#define	ICH_FLASH_REG_SET	2	/* solaris mapping of flash memory */
#define	OS_DEP(hw)		((struct e1000g_osdep *)((hw)->back))

#define	E1000_READ_ICH_FLASH_REG(hw, reg)	\
	ddi_get32((OS_DEP(hw))->ich_flash_handle, \
		(uint32_t *)((OS_DEP(hw))->ich_flash_base + (reg)))

#define	E1000_READ_ICH_FLASH_REG16(hw, reg)	\
	ddi_get16((OS_DEP(hw))->ich_flash_handle, \
		(uint16_t *)((OS_DEP(hw))->ich_flash_base + (reg)))

#define	E1000_WRITE_ICH_FLASH_REG(hw, reg, value)	\
	ddi_put32((OS_DEP(hw))->ich_flash_handle, \
		(uint32_t *)((OS_DEP(hw))->ich_flash_base + (reg)), (value))

#define	E1000_WRITE_ICH_FLASH_REG16(hw, reg, value)	\
	ddi_put16((OS_DEP(hw))->ich_flash_handle, \
		(uint16_t *)((OS_DEP(hw))->ich_flash_base + (reg)), (value))

/*
 * The size of the receive buffers we allocate,
 */
#define	E1000_SIZE_OF_RECEIVE_BUFFERS	(2048)

/*
 * Use this define refer to the size of a recieve buffer plus its
 * align size
 */
#define	E1000_SIZE_OF_UNALIGNED_RECEIVE_BUFFERS	\
	E1000_SIZE_OF_RECEIVE_BUFFERS + RECEIVE_BUFFER_ALIGN_SIZE

/*
 * === END CONTENT FORMERLY IN FXHW.H ===
 */

#define	msec_delay_irq	msec_delay

typedef uint8_t		UCHAR;	/* 8-bit unsigned */
typedef UCHAR		UINT8;	/* 8-bit unsigned */
typedef uint16_t	USHORT;	/* 16-bit unsigned */
typedef uint16_t	UINT16;	/* 16-bit unsigned */
typedef uint32_t	ULONG;	/* 32-bit unsigned */
typedef uint32_t	UINT32;
typedef uint32_t	UINT;	/* 32-bit unsigned */
typedef UCHAR		BOOLEAN;
typedef UCHAR		*PUCHAR;
typedef UINT		*PUINT;
typedef ULONG		*PLONG;
typedef ULONG		NDIS_STATUS;
typedef USHORT		*PUSHORT;
typedef PUSHORT		PUINT16; /* 16-bit unsigned pointer */
typedef ULONG		E1000_32_BIT_PHYSICAL_ADDRESS,
	*PFX_32_BIT_PHYSICAL_ADDRESS;
typedef uint64_t	E1000_64_BIT_PHYSICAL_ADDRESS,
	*PFX_64_BIT_PHYSICAL_ADDRESS;

struct e1000g_osdep {
	ddi_acc_handle_t E1000_handle;
	ddi_acc_handle_t handle;
	/* flash access */
	ddi_acc_handle_t ich_flash_handle;
	caddr_t ich_flash_base;
	off_t ich_flash_size;
};

#ifdef __sparc	/* on SPARC, use only memory-mapped routines */

#define	E1000_READ_REG_IO	E1000_READ_REG
#define	E1000_WRITE_REG_IO	E1000_WRITE_REG

#else	/* on x86, use port io routines */

#define	E1000_READ_REG_IO(a, reg)	\
	e1000_read_reg_io((a), E1000_##reg)
#define	E1000_WRITE_REG_IO(a, reg, val)	\
	e1000_write_reg_io((a), E1000_##reg, val)

#endif	/* __sparc */

#ifdef __cplusplus
}
#endif

#endif	/* _E1000_OSDEP_H */
