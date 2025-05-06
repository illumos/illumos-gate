/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef __CXGBE_OSDEP_H
#define	__CXGBE_OSDEP_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/cmn_err.h>
#include <sys/pcie.h>
#include <sys/sysmacros.h>
#include <sys/inttypes.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/mutex.h>


#define	CH_DUMP_MBOX(adap, mbox, data_reg, size)	do {} while (0)

#define	PCI_VENDOR_ID		0x00
#define	PCI_DEVICE_ID		0x02

#define	PCI_BASE_ADDRESS_0	0x10
#define	PCI_BASE_ADDRESS_1	0x14
#define	PCI_BASE_ADDRESS_2	0x18
#define	PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)

#define	PCI_CAP_ID_EXP		PCI_CAP_ID_PCI_E
#define	PCI_EXP_DEVCTL		PCIE_DEVCTL
#define	PCI_EXP_DEVCTL_PAYLOAD	PCIE_DEVCTL_MAX_PAYLOAD_MASK
#define	PCI_EXP_DEVCTL_READRQ	PCIE_DEVCTL_MAX_READ_REQ_MASK
#define	PCI_EXP_LNKCTL		PCIE_LINKCTL
#define	PCI_EXP_LNKSTA		PCIE_LINKSTS
#define	PCI_EXP_LNKSTA_CLS	PCIE_LINKSTS_SPEED_MASK
#define	PCI_EXP_LNKSTA_NLW	PCIE_LINKSTS_NEG_WIDTH_MASK
#define	PCI_EXP_DEVCTL2		0x28

#define	PCI_VPD_ADDR	2
#define	PCI_VPD_ADDR_F	0x8000
#define	PCI_VPD_DATA	4

#define	__devinit
#define	DIV_ROUND_UP(x, y) howmany(x, y)

#define	udelay(x) drv_usecwait(x)
#define	msleep(x) delay(drv_usectohz(1000ULL * (x)))
#define	mdelay(x) drv_usecwait(1000UL * (x))

#define	le16_to_cpu(x) LE_16((uint16_t)(x))
#define	le32_to_cpu(x) LE_32((uint32_t)(x))
#define	le64_to_cpu(x) LE_64((uint64_t)(x))
#define	cpu_to_le16(x) LE_16((uint16_t)(x))
#define	cpu_to_le32(x) LE_32((uint32_t)(x))
#define	cpu_to_le64(x) LE_64((uint64_t)(x))
#define	be16_to_cpu(x) BE_16((uint16_t)(x))
#define	be32_to_cpu(x) BE_32((uint32_t)(x))
#define	be64_to_cpu(x) BE_64((uint64_t)(x))
#define	cpu_to_be16(x) BE_16((uint16_t)(x))
#define	cpu_to_be32(x) BE_32((uint32_t)(x))
#define	cpu_to_be64(x) BE_64((uint64_t)(x))
#define	swab32(x) BSWAP_32(x)

typedef uint8_t 	u8;
typedef uint16_t 	u16;
typedef uint32_t 	u32;
typedef uint64_t 	u64;

typedef uint8_t		__u8;
typedef uint16_t	__u16;
typedef uint32_t	__u32;
typedef uint64_t	__u64;
typedef uint8_t		__be8;
typedef uint16_t	__be16;
typedef uint32_t	__be32;
typedef uint64_t	__be64;

typedef uint32_t	__le32;

typedef int8_t		s8;
typedef int16_t		s16;
typedef int32_t		s32;
typedef int64_t		s64;

#if defined(__sparc)
#define	__BIG_ENDIAN_BITFIELD
#define	PAGE_SIZE 8192
#define	PAGE_SHIFT 13
#else
#define	__LITTLE_ENDIAN_BITFIELD
#define	PAGE_SIZE 4096
#define	PAGE_SHIFT 12
#endif

#define	ETH_ALEN		6

#define	isspace(x) ((x) == ' ' || (x) == '\t')

#ifdef _KERNEL

#define	t4_os_alloc(_size)	kmem_alloc(_size, KM_SLEEP)
#define	fls(x) ddi_fls(x)

static inline int
ilog2(long x)
{
	return (ddi_fls(x) - 1);
}

typedef kmutex_t t4_os_lock_t;

static inline void
t4_os_lock(t4_os_lock_t *lock)
{
	mutex_enter(lock);
}

static inline void
t4_os_unlock(t4_os_lock_t *lock)
{
	mutex_exit(lock);
}

/*
 * The common code reaches directly into the adapter flags, so we must conform
 * our prefix in order to meet its expectations.
 */
#define	FW_OK	TAF_FW_OK

#endif /* _KERNEL */

#endif /* __CXGBE_OSDEP_H */
