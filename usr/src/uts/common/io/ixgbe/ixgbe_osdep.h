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
 * Copyright(c) 2007-2010 Intel Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2016 OmniTI Computer Consulting, Inc. All rights reserved.
 */

#ifndef	_IXGBE_OSDEP_H
#define	_IXGBE_OSDEP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/byteorder.h>
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
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/atomic.h>
#include <sys/note.h>
#include "ixgbe_debug.h"

/* Cheesy hack for EWARN() */
#define	EWARN(H, W, S) cmn_err(CE_NOTE, W)

/* function declarations */
struct ixgbe_hw;
uint16_t ixgbe_read_pci_cfg(struct ixgbe_hw *, uint32_t);
void ixgbe_write_pci_cfg(struct ixgbe_hw *, uint32_t, uint32_t);
boolean_t ixgbe_removed(struct ixgbe_hw *);

#define	usec_delay(x)		drv_usecwait(x)
#define	msec_delay(x)		drv_usecwait(x * 1000)

#define	OS_DEP(hw)		((struct ixgbe_osdep *)((hw)->back))

#define	false		B_FALSE
#define	true		B_TRUE
#define	FALSE		B_FALSE
#define	TRUE		B_TRUE

#define	IXGBE_READ_PCIE_WORD 	ixgbe_read_pci_cfg
#define	IXGBE_WRITE_PCIE_WORD 	ixgbe_write_pci_cfg
#define	CMD_MEM_WRT_INVALIDATE	0x0010	/* BIT_4 */
#define	PCI_COMMAND_REGISTER	0x04
#define	PCI_EX_CONF_CAP		0xE0
#define	SPEED_10GB		10000
#define	SPEED_5GB		5000
#define	SPEED_2_5GB		2500
#define	SPEED_1GB		1000
#define	SPEED_100		100
#define	FULL_DUPLEX		2

#define	IXGBE_WRITE_FLUSH(a)	(void) IXGBE_READ_REG(a, IXGBE_STATUS)

#define	IXGBE_WRITE_REG(a, reg, value)	\
	ddi_put32((OS_DEP(a))->reg_handle, \
	    (uint32_t *)((uintptr_t)(a)->hw_addr + reg), (value))

#define	IXGBE_WRITE_REG_ARRAY(a, reg, index, value)	\
	IXGBE_WRITE_REG(a, ((reg) + ((index) << 2)), (value))

#define	IXGBE_READ_REG(a, reg)	\
	ddi_get32((OS_DEP(a))->reg_handle, \
	    (uint32_t *)((uintptr_t)(a)->hw_addr + reg))

#define	IXGBE_READ_REG_ARRAY(a, reg, index)	\
	IXGBE_READ_REG(a, ((reg) + ((index) << 2)))

#define	msec_delay_irq	msec_delay
#define	IXGBE_HTONL	htonl
#define	IXGBE_NTOHL	ntohl
#define	IXGBE_NTOHS	ntohs

#ifdef _BIG_ENDIAN
#define	IXGBE_CPU_TO_LE32	BSWAP_32
#define	IXGBE_LE32_TO_CPUS	BSWAP_32
#define	IXGBE_CPU_TO_BE16(x)	(x)
#define	IXGBE_CPU_TO_BE32(x)	(x)
#else
#define	IXGBE_CPU_TO_LE32(x)	(x)
#define	IXGBE_LE32_TO_CPUS(x)	(x)
#define	IXGBE_CPU_TO_BE16	BSWAP_16
#define	IXGBE_CPU_TO_BE32	BSWAP_32
#endif /* _BIG_ENDIAN */

#define	UNREFERENCED_PARAMETER(x)		_NOTE(ARGUNUSED(x))
#define	UNREFERENCED_1PARAMETER(_p)		UNREFERENCED_PARAMETER(_p)
#define	UNREFERENCED_2PARAMETER(_p, _q)		_NOTE(ARGUNUSED(_p, _q))
#define	UNREFERENCED_3PARAMETER(_p, _q, _r)	_NOTE(ARGUNUSED(_p, _q, _r))
#define	UNREFERENCED_4PARAMETER(_p, _q, _r, _s)	_NOTE(ARGUNUSED(_p, _q,_r, _s))


#define	IXGBE_REMOVED(hw) ixgbe_removed(hw)

typedef	int8_t		s8;
typedef	int16_t		s16;
typedef	int32_t		s32;
typedef	int64_t		s64;
typedef uint8_t		u8;
typedef	uint16_t 	u16;
typedef	uint32_t	u32;
typedef	uint64_t	u64;
typedef boolean_t	bool;

/* shared code requires this */
#define	__le16  u16
#define	__le32  u32
#define	__le64  u64
#define	__be16  u16
#define	__be32  u32
#define	__be64  u64

struct ixgbe_osdep {
	ddi_acc_handle_t reg_handle;
	ddi_acc_handle_t cfg_handle;
	struct ixgbe *ixgbe;
};

#ifdef __cplusplus
}
#endif

#endif	/* _IXGBE_OSDEP_H */
