/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#ifndef	_IXGBE_OSDEP_H
#define	_IXGBE_OSDEP_H

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
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/atomic.h>
#include <sys/note.h>
#include "ixgbe_debug.h"

/* function declarations */
struct ixgbe_hw;
uint16_t ixgbe_read_pci_cfg(struct ixgbe_hw *, uint32_t);


#define	usec_delay(x)		drv_usecwait(x)
#define	msec_delay(x)		drv_usecwait(x * 1000)

#ifdef IXGBE_DEBUG
#define	DEBUGOUT(S)		IXGBE_DEBUGLOG_0(NULL, S)
#define	DEBUGOUT1(S, A)		IXGBE_DEBUGLOG_1(NULL, S, A)
#define	DEBUGOUT2(S, A, B)	IXGBE_DEBUGLOG_2(NULL, S, A, B)
#define	DEBUGOUT3(S, A, B, C)	IXGBE_DEBUGLOG_3(NULL, S, A, B, C)
#define	DEBUGOUT6(S, A, B, C, D, E, F) \
    IXGBE_DEBUGLOG_6(NULL, S, A, B, C, D, E, F)
#define	DEBUGFUNC(F)		IXGBE_DEBUGLOG_1(NULL, "Entering %s", F)
#else
#define	DEBUGOUT(S)
#define	DEBUGOUT1(S, A)
#define	DEBUGOUT2(S, A, B)
#define	DEBUGOUT3(S, A, B, C)
#define	DEBUGOUT6(S, A, B, C, D, E, F)
#define	DEBUGFUNC(F)
#endif

#define	OS_DEP(hw)		((struct ixgbe_osdep *)((hw)->back))

#define	false		B_FALSE
#define	true		B_TRUE

#define	IXGBE_READ_PCIE_WORD 	ixgbe_read_pci_cfg
#define	CMD_MEM_WRT_INVALIDATE	0x0010	/* BIT_4 */
#define	PCI_COMMAND_REGISTER	0x04
#define	PCI_EX_CONF_CAP		0xE0
#define	MAX_NUM_UNICAST_ADDRESSES 0x10
#define	MAX_NUM_MULTICAST_ADDRESSES 0x1000
#define	SPEED_10GB		10000
#define	SPEED_1GB		1000
#define	SPEED_100		100
#define	FULL_DUPLEX		2

#define	IXGBE_WRITE_FLUSH(a)	(void) IXGBE_READ_REG(a, IXGBE_STATUS)

#define	IXGBE_WRITE_REG(a, reg, value)	\
	ddi_put32((OS_DEP(a))->reg_handle, \
	    (uint32_t *)((uintptr_t)(a)->hw_addr + reg), (value))

#define	IXGBE_READ_REG(a, reg)	\
	ddi_get32((OS_DEP(a))->reg_handle, \
	    (uint32_t *)((uintptr_t)(a)->hw_addr + reg))

#define	msec_delay_irq	msec_delay

#define	UNREFERENCED_PARAMETER(x)	_NOTE(ARGUNUSED(x))

typedef	int8_t		s8;
typedef	int16_t		s16;
typedef	int32_t		s32;
typedef	int64_t		s64;
typedef uint8_t		u8;
typedef	uint16_t 	u16;
typedef	uint32_t	u32;
typedef	uint64_t	u64;
typedef boolean_t	bool;

struct ixgbe_osdep {
	ddi_acc_handle_t reg_handle;
	ddi_acc_handle_t cfg_handle;
	struct ixgbe *ixgbe;
};

#ifdef __cplusplus
}
#endif

#endif	/* _IXGBE_OSDEP_H */
