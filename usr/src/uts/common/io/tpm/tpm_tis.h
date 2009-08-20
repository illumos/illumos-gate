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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_TPM_TIS_H
#define	_TPM_TIS_H

/*
 * TPM Interface Specification Defaults
 * ICH7 spec (pg 253) says this is the base
 * TPM on LPC: FED40000-FED40FFF But this is only locality 0
 * It has to include 4 localities so the real range is FED40000-FED44FFF
 * (TIS 1.2 pg 27)
 */
#define	TIS_MEM_BASE	0xFED40000
#define	TIS_MEM_LEN    	0x5000

#define	TPM_LOCALITY_OFFSET(x)	((x) << 12)

/* Used to gain ownership */
#define	TPM_ACCESS		0x0000
/* Enable Interrupts */
#define	TPM_INT_ENABLE		0x0008
/* Interrupt vector (SIRQ values) */
#define	TPM_INT_VECTOR		0x000C
/* What caused interrupt */
#define	TPM_INT_STATUS		0x0010
/* Supported Interrupts */
#define	TPM_INTF_CAP		0x0014
/* Status Register */
#define	TPM_STS			0x0018
/* I/O FIFO */
#define	TPM_DATA_FIFO   	0x0024
/* Vendor and Device ID */
#define	TPM_DID_VID		0x0F00
/* Revision ID */
#define	TPM_RID			0x0F04

/* The number of all ordinals */
#define	TSC_ORDINAL_MAX		12
#define	TPM_ORDINAL_MAX		243
#define	TSC_ORDINAL_MASK	0x40000000

/* Timeouts (in milliseconds) (TIS v1.2 pg 43) */
#define	TPM_REQUEST_TIMEOUT	9000000		/* 9 seconds...too long? */
#define	TPM_POLLING_TIMEOUT	10000		/* 10 ms for polling */

enum tis_timeouts {
	TIS_TIMEOUT_A = 750000,
	TIS_TIMEOUT_B = 2000000,
	TIS_TIMEOUT_C = 750000,
	TIS_TIMEOUT_D = 750000
};

#define	TPM_DEFAULT_DURATION	750000

/* Possible TPM_ACCESS register bit values (TIS 1.2 pg.47-49) */
enum tis_access {
	TPM_ACCESS_VALID = 0x80,
	TPM_ACCESS_ACTIVE_LOCALITY = 0x20,
	TPM_ACCESS_REQUEST_PENDING = 0x04,
	TPM_ACCESS_REQUEST_USE = 0x02
};

/* Possible TPM_STS register values (TIS 1.2 pg.52-54) */
enum tis_status {
	/* bit 0 and bit 2 are reserved */
	TPM_STS_RESPONSE_RETRY	= 0x02, /* bit 1 */
	TPM_STS_DATA_EXPECT	= 0x08, /* bit 3 */
	TPM_STS_DATA_AVAIL	= 0x10, /* bit 4 */
	TPM_STS_GO		= 0x20, /* bit 5 */
	TPM_STS_CMD_READY	= 0x40, /* bit 6 */
	TPM_STS_VALID		= 0x80  /* bit 7 */
};

/* Possible TPM_INTF_CAPABILITY register values (TIS 1.2 pg.55) */
enum tis_intf_cap {
	TPM_INTF_BURST_COUNT_STATIC = 0x100,
	TPM_INTF_CMD_READY_INT = 0x080,
	TPM_INTF_INT_EDGE_FALLING = 0x040,
	TPM_INTF_INT_EDGE_RISING = 0x020,
	TPM_INTF_INT_LEVEL_LOW = 0x010,
	TPM_INTF_INT_LEVEL_HIGH = 0x008,
	TPM_INTF_INT_LOCALITY_CHANGE_INT = 0x004,
	TPM_INTF_INT_STS_VALID_INT = 0x002,
	TPM_INTF_INT_DATA_AVAIL_INT = 0x001
};

/* Possible TPM_INT_ENABLE register values (TIS 1.2 pg.62-63) */
/* Interrupt enable bit for TPM_INT_ENABLE_x register */
/* Too big to fit in enum... */
#define	TPM_INT_GLOBAL_EN	0x80000000
enum tis_int_enable {
	TPM_INT_CMD_RDY_EN = 0x80,
	TPM_INT_LOCAL_CHANGE_INT_EN = 0x04,
	TPM_INT_STS_VALID_EN = 0x02,
	TPM_INT_STS_DATA_AVAIL_EN = 0x01
};

#endif	/* _TPM_TIS_H */
