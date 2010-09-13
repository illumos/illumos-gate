/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1998-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SCAT_ASICBRD_TYPES_H
#define	_SCAT_ASICBRD_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains enumerations of the board and asic types used
 * in Starcat.
 */

/*
 * POST DEVELOPERS:
 * This file is copied to the OS workspace, and thus must abide by the OS
 * coding standards.  This file must always pass cstyle and hdrchk.
 */

#ifdef __cplusplus
extern "C" {
#endif


	/* Enumeration of Starcat positional board types: */
typedef enum {
	XCBT_SYS0 = 0,		/* Full-slot system board, e.g., CPU */
	XCBT_SYS1 = 1,		/* Half-slot system board, e,g., I/O */
	XCBT_EXB = 2,		/* Expander board */
	XCBT_CSB = 3,		/* Centerplane support board */
	XCBT_CP = 4,		/* Half-centerplane */
	XCBT_SC = 5,		/* System controller */

	XCBT_COUNT		/* Size of array */
} xcbrdtype_t;
#define	IS_VALID_XCBT(xcbt) \
	((((int)(xcbt)) >= 0) && (((int)(xcbt)) < (int)XCBT_COUNT))

	/* Enumeration of Starcat L1 system board types */
typedef enum {
	XCL1BT_CPU,		/* Slot 0. Four CPUs, memory */
	XCL1BT_WIB,		/* Slot 0. Two CPUs & mem, two WCIs */
	XCL1BT_hPCI,		/* Slot 1. Two Schizos. "Hotplug PCI" */
	XCL1BT_cPCI,		/* Slot 1. Two Schizos. */
	XCL1BT_MAXCAT,		/* Slot 1. Two CPUs, no memory */
	XCL1BT_WIBPCI,		/* Slot 1, hybrid hPCI / WCI */
	XCL1BT_sPCI,		/* Slot 1. Two Schizos. "Standard PCI" */

	XCL1BT_COUNT
} xcl1bt_t;
#define	IS_VALID_XCL1BT(l1bt) \
	((((int)(l1bt)) >= 0) && (((int)(l1bt)) < (int)XCL1BT_COUNT))


	/*
	 * Arbitrarily chosen enumeration for the Starcat asics, so we
	 * can build some tables & bitmasks. Make sure any changes are
	 * reflected in the initialization of xc_asic_name[] in libxcpost.
	 */
typedef enum {
	XCASICT_AXQ,
	XCASICT_SDI,
	XCASICT_AMX,
	XCASICT_RMX,
	XCASICT_DARB,
	XCASICT_DMX,
	XCASICT_CSBCBR,		/* Mode of SDI CSB Console Bus Repeater */
	XCASICT_EXBCBR,		/* Mode of SDI EXB Console Bus Repeater */

	XCASICT_AR,
	XCASICT_DX,
	XCASICT_SDC,
	XCASICT_DCDS,
	XCASICT_L1EPLD,

	XCASICT_L1BBC,
	XCASICT_EXBBBC,
	XCASICT_CSBBBC,

	XCASICT_CPU,
	XCASICT_RIO,
	XCASICT_SCHIZO,
	XCASICT_WCI,

	XCASICT_CBH,
	XCASICT_SCM,

	XCASICT_COUNT	/* Size of array */
} xcasictype_t;
#define	IS_VALID_XCASICT(asict) \
	((((int)(asict)) >= 0) && (((int)(asict)) < (int)XCASICT_COUNT))

#ifdef __cplusplus
}
#endif

#endif	/* !_SCAT_ASICBRD_TYPES_H */
