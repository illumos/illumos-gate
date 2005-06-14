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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SAFARI_PCD_H
#define	_SYS_SAFARI_PCD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions of the structure spcd_t, Port Configuration
 * Descriptor, which is part of the information handed off to OBP and
 * the OS by POST in the "golden" I/O SRAM.
 * It is very similar in function to, and borrows heavily from, the spd
 */

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_BANKS_PER_PORT	4	/* Physical and Logical */
#define	MAX_DIMMS_PER_PORT	8
#define	IOBUS_PER_PORT		2
#define	IOCARD_PER_BUS		4
#define	LINKS_PER_PORT		5
#define	UPADEV_PER_PORT		2
#define	AGENTS_PER_PORT		2

#define	PCD_VERSION 1
#define	PCD_MAGIC ('P'<<24 |'C'<<16 |'D'<<8 | 0)


	/* Types of Safari ports */
#define	SAFPTYPE_NULL	0
#define	SAFPTYPE_CPU	1
#define	SAFPTYPE_sPCI	2
#define	SAFPTYPE_cPCI	3
#define	SAFPTYPE_WCI	4
#define	SAFPTYPE_PCIX	5

	/*
	 * RSV stands for Resource Status Value.
	 * These are the values used in all cases where the status of
	 * a resource is maintained in a byte element of a structure.
	 * These are ordered in terms of preserving interesting information
	 * in POST displays where all configurations are displayed in a
	 * single value.
	 */

typedef uint8_t	spcdrsv_t;

#define	SPCD_RSV_PASS	0x1		/* Passed some sort of test */
#define	SPCD_RSV_FAIL	0xff

typedef struct {
	uint32_t	spcd_magic;	/* PCD_MAGIC */
	uint8_t		spcd_version;	/* structure version: PCD_VERSION */
	uint64_t	spcd_ver_reg;	/* port version register */
	uint16_t	spcd_afreq;	/* actual operating frequency Mhz */

	uint8_t		spcd_ptype;	/* port type. See SAFPTYPE_ below */
	uint8_t		spcd_cache;	/* external cache size (MByte?) */
	spcdrsv_t	spcd_prsv;	/* The entire port status */
	spcdrsv_t	spcd_agent[AGENTS_PER_PORT];
	uint16_t	spcd_cpuid[AGENTS_PER_PORT];

		/* for ports with UPA device */
	spcdrsv_t	spcd_upadev[UPADEV_PER_PORT];

		/* for ports with IO buses */
	spcdrsv_t	spcd_iobus_rsv[IOBUS_PER_PORT];
		/* status of each IO card on port */
	spcdrsv_t	spcd_iocard_rsv[IOBUS_PER_PORT][IOCARD_PER_BUS];

		/* for ports with WIC links */
	spcdrsv_t	spcd_wic_links[LINKS_PER_PORT];
		/* status of each WIC link on port */

	uint32_t	memory_layout_size;	/* size of memory-layout */
	uint8_t		*memory_layout;		/* ptr to memory-layout data */

	char		*sprd_bank_rsv[MAX_BANKS_PER_PORT];
		/* status of each bank */
	char		*sprd_dimm[MAX_DIMMS_PER_PORT];
		/* status of each dimm */
	char		*sprd_ecache_dimm_label[MAX_DIMMS_PER_PORT];
		/* labels for ecache dimms */

} spcd_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SAFARI_PCD_H */
