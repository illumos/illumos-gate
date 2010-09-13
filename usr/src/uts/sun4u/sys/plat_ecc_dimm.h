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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PLAT_ECC_DIMM_H
#define	_SYS_PLAT_ECC_DIMM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/int_types.h>
#include <sys/cheetahregs.h>
#include <sys/cpuvar.h>
#include <sys/dditypes.h>
#include <sys/ddipropdefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/mc-us3.h>
#include <sys/plat_ecc_unum.h>

/*
 * DIMM Serial Ids support for Starcat and Serengeti platforms
 */

#define	PLAT_MAX_DIMM_SID_LEN		16
#define	PLAT_MAX_DIMMS_PER_BOARD	32

typedef char plat_dimm_sid_t[PLAT_MAX_DIMM_SID_LEN];

typedef struct plat_dimm_sid_request_data {
	plat_ecc_msg_hdr_t	pdsrd_header;
	uint8_t			pdsrd_board_num;  /* bd# of SIDs requested */
} plat_dimm_sid_request_data_t;

#define	pdsrd_major_version	pdsrd_header.emh_major_ver
#define	pdsrd_minor_version	pdsrd_header.emh_minor_ver
#define	pdsrd_msg_type		pdsrd_header.emh_msg_type
#define	pdsrd_msg_length	pdsrd_header.emh_msg_length

typedef struct plat_dimm_sid_board_data {
	plat_ecc_msg_hdr_t	pdsbd_header;
	uint32_t		pdsbd_errno;	/* set if SC failed request */
	uint8_t			pdsbd_board_num; /* bd where SIDs are located */
	uint8_t			pdsbd_pad1;
	uint16_t		pdsbd_pad2;
	uint32_t		pdsbd_valid_bitmap; /* map of SIDs returned */
	plat_dimm_sid_t		pdsbd_dimm_sids[PLAT_MAX_DIMMS_PER_BOARD];
} plat_dimm_sid_board_data_t;

#define	pdsbd_major_version	pdsbd_header.emh_major_ver
#define	pdsbd_minor_version	pdsbd_header.emh_minor_ver
#define	pdsbd_msg_type		pdsbd_header.emh_msg_type
#define	pdsbd_msg_length	pdsbd_header.emh_msg_length

#define	PLAT_ECC_DIMM_SID_VERSION_MAJOR	1
#define	PLAT_ECC_DIMM_SID_VERSION_MINOR	1

#define	PDSB_STATE_INVALID		0x0
#define	PDSB_STATE_STORE_IN_PROGRESS	0x1
#define	PDSB_STATE_STORED		0x2
#define	PDSB_STATE_FAILED_TO_STORE	0x3

/* DIMM serial id data for one board */
typedef struct plat_dimm_sid_board {
	kmutex_t	pdsb_lock;		/* protect data for this bd */
	uint8_t		pdsb_state;		/* current state of data */
	uint32_t	pdsb_valid_bitmap;	/* map of valid SIDs */
	plat_dimm_sid_t	pdsb_dimm_sids[PLAT_MAX_DIMMS_PER_BOARD]; /* SIDs */
} plat_dimm_sid_board_t;

extern int plat_request_mem_sids(int boardnum);
extern int plat_store_mem_sids(plat_dimm_sid_board_data_t *data);
extern int plat_discard_mem_sids(int boardnum);

extern plat_dimm_sid_board_t	domain_dimm_sids[];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PLAT_ECC_DIMM_H */
