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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_TARGETS_SCSA1394_SBP2_H
#define	_SYS_1394_TARGETS_SCSA1394_SBP2_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SCSI command and status encapsulation in SBP-2
 *
 * References are to ANSI NCITS 325-1998 unless specified otherwise
 */

#include <sys/sbp2/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* SCSI command block ORB (ref: B.1) */
typedef struct scsa1394_cmd_orb {
	sbp2_orbp_t	co_next_orb;	/* next ORB pointer */
	uint32_t	co_data_descr[2]; /* data descriptor */
	uint16_t	co_params;	/* parameters */
	uint16_t	co_data_size;	/* parameters */
	uint8_t		co_cdb[12];	/* CDB */
} scsa1394_cmd_orb_t;


/* status block with SCSI sense data (ref: B.1) */
typedef struct scsa1394_status {
	uint8_t		st_param;	/* parameters */
	uint8_t		st_sbp_status;	/* SBP status */
	uint16_t	st_orb_offset_hi; /* ORB offset hi */
	uint32_t	st_orb_offset_lo; /* ORB offset lo */
	uint8_t		st_status;	/* SCSI status */
	uint8_t		st_sense_bits;	/* misc sense bits */
	uint8_t		st_sense_code;	/* sense code */
	uint8_t		st_sense_qual;	/* sense qualifier */
	uint8_t		st_info[4];	/* information bytes */
	uint8_t		st_cdb[4];	/* CDB-dependent */
	uint8_t		st_fru;		/* FRU code */
	uint8_t		st_sks[3];	/* sense_key-dependent */
	uint32_t	st_vendor[2];	/* vendor-dependent */
} scsa1394_status_t;

/* st_status */
#define	SCSA1394_ST_SFMT		0xC0	/* status block format */
#define	SCSA1394_ST_SFMT_SHIFT		6
#define	SCSA1394_ST_STATUS		0x3F	/* SCSI status */

/* status block formats */
#define	SCSA1394_ST_SFMT_CURRENT	0x00	/* current error */
#define	SCSA1394_ST_SFMT_DEFERRED	0x40	/* deferred error */
#define	SCSA1394_ST_SFMT_VENDOR		0xC0	/* vendor-dependent */

/* st_sense_bits */
#define	SCSA1394_ST_VALID		0x80	/* valid bit */
#define	SCSA1394_ST_VALID_SHIFT		7
#define	SCSA1394_ST_MARK		0x40	/* filemark */
#define	SCSA1394_ST_MARK_SHIFT		6
#define	SCSA1394_ST_EOM			0x20	/* EOM */
#define	SCSA1394_ST_EOM_SHIFT		5
#define	SCSA1394_ST_ILI			0x10	/* ILI */
#define	SCSA1394_ST_ILI_SHIFT		4
#define	SCSA1394_ST_SENSE_KEY		0x0F	/* sense key */

/* st_extra */
#define	SCSA1394_ST_FRU			0xFF000000 /* FRU */
#define	SCSA1394_ST_FRU_SHIFT		24
#define	SCSA1394_ST_SKEY_DEP		0x00FFFFFF /* sense key-dependent */
#define	SCSA1394_ST_SKEY_DEP_SHIFT	0

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_SCSA1394_SBP2_H */
