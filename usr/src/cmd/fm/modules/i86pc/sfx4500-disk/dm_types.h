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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DM_TYPES_H
#define	_DM_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common types for the disk monitor
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	NSEC_PER_POLL_POSITION	250000000UL	/* 0.25 of a second */

typedef enum {
	HPS_UNKNOWN		= 0x0000,
	HPS_ABSENT		= 0x0001,
	HPS_PRESENT		= 0x0002,
	HPS_UNCONFIGURED	= 0x0003,
	HPS_CONFIGURED		= 0x0004,
	HPS_FAULTED		= 0x1000,	/* This state can be OR'ed in */
	HPS_REPAIRED		= 0x2000
} hotplug_state_t;

typedef struct {
	/*
	 * Each field is the size of the corresponding field in the scsi
	 * inquiry structure + 1 byte for the terminating NUL.
	 */
	char		manuf[9];	/* 8 characters */
	char		model[33];	/* 32 characters to fo ATA ident$ */
	char		rev[9];		/* 8 characters */
	/*
	 * SCSI Serial number is 12 bytes from the main INQUIRY
	 * page, but it may be longer in the Unit Serial Number
	 * VPD page, so save space for up to 20 bytes of it (ATA
	 * serial numbers may be up to 20-bytes long).
	 */
	char		serial[21];
	uint64_t	size_in_bytes;
} dm_fru_t;

#ifdef __cplusplus
}
#endif

#endif /* _DM_TYPES_H */
