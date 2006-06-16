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

#ifndef	_OPL_DIMM_H
#define	_OPL_DIMM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef __cplusplus
extern "C" {
#endif

#define	OPL_DIMM_INFO_VERSION	1	/* Version number */
#define	OPL_MAX_DIMMS		32	/* Max dimms per board */

typedef struct board_dimm_info {
	uint8_t	bd_version;		/* Version of this structure */
	uint8_t bd_boardnum;		/* Board Number */
	uint8_t bd_numdimms;		/* Number of dimms attached */
	uint8_t	bd_dnamesz;		/* DIMM name size */
	uint8_t	bd_serialsz;		/* Serial number size */
	uint8_t	bd_partnumsz;		/* Partnumber size */
	/*
	 * DIMM info for each dimm(0 - bd_numdimms) is appended
	 * to this structure in the form similar to below:
	 *
	 * char name[bd_dnamesz];
	 * char serial[bd_serialsz];
	 * char partnum[bd_partnumsz];
	 */
} board_dimm_info_t;

#ifdef __cplusplus
}
#endif

#endif /* _OPL_DIMM_H */
