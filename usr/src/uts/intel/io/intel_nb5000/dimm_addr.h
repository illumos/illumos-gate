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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIMM_ADDR_H
#define	_DIMM_ADDR_H

#ifdef __cplusplus
extern "C" {
#endif

/* Map for memory address translation for each interleave */

struct rank_geometry {
	uint8_t row[16];	/* Address bit associated with row bit */
	uint8_t bank[3];	/* Address bit associated with bank bit */
	uint8_t col[13];	/* Address bit associated with column bit */
	uint8_t interleave[3];	/* Address bit associated with interleave bit */
};

struct dimm_geometry {
	uint8_t row_nbits;	/* number of row bits */
	uint8_t col_nbits;	/* number of column bits */
	uint8_t bank_nbits;	/* number of bank bits */
	uint8_t width;		/* width */
	struct rank_geometry rank_geometry[4];	/* for interleave 1,2,4,8 */
} dimm_data[1];

int dimm_types = sizeof (dimm_data) / sizeof (struct dimm_geometry);

#ifdef __cplusplus
}
#endif

#endif /* _DIMM_ADDR_H */
