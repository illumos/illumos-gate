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

#ifndef _MCAMD_DIMMCFG_H
#define	_MCAMD_DIMMCFG_H

#include <sys/types.h>
#include <sys/mc_amd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mcdcfg_csl mcdcfg_csl_t;
typedef struct mcdcfg_rslt mcdcfg_rslt_t;

/*
 * Chip-select line representation.
 */
struct mcdcfg_csl {
	uint8_t	csl_chan;	/* 0 = A, 1 = B */
	uint8_t	csl_slot;	/* dimm slot on channel, 0/1/2/3 (pair #) */
	uint8_t	csl_rank;	/* dimm rank in slot, 0/1/2/3 */
};

/*
 * Results structure for mdcfg_lookup
 */
struct mcdcfg_rslt {
	int	ldimm;			/* logical DIMM number */
	int	ndimm;			/* # of associated physical dimms */
	struct {
		int	toponum;		/* dimm instance in topology */
		const mcdcfg_csl_t *cslp;	/* chip-select parameters */
	} dimm[MC_CHIP_DIMMPERCS];	/* ndimm entries are valid */
};

/*
 * Chip-select line name maximum string length
 */
#define	MCDCFG_CSNAMELEN 32

extern int mcdcfg_lookup(uint32_t, int, int, int, uint32_t, int, int,
    mcdcfg_rslt_t *);
extern void mcdcfg_csname(uint32_t, const mcdcfg_csl_t *, char *, int);


#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_DIMMCFG_H */
