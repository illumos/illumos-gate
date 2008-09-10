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

#ifndef _MCAMD_DIMMCFG_IMPL_H
#define	_MCAMD_DIMMCFG_IMPL_H

#include <sys/types.h>
#include <sys/x86_archext.h>
#include <sys/mc_amd.h>
#include <mcamd_dimmcfg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defines for csl_chan
 */
#define	CH_A	0
#define	CH_B	1

/*
 * Line structure for the tables.  We include up to 2 chip-selects per
 * line - the consumer must use the first in 64-bit mode and both in
 * 128-bit mode.
 */
struct mcdcfg_csmapline {
	uint32_t csm_pkg;	/* applicable package types */
	uint8_t	csm_basereg;	/* csbase register number; implies mask */
	uint8_t csm_dimmcfg;	/* bitmask of DIMM_{N,R4,S4} which apply */
	uint8_t	csm_ldimm;	/* Logical DIMM number */
	const struct mcdcfg_csl csm_cs[MC_CHIP_DIMMPERCS];
};

/*
 * Defines for use with csm_pkg - pre-NPT packages
 */
#define	SKT_754		X86_SOCKET_754
#define	SKT_939		X86_SOCKET_939
#define	SKT_940		X86_SOCKET_940
#define	SKT_ALL		(X86_SOCKET_754 | X86_SOCKET_939 | X86_SOCKET_940)

/*
 * Defines for use with csm_pkg - NPT packages
 */
#define	F1207		X86_SOCKET_F1207
#define	AM2		X86_SOCKET_AM2
#define	S1g1		X86_SOCKET_S1g1
#define	SKT_NPT		(X86_SOCKET_S1g1 | X86_SOCKET_AM2 | X86_SOCKET_F1207)
#define	AM2F1207	(X86_SOCKET_AM2 | X86_SOCKET_F1207)
#define	AM2S1g1		(X86_SOCKET_AM2 | X86_SOCKET_S1g1)

/*
 * Defines for use with csm_dimmcfg
 */
#define	DCFG_N		0x1	/* Normal */
#define	DCFG_R4		0x2	/* Four-rank registered DIMM */
#define	DCFG_S4		0x4	/* four-rank SO-DIMM (NPT only) */
#define	DCFG_ALL	(DCFG_N | DCFG_R4)
#define	DCFG_ALLNPT	(DCFG_N | DCFG_R4 | DCFG_S4)

#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_DIMMCFG_IMPL_H */
