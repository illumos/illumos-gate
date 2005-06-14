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
 * Copyright, 1991-1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	HANDLE_CONTINUATION
static char *hsfs_sig_tab[] = {
	SUSP_SP,
	SUSP_CE,
	SUSP_PD,
	SUSP_ST,
	SUSP_ER,
	RRIP_PX,
	RRIP_PN,
	RRIP_SL,
	RRIP_CL,
	RRIP_PL,
	RRIP_RE,
	RRIP_TF,
	RRIP_RR,
	RRIP_NM
};

static int	hsfs_num_sig = sizeof (hsfs_sig_tab) / sizeof (hsfs_sig_tab[0]);
#endif	/* HANDLE_CONTINUATION */

#define	HSFS_NUM_SIG	14

#define	SUSP_SP_IX	0
#define	SUSP_CE_IX	1
#define	SUSP_PD_IX	2
#define	SUSP_ST_IX	3
#define	SUSP_ER_IX	4

#define	RRIP_PX_IX	5
#define	RRIP_PN_IX	6
#define	RRIP_SL_IX	7
#define	RRIP_CL_IX	8
#define	RRIP_PL_IX	9
#define	RRIP_RE_IX	10
#define	RRIP_RF_IX	11
#define	RRIP_RR_IX	12
#define	RRIP_NM_IX	13
