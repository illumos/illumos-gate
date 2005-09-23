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

#ifndef _CMD_MEMERR_ARCH_H
#define	_CMD_MEMERR_ARCH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header file for Niagara-specific registers
 */

/*
 * Bit masks for interrupt bits in L2 Error Status Register
 */

#define	NI_L2AFSR_MEU 	0x8000000000000000
#define	NI_L2AFSR_MEC	0x4000000000000000
#define	NI_L2AFSR_RW 	0x2000000000000000
#define	NI_L2AFSR_RSVD0	0x1000000000000000
#define	NI_L2AFSR_MODA	0x0800000000000000
#define	NI_L2AFSR_VCID	0x07C0000000000000
#define	NI_L2AFSR_LDAC	0x0020000000000000
#define	NI_L2AFSR_LDAU	0x0010000000000000
#define	NI_L2AFSR_LDWC	0x0008000000000000
#define	NI_L2AFSR_LDWU	0x0004000000000000
#define	NI_L2AFSR_LDRC	0x0002000000000000
#define	NI_L2AFSR_LDRU	0x0001000000000000
#define	NI_L2AFSR_LDSC	0x0000800000000000
#define	NI_L2AFSR_LDSU	0x0000400000000000
#define	NI_L2AFSR_LTC	0x0000200000000000
#define	NI_L2AFSR_LRU	0x0000100000000000
#define	NI_L2AFSR_LVU	0x0000080000000000
#define	NI_L2AFSR_DAC	0x0000040000000000
#define	NI_L2AFSR_DAU	0x0000020000000000
#define	NI_L2AFSR_DRC	0x0000010000000000
#define	NI_L2AFSR_DRU	0x0000008000000000
#define	NI_L2AFSR_DSC	0x0000004000000000
#define	NI_L2AFSR_DSU	0x0000002000000000
#define	NI_L2AFSR_VEC	0x0000001000000000
#define	NI_L2AFSR_VEU	0x0000000800000000
#define	NI_L2AFSR_RSVD1	0x0000000700000000
#define	NI_L2AFSR_SYND	0x00000000FFFFFFFF

/*
 * These bit masks are used to determine if another bit of higher priority
 * is set.  This tells us whether the reported syndrome and  address "belong"
 * to this ereport. If the error in hand is Pn, use Pn-1 to bitwise & with
 * the l2-afsr value.  If result is 0, then this ereport's afsr is valid.
 */
#define	NI_L2AFSR_P01	(NI_L2AFSR_LVU)
#define	NI_L2AFSR_P02	(NI_L2AFSR_P01 | NI_L2AFSR_LRU)
#define	NI_L2AFSR_P03	(NI_L2AFSR_P02 | NI_L2AFSR_LDAU | NI_L2AFSR_LDSU)
#define	NI_L2AFSR_P04	(NI_L2AFSR_P03 | NI_L2AFSR_LDWU)
#define	NI_L2AFSR_P05	(NI_L2AFSR_P04 | NI_L2AFSR_LDRU)
#define	NI_L2AFSR_P06	(NI_L2AFSR_P05 | NI_L2AFSR_DAU | NI_L2AFSR_DRU)
#define	NI_L2AFSR_P07	(NI_L2AFSR_P06 | NI_L2AFSR_LTC)
#define	NI_L2AFSR_P08	(NI_L2AFSR_P07 | NI_L2AFSR_LDAC | NI_L2AFSR_LDSC)
#define	NI_L2AFSR_P09	(NI_L2AFSR_P08 | NI_L2AFSR_LDWC)
#define	NI_L2AFSR_P10	(NI_L2AFSR_P09 | NI_L2AFSR_LDRC)
#define	NI_L2AFSR_P11	(NI_L2AFSR_P10 | NI_L2AFSR_DAC | NI_L2AFSR_DRC)


#define	NI_DMAFSR_MEU 	0x8000000000000000
#define	NI_DMAFSR_MEC	0x4000000000000000
#define	NI_DMAFSR_DAC 	0x2000000000000000
#define	NI_DMAFSR_DAU	0x1000000000000000
#define	NI_DMAFSR_DSC	0x0800000000000000
#define	NI_DMAFSR_DSU	0x0400000000000000
#define	NI_DMAFSR_DBU	0x0200000000000000
#define	NI_DMAFSR_RSVD	0x01FFFFFFFFFF0000
#define	NI_DMAFSR_SYND	0x000000000000FFFF

#define	NI_DMAFSR_P01	(NI_DMAFSR_DSU | NI_DMAFSR_DAU)

#define	NI_DRAM_POISON_SYND_FROM_LDWU		0x1118
#define	NI_L2_POISON_SYND_FROM_DAU		0x3

#ifdef __cplusplus
}
#endif

#endif /* _CMD_MEMERR_ARCH_H */
