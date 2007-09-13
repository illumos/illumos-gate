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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MACHASI_H
#define	_SYS_MACHASI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Spitfire ancillary state registers, for asrset_t
 */
#define	ASR_GSR	(3)

/*
 * alternate address space identifiers
 *
 * 0x00 - 0x7F are privileged
 * 0x80 - 0xFF can be used by users
 */


/*
 * UltraSPARC ASIs
 */
#define	ASI_NQUAD_LD		0x24	/* 128-bit atomic load */
#define	ASI_NQUAD_LD_L		0x2c	/* 128-bit atomic load little */

#define	ASI_QUAD_LDD_PHYS	0x34	/* 128-bit physical atomic load */
#define	ASI_QUAD_LDD_PHYS_L	0x3C	/* 128-bit phys. atomic load little */

#define	ASI_INTR_DISPATCH_STATUS 0x48	/* interrupt vector dispatch status */
#define	ASI_INTR_RECEIVE_STATUS	0x49	/* interrupt vector receive status */

#define	ASI_SCRATCHPAD		0x4F	/* Scratchpad registers ASI */

#define	ASI_BLK_AIUP		0x70	/* block as if user primary */
#define	ASI_BLK_AIUS		0x71	/* block as if user secondary */

#define	ASI_SDB_INTR_W		0x77	/* interrupt vector dispatch */
#define	ASI_SDB_INTR_R		0x7F	/* incoming interrupt vector */
#define	ASI_INTR_DISPATCH	ASI_SDB_INTR_W
#define	ASI_INTR_RECEIVE	ASI_SDB_INTR_R

#define	ASI_BLK_AIUPL		0x78	/* block as if user primary little */
#define	ASI_BLK_AIUSL		0x79	/* block as if user secondary little */

/*
 * Spitfire asis
 */
#define	ASI_LSU			0x45	/* load-store unit control */
#define	ASI_DC_INVAL		0x42	/* d$ invalidate */


#define	ASI_DC_DATA		0x46	/* d$ data */
#define	ASI_DC_TAG		0x47	/* d$ tag */

#define	ASI_UPA_CONFIG		0x4A	/* upa configuration reg */

#define	ASI_ESTATE_ERR		0x4B	/* estate error enable reg */

#define	ASI_AFSR		0x4C	/* asynchronous fault status */
#define	ASI_AFAR		0x4D	/* asynchronous fault address */

#define	ASI_IMMU		0x50	/* instruction mmu */
#define	ASI_IMMU_TSB_8K		0x51	/* immu tsb 8k ptr */
#define	ASI_IMMU_TSB_64K	0x52	/* immu tsb 64k ptr */
#define	ASI_DEVICE_SERIAL_ID	0x53	/* device serial id */
#define	ASI_ITLB_IN		0x54	/* immu tlb data in */
#define	ASI_ITLB_ACCESS		0x55	/* immu tlb data access */
#define	ASI_ITLB_TAGREAD	0x56	/* immu tlb tag read */
#define	ASI_ITLB_DEMAP		0x57	/* immu tlb demap */

#define	ASI_DMMU		0x58	/* data mmu */
#define	ASI_MMU_CTX		ASI_DMMU
#define	ASI_DMMU_TSB_8K		0x59	/* dmmu tsb 8k ptr */
#define	ASI_DMMU_TSB_64K	0x5A	/* dmmu tsb 64k ptr */
#define	ASI_DMMU_TSB_DIRECT	0x5B	/* dmmu tsb direct ptr */
#define	ASI_DTLB_IN		0x5C	/* dmmu tlb data in */
#define	ASI_DTLB_ACCESS		0x5D	/* dmmu tlb data access */
#define	ASI_DTLB_TAGREAD	0x5E	/* dmmu tlb tag read */
#define	ASI_DTLB_DEMAP		0x5F	/* dmmu tlb demap */
#define	ASI_ITSB_PREFETCH	0x61	/* IMMU tsb prefetch */
#define	ASI_DTSB_PREFETCH	0x62	/* DMMU tsb prefetch */

#define	ASI_IC_DATA		0x66	/* i$ data */
#define	ASI_IC_TAG		0x67	/* i$ tag */
#define	ASI_IC_DECODE		0x6E	/* i$ pre-decode */
#define	ASI_IC_NEXT		0x6F	/* i$ next field */

#define	ASI_EC_W		0x76	/* e$ access write */
#define	ASI_EC_R		0x7E	/* e$ access read */
#define	ASI_EC_DIAG		0x4E	/* e$ diagnostic reg */
					/* PRM calls this ASI_ECACHE_TAG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHASI_H */
