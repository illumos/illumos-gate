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
 * Copyright (c) 1996, by Sun MicroSystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DADA_IMPL_SERVICES_H
#define	_SYS_DADA_IMPL_SERVICES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#ifdef	__STDC__

#ifdef NOT_NEEDED
extern int dcd_poll(struct dcd_pkt *);
#endif

#else
extern int dcd_poll();
#endif


#define	DCD_DEBUG	0xDEB00000

#define	DCD_ERR_ALL		0
#define	DCD_ERR_UNKONOW		1
#define	DCD_ERR_INFO		2
#define	DCD_ERR_RECOVERED	3
#define	DCD_ERR_RETRYABLE	4
#define	DCD_ERR_FATAL		5
#define	DCD_ERR_NONE		6


/*
 * Common Capability strings array
 */

#define	DCD_CAP_DMA_MAX		0
#define	DCD_CAP_ULTRA_ATA	1
#define	DCD_CAP_BUS_MASTER	2
#define	DCD_CAP_OVERLAP		3
#define	DCD_CAP_PARITY		4
#define	DCD_CAP_SECTOR_SIZE	5
#define	DCD_CAP_TOTAL_SECTORS	6
#define	DCD_CAP_GEOMETRY	7
#define	DCD_CAP_BLOCKMODE	8
#define	DCD_CAP_BLOCKFACTOR	9
#define	DCD_CAP_DMA_SUPPORT	10
#define	DCD_CAP_PIO_SUPPORT	11
#define	DCD_CAP_LBA_ADDRESSING	12

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_IMPL_SERVICES_H */
