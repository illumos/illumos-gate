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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SATA_SATL_H
#define	_SATA_SATL_H

#include <sys/scsi/impl/spc3_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions and declarations
 * ANSI SCSI / ATA Translation - 2 (SAT-2) specification
 */

/*
 * SATL ATA Pass Through PROTOCOL field values
 */
#define	SATL_APT_P_HW_RESET		0	/* ATA hardware reset */
#define	SATL_APT_P_SRST			0x1	/* Software reset */
#define	SATL_APT_P_NON_DATA		0x3	/* Non-data */
#define	SATL_APT_P_PIO_DATA_IN		0x4	/* PIO Data-in */
#define	SATL_APT_P_PIO_DATA_OUT		0x5	/* PIO Data-out */
#define	SATL_APT_P_DMA			0x6	/* DMA */
#define	SATL_APT_P_DMA_QUEUED		0x7	/* DMA Queued */
#define	SATL_APT_P_DEV_DIAG		0x8	/* Device Diagnostics */
#define	SATL_APT_P_DEV_RESET		0x9	/* Device Reset */
#define	SATL_APT_P_UDMA_IN		0xa	/* UDMA Data In */
#define	SATL_APT_P_UDMA_OUT		0xb	/* UDMA Data Out */
#define	SATL_APT_P_FPDMA		0xc	/* FPDMA */
#define	SATL_APT_P_RET_RESP		0xf	/* Return Response Info */

/*
 * SATL ATA Pass Through bit masks
 */
#define	SATL_APT_BM_EXTEND		0x01
#define	SATL_APT_BM_CK_COND		0x20
#define	SATL_APT_BM_T_DIR		0x08
#define	SATL_APT_BM_BYTE_BLOCK		0x04

#ifdef __cplusplus
}
#endif

#endif	/* _SATA_SATL_H */
