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
 * Copyright (c) 1996, by Sun Microsystems Inc.
 * All rights resserved.
 */

#ifndef	_SYS_DADA_IMPL_STATUS_H
#define	_SYS_DADA_IMPL_STATUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following are the status bytes definition
 */

#define		STATUS_ATA_BUSY		0x80	/* Controller Busy */
#define		STATUS_ATA_DRDY		0x40	/* Drive Ready */
#define		STATUS_ATA_DWF		0x20	/* Write Fault */
#define		STATUS_ATA_DSC		0x10	/* Seek operation complete */
#define		STATUS_ATA_DRQ		0x08	/* Data Request */
#define		STATUS_ATA_CORR		0x04	/* ECC corection applied */
#define		STATUS_ATA_IDX		0x02	/* Disk revolution index */
#define		STATUS_ATA_ERR		0x01	/* Error Flag	*/
#define		STATUS_ATA_MASK		0x81	/* Mask for status byte */
#define		STATUS_GOOD		0x00	/* Good status */

/*
 * The following are the defines for the error register
 */

#define		ERR_AMNF		0x01	/* Address Mark not found */
#define		ERR_TKONF		0x02	/* Track 0 not found */
#define		ERR_ABORT		0x04	/* Aborted command 	*/
#define		ERR_IDNF		0x10	/* ID not found */
#define		ERR_MC			0x20	/* MEdia Change */
#define		ERR_UNC			0x40	/* Uncorrectable data error */
#define		ERR_BBK			0x80	/* Bad block detected */


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DADA_IMPL_STATUS_H */
