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

#ifndef	_SYS_NXGE_NXGE_ESPC_HW_H
#define	_SYS_NXGE_NXGE_ESPC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>

/* EPC / SPC Registers offsets */
#define	ESPC_PIO_EN_REG		0x040000
#define	ESPC_PIO_EN_MASK	0x0000000000000001ULL
#define	ESPC_PIO_STATUS_REG	0x040008

/* EPC Status Register */
#define	EPC_READ_INITIATE	(1ULL << 31)
#define	EPC_READ_COMPLETE	(1 << 30)
#define	EPC_WRITE_INITIATE	(1 << 29)
#define	EPC_WRITE_COMPLETE	(1 << 28)
#define	EPC_EEPROM_ADDR_BITS	0x3FFFF
#define	EPC_EEPROM_ADDR_SHIFT	8
#define	EPC_EEPROM_ADDR_MASK	(EPC_EEPROM_ADDR_BITS << EPC_EEPROM_ADDR_SHIFT)
#define	EPC_EEPROM_DATA_MASK	0xFF

#define	EPC_RW_WAIT		10	/* TBD */

#define	ESPC_NCR_REG		0x040020   /* Count 128, step 8 */
#define	ESPC_REG_ADDR(reg)	(FZC_PROM + (reg))

#define	ESPC_NCR_REGN(n)	((ESPC_REG_ADDR(ESPC_NCR_REG)) + n*8)
#define	ESPC_NCR_VAL_MASK	0x00000000FFFFFFFFULL

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_ESPC_HW_H */
