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

#ifndef _SYS_NXGE_NXGE_CRC_H
#define	_SYS_NXGE_NXGE_CRC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

void nxge_crc32c_init(void);
uint32_t nxge_crc32c(uint32_t, const uint8_t *, int);

void nxge_crc_ccitt_init(void);
uint16_t nxge_crc_ccitt(uint16_t, const uint8_t *, int);

uint32_t nxge_compute_h1_table1(uint32_t, uint32_t *, uint32_t);
uint32_t nxge_compute_h1_table4(uint32_t, uint32_t *, uint32_t);
uint32_t nxge_compute_h1_serial(uint32_t crcin, uint32_t *, uint32_t);

#define	nxge_compute_h2(cin, flow, len)			\
	nxge_crc_ccitt(cin, flow, len)

void nxge_init_h1_table(void);

#define	nxge_compute_h1(cin, flow, len)			\
	nxge_compute_h1_table4(cin, flow, len)


#ifdef __cplusplus
}
#endif

#endif /* _SYS_NXGE_NXGE_CRC_H */
