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
 *
 * eft.h -- public definitions for eft files
 *
 */

#ifndef	_ESC_COMMON_EFT_H
#define	_ESC_COMMON_EFT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>

/* eft file header */
#define	EFT_HDR_MAGIC	0x45465400
#define	EFT_HDR_MAJOR 3
#define	EFT_HDR_MINOR 1
#define	EFT_HDR_MAXCOMMENT 256
struct eftheader {
	uint32_t magic;
	uint16_t major;
	uint16_t minor;
	uint16_t cmajor;
	uint16_t cminor;
	uint32_t identlen;
	uint32_t dictlen;
	uint32_t unused[2];
	uint32_t csum;
	char comment[EFT_HDR_MAXCOMMENT];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_EFT_H */
