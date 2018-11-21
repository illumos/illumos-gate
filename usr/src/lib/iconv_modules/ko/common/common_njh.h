/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 */



#ifndef	_COMMON_NJH_H_
#define	_COMMON_NJH_H_

#include "common_han.h"

#define NJH_UDC_SEG		0xD8
#define NJH_UDC_OFFSET1_START	0x31
#define NJH_UDC_OFFSET1_END	0x7E
#define NJH_UDC_OFFSET2_START	0x91
#define NJH_UDC_OFFSET2_END	0xFE
#define NJH_UDC_OFFSET_GAP	(NJH_UDC_OFFSET1_END - NJH_UDC_OFFSET1_START + 1)

#define NJH_HANGUL_END		0xD3FE	/* start Hanja or special symbol */

#endif	/* _COMMON_NJH_H_ */
