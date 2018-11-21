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



#ifndef	_COMMON_EUC_H_
#define	_COMMON_EUC_H_

#include "common_thai.h"

#define EUC_UDC_SEG1		0xC9
#define EUC_UDC_SEG2		0xFE
#define EUC_UDC_OFFSET_START	0xA1
#define EUC_UDC_OFFSET_END	0xFE
#define EUC_UDC_SEG_GAP		(EUC_UDC_OFFSET_END - EUC_UDC_OFFSET_START + 1)

#endif	/* _COMMON_EUC_H_ */
