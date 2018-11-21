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
 * Copyright(c) 2001 Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _ISCII_MLM_H_
#define _ISCII_MLM_H_

#include "iscii-common.h"

Entry Malayalam_isc[] ={
    {0xA2, 0x0D02, 2},
    {0xA4, 0x0D05, 10},
    {0xAF, 0x0D12, 3},
    {0xB3, 0x0D15, 20},
    {0xC8, 0x0D2A, 6},
    {0xCF, 0x0D30, 10},
    {ISC_INV, UNI_INV, 1},
    {0xDA, 0x0D3E, 9},
    {0xE4, 0x0D4A, 3},
    {0xE8, 0x0D4D, 1},
    {0xF1, 0x0D66, 10}
};

/*
Entry *Malayalam_uni = Malayalam_isc;
*/
Entry Malayalam_uni[] ={
    {0xA2, 0x0D02, 2},
    {0xA4, 0x0D05, 10},
    {0xAF, 0x0D12, 3},
    {0xB3, 0x0D15, 20},
    {0xC8, 0x0D2A, 6},
    {0xCF, 0x0D30, 10},
    {0xDA, 0x0D3E, 9},
    {0xE4, 0x0D4A, 3},
    {0xE8, 0x0D4D, 1},
    {0xF1, 0x0D66, 10},
    {0xE8, UNI_ZWNJ,HALANT},
    {0xE9, UNI_ZWJ, HALANT},
    {ISC_INV, UNI_INV, 1}
};


#endif
