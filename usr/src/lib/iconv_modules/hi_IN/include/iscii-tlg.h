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

#ifndef _ISCII_TLG_H_
#define _ISCII_TLG_H_

#include "iscii-common.h"

Entry Telugu_isc[] ={
    {0xA2, 0x0C02, 2},
    {0xA4, 0x0C05, 10},
    {0xAF, 0x0C12, 3},
    {0xB3, 0x0C15, 20},
    {0xC8, 0x0C2A, 6},
    {0xCF, 0x0C30, 4},
    {0xD4, 0x0C35, 5},
    {ISC_INV, UNI_INV, 1},
    {0xDA, 0x0C3E, 9},
    {0xE4, 0x0C4A, 3},
    {0xE8, 0x0C4D, 1},
    {0xF1, 0x0C66, 10}
};

/*
Entry *Telugu_uni = Telugu_isc;
*/
Entry Telugu_uni[] ={
    {0xA2, 0x0C02, 2},
    {0xA4, 0x0C05, 10},
    {0xAF, 0x0C12, 3},
    {0xB3, 0x0C15, 20},
    {0xC8, 0x0C2A, 6},
    {0xCF, 0x0C30, 4},
    {0xD4, 0x0C35, 5},
    {0xDA, 0x0C3E, 9},
    {0xE4, 0x0C4A, 3},
    {0xE8, 0x0C4D, 1},
    {0xF1, 0x0C66, 10},
    {0xE8, UNI_ZWNJ,HALANT},
    {0xE9, UNI_ZWJ, HALANT},
    {ISC_INV, UNI_INV, 1}
};


#endif
