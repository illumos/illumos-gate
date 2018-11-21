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

#ifndef _ISCII_GJR_H_
#define _ISCII_GJR_H_

#include "iscii-common.h"

Entry Gujarati_isc[] ={
    {0xA1, 0x0A81, 3},
    {0xA4, 0x0A85, 7},
    {0xAC, 0x0A8F, 2},
    {0xB0, 0x0A93, 2},
    {0xB3, 0x0B95, 20},
    {0xC8, 0x0AAA, 6},
    {0xCF, 0x0AB0, 1},
    {0xD4, 0x0AB5, 5},
    {ISC_INV, UNI_INV, 1},
    {0xDA, 0x0ABE, 5},
    {0xE1, 0x0AC7, 2},
    {0xE5, 0x0ACB, 2},
    {0xE8, 0x0ACD, 1},
    {0xF1, 0x0AE6, 10}
};

/*
Entry *Gujarati_uni = Gujarati_isc;
*/

Entry Gujarati_uni[] = {
    {0xA1, 0x0A81, 3},
    {0xA4, 0x0A85, 7},
    {0xAC, 0x0A8F, 2},
    {0xB0, 0x0A93, 2},
    {0xB3, 0x0B95, 20},
    {0xC8, 0x0AAA, 6},
    {0xCF, 0x0AB0, 1},
    {0xD4, 0x0AB5, 5},
    {0xDA, 0x0ABE, 5},
    {0xE1, 0x0AC7, 2},
    {0xE5, 0x0ACB, 2},
    {0xE8, 0x0ACD, 1},
    {0xF1, 0x0AE6, 10},
    {0xE8, UNI_ZWNJ, HALANT},
    {0xE9, UNI_ZWJ, HALANT},
    {ISC_INV, UNI_INV, 1}
};
#endif
