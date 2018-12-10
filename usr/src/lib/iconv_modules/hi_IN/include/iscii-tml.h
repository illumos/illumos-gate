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

#ifndef _ISCII_TML_H_
#define _ISCII_TML_H_

#include "iscii-common.h"

Entry Tamil_isc[] ={
    {0xA3, 0x0B83, 1},
    {0xA4, 0x0B85, 6},
    {0xAB, 0x0B8E, 3},
    {0xAF, 0x0B92, 3},
    {0xB3, 0x0B95, 1},
    {0xB7, 0x0B99, 2},
    {0xBA, 0x0B9C, 1},
    {0xBC, 0x0B9E, 2},
    {0xC1, 0x0BA3, 2},
    {0xC8, 0x0BA8, 3},
    {0xCC, 0x0BAE, 2},
    {0xCF, 0x0BB0, 6},
    {0xD6, 0x0BB7, 3},
    {ISC_INV, UNI_INV, 1},
    {0xDA, 0x0BBE, 5},
    {0xE4, 0x0BCA, 3},
    {0xE8, 0x0BCD, 1},
    {0xF2, 0x0BE7, 9}
};

/*
Entry *Tamil_uni = Tamil_isc;
*/
Entry Tamil_uni[] ={
    {0xA3, 0x0B83, 1},
    {0xA4, 0x0B85, 6},
    {0xAB, 0x0B8E, 3},
    {0xAF, 0x0B92, 3},
    {0xB3, 0x0B95, 1},
    {0xB7, 0x0B99, 2},
    {0xBA, 0x0B9C, 1},
    {0xBC, 0x0B9E, 2},
    {0xC1, 0x0BA3, 2},
    {0xC8, 0x0BA8, 3},
    {0xCC, 0x0BAE, 2},
    {0xCF, 0x0BB0, 6},
    {0xD6, 0x0BB7, 3},
    {0xDA, 0x0BBE, 5},
    {0xE4, 0x0BCA, 3},
    {0xE8, 0x0BCD, 1},
    {0xF2, 0x0BE7, 9},
    {0xE8, UNI_ZWNJ,HALANT},
    {0xE9, UNI_ZWJ, HALANT},
    {ISC_INV, UNI_INV, 1}
};


#endif
