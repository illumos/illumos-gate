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

#ifndef _ISCII_COMMON_H_
#define _ISCII_COMMON_H_

#define ucs_t  unsigned long

#define uchar unsigned char

#define NUKTA      0
#define EXT        -1
#define HALANT     -2
#define DOUBLE_DANDA -3

#define ISC_INV    0xd9  /* Consonant Invisible */

#define ISC_halant 0xe8
#define ISC_nukta  0xe9
#define ISC_danda  0xea
#define ISC_atr    0xef  /* Attribute code */
#define ISC_ext    0xf0  /* Extension code */

#define UNI_DOUBLE_DANDA 0x0965

#define UNI_ZWNJ   0x200C /* Zero Width Non Joiner */
#define UNI_ZWJ    0x200D /* Zero Width Joiner */
#define UNI_INV    0x200E /* map INV to Unicode LRM, same as Apple implementation */

#define EXT_RANGE_BEGIN  0xA1
#define EXT_RANGE_END    0xEE
#define is_valid_ext_code(v)  ((v) >= EXT_RANGE_BEGIN && (v) <= EXT_RANGE_END)

typedef enum { DEV, BNG, GMK, GJR, ORI, TML, TLG, KND, MLM, NUM_ISCII } ISCII;

typedef struct _entry {
    uchar   iscii;
    ucs_t   ucs;
    int     count;
} Entry;


#endif
