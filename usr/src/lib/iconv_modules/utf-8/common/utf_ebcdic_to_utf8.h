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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */


#ifndef	UTF_EBCDIC_TO_UTF8_H
#define	UTF_EBCDIC_TO_UTF8_H


#include "common_defs.h"


static 	unsigned int utf_ebcdic_to_i8[0x100] = {

#include "txt_ebcdic_utf/utf_ebcdic_to_i8.txt"

};


/*
 * shadow flag defined in specification.
 */
static 	signed char number_of_bytes_in_utf_ebcidc[0x100] = {

#include "txt_ebcdic_utf/shadow.txt"

};
#define UTF_EBCDIC_LEAD_OCTET_MAX 7
#define UTF_EBCDIC_LEAD_OCTET_MIN 0 /* Control Character */
#define UTF_EBCDIC_TRAILING_OCTET 9


/*
 * Following is a vector of bit-masks to get used bits in the first byte of
 * a UTF-EBCDIC character.  Index is 0 for control character or the number
 * of bytes in the UTF-EBCDIC character.
 * and the index value comes from above table.
 */
static const uchar_t utf_ebcdic_masks_tbl[UTF_EBCDIC_LEAD_OCTET_MAX+1] =
	{ 0xff, 0xff, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x01};
/*	     0     1     2     3     4     5     6     7	*/

#define	UTF_EBCDIC_BIT_SHIFT		5
#define	UTF_EBCDIC_BIT_MASK		0x1f


#endif	/* UTF_EBCDIC_TO_UTF8_H */
