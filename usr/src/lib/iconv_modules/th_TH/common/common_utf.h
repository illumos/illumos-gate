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



#ifndef	_COMMON_UTF_H_
#define	_COMMON_UTF_H_

#include "common_thai.h"

#define UTF_UDC_ERROR	0xFFFF		/* if occur error during UDC conversion */
					/* the code value will be filled by this */

#define IDX_UDC_ERROR	-1		/* if occur error during getting UDC index */
					/* the code value will be filled by this */

#define UNICODE_JAMO_START	0x1100	/* HANGUL JAMO code Area in Unicode 2.0 */
#define UNICODE_JAMO_END	0x11F9

#define UNICODE_CMPJAMO_START	0x3131	/* HANGUL Compatibility JAMO code Area */
#define UNICODE_CMPJAMO_END	0x318E  /* in Unicode 2.0 */

#define UNICODE_HANGUL_START	0xAC00	/* HANGUL code Area in Unicode 2.0 */
#define UNICODE_HANGUL_END	0xD7A3

extern hcode_type _uni_to_utf8(hcode_type unicode);
extern hcode_type _utf8_to_uni(hcode_type utf8code);

extern hcode_type _udcidx_to_utf(int udcidx);
	/*  Return UTF-8 code from given User Defined Character Index(Serial Number) */

extern int _utf_to_udcidx(hcode_type utf_code);
	/*  Return User Defined Character Index(Serial Number) from given UTF-8 code */

#endif	/* _COMMON_UTF_H_ */
