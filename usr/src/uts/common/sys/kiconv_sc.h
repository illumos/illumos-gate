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
 */

#ifndef _SYS_KICONV_SC_H
#define	_SYS_KICONV_SC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* Valid first byte of GB18030 character or not. */
#define	KICONV_SC_IS_GBK_1st_BYTE(c)		((c) >= 0x81 && (c) <= 0xfe)

/* Valid 2nd byte of 2 bytes GB18030 character or not. */
#define	KICONV_SC_IS_GBK_2nd_BYTE(c)					\
		(((c) >= 0x40 && (c) <= 0x7E) || ((c) >= 0x80 && (c) <= 0xFE))

/* Valid 2nd byte of 4 bytes GB18030 character or not. */
#define	KICONV_SC_IS_GB18030_2nd_BYTE(c)	((c) >= 0x30 && (c) <= 0x39)

/* Valid 3rd byte of 4 bytes GB18030 character or not. */
#define	KICONV_SC_IS_GB18030_3rd_BYTE(c)	((c) >= 0x81 && (c) <= 0xfe)

/* Valid 4th byte of 4 bytes GB18030 character or not. */
#define	KICONV_SC_IS_GB18030_4th_BYTE(c)			\
	    KICONV_SC_IS_GB18030_2nd_BYTE((c))

/* Get the number of bytes of one GB character(uint32_t). */
#define	KICONV_SC_GET_GB_LEN(v, l)				\
	    if (((v) & 0xFFFF0000) != 0)			\
		    (l) = 4;					\
	    else if (((v) & 0xFF00) != 0)			\
		    (l) = 2;					\
	    else						\
		    (l) = 1

/* Valid GB2312 byte or not. */
#define	KICONV_SC_IS_GB2312_BYTE(b)		((b) >= 0xA1 && (b) <= 0xFE)

/* UTF-8 value of Unicode Plane 1 start code point (U+10000). */
#define	KICONV_SC_PLANE1_UCS4_START		(0x10000)
#define	KICONV_SC_PLANE1_UTF8_START		(0xF0908080)

/* Start code point of GB18030 which maps to U+10000. */
#define	KICONV_SC_PLANE1_GB18030_START		(0x90308130)

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KICONV_SC_H */
