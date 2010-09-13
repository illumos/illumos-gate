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

#ifndef _SYS_KICONV_TC_H
#define	_SYS_KICONV_TC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* Valid first BIG5 byte or not. */
#define	KICONV_TC_IS_BIG5_1st_BYTE(v)	((v) >= 0x81 && (v) <= 0xFE)

/* Valid second BIG5 byte or not. */
#define	KICONV_TC_IS_BIG5_2nd_BYTE(v)				\
	    (((v) >= 0x40 && (v) <= 0x7E) || ((v) >= 0xA1 && (v) <= 0xFE))

/* Start byte of CNS 11643 plane 2 - plane 16. */
#define	KICONV_TC_EUCTW_MBYTE		(0x8E)

/* Plane number mask of CNS 11643 */
#define	KICONV_TC_EUCTW_PMASK		(0xA0)

/* Valid first byte of CNS 11643 1-16 plane character or not. */
#define	KICONV_TC_IS_EUCTW_1st_BYTE(v)				\
		((v) == KICONV_TC_EUCTW_MBYTE || KICONV_IS_VALID_EUC_BYTE(v))

/* Valid EUC-TW sequence or not. */
#define	KICONV_TC_IS_VALID_EUCTW_SEQ(ib)				\
	    ((isplane1 && (KICONV_IS_VALID_EUC_BYTE(*((ib) + 1)))) ||	\
	    (plane_no <= 16 && plane_no >= 2 && 			\
	    KICONV_IS_VALID_EUC_BYTE(*((ib) + 2)) &&			\
	    KICONV_IS_VALID_EUC_BYTE(*((ib) + 3))))

/*
 * Plane 12/13/14/16 of EUC-TW fall in UDA range [U+F0000, U+F8A0F] in
 * Unicode.
 */
#define	KICONV_TC_UDA_UCS4_START	(0xF0000)
#define	KICONV_TC_UDA_UTF8_START	(0xF3B08080)
#define	KICONV_TC_UDA_UTF8_END		(0xF3B8A88F)

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KICONV_TC_H */
