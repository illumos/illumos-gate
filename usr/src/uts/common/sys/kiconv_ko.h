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

#ifndef _SYS_KICONV_KO_H
#define	_SYS_KICONV_KO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* Valid EUC-KR byte or not. */
#define	KICONV_KO_IS_EUCKR_BYTE(b)	((b) >= 0xA1 && (b) <= 0xFE)

/* Valid UHC byte or not. */
#define	KICONV_KO_IS_UHC_1st_BYTE(b)	((b) >= 0x81 && (b) <= 0xFE)
#define	KICONV_KO_IS_UHC_2nd_BYTE(b)					\
		    ((b) >= 0x41 && (b) <= 0x5A ||			\
		    (b) >= 0x61 && (b) <= 0x7A ||			\
		    (b) >= 0x81 && (b) <= 0xFE)

/* UDA range in EUC-KR: row 41 and 94 of KS C 5601-1987. */
#define	KICONV_KO_UDA_EUC_SEG1_START	(0xC9A1)
#define	KICONV_KO_UDA_EUC_SEG1_END	(0xC9FE)
#define	KICONV_KO_UDA_EUC_SEG2_START	(0xFEA1)
#define	KICONV_KO_UDA_EUC_SEG2_END	(0xFEFE)
#define	KICONV_KO_UDA_EUC_SEG1		(0xC9)
#define	KICONV_KO_UDA_EUC_SEG2		(0xFE)
#define	KICONV_KO_UDA_OFFSET_START	(0xA1)
#define	KICONV_KO_UDA_OFFSET_END	(0xFE)
#define	KICONV_KO_UDA_RANGE		(0x5E)		/* 0xFE - 0xA1 + 1 */
#define	KICONV_KO_UDA_OFFSET_1		(0xF65F)	/* 0xF700 - 0xA1 */
#define	KICONV_KO_UDA_OFFSET_2		(0xF6BD)	/* 0xF65F + 0x5E */

/* EUC-KR UDA range in Unicode. */
#define	KICONV_KO_UDA_UCS4_START	(0xF700)
#define	KICONV_KO_UDA_UCS4_END		(0xF7BB)
#define	KICONV_KO_UDA_UTF8_START	(0xEF9C80)
#define	KICONV_KO_UDA_UTF8_END		(0xEF9EBB)

/* Whether EUC character is UDC or not. */
#define	KICONV_KO_IS_UDC_IN_EUC(v)				\
	    (((v) >= KICONV_KO_UDA_EUC_SEG1_START &&		\
	    (v) <= KICONV_KO_UDA_EUC_SEG1_END) ||		\
	    ((v) >= KICONV_KO_UDA_EUC_SEG2_START &&		\
	    (v) <= KICONV_KO_UDA_EUC_SEG2_END))

/* Whether UTF-8 character is UDC or not. */
#define	KICONV_KO_IS_UDC_IN_UTF8(v)				\
	    ((v) >= KICONV_KO_UDA_UTF8_START &&			\
	    (v) <= KICONV_KO_UDA_UTF8_END)

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KICONV_KO_H */
