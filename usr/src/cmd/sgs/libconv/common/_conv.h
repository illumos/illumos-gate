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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__CONV_DOT_H
#define	__CONV_DOT_H

/*
 * Local include file for conversion library.
 */
#include <conv.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some format strings differ depending on whether they are used for 32-bit
 * or 64-bit values.
 */
#if	defined(_ELF64)
#define	MSG_GBL_FMT_DEC		MSG_GBL_FMT_DEC_64
#define	MSG_GBL_FMT_DECS	MSG_GBL_FMT_DECS_64
#define	MSG_GBL_FMT_HEX		MSG_GBL_FMT_HEX_64
#define	MSG_GBL_FMT_HEXS	MSG_GBL_FMT_HEXS_64

#define	MSG_SYM_FMT_VAL		MSG_SYM_FMT_VAL_64
#else
#define	MSG_GBL_FMT_DEC		MSG_GBL_FMT_DEC_32
#define	MSG_GBL_FMT_DECS	MSG_GBL_FMT_DECS_32
#define	MSG_GBL_FMT_HEX		MSG_GBL_FMT_HEX_32
#define	MSG_GBL_FMT_HEXS	MSG_GBL_FMT_HEXS_32

#define	MSG_SYM_FMT_VAL		MSG_SYM_FMT_VAL_32
#endif


/*
 * There are routines in libconv that are built once for each ELFCLASS
 * because they are formatting Xword values. However, all ELF constants
 * lie in 32-bit ranges, due to the need be usable for ELFCLASS32. Hence,
 * the value of the ELFCLASS64 support here is purely to detect unexpected
 * garbage values above the 32-bit range.
 *
 * The CONV_XWORD_64TEST() macro tests the upper half of an ELFCLASS64 Xword,
 * and formats the value in hex if non-zero bits are seen. For ELFCLASS32,
 * it is a no-op.
 */
#ifdef _ELF64
#define	CONV_XWORD_64TEST(_value, _fmt_flags, _inv_buf) \
	if (_value & 0xffffffff00000000) \
	    return (conv_invalid_val(_inv_buf, _value, _fmt_flags))
#else
#define	CONV_XWORD_64TEST(_value, _fmt_flags, _inv_buf)
#endif


/* # of elements in an array */
#define	ARRAY_NELTS(arr) (sizeof (arr) / sizeof (*arr))

/*
 * Functions intended for use inter-file, within libconv only
 */
extern	const conv_ds_t	**conv_cap_tag_strings(Conv_fmt_flags_t);
extern	const Val_desc	*conv_dyn_feature1_strings(Conv_fmt_flags_t);
extern	const Val_desc	*conv_dyn_flag_strings(Conv_fmt_flags_t);
extern	const Val_desc	*conv_dyn_flag1_strings(Conv_fmt_flags_t);
extern	const Val_desc	*conv_dyn_posflag1_strings(Conv_fmt_flags_t);
extern	const conv_ds_t	**conv_dyn_tag_strings(conv_iter_osabi_t, Half,
			    Conv_fmt_flags_t);
extern	const Val_desc2	*conv_sec_flags_strings(Conv_fmt_flags_t);


#ifdef	__cplusplus
}
#endif

#endif	/* __CONV_DOT_H */
