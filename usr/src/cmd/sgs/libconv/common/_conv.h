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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__CONV_DOT_H
#define	__CONV_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Map an integer into a descriptive string.
 *
 * entry:
 *	buf - A buffer into which this routine can format
 *		a result string, if necessary.
 *	bufsize - sizeof(buf)
 *	val - The value for which a string is desired.
 *	flags - CONV_FMT_* values, used to influence formatting of
 *		the resulting string.
 *	num_msg - # of Msg entries in msg, msg_altdump, and msg_altfile.
 *	msg - Array of num_msg Msg items corresponding to the possible
 *		strings corresponding to val.
 *	msg_altdump - NULL, or array of num_msg Msg items, to be used
 *		instead of msg when the CONV_FMT_ALTDUMP flag is set.
 *	msg_altfile - NULL, or array of num_msg Msg items, to be used
 *		instead of msg when the CONV_FMT_ALTFILE flag is set.
 *
 * exit:
 *	If val lies in the range [0-(num_msg-1)], then the string
 *	corresponding to it is returned:
 *		1) If CONV_FMT_ALTDUMP is set and msg_altdump is non-NULL,
 *			the string comes from msg_altdump.
 *		2) If CONV_FMT_ALTFILE is set and msg_altfile is non-NULL,
 *			the string comes from msg_altfile.
 *		3) If neither of the previous rules holds, the string
 *			comes from msg.
 *	if val is outside the range, an ASCII representation of it is
 *	formatted into string, and that is returned.
 *
 * note:
 *	Ideally, this would be a function defined in globals.c.
 *	However, it uses the MSG_ORIG macro, which uses an array
 *	that is local to each module. Hence, this is a static function,
 *	defined by this macro. Once defined by a module, the routine
 *	is called normally.
 */
#define	DEFINE_conv_map2str \
static \
const char * \
conv_map2str(Conv_inv_buf_t *inv_buf, int val, int flags, int num_msg, \
	const Msg *msg, const Msg *msg_altdump, const Msg *msg_altfile) \
{ \
	if ((val >= 0) && (val < num_msg)) { \
		if ((flags & CONV_FMT_ALTDUMP) && msg_altdump) { \
			return (MSG_ORIG(msg_altdump[val])); \
		} else if ((flags & CONV_FMT_ALTFILE) && msg_altfile) { \
			return (MSG_ORIG(msg_altfile[val])); \
		} else { \
			return (MSG_ORIG(msg[val])); \
		} \
	} \
\
	/* If we get here, it's an unknown value */ \
	return (conv_invalid_val(inv_buf, val, flags)); \
}

/* # of elements in an array */
#define	ARRAY_NELTS(arr) (sizeof (arr) / sizeof (*arr))



#ifdef	__cplusplus
}
#endif

#endif	/* __CONV_DOT_H */
