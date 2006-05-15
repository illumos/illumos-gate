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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<strings.h>
#include	<sys/machelf.h>
#include	"_conv.h"
#include	"globals_msg.h"


/*
 * Given an integer value, generate an ASCII representation of it.
 *
 * entry:
 *	string - Buffer into which the resulting string is generated.
 *	size - Size of string buffer (i.e. sizeof(string))
 *	value - Value to be formatted.
 *	fmt_flags - CONV_FMT_* values, used to specify formatting details.
 *
 * exit:
 *	The formatted string, or as much as will fit, is placed into
 *	string. String is returned.
 */
const char *
conv_invalid_val(char *string, size_t size, Xword value, int fmt_flags)
{
	const char	*fmt;

	if (fmt_flags & CONV_FMT_DECIMAL) {
		if (fmt_flags & CONV_FMT_SPACE)
			fmt = MSG_ORIG(MSG_GBL_FMT_DECS);
		else
			fmt = MSG_ORIG(MSG_GBL_FMT_DEC);
	} else {
		if (fmt_flags & CONV_FMT_SPACE)
			fmt = MSG_ORIG(MSG_GBL_FMT_HEXS);
		else
			fmt = MSG_ORIG(MSG_GBL_FMT_HEX);
	}
	(void) snprintf(string, size, fmt, value);
	return ((const char *)string);
}



/*
 * Provide a focal point for expanding bit-fields values into
 * their corresponding strings.
 *
 * entry:
 *	string - Buffer into which the resulting string is generated.
 *	size - Size of string buffer (i.e. sizeof(string))
 *	vdp - Array of value descriptors, giving the possible bit
 *		values, and their corresponding strings. Note that the
 *		final element must contain only NULL values. This
 *		terminates the list.
 *	oflags - Bits for which output strings are desired.
 *	rflags - Bits for which a numeric value should be printed
 *		if vdp does not provide a corresponding string. This
 *		must be a proper subset of oflags.
 *	separator - If non-NULL, a separator string to be inserted
 *		between each string value copied into the output.
 *	element - TRUE if first element output should be preceeded
 *		by a separator, and FALSE otherwise.
 *
 * exit:
 *	string contains the formatted result. True (1) is returned if there
 *	was no error, and False (0) if the buffer was too small.
 */
int
conv_expn_field(char *string, size_t size, const Val_desc *vdp,
    Xword oflags, Xword rflags, const char *separator, int element)
{
	const Val_desc	*vde;

	/*
	 * Traverse the callers Val_desc array and determine if the value
	 * corresponds to any array item.
	 */
	for (vde = vdp; vde->v_msg; vde++) {
		if (oflags & vde->v_val) {
			/*
			 * If a separator is required, and elements have already
			 * been added to the users output buffer, add the
			 * separator to the buffer first.
			 */
			if (separator && element++) {
				if (strlcat(string, separator, size) >= size) {
					(void) conv_invalid_val(string, size,
					    oflags, 0);
					return (0);
				}
			}

			/*
			 * Add the items strings to the users output buffer.
			 */
			if (strlcat(string, vde->v_msg, size) >= size) {
				(void) conv_invalid_val(string, size,
				    oflags, 0);
				return (0);
			}

			/*
			 * Indicate this item has been collected.
			 */
			rflags &= ~(vde->v_val);
		}
	}

	/*
	 * If any flags remain, then they are unidentified.  Add the number
	 * representation of these flags to the users output buffer.
	 */
	if (rflags) {
		size_t  off = strlen(string);
		size_t  rem = size - off;

		(void) conv_invalid_val(&string[off], rem, rflags,
		    CONV_FMT_SPACE);
	}

	return (1);
}
