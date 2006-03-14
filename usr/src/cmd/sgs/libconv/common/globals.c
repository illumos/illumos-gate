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

const char *
conv_invalid_val(char *string, size_t size, Xword value, int flags)
{
	const char	*fmt;

	if (flags & CONV_INV_DECIMAL) {
		if (flags & CONV_INV_SPACE)
			fmt = MSG_ORIG(MSG_GBL_FMT_DECS);
		else
			fmt = MSG_ORIG(MSG_GBL_FMT_DEC);
	} else {
		if (flags & CONV_INV_SPACE)
			fmt = MSG_ORIG(MSG_GBL_FMT_HEXS);
		else
			fmt = MSG_ORIG(MSG_GBL_FMT_HEX);
	}
	(void) snprintf(string, size, fmt, value);
	return ((const char *)string);
}

/*
 * Provide a focal point for expanding values (typically bit-fields) into
 * their corresponding strings.
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
		    CONV_INV_SPACE);
	}

	return (1);
}
