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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routine for symbol references.
 */
#include	"_conv.h"
#include	"deftag_msg.h"

const char *
conv_def_tag(Symref ref, Conv_inv_buf_t *inv_buf)
{
	static const Msg	refs[] = {
		MSG_REF_DYN_SEEN,	MSG_REF_DYN_NEED,	MSG_REF_REL_NEED
	};

	if (ref >= REF_NUM)
		return (conv_invalid_val(inv_buf, ref, 0));
	else
		return (MSG_ORIG(refs[ref]));
}
