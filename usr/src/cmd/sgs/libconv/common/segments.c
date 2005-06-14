/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routine for segment flags.
 */
#include	<string.h>
#include	"libld.h"
#include	"segments_msg.h"

#define	SEGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_FLG_SG_VADDR_SIZE + \
		MSG_FLG_SG_PADDR_SIZE + \
		MSG_FLG_SG_LENGTH_SIZE + \
		MSG_FLG_SG_ALIGN_SIZE + \
		MSG_FLG_SG_ROUND_SIZE + \
		MSG_FLG_SG_FLAGS_SIZE + \
		MSG_FLG_SG_TYPE_SIZE + \
		MSG_FLG_SG_ORDER_SIZE + \
		MSG_FLG_SG_EMPTY_SIZE + \
		MSG_FLG_SG_NOHDR_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

const char *
conv_segaflg_str(uint_t flags)
{
	static	char	string[SEGSZ] = { '\0' };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	else {
		(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));
		if (flags & FLG_SG_VADDR)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_VADDR));
		if (flags & FLG_SG_PADDR)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_PADDR));
		if (flags & FLG_SG_LENGTH)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_LENGTH));
		if (flags & FLG_SG_ALIGN)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_ALIGN));
		if (flags & FLG_SG_ROUND)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_ROUND));
		if (flags & FLG_SG_FLAGS)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_FLAGS));
		if (flags & FLG_SG_TYPE)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_TYPE));
		if (flags & FLG_SG_ORDER)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_ORDER));
		if (flags & FLG_SG_EMPTY)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_EMPTY));
		if (flags & FLG_SG_NOHDR)
			(void) strcat(string, MSG_ORIG(MSG_FLG_SG_NOHDR));
		(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

		return ((const char *)string);
	}
}
