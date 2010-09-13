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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>

#include "options.h"

static uchar_t bitlocation[8] = {1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80};

/*
 * Create a bytemask to store the command line options.
 */
void
set_options_mask(options *msk, char *str)
{
	int i;
	(void) memset(msk, 0, sizeof (*msk));
	for (i = 0; str[i] != 0; i++) {
		add_option(msk, str[i]);
	}
}

void
add_option(options *msk, char option)
{
	uint_t loc;
	loc = (uint_t)option;
	loc &= 0x7f;
	/* put option into the correct bucket */
	msk->bitmap[loc >> 3] |= bitlocation[loc & 7];
}

/*
 * Compare the bytemask of the command line options used with
 * acceptable options. If an invalid option is found use it as
 * the return value.
 */
int
compare_options_mask(options *msk, options *specified)
{
	int i, j;
	uchar_t bmap = 0;

	for (i = 0; i < 16; i++) {
		if (msk->bitmap[i] == specified->bitmap[i])
			continue;
		bmap = msk->bitmap[i] | specified->bitmap[i];
		bmap ^= msk->bitmap[i];
		if (bmap)
			break;
	}
	if (i == 16) {
		/* no invalid options found */
		return (0);
	}

	for (j = 0; j < 8; j++) {
		if (bmap & bitlocation[j])
			break;
	}
	return ((i*8) + j);
}
