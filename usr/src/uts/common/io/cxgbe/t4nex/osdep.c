/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "common.h"
#include "osdep.h"

int
ilog2(long x)
{
	return (ddi_fls(x) - 1);
}

unsigned char *
strstrip(unsigned char *s)
{
	unsigned char c, *r, *trim_at;

	while (isspace(*s))
		s++;
	r = trim_at = s;

	while ((c = *s++) != 0) {
		if (!isspace(c))
			trim_at = s;
	}
	*trim_at = 0;

	return (r);
}
