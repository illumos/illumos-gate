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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mallint.h"
#include <errno.h>

/*
 * mallopt -- System V-compatible malloc "optimizer"
 */
int
mallopt(int cmd, int value)
{
	if (__mallinfo.smblks != 0)
		return (-1);		/* small block has been allocated */

	switch (cmd) {
	case M_MXFAST:		/* small block size */
		if (value < 0)
			return (-1);
		__mallinfo.mxfast = value;
		break;

	case M_NLBLKS:		/* # small blocks per holding block */
		if (value <= 0)
			return (-1);
		__mallinfo.nlblks = value;
		break;

	case M_GRAIN:		/* small block rounding factor */
		if (value <= 0)
			return (-1);
		/* round up to multiple of minimum alignment */
		__mallinfo.grain = roundup(value, ALIGNSIZ);
		break;

	case M_KEEP:		/* Sun algorithm always preserves data */
		break;

	default:
		return (-1);
	}

	/* make sure that everything is consistent */
	__mallinfo.mxfast = roundup(__mallinfo.mxfast, __mallinfo.grain);

	return (0);
}


/*
 * mallinfo -- System V-compatible malloc information reporter
 */
struct mallinfo
mallinfo(void)
{
	struct mallinfo mi;

	mi = __mallinfo;
	mi.uordblks = mi.uordbytes - (mi.allocated * sizeof(uint));
	mi.fordblks = mi.arena - (mi.treeoverhead + mi.uordblks +
					    (mi.ordblks * sizeof(uint)));
	return (mi);
}
