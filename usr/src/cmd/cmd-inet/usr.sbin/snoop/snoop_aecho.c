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

#include <stdio.h>
#include <sys/types.h>

#include <at.h>
#include <snoop.h>

void
interpret_aecho(int flags, struct ddp_hdr *ddp, int len)
{
	char *data;

	data = (char *)ddp + DDPHDR_SIZE;

	if (flags & F_SUM) {
		if (len < DDPHDR_SIZE + 1) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "AECHO (short packet)");
			return;
		}

		(void) snprintf(get_sum_line(), MAXLINE,
		    "AECHO F=%s LEN=%d",
		    *data == AEP_REQ ? "Request" : "Reply",
		    len);
	}

	if (flags & F_DTAIL) {
		if (len < DDPHDR_SIZE + 1) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "AECHO (short packet)");
			return;
		}

		show_header("AECHO:  ", "AECHO Header", len);
		show_space();

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Func = %d (%s)",
		    data[0],
		    data[0] == AEP_REQ ? "Request" : "Reply");
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length = %d", len);
	}
}
