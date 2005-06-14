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
 * Copyright (c) 1991, 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS	*/

#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <sys/tiuser.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include "snoop.h"

extern char *dlc_header;
extern jmp_buf xdr_err;

void detail_stats();		/* Version 1 */
void detail_statsswtch();	/* Version 2 */
void detail_statstime();	/* Version 3 */
void detail_statsvar();		/* Version 4 */

static char *procnames_short[] = {
	"Null",			/*  0 */
	"Get Statistics",	/*  1 */
	"Have Disk",		/*  2 */
};

static char *procnames_long[] = {
	"Null procedure",		/*  0 */
	"Get Statistics",		/*  1 */
	"Have Disk",			/*  2 */
};

#define	MAXPROC	2

void
interpret_rstat(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line,
				"RSTAT C %s",
				procnames_short[proc]);

			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "RSTAT R %s ",
				procnames_short[proc]);
		}
	}

	if (flags & F_DTAIL) {
		show_header("RSTAT:  ", "RSTAT Get Statistics", len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0),
			"Proc = %d (%s)",
			proc, procnames_long[proc]);

		if (type == REPLY) {
			switch (proc) {
			case 1:
				switch (vers) {
				case 1:
					detail_stats();
					break;
				case 2:
					detail_statsswtch();
					break;
				case 3:
					detail_statstime();
					break;
				case 4:
					detail_statsvar();
					break;
				}
				break;
			case 2:
				(void) showxdr_u_long(
					"Result = %lu");
				break;
			}
		}
		show_trailer();
	}
}

void
detail_stats()
{
	show_space();
	(void) sprintf(get_line(0, 0), "CPU Times:");
	(void) showxdr_long("  Time (1)       = %d");
	(void) showxdr_long("  Time (2)       = %d");
	(void) showxdr_long("  Time (3)       = %d");
	(void) showxdr_long("  Time (4)       = %d");
	show_space();
	(void) sprintf(get_line(0, 0), "Disk Transfers:");
	(void) showxdr_long("  Transfers(1)   = %d");
	(void) showxdr_long("  Transfers(2)   = %d");
	(void) showxdr_long("  Transfers(3)   = %d");
	(void) showxdr_long("  Transfers(4)   = %d");
	show_space();
	(void) showxdr_u_long("Pages in         = %lu");
	(void) showxdr_u_long("Pages out        = %lu");
	(void) showxdr_u_long("Swaps in         = %lu");
	(void) showxdr_u_long("Swaps out        = %lu");
	(void) showxdr_u_long("Interrupts       = %lu");
	show_space();
	(void) showxdr_long("Receive packets  = %d");
	(void) showxdr_long("Receive errors   = %d");
	(void) showxdr_long("Transmit packets = %d");
	(void) showxdr_long("Transmit errors  = %d");
	(void) showxdr_long("Collisions       = %d");
}

void
detail_statsswtch()
{
	show_space();
	(void) sprintf(get_line(0, 0), "CPU Times:");
	(void) showxdr_long("  Time (1)       = %d");
	(void) showxdr_long("  Time (2)       = %d");
	(void) showxdr_long("  Time (3)       = %d");
	(void) showxdr_long("  Time (4)       = %d");
	show_space();
	(void) sprintf(get_line(0, 0), "Disk Transfers:");
	(void) showxdr_long("  Transfers(1)   = %d");
	(void) showxdr_long("  Transfers(2)   = %d");
	(void) showxdr_long("  Transfers(3)   = %d");
	(void) showxdr_long("  Transfers(4)   = %d");
	show_space();
	(void) showxdr_u_long("Pages in         = %lu");
	(void) showxdr_u_long("Pages out        = %lu");
	(void) showxdr_u_long("Swaps in         = %lu");
	(void) showxdr_u_long("Swaps out        = %lu");
	(void) showxdr_u_long("Interrupts       = %lu");
	show_space();
	(void) showxdr_long("Receive packets  = %d");
	(void) showxdr_long("Receive errors   = %d");
	(void) showxdr_long("Transmit packets = %d");
	(void) showxdr_long("Transmit errors  = %d");
	(void) showxdr_long("Collisions       = %d");
	show_space();
	(void) showxdr_u_long("V switch         = %lu");
	(void) showxdr_long("Average run 0    = %d");
	(void) showxdr_long("Average run 1    = %d");
	(void) showxdr_long("Average run 2    = %d");
	show_space();
	(void) showxdr_date("Boot time:       = %s");
}

void
detail_statstime()
{
	show_space();
	(void) sprintf(get_line(0, 0), "CPU Times:");
	(void) showxdr_long("  Time (1)     = %d");
	(void) showxdr_long("  Time (2)     = %d");
	(void) showxdr_long("  Time (3)     = %d");
	(void) showxdr_long("  Time (4)     = %d");
	show_space();
	(void) sprintf(get_line(0, 0), "Disk Transfers:");
	(void) showxdr_long("  Transfers(1)   = %d");
	(void) showxdr_long("  Transfers(2)   = %d");
	(void) showxdr_long("  Transfers(3)   = %d");
	(void) showxdr_long("  Transfers(4)   = %d");
	show_space();
	(void) showxdr_u_long("Pages in         = %lu");
	(void) showxdr_u_long("Pages out        = %lu");
	(void) showxdr_u_long("Swaps in         = %lu");
	(void) showxdr_u_long("Swaps out        = %lu");
	(void) showxdr_u_long("Interrupts       = %lu");
	show_space();
	(void) showxdr_long("Receive packets  = %d");
	(void) showxdr_long("Receive errors   = %d");
	(void) showxdr_long("Transmit packets = %d");
	(void) showxdr_long("Transmit errors  = %d");
	(void) showxdr_long("Collisions       = %d");
	show_space();
	(void) showxdr_u_long("V switch         = %lu");
	(void) showxdr_long("Average run 0    = %d");
	(void) showxdr_long("Average run 1    = %d");
	(void) showxdr_long("Average run 2    = %d");
	show_space();
	(void) showxdr_date("Boot time:       = %s");
	(void) showxdr_date("Current time     = %s");
}

void
detail_statsvar()
{
	int i, n;

	show_space();
	(void) sprintf(get_line(0, 0), "CPU Times:");
	n = getxdr_u_long();
	for (i = 1; i <= n; i++) {
		(void) sprintf(get_line(0, 0),
			"  Time (%2d)      = %d", i, getxdr_long());
	}
	show_space();
	(void) sprintf(get_line(0, 0), "Disk Transfers:");
	n = getxdr_u_long();
	for (i = 1; i <= n; i++) {
		(void) sprintf(get_line(0, 0),
			"  Transfers (%2d) = %d", i, getxdr_long());
	}
	show_space();
	(void) showxdr_u_long("Pages in         = %lu");
	(void) showxdr_u_long("Pages out        = %lu");
	(void) showxdr_u_long("Swaps in         = %lu");
	(void) showxdr_u_long("Swaps out        = %lu");
	(void) showxdr_u_long("Interrupts       = %lu");
	show_space();
	(void) showxdr_long("Receive packets  = %d");
	(void) showxdr_long("Receive errors   = %d");
	(void) showxdr_long("Transmit packets = %d");
	(void) showxdr_long("Transmit errors  = %d");
	(void) showxdr_long("Collisions       = %d");
	show_space();
	(void) showxdr_u_long("V switch         = %lu");
	(void) showxdr_long("Average run 0    = %d");
	(void) showxdr_long("Average run 1    = %d");
	(void) showxdr_long("Average run 2    = %d");
	show_space();
	(void) showxdr_date("Boot time:       = %s");
	(void) showxdr_date("Current time     = %s");
}
