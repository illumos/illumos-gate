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
 * discard inetd service - both stream and dgram based.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <inetsvc.h>


static void
discard_stream(int s, char *argv[])
{
	char buffer[BUFSIZ];

	setproctitle("discard", s, argv);
	while (read(s, buffer, sizeof (buffer)) > 0)
		;
}

/* ARGSUSED0 */
static void
noop(int s, const struct sockaddr *sap, int sa_size, const void *buf, size_t sz)
{
}

int
main(int argc, char *argv[])
{
	opterr = 0;	/* disable getopt error msgs */
	switch (getopt(argc, argv, "ds")) {
	case 'd':
		/*
		 * We don't need to do any work since dg_template consumes the
		 * datagrams for us, and we just ignore them.
		 */
		dg_template(noop, STDIN_FILENO, NULL, 0);
		break;
	case 's':
		discard_stream(STDIN_FILENO, argv);
		break;
	default:
		return (1);
	}

	return (0);
}
