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
 * Copyright 1987-1990,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>

#include <netdb.h>
#include <stdio.h>
#include <strings.h>

/*
 * Filter to convert addresses in /etc/ethers file to standard form
 */

int
main(int argc, char **argv)
{
	/*
	 * The hostname buffer must be at least as large as the line buffer
	 * to avoid buffer overflows when ether_line(3SOCKET) is called.
	 * We simply use the same size for both buffers to be safe.
	 */
	char line[MAXHOSTNAMELEN + 256], *lf, hostname[sizeof (line)];
	struct ether_addr e;
	FILE *in;

	if (argc > 1) {
		in = fopen(argv[1], "r");
		if (in == NULL) {
			fprintf(stderr,
			    "%s: can't open %s\n", argv[0], argv[1]);
			return (1);
		}
	} else {
		in = stdin;
	}
	while (fgets(line, sizeof (line), in) != NULL) {
		lf = strchr(line, '\n');
		if (lf != NULL)
			*lf = '\0';
		if ((line[0] == '#') || (line[0] == '\0'))
			continue;
		if (ether_line(line, &e, hostname) == 0) {
			(void) fprintf(stdout, "%s\t%s\n", ether_ntoa(&e),
			    hostname);
		} else {
			(void) fprintf(stderr,
			    "%s: ignoring line: %s\n", argv[0], line);
		}
	}
	return (0);
}
