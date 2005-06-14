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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * openchild.c,
 *
 * Open two pipes to a child process, one for reading, one for writing. The
 * pipes are accessed by FILE pointers. This is NOT a public interface, but
 * for internal use only!
 */
#include <stdio.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/trace.h>
#include <unistd.h>
#include <stdlib.h>
#include "rpc_mt.h"


/*
 * returns pid, or -1 for failure
 */
int
__rpc_openchild(command, fto, ffrom)
	char	*command;
	FILE	**fto;
	FILE	**ffrom;
{
	int	i;
	int	pid;
	int	pdto[2];
	int	pdfrom[2];

	trace1(TR___rpc_openchild, 0);

	if (pipe(pdto) < 0) {
		goto error1;
	}
	if (pipe(pdfrom) < 0) {
		goto error2;
	}
	switch (pid = fork()) {
	case -1:
		goto error3;

	case 0:
		/*
		 * child: read from pdto[0], write into pdfrom[1]
		 */
		dup2(pdto[0], 0);
		dup2(pdfrom[1], 1);
		closefrom(3);
		fflush(stderr);
		execlp(command, command, 0);
		perror("exec");
		trace1(TR___rpc_openchild, 1);
		_exit(~0);

	default:
		/*
		 * parent: write into pdto[1], read from pdfrom[0]
		 */
		*fto = fdopen(pdto[1], "w");
		(void) close(pdto[0]);
		*ffrom = fdopen(pdfrom[0], "r");
		(void) close(pdfrom[1]);
		break;
	}
	trace1(TR___rpc_openchild, 1);
	return (pid);

	/*
	 * error cleanup and return
	 */
error3:
	(void) close(pdfrom[0]);
	(void) close(pdfrom[1]);
error2:
	(void) close(pdto[0]);
	(void) close(pdto[1]);
error1:
	trace1(TR___rpc_openchild, 1);
	return (-1);
}
