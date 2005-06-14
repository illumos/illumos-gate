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

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/systeminfo.h>

/*ARGSUSED*/
int
main(int argc, char *argv[])
{

	char buffer[BUFSIZ];
	char *buf = buffer;
	int ret = 0;
	size_t bufsize = BUFSIZ;

	ret = sysinfo(SI_ISALIST, buf, bufsize);
	if (ret == -1) {
			perror("isalist");
			exit(1);
	} else if (ret > bufsize) {

		/* We lost some because our buffer wasn't big enuf */
		buf = malloc(bufsize = ret);
		if (buf == NULL) {
			errno = ENOMEM;
			perror("isalist");
			exit(1);
		}
		ret = sysinfo(SI_ISALIST, buf, bufsize);
		if (ret == -1) {
			perror("isalist");
			exit(1);
		}
	}
	(void) printf("%s\n", buf);
	return (0);


}
