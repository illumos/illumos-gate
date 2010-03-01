/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1984 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Return the number of the slot in the utmp file
 * corresponding to the current user: try for file 0, 1, 2.
 * To mimic the behavior of getttyent, we loop through utmp
 * and try to find an entry with a matching line number.
 * If we don't find one we return the index of the end of
 * the file, so that the record can be added to the end of
 * the file.
 */
#include "../../sys/common/compat.h"
#include <sys/syscall.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>

int
ttyslot(void)
{
	char *tp, *p;
	int s;
	int fd;
	struct utmpx utx;


	if ((tp = ttyname(0)) == NULL &&
	    (tp = ttyname(1)) == NULL &&
	    (tp = ttyname(2)) == NULL)
		return (0);
	if ((p = rindex(tp, '/')) == NULL)
		p = tp;
	else
		p++;

	if ((fd = _syscall(SYS_openat,
	    AT_FDCWD, "/etc/utmpx", O_RDONLY)) == -1) {
		perror("ttyslot: open of /etc/utmpx failed:");
		return (0);
	}

	s = 0;
	while (_read(fd, &utx, sizeof (struct utmpx)) > 0) {
		s++;
		if (strncmp(utx.ut_line, p, sizeof (utx.ut_line)) == 0) {
			_syscall(SYS_close, fd);
			return (s);
		}
	}
	_syscall(SYS_close, fd);
	return (s);
}
