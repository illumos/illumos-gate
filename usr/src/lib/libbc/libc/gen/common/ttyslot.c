/*
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1984 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
		return(0);
	if ((p = rindex(tp, '/')) == NULL)
		p = tp;
	else
		p++;

	if ((fd = _syscall(SYS_open, "/etc/utmpx", O_RDONLY)) == -1) {
		perror("ttyslot: open of /etc/utmpx failed:");
		return(0);
	}

	s = 0;
	while (_read(fd, &utx, sizeof(struct utmpx)) > 0) {
		s++;
		if (strncmp(utx.ut_line, p, sizeof(utx.ut_line)) == 0) {
			_syscall(SYS_close, fd);
			return(s);
		}
	}
	_syscall(SYS_close, fd);
	return (s);
}
