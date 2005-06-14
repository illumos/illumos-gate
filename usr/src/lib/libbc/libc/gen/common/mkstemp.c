#pragma ident	"%Z%%M%	%I%	%E% SMI" /* from UCB 5.2 3/9/86 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <sys/file.h>

mkstemp(as)
	char *as;
{
	register char *s;
	register unsigned int pid;
	register int fd, i;

	pid = getpid();
	s = as;
	while (*s++)
		/* void */;
	s--;
	while (*--s == 'X') {
		*s = (pid % 10) + '0';
		pid /= 10;
	}
	s++;
	i = 'a';
	while ((fd = open(as, O_CREAT|O_EXCL|O_RDWR, 0600)) == -1) {
		if (i == 'z')
			return(-1);
		*s = i++;
	}
	return(fd);
}
