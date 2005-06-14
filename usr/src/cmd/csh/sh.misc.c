/*
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"
#include "sh.tconst.h"
#include <fcntl.h>
#include <unistd.h>

/*
 * C Shell
 */

any(c, s)
	register int c;
	register tchar *s;
{

	while (s && *s)
		if (*s++ == c)
			return (1);
	return (0);
}

onlyread(cp)
	tchar *cp;
{
	extern char end[];

	return ((char *)cp < end);
}


/*
 * WARNING: changes here also need to occur in the XFREE macro in sh.h.
 */

xfree(cp)
	char *cp;
{
	extern char end[];

#if defined(sparc)
	if ((char *)cp >= end && (char *)cp <  (char *)&cp)
		free(cp);
#elif defined(i386)
	if ((char *)cp >= end)
		free(cp);
#else
#error xfree function is machine dependent and no machine type is recognized
#endif
}

tchar *
savestr(s)
	register tchar *s;
{
	tchar *n;
	register tchar *p;

	if (s == 0)
		s = S_ /* "" */;
#ifndef m32
	for (p = s; *p++; )
		;
	n = p = (tchar *)xalloc((unsigned) (p - s)*sizeof (tchar));
	while (*p++ = *s++)
		;
	return (n);
#else
	p = (tchar *) xalloc((strlen_(s) + 1)*sizeof (tchar));
	strcpy_(p, s);
	return (p);
#endif
}

void *
calloc(i, j)
	register unsigned i;
	unsigned j;
{
	register char *cp;

	i *= j;
	cp = (char *)xalloc(i);
	bzero(cp, (int)i);
	return (cp);
}

nomem(i)
	unsigned i;
{
#ifdef debug
	static tchar *av[2] = {0, 0};
#endif

	child++;
#ifndef debug
	error("Out of memory");
#ifdef lint
	i = i;
#endif
#else
	showall(av);
	printf("i=%d: Out of memory\n", i);
	chdir("/usr/bill/cshcore");
	abort();
#endif
	return (0);		/* fool lint */
}

tchar **
blkend(up)
	register tchar **up;
{

	while (*up)
		up++;
	return (up);
}

blkpr(av)
	register tchar **av;
{

	for (; *av; av++) {
		printf("%t", *av);
		if (av[1])
			printf(" ");
	}
}

blklen(av)
	register tchar **av;
{
	register int i = 0;

	while (*av++)
		i++;
	return (i);
}

tchar **
blkcpy(oav, bv)
	tchar **oav;
	register tchar **bv;
{
	register tchar **av = oav;

	while (*av++ = *bv++)
		continue;
	return (oav);
}

tchar **
blkcat(up, vp)
	tchar **up, **vp;
{

	(void) blkcpy(blkend(up), vp);
	return (up);
}

blkfree(av0)
	tchar **av0;
{
	register tchar **av = av0;

	for (; *av; av++)
		XFREE(*av)
	XFREE((tchar *)av0)
}

tchar **
saveblk(v)
	register tchar **v;
{
	register tchar **newv =
		(tchar **) calloc((unsigned) (blklen(v) + 1),
				sizeof (tchar **));
	tchar **onewv = newv;

	while (*v)
		*newv++ = savestr(*v++);
	return (onewv);
}

tchar *
strspl(cp, dp)
	tchar *cp, *dp;
{
	tchar *ep;
	register tchar *p, *q;

#ifndef m32
	for (p = cp; *p++; )
		;
	for (q = dp; *q++; )
		;
	ep = (tchar *) xalloc((unsigned) (((p - cp) +
			(q - dp) - 1))*sizeof (tchar));
	for (p = ep, q = cp; *p++ = *q++; )
		;
	for (p--, q = dp; *p++ = *q++; )
		;
#else
	int	len1 = strlen_(cp);
	int	len2 = strlen_(dp);

	ep = (tchar *)xalloc((unsigned) (len1 + len2 + 1)*sizeof (tchar));
	strcpy_(ep, cp);
	strcat_(ep, dp);
#endif
	return (ep);
}

tchar **
blkspl(up, vp)
	register tchar **up, **vp;
{
	register tchar **wp =
		(tchar **) calloc((unsigned) (blklen(up) + blklen(vp) + 1),
			sizeof (tchar **));

	(void) blkcpy(wp, up);
	return (blkcat(wp, vp));
}

lastchr(cp)
	register tchar *cp;
{

	if (!*cp)
		return (0);
	while (cp[1])
		cp++;
	return (*cp);
}

donefds()
{
	(void) close(0);
	(void) close(1);
	(void) close(2);

	/*
	 * To avoid NIS+ functions to get hold of 0/1/2,
	 * use descriptor 0, and dup it to 1 and 2.
	 */
	open("/dev/null", 0);
	dup(0); dup(0);
	didfds = 0;
}

/*
 * Move descriptor i to j.
 * If j is -1 then we just want to get i to a safe place,
 * i.e. to a unit > 2.  This also happens in dcopy.
 */
dmove(i, j)
	register int i, j;
{
	int fd;

	if (i == j || i < 0)
		return (i);
	if (j >= 0) {
		fd = dup2(i, j);
		if (fd != -1)
			setfd(fd);
	} else
		j = dcopy(i, j);
	if (j != i) {
		(void) close(i);
		unsetfd(i);
	}
	return (j);
}

dcopy(i, j)
	register int i, j;
{

	int fd;

	if (i == j || i < 0 || j < 0 && i > 2)
		return (i);
	if (j >= 0) {
		fd = dup2(i, j);
		if (fd != -1)
			setfd(fd);
		return (j);
	}
	(void) close(j);
	unsetfd(j);
	return (renum(i, j));
}

renum(i, j)
	register int i, j;
{
	register int k = dup(i);

	if (k < 0)
		return (-1);
	if (j == -1 && k > 2) {
		setfd(k);
		return (k);
	}
	if (k != j) {
		j = renum(k, j);
		(void) close(k);	/* no need ofr unsetfd() */
		return (j);
	}
	return (k);
}

#ifndef copy
copy(to, from, size)
	register tchar *to, *from;
	register int size;
{

	if (size)
		do
			*to++ = *from++;
		while (--size != 0);
}
#endif

/*
 * Left shift a command argument list, discarding
 * the first c arguments.  Used in "shift" commands
 * as well as by commands like "repeat".
 */
lshift(v, c)
	register tchar **v;
	register int c;
{
	register tchar **u = v;

	while (*u && --c >= 0)
		xfree(*u++);
	(void) blkcpy(v, u);
}

number(cp)
	tchar *cp;
{

	if (*cp == '-') {
		cp++;
		if (!digit(*cp++))
			return (0);
	}
	while (*cp && digit(*cp))
		cp++;
	return (*cp == 0);
}

tchar **
copyblk(v)
	register tchar **v;
{
	register tchar **nv =
		(tchar **) calloc((unsigned) (blklen(v) + 1),
				sizeof (tchar **));

	return (blkcpy(nv, v));
}

tchar *
strend(cp)
	register tchar *cp;
{

	while (*cp)
		cp++;
	return (cp);
}

tchar *
strip(cp)
	tchar *cp;
{
	register tchar *dp = cp;

	while (*dp++ &= TRIM)
		continue;
	return (cp);
}

udvar(name)
	tchar *name;
{

	setname(name);
	bferr("Undefined variable");
}

prefix(sub, str)
	register tchar *sub, *str;
{

	for (;;) {
		if (*sub == 0)
			return (1);
		if (*str == 0)
			return (0);
		if (*sub++ != *str++)
			return (0);
	}
}

/*
 * blk*_ routines
 */

char **
blkend_(up)
	register char **up;
{

	while (*up)
		up++;
	return (up);
}

blklen_(av)
	register char **av;
{
	register int i = 0;

	while (*av++)
		i++;
	return (i);
}

char **
blkcpy_(oav, bv)
	char **oav;
	register char **bv;
{
	register char **av = oav;

	while (*av++ = *bv++)
		continue;
	return (oav);
}

char **
blkcat_(up, vp)
	char **up, **vp;
{

	(void) blkcpy_(blkend_(up), vp);
	return (up);
}

char **
blkspl_(up, vp)
	register char **up, **vp;
{
	register char **wp =
		(char **) calloc((unsigned) (blklen_(up) + blklen_(vp) + 1),
			sizeof (char **));

	(void) blkcpy_(wp, up);
	return (blkcat_(wp, vp));
}
