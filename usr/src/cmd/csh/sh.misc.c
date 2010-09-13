/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
tchar	**blkcat(tchar **, tchar **);
tchar	**blkend(tchar **);

int
any(int c, tchar *s)
{

	while (s && *s)
		if (*s++ == c)
			return (1);
	return (0);
}

int
onlyread(tchar *cp)
{
	extern char end[];

	return ((char *)cp < end);
}

tchar *
savestr(tchar *s)
{
	tchar *n;
	tchar *p;

	if (s == 0)
		s = S_ /* "" */;
#ifndef m32
	for (p = s; *p++; )
		;
	n = p = (tchar *)xalloc((unsigned)(p - s)*sizeof (tchar));
	while (*p++ = *s++)
		;
	return (n);
#else
	p = (tchar *) xalloc((strlen_(s) + 1)*sizeof (tchar));
	strcpy_(p, s);
	return (p);
#endif
}

static void *
nomem(size_t i)
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
blkend(tchar **up)
{

	while (*up)
		up++;
	return (up);
}

void
blkpr(tchar **av)
{

	for (; *av; av++) {
		printf("%t", *av);
		if (av[1])
			printf(" ");
	}
}

int
blklen(tchar **av)
{
	int i = 0;

	while (*av++)
		i++;
	return (i);
}

tchar **
blkcpy(tchar **oav, tchar **bv)
{
	tchar **av = oav;

	while (*av++ = *bv++)
		continue;
	return (oav);
}

tchar **
blkcat(tchar **up, tchar **vp)
{

	(void) blkcpy(blkend(up), vp);
	return (up);
}

void
blkfree(tchar **av0)
{
	tchar **av = av0;

	for (; *av; av++)
		xfree(*av);
	xfree(av0);
}

tchar **
saveblk(tchar **v)
{
	tchar **newv =
		(tchar **)xcalloc((unsigned)(blklen(v) + 1),
				sizeof (tchar **));
	tchar **onewv = newv;

	while (*v)
		*newv++ = savestr(*v++);
	return (onewv);
}

tchar *
strspl(tchar *cp, tchar *dp)
{
	tchar *ep;
	tchar *p, *q;

#ifndef m32
	for (p = cp; *p++; )
		;
	for (q = dp; *q++; )
		;
	ep = (tchar *) xalloc((unsigned)(((p - cp) +
			(q - dp) - 1))*sizeof (tchar));
	for (p = ep, q = cp; *p++ = *q++; )
		;
	for (p--, q = dp; *p++ = *q++; )
		;
#else
	int	len1 = strlen_(cp);
	int	len2 = strlen_(dp);

	ep = (tchar *)xalloc((unsigned)(len1 + len2 + 1)*sizeof (tchar));
	strcpy_(ep, cp);
	strcat_(ep, dp);
#endif
	return (ep);
}

tchar **
blkspl(tchar **up, tchar **vp)
{
	tchar **wp =
		(tchar **)xcalloc((unsigned)(blklen(up) + blklen(vp) + 1),
			sizeof (tchar **));

	(void) blkcpy(wp, up);
	return (blkcat(wp, vp));
}

int
lastchr(tchar *cp)
{

	if (!*cp)
		return (0);
	while (cp[1])
		cp++;
	return (*cp);
}

void
donefds(void)
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
int
dmove(int i, int j)
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

int
dcopy(int i, int j)
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

int
renum(int i, int j)
{
	int k = dup(i);

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
void
copy(tchar *to, tchar *from, int size)
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
void
lshift(tchar **v, int c)
{
	tchar **u = v;

	while (*u && --c >= 0)
		xfree((char *)*u++);
	(void) blkcpy(v, u);
}

int
number(tchar *cp)
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
copyblk(tchar **v)
{
	tchar **nv =
		(tchar **)xcalloc((unsigned)(blklen(v) + 1),
				sizeof (tchar **));

	return (blkcpy(nv, v));
}

tchar *
strend(tchar *cp)
{

	while (*cp)
		cp++;
	return (cp);
}

tchar *
strip(tchar *cp)
{
	tchar *dp = cp;

	while (*dp++ &= TRIM)
		continue;
	return (cp);
}

void
udvar(tchar *name)
{

	setname(name);
	bferr("Undefined variable");
}

int
prefix(tchar *sub, tchar *str)
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
blkend_(char **up)
{

	while (*up)
		up++;
	return (up);
}

int
blklen_(char **av)
{
	int i = 0;

	while (*av++)
		i++;
	return (i);
}

char **
blkcpy_(char **oav, char **bv)
{
	char **av = oav;

	while (*av++ = *bv++)
		continue;
	return (oav);
}

char **
blkcat_(char **up, char **vp)
{

	(void) blkcpy_(blkend_(up), vp);
	return (up);
}

char **
blkspl_(char **up, char **vp)
{
	char **wp =
		(char **)xcalloc((unsigned)(blklen_(up) + blklen_(vp) + 1),
			sizeof (char **));

	(void) blkcpy_(wp, up);
	return (blkcat_(wp, vp));
}

/*
 * If stack address was passed to free(), we have no good way to see if
 * they are really in the stack. Therefore, we record the bottom of heap,
 * and filter out the address not within heap's top(end) and bottom
 * (xalloc_bottom).
 */
extern char	end[];
static char	*xalloc_bottom;

void *
xalloc(size_t size)
{
	char	*rptr, *bp;

	if ((rptr = malloc(size)) == NULL)
		return (nomem(size));
	bp = rptr + size;
	if (bp > xalloc_bottom)
		xalloc_bottom = bp;
	return (rptr);
}

void *
xrealloc(void *ptr, size_t size)
{
	char	*rptr = ptr, *bp;

	if (ptr == NULL)
		return (xalloc(size));
	if (rptr < end) {
		/* data area, but not in heap area. don't touch it */
oob:
		if (size == 0)
			return (NULL);
		rptr = xalloc(size);
		/* copy max size */
		(void) memcpy(rptr, ptr, size);
		return (rptr);
	}
	if (rptr < xalloc_bottom) {
		/* address in the heap */
inb:
		if (size == 0) {
			free(ptr);
			return (NULL);
		}
		if ((rptr = realloc(ptr, size)) == NULL)
			return (nomem(size));
		bp = rptr + size;
		if (bp > xalloc_bottom)
			xalloc_bottom = bp;
		return (rptr);
	}
#if defined(__sparc)
	if (rptr > (char *)&rptr) {
		/* in the stack frame */
		goto oob;
	}
#endif
	/*
	 * can be a memory block returned indirectly from
	 * library functions. update bottom, and check it again.
	 */
	xalloc_bottom = sbrk(0);
	if (rptr <= xalloc_bottom)
		goto inb;
	else
		goto oob;
	/*NOTREACHED*/
}

void
xfree(void *ptr)
{
	char	*rptr = ptr;

	if (rptr < end) {
		return;
	}
	if (rptr < xalloc_bottom) {
		free(ptr);
		return;
	}
#if defined(__sparc)
	if (rptr > (char *)&rptr) {
		/* in the stack frame */
		return;
	}
#endif
	xalloc_bottom = sbrk(0);
	if (rptr <= xalloc_bottom) {
		free(ptr);
	}
}

void *
xcalloc(size_t i, size_t j)
{
	char *cp;

	i *= j;
	cp = xalloc(i);
	(void) memset(cp, '\0', i);
	return (cp);
}
