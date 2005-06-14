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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpcsvc/dbm.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

#if defined(sparc)
#define	_FSTAT	_fstat
extern int _fstat(int, struct stat *);
#else  /* !sparc */
#define	_FSTAT	fstat
#endif /* sparc */


void dbm_access(long);
void delitem(char *, int);
void chkblk(char *);
int  additem(char *, datum);
int  getbit(void);
int  setbit(void);
int  cmpdatum(datum, datum);

int
dbminit(file)
	char *file;
{
	struct stat statb;

	trace1(TR_dbminit, 0);
	dbrdonly = 0;
	if (strlcpy(pagbuf, file, sizeof (pagbuf)) >= sizeof (pagbuf) ||
	    strlcat(pagbuf, ".pag", sizeof (pagbuf)) >= sizeof (pagbuf)) {
		/*
		 * file.pag does not fit into pagbuf.
		 * fails with ENAMETOOLONG.
		 */
		trace1(TR_dbminit, 1);
		errno = ENAMETOOLONG;
		return (-1);
	}
	pagf = open(pagbuf, 2);
	if (pagf < 0) {
		pagf = open(pagbuf, 0);
		dbrdonly = 1;
	}
	/*
	 * We know this won't overflow so it is safe to ignore the
	 * return value; we use strl* to prevent false hits in
	 * code sweeps.
	 */
	(void) strlcpy(pagbuf, file, sizeof (pagbuf));
	(void) strlcat(pagbuf, ".dir", sizeof (pagbuf));
	dirf = open(pagbuf, 2);
	if (dirf < 0) {
		dirf = open(pagbuf, 0);
		dbrdonly = 1;
	}
	if (pagf < 0 || dirf < 0) {
		trace1(TR_dbminit, 1);
		return (-1);
	}
	_FSTAT(dirf, &statb);
	maxbno = statb.st_size*BYTESIZ-1;
	trace1(TR_dbminit, 1);
	return (0);
}

static long oldb1 = -1;
static long oldb2 = -1;

/* Avoid using cached data for subsequent accesses. */
int
dbmflush()
{
	trace1(TR_dbmflush, 0);
	oldb1 = -1;
	oldb2 = -1;
	trace1(TR_dbmflush, 1);
	return (0);
}

/* Clean up after ourself. */
int
dbmclose()
{
	trace1(TR_dbmclose, 0);
	(void) close(pagf);
	(void) close(dirf);
	bitno = 0;
	maxbno = 0;
	blkno = 0;
	hmask = 0;
	oldb1 = -1;
	oldb2 = -1;
	trace1(TR_dbmclose, 1);
	return (0);
}

long
forder(key)
	datum key;
{
	long hash;

	trace1(TR_forder, 0);
	hash = calchash(key);
	for (hmask = 0; ; hmask = (hmask<<1) + 1) {
		blkno = hash & hmask;
		bitno = blkno + hmask;
		if (getbit() == 0)
			break;
	}
	trace1(TR_forder, 1);
	return (blkno);
}

datum
fetch(key)
	datum key;
{
	int i;
	datum item;

	trace1(TR_fetch, 0);
	dbm_access(calchash(key));
	for (i = 0; ; i += 2) {
		item = makdatum(pagbuf, i);
		if (item.dptr == NULL) {
			trace1(TR_fetch, 1);
			return (item);
		}
		if (cmpdatum(key, item) == 0) {
			item = makdatum(pagbuf, i+1);
			if (item.dptr == NULL)
				(void) printf("items not in pairs\n");
			trace1(TR_fetch, 1);
			return (item);
		}
	}
}

int
delete(key)
	datum key;
{
	int i;
	datum item;

	trace1(TR_delete, 0);
	if (dbrdonly) {
		trace1(TR_delete, 1);
		return (-1);
	}
	dbm_access(calchash(key));
	for (i = 0; ; i += 2) {
		item = makdatum(pagbuf, i);
		if (item.dptr == NULL) {
			trace1(TR_delete, 1);
			return (-1);
		}
		if (cmpdatum(key, item) == 0) {
			delitem(pagbuf, i);
			delitem(pagbuf, i);
			break;
		}
	}
	(void) lseek(pagf, blkno*PBLKSIZ, 0);
	(void) write(pagf, pagbuf, PBLKSIZ);
	trace1(TR_delete, 1);
	return (0);
}

int
store(key, dat)
	datum key, dat;
{
	int i;
	datum item;
	char ovfbuf[PBLKSIZ];

	trace1(TR_store, 0);
	if (dbrdonly) {
		trace1(TR_store, 1);
		return (-1);
	}
loop:
	dbm_access(calchash(key));
	for (i = 0; ; i += 2) {
		item = makdatum(pagbuf, i);
		if (item.dptr == NULL)
			break;
		if (cmpdatum(key, item) == 0) {
			delitem(pagbuf, i);
			delitem(pagbuf, i);
			break;
		}
	}
	i = additem(pagbuf, key);
	if (i < 0)
		goto split;
	if (additem(pagbuf, dat) < 0) {
		delitem(pagbuf, i);
		goto split;
	}
	(void) lseek(pagf, blkno*PBLKSIZ, 0);
	(void) write(pagf, pagbuf, PBLKSIZ);
	trace1(TR_store, 1);
	return (0);

split:
	if (key.dsize + dat.dsize + 3 * sizeof (short) >= PBLKSIZ) {
		(void) printf("entry too big\n");
		trace1(TR_store, 1);
		return (-1);
	}
	(void) memset((char *)&ovfbuf, 0, PBLKSIZ);
	for (i = 0; ; ) {
		item = makdatum(pagbuf, i);
		if (item.dptr == NULL)
			break;
		if (calchash(item) & (hmask+1)) {
			(void) additem(ovfbuf, item);
			delitem(pagbuf, i);
			item = makdatum(pagbuf, i);
			if (item.dptr == NULL) {
				(void) printf("split not paired\n");
				break;
			}
			(void) additem(ovfbuf, item);
			delitem(pagbuf, i);
			continue;
		}
		i += 2;
	}
	(void) lseek(pagf, blkno*PBLKSIZ, 0);
	if (write(pagf, pagbuf, PBLKSIZ) < 0) {
		trace1(TR_store, 1);
		return (-1);
	}
	(void) lseek(pagf, (blkno+hmask+1)*PBLKSIZ, 0);
	if (write(pagf, ovfbuf, PBLKSIZ) < 0) {
		trace1(TR_store, 1);
		return (-1);
	}
	if (setbit() < 0) {
		trace1(TR_store, 1);
		return (-1);
	}
	goto loop;
}

datum
firstkey()
{
	datum dummy;

	trace1(TR_firstkey, 0);
	dummy = firsthash(0L);
	trace1(TR_firstkey, 1);
	return (dummy);
}

datum
nextkey(key)
	datum key;
{
	int i;
	datum item, bitem;
	long hash;
	int f;
	datum dummy;

	trace1(TR_nextkey, 0);
#ifdef lint
	bitem.dptr = NULL;
	bitem.dsize = 0;
#endif /* lint */
	hash = calchash(key);
	dbm_access(hash);
	f = 1;
	for (i = 0; ; i += 2) {
		item = makdatum(pagbuf, i);
		if (item.dptr == NULL)
			break;
		if (cmpdatum(key, item) <= 0)
			continue;
		if (f || cmpdatum(bitem, item) < 0) {
			bitem = item;
			f = 0;
		}
	}
	if (f == 0) {
		trace1(TR_nextkey, 1);
		return (bitem);
	}
	hash = hashinc(hash);
	if (hash == 0) {
		trace1(TR_nextkey, 1);
		return (item);
	}
	dummy = firsthash(hash);
	trace1(TR_nextkey, 1);
	return (dummy);
}

datum
firsthash(hash)
	long hash;
{
	int i;
	datum item, bitem;

	trace2(TR_firsthash, 0, hash);
loop:
	dbm_access(hash);
	bitem = makdatum(pagbuf, 0);
	for (i = 2; ; i += 2) {
		item = makdatum(pagbuf, i);
		if (item.dptr == NULL)
			break;
		if (cmpdatum(bitem, item) < 0)
			bitem = item;
	}
	if (bitem.dptr != NULL) {
		trace1(TR_firsthash, 1);
		return (bitem);
	}
	hash = hashinc(hash);
	if (hash == 0) {
		trace1(TR_firsthash, 1);
		return (item);
	}
	goto loop;
}

void
dbm_access(hash)
	long hash;
{
	ssize_t readsize;

	trace2(TR_dbm_access, 0, hash);
	for (hmask = 0; ; hmask = (hmask<<1) + 1) {
		blkno = hash & hmask;
		bitno = blkno + hmask;
		if (getbit() == 0)
			break;
	}
	if (blkno != oldb1) {
		(void) lseek(pagf, blkno*PBLKSIZ, 0);
		readsize = read(pagf, pagbuf, PBLKSIZ);
		if (readsize != PBLKSIZ) {
			if (readsize < 0) readsize = 0;
			(void) memset((char *)(&pagbuf+readsize),
			    0, PBLKSIZ-readsize);
		}
		chkblk(pagbuf);
		oldb1 = blkno;
	}
	trace1(TR_dbm_access, 1);
}

int
getbit(void)
{
	long bn;
	ssize_t readsize;
	long b, i, n;

	trace1(TR_getbit, 0);
	if (bitno > maxbno) {
		trace1(TR_getbit, 1);
		return (0);
	}
	n = bitno % BYTESIZ;
	bn = bitno / BYTESIZ;
	i = bn % DBLKSIZ;
	b = bn / DBLKSIZ;
	if (b != oldb2) {
		(void) lseek(dirf, (long)b*DBLKSIZ, 0);
		readsize = read(dirf, dirbuf, DBLKSIZ);
		if (readsize != DBLKSIZ) {
			if (readsize < 0) readsize = 0;
			(void) memset((char *)(&dirbuf+readsize),
			    0, DBLKSIZ-readsize);
		}
		oldb2 = b;
	}
	if (dirbuf[i] & (1<<n)) {
		trace1(TR_getbit, 1);
		return (1);
	}
	trace1(TR_getbit, 1);
	return (0);
}

int
setbit(void)
{
	long bn;
	long i, n, b;

	trace1(TR_setbit, 0);
	if (dbrdonly) {
		trace1(TR_setbit, 1);
		return (-1);
	}
	if (bitno > maxbno) {
		maxbno = bitno;
		(void) getbit();
	}
	n = bitno % BYTESIZ;
	bn = bitno / BYTESIZ;
	i = bn % DBLKSIZ;
	b = bn / DBLKSIZ;
	dirbuf[i] |= 1<<n;
	(void) lseek(dirf, (long)b*DBLKSIZ, 0);
	if (write(dirf, dirbuf, DBLKSIZ) < 0) {
		trace1(TR_setbit, 1);
		return (-1);
	}
	trace1(TR_setbit, 1);
	return (0);
}

datum
makdatum(char buf[PBLKSIZ], int n)
{
	short *sp;
	int t;
	datum item;

	trace1(TR_makdatum, 0);
	sp = (short *)buf;
	if (n < 0 || n >= sp[0])
		goto null;
	t = PBLKSIZ;
	if (n > 0)
		t = sp[n+1-1];
	item.dptr = buf+sp[n+1];
	item.dsize = t - sp[n+1];
	trace1(TR_makdatum, 1);
	return (item);

null:
	item.dptr = NULL;
	item.dsize = 0;
	trace1(TR_makdatum, 1);
	return (item);
}

int
cmpdatum(d1, d2)
	datum d1, d2;
{
	int n;
	char *p1, *p2;

	trace1(TR_cmpdatum, 0);
	n = d1.dsize;
	if (n != d2.dsize) {
		trace1(TR_cmpdatum, 1);
		return (n - d2.dsize);
	}
	if (n == 0) {
		trace1(TR_cmpdatum, 1);
		return (0);
	}
	p1 = d1.dptr;
	p2 = d2.dptr;
	do
		if (*p1++ != *p2++) {
			trace1(TR_cmpdatum, 1);
			return (*--p1 - *--p2);
		}
	while (--n);
	trace1(TR_cmpdatum, 1);
	return (0);
}

int	hitab[16]
/*
 * ken's
 * {
 *	055, 043, 036, 054, 063, 014, 004, 005,
 *	010, 064, 077, 000, 035, 027, 025, 071,
 * };
 */
	= {	61, 57, 53, 49, 45, 41, 37, 33,
	29, 25, 21, 17, 13,  9,  5,  1,
};
long	hltab[64]
	= {
	06100151277L, 06106161736L, 06452611562L, 05001724107L,
	02614772546L, 04120731531L, 04665262210L, 07347467531L,
	06735253126L, 06042345173L, 03072226605L, 01464164730L,
	03247435524L, 07652510057L, 01546775256L, 05714532133L,
	06173260402L, 07517101630L, 02431460343L, 01743245566L,
	00261675137L, 02433103631L, 03421772437L, 04447707466L,
	04435620103L, 03757017115L, 03641531772L, 06767633246L,
	02673230344L, 00260612216L, 04133454451L, 00615531516L,
	06137717526L, 02574116560L, 02304023373L, 07061702261L,
	05153031405L, 05322056705L, 07401116734L, 06552375715L,
	06165233473L, 05311063631L, 01212221723L, 01052267235L,
	06000615237L, 01075222665L, 06330216006L, 04402355630L,
	01451177262L, 02000133436L, 06025467062L, 07121076461L,
	03123433522L, 01010635225L, 01716177066L, 05161746527L,
	01736635071L, 06243505026L, 03637211610L, 01756474365L,
	04723077174L, 03642763134L, 05750130273L, 03655541561L,
};

long
hashinc(hash)
	long hash;
{
	long bit;

	trace2(TR_hashinc, 0, hash);
	hash &= hmask;
	bit = hmask+1;
	for (; ; ) {
		bit >>= 1;
		if (bit == 0) {
			trace1(TR_hashinc, 1);
			return (0L);
		}
		if ((hash&bit) == 0) {
			trace1(TR_hashinc, 1);
			return (hash|bit);
		}
		hash &= ~bit;
	}
}

long
calchash(item)
	datum item;
{
	int i, j, f;
	long hashl;
	int hashi;

	trace1(TR_calchash, 0);
	hashl = 0;
	hashi = 0;
	for (i = 0; i < item.dsize; i++) {
		f = item.dptr[i];
		for (j = 0; j < BYTESIZ; j += 4) {
			hashi += hitab[f&017];
			hashl += hltab[hashi&63];
			f >>= 4;
		}
	}
	trace1(TR_calchash, 1);
	return (hashl);
}

void
delitem(buf, n)
	char buf[PBLKSIZ];
	int n;
{
	short *sp;
	int i1, i2, i3;

	trace1(TR_delitem, 0);
	sp = (short *)buf;
	if (n < 0 || n >= sp[0])
		goto bad;
	i1 = sp[n+1];
	i2 = PBLKSIZ;
	if (n > 0)
		i2 = sp[n+1-1];
	i3 = sp[sp[0]+1-1];
	if (i2 > i1)
	while (i1 > i3) {
		i1--;
		i2--;
		buf[i2] = buf[i1];
		buf[i1] = 0;
	}
	i2 -= i1;
	for (i1 = n + 1; i1 < sp[0]; i1++)
		sp[i1+1-1] = sp[i1+1] + i2;
	sp[0]--;
	sp[sp[0]+1] = 0;
	trace1(TR_delitem, 1);
	return;

bad:
	(void) printf("bad delitem\n");
	trace1(TR_delitem, 1);
	abort();
}

int
additem(buf, item)
	char buf[PBLKSIZ];
	datum item;
{
	short *sp;
	int i1, i2;

	trace1(TR_additem, 0);
	sp = (short *)buf;
	i1 = PBLKSIZ;
	if (sp[0] > 0)
		i1 = sp[sp[0]+1-1];
	i1 -= item.dsize;
	i2 = (sp[0]+2) * (int)sizeof (short);
	if (i1 <= i2) {
		trace1(TR_additem, 1);
		return (-1);
	}
	sp[sp[0]+1] = (short)i1;
	for (i2 = 0; i2 < item.dsize; i2++) {
		buf[i1] = item.dptr[i2];
		i1++;
	}
	sp[0]++;
	trace1(TR_additem, 1);
	return (sp[0]-1);
}

void
chkblk(buf)
	char buf[PBLKSIZ];
{
	short *sp;
	int t, i;

	trace1(TR_chkblk, 0);
	sp = (short *)buf;
	t = PBLKSIZ;
	for (i = 0; i < sp[0]; i++) {
		if (sp[i+1] > t)
			goto bad;
		t = sp[i+1];
	}
	if (t < (sp[0]+1) * sizeof (short))
		goto bad;
	trace1(TR_chkblk, 1);
	return;

bad:
	(void) printf("bad block\n");
	trace1(TR_chkblk, 1);
	abort();
	(void) memset((char *)&buf, 0, PBLKSIZ);
}
