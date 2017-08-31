/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdio.h>
#include <errno.h>
#include <ndbm.h>
#include <stdlib.h>
#include <string.h>

datum dbm_do_nextkey(DBM *, datum);


/*add support for batched writing for NIS*/

#define _DBM_DEFWRITE 0x4
#define _DBM_DIRTY 0x8
#define _DBM_DIRDIRTY 0x10
#define dbm_dirty(db) ((db)->dbm_flags & _DBM_DIRTY)
#define dbm_dirdirty(db) ((db)->dbm_flags & _DBM_DIRDIRTY)
#define dbm_defwrite(db) ((db)->dbm_flags & _DBM_DEFWRITE)
#define dbm_setdirty(db) (db)->dbm_flags |= _DBM_DIRTY
#define dbm_clrdirty(db) (db)->dbm_flags &= ~_DBM_DIRTY
#define dbm_setdirdirty(db) (db)->dbm_flags |= _DBM_DIRDIRTY
#define dbm_clrdirdirty(db) (db)->dbm_flags &= ~_DBM_DIRDIRTY


static void	dbm_access(DBM *, long);
static int	getbit(DBM *);
static int	setbit(DBM *);
static int	cmpdatum(datum, datum);
static int	finddatum(char [PBLKSIZ], datum);
static int	delitem(char [PBLKSIZ], int);
static int	additem(char [PBLKSIZ], datum, datum);
static datum	makdatum(char [PBLKSIZ], int);
static long	dcalchash(datum);

/*used to make a dbm file all at once instead of incrementally*/
void
dbm_setdefwrite(DBM *db)
{
	db->dbm_flags |= _DBM_DEFWRITE;
}

int
dbm_flush(DBM *db)
{
	int ok=0;
	if (dbm_flushpag(db)<0) ok= -1;
	if (dbm_flushdir(db)<0) ok= -1;
	return(ok);
}

int
dbm_flushpag(DBM *db)
{
	int ok=0;
	if (dbm_dirty(db)){ /*must page out the page*/
		(void) lseek(db->dbm_pagf, (long)(db->dbm_pagbno*PBLKSIZ), L_SET);
		if (write(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ) {
			db->dbm_flags |= _DBM_IOERR;
			ok= -1;
			}
		dbm_clrdirty(db);
	}
	return(ok);
}

int
dbm_flushdir(DBM *db)
{
	int ok=0;
	if (dbm_dirdirty(db)){ /*must page out the dir*/
	(void) lseek(db->dbm_dirf, (long)(db->dbm_dirbno*DBLKSIZ), L_SET);
	if (write(db->dbm_dirf, db->dbm_dirbuf, DBLKSIZ) != DBLKSIZ) {
		ok= -1;
		}
	dbm_clrdirdirty(db);
	}
	return(ok);
}
#define BYTESIZ 8
#undef setbit

DBM *
dbm_open(char *file, int flags, int mode)
{
	struct stat statb;
	DBM *db;
	int	serrno;

	if ((db = (DBM *)malloc(sizeof *db)) == 0) {
		errno = ENOMEM;
		return ((DBM *)0);
	}
	db->dbm_flags = (flags & 03) == O_RDONLY ? _DBM_RDONLY : 0;
	if ((flags & 03) == O_WRONLY)
		flags = (flags & ~03) | O_RDWR;
	if (strlcpy(db->dbm_pagbuf, file, sizeof (db->dbm_pagbuf)) >=
	    sizeof (db->dbm_pagbuf) ||
	    strlcat(db->dbm_pagbuf, ".pag", sizeof (db->dbm_pagbuf)) >=
	    sizeof (db->dbm_pagbuf)) {
		/*
		 * file.pag does not fit into dbm_pagbuf.
		 * fails with ENAMETOOLONG.
		 */
		serrno = ENAMETOOLONG;
		goto bad;
	}
	db->dbm_pagf = open(db->dbm_pagbuf, flags, mode);
	if (db->dbm_pagf < 0) {
		serrno = errno;
		goto bad;
	}
	/*
	 * We know this won't overflow so it is safe to ignore the
	 * return value; we use strl* to prevent false hits in
	 * code sweeps.
	 */
	(void) strlcpy(db->dbm_pagbuf, file, sizeof (db->dbm_pagbuf));
	(void) strlcat(db->dbm_pagbuf, ".dir", sizeof (db->dbm_pagbuf));
	db->dbm_dirf = open(db->dbm_pagbuf, flags, mode);
	if (db->dbm_dirf < 0) {
		serrno = errno;
		goto bad1;
	}
	(void) fstat(db->dbm_dirf, &statb);
	db->dbm_maxbno = statb.st_size*BYTESIZ-1;
	db->dbm_pagbno = db->dbm_dirbno = -1;
	return (db);
bad1:
	(void) close(db->dbm_pagf);
bad:
	free((char *)db);
	errno = serrno;
	return ((DBM *)0);
}

void
dbm_close(DBM *db)
{
	(void) dbm_close_status(db);
}

/*close with return code*/
int
dbm_close_status(DBM *db)
{
	int ok;
	ok=0;

	if (dbm_flush(db) <0)   ok = -1;
	if (close(db->dbm_dirf)<0) ok= -1;
	if ( close(db->dbm_pagf)<0) ok= -1;
	free((char *)db);
	return (ok);
}

long
dbm_forder(DBM *db, datum key)
{
	long hash;

	hash = dcalchash(key);
	for (db->dbm_hmask=0;; db->dbm_hmask=(db->dbm_hmask<<1)+1) {
		db->dbm_blkno = hash & db->dbm_hmask;
		db->dbm_bitno = db->dbm_blkno + db->dbm_hmask;
		if (getbit(db) == 0)
			break;
	}
	return (db->dbm_blkno);
}

datum
dbm_fetch(DBM *db, datum key)
{
	int i;
	datum item;

	if (dbm_error(db))
		goto err;
	dbm_access(db, dcalchash(key));
	if ((i = finddatum(db->dbm_pagbuf, key)) >= 0) {
		item = makdatum(db->dbm_pagbuf, i+1);
		if (item.dptr != NULL)
			return (item);
	}
err:
	item.dptr = NULL;
	item.dsize = 0;
	return (item);
}

int
dbm_delete(DBM *db, datum key)
{
	int i;

	if (dbm_error(db))
		return (-1);
	if (dbm_rdonly(db)) {
		errno = EPERM;
		return (-1);
	}
	dbm_access(db, dcalchash(key));
	if ((i = finddatum(db->dbm_pagbuf, key)) < 0)
		return (-1);
	if (!delitem(db->dbm_pagbuf, i))
		goto err;
	db->dbm_pagbno = db->dbm_blkno;
	if (dbm_defwrite(db)) {
		dbm_setdirty(db);
	}
	else {
	(void) lseek(db->dbm_pagf, (long)(db->dbm_blkno*PBLKSIZ), L_SET);
	if (write(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ) {
	err:
		db->dbm_flags |= _DBM_IOERR;
		return (-1);
	}
	}
	return (0);
}

int
dbm_store(DBM *db, datum key, datum dat, int replace)
{
	int i;
	datum item, item1;
	char ovfbuf[PBLKSIZ];

	if (dbm_error(db))
		return (-1);
	if (dbm_rdonly(db)) {
		errno = EPERM;
		return (-1);
	}
loop:
	dbm_access(db, dcalchash(key));
	if ((i = finddatum(db->dbm_pagbuf, key)) >= 0) {
		if (!replace)
			return (1);
		if (!delitem(db->dbm_pagbuf, i)) {
			db->dbm_flags |= _DBM_IOERR;
			return (-1);
		}
	}
	if (!additem(db->dbm_pagbuf, key, dat))
		goto split;
	db->dbm_pagbno = db->dbm_blkno;
	if (dbm_defwrite(db)) {
		dbm_setdirty(db);
	}
	else {

		(void) lseek(db->dbm_pagf, (long)(db->dbm_blkno*PBLKSIZ), L_SET);
		if (write(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ) {
			db->dbm_flags |= _DBM_IOERR;
			return (-1);
		}
	}
	return (0);

split:
	if (key.dsize+dat.dsize+3*sizeof(short) >= PBLKSIZ) {
		db->dbm_flags |= _DBM_IOERR;
		errno = ENOSPC;
		return (-1);
	}
	bzero(ovfbuf, PBLKSIZ);
	for (i=0;;) {
		item = makdatum(db->dbm_pagbuf, i);
		if (item.dptr == NULL)
			break;
		if (dcalchash(item) & (db->dbm_hmask+1)) {
			item1 = makdatum(db->dbm_pagbuf, i+1);
			if (item1.dptr == NULL) {
				/*(void) fprintf(stderr, "ndbm: split not paired\n");*/
				db->dbm_flags |= _DBM_IOERR;
				break;
			}
			if (!additem(ovfbuf, item, item1) ||
			    !delitem(db->dbm_pagbuf, i)) {
				db->dbm_flags |= _DBM_IOERR;
				return (-1);
			}
			continue;
		}
		i += 2;
	}
	db->dbm_pagbno = db->dbm_blkno;
	(void) lseek(db->dbm_pagf, (long)(db->dbm_blkno*PBLKSIZ), L_SET);
	if (write(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ) {
		db->dbm_flags |= _DBM_IOERR;
		return (-1);
	}
	dbm_clrdirty(db); /*clear dirty*/
	(void) lseek(db->dbm_pagf,
		(long)((db->dbm_blkno+db->dbm_hmask+1)*PBLKSIZ), L_SET);
	if (write(db->dbm_pagf, ovfbuf, PBLKSIZ) != PBLKSIZ) {
		db->dbm_flags |= _DBM_IOERR;
		return (-1);
	}
	if (setbit(db) < 0) {
		db->dbm_flags |= _DBM_IOERR;
		return (-1);
	}
	goto loop;
}

static long
dbm_hashinc(DBM *db, long hash)
{

	long bit;

	hash &= db->dbm_hmask;
	bit = db->dbm_hmask+1;
	for(;;) {
		bit >>= 1;
		if(bit == 0)
			return(0L);
		if((hash&bit) == 0)
			return(hash|bit);
		hash &= ~bit;
	}
}



static datum nullkey= {NULL, 0};

datum
dbm_firsthash(DBM *db, long hash)
{
	int i,j;
	datum item, bitem;

loop:
	dbm_access(db, hash);
	j=0;
	bitem = makdatum(db->dbm_pagbuf, 0);
	for(i=2;; i+=2) {
		item = makdatum(db->dbm_pagbuf, i);
		if(item.dptr == NULL)
			break;
		if(cmpdatum(bitem, item) < 0) {
			j=i;
			bitem = item;
			}
	}
	if(bitem.dptr != NULL) {
	        db->dbm_keyptr = j + 2;
	        db->dbm_blkptr = db->dbm_blkno;
		return(bitem);
	}
	hash = dbm_hashinc(db,hash);
	if(hash == 0)
		return(item); /*null item*/
	goto loop;

}

datum
dbm_firstkey(DBM *db)
{

	db->dbm_blkptr = 0L;
	db->dbm_keyptr = 0;
	return (dbm_firsthash(db, 0L));
}

datum
dbm_nextkey(DBM *db)
{

	return (dbm_do_nextkey(db, nullkey));
}

/*this is used if keyptr-2,blocknum doesn't point to the previous
specific key allowing the fast hash order search --
its use indicates user tampering with our state variables,
which some evil users might do to search from some specific place.
It finds the first key at or after blkptr,keyptr in block seq order
this requires looking at all sorts of emtpy blocks in many cases*/

static datum
dbm_slow_nextkey(DBM *db)
{
	struct stat statb;
	datum item;

	if (dbm_error(db) || fstat(db->dbm_pagf, &statb) < 0)
		goto err;
	statb.st_size /= PBLKSIZ;

	for (;;) {
		if (db->dbm_blkptr != db->dbm_pagbno) {

			if (dbm_dirty(db)) dbm_flushpag(db);

			db->dbm_pagbno = db->dbm_blkptr;
			(void) lseek(db->dbm_pagf, (long)(db->dbm_blkptr*PBLKSIZ), L_SET);
			if (read(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ)
				bzero(db->dbm_pagbuf, PBLKSIZ);
#ifdef DEBUG
			else if (chkblk(db->dbm_pagbuf) < 0)
				db->dbm_flags |= _DBM_IOERR;
#endif
		}
		/*Am I an empty block?*/
		if (((short *)db->dbm_pagbuf)[0] != 0) {
			item = makdatum(db->dbm_pagbuf, db->dbm_keyptr);
			if (item.dptr != NULL) {
				db->dbm_keyptr += 2;
				return (item);
			}
			db->dbm_keyptr = 0;
		}
		/*go to next sequential block*/
		if (++db->dbm_blkptr >= statb.st_size)
			break;
	}
err:
	item.dptr = NULL;
	item.dsize = 0;
	return (item);
}

datum
dbm_do_nextkey(DBM *db, datum inkey)
{
	datum item,bitem;
	long hash;
	datum key;
	int f;
	int i;
	int j;
	short *sp;
	int n;
	char *p1, *p2;

	if ( dbm_error(db) ) {
		item.dptr = NULL;
		item.dsize = 0;
		return (item);
	}

	/*user has supplied lastkey*/

	if(inkey.dptr != NULL) {
	       dbm_access(db, (hash=dcalchash(inkey)));
	       if ((i = finddatum(db->dbm_pagbuf, inkey)) >= 0) {
		       db->dbm_keyptr = i + 2;
		       db->dbm_blkptr = db->dbm_blkno;
	       }
	       key=inkey;
       }
       else  {
		/*is this a manual firstkey request? */

		if (db->dbm_blkptr == 0L &&
			db->dbm_keyptr == 0)
			return (dbm_firsthash(db, 0L));

		/*no -- get lastkey this is like dbm_access by blkptr*/

		if (db->dbm_blkptr != db->dbm_pagbno) {

			if (dbm_dirty(db)) dbm_flushpag(db);
			db->dbm_pagbno = db->dbm_blkptr;
			(void) lseek(db->dbm_pagf, (long)(db->dbm_blkptr*PBLKSIZ), L_SET);
			if (read(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ)
				bzero(db->dbm_pagbuf, PBLKSIZ);
#ifdef DEBUG
			else if (chkblk(db->dbm_pagbuf) < 0)
			db->dbm_flags |= _DBM_IOERR;
#endif
		}
		/*now just make up last key datum*/
		if (db->dbm_keyptr >=2) key= makdatum(db->dbm_pagbuf,(db->dbm_keyptr-2));
		else key=nullkey;

	/* the keyptr pagbuf have failed us, the user must
	depend on these variables and their former meaning.
	If we set the variables this would have got
	us the key for sure! So give the user the old algorithm.*/
		if (key.dptr == NULL) return (dbm_slow_nextkey(db));
	}

	/*at this point the last key is paged in and
	we can proceed as in old dbm -- like Ken did his. */

	f = 1;
	j=0;
	sp = (short *)db->dbm_pagbuf;

	for(i=0;; i+=2) {

		/*begin put makdatum inline*/

		if ((unsigned)i >= sp[0]) {
			item.dptr = NULL;
			item.dsize = 0;
			break; /*from below*/
		}
		else {
			if (i > 0) item.dsize = sp[i] - sp[i+1];
			else item.dsize = PBLKSIZ - sp[i+1];
			item.dptr = db->dbm_pagbuf+sp[i+1];
		}

		/*	item = makdatum(db->dbm_pagbuf, i);*/
		/*end put makdatum inline*/

		if(item.dptr == NULL)
			break;
/*inline cmpdatum*/


		n = key.dsize;
		if(n != item.dsize)
			if( (n - item.dsize) <= 0 ) continue;
			else { }
		else {
			if(n == 0) continue;
			p1 = key.dptr;
			p2 = item.dptr;
			do
				if(*p1++ != *p2++)
					if((*--p1 - *--p2) > 0) goto keep_going;
					else continue;
			while(--n);
			continue;
			}

keep_going:

/*end inline cmpdatum*/
		/*if(cmpdatum(key, item) <= 0)
			continue;*/
		if (f) {
			bitem = item;
			j=i;
			f = 0;
		}
		else {

/*		if(cmpdatum(bitem, item) < 0)*/

		n = bitem.dsize;
		if(n != item.dsize)
			{
			if((n - item.dsize) <0) {
					bitem = item;
					j=i;
				}
			}
			else  if (n != 0) {
				p1 = bitem.dptr;
				p2 = item.dptr;
				do
				if(*p1++ != *p2++) {
					if((*--p1 - *--p2) <0) {
						bitem = item;
						j=i;
					}
					break;
				}
				while(--n);
			}
		}
	}

	if(f == 0) {
	        db->dbm_keyptr = j + 2;
	        db->dbm_blkptr = db->dbm_blkno;
		return (bitem);
	}

	/* really need hash at this point */
	/* if it gave us a key we have already calculated the hash */
	/* if not get the hash */
	if (inkey.dptr == NULL) hash=dcalchash(key);
	hash = dbm_hashinc(db,hash);

	if(hash == 0)
		return (item); /*null*/
	/*get first item on next page in hash table order*/
	return (dbm_firsthash(db, hash));


}

static void
dbm_access(DBM *db, long hash)
{
	int b, i, n;
	long bn;
	long my_bitno;
	long my_hmask;
	long my_blkno;

	for (my_hmask=0;; my_hmask=(my_hmask<<1)+1) {
		my_blkno = hash & my_hmask;
		my_bitno = my_blkno + my_hmask;
		/*getbit inline*/
		if (my_bitno > db->dbm_maxbno) break;
		n = my_bitno % BYTESIZ;
		bn = my_bitno / BYTESIZ;
		i = bn % DBLKSIZ;
		b = bn / DBLKSIZ;
		if (b != db->dbm_dirbno) {
			if (dbm_dirdirty(db)) dbm_flushdir(db); /*must flush*/
			db->dbm_dirbno = b;
			(void) lseek(db->dbm_dirf, (long)(b*DBLKSIZ), L_SET);
			if (read(db->dbm_dirf, db->dbm_dirbuf, DBLKSIZ) != DBLKSIZ)
				bzero(db->dbm_dirbuf, DBLKSIZ);
		}
		if ( (db->dbm_dirbuf[i] & (1<<n)) == 0 ) break;

		/*
		if (getbit(db) == 0)
			break;
		*/
	}
	/*copy*/
	db->dbm_blkno=my_blkno;
	db->dbm_bitno=my_bitno;
	db->dbm_hmask=my_hmask;

	if (my_blkno != db->dbm_pagbno) {
		if (dbm_dirty(db)){ /*must page out the page*/
			(void) lseek(db->dbm_pagf, (long)(db->dbm_pagbno*PBLKSIZ), L_SET);
			if (write(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ) {
				db->dbm_flags |= _DBM_IOERR;
			}
		dbm_clrdirty(db);
		}

		db->dbm_pagbno = my_blkno;
		(void) lseek(db->dbm_pagf, (long)(my_blkno*PBLKSIZ), L_SET);
		if (read(db->dbm_pagf, db->dbm_pagbuf, PBLKSIZ) != PBLKSIZ)
			bzero(db->dbm_pagbuf, PBLKSIZ);
#ifdef DEBUG
		else if (chkblk(db->dbm_pagbuf) < 0)
			db->dbm_flags |= _DBM_IOERR;
#endif
	}
}

static int
getbit(DBM *db)
{
	long bn;
	int b, i, n;


	if (db->dbm_bitno > db->dbm_maxbno)
		return (0);
	n = db->dbm_bitno % BYTESIZ;
	bn = db->dbm_bitno / BYTESIZ;
	i = bn % DBLKSIZ;
	b = bn / DBLKSIZ;
	if (b != db->dbm_dirbno) {
		if (dbm_dirdirty(db)) dbm_flushdir(db); /*must flush*/
		db->dbm_dirbno = b;
		(void) lseek(db->dbm_dirf, (long)(b*DBLKSIZ), L_SET);
		if (read(db->dbm_dirf, db->dbm_dirbuf, DBLKSIZ) != DBLKSIZ)
			bzero(db->dbm_dirbuf, DBLKSIZ);
	}
	return (db->dbm_dirbuf[i] & (1<<n));
}

static int
setbit(DBM *db)
{
	long bn;
	int i, n, b;

	if (db->dbm_bitno > db->dbm_maxbno)
		db->dbm_maxbno = db->dbm_bitno;
	n = db->dbm_bitno % BYTESIZ;
	bn = db->dbm_bitno / BYTESIZ;
	i = bn % DBLKSIZ;
	b = bn / DBLKSIZ;
	if (b != db->dbm_dirbno) {
		if (dbm_dirdirty(db)) dbm_flushdir(db);
		db->dbm_dirbno = b;
		(void) lseek(db->dbm_dirf, (long)(b*DBLKSIZ), L_SET);
		if (read(db->dbm_dirf, db->dbm_dirbuf, DBLKSIZ) != DBLKSIZ)
			bzero(db->dbm_dirbuf, DBLKSIZ);
	}
	db->dbm_dirbuf[i] |= 1<<n;
	db->dbm_dirbno = b;
	if (dbm_defwrite(db)) {
	dbm_setdirdirty(db);
	} else{
	(void) lseek(db->dbm_dirf, (long)(b*DBLKSIZ), L_SET);
	if (write(db->dbm_dirf, db->dbm_dirbuf, DBLKSIZ) != DBLKSIZ) {
		return (-1);
	}
	}
	return (0);
}

static datum
makdatum(char buf[PBLKSIZ], int n)
{
	short *sp;
	int t;
	datum item;

	sp = (short *)buf;
	if ((unsigned)n >= sp[0]) {
		item.dptr = NULL;
		item.dsize = 0;
		return (item);
	}
	t = PBLKSIZ;
	if (n > 0)
		t = sp[n];
	item.dptr = buf+sp[n+1];
	item.dsize = t - sp[n+1];
	return (item);
}

static int
cmpdatum(datum d1, datum d2)
{
	int n;
	char *p1, *p2;

	n = d1.dsize;
	if(n != d2.dsize)
		return(n - d2.dsize);
	if(n == 0)
		return(0);
	p1 = d1.dptr;
	p2 = d2.dptr;
	do
		if(*p1++ != *p2++)
			return(*--p1 - *--p2);
	while(--n);
	return(0);
}

static int
finddatum(char buf[PBLKSIZ], datum item)
{
	short *sp;
	int i, n, j;

	sp = (short *)buf;
	n = PBLKSIZ;
	for (i=0, j=sp[0]; i<j; i+=2, n = sp[i]) {
		n -= sp[i+1];
		if (n != item.dsize)
			continue;
		if (n == 0 || bcmp(&buf[sp[i+1]], item.dptr, n) == 0)
			return (i);
	}
	return (-1);
}

static  int hitab[16]
 = {    61, 57, 53, 49, 45, 41, 37, 33,
	29, 25, 21, 17, 13,  9,  5,  1,
};

static  long hltab[64]
 = {
	06100151277L,06106161736L,06452611562L,05001724107L,
	02614772546L,04120731531L,04665262210L,07347467531L,
	06735253126L,06042345173L,03072226605L,01464164730L,
	03247435524L,07652510057L,01546775256L,05714532133L,
	06173260402L,07517101630L,02431460343L,01743245566L,
	00261675137L,02433103631L,03421772437L,04447707466L,
	04435620103L,03757017115L,03641531772L,06767633246L,
	02673230344L,00260612216L,04133454451L,00615531516L,
	06137717526L,02574116560L,02304023373L,07061702261L,
	05153031405L,05322056705L,07401116734L,06552375715L,
	06165233473L,05311063631L,01212221723L,01052267235L,
	06000615237L,01075222665L,06330216006L,04402355630L,
	01451177262L,02000133436L,06025467062L,07121076461L,
	03123433522L,01010635225L,01716177066L,05161746527L,
	01736635071L,06243505026L,03637211610L,01756474365L,
	04723077174L,03642763134L,05750130273L,03655541561L,
};

static long
dcalchash(datum item)
{
	int s, c, j;
	char *cp;
	long hashl;
	int hashi;

	hashl = 0;
	hashi = 0;
	for (cp = item.dptr, s=item.dsize; --s >= 0; ) {
		c = *cp++;
		for (j=0; j<BYTESIZ; j+=4) {
			hashi += hitab[c&017];
			hashl += hltab[hashi&63];
			c >>= 4;
		}
	}
	return (hashl);
}

/*
 * Delete pairs of items (n & n+1).
 */
static int
delitem(char buf[PBLKSIZ], int n)
{
	short *sp, *sp1;
	int i1, i2;

	sp = (short *)buf;
	i2 = sp[0];
	if ((unsigned)n >= i2 || (n & 1))
		return (0);
	if (n == i2-2) {
		sp[0] -= 2;
		return (1);
	}
	i1 = PBLKSIZ;
	if (n > 0)
		i1 = sp[n];
	i1 -= sp[n+2];
	if (i1 > 0) {
		i2 = sp[i2];
		bcopy(&buf[i2], &buf[i2 + i1], sp[n+2] - i2);
	}
	sp[0] -= 2;
	for (sp1 = sp + sp[0], sp += n+1; sp <= sp1; sp++)
		sp[0] = sp[2] + i1;
	return (1);
}

/*
 * Add pairs of items (item & item1).
 */
static int
additem(char buf[PBLKSIZ], datum item, datum item1)
{
	short *sp;
	int i1, i2;

	sp = (short *)buf;
	i1 = PBLKSIZ;
	i2 = sp[0];
	if (i2 > 0)
		i1 = sp[i2];
	i1 -= item.dsize + item1.dsize;
	if (i1 <= (i2+3) * sizeof(short))
		return (0);
	sp[0] += 2;
	sp[++i2] = i1 + item1.dsize;
	bcopy(item.dptr, &buf[i1 + item1.dsize], item.dsize);
	sp[++i2] = i1;
	bcopy(item1.dptr, &buf[i1], item1.dsize);
	return (1);
}

#ifdef DEBUG
static int
chkblk(char buf[PBLKSIZ])
{
	short *sp;
	int t, i;

	sp = (short *)buf;
	t = PBLKSIZ;
	for (i=0; i<sp[0]; i++) {
		if (sp[i+1] > t)
			return (-1);
		t = sp[i+1];
	}
	if (t < (sp[0]+1)*sizeof(short))
		return (-1);
	return (0);
}
#endif
