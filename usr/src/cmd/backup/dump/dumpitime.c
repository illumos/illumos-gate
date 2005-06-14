/*
 * Copyright 1996-1998, 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dump.h"

#ifndef LOCK_EX
static 	struct flock fl;
#define	flock(fd, flag) (fl.l_type = (flag), fcntl(fd, F_SETLKW, &fl))
#define	LOCK_EX F_WRLCK
#define	LOCK_SH F_RDLCK
#define	LOCK_UN F_UNLCK
#endif

/*
 * Print a date.  A date of 0 is the beginning of time (the "epoch").
 * If the 2nd argument is non-zero, it is ok to format the date in
 * locale-specific form, otherwise we use ctime.  We must use ctime
 * for dates such as those in the dumpdates file, which must be
 * locale-independent.
 */
char *
prdate(d)
	time_t	d;
{
	static char buf[256];
	struct tm *tm;
	char *p;

	if (d == 0)
		return (gettext("the epoch"));

	tm = localtime(&d);
	if (strftime(buf, sizeof (buf), "%c", tm) != 0) {
		p = buf;
	} else {
		/* Wouldn't fit in buf, fall back */
		p = ctime(&d);
		p[24] = '\0';	/* lose trailing newline */
	}
	return (p);
}

struct	idates	**idatev = 0;
size_t	nidates = 0;
static	int	idates_in = 0;		/* we have read the increment file */
static	int	recno;

#ifdef __STDC__
static void readitimes(FILE *);
static void recout(FILE	*, struct idates *);
static int getrecord(FILE *, struct idates *);
static int makeidate(struct idates *, char *);
#else
static void readitimes();
static void recout();
static int getrecord();
static int makeidate();
#endif

void
#ifdef __STDC__
inititimes(void)
#else
inititimes()
#endif
{
	FILE *df;
	int saverr;

	if (idates_in)
		return;
	if (increm == NULL || *increm == '\0') {
		msg(gettext("inititimes: No dump record file name defined\n"));
		dumpabort();
		/*NOTREACHED*/
	}
	/*
	 * No need to secure this, as increm is hard-coded to NINCREM,
	 * and that file is in /etc.  If random people have write-permission
	 * there, then there are more problems than any degree of paranoia
	 * on our part can fix.
	 */
	if ((df = fopen(increm, "r")) == NULL) {
		saverr = errno;
		if (errno == ENOENT)
			msg(gettext(
			    "Warning - dump record file `%s' does not exist\n"),
				increm);
		else {
			msg(gettext("Cannot open dump record file `%s': %s\n"),
				increm, strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		return;
	}
	if (uflag && access(increm, W_OK) < 0) {
		msg(gettext("Cannot access dump record file `%s' for update\n"),
		    increm);
		dumpabort();
		/*NOTREACHED*/
	}
	(void) flock(fileno(df), LOCK_SH);
	readitimes(df);
	(void) fclose(df);
}

static void
readitimes(df)
	FILE *df;
{
	struct idates *idp;

	recno = 0;
	for (;;) {
		idp = (struct idates *)xcalloc(1, sizeof (*idp));
		if (getrecord(df, idp) < 0) {
			free((char *)idp);
			break;
		}
		nidates++;
		idatev = (struct idates **)xrealloc((void *)idatev,
		    nidates * (size_t)sizeof (*idatev));
		idatev[nidates - 1] = idp;
	}
	/* LINTED: assigned value is used in inititimes */
	idates_in = 1;
}

void
#ifdef __STDC__
getitime(void)
#else
getitime()
#endif
{
	struct	idates	*ip;
	int	i;
	char	*fname;

	/*
	 * if an alternate name was specified via the N flag, use it instead
	 * of the disk name.
	 */
	if (dname != NULL)
		fname = dname;
	else
		fname = disk;

#ifdef FDEBUG

	/* XGETTEXT:  #ifdef FDEBUG only */
	msg(gettext("Looking for name %s in increm = %s for delta = %c\n"),
		fname, increm, (uchar_t)incno);
#endif
	spcl.c_ddate = 0;
	lastincno = '0';

	inititimes();
	if (idatev == 0)
		return;
	/*
	 *	Go find the entry with the same name for a lower increment
	 *	and older date
	 */
	ITITERATE(i, ip) {
		if (strncmp(fname, ip->id_name, sizeof (ip->id_name)) != 0)
			continue;
		if (ip->id_incno >= incno)
			continue;
		if (ip->id_ddate <= spcl.c_ddate)
			continue;
		spcl.c_ddate = ip->id_ddate;
		lastincno = ip->id_incno;
	}
}

void
#ifdef __STDC__
putitime(void)
#else
putitime()
#endif
{
	FILE		*df;
	struct	idates	*itwalk;
	int		i;
	int		fd, saverr;
	char		*fname;

	if (uflag == 0)
		return;
	if ((df = safe_fopen(increm, "r+", 0664)) == (FILE *)NULL) {
		msg("%s: %s\n", increm, strerror(errno));
		(void) unlink(increm);
		dumpabort();
		/*NOTREACHED*/
	}
	fd = fileno(df);
	(void) flock(fd, LOCK_EX);

	/*
	 * if an alternate name was specified via the N flag, use it instead
	 * of the disk name.
	 */
	if (dname != NULL)
		fname = dname;
	else
		fname = disk;

	if (idatev != 0) {
		for (i = 0; i < nidates && idatev[i] != 0; i++)
			free((char *)idatev[i]);
		free((char *)idatev);
	}
	idatev = 0;
	nidates = 0;
	readitimes(df);
	if (fseek(df, 0L, 0) < 0) {   /* rewind() was redefined in dumptape.c */
		saverr = errno;
		msg(gettext("%s: %s error:\n"),
			increm, "fseek", strerror(saverr));
		dumpabort();
		/*NOTREACHED*/
	}
	spcl.c_ddate = 0;
	/* LINTED: won't dereference idatev if it is NULL (see readitimes) */
	ITITERATE(i, itwalk) {
		if (strncmp(fname, itwalk->id_name,
				sizeof (itwalk->id_name)) != 0)
			continue;
		if (itwalk->id_incno != incno)
			continue;
		goto found;
	}
	/*
	 *	Add one more entry to idatev
	 */
	nidates++;
	idatev = (struct idates **)xrealloc((void *)idatev,
		nidates * (size_t)sizeof (struct idates *));
	itwalk = idatev[nidates - 1] =
	    (struct idates *)xcalloc(1, sizeof (*itwalk));
found:
	(void) strncpy(itwalk->id_name, fname, sizeof (itwalk->id_name));
	itwalk->id_name[sizeof (itwalk->id_name) - 1] = '\0';
	itwalk->id_incno = incno;
	itwalk->id_ddate = spcl.c_date;

	ITITERATE(i, itwalk) {
		recout(df, itwalk);
	}
	if (ftruncate64(fd, ftello64(df))) {
		saverr = errno;
		msg(gettext("%s: %s error:\n"),
		    increm, "ftruncate64", strerror(saverr));
		dumpabort();
		/*NOTREACHED*/
	}
	(void) fclose(df);
	msg(gettext("Level %c dump on %s\n"),
	    (uchar_t)incno, prdate(spcl.c_date));
}

static void
recout(file, what)
	FILE	*file;
	struct	idates	*what;
{
	time_t ddate = what->id_ddate;
	/* must use ctime, so we can later use unctime() */
	(void) fprintf(file, DUMPOUTFMT,
		what->id_name,
		(uchar_t)what->id_incno,
		ctime(&ddate));
}

static int
getrecord(df, idatep)
	FILE	*df;
	struct	idates	*idatep;
{
	char		buf[BUFSIZ];

	if ((fgets(buf, BUFSIZ, df)) != buf)
		return (-1);
	recno++;
	if (makeidate(idatep, buf) < 0) {
		msg(gettext(
		    "Malformed entry in dump record file `%s', line %d\n"),
			increm, recno);
		if (strcmp(increm, NINCREM)) {
			msg(gettext("`%s' not a dump record file\n"), increm);
			dumpabort();
			/*NOTREACHED*/
		}
		return (-1);
	}

#ifdef FDEBUG
	msg("getrecord: %s %c %s\n",
		idatep->id_name,
		(uchar_t)idatep->id_incno,
		prdate(idatep->id_ddate));
#endif
	return (0);
}

static int
makeidate(ip, buf)
	struct	idates	*ip;
	char	*buf;
{
	char	un_buf[128];	/* size must be >= second one in DUMPINFMT */

	/*
	 * MAXNAMLEN has different values in dirent.h and ufs_fsdir.h,
	 * and we need to ensure that the length in DUMPINFMT matches
	 * what we allow for.  Can't just use MAXNAMLEN in the test,
	 * because there's no convenient way to substitute it into
	 * DUMPINFMT.
	 * XXX There's got to be a better way.
	 */
	/*LINTED [assertion always true]*/
	assert(sizeof (ip->id_name) == (255 + 3));

	if (sscanf(buf, DUMPINFMT, ip->id_name, &ip->id_incno, un_buf) != 3)
		return (-1);
	/* LINTED casting from 64-bit to 32-bit time */
	ip->id_ddate = (time32_t)unctime(un_buf);
	if (ip->id_ddate < 0)
		return (-1);
	return (0);
}

/*
 * This is an estimation of the number of tp_bsize blocks in the file.
 * It estimates the number of blocks in files with holes by assuming
 * that all of the blocks accounted for by di_blocks are data blocks
 * (when some of the blocks are usually used for indirect pointers);
 * hence the estimate may be high.
 */
void
est(ip)
	struct dinode *ip;
{
	u_offset_t s, t;

	/*
	 * ip->di_size is the size of the file in bytes.
	 * ip->di_blocks stores the number of sectors actually in the file.
	 * If there are more sectors than the size would indicate, this just
	 *	means that there are indirect blocks in the file or unused
	 *	sectors in the last file block; we can safely ignore these
	 *	(s = t below).
	 * If the file is bigger than the number of sectors would indicate,
	 *	then the file has holes in it.	In this case we must use the
	 *	block count to estimate the number of data blocks used, but
	 *	we use the actual size for estimating the number of indirect
	 *	dump blocks (t vs. s in the indirect block calculation).
	 */
	o_esize++;
	s = (unsigned)(ip->di_blocks) / (unsigned)(tp_bsize / DEV_BSIZE);
	/* LINTED: spurious complaint about sign-extending 32 to 64 bits */
	t = d_howmany(ip->di_size, (unsigned)tp_bsize);
	if (s > t)
		s = t;
	if (ip->di_size > (u_offset_t)((unsigned)(sblock->fs_bsize) * NDADDR)) {
		/* calculate the number of indirect blocks on the dump tape */
		/* LINTED: spurious complaint sign-extending 32 to 64 bits */
		s += d_howmany(t -
			(unsigned)(NDADDR * sblock->fs_bsize / tp_bsize),
			(unsigned)TP_NINDIR);
	}
	f_esize += s;
}

/*ARGSUSED*/
void
bmapest(map)
	uchar_t *map;
{
	o_esize++;
	/* LINTED: spurious complaint sign-extending 32 to 64 bits */
	f_esize += d_howmany(msiz * sizeof (map[0]), (unsigned)tp_bsize);
}


/*
 * Check to see if what we are trying to dump is a fs snapshot
 * If so, we can use the snapshot's create time to populate
 * the dumpdates file, instead of the time of the dump.
 */
time32_t
is_fssnap_dump(char *disk)
{
	struct stat st;
	char *last;
	int snapnum;
	kstat_ctl_t *kslib;
	kstat_t *ksnum;
	kstat_named_t *numval;

	last = basename(disk);
	if ((strstr(disk, SNAP_NAME) == NULL) || (stat(disk, &st) == -1) ||
	    (isdigit(last[0]) == 0))
		return (0);

	snapnum = atoi(last);

	if ((kslib = kstat_open()) == NULL)
		return (0);

	ksnum = kstat_lookup(kslib, SNAP_NAME, snapnum, FSSNAP_KSTAT_NUM);
	if (ksnum == NULL) {
		(void) kstat_close(kslib);
		return (0);
	}

	if (kstat_read(kslib, ksnum, NULL) == -1) {
		(void) kstat_close(kslib);
		return (0);
	}

	numval = kstat_data_lookup(ksnum, FSSNAP_KSTAT_NUM_CREATETIME);
	if (numval == NULL) {
		(void) kstat_close(kslib);
		return (0);
	}

	(void) kstat_close(kslib);
	/* LINTED casting from long to 32-bit time */
	return (time32_t)(numval->value.l & INT_MAX);
}
