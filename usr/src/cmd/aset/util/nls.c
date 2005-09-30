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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * List files or directories
 */

#define	_FILE_OFFSET_BITS 64
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/acl.h>

#include <wchar.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <locale.h>
#include <curses.h>
#include <termios.h>
#include <stdlib.h>
#include <widec.h>
#include <locale.h>
#include <wctype.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>

#ifndef STANDALONE
#define	TERMINFO
#endif

/*
 * -DNOTERMINFO can be defined on the cc command line to prevent
 * the use of terminfo.  This should be done on systems not having
 * the terminfo feature(pre 6.0 sytems ?).
 * As a result, columnar listings assume 80 columns for output,
 * unless told otherwise via the COLUMNS environment variable.
 */
#ifdef NOTERMINFO
#undef TERMINFO
#endif

#include <term.h>

#define	BFSIZE	16
/* this bit equals 1 in lflags of structure lbuf if *namep is to be used */
#define	ISARG	0100000

/*
 * Date and time formats
 *
 * b --- abbreviated month name
 * e --- day number
 * Y --- year in the form ccyy
 * H --- hour(24-hour version)
 * M --- minute
 */
#define	FORMAT1	 " %b %e  %Y "
#define	FORMAT2  " %b %e %H:%M "
#define	FORMAT3  " %b %e %H:%M %Y "

#undef BUFSIZ
#define	BUFSIZ 4096

struct	lbuf	{
	union	{
		char	lname[MAXNAMLEN]; /* used for filename in a directory */
		char	*namep;		/* for name in ls-command; */
	} ln;
	char	ltype;		/* filetype */
	ino_t	lnum;		/* inode number of file */
	mode_t	lflags; 	/* 0777 bits used as r,w,x permissions */
	nlink_t	lnl;		/* number of links to file */
	uid_t	luid;
	gid_t	lgid;
	off_t	lsize;		/* filesize or major/minor dev numbers */
	blkcnt_t	lblocks;	/* number of file blocks */
	time_t	lmtime;
	char	*flinkto;	/* symbolic link contents */
	char 	acl;		/* indicate there are additional acl entries */
};

struct dchain {
	char *dc_name;		/* path name */
	struct dchain *dc_next;	/* next directory in the chain */
};

static struct dchain *dfirst;	/* start of the dir chain */
static struct dchain *cdfirst;	/* start of the durrent dir chain */
static struct dchain *dtemp;	/* temporary - used for linking */
static char *curdir;		/* the current directory */

static int	first = 1;	/* true if first line is not yet printed */
static int	nfiles = 0;	/* number of flist entries in current use */
static int	nargs = 0;	/* number of flist entries used for arguments */
static int	maxfils = 0;	/* number of flist/lbuf entries allocated */
static int	maxn = 0;	/* number of flist entries with lbufs asigned */
static int	quantn = 64;	/* allocation growth quantum */

static struct lbuf	*nxtlbf;	/* ptr to next lbuf to be assigned */
static struct lbuf	**flist;	/* ptr to list of lbuf pointers */
static struct lbuf	*gstat(char *, int);
static char		*getname(uid_t);
static char		*getgroup(gid_t);
static char		*makename(char *, char *);
static void		pentry(struct lbuf *);
static void		column(void);
static void		pmode(mode_t aflag);
static void		selection(int *);
static void		new_line(void);
static void		rddir(char *);
static int		strcol(unsigned char *);
static void		pem(struct lbuf **, struct lbuf **, int);
static void		pdirectory(char *, int, int);
static struct cachenode *findincache(struct cachenode **, long);
static void		csi_pprintf(unsigned char *);
static void		pprintf(char *, char *);
static int		compar(struct lbuf **pp1, struct lbuf **pp2);

static int	aflg, bflg, cflg, dflg, fflg, gflg, iflg, lflg, mflg;
static int	nflg, oflg, pflg, qflg, sflg, tflg, uflg, xflg;
static int	Cflg, Fflg, Rflg, Lflg;
static int	Aflg;
static int	rflg = 1;	/* initialized to 1 for special use in compar */
static mode_t	flags;
static int	err = 0;	/* Contains return code */

static uid_t	lastuid	= (uid_t)-1;
static gid_t	lastgid = (gid_t)-1;
static char	*lastuname = NULL;
static char	*lastgname = NULL;
static int	statreq; /* is > 0 if any of sflg, (n)lflg, tflg are on */

static char	*dotp = ".";

static u_longlong_t tblocks; /* number of blocks of files in a directory */
static time_t	year, now;

static int	num_cols = 80;
static int	colwidth;
static int	filewidth;
static int	fixedwidth;
static int	nomocore;
static int	curcol;

static struct	winsize	win;

static char	time_buf[50];	/* array to hold day and time */

int
main(int argc, char *argv[])
{
	int		c;
	int		i;
	int		width;
	int		amino = 0;
	int		opterr = 0;
	struct lbuf	*ep;
	struct lbuf	lb;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
#ifdef STANDALONE
	if (argv[0][0] == '\0')
		argc = getargv("ls", &argv, 0);
#endif

	lb.lmtime = time(NULL);
	year = lb.lmtime - 6L*30L*24L*60L*60L; /* 6 months ago */
	now = lb.lmtime + 60;
	if (isatty(1)) {
		Cflg = 1;
		mflg = 0;
	}


	while ((c = getopt(argc, argv, "RaAdC1xmnlogrtucpFbqisfL")) != EOF)
		switch (c) {
		case 'R':
			Rflg++;
			statreq++;
			continue;
		case 'A':
			Aflg++;
			continue;
		case 'a':
			aflg++;
			continue;
		case 'd':
			dflg++;
			continue;
		case 'C':
			Cflg = 1;
			mflg = 0;
#ifdef XPG4
			lflg = 0;
#endif
			continue;
		case '1':
			Cflg = 0;
			continue;
		case 'x':
			xflg = 1;
			Cflg = 1;
			mflg = 0;
#ifdef XPG4
			lflg = 0;
#endif
			continue;
		case 'm':
			Cflg = 0;
			mflg = 1;
#ifdef XPG4
			lflg = 0;
#endif
			continue;
		case 'n':
			nflg++;
			/* FALLTHROUGH */
		case 'l':
			lflg++;
			statreq++;
			Cflg = 0;
			xflg = 0;
			mflg = 0;
			continue;
		case 'o':
			oflg++;
			lflg++;
			statreq++;
			continue;
		case 'g':
			gflg++;
			lflg++;
			statreq++;
			continue;
		case 'r':
			rflg = -1;
			continue;
		case 't':
			tflg++;
			statreq++;
			continue;
		case 'u':
			cflg = 0;
			uflg++;
			continue;
		case 'c':
			uflg = 0;
			cflg++;
			continue;
		case 'p':
			pflg++;
			statreq++;
			continue;
		case 'F':
			Fflg++;
			statreq++;
			continue;
		case 'b':
			bflg = 1;
			qflg = 0;
			continue;
		case 'q':
			qflg = 1;
			bflg = 0;
			continue;
		case 'i':
			iflg++;
			continue;
		case 's':
			sflg++;
			statreq++;
			continue;
		case 'f':
			fflg++;
			continue;
		case 'L':
			Lflg++;
			continue;
		case '?':
			opterr++;
			continue;
		}
	if (opterr) {
		(void) fprintf(stderr, gettext(
		    "usage: ls -1RaAdCxmnlogrtucpFbqisfL [files]\n"));
		return (2);
	}

	if (fflg) {
		aflg++;
		lflg = 0;
		sflg = 0;
		tflg = 0;
		statreq = 0;
	}

	fixedwidth = 2;
	if (pflg || Fflg)
		fixedwidth++;
	if (iflg)
		fixedwidth += 11;
	if (sflg)
		fixedwidth += 5;

	if (lflg) {
		if (!gflg && !oflg)
			gflg = oflg = 1;
		else
		if (gflg && oflg)
			gflg = oflg = 0;
		Cflg = mflg = 0;
	}

	if (Cflg || mflg) {
		char *clptr;
		if ((clptr = getenv("COLUMNS")) != NULL)
			num_cols = atoi(clptr);
#ifdef TERMINFO
		else {
			if (ioctl(1, TIOCGWINSZ, &win) != -1)
				num_cols = (win.ws_col == 0 ? 80 : win.ws_col);
		}
#endif
		if (num_cols < 20 || num_cols > 160)
			/* assume it is an error */
			num_cols = 80;
	}

	/* allocate space for flist and the associated	*/
	/* data structures (lbufs)			*/
	maxfils = quantn;
	if (((flist = malloc(maxfils * sizeof (struct lbuf *))) == NULL) ||
	    ((nxtlbf = malloc(quantn * sizeof (struct lbuf))) == NULL)) {
		perror("ls");
		return (2);
	}
	if ((amino = (argc-optind)) == 0) {
					/*
					 * case when no names are given
					 * in ls-command and current
					 * directory is to be used
					 */
		argv[optind] = dotp;
	}

	for (i = 0; i < (amino ? amino : 1); i++) {
		if (Cflg || mflg) {
			width = strcol((unsigned char *)argv[optind]);
			if (width > filewidth)
				filewidth = width;
		}
		if ((ep = gstat((*argv[optind] ? argv[optind] : dotp), 1))
		    == NULL) {
			if (nomocore)
				return (2);
			err = 2;
			optind++;
			continue;
		}
		ep->ln.namep = (*argv[optind] ? argv[optind] : dotp);
		ep->lflags |= ISARG;
		optind++;
		nargs++;	/* count good arguments stored in flist */
	}
	colwidth = fixedwidth + filewidth;
	qsort(flist, (unsigned)nargs, sizeof (struct lbuf *),
	    (int (*)(const void *, const void *))compar);
	for (i = 0; i < nargs; i++) {
		if (flist[i]->ltype == 'd' && dflg == 0 || fflg)
			break;
	}
	pem(&flist[0], &flist[i], 0);
	for (; i < nargs; i++) {
		pdirectory(flist[i]->ln.namep, Rflg || (amino > 1), nargs);
		if (nomocore)
			return (2);
		/* -R: print subdirectories found */
		while (dfirst || cdfirst) {
			/* Place direct subdirs on front in right order */
			while (cdfirst) {
				/* reverse cdfirst onto front of dfirst */
				dtemp = cdfirst;
				cdfirst = cdfirst -> dc_next;
				dtemp -> dc_next = dfirst;
				dfirst = dtemp;
			}
			/* take off first dir on dfirst & print it */
			dtemp = dfirst;
			dfirst = dfirst->dc_next;
			pdirectory(dtemp->dc_name, 1, nargs);
			if (nomocore)
				return (2);
			free(dtemp->dc_name);
			free(dtemp);
		}
	}
	return (err);
}

/*
 * pdirectory: print the directory name, labelling it if title is
 * nonzero, using lp as the place to start reading in the dir.
 */
static void
pdirectory(char *name, int title, int lp)
{
	struct dchain *dp;
	struct lbuf *ap;
	char *pname;
	int j;

	filewidth = 0;
	curdir = name;
	if (title) {
		if (!first)
			(void) putc('\n', stdout);
		pprintf(name, ":");
		new_line();
	}
	nfiles = lp;
	rddir(name);
	if (nomocore)
		return;
	if (fflg == 0)
		qsort(&flist[lp], (unsigned)(nfiles - lp),
		    sizeof (struct lbuf *),
		    (int (*)(const void *, const void *))compar);
	if (Rflg)
		for (j = nfiles - 1; j >= lp; j--) {
			ap = flist[j];
			if (ap->ltype == 'd' && strcmp(ap->ln.lname, ".") &&
			    strcmp(ap->ln.lname, "..")) {
				dp = (struct dchain *)calloc(1,
				    sizeof (struct dchain));
				if (dp == NULL) {
					perror("ls");
					exit(2);
				}
				pname = makename(curdir, ap->ln.lname);
				if ((dp->dc_name = strdup(pname)) == NULL) {
					perror("ls");
					exit(2);
				}
				dp->dc_next = dfirst;
				dfirst = dp;
			}
		}
	if (lflg || sflg)
		curcol += printf(gettext("total %llu"), tblocks);
	pem(&flist[lp], &flist[nfiles], lflg||sflg);
}

/*
 * pem: print 'em. Print a list of files (e.g. a directory) bounded
 * by slp and lp.
 */
static void
pem(struct lbuf **slp, struct lbuf **lp, int tot_flag)
{
	long row, nrows;
	int col, ncols;
	struct lbuf **ep;

	if (Cflg || mflg) {
		if (colwidth > num_cols) {
			ncols = 1;
		} else {
			ncols = num_cols / colwidth;
		}
	}

	if (ncols == 1 || mflg || xflg || !Cflg) {
		for (ep = slp; ep < lp; ep++)
			pentry(*ep);
		new_line();
		return;
	}
	/* otherwise print -C columns */
	if (tot_flag)
		slp--;
	nrows = (lp - slp - 1) / ncols + 1;
	for (row = 0; row < nrows; row++) {
		col = (row == 0 && tot_flag);
		for (; col < ncols; col++) {
			ep = slp + (nrows * col) + row;
			if (ep < lp)
				pentry(*ep);
		}
		new_line();
	}
}

/*
 * print one output entry;
 * if uid/gid is not found in the appropriate
 * file(passwd/group), then print uid/gid instead of
 * user/group name;
 */
static void
pentry(struct lbuf *ap)
{
	struct lbuf *p;
	char buf[BUFSIZ];
	char *dmark = "";	/* Used if -p or -F option active */
	char *cp;

	p = ap;
	column();
	if (iflg)
		if (mflg && !lflg)
			curcol += printf("%llu ", p->lnum);
		else
			curcol += printf((p->lnum < 10000000000ULL) ? "%10llu "
				: "%llu ", p->lnum);
	if (sflg)
		curcol += printf((mflg && !lflg) ? "%lld " :
			(p->lblocks < 10000) ? "%4lld " : "%lld ",
			(p->ltype != 'b' && p->ltype != 'c') ?
				p->lblocks : 0LL);
	if (lflg) {
		(void) putchar(p->ltype);
		curcol++;
		pmode(p->lflags);

		/* ACL: additional access mode flag */
		(void) putchar(p->acl);
		curcol++;

		curcol += printf("%3ld ", p->lnl);
		if (oflg)
			if (!nflg) {
				cp = getname(p->luid);
				curcol += printf("%-8s ", cp);
			} else
				curcol += printf("%-8lu ", p->luid);
		if (gflg)
			if (!nflg) {
				cp = getgroup(p->lgid);
				curcol += printf("%-8s ", cp);
			} else
				curcol += printf("%-8lu ", p->lgid);
		if (p->ltype == 'b' || p->ltype == 'c') {
			curcol += printf("%3ld,%3ld", major((dev_t)p->lsize),
			    minor((dev_t)p->lsize));
		} else {
			curcol += printf((p->lsize < (off_t)10000000) ?
			    "%7lld" : "%lld", p->lsize);
		}
		(void) cftime(time_buf,
			dcgettext(NULL, FORMAT3, LC_TIME), &p->lmtime);
		curcol += printf("%s", time_buf);
	}

	/*
	 * prevent both "->" and trailing marks
	 * from appearing
	 */

	if (pflg && p->ltype == 'd')
		dmark = "/";

	if (Fflg && !(lflg && p->flinkto)) {
		if (p->ltype == 'd')
			dmark = "/";
		else if (p->ltype == 'D')
			dmark = ">";
		else if (p->ltype == 'p')
			dmark = "|";
		else if (p->ltype == 'l')
			dmark = "@";
		else if (p->ltype == 's')
			dmark = "=";
		else if (p->lflags & (S_IXUSR|S_IXGRP|S_IXOTH))
			dmark = "*";
		else
			dmark = "";
	}

	if (lflg && p->flinkto) {
		(void) strncpy(buf, " -> ", 4);
		(void) strcpy(buf + 4, p->flinkto);
		dmark = buf;
	}

	if (p->lflags & ISARG) {
		if (qflg || bflg)
			pprintf(p->ln.namep, dmark);
		else {
			(void) printf("%s%s", p->ln.namep, dmark);
			curcol += strcol((unsigned char *)p->ln.namep);
			curcol += strcol((unsigned char *)dmark);
		}
	} else {
		if (qflg || bflg)
			pprintf(p->ln.lname, dmark);
		else {
			(void) printf("%s%s", p->ln.lname, dmark);
			curcol += strcol((unsigned char *)p->ln.lname);
			curcol += strcol((unsigned char *)dmark);
		}
	}
}

/* print various r,w,x permissions */
static void
pmode(mode_t aflag)
{
	/* these arrays are declared static to allow initializations */
	static int	m0[] = { 1, S_IRUSR, 'r', '-' };
	static int	m1[] = { 1, S_IWUSR, 'w', '-' };
	static int	m2[] = { 3, S_ISUID|S_IXUSR, 's', S_IXUSR,
	    'x', S_ISUID, 'S', '-' };
	static int	m3[] = { 1, S_IRGRP, 'r', '-' };
	static int	m4[] = { 1, S_IWGRP, 'w', '-' };
	static int	m5[] = { 3, S_ISGID|S_IXGRP, 's', S_IXGRP,
#ifdef XPG4
	    'x', S_ISGID, 'L', '-'};
#else
	    'x', S_ISGID, 'l', '-'};
#endif
	static int	m6[] = { 1, S_IROTH, 'r', '-' };
	static int	m7[] = { 1, S_IWOTH, 'w', '-' };
	static int	m8[] = { 3, S_ISVTX|S_IXOTH, 't', S_IXOTH,
	    'x', S_ISVTX, 'T', '-'};

	static int *m[] = { m0, m1, m2, m3, m4, m5, m6, m7, m8};

	int **mp;

	flags = aflag;
	for (mp = &m[0]; mp < &m[sizeof (m) / sizeof (m[0])]; mp++)
		selection(*mp);
}

static void
selection(int *pairp)
{
	int n;

	n = *pairp++;
	while (n-->0) {
		if ((flags & *pairp) == *pairp) {
			pairp++;
			break;
		} else {
			pairp += 2;
		}
	}
	(void) putchar(*pairp);
	curcol++;
}

/*
 * column: get to the beginning of the next column.
 */
static void
column(void)
{
	if (curcol == 0)
		return;
	if (mflg) {
		(void) putc(',', stdout);
		curcol++;
		if (curcol + colwidth + 2 > num_cols) {
			(void) putc('\n', stdout);
			curcol = 0;
			return;
		}
		(void) putc(' ', stdout);
		curcol++;
		return;
	}
	if (Cflg == 0) {
		(void) putc('\n', stdout);
		curcol = 0;
		return;
	}
	if ((curcol / colwidth + 2) * colwidth > num_cols) {
		(void) putc('\n', stdout);
		curcol = 0;
		return;
	}
	do {
		(void) putc(' ', stdout);
		curcol++;
	} while (curcol % colwidth);
}

static void
new_line(void)
{
	if (curcol) {
		first = 0;
		(void) putc('\n', stdout);
		curcol = 0;
	}
}

/*
 * read each filename in directory dir and store its
 * status in flist[nfiles]
 * use makename() to form pathname dir/filename;
 */
static void
rddir(char *dir)
{
	struct dirent *dentry;
	DIR *dirf;
	int j;
	struct lbuf *ep;
	int width;

	if ((dirf = opendir(dir)) == NULL) {
		(void) fflush(stdout);
		perror(dir);
		err = 2;
		return;
	} else {
		tblocks = 0;
		while (dentry = readdir(dirf)) {
			if (aflg == 0 && dentry->d_name[0] == '.' &&
			    (Aflg == 0 ||
			    dentry->d_name[1] == '\0' ||
			    dentry->d_name[1] == '.' &&
			    dentry->d_name[2] == '\0'))
				/*
				 * check for directory items '.', '..',
				 *  and items without valid inode-number;
				 */
				continue;

			if (Cflg || mflg) {
				width = strcol((unsigned char *)dentry->d_name);
				if (width > filewidth)
					filewidth = width;
			}
			ep = gstat(makename(dir, dentry->d_name), 0);
			if (ep == NULL) {
				if (nomocore)
					return;
				continue;
			} else {
				ep->lnum = dentry->d_ino;
				for (j = 0; dentry->d_name[j] != '\0'; j++)
					ep->ln.lname[j] = dentry->d_name[j];
				ep->ln.lname[j] = '\0';
			}
		}
		(void) closedir(dirf);
		colwidth = fixedwidth + filewidth;
	}
}

/*
 * get status of file and recomputes tblocks;
 * argfl = 1 if file is a name in ls-command and = 0
 * for filename in a directory whose name is an
 * argument in the command;
 * stores a pointer in flist[nfiles] and
 * returns that pointer;
 * returns NULL if failed;
 */
static struct lbuf *
gstat(char *file, int argfl)
{
	struct stat statb, statb1;
	struct lbuf *rep;
	char buf[BUFSIZ];
	int cc;
	int (*statf)() = Lflg ? stat : lstat;

	if (nomocore)
		return (NULL);

	if (nfiles >= maxfils) {
		/*
		 * all flist/lbuf pair assigned files, time to get some
		 * more space
		 */
		maxfils += quantn;
		if (((flist = realloc(flist,
		    maxfils * sizeof (struct lbuf *))) == NULL) ||
		    ((nxtlbf = malloc(quantn *
		    sizeof (struct lbuf))) == NULL)) {
			perror("ls");
			nomocore = 1;
			return (NULL);
		}
	}

/*
 * nfiles is reset to nargs for each directory
 * that is given as an argument maxn is checked
 * to prevent the assignment of an lbuf to a flist entry
 * that already has one assigned.
 */
	if (nfiles >= maxn) {
		rep = nxtlbf++;
		flist[nfiles++] = rep;
		maxn = nfiles;
	} else {
		rep = flist[nfiles++];
	}
	rep->lflags = (mode_t)0;
	rep->flinkto = NULL;
	if (argfl || statreq) {
		int doacl;

		if (lflg)
			doacl = 1;
		else
			doacl = 0;
		if ((*statf)(file, &statb) < 0) {
			perror(file);
			nfiles--;
			return (NULL);
		}
		rep->lnum = statb.st_ino;
		rep->lsize = statb.st_size;
		rep->lblocks = statb.st_blocks;
		switch (statb.st_mode & S_IFMT) {
		case S_IFDIR:
			rep->ltype = 'd';
			break;
		case S_IFBLK:
			rep->ltype = 'b';
			rep->lsize = (off_t)statb.st_rdev;
			break;
		case S_IFCHR:
			rep->ltype = 'c';
			rep->lsize = (off_t)statb.st_rdev;
			break;
		case S_IFIFO:
			rep->ltype = 'p';
			break;
		case S_IFSOCK:
			rep->ltype = 's';
			rep->lsize = 0;
			break;
		case S_IFLNK:
			/* symbolic links may not have ACLs, so elide acl() */
			if (Lflg == 0)
				doacl = 0;
			rep->ltype = 'l';
			if (lflg) {
				cc = readlink(file, buf, BUFSIZ);
				if (cc >= 0) {

					/*
					 * follow the symbolic link
					 * to generate the appropriate
					 * Fflg marker for the object
					 * eg, /bin -> /sym/bin/
					 */
					if ((Fflg || pflg) &&
					    (stat(file, &statb1) >= 0)) {
						switch (statb1.st_mode &
						    S_IFMT) {
						case S_IFDIR:
							buf[cc++] = '/';
							break;
						case S_IFSOCK:
							buf[cc++] = '=';
							break;
						default:
							if ((statb1.st_mode &
							    ~S_IFMT) &
							    (S_IXUSR|S_IXGRP|
							    S_IXOTH))
								buf[cc++] = '*';
							break;
						}
					}
					buf[cc] = '\0';
					rep->flinkto = strdup(buf);
				}
				break;
			}

			/*
			 * ls /sym behaves differently from ls /sym/
			 * when /sym is a symbolic link. This is fixed
			 * when explicit arguments are specified.
			 */

			if (!argfl || stat(file, &statb1) < 0)
				break;
			if ((statb1.st_mode & S_IFMT) == S_IFDIR) {
				statb = statb1;
				rep->ltype = 'd';
				rep->lsize = statb1.st_size;
			}
			break;
		case S_IFDOOR:
			rep->ltype = 'D';
			break;
		case S_IFREG:
			rep->ltype = '-';
			break;
		default:
			rep->ltype = '?';
			break;
		}
		rep->lflags = statb.st_mode & ~S_IFMT;

		/* ACL: check acl entries count */
		if (doacl && acl(file, GETACLCNT, 0, NULL) > MIN_ACL_ENTRIES)
			rep->acl = '+';
		else
			rep->acl = ' ';

		/* mask ISARG and other file-type bits */

		rep->luid = statb.st_uid;
		rep->lgid = statb.st_gid;
		rep->lnl = statb.st_nlink;
		if (uflg)
			rep->lmtime = statb.st_atime;
		else if (cflg)
			rep->lmtime = statb.st_ctime;
		else
			rep->lmtime = statb.st_mtime;
		if (rep->ltype != 'b' && rep->ltype != 'c')
			tblocks += rep->lblocks;
	}
	return (rep);
}

/*
 * returns pathname of the form dir/file;
 * dir is a null-terminated string;
 */
static char *
makename(char *dir, char *file)
{
	/*
	 * MAXNAMLEN is the maximum length of a file/dir name in ls.
	 * dfile is static as this is returned by makename().
	 */
	static char dfile[MAXNAMLEN];
	char *dp, *fp;

	dp = dfile;
	fp = dir;
	while (*fp)
		*dp++ = *fp++;
	if (dp > dfile && *(dp - 1) != '/')
		*dp++ = '/';
	fp = file;
	while (*fp)
		*dp++ = *fp++;
	*dp = '\0';
	return (dfile);
}


#include <pwd.h>
#include <grp.h>
#include <utmpx.h>

struct	utmpx utmp;

#define	NMAX	(sizeof (utmp.ut_name))
#define	SCPYN(a, b)	(void) strncpy(a, b, NMAX)


struct cachenode {		/* this struct must be zeroed before using */
	struct cachenode *lesschild;	/* subtree whose entries < val */
	struct cachenode *grtrchild;	/* subtree whose entries > val */
	long val;			/* the uid or gid of this entry */
	int initted;			/* name has been filled in */
	char name[NMAX+1];		/* the string that val maps to */
};
static struct cachenode *names, *groups;

static struct cachenode *
findincache(struct cachenode **head, long val)
{
	struct cachenode **parent = head;
	struct cachenode *c = *parent;

	while (c != NULL) {
		if (val == c->val) {
			/* found it */
			return (c);
		} else if (val < c->val) {
			parent = &c->lesschild;
			c = c->lesschild;
		} else {
			parent = &c->grtrchild;
			c = c->grtrchild;
		}
	}

	/* not in the cache, make a new entry for it */
	c = calloc(1, sizeof (struct cachenode));
	if (c == NULL) {
		perror("ls");
		exit(2);
	}
	*parent = c;
	c->val = val;
	return (c);
}

/*
 * get name from cache, or passwd file for a given uid;
 * lastuid is set to uid.
 */
static char *
getname(uid_t uid)
{
	struct passwd *pwent;
	struct cachenode *c;

	if ((uid == lastuid) && lastuname)
		return (lastuname);

	c = findincache(&names, uid);
	if (c->initted == 0) {
		if ((pwent = getpwuid(uid)) != NULL) {
			SCPYN(&c->name[0], pwent->pw_name);
		} else {
			(void) sprintf(&c->name[0], "%-8lu", uid);
		}
		c->initted = 1;
	}
	lastuid = uid;
	lastuname = &c->name[0];
	return (lastuname);
}

/*
 * get name from cache, or group file for a given gid;
 * lastgid is set to gid.
 */
static char *
getgroup(gid_t gid)
{
	struct group *grent;
	struct cachenode *c;

	if ((gid == lastgid) && lastgname)
		return (lastgname);

	c = findincache(&groups, gid);
	if (c->initted == 0) {
		if ((grent = getgrgid(gid)) != NULL) {
			SCPYN(&c->name[0], grent->gr_name);
		} else {
			(void) sprintf(&c->name[0], "%-8lu", gid);
		}
		c->initted = 1;
	}
	lastgid = gid;
	lastgname = &c->name[0];
	return (lastgname);
}

/* return >0 if item pointed by pp2 should appear first */
static int
compar(struct lbuf **pp1, struct lbuf **pp2)
{
	struct lbuf *p1, *p2;

	p1 = *pp1;
	p2 = *pp2;
	if (dflg == 0) {
/*
 * compare two names in ls-command one of which is file
 * and the other is a directory;
 * this portion is not used for comparing files within
 * a directory name of ls-command;
 */
		if (p1->lflags&ISARG && p1->ltype == 'd') {
			if (!(p2->lflags&ISARG && p2->ltype == 'd'))
				return (1);
		} else {
			if (p2->lflags&ISARG && p2->ltype == 'd')
				return (-1);
		}
	}
	if (tflg) {
		if (p2->lmtime > p1->lmtime)
			return (rflg);
		else if (p2->lmtime < p1->lmtime)
			return (-rflg);
		/* if times are equal, fall through and sort by name */
	}
	return (rflg * strcoll(
	    p1->lflags & ISARG ? p1->ln.namep : p1->ln.lname,
	    p2->lflags&ISARG ? p2->ln.namep : p2->ln.lname));
}

static void
pprintf(char *s1, char *s2)
{
	csi_pprintf((unsigned char *)s1);
	csi_pprintf((unsigned char *)s2);
}

static void
csi_pprintf(unsigned char *s)
{
	unsigned char *cp;
	char	c;
	int	i;
	int	c_len;
	int	p_col;
	wchar_t	pcode;

	if (!qflg && !bflg) {
		for (cp = s; *cp != '\0'; cp++) {
			(void) putchar(*cp);
			curcol++;
		}
		return;
	}

	for (cp = s; *cp; ) {
		if (isascii(c = *cp)) {
			if (!isprint(c)) {
				if (qflg) {
					c = '?';
				} else {
					curcol += 3;
					(void) putc('\\', stdout);
					c = '0' + ((*cp >> 6) & 07);
					(void) putc(c, stdout);
					c = '0' + ((*cp >> 3) & 07);
					(void) putc(c, stdout);
					c = '0' + (*cp & 07);
				}
			}
			curcol++;
			cp++;
			(void) putc(c, stdout);
			continue;
		}

		if ((c_len = mbtowc(&pcode, (char *)cp, MB_LEN_MAX)) <= 0) {
			c_len = 1;
			goto not_print;
		}

		if ((p_col = wcwidth(pcode)) > 0) {
			(void) putwchar(pcode);
			cp += c_len;
			curcol += p_col;
			continue;
		}

not_print:
		for (i = 0; i < c_len; i++) {
			if (qflg) {
				c = '?';
			} else {
				curcol += 3;
				(void) putc('\\', stdout);
				c = '0' + ((*cp >> 6) & 07);
				(void) putc(c, stdout);
				c = '0' + ((*cp >> 3) & 07);
				(void) putc(c, stdout);
				c = '0' + (*cp & 07);
			}
			curcol++;
			(void) putc(c, stdout);
			cp++;
		}
	}
}

static int
strcol(unsigned char *s1)
{
	int	w;
	int	w_col;
	int	len;
	wchar_t	wc;

	w = 0;
	while (*s1) {
		if (isascii(*s1)) {
			w++;
			s1++;
			continue;
		}

		if ((len = mbtowc(&wc, (char *)s1, MB_LEN_MAX)) <= 0) {
			w++;
			s1++;
			continue;
		}

		if ((w_col = wcwidth(wc)) < 0)
			w_col = len;
		s1 += len;
		w += w_col;
	}
	return (w);
}
