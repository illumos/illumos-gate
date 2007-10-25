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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <aclutils.h>
#include <libnvpair.h>
#include <libcmdutils.h>
#include <attr.h>

#ifndef STANDALONE
#define	TERMINFO
#endif

/*
 * -DNOTERMINFO can be defined on the cc command line to prevent
 * the use of terminfo.  This should be done on systems not having
 * the terminfo feature(pre 6.0 systems ?).
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
 * this flag has been added to manipulate the display of S instead of 'l' when
 * the file is not a regular file and when group execution bit is off
 */
#define	LS_NOTREG	010000


/*
 * Date and time formats
 *
 * b --- abbreviated month name
 * e --- day number
 * Y --- year in the form ccyy
 * H --- hour(24-hour version)
 * M --- minute
 * F --- yyyy-mm-dd
 * T --- hh:mm:ss
 * z --- time zone as hours displacement from UTC
 * note that %F and %z are from the ISO C99 standard and are
 * not present in older C libraries
 */
#define	FORMAT1	 " %b %e  %Y "
#define	FORMAT2  " %b %e %H:%M "
#define	FORMAT3  " %b %e %T %Y "
#define	FORMAT4  " %%F %%T.%.09ld %%z "

#undef BUFSIZ
#define	BUFSIZ 4096
#define	NUMBER_WIDTH 40
#define	FMTSIZE 50

struct ditem {
	dev_t	dev;			/* directory items device number */
	ino_t	ino;			/* directory items inode number */
	struct ditem *parent;		/* dir items ptr to its parent's info */
};
/* Holds boolean extended system attributes */
struct attrb {
	char		*name;
};
/* Holds timestamp extended system attributes */
struct attrtm {
	char		*name;
	uint64_t	stm;
	uint64_t	nstm;
};

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
	timestruc_t	lmtime;
	timestruc_t	lat;
	timestruc_t	lct;
	timestruc_t	lmt;
	char	*flinkto;	/* symbolic link contents */
	char 	acl;		/* indicate there are additional acl entries */
	int	cycle;		/* cycle detected flag */
	struct ditem *ancinfo;	/* maintains ancestor info */
	acl_t *aclp;		/* ACL if present */
	struct attrb *exttr;	/* boolean extended system attributes */
	struct attrtm *extm;	/* timestamp extended system attributes */
};

struct dchain {
	char *dc_name;		/* path name */
	int cycle_detected;	/* cycle detected visiting this directory */
	struct ditem *myancinfo;	/* this directory's ancestry info */
	struct dchain *dc_next;	/* next directory in the chain */
};

/*
 * A numbuf_t is used when converting a number to a string representation
 */
typedef char numbuf_t[NUMBER_WIDTH];

static struct dchain *dfirst;	/* start of the dir chain */
static struct dchain *cdfirst;	/* start of the current dir chain */
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
static struct lbuf	*gstat(char *, int, struct ditem *);
static char		*getname(uid_t);
static char		*getgroup(gid_t);
static char		*makename(char *, char *);
static void		pentry(struct lbuf *);
static void		column(void);
static void		pmode(mode_t aflag);
static void		selection(int *);
static void		new_line(void);
static void		rddir(char *, struct ditem *);
static int		strcol(unsigned char *);
static void		pem(struct lbuf **, struct lbuf **, int);
static void		pdirectory(char *, int, int, int, struct ditem *);
static struct cachenode *findincache(struct cachenode **, long);
static void		csi_pprintf(unsigned char *);
static void		pprintf(char *, char *);
static int		compar(struct lbuf **pp1, struct lbuf **pp2);
static char 		*number_to_scaled_string(numbuf_t buf,
			    unsigned long long number,
			    long scale);
static void		record_ancestry(char *, struct stat *, struct lbuf *,
			    int, struct ditem *);

static int		aflg;
static int		atflg;
static int		bflg;
static int		cflg;
static int		dflg;
static int		eflg;
static int		fflg;
static int		gflg;
static int		hflg;
static int		iflg;
static int		lflg;
static int		mflg;
static int		nflg;
static int		oflg;
static int		pflg;
static int		qflg;
static int		rflg = 1; /* init to 1 for special use in compar */
static int		sflg;
static int		tflg;
static int		uflg;
static int		xflg;
static int		Aflg;
static int		Cflg;
static int		Eflg;
static int		Fflg;
static int		Hflg;
static int		Lflg;
static int		Rflg;
static int		Sflg;
static int		vflg;
static int		Vflg;
static int		saflg;		/* boolean extended system attr. */
static int		sacnt;		/* number of extended system attr. */
static int		copt;
static int		vopt;
static int		tmflg;		/* create time ext. system attr. */
static int		ctm;
static int		atm;
static int		mtm;
static int		crtm;
static int		alltm;
static long		hscale;
static mode_t		flags;
static int		err = 0;	/* Contains return code */

static uid_t		lastuid	= (uid_t)-1;
static gid_t		lastgid = (gid_t)-1;
static char		*lastuname = NULL;
static char		*lastgname = NULL;

/* statreq > 0 if any of sflg, (n)lflg, tflg, Sflg are on */
static int		statreq;

static char		*dotp = ".";

static u_longlong_t 	tblocks; /* number of blocks of files in a directory */
static time_t		year, now;

static int		num_cols = 80;
static int		colwidth;
static int		filewidth;
static int		fixedwidth;
static int		nomocore;
static int		curcol;

static struct	winsize	win;

static char	time_buf[FMTSIZE];	/* array to hold day and time */

#define	NOTWORKINGDIR(d, l)	(((l) < 2) || \
				    (strcmp((d) + (l) - 2, "/.") != 0))

#define	NOTPARENTDIR(d, l)	(((l) < 3) || \
				    (strcmp((d) + (l) - 3, "/..") != 0))
/* Extended system attributes support */
static int get_sysxattr(char *, struct lbuf *);
static void set_sysattrb_display(char *, boolean_t, struct lbuf *);
static void set_sysattrtm_display(char *, struct lbuf *);
static void format_time(const char *, time_t);
static void format_etime(const char *, time_t, time_t);
static void print_time(struct lbuf *);
static void format_attrtime(struct lbuf *);
static void *xmalloc(size_t, struct lbuf *);
static void free_sysattr(struct lbuf *);
static nvpair_t *pair;
static nvlist_t	*response;

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
	struct ditem	*myinfo;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
#ifdef STANDALONE
	if (argv[0][0] == '\0')
		argc = getargv("ls", &argv, 0);
#endif

	lb.lmtime.tv_sec = time(NULL);
	lb.lmtime.tv_nsec = 0;
	year = lb.lmtime.tv_sec - 6L*30L*24L*60L*60L; /* 6 months ago */
	now = lb.lmtime.tv_sec + 60;
	if (isatty(1)) {
		Cflg = 1;
		mflg = 0;
	}

	while ((c = getopt(argc, argv,
	    "aAbcCdeEfFghHilLmnopqrRsStux1@vV/:%:")) != EOF)
		switch (c) {
		case 'a':
			aflg++;
			continue;
		case 'A':
			Aflg++;
			continue;
		case 'b':
			bflg = 1;
			qflg = 0;
			continue;
		case 'c':
			uflg = 0;
			atm = 0;
			ctm = 0;
			mtm = 0;
			crtm = 0;
			cflg++;
			continue;
		case 'C':
			Cflg = 1;
			mflg = 0;
#ifdef XPG4
			lflg = 0;
#endif
			continue;
		case 'd':
			dflg++;
			continue;
		case 'e':
			eflg++;
			lflg++;
			statreq++;
			Eflg = 0;
			continue;
		case 'E':
			Eflg++;
			lflg++;
			statreq++;
			eflg = 0;
			continue;
		case 'f':
			fflg++;
			continue;
		case 'F':
			Fflg++;
			statreq++;
			continue;
		case 'g':
			gflg++;
			lflg++;
			statreq++;
			continue;
		case 'h':
			hflg++;
			hscale = 1024;
			continue;
		case 'H':
			Hflg++;
			/* -H and -L are mutually exclusive */
			Lflg = 0;
			continue;
		case 'i':
			iflg++;
			continue;
		case 'l':
			lflg++;
			statreq++;
			Cflg = 0;
			xflg = 0;
			mflg = 0;
			atflg = 0;
			continue;
		case 'L':
			Lflg++;
			/* -H and -L are mutually exclusive */
			Hflg = 0;
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
			lflg++;
			statreq++;
			Cflg = 0;
			xflg = 0;
			mflg = 0;
			atflg = 0;
			continue;
		case 'o':
			oflg++;
			lflg++;
			statreq++;
			continue;
		case 'p':
			pflg++;
			statreq++;
			continue;
		case 'q':
			qflg = 1;
			bflg = 0;
			continue;
		case 'r':
			rflg = -1;
			continue;
		case 'R':
			Rflg++;
			statreq++;
			continue;
		case 's':
			sflg++;
			statreq++;
			continue;
		case 'S':
			tflg = 0;
			Sflg++;
			statreq++;
			continue;
		case 't':
			Sflg = 0;
			tflg++;
			statreq++;
			continue;
		case 'u':
			cflg = 0;
			atm = 0;
			ctm = 0;
			mtm = 0;
			crtm = 0;
			uflg++;
			continue;
		case 'V':
			Vflg++;
			/*FALLTHROUGH*/
		case 'v':
			vflg++;
#if !defined(XPG4)
			if (lflg)
				continue;
#endif
			lflg++;
			statreq++;
			Cflg = 0;
			xflg = 0;
			mflg = 0;
			continue;
		case 'x':
			xflg = 1;
			Cflg = 1;
			mflg = 0;
#ifdef XPG4
			lflg = 0;
#endif
			continue;
		case '1':
			Cflg = 0;
			continue;
		case '@':
#if !defined(XPG4)
			/*
			 * -l has precedence over -@
			 */
			if (lflg)
				continue;
#endif
			atflg++;
			lflg++;
			statreq++;
			Cflg = 0;
			xflg = 0;
			mflg = 0;
			continue;
		case '/':
			saflg++;
			if (optarg != NULL) {
				if (strcmp(optarg, "c") == 0) {
					copt++;
					vopt = 0;
				} else if (strcmp(optarg, "v") == 0) {
					vopt++;
					copt = 0;
				} else
					opterr++;
			} else
				opterr++;
			lflg++;
			statreq++;
			Cflg = 0;
			xflg = 0;
			mflg = 0;
			continue;
		case '%':
			tmflg++;
			if (optarg != NULL) {
				if (strcmp(optarg, "ctime") == 0) {
					ctm++;
					atm = 0;
					mtm = 0;
					crtm = 0;
				} else if (strcmp(optarg, "atime") == 0) {
					atm++;
					ctm = 0;
					mtm = 0;
					crtm = 0;
					uflg = 0;
					cflg = 0;
				} else if (strcmp(optarg, "mtime") == 0) {
					mtm++;
					atm = 0;
					ctm = 0;
					crtm = 0;
					uflg = 0;
					cflg = 0;
				} else if (strcmp(optarg, "crtime") == 0) {
					crtm++;
					atm = 0;
					ctm = 0;
					mtm = 0;
					uflg = 0;
					cflg = 0;
				} else if (strcmp(optarg, "all") == 0) {
					alltm++;
					atm = 0;
					ctm = 0;
					mtm = 0;
					crtm = 0;
				} else
					opterr++;
			} else
				opterr++;

			Sflg = 0;
			statreq++;
			mflg = 0;
			continue;
		case '?':
			opterr++;
			continue;
		}
	if (opterr) {
		(void) fprintf(stderr, gettext(
		    "usage: ls -aAbcCdeEfFghHilLmnopqrRsStuxvV1@/%[c | v]"
		    "%%[atime | crtime | ctime | mtime | all]"
		    " [files]\n"));
		exit(2);
	}

	if (fflg) {
		aflg++;
		lflg = 0;
		sflg = 0;
		tflg = 0;
		Sflg = 0;
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
		if (num_cols < 20 || num_cols > 1000)
			/* assume it is an error */
			num_cols = 80;
	}

	/* allocate space for flist and the associated	*/
	/* data structures (lbufs)			*/
	maxfils = quantn;
	if (((flist = malloc(maxfils * sizeof (struct lbuf *))) == NULL) ||
	    ((nxtlbf = malloc(quantn * sizeof (struct lbuf))) == NULL)) {
		perror("ls");
		exit(2);
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

		/*
		 * If we are recursing, we need to make sure we don't
		 * get into an endless loop.  To keep track of the inodes
		 * (actually, just the directories) visited, we
		 * maintain a directory ancestry list for a file
		 * hierarchy.  As we go deeper into the hierarchy,
		 * a parent directory passes its directory list
		 * info (device id, inode number, and a pointer to
		 * its parent) to each of its children.  As we
		 * process a child that is a directory, we save
		 * its own personal directory list info.  We then
		 * check to see if the child has already been
		 * processed by comparing its device id and inode
		 * number from its own personal directory list info
		 * to that of each of its ancestors.  If there is a
		 * match, then we know we've detected a cycle.
		 */
		if (Rflg) {
			/*
			 * This is the first parent in this lineage
			 * (first in a directory hierarchy), so
			 * this parent's parent doesn't exist.  We
			 * only initialize myinfo when we are
			 * recursing, otherwise it's not used.
			 */
			if ((myinfo = (struct ditem *)malloc(
			    sizeof (struct ditem))) == NULL) {
				perror("ls");
				exit(2);
			} else {
				myinfo->dev = 0;
				myinfo->ino = 0;
				myinfo->parent = NULL;
			}
		}

		if (Cflg || mflg) {
			width = strcol((unsigned char *)argv[optind]);
			if (width > filewidth)
				filewidth = width;
		}
		if ((ep = gstat((*argv[optind] ? argv[optind] : dotp),
		    1, myinfo)) == NULL) {
			if (nomocore)
				exit(2);
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
		pdirectory(flist[i]->ln.namep, Rflg ||
		    (amino > 1), nargs, 0, flist[i]->ancinfo);
		if (nomocore)
			exit(2);
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
			pdirectory(dtemp->dc_name, 1, nargs,
			    dtemp->cycle_detected, dtemp->myancinfo);
			if (nomocore)
				exit(2);
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
pdirectory(char *name, int title, int lp, int cdetect, struct ditem *myinfo)
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
	/*
	 * If there was a cycle detected, then notify and don't report
	 * further.
	 */
	if (cdetect) {
		if (lflg || sflg) {
			curcol += printf(gettext("total %d"), 0);
			new_line();
		}
		(void) fprintf(stderr, gettext(
		    "ls: cycle detected for %s\n"), name);
		return;
	}

	nfiles = lp;
	rddir(name, myinfo);
	if (nomocore)
		return;
	if (fflg == 0)
		qsort(&flist[lp], (unsigned)(nfiles - lp),
		    sizeof (struct lbuf *),
		    (int (*)(const void *, const void *))compar);
	if (Rflg) {
		for (j = nfiles - 1; j >= lp; j--) {
			ap = flist[j];
			if (ap->ltype == 'd' && strcmp(ap->ln.lname, ".") &&
			    strcmp(ap->ln.lname, "..")) {
				dp = malloc(sizeof (struct dchain));
				if (dp == NULL) {
					perror("ls");
					exit(2);
				}
				pname = makename(curdir, ap->ln.lname);
				if ((dp->dc_name = strdup(pname)) == NULL) {
					perror("ls");
					exit(2);
				}
				dp->cycle_detected = ap->cycle;
				dp->myancinfo = ap->ancinfo;
				dp->dc_next = dfirst;
				dfirst = dp;
			}
		}
	}
	if (lflg || sflg) {
		curcol += printf(gettext("total %llu"), tblocks);
		new_line();
	}
	pem(&flist[lp], &flist[nfiles], lflg||sflg);
}

/*
 * pem: print 'em. Print a list of files (e.g. a directory) bounded
 * by slp and lp.
 */
static void
pem(struct lbuf **slp, struct lbuf **lp, int tot_flag)
{
	long row, nrows, i;
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
	if (tot_flag) {
		slp--;
		row = 1;
	}
	else
		row = 0;

	nrows = (lp - slp - 1) / ncols + 1;
	for (i = 0; i < nrows; i++, row++) {
		for (col = 0; col < ncols; col++) {
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
	numbuf_t hbuf;
	char buf[BUFSIZ];
	char *dmark = "";	/* Used if -p or -F option active */
	char *cp;

	p = ap;
	column();
	if (iflg)
		if (mflg && !lflg)
			curcol += printf("%llu ", (long long)p->lnum);
		else
			curcol += printf("%10llu ", (long long)p->lnum);
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

		curcol += printf("%3lu ", (ulong_t)p->lnl);
		if (oflg)
			if (!nflg) {
				cp = getname(p->luid);
				curcol += printf("%-8s ", cp);
			} else
				curcol += printf("%-8lu ", (ulong_t)p->luid);
		if (gflg)
			if (!nflg) {
				cp = getgroup(p->lgid);
				curcol += printf("%-8s ", cp);
			} else
				curcol += printf("%-8lu ", (ulong_t)p->lgid);
		if (p->ltype == 'b' || p->ltype == 'c') {
			curcol += printf("%3u, %2u",
			    (uint_t)major((dev_t)p->lsize),
			    (uint_t)minor((dev_t)p->lsize));
		} else if (hflg && (p->lsize >= hscale)) {
			curcol += printf("%7s",
			    number_to_scaled_string(hbuf, p->lsize, hscale));
		} else {
			curcol += printf((p->lsize < (off_t)10000000) ?
			    "%7lld" : "%lld", p->lsize);
		}
		if (eflg)
			format_time(FORMAT3, p->lmtime.tv_sec);
		else if (Eflg)
			/* fill in nanoseconds first */
			format_etime(FORMAT4, p->lmtime.tv_sec,
			    p->lmtime.tv_nsec);
		else {
			if ((p->lmtime.tv_sec < year) ||
			    (p->lmtime.tv_sec > now))
				format_time(FORMAT1, p->lmtime.tv_sec);
			else
				format_time(FORMAT2, p->lmtime.tv_sec);
		}
		/* format extended system attribute time */
		if (tmflg && crtm)
			format_attrtime(p);

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

	/* Display extended system attributes */
	if (saflg) {
		int i;

		new_line();
		(void) printf("	\t{");
		if (p->exttr != NULL) {
			int k = 0;
			for (i = 0; i < sacnt; i++) {
				if (p->exttr[i].name != NULL)
					k++;
			}
			for (i = 0; i < sacnt; i++) {
				if (p->exttr[i].name != NULL) {
					(void) printf("%s", p->exttr[i].name);
					k--;
					if (vopt && (k != 0))
						(void) printf(",");
				}
			}
		}
		(void) printf("}\n");
	}
	/* Display file timestamps and extended system attribute timestamps */
	if (tmflg && alltm) {
		new_line();
		print_time(p);
		new_line();
	}
	if (vflg) {
		new_line();
		if (p->aclp) {
			acl_printacl(p->aclp, num_cols, Vflg);
		}
	}
	/* Free extended system attribute lists */
	if (saflg || tmflg)
		free_sysattr(p);
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
	static int	m5[] = { 4, S_ISGID|S_IXGRP, 's', S_IXGRP,
				'x', S_ISGID|LS_NOTREG, 'S',
#ifdef XPG4
		S_ISGID, 'L', '-'};
#else
		S_ISGID, 'l', '-'};
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
rddir(char *dir, struct ditem *myinfo)
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
		for (;;) {
			errno = 0;
			if ((dentry = readdir(dirf)) == NULL)
				break;
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
			ep = gstat(makename(dir, dentry->d_name), 0, myinfo);
			if (ep == NULL) {
				if (nomocore)
					exit(2);
				continue;
			} else {
				ep->lnum = dentry->d_ino;
				for (j = 0; dentry->d_name[j] != '\0'; j++)
					ep->ln.lname[j] = dentry->d_name[j];
				ep->ln.lname[j] = '\0';
			}
		}
		if (errno) {
			int sav_errno = errno;

			(void) fprintf(stderr,
			    gettext("ls: error reading directory %s: %s\n"),
			    dir, strerror(sav_errno));
		}
		(void) closedir(dirf);
		colwidth = fixedwidth + filewidth;
	}
}

/*
 * Attaching a link to an inode's ancestors.  Search
 * through the ancestors to check for cycles (an inode which
 * we have already tracked in this inodes ancestry).  If a cycle
 * is detected, set the exit code and record the fact so that
 * it is reported at the right time when printing the directory.
 * In addition, set the exit code.  Note:  If the -a flag was
 * specified, we don't want to check for cycles for directories
 * ending in '/.' or '/..' unless they were specified on the
 * command line.
 */
static void
record_ancestry(char *file, struct stat *pstatb, struct lbuf *rep,
    int argfl, struct ditem *myparent)
{
	size_t		file_len;
	struct ditem	*myinfo;
	struct ditem	*tptr;

	file_len = strlen(file);
	if (!aflg || argfl || (NOTWORKINGDIR(file, file_len) &&
	    NOTPARENTDIR(file, file_len))) {
		/*
		 * Add this inode's ancestry
		 * info and insert it into the
		 * ancestry list by pointing
		 * back to its parent.  We save
		 * it (in rep) with the other info
		 * we're gathering for this inode.
		 */
		if ((myinfo = malloc(
		    sizeof (struct ditem))) == NULL) {
			perror("ls");
			exit(2);
		}
		myinfo->dev = pstatb->st_dev;
		myinfo->ino = pstatb->st_ino;
		myinfo->parent = myparent;
		rep->ancinfo = myinfo;

		/*
		 * If this node has the same device id and
		 * inode number of one of its ancestors,
		 * then we've detected a cycle.
		 */
		if (myparent != NULL) {
			for (tptr = myparent; tptr->parent != NULL;
			    tptr = tptr->parent) {
				if ((tptr->dev == pstatb->st_dev) &&
				    (tptr->ino == pstatb->st_ino)) {
					/*
					 * Cycle detected for this
					 * directory.  Record the fact
					 * it is a cycle so we don't
					 * try to process this
					 * directory as we are
					 * walking through the
					 * list of directories.
					 */
					rep->cycle = 1;
					err = 2;
					break;
				}
			}
		}
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
gstat(char *file, int argfl, struct ditem *myparent)
{
	struct stat statb, statb1;
	struct lbuf *rep;
	char buf[BUFSIZ];
	ssize_t cc;
	int (*statf)() = ((Lflg) || (Hflg && argfl)) ? stat : lstat;
	int aclcnt;
	int error;
	aclent_t *tp;
	o_mode_t groupperm, mask;
	int grouppermfound, maskfound;

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
	rep->cycle = 0;
	if (argfl || statreq) {
		int doacl;

		if (lflg)
			doacl = 1;
		else
			doacl = 0;
		if ((*statf)(file, &statb) < 0) {
			if (argfl || errno != ENOENT ||
			    (Lflg && lstat(file, &statb) == 0)) {
				/*
				 * Avoid race between readdir and lstat.
				 * Print error message in case of dangling link.
				 */
				perror(file);
			}
			nfiles--;
			return (NULL);
		}

		/*
		 * If -H was specified, and the file linked to was
		 * not a directory, then we need to get the info
		 * for the symlink itself.
		 */
		if ((Hflg) && (argfl) &&
		    ((statb.st_mode & S_IFMT) != S_IFDIR)) {
			if (lstat(file, &statb) < 0) {
				perror(file);
			}
		}

		rep->lnum = statb.st_ino;
		rep->lsize = statb.st_size;
		rep->lblocks = statb.st_blocks;
		switch (statb.st_mode & S_IFMT) {
		case S_IFDIR:
			rep->ltype = 'd';
			if (Rflg) {
				record_ancestry(file, &statb, rep,
				    argfl, myparent);
			}
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
			if ((Lflg == 0) || (Hflg == 0) ||
			    ((Hflg) && (!argfl))) {
				doacl = 0;
			}
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
						case S_IFDOOR:
							buf[cc++] = '>';
							break;
						case S_IFIFO:
							buf[cc++] = '|';
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

#ifdef XPG6
			/* Do not follow a symlink when -F is specified */
			if ((!argfl) || (argfl && Fflg) ||
			    (stat(file, &statb1) < 0))
#else
			/* Follow a symlink when -F is specified */
			if (!argfl || stat(file, &statb1) < 0)
#endif /* XPG6 */
				break;
			if ((statb1.st_mode & S_IFMT) == S_IFDIR) {
				statb = statb1;
				rep->ltype = 'd';
				rep->lsize = statb1.st_size;
				if (Rflg) {
					record_ancestry(file, &statb, rep,
					    argfl, myparent);
				}
			}
			break;
		case S_IFDOOR:
			rep->ltype = 'D';
			break;
		case S_IFREG:
			rep->ltype = '-';
			break;
		case S_IFPORT:
			rep->ltype = 'P';
			break;
		default:
			rep->ltype = '?';
			break;
		}
		rep->lflags = statb.st_mode & ~S_IFMT;

		if (!S_ISREG(statb.st_mode))
			rep->lflags |= LS_NOTREG;

		/* ACL: check acl entries count */
		if (doacl) {

			error = acl_get(file, 0, &rep->aclp);
			if (error) {
				(void) fprintf(stderr,
				    gettext("ls: can't read ACL on %s: %s\n"),
				    file, acl_strerror(error));
				return (NULL);
			}

			rep->acl = ' ';

			if (rep->aclp &&
			    ((acl_flags(rep->aclp) & ACL_IS_TRIVIAL) == 0)) {
				rep->acl = '+';
				/*
				 * Special handling for ufs aka aclent_t ACL's
				 */
				if (rep->aclp &&
				    acl_type(rep->aclp) == ACLENT_T) {
					/*
					 * For files with non-trivial acls, the
					 * effective group permissions are the
					 * intersection of the GROUP_OBJ value
					 * and the CLASS_OBJ (acl mask) value.
					 * Determine both the GROUP_OBJ and
					 * CLASS_OBJ for this file and insert
					 * the logical AND of those two values
					 * in the group permissions field
					 * of the lflags value for this file.
					 */

					/*
					 * Until found in acl list, assume
					 * maximum permissions for both group
					 * a nd mask.  (Just in case the acl
					 * lacks either value for some reason.)
					 */
					groupperm = 07;
					mask = 07;
					grouppermfound = 0;
					maskfound = 0;
					aclcnt = acl_cnt(rep->aclp);
					for (tp =
					    (aclent_t *)acl_data(rep->aclp);
					    aclcnt--; tp++) {
						if (tp->a_type == GROUP_OBJ) {
							groupperm = tp->a_perm;
							grouppermfound = 1;
							continue;
						}
						if (tp->a_type == CLASS_OBJ) {
							mask = tp->a_perm;
							maskfound = 1;
						}
						if (grouppermfound && maskfound)
							break;
					}


					/* reset all the group bits */
					rep->lflags &= ~S_IRWXG;

					/*
					 * Now set them to the logical AND of
					 * the GROUP_OBJ permissions and the
					 * acl mask.
					 */

					rep->lflags |= (groupperm & mask) << 3;

				}
			}

			if (!vflg && !Vflg && rep->aclp) {
				acl_free(rep->aclp);
				rep->aclp = NULL;
			}

			if (atflg && pathconf(file, _PC_XATTR_EXISTS) == 1)
				rep->acl = '@';

		} else
			rep->acl = ' ';

		/* mask ISARG and other file-type bits */

		rep->luid = statb.st_uid;
		rep->lgid = statb.st_gid;
		rep->lnl = statb.st_nlink;
		if (uflg || (tmflg && atm))
			rep->lmtime = statb.st_atim;
		else if (cflg || (tmflg && ctm))
			rep->lmtime = statb.st_ctim;
		else
			rep->lmtime = statb.st_mtim;
		rep->lat = statb.st_atim;
		rep->lct = statb.st_ctim;
		rep->lmt = statb.st_mtim;

		if (rep->ltype != 'b' && rep->ltype != 'c')
			tblocks += rep->lblocks;

		/* Get extended system attributes */

		rep->exttr = NULL;
		rep->extm = NULL;
		if ((saflg || (tmflg && crtm) || (tmflg && alltm)) &&
		    (sysattr_support(file, _PC_SATTR_EXISTS) == 1)) {
			int i;

			sacnt = attr_count();
			/*
			 * Allocate 'sacnt' size array to hold extended
			 * system attribute name (verbose) or respective
			 * symbol represenation (compact).
			 */
			rep->exttr = xmalloc(sacnt * sizeof (struct attrb),
			    rep);

			/* initialize boolean attribute list */
			for (i = 0; i < sacnt; i++)
				rep->exttr[i].name = NULL;
			if (get_sysxattr(file, rep) != 0) {
				(void) fprintf(stderr,
				    gettext("ls:Failed to retrieve "
				    "extended system attribute from "
				    "%s\n"), file);
				rep->exttr[0].name = xmalloc(2, rep);
				(void) strlcpy(rep->exttr[0].name, "?", 2);
			}
		}
	}
	return (rep);
}

/*
 * returns pathname of the form dir/file;
 * dir and file are null-terminated strings.
 */
static char *
makename(char *dir, char *file)
{
	/*
	 * PATH_MAX is the maximum length of a path name.
	 * MAXNAMLEN is the maximum length of any path name component.
	 * Allocate space for both, plus the '/' in the middle
	 * and the null character at the end.
	 * dfile is static as this is returned by makename().
	 */
	static char dfile[PATH_MAX + 1 + MAXNAMLEN + 1];
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
			(void) sprintf(&c->name[0], "%-8u", (int)uid);
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
			(void) sprintf(&c->name[0], "%-8u", (int)gid);
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
		if (p2->lmtime.tv_sec > p1->lmtime.tv_sec)
			return (rflg);
		else if (p2->lmtime.tv_sec < p1->lmtime.tv_sec)
			return (-rflg);
		/* times are equal to the sec, check nsec */
		if (p2->lmtime.tv_nsec > p1->lmtime.tv_nsec)
			return (rflg);
		else if (p2->lmtime.tv_nsec < p1->lmtime.tv_nsec)
			return (-rflg);
		/* if times are equal, fall through and sort by name */
	} else if (Sflg) {
		/*
		 * The size stored in lsize can be either the
		 * size or the major minor number (in the case of
		 * block and character special devices).  If it's
		 * a major minor number, then the size is considered
		 * to be zero and we want to fall through and sort
		 * by name.  In addition, if the size of p2 is equal
		 * to the size of p1 we want to fall through and
		 * sort by name.
		 */
		off_t	p1size = (p1->ltype == 'b') ||
		    (p1->ltype == 'c') ? 0 : p1->lsize;
		off_t	p2size = (p2->ltype == 'b') ||
		    (p2->ltype == 'c') ? 0 : p2->lsize;
		if (p2size > p1size) {
			return (rflg);
		} else if (p2size < p1size) {
			return (-rflg);
		}
		/* Sizes are equal, fall through and sort by name. */
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

/*
 * Convert an unsigned long long to a string representation and place the
 * result in the caller-supplied buffer.
 *
 * The number provided is a size in bytes.  The number is first
 * converted to an integral multiple of 'scale' bytes.  This new
 * number is then scaled down until it is small enough to be in a good
 * human readable format, i.e.  in the range 0 thru scale-1.  If the
 * number used to derive the final number is not a multiple of scale, and
 * the final number has only a single significant digit, we compute
 * tenths of units to provide a second significant digit.
 *
 * The value "(unsigned long long)-1" is a special case and is always
 * converted to "-1".
 *
 * A pointer to the caller-supplied buffer is returned.
 */
static char *
number_to_scaled_string(
			numbuf_t buf,		/* put the result here */
			unsigned long long number, /* convert this number */
			long scale)
{
	unsigned long long save;
	/* Measurement: kilo, mega, giga, tera, peta, exa */
	char *uom = "KMGTPE";

	if ((long long)number == (long long)-1) {
		(void) strlcpy(buf, "-1", sizeof (numbuf_t));
		return (buf);
	}

	save = number;
	number = number / scale;

	/*
	 * Now we have number as a count of scale units.
	 * If no further scaling is necessary, we round up as appropriate.
	 *
	 * The largest value number could have had entering the routine is
	 * 16 Exabytes, so running off the end of the uom array should
	 * never happen.  We check for that, though, as a guard against
	 * a breakdown elsewhere in the algorithm.
	 */
	if (number < (unsigned long long)scale) {
		if ((save % scale) >= (unsigned long long)(scale / 2)) {
			if (++number == (unsigned long long)scale) {
				uom++;
				number = 1;
			}
		}
	} else {
		while ((number >= (unsigned long long)scale) && (*uom != 'E')) {
			uom++; /* next unit of measurement */
			save = number;
			/*
			 * If we're over half way to the next unit of
			 * 'scale' bytes (which means we should round
			 * up), then adding half of 'scale' prior to
			 * the division will push us into that next
			 * unit of scale when we perform the division
			 */
			number = (number + (scale / 2)) / scale;
		}
	}

	/* check if we should output a decimal place after the point */
	if ((save / scale) < 10) {
		/* snprintf() will round for us */
		float fnum = (float)save / scale;
		(void) snprintf(buf, sizeof (numbuf_t), "%2.1f%c",
		    fnum, *uom);
	} else {
		(void) snprintf(buf, sizeof (numbuf_t), "%4llu%c",
		    number, *uom);
	}
	return (buf);
}

/* Get extended system attributes and set the display */

int
get_sysxattr(char *fname, struct lbuf *rep)
{
	boolean_t	value;
	data_type_t	type;
	int		error;
	char		*name;
	int		i;

	if ((error = nvlist_alloc(&response, NV_UNIQUE_NAME, 0)) != 0) {
		perror("ls:nvlist_alloc");
		return (error);
	}
	if ((error = getattrat(AT_FDCWD, XATTR_VIEW_READWRITE, fname,
	    &response)) != 0) {
		perror("ls:getattrat");
		nvlist_free(response);
		return (error);
	}

	/*
	 * Allocate 'sacnt' size array to hold extended timestamp
	 * system attributes and initialize the array.
	 */
	rep->extm = xmalloc(sacnt * sizeof (struct attrtm), rep);
	for (i = 0; i < sacnt; i++) {
		rep->extm[i].stm = 0;
		rep->extm[i].nstm = 0;
		rep->extm[i].name = NULL;
	}
	while ((pair = nvlist_next_nvpair(response, pair)) != NULL) {
		name = nvpair_name(pair);
		type = nvpair_type(pair);
		if (type == DATA_TYPE_BOOLEAN_VALUE) {
			error = nvpair_value_boolean_value(pair, &value);
			if (error) {
				(void) fprintf(stderr,
				    gettext("nvpair_value_boolean_value "
				    "failed: error = %d\n"), error);
				continue;
			}
			if (name != NULL)
				set_sysattrb_display(name, value, rep);
			continue;
		} else if (type == DATA_TYPE_UINT64_ARRAY) {
			if (name != NULL)
				set_sysattrtm_display(name, rep);
			continue;
		}
	}
	nvlist_free(response);
	return (0);
}

/* Set extended system attribute boolean display */

void
set_sysattrb_display(char *name, boolean_t val, struct lbuf *rep)
{
	f_attr_t	fattr;
	const char	*opt;
	size_t		len;

	fattr = name_to_attr(name);
	if (fattr != F_ATTR_INVAL && fattr < sacnt) {
		if (vopt) {
			len = strlen(name);
			if (val) {
				rep->exttr[fattr].name = xmalloc(len + 1, rep);
				(void) strlcpy(rep->exttr[fattr].name, name,
				    len + 1);
			} else {
				rep->exttr[fattr].name = xmalloc(len + 3, rep);
				(void) snprintf(rep->exttr[fattr].name, len + 3,
				    "no%s", name);
			}
		} else {
			opt = attr_to_option(fattr);
			if (opt != NULL) {
				len = strlen(opt);
				rep->exttr[fattr].name = xmalloc(len + 1, rep);
				if (val)
					(void) strlcpy(rep->exttr[fattr].name,
					    opt, len + 1);
				else
					(void) strlcpy(rep->exttr[fattr].name,
					    "-", len + 1);
			}
		}
	}
}

/* Set extended system attribute timestamp display */

void
set_sysattrtm_display(char *name, struct lbuf *rep)
{
	uint_t		nelem;
	uint64_t	*value;
	int		i;
	size_t		len;

	if (nvpair_value_uint64_array(pair, &value, &nelem) == 0) {
		if (*value != NULL) {
			len = strlen(name);
			i = 0;
			while (rep->extm[i].stm != 0 && i < sacnt)
				i++;
			rep->extm[i].stm = value[0];
			rep->extm[i].nstm = value[1];
			rep->extm[i].name = xmalloc(len + 1, rep);
			(void) strlcpy(rep->extm[i].name, name, len + 1);
		}
	}
}

void
format_time(const char *format, time_t sec)
{

	(void) strftime(time_buf, sizeof (time_buf),
	    dcgettext(NULL, format, LC_TIME),
	    localtime(&sec));
}

void
format_etime(const char *format, time_t sec, time_t nsec)
{
	char fmt_buf[FMTSIZE];

	(void) snprintf(fmt_buf, FMTSIZE,
	    format, nsec);
	(void) strftime(time_buf, sizeof (time_buf),
	    fmt_buf, localtime(&sec));
}

/* Format timestamp extended system attributes */

void
format_attrtime(struct lbuf *p)
{
	int	tmattr = 0;
	int i;

	if (p->extm != NULL) {
		for (i = 0; i < sacnt; i++) {
			if (p->extm[i].name != NULL) {
				tmattr = 1;
				break;
			}
		}
	}
	if (tmattr) {
		if (Eflg)
			format_etime(FORMAT4, (time_t)p->extm[i].stm,
			    (time_t)p->extm[i].nstm);
		else  {
			if ((p->lmtime.tv_sec < year) ||
			    (p->lmtime.tv_sec > now))
				format_time(FORMAT1,
				    (time_t)p->extm[i].stm);
			else
				format_time(FORMAT2,
				    (time_t)p->extm[i].stm);
		}
	}
}

void
print_time(struct lbuf *p)
{
	int i = 0;

	new_line();
	if (Eflg) {
		format_etime(FORMAT4, p->lat.tv_sec, p->lat.tv_nsec);
		(void) printf("		timestamp: atime	%s\n",
		    time_buf);
		format_etime(FORMAT4, p->lct.tv_sec, p->lct.tv_nsec);
		(void) printf("		timestamp: ctime	%s\n",
		    time_buf);
		format_etime(FORMAT4, p->lmt.tv_sec, p->lmt.tv_nsec);
		(void) printf("		timestamp: mtime	%s\n",
		    time_buf);
		if (p->extm != NULL) {
			while (p->extm[i].nstm != 0 && i < sacnt) {
				format_etime(FORMAT4, p->extm[i].stm,
				    p->extm[i].nstm);
				if (p->extm[i].name != NULL) {
					(void) printf("		timestamp:"
					    " %s	%s\n",
					    p->extm[i].name, time_buf);
				}
				i++;
			}
		}
	} else {
		format_time(FORMAT3, p->lat.tv_sec);
		(void) printf("		timestamp: atime	%s\n",
		    time_buf);
		format_time(FORMAT3, p->lct.tv_sec);
		(void) printf("		timestamp: ctime	%s\n",
		    time_buf);
		format_time(FORMAT3, p->lmt.tv_sec);
		(void) printf("		timestamp: mtime	%s\n",
		    time_buf);
		if (p->extm != NULL) {
			while (p->extm[i].stm != 0 && i < sacnt) {
				format_time(FORMAT3, p->extm[i].stm);
				if (p->extm[i].name != NULL) {
					(void) printf("		timestamp:"
					    " %s	%s\n",
					    p->extm[i].name, time_buf);
				}
				i++;
			}
		}
	}
}

/* Free extended system attribute lists */

void
free_sysattr(struct lbuf *p)
{
	int i;

	if (p->exttr != NULL) {
		for (i = 0; i < sacnt; i++) {
			if (p->exttr[i].name != NULL)
				free(p->exttr[i].name);
		}
		free(p->exttr);
	}
	if (p->extm != NULL) {
		for (i = 0; i < sacnt; i++) {
			if (p->extm[i].name != NULL)
				free(p->extm[i].name);
		}
		free(p->extm);
	}
}

/* Allocate extended system attribute list */

void *
xmalloc(size_t size, struct lbuf *p)
{
	if ((p = malloc(size)) == NULL) {
		perror("ls");
		free_sysattr(p);
		nvlist_free(response);
		exit(2);
	}
	return (p);
}
