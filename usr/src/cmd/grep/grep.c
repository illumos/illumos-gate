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

/* Copyright 2012 Nexenta Systems, Inc.  All rights reserved. */

/*
 * Copyright 2013 Damian Bogel. All rights reserved.
 */

/*
 * grep -- print lines matching (or not matching) a pattern
 *
 *	status returns:
 *		0 - ok, and some matches
 *		1 - ok, but no matches
 *		2 - some error
 */

#include <sys/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <locale.h>
#include <memory.h>
#include <regexpr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ftw.h>
#include <limits.h>
#include <sys/param.h>

static const char *errstr[] = {
	"Range endpoint too large.",
	"Bad number.",
	"``\\digit'' out of range.",
	"No remembered search string.",
	"\\( \\) imbalance.",
	"Too many \\(.",
	"More than 2 numbers given in \\{ \\}.",
	"} expected after \\.",
	"First number exceeds second in \\{ \\}.",
	"[ ] imbalance.",
	"Regular expression overflow.",
	"Illegal byte sequence.",
	"Unknown regexp error code!!",
	NULL
};

#define	STDIN_FILENAME	gettext("(standard input)")

#define	errmsg(msg, arg)	(void) fprintf(stderr, gettext(msg), arg)
#define	BLKSIZE	512
#define	GBUFSIZ	8192
#define	MAX_DEPTH	1000

static int	temp;
static long long	lnum;
static char	*linebuf;
static char	*prntbuf = NULL;
static long	fw_lPrntBufLen = 0;
static int	nflag;
static int	bflag;
static int	lflag;
static int	cflag;
static int	rflag;
static int	Rflag;
static int	vflag;
static int	sflag;
static int	iflag;
static int	wflag;
static int	hflag;
static int 	Hflag;
static int	qflag;
static int	errflg;
static int	nfile;
static long long	tln;
static int	nsucc;
static int	outfn = 0;
static int	nlflag;
static char	*ptr, *ptrend;
static char	*expbuf;

static void	execute(const char *, int);
static void	regerr(int);
static void	prepare(const char *);
static int	recursive(const char *, const struct stat *, int, struct FTW *);
static int	succeed(const char *);

int
main(int argc, char **argv)
{
	int	c;
	char	*arg;
	extern int	optind;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "hHqblcnRrsviyw")) != -1)
		switch (c) {
		/* based on options order h or H is set as in GNU grep */
		case 'h':
			hflag++;
			Hflag = 0; /* h excludes H */
			break;
		case 'H':
			if (!lflag) /* H is excluded by l */
				Hflag++;
			hflag = 0; /* H excludes h */
			break;
		case 'q':	/* POSIX: quiet: status only */
			qflag++;
			break;
		case 'v':
			vflag++;
			break;
		case 'c':
			cflag++;
			break;
		case 'n':
			nflag++;
			break;
		case 'R':
			Rflag++;
			/* FALLTHROUGH */
		case 'r':
			rflag++;
			break;
		case 'b':
			bflag++;
			break;
		case 's':
			sflag++;
			break;
		case 'l':
			lflag++;
			Hflag = 0; /* l excludes H */
			break;
		case 'y':
		case 'i':
			iflag++;
			break;
		case 'w':
			wflag++;
			break;
		case '?':
			errflg++;
		}

	if (errflg || (optind >= argc)) {
		errmsg("Usage: grep [-c|-l|-q] [-r|-R] -hHbnsviw "
		    "pattern file . . .\n",
		    (char *)NULL);
		exit(2);
	}

	argv = &argv[optind];
	argc -= optind;
	nfile = argc - 1;

	if (strrchr(*argv, '\n') != NULL)
		regerr(41);

	if (iflag) {
		for (arg = *argv; *arg != NULL; ++arg)
			*arg = (char)tolower((int)((unsigned char)*arg));
	}

	if (wflag) {
		unsigned int	wordlen;
		char		*wordbuf;

		wordlen = strlen(*argv) + 5; /* '\\' '<' *argv '\\' '>' '\0' */
		if ((wordbuf = malloc(wordlen)) == NULL) {
			errmsg("grep: Out of memory for word\n", (char *)NULL);
			exit(2);
		}

		(void) strcpy(wordbuf, "\\<");
		(void) strcat(wordbuf, *argv);
		(void) strcat(wordbuf, "\\>");
		*argv = wordbuf;
	}

	expbuf = compile(*argv, (char *)0, (char *)0);
	if (regerrno)
		regerr(regerrno);

	if (--argc == 0)
		execute(NULL, 0);
	else
		while (argc-- > 0)
			prepare(*++argv);

	return (nsucc == 2 ? 2 : (nsucc == 0 ? 1 : 0));
}

static void
prepare(const char *path)
{
	struct	stat st;
	int	walkflags = FTW_CHDIR;
	char	*buf = NULL;

	if (rflag) {
		if (stat(path, &st) != -1 &&
		    (st.st_mode & S_IFMT) == S_IFDIR) {
			outfn = 1;

			/*
			 * Add trailing slash if arg
			 * is directory, to resolve symlinks.
			 */
			if (path[strlen(path) - 1] != '/') {
				(void) asprintf(&buf, "%s/", path);
				if (buf != NULL)
					path = buf;
			}

			/*
			 * Search through subdirs if path is directory.
			 * Don't follow symlinks if Rflag is not set.
			 */
			if (!Rflag)
				walkflags |= FTW_PHYS;

			if (nftw(path, recursive, MAX_DEPTH, walkflags) != 0) {
				if (!sflag)
					errmsg("grep: can't open %s\n", path);
				nsucc = 2;
			}
			return;
		}
	}
	execute(path, 0);
}

static int
recursive(const char *name, const struct stat *statp, int info, struct FTW *ftw)
{
	/*
	 * process files and follow symlinks if Rflag set.
	 */
	if (info != FTW_F) {
		if (!sflag &&
		    (info == FTW_SLN || info == FTW_DNR || info == FTW_NS)) {
			/* report broken symlinks and unreadable files */
			errmsg("grep: can't open %s\n", name);
		}
		return (0);
	}

	/* skip devices and pipes if Rflag is not set */
	if (!Rflag && !S_ISREG(statp->st_mode))
		return (0);

	/* pass offset to relative name from FTW_CHDIR */
	execute(name, ftw->base);
	return (0);
}

static void
execute(const char *file, int base)
{
	char	*lbuf, *p;
	long	count;
	long	offset = 0;
	char	*next_ptr = NULL;
	long	next_count = 0;

	tln = 0;

	if (prntbuf == NULL) {
		fw_lPrntBufLen = GBUFSIZ + 1;
		if ((prntbuf = malloc(fw_lPrntBufLen)) == NULL) {
			exit(2); /* out of memory - BAIL */
		}
		if ((linebuf = malloc(fw_lPrntBufLen)) == NULL) {
			exit(2); /* out of memory - BAIL */
		}
	}

	if (file == NULL) {
		temp = 0;
		file = STDIN_FILENAME;
	} else if ((temp = open(file + base, O_RDONLY)) == -1) {
		if (!sflag)
			errmsg("grep: can't open %s\n", file);
		nsucc = 2;
		return;
	}

	/* read in first block of bytes */
	if ((count = read(temp, prntbuf, GBUFSIZ)) <= 0) {
		(void) close(temp);

		if (cflag && !qflag) {
			if (Hflag || (nfile > 1 && !hflag))
				(void) fprintf(stdout, "%s:", file);
			if (!rflag)
			(void) fprintf(stdout, "%lld\n", tln);
		}
		return;
	}

	lnum = 0;
	ptr = prntbuf;
	for (;;) {
		/* look for next newline */
		if ((ptrend = memchr(ptr + offset, '\n', count)) == NULL) {
			offset += count;

			/*
			 * shift unused data to the beginning of the buffer
			 */
			if (ptr > prntbuf) {
				(void) memmove(prntbuf, ptr, offset);
				ptr = prntbuf;
			}

			/*
			 * re-allocate a larger buffer if this one is full
			 */
			if (offset + GBUFSIZ > fw_lPrntBufLen) {
				/*
				 * allocate a new buffer and preserve the
				 * contents...
				 */
				fw_lPrntBufLen += GBUFSIZ;
				if ((prntbuf = realloc(prntbuf,
				    fw_lPrntBufLen)) == NULL)
					exit(2);

				/*
				 * set up a bigger linebuffer (this is only used
				 * for case insensitive operations). Contents do
				 * not have to be preserved.
				 */
				free(linebuf);
				if ((linebuf = malloc(fw_lPrntBufLen)) == NULL)
					exit(2);

				ptr = prntbuf;
			}

			p = prntbuf + offset;
			if ((count = read(temp, p, GBUFSIZ)) > 0)
				continue;

			if (offset == 0)
				/* end of file already reached */
				break;

			/* last line of file has no newline */
			ptrend = ptr + offset;
			nlflag = 0;
		} else {
			next_ptr = ptrend + 1;
			next_count = offset + count - (next_ptr - ptr);
			nlflag = 1;
		}
		lnum++;
		*ptrend = '\0';

		if (iflag) {
			/*
			 * Make a lower case copy of the record
			 */
			p = ptr;
			for (lbuf = linebuf; p < ptrend; )
				*lbuf++ = (char)tolower((int)
				    (unsigned char)*p++);
			*lbuf = '\0';
			lbuf = linebuf;
		} else
			/*
			 * Use record as is
			 */
			lbuf = ptr;

		/* lflag only once */
		if ((step(lbuf, expbuf) ^ vflag) && succeed(file) == 1)
			break;

		if (!nlflag)
			break;

		ptr = next_ptr;
		count = next_count;
		offset = 0;
	}
	(void) close(temp);

	if (cflag && !qflag) {
		if (Hflag || (!hflag && ((nfile > 1) ||
		    (rflag && outfn))))
			(void) fprintf(stdout, "%s:", file);
		(void) fprintf(stdout, "%lld\n", tln);
	}
}

static int
succeed(const char *f)
{
	int nchars;
	nsucc = (nsucc == 2) ? 2 : 1;

	if (qflag) {
		/* no need to continue */
		return (1);
	}

	if (cflag) {
		tln++;
		return (0);
	}

	if (lflag) {
		(void) fprintf(stdout, "%s\n", f);
		return (1);
	}

	if (Hflag || (!hflag && (nfile > 1 || (rflag && outfn)))) {
		/* print filename */
		(void) fprintf(stdout, "%s:", f);
	}

	if (bflag)
		/* print block number */
		(void) fprintf(stdout, "%lld:", (offset_t)
		    ((lseek(temp, (off_t)0, SEEK_CUR) - 1) / BLKSIZE));

	if (nflag)
		/* print line number */
		(void) fprintf(stdout, "%lld:", lnum);

	if (nlflag) {
		/* newline at end of line */
		*ptrend = '\n';
		nchars = ptrend - ptr + 1;
	} else {
		/* don't write sentinel \0 */
		nchars = ptrend - ptr;
	}

	(void) fwrite(ptr, 1, nchars, stdout);
	return (0);
}

static void
regerr(int err)
{
	errmsg("grep: RE error %d: ", err);
	switch (err) {
		case 11:
			err = 0;
			break;
		case 16:
			err = 1;
			break;
		case 25:
			err = 2;
			break;
		case 41:
			err = 3;
			break;
		case 42:
			err = 4;
			break;
		case 43:
			err = 5;
			break;
		case 44:
			err = 6;
			break;
		case 45:
			err = 7;
			break;
		case 46:
			err = 8;
			break;
		case 49:
			err = 9;
			break;
		case 50:
			err = 10;
			break;
		case 67:
			err = 11;
			break;
		default:
			err = 12;
			break;
	}

	errmsg("%s\n", gettext(errstr[err]));
	exit(2);
}
