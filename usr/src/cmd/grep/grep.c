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

/*
 * grep - pattern matching program - combined grep, egrep, and fgrep.
 *	Based on MKS grep command, with XCU & Solaris mods.
 */

/*
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

/*
 * Copyright 2018 RackTop Systems.
 * Copyright 2018 Nexenta Systems, Inc.
 * Copyright 2013 Damian Bogel. All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <regex.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <locale.h>
#include <wchar.h>
#include <errno.h>
#include <unistd.h>
#include <wctype.h>
#include <ftw.h>
#include <sys/param.h>

#define	STDIN_FILENAME gettext("(standard input)")

#define	BSIZE		512		/* Size of block for -b */
#define	BUFSIZE		8192		/* Input buffer size */
#define	MAX_DEPTH	1000		/* how deep to recurse */

#define	AFTER 	1			/* 'After' Context */
#define	BEFORE 	2			/* 'Before' Context */
#define	CONTEXT	(AFTER|BEFORE)		/* Full Context */

#define	M_CSETSIZE	256		/* singlebyte chars */
static int	bmglen;			/* length of BMG pattern */
static char	*bmgpat;		/* BMG pattern */
static int	bmgtab[M_CSETSIZE];	/* BMG delta1 table */

typedef	struct	_PATTERN	{
	char	*pattern;		/* original pattern */
	wchar_t	*wpattern;		/* wide, lowercased pattern */
	struct	_PATTERN	*next;
	regex_t	re;			/* compiled pattern */
} PATTERN;

static PATTERN	*patterns;
static char	errstr[128];		/* regerror string buffer */
static int	regflags = 0;		/* regcomp options */
static int	matched = 0;		/* return of the grep() */
static int	errors = 0;		/* count of errors */
static uchar_t	fgrep = 0;		/* Invoked as fgrep */
static uchar_t	egrep = 0;		/* Invoked as egrep */
static boolean_t	nvflag = B_TRUE;	/* Print matching lines */
static uchar_t	cflag;			/* Count of matches */
static uchar_t	iflag;			/* Case insensitve matching */
static uchar_t	Hflag;			/* Precede lines by file name */
static uchar_t	hflag;			/* Supress printing of filename */
static uchar_t	lflag;			/* Print file names of matches */
static uchar_t	nflag;			/* Precede lines by line number */
static uchar_t	rflag;			/* Search directories recursively */
static uchar_t	bflag;			/* Preccede matches by block number */
static uchar_t	sflag;			/* Suppress file error messages */
static uchar_t	qflag;			/* Suppress standard output */
static uchar_t	wflag;			/* Search for expression as a word */
static uchar_t	xflag;			/* Anchoring */
static uchar_t	Eflag;			/* Egrep or -E flag */
static uchar_t	Fflag;			/* Fgrep or -F flag */
static uchar_t	Rflag;			/* Like rflag, but follow symlinks */
static uchar_t	outfn;			/* Put out file name */
static uchar_t	conflag;		/* show context of matches */
static char	*cmdname;

static int	use_wchar, use_bmg, mblocale;

static size_t	outbuflen, prntbuflen, conbuflen;
static unsigned long 	conalen, conblen, conmatches;
static char	*prntbuf, *conbuf;
static wchar_t	*outline;

static void	addfile(const char *fn);
static void	addpattern(char *s);
static void	fixpatterns(void);
static void	usage(void);
static int	grep(int, const char *);
static void	bmgcomp(char *, int);
static char	*bmgexec(char *, char *);
static int	recursive(const char *, const struct stat *, int, struct FTW *);
static void	process_path(const char *);
static void	process_file(const char *, int);

/*
 * mainline for grep
 */
int
main(int argc, char **argv)
{
	char	*ap, *test;
	int	c;
	int	fflag = 0;
	int	i, n_pattern = 0, n_file = 0;
	char	**pattern_list = NULL;
	char	**file_list = NULL;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * true if this is running on the multibyte locale
	 */
	mblocale = (MB_CUR_MAX > 1);
	/*
	 * Skip leading slashes
	 */
	cmdname = argv[0];
	if (ap = strrchr(cmdname, '/'))
		cmdname = ap + 1;

	ap = cmdname;
	/*
	 * Detect egrep/fgrep via command name, map to -E and -F options.
	 */
	if (*ap == 'e' || *ap == 'E') {
		regflags |= REG_EXTENDED;
		egrep++;
	} else {
		if (*ap == 'f' || *ap == 'F') {
			fgrep++;
		}
	}

	/* check for non-standard "-line-count" option */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0)
			break;

		/* isdigit() check prevents negative arguments */
		if ((argv[i][0] == '-') && isdigit(argv[i][1])) {
			if (strlen(&argv[i][1]) !=
			    strspn(&argv[i][1], "0123456789")) {
				(void) fprintf(stderr, gettext(
				    "%s: Bad number flag\n"), argv[0]);
				usage();
			}

			errno = 0;
			conalen = conblen = strtoul(&argv[i][1], (char **)NULL,
			    10);

			if (errno != 0 || conalen >= ULONG_MAX) {
				(void) fprintf(stderr, gettext(
				    "%s: Bad context argument\n"), argv[0]);
			} else if (conalen)
				conflag = CONTEXT;

			while (i < argc) {
				argv[i] = argv[i + 1];
				i++;
			}
			argc--;
		}
	}

	while ((c = getopt(argc, argv, "vwchHilnrbse:f:qxEFIRA:B:C:")) != EOF) {
		unsigned long tval;
		switch (c) {
		case 'v':	/* POSIX: negate matches */
			nvflag = B_FALSE;
			break;

		case 'c':	/* POSIX: write count */
			cflag++;
			break;

		case 'i':	/* POSIX: ignore case */
			iflag++;
			regflags |= REG_ICASE;
			break;

		case 'l':	/* POSIX: Write filenames only */
			lflag++;
			break;

		case 'n':	/* POSIX: Write line numbers */
			nflag++;
			break;

		case 'r':	/* Solaris: search recursively */
			rflag++;
			break;

		case 'b':	/* Solaris: Write file block numbers */
			bflag++;
			break;

		case 's':	/* POSIX: No error msgs for files */
			sflag++;
			break;

		case 'e':	/* POSIX: pattern list */
			n_pattern++;
			pattern_list = realloc(pattern_list,
			    sizeof (char *) * n_pattern);
			if (pattern_list == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}
			*(pattern_list + n_pattern - 1) = optarg;
			break;

		case 'f':	/* POSIX: pattern file */
			fflag = 1;
			n_file++;
			file_list = realloc(file_list,
			    sizeof (char *) * n_file);
			if (file_list == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}
			*(file_list + n_file - 1) = optarg;
			break;

		/* based on options order h or H is set as in GNU grep */
		case 'h':	/* Solaris: supress printing of file name */
			hflag = 1;
			Hflag = 0;
			break;
		/* Solaris: precede every matching with file name */
		case 'H':
			Hflag = 1;
			hflag = 0;
			break;

		case 'q':	/* POSIX: quiet: status only */
			qflag++;
			break;

		case 'w':	/* Solaris: treat pattern as word */
			wflag++;
			break;

		case 'x':	/* POSIX: full line matches */
			xflag++;
			break;

		case 'E':	/* POSIX: Extended RE's */
			regflags |= REG_EXTENDED;
			Eflag++;
			break;

		case 'F':	/* POSIX: strings, not RE's */
			Fflag++;
			break;

		case 'R':	/* Solaris: like rflag, but follow symlinks */
			Rflag++;
			rflag++;
			break;

		case 'A':	/* print N lines after each match */
			errno = 0;
			conalen = strtoul(optarg, &test, 10);
			/* *test will be non-null if optarg is negative */
			if (errno != 0 || *test != '\0' ||
			    conalen >= ULONG_MAX) {
				(void) fprintf(stderr, gettext(
				    "%s: Bad context argument: %s\n"),
				    argv[0], optarg);
				exit(2);
			}
			if (conalen)
				conflag |= AFTER;
			else
				conflag &= ~AFTER;
			break;
		case 'B':	/* print N lines before each match */
			errno = 0;
			conblen = strtoul(optarg, &test, 10);
			/* *test will be non-null if optarg is negative */
			if (errno != 0 || *test != '\0' ||
			    conblen >= ULONG_MAX) {
				(void) fprintf(stderr, gettext(
				    "%s: Bad context argument: %s\n"),
				    argv[0], optarg);
				exit(2);
			}
			if (conblen)
				conflag |= BEFORE;
			else
				conflag &= ~BEFORE;
			break;
		case 'C':	/* print N lines around each match */
			errno = 0;
			tval = strtoul(optarg, &test, 10);
			/* *test will be non-null if optarg is negative */
			if (errno != 0 || *test != '\0' || tval >= ULONG_MAX) {
				(void) fprintf(stderr, gettext(
				    "%s: Bad context argument: %s\n"),
				    argv[0], optarg);
				exit(2);
			}
			if (tval) {
				if ((conflag & BEFORE) == 0)
					conblen = tval;
				if ((conflag & AFTER) == 0)
					conalen = tval;
				conflag = CONTEXT;
			}
			break;

		default:
			usage();
		}
	}
	/*
	 * If we're invoked as egrep or fgrep we need to do some checks
	 */

	if (egrep || fgrep) {
		/*
		 * Use of -E or -F with egrep or fgrep is illegal
		 */
		if (Eflag || Fflag)
			usage();
		/*
		 * Don't allow use of wflag with egrep / fgrep
		 */
		if (wflag)
			usage();
		/*
		 * For Solaris the -s flag is equivalent to XCU -q
		 */
		if (sflag)
			qflag++;
		/*
		 * done with above checks - set the appropriate flags
		 */
		if (egrep)
			Eflag++;
		else			/* Else fgrep */
			Fflag++;
	}

	if (wflag && (Eflag || Fflag)) {
		/*
		 * -w cannot be specified with grep -F
		 */
		usage();
	}

	/*
	 * -E and -F flags are mutually exclusive - check for this
	 */
	if (Eflag && Fflag)
		usage();

	/*
	 * -l overrides -H like in GNU grep
	 */
	if (lflag)
		Hflag = 0;

	/*
	 * -c, -l and -q flags are mutually exclusive
	 * We have -c override -l like in Solaris.
	 * -q overrides -l & -c programmatically in grep() function.
	 */
	if (cflag && lflag)
		lflag = 0;

	argv += optind - 1;
	argc -= optind - 1;

	/*
	 * Now handling -e and -f option
	 */
	if (pattern_list) {
		for (i = 0; i < n_pattern; i++) {
			addpattern(pattern_list[i]);
		}
		free(pattern_list);
	}
	if (file_list) {
		for (i = 0; i < n_file; i++) {
			addfile(file_list[i]);
		}
		free(file_list);
	}

	/*
	 * No -e or -f?  Make sure there is one more arg, use it as the pattern.
	 */
	if (patterns == NULL && !fflag) {
		if (argc < 2)
			usage();
		addpattern(argv[1]);
		argc--;
		argv++;
	}

	/*
	 * If -x flag is not specified or -i flag is specified
	 * with fgrep in a multibyte locale, need to use
	 * the wide character APIs.  Otherwise, byte-oriented
	 * process will be done.
	 */
	use_wchar = Fflag && mblocale && (!xflag || iflag);

	/*
	 * Compile Patterns and also decide if BMG can be used
	 */
	fixpatterns();

	/* Process all files: stdin, or rest of arg list */
	if (argc < 2) {
		matched = grep(0, STDIN_FILENAME);
	} else {
		if (Hflag || (argc > 2 && hflag == 0))
			outfn = 1;	/* Print filename on match line */
		for (argv++; *argv != NULL; argv++) {
			process_path(*argv);
		}
	}
	/*
	 * Return() here is used instead of exit
	 */

	(void) fflush(stdout);

	if (errors)
		return (2);
	return (matched ? 0 : 1);
}

static void
process_path(const char *path)
{
	struct	stat st;
	int	walkflags = FTW_CHDIR;
	char	*buf = NULL;

	if (rflag) {
		if (stat(path, &st) != -1 &&
		    (st.st_mode & S_IFMT) == S_IFDIR) {
			outfn = 1; /* Print filename */

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
					(void) fprintf(stderr,
					    gettext("%s: can't open \"%s\"\n"),
					    cmdname, path);
				errors = 1;
			}
			return;
		}
	}
	process_file(path, 0);
}

/*
 * Read and process all files in directory recursively.
 */
static int
recursive(const char *name, const struct stat *statp, int info, struct FTW *ftw)
{
	/*
	 * Process files and follow symlinks if Rflag set.
	 */
	if (info != FTW_F) {
		/* Report broken symlinks and unreadable files */
		if (!sflag &&
		    (info == FTW_SLN || info == FTW_DNR || info == FTW_NS)) {
			(void) fprintf(stderr,
			    gettext("%s: can't open \"%s\"\n"), cmdname, name);
		}
		return (0);
	}


	/* Skip devices and pipes if Rflag is not set */
	if (!Rflag && !S_ISREG(statp->st_mode))
		return (0);
	/* Pass offset to relative name from FTW_CHDIR */
	process_file(name, ftw->base);
	return (0);
}

/*
 * Opens file and call grep function.
 */
static void
process_file(const char *name, int base)
{
	int fd;

	if ((fd = open(name + base, O_RDONLY)) == -1) {
		errors = 1;
		if (!sflag) /* Silent mode */
			(void) fprintf(stderr, gettext(
			    "%s: can't open \"%s\"\n"),
			    cmdname, name);
		return;
	}
	matched |= grep(fd, name);
	(void) close(fd);

	if (ferror(stdout)) {
		(void) fprintf(stderr, gettext(
		    "%s: error writing to stdout\n"),
		    cmdname);
		(void) fflush(stdout);
		exit(2);
	}

}

/*
 * Add a file of strings to the pattern list.
 */
static void
addfile(const char *fn)
{
	FILE	*fp;
	char	*inbuf;
	char	*bufp;
	size_t	bufsiz, buflen, bufused;

	/*
	 * Open the pattern file
	 */
	if ((fp = fopen(fn, "r")) == NULL) {
		(void) fprintf(stderr, gettext("%s: can't open \"%s\"\n"),
		    cmdname, fn);
		exit(2);
	}
	bufsiz = BUFSIZE;
	if ((inbuf = malloc(bufsiz)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: out of memory\n"), cmdname);
		exit(2);
	}
	bufp = inbuf;
	bufused = 0;
	/*
	 * Read in the file, reallocing as we need more memory
	 */
	while (fgets(bufp, bufsiz - bufused, fp) != NULL) {
		buflen = strlen(bufp);
		bufused += buflen;
		if (bufused + 1 == bufsiz && bufp[buflen - 1] != '\n') {
			/*
			 * if this line does not fit to the buffer,
			 * realloc larger buffer
			 */
			bufsiz += BUFSIZE;
			if ((inbuf = realloc(inbuf, bufsiz)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}
			bufp = inbuf + bufused;
			continue;
		}
		if (bufp[buflen - 1] == '\n') {
			bufp[--buflen] = '\0';
		}
		addpattern(inbuf);

		bufp = inbuf;
		bufused = 0;
	}
	free(inbuf);
	free(prntbuf);
	free(conbuf);
	(void) fclose(fp);
}

/*
 * Add a string to the pattern list.
 */
static void
addpattern(char *s)
{
	PATTERN	*pp;
	char	*wordbuf;
	char	*np;

	for (; ; ) {
		np = strchr(s, '\n');
		if (np != NULL)
			*np = '\0';
		if ((pp = malloc(sizeof (PATTERN))) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: out of memory\n"),
			    cmdname);
			exit(2);
		}
		if (wflag) {
			/*
			 * Solaris wflag support: Add '<' '>' to pattern to
			 * select it as a word. Doesn't make sense with -F
			 * but we're Libertarian.
			 */
			size_t	slen, wordlen;

			slen = strlen(s);
			wordlen = slen + 5; /* '\\' '<' s '\\' '>' '\0' */
			if ((wordbuf = malloc(wordlen)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}
			(void) strcpy(wordbuf, "\\<");
			(void) strcpy(wordbuf + 2, s);
			(void) strcpy(wordbuf + 2 + slen, "\\>");
		} else {
			if ((wordbuf = strdup(s)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}
		}
		pp->pattern = wordbuf;
		pp->next = patterns;
		patterns = pp;
		if (np == NULL)
			break;
		s = np + 1;
	}
}

/*
 * Fix patterns.
 * Must do after all arguments read, in case later -i option.
 */
static void
fixpatterns(void)
{
	PATTERN	*pp;
	int	rv, fix_pattern, npatterns;

	/*
	 * Fix the specified pattern if -x is specified.
	 */
	fix_pattern = !Fflag && xflag;

	for (npatterns = 0, pp = patterns; pp != NULL; pp = pp->next) {
		npatterns++;
		if (fix_pattern) {
			char	*cp, *cq;
			size_t	plen, nplen;

			plen = strlen(pp->pattern);
			/* '^' pattern '$' */
			nplen = 1 + plen + 1 + 1;
			if ((cp = malloc(nplen)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}
			cq = cp;
			*cq++ = '^';
			cq = strcpy(cq, pp->pattern) + plen;
			*cq++ = '$';
			*cq = '\0';
			free(pp->pattern);
			pp->pattern = cp;
		}

		if (Fflag) {
			if (use_wchar) {
				/*
				 * Fflag && mblocale && iflag
				 * Fflag && mblocale && !xflag
				 */
				size_t	n;
				n = strlen(pp->pattern) + 1;
				if ((pp->wpattern =
				    malloc(sizeof (wchar_t) * n)) == NULL) {
					(void) fprintf(stderr,
					    gettext("%s: out of memory\n"),
					    cmdname);
					exit(2);
				}
				if (mbstowcs(pp->wpattern, pp->pattern, n) ==
				    (size_t)-1) {
					(void) fprintf(stderr,
					    gettext("%s: failed to convert "
					    "\"%s\" to wide-characters\n"),
					    cmdname, pp->pattern);
					exit(2);
				}
				if (iflag) {
					wchar_t	*wp;
					for (wp = pp->wpattern; *wp != L'\0';
					    wp++) {
						*wp = towlower((wint_t)*wp);
					}
				}
				free(pp->pattern);
			} else {
				/*
				 * Fflag && mblocale && !iflag
				 * Fflag && !mblocale && iflag
				 * Fflag && !mblocale && !iflag
				 */
				if (iflag) {
					unsigned char	*cp;
					for (cp = (unsigned char *)pp->pattern;
					    *cp != '\0'; cp++) {
						*cp = tolower(*cp);
					}
				}
			}
			/*
			 * fgrep: No regular expressions.
			 */
			continue;
		}

		/*
		 * For non-fgrep, compile the regular expression,
		 * give an informative error message, and exit if
		 * it didn't compile.
		 */
		if ((rv = regcomp(&pp->re, pp->pattern, regflags)) != 0) {
			(void) regerror(rv, &pp->re, errstr, sizeof (errstr));
			(void) fprintf(stderr,
			    gettext("%s: RE error in %s: %s\n"),
			    cmdname, pp->pattern, errstr);
			exit(2);
		}
		free(pp->pattern);
	}

	/*
	 * Decide if we are able to run the Boyer-Moore-Gosper algorithm.
	 * Use the Boyer-Moore-Gosper algorithm if:
	 * - fgrep			(Fflag)
	 * - singlebyte locale		(!mblocale)
	 * - no ignoring case		(!iflag)
	 * - no printing line numbers	(!nflag)
	 * - no negating the output	(nvflag)
	 * - only one pattern		(npatterns == 1)
	 * - non zero length pattern	(strlen(patterns->pattern) != 0)
	 * - no context required	(conflag == 0)
	 *
	 * It's guaranteed patterns->pattern is still alive
	 * when Fflag && !mblocale.
	 */
	use_bmg = Fflag && !mblocale && !iflag && !nflag && nvflag &&
	    (npatterns == 1) && (strlen(patterns->pattern) != 0) &&
	    conflag == 0;
}

/*
 * Search a newline from the beginning of the string
 */
static char *
find_nl(const char *ptr, size_t len)
{
	while (len-- != 0) {
		if (*ptr++ == '\n') {
			return ((char *)--ptr);
		}
	}
	return (NULL);
}

/*
 * Search a newline from the end of the string
 */
static char *
rfind_nl(const char *ptr, size_t len)
{
	const char	*uptr = ptr + len;
	while (len--) {
		if (*--uptr == '\n') {
			return ((char *)uptr);
		}
	}
	return (NULL);
}

/*
 * Duplicate the specified string converting each character
 * into a lower case.
 */
static char *
istrdup(const char *s1)
{
	static size_t	ibuflen = 0;
	static char	*ibuf = NULL;
	size_t	slen;
	char	*p;

	slen = strlen(s1);
	if (slen >= ibuflen) {
		/* ibuf does not fit to s1 */
		ibuflen = slen + 1;
		ibuf = realloc(ibuf, ibuflen);
		if (ibuf == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: out of memory\n"), cmdname);
			exit(2);
		}
	}
	p = ibuf;
	do {
		*p++ = tolower(*s1);
	} while (*s1++ != '\0');
	return (ibuf);
}

/*
 * Do grep on a single file.
 * Return true in any lines matched.
 *
 * We have two strategies:
 * The fast one is used when we have a single pattern with
 * a string known to occur in the pattern. We can then
 * do a BMG match on the whole buffer.
 * This is an order of magnitude faster.
 * Otherwise we split the buffer into lines,
 * and check for a match on each line.
 */
static int
grep(int fd, const char *fn)
{
	PATTERN *pp;
	off_t	data_len;	/* length of the data chunk */
	off_t	line_len;	/* length of the current line */
	off_t	line_offset;	/* current line's offset from the beginning */
	off_t	blkoffset;	/* line_offset but context-compatible */
	long long	lineno, linenum;
	long long	matches = 0;	/* Number of matching lines */
	long long	conacnt = 0, conbcnt = 0; 	/* context line count */
	int	newlinep;	/* 0 if the last line of file has no newline */
	char	*ptr, *ptrend, *prntptr, *prntptrend;
	char	*nextptr = NULL, *nextend = NULL;
	char	*conptr = NULL, *conptrend = NULL;
	char	*matchptr = NULL;
	int	conaprnt = 0, conbprnt = 0, lastmatch = 0;
	boolean_t	nearmatch; /* w/in N+1 of last match */
	boolean_t	havematch = B_FALSE; /* have a match in context */
	size_t	prntlen;

	if (patterns == NULL)
		return (0);	/* no patterns to match -- just return */

	pp = patterns;

	if (use_bmg) {
		bmgcomp(pp->pattern, strlen(pp->pattern));
	}

	if (use_wchar && outline == NULL) {
		outbuflen = BUFSIZE + 1;
		outline = malloc(sizeof (wchar_t) * outbuflen);
		if (outline == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    cmdname);
			exit(2);
		}
	}

	if (prntbuf == NULL) {
		prntbuflen = BUFSIZE;
		if ((prntbuf = malloc(prntbuflen + 1)) == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    cmdname);
			exit(2);
		}
	}

	if (conflag != 0 && (conbuf == NULL)) {
		conbuflen = BUFSIZE;
		if ((conbuf = malloc(BUFSIZE+1)) == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    cmdname);
			exit(2);
		}
	}

	nearmatch = (conmatches != 0);
	blkoffset = line_offset = 0;
	lineno = 0;
	linenum = 1;
	newlinep = 1;
	data_len = 0;
	for (; ; ) {
		long	count;
		off_t	offset = 0;
		char	separate;
		boolean_t	last_ctx = B_FALSE, eof = B_FALSE;

		if (data_len == 0) {
			/*
			 * If no data in the buffer, reset ptr
			 */
			ptr = prntbuf;
			if (conflag != 0 && conptr == NULL) {
				conptr = conbuf;
				conptrend = conptr - 1;
			}
		}
		if (ptr == prntbuf) {
			/*
			 * The current data chunk starts from prntbuf.
			 * This means either the buffer has no data
			 * or the buffer has no newline.
			 * So, read more data from input.
			 */
			count = read(fd, ptr + data_len, prntbuflen - data_len);
			if (count < 0) {
				/* read error */
				if (cflag) {
					if (outfn && !rflag) {
						(void) fprintf(stdout,
						    "%s:", fn);
					}
					if (!qflag && !rflag) {
						(void) fprintf(stdout, "%lld\n",
						    matches);
					}
				}
				return (0);
			} else if (count == 0) {
				/* no new data */
				eof = B_TRUE;

				if (data_len == 0) {
					/* end of file already reached */
					if (conflag != 0) {
						if (conptrend >= conptr)
							*conptrend = '\n';
						last_ctx = B_TRUE;
						goto L_next_line;
					} else {
						goto out;
					}
				}
				/* last line of file has no newline */
				ptrend = ptr + data_len;
				newlinep = 0;
				goto L_start_process;
			}
			offset = data_len;
			data_len += count;
		}

		/*
		 * Look for newline in the chunk
		 * between ptr + offset and ptr + data_len - offset.
		 */
		ptrend = find_nl(ptr + offset, data_len - offset);
		if (ptrend == NULL) {
			/* no newline found in this chunk */
			if (ptr > prntbuf) {
				/*
				 * Move remaining data to the beginning
				 * of the buffer.
				 * Remaining data lie from ptr for
				 * data_len bytes.
				 */
				(void) memmove(prntbuf, ptr, data_len);
			}
			if (data_len == prntbuflen) {
				/*
				 * Not enough room in the buffer
				 */
				if (prntbuflen > SIZE_MAX - BUFSIZE) {
					(void) fprintf(stderr,
					    gettext("%s: buflen would"
					    " overflow\n"),
					    cmdname);
					exit(2);
				}

				prntbuflen += BUFSIZE;
				prntbuf = realloc(prntbuf, prntbuflen + 1);
				if (prntbuf == NULL) {
					(void) fprintf(stderr,
					    gettext("%s: out of memory\n"),
					    cmdname);
					exit(2);
				}
			}
			ptr = prntbuf;
			/* read the next input */
			continue;
		}
L_start_process:

		/*
		 * Beginning of the chunk:	ptr
		 * End of the chunk:		ptr + data_len
		 * Beginning of the line:	ptr
		 * End of the line:		ptrend
		 *
		 * conptr:	Beginning of the context.
		 * conptrend: If context is empty, conptr - 1 (invalid memory).
		 *	Otherwise, Last newline in the context.
		 */

		if (use_bmg) {
			/*
			 * Use Boyer-Moore-Gosper algorithm to find out if
			 * this chunk (not this line) contains the specified
			 * pattern.  If not, restart from the last line
			 * of this chunk.
			 */
			char	*bline;
			bline = bmgexec(ptr, ptr + data_len);
			if (bline == NULL) {
				/*
				 * No pattern found in this chunk.
				 * Need to find the last line
				 * in this chunk.
				 */
				ptrend = rfind_nl(ptr, data_len);

				/*
				 * When this chunk does not contain newline,
				 * ptrend becomes NULL, which should happen
				 * when the last line of file does not end
				 * with a newline.  At such a point,
				 * newlinep should have been set to 0.
				 * Therefore, just after jumping to
				 * L_skip_line, the main for-loop quits,
				 * and the line_len value won't be
				 * used.
				 */
				line_len = ptrend - ptr;
				goto L_skip_line;
			}
			if (bline > ptrend) {
				/*
				 * Pattern found not in the first line
				 * of this chunk.
				 * Discard the first line.
				 */
				line_len = ptrend - ptr;
				goto L_skip_line;
			}
			/*
			 * Pattern found in the first line of this chunk.
			 * Using this result.
			 */
			*ptrend = '\0';
			line_len = ptrend - ptr;

			/*
			 * before jumping to L_next_line,
			 * need to handle xflag if specified
			 */
			if (xflag && (line_len != bmglen ||
			    strcmp(bmgpat, ptr) != 0)) {
				/* didn't match */
				pp = NULL;
			} else {
				pp = patterns; /* to make it happen */
			}
			goto L_next_line;
		}
		lineno++;
		/*
		 * Line starts from ptr and ends at ptrend.
		 * line_len will be the length of the line.
		 */
		*ptrend = '\0';
		line_len = ptrend - ptr;

		/*
		 * From now, the process will be performed based
		 * on the line from ptr to ptrend.
		 */
		if (use_wchar) {
			size_t	len;

			if (line_len >= outbuflen) {
				outbuflen = line_len + 1;
				outline = realloc(outline,
				    sizeof (wchar_t) * outbuflen);
				if (outline == NULL) {
					(void) fprintf(stderr,
					    gettext("%s: out of memory\n"),
					    cmdname);
					exit(2);
				}
			}

			len = mbstowcs(outline, ptr, line_len);
			if (len == (size_t)-1) {
				(void) fprintf(stderr, gettext(
	"%s: input file \"%s\": line %lld: invalid multibyte character\n"),
				    cmdname, fn, lineno);
				/* never match a line with invalid sequence */
				goto L_skip_line;
			}
			outline[len] = L'\0';

			if (iflag) {
				wchar_t	*cp;
				for (cp = outline; *cp != '\0'; cp++) {
					*cp = towlower((wint_t)*cp);
				}
			}

			if (xflag) {
				for (pp = patterns; pp; pp = pp->next) {
					if (outline[0] == pp->wpattern[0] &&
					    wcscmp(outline,
					    pp->wpattern) == 0) {
						/* matched */
						break;
					}
				}
			} else {
				for (pp = patterns; pp; pp = pp->next) {
					if (wcswcs(outline, pp->wpattern)
					    != NULL) {
						/* matched */
						break;
					}
				}
			}
		} else if (Fflag) {
			/* fgrep in byte-oriented handling */
			char	*fptr;
			if (iflag) {
				fptr = istrdup(ptr);
			} else {
				fptr = ptr;
			}
			if (xflag) {
				/* fgrep -x */
				for (pp = patterns; pp; pp = pp->next) {
					if (fptr[0] == pp->pattern[0] &&
					    strcmp(fptr, pp->pattern) == 0) {
						/* matched */
						break;
					}
				}
			} else {
				for (pp = patterns; pp; pp = pp->next) {
					if (strstr(fptr, pp->pattern) != NULL) {
						/* matched */
						break;
					}
				}
			}
		} else {
			/* grep or egrep */
			for (pp = patterns; pp; pp = pp->next) {
				int	rv;

				rv = regexec(&pp->re, ptr, 0, NULL, 0);
				if (rv == REG_OK) {
					/* matched */
					break;
				}

				switch (rv) {
				case REG_NOMATCH:
					break;
				case REG_ECHAR:
					(void) fprintf(stderr, gettext(
	    "%s: input file \"%s\": line %lld: invalid multibyte character\n"),
					    cmdname, fn, lineno);
					break;
				default:
					(void) regerror(rv, &pp->re, errstr,
					    sizeof (errstr));
					(void) fprintf(stderr, gettext(
	    "%s: input file \"%s\": line %lld: %s\n"),
					    cmdname, fn, lineno, errstr);
					exit(2);
				}
			}
		}

		/*
		 * Context is set up as follows:
		 * For a 'Before' context, we maintain a set of pointers
		 * containing 'N' lines of context. If the current number of
		 * lines contained is greater than N, and N isn't a match, the
		 * start pointer is moved forward to the next newline.
		 *
		 * If we ever find a match, we print out immediately.
		 * 'nearmatch' tells us if we're within N+1 lines of the last
		 * match ; if we are, and we find another match, we don't
		 * separate the matches. 'nearmatch' becomes false when
		 * a line gets rotated out of the context.
		 *
		 * For an 'After' context, we simply wait until we've found a
		 * match, then create a context N+1 lines big. If we don't find
		 * a match within the context, we print out the current context.
		 * Otherwise, we save a reference to the new matching line,
		 * print out the other context, and reset our context pointers
		 * to the new matching line.
		 *
		 * 'nearmatch' becomes false when we find a non-matching line
		 * that isn't a part of any context.
		 *
		 * A full-context is implemented as a combination of the
		 * 'Before' and 'After' context logic. Before we find a match,
		 * we follow the Before logic. When we find a match, we
		 * follow the After logic. 'nearmatch' is handled by the Before
		 * logic.
		 */

		if (conflag == 0)
			goto L_next_line;

		/* Do we have room to add this line to the context buffer? */
		while ((line_len + 1) > (conbuflen -
		    ((conptrend >= conptr) ? conptrend - conbuf : 0))) {
			char *oldconbuf = conbuf;
			char *oldconptr = conptr;
			long tmp = matchptr - conptr;

			if (conbuflen > SIZE_MAX - BUFSIZE) {
				(void) fprintf(stderr,
				    gettext("%s: buflen would overflow\n"),
				    cmdname);
				exit(2);
			}

			conbuflen += BUFSIZE;
			conbuf = realloc(conbuf, conbuflen + 1);
			if (conbuf == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"),
				    cmdname);
				exit(2);
			}

			conptr = conbuf + (conptr - oldconbuf);
			conptrend = conptr + (conptrend - oldconptr);
			if (matchptr)
				matchptr = conptr + tmp;
		}
		(void) memcpy(conptrend + 1, ptr, line_len);
		conptrend += line_len + 1;
		*conptrend = '\n';

		if (nvflag == (pp != NULL)) {
			/* matched */
			if (havematch) {
				if ((conflag & AFTER) != 0) {
					conaprnt = 1;
					nextend = conptrend;
					conptrend = conptr + lastmatch;
					nextptr = conptrend + 1;
					*nextend = '\n';
				}
			} else {
				if (conflag == AFTER) {
					conptr = conptrend - (line_len);
					linenum = lineno;
				}
				blkoffset = line_offset -
				    (conptrend - conptr - line_len);
			}

			if (conflag == BEFORE)
				conbprnt = 1;

			lastmatch = conptrend - conptr;
			havematch = B_TRUE;
			goto L_next_line;
		}

		if (!havematch) {
			if ((conflag & BEFORE) != 0) {
				if (conbcnt >= conblen) {
					char *tmp = conptr;
					conptr = find_nl(conptr,
					    conptrend - conptr) + 1;
					if (bflag)
						blkoffset += conptr - tmp;
					linenum++;
					nearmatch = B_TRUE;
				} else {
					conbcnt++;
				}
			}
			if (conflag == AFTER)
				nearmatch = B_TRUE;
		} else  {
			if (++conacnt >= conalen && !conaprnt && conalen)
				conaprnt = 1;
			else
				lastmatch = conptrend - conptr;
		}

L_next_line:
		/*
		 * Here, if pp points to non-NULL, something has been matched
		 * to the pattern.
		 */
		if (!last_ctx && nvflag == (pp != NULL)) {
			matches++;
			if (!nextend)
				matchptr = (conflag != 0) ? conptrend : ptrend;
		}

		/*
		 * Set up some print context so that we can treat
		 * single-line matches as a zero-N context.
		 * Apply CLI flags to each line of the context.
		 *
		 * For context, we only print if we both have a match and are
		 * either at the end of the data stream, or we've previously
		 * declared that we want to print for a particular context.
		 */
		if (havematch && (eof || conaprnt || conbprnt)) {

			/*
			 * We'd normally do this earlier, but we had to
			 * escape early because we reached the end of the data.
			 */
			if (eof && nextptr)
				conptrend = nextend;

			prntlen = conptrend - conptr + 1;
			prntptr = conptr;
			if (conmatches++ && nearmatch && !cflag)
				(void) fwrite("--\n", 1, 3, stdout);
		} else if (conflag == 0 && nvflag == (pp != NULL)) {
			*ptrend = '\n';
			prntlen = line_len + 1;
			prntptr = ptr;
			linenum = lineno;
			blkoffset = line_offset;
		} else if (eof) {
			/* No match and no more data */
			goto out;
		} else {
			/* No match, or we're not done building context */
			goto L_skip_line;
		}

		prntptrend = prntptr - 1;
		while ((prntptrend = find_nl(prntptrend + 1,
		    prntlen)) != NULL) {

			/*
			 * GNU grep uses '-' for context lines and ':' for
			 * matching lines, so replicate that here.
			 */
			if (prntptrend == matchptr) {
				if (eof && nextptr) {
					matchptr = nextend;
					nextptr = NULL;
				} else {
					matchptr = NULL;
				}
				separate = ':';
			} else {
				separate = '-';
			}

			/*
			 * Handle q, l, and c flags.
			 */
			if (qflag) {
				/* no need to continue */
				/*
				 * End of this line is ptrend.
				 * We have read up to ptr + data_len.
				 */
				off_t	pos;
				pos = ptr + data_len - (ptrend + 1);
				(void) lseek(fd, -pos, SEEK_CUR);
				exit(0);
			}
			if (lflag) {
				(void) printf("%s\n", fn);
				goto out;
			}
			if (!cflag) {
				if (Hflag || outfn) {
					(void) printf("%s%c", fn, separate);
				}
				if (bflag) {
					(void) printf("%lld%c", (offset_t)
					    (blkoffset / BSIZE), separate);
				}
				if (nflag) {
					(void) printf("%lld%c", linenum,
					    separate);
				}
				(void) fwrite(prntptr, 1,
				    prntptrend - prntptr + 1, stdout);
			}
			if (ferror(stdout)) {
				return (0);
			}
			linenum++;
			prntlen -= prntptrend - prntptr + 1;
			blkoffset += prntptrend - prntptr + 1;
			prntptr = prntptrend + 1;
		}

		if (eof)
			goto out;

		/*
		 * Update context buffer and variables post-print
		 */
		if (conflag != 0) {
			conptr = conbuf;
			conaprnt = conbprnt = 0;
			nearmatch = B_FALSE;
			conacnt = conbcnt = 0;

			if (nextptr) {
				(void) memmove(conbuf, nextptr,
				    nextend - nextptr + 1);
				blkoffset += nextptr - conptrend - 1;
				conptrend = conptr + (nextend - nextptr);
				matchptr = conptrend;
				linenum = lineno;
				lastmatch = conptrend - conptr;
				havematch = B_TRUE;
			} else {
				conptrend = conptr - 1;
				conacnt = 0;
				lastmatch = 0;
				havematch = B_FALSE;
			}
			nextptr = nextend = NULL;
		}

L_skip_line:
		if (!newlinep)
			break;

		data_len -= line_len + 1;
		line_offset += line_len + 1;
		ptr = ptrend + 1;
	}

out:
	if (cflag) {
		if (Hflag || outfn) {
			(void) printf("%s:", fn);
		}
		if (!qflag) {
			(void) printf("%lld\n", matches);
		}
	}
	return (matches != 0);
}

/*
 * usage message for grep
 */
static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: %5s"), cmdname);
	if (!egrep && !fgrep)
		(void) fprintf(stderr, gettext(" [-E|-F]"));
	(void) fprintf(stderr, gettext(" [-bchHilnqrRsvx] [-A num] [-B num] "
	    "[-C num|-num]\n             [-e pattern_list]... "
	    "[-f pattern_file]... [pattern_list] [file]...\n"));
	exit(2);
	/* NOTREACHED */
}

/*
 * Compile literal pattern into BMG tables
 */
static void
bmgcomp(char *pat, int len)
{
	int	i;
	int	tlen;
	unsigned char	*uc = (unsigned char *)pat;

	bmglen = len;
	bmgpat = pat;

	for (i = 0; i < M_CSETSIZE; i++) {
		bmgtab[i] = len;
	}

	len--;
	for (tlen = len, i = 0; i <= len; i++, tlen--) {
		bmgtab[*uc++] = tlen;
	}
}

/*
 * BMG search.
 */
static char *
bmgexec(char *str, char *end)
{
	int	t;
	char	*k, *s, *p;

	k = str + bmglen - 1;
	if (bmglen == 1) {
		return (memchr(str, bmgpat[0], end - str));
	}
	for (; ; ) {
		/* inner loop, should be most optimized */
		while (k < end && (t = bmgtab[(unsigned char)*k]) != 0) {
			k += t;
		}
		if (k >= end) {
			return (NULL);
		}
		for (s = k, p = bmgpat + bmglen - 1; *--s == *--p; ) {
			if (p == bmgpat) {
				return (s);
			}
		}
		k++;
	}
	/* NOTREACHED */
}
