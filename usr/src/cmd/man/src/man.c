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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989  AT&T.	*/
/*		All rights reserved.					*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * man
 * links to apropos, whatis, and catman
 * This version uses more for underlining and paging.
 */

#include <stdio.h>
#include <ctype.h>
#include <sgtty.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <limits.h>
#include <wchar.h>

#define	MACROF 	"tmac.an"		/* name of <locale> macro file */
#define	TMAC_AN	"-man"		/* default macro file */

/*
 * The default search path for man subtrees.
 */

#define	MANDIR		"/usr/share/man" 	/* default mandir */
#define	MAKEWHATIS	"/usr/lib/makewhatis"
#define	WHATIS		"windex"
#define	TEMPLATE	"/tmp/mpXXXXXX"
#define	CONFIG		"man.cf"

/*
 * Names for formatting and display programs.  The values given
 * below are reasonable defaults, but sites with source may
 * wish to modify them to match the local environment.  The
 * value for TCAT is particularly problematic as there's no
 * accepted standard value available for it.  (The definition
 * below assumes C.A.T. troff output and prints it).
 */

#define	MORE	"more -s" 		/* default paging filter */
#define	CAT_S	"/usr/bin/cat -s"	/* for '-' opt (no more) */
#define	CAT_	"/usr/bin/cat"		/* for when output is not a tty */
#define	TROFF	"troff"			/* local name for troff */
#define	TCAT	"lp -c -T troff"	/* command to "display" troff output */

#define	SOLIMIT		10	/* maximum allowed .so chain length */
#define	MAXDIRS		128	/* max # of subdirs per manpath */
#define	MAXPAGES	32	/* max # for multiple pages */
#define	PLEN		3	/* prefix length {man, cat, fmt} */
#define	TMPLEN		7	/* length of tmpfile prefix */
#define	MAXTOKENS 	64
#define	MAXSUFFIX	20	/* length of section suffix */

#define	DOT_SO		".so "
#define	PREPROC_SPEC	"'\\\" "

#define	DPRINTF		if (debug && !catmando) \
				(void) printf

#define	sys(s)		(debug ? ((void)puts(s), 0) : system(s))
#define	eq(a, b)	(strcmp(a, b) == 0)
#define	match(a, b, c)	(strncmp(a, b, c) == 0)

#define	ISDIR(A)	((A.st_mode & S_IFMT) == S_IFDIR)

#define	SROFF_CMD	"/usr/lib/sgml/sgml2roff" /* sgml converter */
#define	MANDIRNAME	"man"			  /* man directory */
#define	SGMLDIR		"sman"			  /* sman directory */
#define	SGML_SYMBOL	"<!DOCTYPE"	/* a sgml file should contain this */
#define	SGML_SYMBOL_LEN		9	/* length of SGML_SYMBOL */

/*
 * Directory mapping of old directories to new directories
 */

typedef struct {
	char *old_name;
	char *new_name;
} map_entry;

static const map_entry map[] = {
					{ "3b", "3ucb" },
					{ "3e", "3elf" },
					{ "3g", "3gen" },
					{ "3k", "3kstat" },
					{ "3n", "3socket" },
					{ "3r", "3rt" },
					{ "3s", "3c" },
					{ "3t", "3thr" },
					{ "3x", "3curses" },
					{ "3xc", "3xcurses" },
					{ "3xn", "3xnet" }
};

/*
 * A list of known preprocessors to precede the formatter itself
 * in the formatting pipeline.  Preprocessors are specified by
 * starting a manual page with a line of the form:
 *	'\" X
 * where X is a string consisting of letters from the p_tag fields
 * below.
 */
static const struct preprocessor {
	char	p_tag;
	char	*p_nroff,
		*p_troff;
} preprocessors [] = {
	{'c',	"cw",				"cw"},
	{'e',	"neqn /usr/share/lib/pub/eqnchar",
			"eqn /usr/share/lib/pub/eqnchar"},
	{'p',	"pic",				"pic"},
	{'r',	"refer",			"refer"},
	{'t',	"tbl",				"tbl"},
	{'v',	"vgrind -f",			"vgrind -f"},
	{0,	0,				0}
};

struct suffix {
	char *ds;
	char *fs;
};

/*
 * Subdirectories to search for unformatted/formatted man page
 * versions, in nroff and troff variations.  The searching
 * code in manual() is structured to expect there to be two
 * subdirectories apiece, the first for unformatted files
 * and the second for formatted ones.
 */
static char	*nroffdirs[] = { "man", "cat", 0 };
static char	*troffdirs[] = { "man", "fmt", 0 };

#define	MAN_USAGE "\
usage:\tman [-] [-adFlrt] [-M path] [-T macro-package ] [ -s section ] \
name ...\n\
\tman [-M path] -k keyword ...\n\tman [-M path] -f file ..."
#define	CATMAN_USAGE "\
usage:\tcatman [-p] [-c|-ntw] [-M path] [-T macro-package ] [sections]"

static char *opts[] = {
	"FfkrP:M:T:ts:lad",	/* man */
	"wpnP:M:T:tc"		/* catman */
};

struct man_node {
	char *path;		/* mandir path */
	char **secv;		/* submandir suffices */
	struct man_node *next;
};

static char	*pages[MAXPAGES];
static char	**endp = pages;

/*
 * flags (options)
 */
static int	nomore;
static int	troffit;
static int	debug;
static int	Tflag;
static int	sargs;
static int	margs;
static int	force;
static int	found;
static int	list;
static int	all;
static int	whatis;
static int	apropos;
static int	catmando;
static int	nowhatis;
static int	whatonly;
static int	compargs;	/* -c option for catman */

static char	*CAT	= CAT_;
static char	macros[MAXPATHLEN];
static char	*manpath;
static char	*mansec;
static char	*pager;
static char	*troffcmd;
static char	*troffcat;
static char	**subdirs;

static char *check_config(char *);
static struct man_node *build_manpath(char **);
static void getpath(struct man_node *, char **);
static void getsect(struct man_node *, char **);
static void get_all_sect(struct man_node *);
static void catman(struct man_node *, char **, int);
static int makecat(char *, char **, int);
static int getdirs(char *, char ***, short);
static void whatapro(struct man_node *, char *, int);
static void lookup_windex(char *, char *);
static int icmp(wchar_t *, wchar_t *);
static void more(char **, int);
static void cleanup(char **);
static void bye(int);
static char **split(char *, char);
static void fullpaths(struct man_node **);
static void lower(char *);
static int cmp(const void *, const void *);
static void manual(struct man_node *, char *);
static void mandir(char **, char *, char *);
static void sortdir(DIR *, char ***);
static int searchdir(char *, char *, char *);
static int windex(char **, char *, char *);
static void section(struct suffix *, char *);
static int bfsearch(FILE *, char **, char *);
static int compare(char *, char *);
static int format(char *, char *, char *, char *);
static char *addlocale(char *);
static int get_manconfig(FILE *, char *);
static void	malloc_error(void);
static int	sgmlcheck(const char *);
static char *map_section(char *, char *);
static void free_manp(struct man_node *manp);

/*
 * This flag is used when the SGML-to-troff converter
 * is absent - all the SGML searches are bypassed.
 */
static int no_sroff = 0;

/*
 * This flag is used to describe the case where we've found
 * an SGML formatted manpage in the sman directory, we haven't
 * found a troff formatted manpage, and we don't have the SGML to troff
 * conversion utility on the system.
 */
static int sman_no_man_no_sroff;

static char language[PATH_MAX + 1]; 	/* LC_MESSAGES */
static char localedir[PATH_MAX + 1];	/* locale specific path component */

static int	defaultmandir = 1;	/* if processing default mandir, 1 */

static char *newsection = NULL;

int
main(int argc, char *argv[])
{
	int badopts = 0;
	int c;
	char **pathv, **p;
	char *cmdname;
	static struct man_node	*manpage = NULL;

	if (access(SROFF_CMD, F_OK | X_OK) != 0)
		no_sroff = 1;

	(void) setlocale(LC_ALL, "");
	(void) strcpy(language, setlocale(LC_MESSAGES, (char *)0));
	if (strcmp("C", language) != 0)
		(void) sprintf(localedir, "%s", language);

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) strcpy(macros, TMAC_AN);

	/*
	 * get user defined stuff
	 */
	if ((manpath = getenv("MANPATH")) == NULL)
		manpath = MANDIR;
	/*
	 * get base part of command name
	 */
	if ((cmdname = strrchr(argv[0], '/')) != NULL)
		cmdname++;
	else
		cmdname = argv[0];

	if (eq(cmdname, "apropos") || eq(cmdname, "whatis")) {
		whatis++;
		apropos = (*cmdname == 'a');
		if ((optind = 1) == argc) {
			(void) fprintf(stderr, gettext("%s what?\n"), cmdname);
			exit(2);
		}
		goto doargs;
	} else if (eq(cmdname, "catman"))
		catmando++;

	opterr = 0;
	while ((c = getopt(argc, argv, opts[catmando])) != -1)
		switch (c) {

		/*
		 * man specific options
		 */
		case 'k':
			apropos++;
			/*FALLTHROUGH*/
		case 'f':
			whatis++;
			break;
		case 'F':
			force++;	/* do lookups the hard way */
			break;
		case 's':
			mansec = optarg;
			sargs++;
			break;
		case 'r':
			nomore++, troffit++;
			break;
		case 'l':
			list++;		/* implies all */
			/*FALLTHROUGH*/
		case 'a':
			all++;
			break;
		case 'd':

		/*
		 * catman specific options
		 */
		case 'p':
			debug++;
			break;
		case 'n':
			nowhatis++;
			break;
		case 'w':
			whatonly++;
			break;
		case 'c':	/* n|troff compatibility */
			if (no_sroff)
				(void) fprintf(stderr, gettext(
					"catman: SGML conversion not "
				    "available -- -c flag ignored\n"));
			else
				compargs++;
			continue;

		/*
		 * shared options
		 */
		case 'P':	/* Backwards compatibility */
		case 'M':	/* Respecify path for man pages. */
			manpath = optarg;
			margs++;
			break;
		case 'T':	/* Respecify man macros */
			(void) strcpy(macros, optarg);
			Tflag++;
			break;
		case 't':
			troffit++;
			break;
		case '?':
			badopts++;
		}

	/*
	 *  Bad options or no args?
	 *	(catman doesn't need args)
	 */
	if (badopts || (!catmando && optind == argc)) {
		(void) fprintf(stderr, "%s\n", catmando ?
		    gettext(CATMAN_USAGE) : gettext(MAN_USAGE));
		exit(2);
	}

	if (compargs && (nowhatis || whatonly || troffit)) {
		(void) fprintf(stderr, "%s\n", gettext(CATMAN_USAGE));
		(void) fprintf(stderr, gettext(
			"-c option cannot be used with [-w][-n][-t]\n"));
		exit(2);
	}

	if (sargs && margs && catmando) {
		(void) fprintf(stderr, "%s\n", gettext(CATMAN_USAGE));
		exit(2);
	}

	if (troffit == 0 && nomore == 0 && !isatty(fileno(stdout)))
		nomore++;

	/*
	 * Collect environment information.
	 */
	if (troffit) {
		if ((troffcmd = getenv("TROFF")) == NULL)
			troffcmd = TROFF;
		if ((troffcat = getenv("TCAT")) == NULL)
			troffcat = TCAT;
	} else {
		if (((pager = getenv("PAGER")) == NULL) ||
		    (*pager == NULL))
			pager = MORE;
	}

doargs:
	subdirs = troffit ? troffdirs : nroffdirs;

	pathv = split(manpath, ':');

	manpage = build_manpath(pathv);

	/* release pathv allocated by split() */
	p = pathv;
	while (*p) {
		free(*p);
		p++;
	}
	free(pathv);

	fullpaths(&manpage);

	if (catmando) {
		catman(manpage, argv+optind, argc-optind);
		exit(0);
	}

	/*
	 * The manual routine contains windows during which
	 * termination would leave a temp file behind.  Thus
	 * we blanket the whole thing with a clean-up routine.
	 */
	if (signal(SIGINT, SIG_IGN) == SIG_DFL) {
		(void) signal(SIGINT, bye);
		(void) signal(SIGQUIT, bye);
		(void) signal(SIGTERM, bye);
	}

	for (; optind < argc; optind++) {
		if (strcmp(argv[optind], "-") == 0) {
			nomore++;
			CAT = CAT_S;
		} else if (whatis)
			whatapro(manpage, argv[optind], apropos);
		else
			manual(manpage, argv[optind]);
	}
	return (0);
	/*NOTREACHED*/
}

/*
 * This routine builds the manpage structure from MANPATH.
 */

static struct man_node *
build_manpath(char **pathv)
{
	struct man_node *manpage = NULL;
	struct man_node *currp = NULL;
	struct man_node *lastp = NULL;
	char **p;
	char **q;
	char **r;
	int s;

	s = sizeof (struct man_node);
	for (p = pathv; *p; p++) {

		q = split(*p, ',');

		if (access(q[0], R_OK|X_OK) != 0) {
			if (catmando) {
				(void) fprintf(stderr,
					gettext("%s is not accessible.\n"),
					q[0]);
				(void) fflush(stderr);
			}
		} else {

			if (manpage == NULL)
				currp = lastp = manpage =
					(struct man_node *)malloc(s);
			else
				currp =  (struct man_node *)malloc(s);

			if (currp == NULL)
				malloc_error();

			getpath(currp, p);
			getsect(currp, p);

			currp->next = NULL;
			if (currp != manpage)
				lastp->next = currp;
			lastp = currp;
		}
		for (r = q; *r != NULL; r++)
			free(*r);
		free(q);
}

	return (manpage);
}

/*
 * Stores the mandir path into the manp structure.
 */

static void
getpath(struct man_node *manp, char **pv)
{
	char *s;
	int i = 0;

	s = *pv;

	while (*s != NULL && *s != ',')
		i++, s++;

	manp->path = (char *)malloc(i+1);
	if (manp->path == NULL)
		malloc_error();
	(void) strncpy(manp->path, *pv, i);
	*(manp->path + i) = '\0';
}

/*
 * Stores the mandir's corresponding sections (submandir
 * directories) into the manp structure.
 */

static void
getsect(struct man_node *manp, char **pv)
{
	char *sections;
	char **sectp;

	if (sargs) {
		manp->secv = split(mansec, ',');

		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);
	} else if ((sections = strchr(*pv, ',')) != NULL) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. /usr/share/man: from -M option, MANSECTS=,1,2,3c
 */
		if (debug)
			(void) fprintf(stdout, gettext(
				"%s: from -M option, MANSECTS=%s\n"),
			    manp->path, sections);
		manp->secv = split(++sections, ',');
		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);

		if (*manp->secv == NULL)
			get_all_sect(manp);
	} else if ((sections = check_config(*pv)) != NULL) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. /usr/share/man: from man.cf, MANSECTS=1,1m,1c,1f
 */
		if (debug)
			(void) fprintf(stdout, gettext(
				"%s: from %s, MANSECTS=%s\n"),
			    manp->path, CONFIG, sections);
		manp->secv = split(sections, ',');

		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);

		if (*manp->secv == NULL)
			get_all_sect(manp);
	} else {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * if man.cf has not been found or sections has not been specified
 * man/catman searches the sections lexicographically.
 */
		if (debug)
			(void) fprintf(stdout, gettext(
			    "%s: search the sections lexicographically\n"),
			    manp->path);
		manp->secv = NULL;
		get_all_sect(manp);
	}
}

/*
 * Get suffices of all sub-mandir directories in a mandir.
 */

static void
get_all_sect(struct man_node *manp)
{
	DIR *dp;
	char **dirv;
	char **dv;
	char **p;
	char prev[MAXSUFFIX];
	char tmp[MAXSUFFIX];
	int  plen;
	int	maxentries = MAXTOKENS;
	int	entries = 0;

	if ((dp = opendir(manp->path)) == 0)
		return;

	/*
	 * sortdir() allocates memory for dirv and dirv[].
	 */
	sortdir(dp, &dirv);

	(void) closedir(dp);

	if (manp->secv == NULL) {
		/*
		 * allocates memory for manp->secv only if it's NULL
		 */
		manp->secv = (char **)malloc(maxentries * sizeof (char *));
		if (manp->secv == NULL)
			malloc_error();
	}

	(void) memset(tmp, 0, MAXSUFFIX);
	(void) memset(prev, 0, MAXSUFFIX);
	for (dv = dirv, p = manp->secv; *dv; dv++) {
		plen = PLEN;
		if (match(*dv, SGMLDIR, PLEN+1))
			++plen;

		if (strcmp(*dv, CONFIG) == 0) {
			/* release memory allocated by sortdir */
			free(*dv);
			continue;
		}

		(void) sprintf(tmp, "%s", *dv + plen);

		if (strcmp(prev, tmp) == 0) {
			/* release memory allocated by sortdir */
			free(*dv);
			continue;
		}

		(void) sprintf(prev, "%s", *dv + plen);
		/*
		 * copy the string in (*dv + plen) to *p
		 */
		*p = strdup(*dv + plen);
		if (*p == NULL)
			malloc_error();
		p++;
		entries++;
		if (entries == maxentries) {
			maxentries += MAXTOKENS;
			manp->secv = (char **)realloc(manp->secv,
				sizeof (char *) * maxentries);
			if (manp->secv == NULL)
				malloc_error();
			p = manp->secv + entries;
		}
		/* release memory allocated by sortdir */
		free(*dv);
	}
	*p = 0;
	/* release memory allocated by sortdir */
	free(dirv);
}

/*
 * Format man pages (build cat pages); if no
 * sections are specified, build all of them.
 * When building cat pages:
 *	catman() tries to build cat pages for locale specific
 *	man dirs first.  Then, catman() tries to build cat pages
 *	for the default man dir (for C locale like /usr/share/man)
 *	regardless of the locale.
 * When building windex file:
 *	catman() tries to build windex file for locale specific
 *	man dirs first.  Then, catman() tries to build windex file
 *	for the default man dir (for C locale like /usr/share/man)
 *	regardless of the locale.
 */

static void
catman(struct man_node *manp, char **argv, int argc)
{
	char cmdbuf[BUFSIZ];
	char **dv;
	int changed;
	struct man_node *p;
	int ndirs = 0;
	char *ldir;
	int	i;

	for (p = manp; p != NULL; p = p->next) {
/*
 * TRANSLATION_NOTE - message for catman -p
 * ex. mandir path = /usr/share/man
 */
		if (debug)
			(void) fprintf(stdout, gettext(
				"\nmandir path = %s\n"), p->path);
		ndirs = 0;
		/*
		 * Build cat pages
		 * addlocale() allocates memory and returns it
		 */
		ldir = addlocale(p->path);
		if (!whatonly) {
			if (*localedir != '\0') {
				if (defaultmandir)
					defaultmandir = 0;
				/* getdirs allocate memory for dv */
				ndirs = getdirs(ldir, &dv, 1);
				if (ndirs != 0) {
					changed = argc ?
						makecat(ldir, argv, argc) :
						makecat(ldir, dv, ndirs);
					/* release memory by getdirs */
					for (i = 0; i < ndirs; i++) {
						free(dv[i]);
					}
					free(dv);
				}
			}

			/* default man dir is always processed */
			defaultmandir = 1;
			ndirs = getdirs(p->path, &dv, 1);
			changed = argc ?
				makecat(p->path, argv, argc) :
				makecat(p->path, dv, ndirs);
			/* release memory allocated by getdirs */
			for (i = 0; i < ndirs; i++) {
				free(dv[i]);
			}
			free(dv);
		}
		/*
		 * Build whatis database
		 *  print error message if locale is set and man dir not found
		 *  won't build it at all if -c option is on
		 */
		if (!compargs && (whatonly || (!nowhatis && changed))) {
			if (*localedir != '\0') {
				/* just count the number of ndirs */
				if ((ndirs = getdirs(ldir, NULL, 0)) != 0) {
					(void) sprintf(cmdbuf,
						"/usr/bin/sh %s %s",
						MAKEWHATIS, ldir);
					(void) sys(cmdbuf);
				}
			}
			/* whatis database of the default man dir */
			/* will be always built in C locale. */
			(void) sprintf(cmdbuf,
				"/usr/bin/sh %s %s",
				MAKEWHATIS, p->path);
			(void) sys(cmdbuf);
		}
		/* release memory allocated by addlocale() */
		free(ldir);
	}
}

/*
 * Build cat pages for given sections
 */

static int
makecat(char *path, char **dv, int ndirs)
{
	DIR *dp, *sdp;
	struct dirent *d;
	struct stat sbuf;
	char mandir[MAXPATHLEN+1];
	char smandir[MAXPATHLEN+1];
	char catdir[MAXPATHLEN+1];
	char *dirp, *sdirp;
	int i, fmt;
	int manflag, smanflag;

	for (i = fmt = 0; i < ndirs; i++) {
		(void) snprintf(mandir, MAXPATHLEN, "%s/%s%s",
				path, MANDIRNAME, dv[i]);
		(void) snprintf(smandir, MAXPATHLEN, "%s/%s%s",
				path, SGMLDIR, dv[i]);
		(void) snprintf(catdir, MAXPATHLEN, "%s/%s%s",
				path, subdirs[1], dv[i]);
		dirp = strrchr(mandir, '/') + 1;
		sdirp = strrchr(smandir, '/') + 1;

		manflag = smanflag = 0;

		if ((dp = opendir(mandir)) != NULL)
			manflag = 1;

		if (!no_sroff && (sdp = opendir(smandir)) != NULL)
			smanflag = 1;

		if (dp == 0 && sdp == 0) {
			if (strcmp(mandir, CONFIG) == 0)
				perror(mandir);
			continue;
		}
/*
 * TRANSLATION_NOTE - message for catman -p
 * ex. Building cat pages for mandir = /usr/share/man/ja
 */
		if (debug)
			(void) fprintf(stdout, gettext(
			    "Building cat pages for mandir = %s\n"), path);

		if (!compargs && stat(catdir, &sbuf) < 0) {
			(void) umask(02);
/*
 * TRANSLATION_NOTE - message for catman -p
 * ex. mkdir /usr/share/man/ja/cat3c
 */
			if (debug)
				(void) fprintf(stdout, gettext("mkdir %s\n"),
					catdir);
			else {
				if (mkdir(catdir, 0755) < 0) {
					perror(catdir);
					continue;
				}
				(void) chmod(catdir, 0755);
			}
		}

		/*
		 * if it is -c option of catman, if there is no
		 * coresponding man dir for sman files to go to,
		 * make the man dir
		 */

		if (compargs && !manflag) {
			if (mkdir(mandir, 0755) < 0) {
				perror(mandir);
				continue;
			}
			(void) chmod(mandir, 0755);
		}

		if (smanflag) {
			while ((d = readdir(sdp))) {
				if (eq(".", d->d_name) || eq("..", d->d_name))
					continue;

				if (format(path, sdirp, (char *)0, d->d_name)
					> 0)
					fmt++;
			}
		}

		if (manflag && !compargs) {
			while ((d = readdir(dp))) {
				if (eq(".", d->d_name) || eq("..", d->d_name))
					continue;

				if (format(path, dirp, (char *)0, d->d_name)
					> 0)
					fmt++;
			}
		}

		if (manflag)
			(void) closedir(dp);

		if (smanflag)
			(void) closedir(sdp);

	}
	return (fmt);
}


/*
 * Get all "man" and "sman" dirs under a given manpath
 * and return the number found
 * If -c option is on, only count sman dirs
 */

static int
getdirs(char *path, char ***dirv, short flag)
{
	DIR *dp;
	struct dirent *d;
	int n = 0;
	int plen, sgml_flag, man_flag;
	int i = 0;
	int	maxentries = MAXDIRS;
	char	**dv;

	if ((dp = opendir(path)) == 0) {
		if (debug) {
			if (*localedir != '\0')
				(void) printf(gettext("\
locale is %s, search in %s\n"), localedir, path);
			perror(path);
		}
		return (0);
	}

	if (flag) {
		/* allocate memory for dirv */
		*dirv = (char **)malloc(sizeof (char *) *
			maxentries);
		if (*dirv == NULL)
			malloc_error();
		dv = *dirv;
	}
	while ((d = readdir(dp))) {
		plen = PLEN;
		man_flag = sgml_flag = 0;
		if (match(d->d_name, SGMLDIR, PLEN+1)) {
			plen = PLEN + 1;
			sgml_flag = 1;
			i++;
		}

		if (match(subdirs[0], d->d_name, PLEN))
			man_flag = 1;

		if (compargs && sgml_flag) {
			if (flag) {
				*dv = strdup(d->d_name+plen);
				if (*dv == NULL)
					malloc_error();
				dv++;
				n = i;
			}
		} else if (!compargs && (sgml_flag || man_flag)) {
			if (flag) {
				*dv = strdup(d->d_name+plen);
				if (*dv == NULL)
					malloc_error();
				dv++;
			}
			n++;
		}
		if (flag) {
			if ((dv - *dirv) == maxentries) {
				int entries = maxentries;
				maxentries += MAXTOKENS;
				*dirv = (char **)realloc(*dirv,
					sizeof (char *) * maxentries);
				if (*dirv == NULL)
					malloc_error();
				dv = *dirv + entries;
			}
		}
	}

	(void) closedir(dp);
	return (n);
}


/*
 * Find matching whatis or apropos entries
 * whatapro() tries to handle the windex file of the locale specific
 * man dirs first, then tries to handle the windex file of the default
 * man dir (of C locale like /usr/share/man).
 */

static void
whatapro(struct man_node *manp, char *word, int apropos)
{
	char whatpath[MAXPATHLEN+1];
	char *p;
	struct man_node *b;
	int ndirs = 0;
	char *ldir;


/*
 * TRANSLATION_NOTE - message for man -d
 * %s takes a parameter to -k option.
 */
	DPRINTF(gettext("word = %s \n"), word);

	/*
	 * get base part of name
	 */
	if (!apropos) {
		if ((p = strrchr(word, '/')) == NULL)
			p = word;
		else
			p++;
	} else {
		p = word;
	}

	for (b = manp; b != NULL; b = b->next) {

		if (*localedir != '\0') {
			/* addlocale() allocates memory and returns it */
			ldir = addlocale(b->path);
			if (defaultmandir)
				defaultmandir = 0;
			ndirs = getdirs(ldir, NULL, 0);
			if (ndirs != 0) {
				(void) sprintf(whatpath, "%s/%s", ldir, WHATIS);
/*
 * TRANSLATION_NOTE - message for man -d
 * ex. mandir path = /usr/share/man/ja
 */
				DPRINTF(gettext("\nmandir path = %s\n"), ldir);
				lookup_windex(whatpath, p);
			}
			/* release memory allocated by addlocale() */
			free(ldir);
		}

		defaultmandir = 1;
		(void) sprintf(whatpath, "%s/%s", b->path, WHATIS);
/*
 * TRANSLATION_NOTE - message for man -d
 * ex. mandir path = /usr/share/man
 */
		DPRINTF(gettext("\nmandir path = %s\n"), b->path);

		lookup_windex(whatpath, p);
	}
}


static void
lookup_windex(char *whatpath, char *word)
{
	FILE *fp;
	char *matches[MAXPAGES];
	char **pp;
	wchar_t	wbuf[BUFSIZ];
	wchar_t *word_wchar = NULL;
	wchar_t	*ws;
	size_t	word_len, ret;

	if ((fp = fopen(whatpath, "r")) == NULL) {
		perror(whatpath);
		return;
	}

	if (apropos) {
		word_len = strlen(word) + 1;
		if ((word_wchar = (wchar_t *)malloc(sizeof (wchar_t) *
			word_len)) == NULL) {
			malloc_error();
		}
		ret = mbstowcs(word_wchar, (const char *)word, word_len);
		if (ret == (size_t)-1) {
			(void) fprintf(stderr, gettext(
				"Invalid character in keyword\n"));
			exit(1);
		}
		while (fgetws(wbuf, BUFSIZ, fp) != NULL)
			for (ws = wbuf; *ws; ws++)
				if (icmp(word_wchar, ws) == 0) {
					(void) printf("%ws", wbuf);
					break;
				}
	} else {
		if (bfsearch(fp, matches, word))
			for (pp = matches; *pp; pp++) {
				(void) printf("%s", *pp);
				/*
				 * release memory allocated by
				 * strdup() in bfsearch()
				 */
				free(*pp);
			}
	}
	(void) fclose(fp);
	if (word_wchar)
		free(word_wchar);

}


/*
 * case-insensitive compare unless upper case is used
 * ie)	"mount" matches mount, Mount, MOUNT
 *	"Mount" matches Mount, MOUNT
 *	"MOUNT" matches MOUNT only
 *	If matched return 0.  Otherwise, return 1.
 */

static int
icmp(wchar_t *ws, wchar_t *wt)
{
	for (; (*ws == 0) ||
		(*ws == (iswupper(*ws) ? *wt: towlower(*wt)));
		ws++, wt++)
		if (*ws == 0)
			return (0);

	return (1);
}


/*
 * Invoke PAGER with all matching man pages
 */

static void
more(char **pages, int plain)
{
	char cmdbuf[BUFSIZ];
	char **vp;

	/*
	 * Dont bother.
	 */
	if (list || (*pages == 0))
		return;

	if (plain && troffit) {
		cleanup(pages);
		return;
	}
	(void) sprintf(cmdbuf, "%s", troffit ? troffcat :
	    plain ? CAT : pager);

	/*
	 * Build arg list
	 */
	for (vp = pages; vp < endp; vp++) {
		(void) strcat(cmdbuf, " ");
		(void) strcat(cmdbuf, *vp);
	}
	(void) sys(cmdbuf);
	cleanup(pages);
}


/*
 * Get rid of dregs.
 */

static void
cleanup(char **pages)
{
	char **vp;

	for (vp = pages; vp < endp; vp++) {
		if (match(TEMPLATE, *vp, TMPLEN))
			(void) unlink(*vp);
		free(*vp);
	}

	endp = pages;	/* reset */
}


/*
 * Clean things up after receiving a signal.
 */

/*ARGSUSED*/
static void
bye(int sig)
{
	cleanup(pages);
	exit(1);
	/*NOTREACHED*/
}


/*
 * Split a string by specified separator.
 *    ignore empty components/adjacent separators.
 *    returns vector to all tokens
 */

static char **
split(char *s1, char sep)
{
	char **tokv, **vp;
	char *mp, *tp;
	int maxentries = MAXTOKENS;
	int entries = 0;

	tokv = vp = (char **)malloc(maxentries * sizeof (char *));
	if (tokv == NULL)
		malloc_error();
	mp = s1;
	for (; mp && *mp; mp = tp) {
		tp = strchr(mp, sep);
		if (mp == tp) {		/* empty component */
			tp++;			/* ignore */
			continue;
		}
		if (tp) {
			/* a component found */
			size_t	len;

			len = tp - mp;
			*vp = (char *)malloc(sizeof (char) * len + 1);
			if (*vp == NULL)
				malloc_error();
			(void) strncpy(*vp, mp, len);
			*(*vp + len) = '\0';
			tp++;
			vp++;
		} else {
			/* the last component */
			*vp = strdup(mp);
			if (*vp == NULL)
				malloc_error();
			vp++;
		}
		entries++;
		if (entries == maxentries) {
			maxentries += MAXTOKENS;
			tokv = (char **)realloc(tokv,
				maxentries * sizeof (char *));
			if (tokv == NULL)
				malloc_error();
			vp = tokv + entries;
		}
	}
	*vp = 0;
	return (tokv);
}


/*
 * Convert paths to full paths if necessary
 *
 */

static void
fullpaths(struct man_node **manp_head)
{
	char *cwd = NULL;
	char *p;
	char cwd_gotten = 0;
	struct man_node *manp = *manp_head;
	struct man_node *b;
	struct man_node *prev = NULL;

	for (b = manp; b != NULL; b = b->next) {
		if (*(b->path) == '/') {
			prev = b;
			continue;
		}

		/* try to get cwd if haven't already */
		if (!cwd_gotten) {
			cwd = getcwd(NULL, MAXPATHLEN+1);
			cwd_gotten = 1;
		}

		if (cwd) {
			/* case: relative manpath with cwd: make absolute */
			if ((p = malloc(strlen(b->path)+strlen(cwd)+2)) ==
			    NULL) {
				malloc_error();
			}
			(void) sprintf(p, "%s/%s", cwd, b->path);
			/*
			 * resetting b->path
			 */
			free(b->path);
			b->path = p;
		} else {
			/* case: relative manpath but no cwd: omit path entry */
			if (prev)
				prev->next = b->next;
			else
				*manp_head = b->next;

			free_manp(b);
		}
	}
	/*
	 * release memory allocated by getcwd()
	 */
	free(cwd);
}

/*
 * Free a man_node structure and its contents
 */

static void
free_manp(struct man_node *manp)
{
	char **p;

	free(manp->path);
	p = manp->secv;
	while ((p != NULL) && (*p != NULL)) {
		free(*p);
		p++;
	}
	free(manp->secv);
	free(manp);
}


/*
 * Map (in place) to lower case
 */

static void
lower(char *s)
{
	if (s == 0)
		return;
	while (*s) {
		if (isupper(*s))
			*s = tolower(*s);
		s++;
	}
}


/*
 * compare for sort()
 * sort first by section-spec, then by prefix {sman, man, cat, fmt}
 *	note: prefix is reverse sorted so that "sman" and "man" always
 * 	comes before {cat, fmt}
 */

static int
cmp(const void *arg1, const void *arg2)
{
	int n;
	char **p1 = (char **)arg1;
	char **p2 = (char **)arg2;


	/* by section; sman always before man dirs */
	if ((n = strcmp(*p1 + PLEN + (**p1 == 's' ? 1 : 0),
		*p2 + PLEN + (**p2 == 's' ? 1 : 0))))
		return (n);

	/* by prefix reversed */
	return (strncmp(*p2, *p1, PLEN));
}


/*
 * Find a man page ...
 *   Loop through each path specified,
 *   first try the lookup method (whatis database),
 *   and if it doesn't exist, do the hard way.
 */

static void
manual(struct man_node *manp, char *name)
{
	struct man_node *p;
	struct man_node *local = NULL;
	int ndirs = 0;
	char *ldir;
	char *ldirs[2];

	/*
	 *  for each path in MANPATH
	 */
	found = 0;

	for (p = manp; p != NULL; p = p->next) {
/*
 * TRANSLATION_NOTE - message for man -d
 * ex. mandir path = /usr/share/man
 */
		DPRINTF(gettext("\nmandir path = %s\n"), p->path);

		if (*localedir != '\0') {
			/* addlocale() allocates memory and returns it */
			ldir = addlocale(p->path);
			if (defaultmandir)
				defaultmandir = 0;
/*
 * TRANSLATION_NOTE - message for man -d
 * ex. localedir = ja, ldir = /usr/share/man/ja
 */
			if (debug)
			    (void) printf(gettext(
					"localedir = %s, ldir = %s\n"),
					localedir, ldir);
			ndirs = getdirs(ldir, NULL, 0);
			if (ndirs != 0) {
				ldirs[0] = ldir;
				ldirs[1] = NULL;
				local = build_manpath(ldirs);
				if (force ||
				    windex(local->secv, ldir, name) < 0)
					mandir(local->secv, ldir, name);
			}
			/* release memory allocated by addlocale() */
			free(ldir);
		}

		defaultmandir = 1;
		/*
		 * locale mandir not valid, man page in locale
		 * mandir not found, or -a option present
		 */
		if (ndirs == 0 || !found || all) {
			if (force || windex(p->secv, p->path, name) < 0)
				mandir(p->secv, p->path, name);
		}

		if (found && !all)
			break;
	}

	if (found) {
		more(pages, nomore);
	} else {
		if (sargs) {
			(void) printf(gettext("No entry for %s in section(s) "
			    "%s of the manual.\n"), name, mansec);
		} else {
			(void) printf(gettext(
			    "No manual entry for %s.\n"), name, mansec);
		}

		if (sman_no_man_no_sroff)
			(void) printf(gettext("(An SGML manpage was found "
			    "for '%s' but it cannot be displayed.)\n"),
			    name, mansec);
	}
	sman_no_man_no_sroff = 0;
}


/*
 * For a specified manual directory,
 *	read, store, & sort section subdirs,
 *	for each section specified
 *		find and search matching subdirs
 */

static void
mandir(char **secv, char *path, char *name)
{
	DIR *dp;
	char **dirv;
	char **dv, **pdv;
	int len, dslen, plen = PLEN;

	if ((dp = opendir(path)) == 0) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * opendir(%s) returned 0
 */
		if (debug)
			(void) fprintf(stdout, gettext(
				" opendir on %s failed\n"), path);
		return;
	}

/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. mandir path = /usr/share/man/ja
 */
	if (debug)
		(void) printf(gettext("mandir path = %s\n"), path);

	/*
	 * sordir() allocates memory for dirv and dirv[].
	 */
	sortdir(dp, &dirv);
	/*
	 * Search in the order specified by MANSECTS
	 */
	for (; *secv; secv++) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  section = 3c
 */
		DPRINTF(gettext("  section = %s\n"), *secv);
		len = strlen(*secv);
		for (dv = dirv; *dv; dv++) {
			plen = PLEN;
			if (*dv[0] == 's')
				plen++;
			dslen = strlen(*dv+plen);
			if (dslen > len)
				len = dslen;
			if (**secv == '\\') {
				if (!eq(*secv + 1, *dv+plen))
					continue;
			} else if (!match(*secv, *dv+plen, len)) {
				/* check to see if directory name changed */
				if (!all &&
				    (newsection = map_section(*secv, path))
				    == NULL) {
					continue;
				}
				if (newsection == NULL)
					newsection = "";
				if (!match(newsection, *dv+plen, len)) {
					continue;
				}
			}

			if (searchdir(path, *dv, name) == 0)
				continue;

			if (!all) {
				/* release memory allocated by sortdir() */
				pdv = dirv;
				while (*pdv) {
					free(*pdv);
					pdv++;
				}
				(void) closedir(dp);
				/* release memory allocated by sortdir() */
				free(dirv);
				return;
			}
			/*
			 * if we found a match in the man dir skip
			 * the corresponding cat dir if it exists
			 */
			if (all && **dv == 'm' && *(dv+1) &&
				eq(*(dv+1)+plen, *dv+plen))
					dv++;
		}
	}
	/* release memory allocated by sortdir() */
	pdv = dirv;
	while (*pdv) {
		free(*pdv);
		pdv++;
	}
	free(dirv);
	(void) closedir(dp);
}

/*
 * Sort directories.
 */

static void
sortdir(DIR *dp, char ***dirv)
{
	struct dirent *d;
	char **dv;
	int	maxentries = MAXDIRS;
	int	entries = 0;

	*dirv = (char **)malloc(sizeof (char *) * maxentries);
	dv = *dirv;
	while ((d = readdir(dp))) {	/* store dirs */
		if (eq(d->d_name, ".") || eq(d->d_name, ".."))	/* ignore */
			continue;

		/* check if it matches sman, man, cat format */
		if (match(d->d_name, SGMLDIR, PLEN+1) ||
		    match(d->d_name, subdirs[0], PLEN) ||
		    match(d->d_name, subdirs[1], PLEN)) {
			*dv = malloc(strlen(d->d_name) + 1);
			if (*dv == NULL)
				malloc_error();
			(void) strcpy(*dv, d->d_name);
			dv++;
			entries++;
			if (entries == maxentries) {
				maxentries += MAXDIRS;
				*dirv = (char **)realloc(*dirv,
					sizeof (char *) * maxentries);
				if (*dirv == NULL)
					malloc_error();
				dv = *dirv + entries;
			}
		}
	}
	*dv = 0;

	qsort((void *)*dirv, dv - *dirv, sizeof (char *), cmp);

}


/*
 * Search a section subdirectory for a
 * given man page, return 1 for success
 */

static int
searchdir(char *path, char *dir, char *name)
{
	DIR *sdp;
	struct dirent *sd;
	char sectpath[MAXPATHLEN+1];
	char file[MAXNAMLEN+1];
	char dname[MAXPATHLEN+1];
	char *last;
	int nlen;

/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.   scanning = man3c
 */
	DPRINTF(gettext("    scanning = %s\n"), dir);
	(void) sprintf(sectpath, "%s/%s", path, dir);
	(void) snprintf(file, MAXPATHLEN, "%s.", name);

	if ((sdp = opendir(sectpath)) == 0) {
		if (errno != ENOTDIR)	/* ignore matching cruft */
			perror(sectpath);
		return (0);
	}
	while ((sd = readdir(sdp))) {
		last = strrchr(sd->d_name, '.');
		nlen = last - sd->d_name;
		(void) sprintf(dname, "%.*s.", nlen, sd->d_name);
		if (eq(dname, file) || eq(sd->d_name, name)) {
			if (no_sroff && *dir == 's') {
				sman_no_man_no_sroff = 1;
				return (0);
			}
			(void) format(path, dir, name, sd->d_name);
			(void) closedir(sdp);
			return (1);
		}
	}
	(void) closedir(sdp);
	return (0);
}

/*
 * Check the hash table of old directory names to see if there is a
 * new directory name.
 * Returns new directory name if a match; after checking to be sure
 * directory exists.
 * Otherwise returns NULL
 */

static char *
map_section(char *section, char *path)
{
	int i;
	int len;
	char fullpath[MAXPATHLEN];

	if (list)  /* -l option fall through */
		return (NULL);

	for (i = 0; i <= ((sizeof (map)/sizeof (map[0]) - 1)); i++) {
		if (strlen(section) > strlen(map[i].new_name)) {
			len = strlen(section);
		} else {
			len = strlen(map[i].new_name);
		}
		if (match(section, map[i].old_name, len)) {
			(void) sprintf(fullpath,
			    "%s/sman%s", path, map[i].new_name);
			if (!access(fullpath, R_OK | X_OK)) {
				return (map[i].new_name);
			} else {
				return (NULL);
			}
		}
	}

	return (NULL);
}


/*
 * Use windex database for quick lookup of man pages
 * instead of mandir() (brute force search)
 */

static int
windex(char **secv, char *path, char *name)
{
	FILE *fp;
	struct stat sbuf;
	struct suffix *sp;
	struct suffix	psecs[MAXPAGES];
	char whatfile[MAXPATHLEN+1];
	char page[MAXPATHLEN+1];
	char *matches[MAXPAGES];
	char *file, *dir;
	char **sv, **vp;
	int len, dslen, exist, i;
	int	found_in_windex = 0;
	char *tmp[] = {0, 0, 0, 0};


	(void) sprintf(whatfile, "%s/%s", path, WHATIS);
	if ((fp = fopen(whatfile, "r")) == NULL) {
		if (errno == ENOENT)
			return (-1);
		return (0);
	}

/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. search in = /usr/share/man/ja/windex file
 */
	if (debug)
		(void) fprintf(stdout, gettext(
			" search in = %s file\n"), whatfile);

	if (bfsearch(fp, matches, name) == 0) {
		(void) fclose(fp);
		return (-1); /* force search in mandir */
	}

	(void) fclose(fp);

	/*
	 * Save and split sections
	 * section() allocates memory for sp->ds
	 */
	for (sp = psecs, vp = matches; *vp; vp++, sp++)
		section(sp, *vp);

	sp->ds = 0;

	/*
	 * Search in the order specified
	 * by MANSECTS
	 */
	for (; *secv; secv++) {
		len = strlen(*secv);

/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  search an entry to match printf.3c
 */
		if (debug)
			(void) fprintf(stdout, gettext(
			    "  search an entry to match %s.%s\n"), name, *secv);
		/*
		 * For every whatis entry that
		 * was matched
		 */
		for (sp = psecs; sp->ds; sp++) {
			dslen = strlen(sp->ds);
			if (dslen > len)
				len = dslen;
			if (**secv == '\\') {
				if (!eq(*secv + 1, sp->ds))
					continue;
			} else if (!match(*secv, sp->ds, len)) {
				/* check to see if directory name changed */
				if (!all &&
				    (newsection = map_section(*secv, path))
				    == NULL) {
					continue;
				}
				if (newsection == NULL)
					newsection = "";
				if (!match(newsection, sp->ds, len)) {
					continue;
				}
			}
			/*
			 * here to form "sman", "man", "cat"|"fmt" in
			 * order
			 */
			if (!no_sroff) {
				tmp[0] = SGMLDIR;
				for (i = 1; i < 4; i++)
					tmp[i] = subdirs[i-1];
			} else {
				for (i = 0; i < 3; i++)
					tmp[i] = subdirs[i];
			}

			for (sv = tmp; *sv; sv++) {
				(void) sprintf(page,
				    "%s/%s%s/%s%s%s", path, *sv,
				    sp->ds, name, *sp->fs ? "." : "",
				    sp->fs);
				exist = (stat(page, &sbuf) == 0);
				if (exist)
					break;
			}
			if (!exist) {
				(void) fprintf(stderr, gettext(
				    "%s entry incorrect:  %s(%s) not found.\n"),
				    WHATIS, name, sp->ds);
				continue;
			}

			file = strrchr(page, '/'), *file = 0;
			dir = strrchr(page, '/');

			/*
			 * By now we have a match
			 */
			found_in_windex = 1;
			(void) format(path, ++dir, name, ++file);

			if (!all)
				goto finish;
		}
	}
finish:
	/*
	 * release memory allocated by section()
	 */
	sp = psecs;
	while (sp->ds) {
		free(sp->ds);
		sp->ds = NULL;
		sp++;
	}

	/*
	 * If we didn't find a match, return failure as if we didn't find
	 * the windex at all. Why? Well, if you create a windex, then upgrade
	 * to a later release that contains new man pages, and forget to
	 * recreate the windex (since we don't do that automatically), you
	 * won't see any new man pages since they aren't in the windex.
	 * Pretending we didn't see a windex at all if there are no matches
	 * forces a search of the underlying directory. After all, the
	 * goal of the windex is to enable searches (man -k) and speed things
	 * up, not to _prevent_ you from seeing new man pages, so this seems
	 * ok. The only problem is when there are multiple entries (different
	 * sections), and some are in and some are out. Say you do 'man ls',
	 * and ls(1) isn't in the windex, but ls(1B) is. In that case, we
	 * will find a match in ls(1B), and you'll see that man page.
	 * That doesn't seem bad since if you specify the section the search
	 * will be restricted too. So in the example above, if you do
	 * 'man -s 1 ls' you'll get ls(1).
	 */
	if (found_in_windex)
		return (0);
	else
		return (-1);
}


/*
 * Return pointers to the section-spec
 * and file-suffix of a whatis entry
 */

static void
section(struct suffix *sp, char *s)
{
	char *lp, *p;

	lp = strchr(s, '(');
	p = strchr(s, ')');

	if (++lp == 0 || p == 0 || lp == p) {
		(void) fprintf(stderr,
		    gettext("mangled windex entry:\n\t%s\n"), s);
		return;
	}
	*p = 0;

	/*
	 * copy the string pointed to by lp
	 */
	lp = strdup(lp);
	if (lp == NULL)
		malloc_error();
	/*
	 * release memory in s
	 * s has been allocated memory in bfsearch()
	 */
	free(s);

	lower(lp);

	/*
	 * split section-specifier if file-name
	 * suffix differs from section-suffix
	 */
	sp->ds = lp;
	if ((p = strchr(lp, '/'))) {
		*p++ = 0;
		sp->fs = p;
	} else
		sp->fs = lp;
}


/*
 * Binary file search to find matching man
 *   pages in whatis database.
 */

static int
bfsearch(FILE *fp, char **matchv, char *key)
{
	char entry[BUFSIZ];
	char **vp;
	long top, bot, mid;
	int	c;

	vp = matchv;
	bot = 0;
	(void) fseek(fp, 0L, 2);
	top = ftell(fp);
	for (;;) {
		mid = (top+bot)/2;
		(void) fseek(fp, mid, 0);
		do {
			c = getc(fp);
			mid++;
		} while (c != EOF && c != '\n');
		if (fgets(entry, sizeof (entry), fp) == NULL)
			break;
		switch (compare(key, entry)) {
		case -2:
		case -1:
		case 0:
			if (top <= mid)
				break;
			top = mid;
			continue;
		case 1:
		case 2:
			bot = mid;
			continue;
		}
		break;
	}
	(void) fseek(fp, bot, 0);
	while (ftell(fp) < top) {
		if (fgets(entry, sizeof (entry), fp) == NULL) {
			*matchv = 0;
			return (matchv - vp);
		}
		switch (compare(key, entry)) {
		case -2:
			*matchv = 0;
			return (matchv - vp);
		case -1:
		case 0:
			*matchv = strdup(entry);
			if (*matchv == NULL)
				malloc_error();
			else
				matchv++;
			break;
		case 1:
		case 2:
			continue;
		}
		break;
	}
	while (fgets(entry, sizeof (entry), fp)) {
		switch (compare(key, entry)) {
		case -1:
		case 0:
			*matchv = strdup(entry);
			if (*matchv == NULL)
				malloc_error();
			else
				matchv++;
			continue;
		}
		break;
	}
	*matchv = 0;
	return (matchv - vp);
}

static int
compare(char *key, char *entry)
{
	char	*entbuf;
	char	*s;
	int	comp, mlen;
	int	mbcurmax = MB_CUR_MAX;

	entbuf = strdup(entry);
	if (entbuf == NULL) {
		malloc_error();
	}

	s = entbuf;
	while (*s) {
		if (*s == '\t' || *s == ' ') {
			*s = '\0';
			break;
		}
		mlen = mblen(s, mbcurmax);
		if (mlen == -1) {
			(void) fprintf(stderr, gettext(
				"Invalid character in windex file.\n"));
			exit(1);
		}
		s += mlen;
	}

	comp = strcmp(key, entbuf);
	free(entbuf);
	if (comp == 0) {
		return (0);
	} else if (comp < 0) {
		return (-2);
	} else {
		return (2);
	}
}


/*
 * Format a man page and follow .so references
 * if necessary.
 */

static int
format(char *path, char *dir, char *name, char *pg)
{
	char manpname[MAXPATHLEN+1], catpname[MAXPATHLEN+1];
	char manpname_sgml[MAXPATHLEN+1], smantmpname[MAXPATHLEN+1];
	char soed[MAXPATHLEN+1], soref[MAXPATHLEN+1];
	char manbuf[BUFSIZ], cmdbuf[BUFSIZ], tmpbuf[BUFSIZ];
	char tmpdir[MAXPATHLEN+1];
	int socount, updatedcat, regencat;
	struct stat mansb, catsb, smansb;
	char *tmpname;
	int catonly = 0;
	struct stat statb;
	int plen = PLEN;
	FILE *md;
	int tempfd;
	ssize_t	count;
	int	temp, sgml_flag = 0, check_flag = 0;
	char prntbuf[BUFSIZ + 1];
	char *ptr;
	char *new_m;
	char	*tmpsubdir;

	found++;

	if (*dir != 'm' && *dir != 's')
		catonly++;


	if (*dir == 's') {
		tmpsubdir = SGMLDIR;
		++plen;
		(void) sprintf(manpname_sgml, "%s/man%s/%s",
			path, dir+plen, pg);
	} else
		tmpsubdir = MANDIRNAME;

	if (list) {
		(void) printf(gettext("%s (%s)\t-M %s\n"),
		    name, dir+plen, path);
		return (-1);
	}

	(void) sprintf(manpname, "%s/%s%s/%s", path, tmpsubdir, dir+plen, pg);
	(void) sprintf(catpname, "%s/%s%s/%s", path, subdirs[1], dir+plen, pg);

	(void) sprintf(smantmpname, "%s/%s%s/%s", path, SGMLDIR, dir+plen, pg);

/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  unformatted = /usr/share/man/ja/man3s/printf.3s
 */
	DPRINTF(gettext(
		"      unformatted = %s\n"), catonly ? "" : manpname);
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  formatted = /usr/share/man/ja/cat3s/printf.3s
 */
	DPRINTF(gettext(
		"      formatted = %s\n"), catpname);

	/*
	 * Take care of indirect references to other man pages;
	 * i.e., resolve files containing only ".so manx/file.x".
	 * We follow .so chains, replacing title with the .so'ed
	 * file at each stage, and keeping track of how many times
	 * we've done so, so that we can avoid looping.
	 */
	*soed = 0;
	socount = 0;
	for (;;) {
		FILE *md;
		char *cp;
		char *s;
		char *new_s;

		if (catonly)
			break;
		/*
		 * Grab manpname's first line, stashing it in manbuf.
		 */


		if ((md = fopen(manpname, "r")) == NULL) {
			if (*soed && errno == ENOENT) {
				(void) fprintf(stderr,
				    gettext("Can't find referent of "
					".so in %s\n"), soed);
				(void) fflush(stderr);
				return (-1);
			}
			perror(manpname);
			return (-1);
		}
		if (fgets(manbuf, BUFSIZ-1, md) == NULL) {
			(void) fclose(md);
			(void) fprintf(stderr, gettext("%s: null file\n"),
			    manpname);
			(void) fflush(stderr);
			return (-1);
		}
		(void) fclose(md);

		if (strncmp(manbuf, DOT_SO, sizeof (DOT_SO) - 1))
			break;
so_again:	if (++socount > SOLIMIT) {
			(void) fprintf(stderr, gettext(".so chain too long\n"));
			(void) fflush(stderr);
			return (-1);
		}
		s = manbuf + sizeof (DOT_SO) - 1;
		if ((check_flag == 1) && ((new_s = strrchr(s, '/')) != NULL)) {
				new_s++;
				(void) sprintf(s, "%s%s/%s",
					tmpsubdir, dir+plen, new_s);
		}

		cp = strrchr(s, '\n');
		if (cp)
			*cp = '\0';
		/*
		 * Compensate for sloppy typists by stripping
		 * trailing white space.
		 */
		cp = s + strlen(s);
		while (--cp >= s && (*cp == ' ' || *cp == '\t'))
			*cp = '\0';

		/*
		 * Go off and find the next link in the chain.
		 */
		(void) strcpy(soed, manpname);
		(void) strcpy(soref, s);
		(void) sprintf(manpname, "%s/%s", path, s);
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  .so ref = man3c/string.3c
 */
		DPRINTF(gettext(".so ref = %s\n"), s);
	}

	/*
	 * Make symlinks if so'ed and cattin'
	 */
	if (socount && catmando) {
		(void) sprintf(cmdbuf, "cd %s; rm -f %s; ln -s ../%s%s %s",
		    path, catpname, subdirs[1], soref+plen, catpname);
		(void) sys(cmdbuf);
		return (1);
	}

	/*
	 * Obtain the cat page that corresponds to the man page.
	 * If it already exists, is up to date, and if we haven't
	 * been told not to use it, use it as it stands.
	 */
	regencat = updatedcat = 0;
	if (compargs || (!catonly && stat(manpname, &mansb) >= 0 &&
	    (stat(catpname, &catsb) < 0 || catsb.st_mtime < mansb.st_mtime)) ||
	    (access(catpname, R_OK) != 0)) {
		/*
		 * Construct a shell command line for formatting manpname.
		 * The resulting file goes initially into /tmp.  If possible,
		 * it will later be moved to catpname.
		 */

		int pipestage = 0;
		int needcol = 0;
		char *cbp = cmdbuf;

		regencat = updatedcat = 1;

		if (!catmando && !debug && !check_flag) {
			(void) fprintf(stderr, gettext(
					"Reformatting page.  Please Wait..."));
			if (sargs && (newsection != NULL) &&
			    (*newsection != '\0')) {
				(void) fprintf(stderr, gettext(
				    "\nThe directory name has been changed "
				    "to %s\n"), newsection);
			}
			(void) fflush(stderr);
		}

		/*
		 * in catman command, if the file exists in sman dir already,
		 * don't need to convert the file in man dir to cat dir
		 */

		if (!no_sroff && catmando &&
			match(tmpsubdir, MANDIRNAME, PLEN) &&
			stat(smantmpname, &smansb) >= 0)
			return (1);

		/*
		 * cd to path so that relative .so commands will work
		 * correctly
		 */
		(void) sprintf(cbp, "cd %s; ", path);
		cbp += strlen(cbp);


		/*
		 * check to see whether it is a sgml file
		 * assume sgml symbol(>!DOCTYPE) can be found in the first
		 * BUFSIZ bytes
		 */

		if ((temp = open(manpname, 0)) == -1) {
				perror(manpname);
				return (-1);
		}

		if ((count = read(temp, prntbuf, BUFSIZ)) <= 0) {
				perror(manpname);
				return (-1);
		}

		prntbuf[count] = '\0';	/* null terminate */
		ptr = prntbuf;
		if (sgmlcheck((const char *)ptr) == 1) {
			sgml_flag = 1;
			if (defaultmandir && *localedir) {
				(void) sprintf(cbp, "LC_MESSAGES=C %s %s ",
					SROFF_CMD, manpname);
			} else {
				(void) sprintf(cbp, "%s %s ",
					SROFF_CMD, manpname);
			}
			cbp += strlen(cbp);
		} else if (*dir == 's') {
			(void) close(temp);
			return (-1);
		}
		(void) close(temp);

		/*
		 * Check for special formatting requirements by examining
		 * manpname's first line preprocessor specifications.
		 */

		if (strncmp(manbuf, PREPROC_SPEC,
		    sizeof (PREPROC_SPEC) - 1) == 0) {
			char *ptp;

			ptp = manbuf + sizeof (PREPROC_SPEC) - 1;
			while (*ptp && *ptp != '\n') {
				const struct preprocessor *pp;

				/*
				 * Check for a preprocessor we know about.
				 */
				for (pp = preprocessors; pp->p_tag; pp++) {
					if (pp->p_tag == *ptp)
						break;
				}
				if (pp->p_tag == 0) {
					(void) fprintf(stderr,
					    gettext("unknown preprocessor "
						"specifier %c\n"), *ptp);
					(void) fflush(stderr);
					return (-1);
				}

				/*
				 * Add it to the pipeline.
				 */
				(void) sprintf(cbp, "%s %s |",
					troffit ? pp->p_troff : pp->p_nroff,
					pipestage++ == 0 ? manpname : "-");
				cbp += strlen(cbp);

				/*
				 * Special treatment: if tbl is among the
				 * preprocessors and we'll process with
				 * nroff, we have to pass things through
				 * col at the end of the pipeline.
				 */
				if (pp->p_tag == 't' && !troffit)
					needcol++;

				ptp++;
			}
		}

		/*
		 * if catman, use the cat page name
		 * otherwise, dup template and create another
		 * (needed for multiple pages)
		 */
		if (catmando)
			tmpname = catpname;
		else {
			tmpname = strdup(TEMPLATE);
			if (tmpname == NULL)
				malloc_error();
			(void) close(mkstemp(tmpname));
		}

		if (! Tflag) {
			if (*localedir != '\0') {
				(void) sprintf(macros, "%s/%s", path, MACROF);
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  locale macros = /usr/share/man/ja/tmac.an
 */
				if (debug)
					(void) printf(gettext(
						"\nlocale macros = %s "),
						macros);
				if (stat(macros, &statb) < 0)
					(void) strcpy(macros, TMAC_AN);
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex.  macros = /usr/share/man/ja/tman.an
 */
				if (debug)
					(void) printf(gettext(
						"\nmacros = %s\n"),
						macros);
			}
		}

		if (sgml_flag == 1) {
			if (check_flag == 0) {
				strcpy(tmpdir, "/tmp/sman_XXXXXX");
				if ((tempfd = mkstemp(tmpdir)) == -1) {
					(void) fprintf(stderr, gettext(
					    "%s: null file\n"), tmpdir);
					(void) fflush(stderr);
					return (-1);
				}

				if (debug)
					close(tempfd);

				(void) sprintf(tmpbuf, "%s > %s",
					cmdbuf, tmpdir);
				if (sys(tmpbuf)) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * Error message if sys(%s) failed
 */
					(void) fprintf(stderr, gettext(
						"sys(%s) fail!\n"), tmpbuf);
					(void) fprintf(stderr,
						gettext(" aborted (sorry)\n"));
					(void) fflush(stderr);
					/* release memory for tmpname */
					if (!catmando) {
						(void) unlink(tmpdir);
						(void) unlink(tmpname);
						free(tmpname);
					}
					return (-1);
				} else if (debug == 0) {
					if ((md = fdopen(tempfd, "r"))
					    == NULL) {
						(void) fprintf(stderr, gettext(
						    "%s: null file\n"), tmpdir);
						(void) fflush(stderr);
						close(tempfd);
						/* release memory for tmpname */
						if (!catmando)
							free(tmpname);
						return (-1);
					}

					/* if the file is empty, */
					/* it's a fragment, do nothing */
					if (fgets(manbuf, BUFSIZ-1, md)
						== NULL) {
						(void) fclose(md);
						/* release memory for tmpname */
						if (!catmando)
							free(tmpname);
						return (1);
					}
					(void) fclose(md);

					if (strncmp(manbuf, DOT_SO,
						sizeof (DOT_SO) - 1) == 0) {
						if (!compargs) {
						check_flag = 1;
						(void) unlink(tmpdir);
						(void) unlink(tmpname);
						/* release memory for tmpname */
						if (!catmando)
							free(tmpname);
						goto so_again;
						} else {
							(void) unlink(tmpdir);
						strcpy(tmpdir,
						    "/tmp/sman_XXXXXX");
						tempfd = mkstemp(tmpdir);
						if ((tempfd == -1) ||
						    (md = fdopen(tempfd, "w"))
						    == NULL) {
							(void) fprintf(stderr,
							gettext(
							    "%s: null file\n"),
							    tmpdir);
							(void) fflush(stderr);
							if (tempfd != -1)
								close(tempfd);
						/* release memory for tmpname */
							if (!catmando)
								free(tmpname);
							return (-1);
						}
				if ((new_m = strrchr(manbuf, '/')) != NULL) {
		(void) fprintf(md, ".so man%s%s\n", dir+plen, new_m);
							} else {
/*
 * TRANSLATION_NOTE - message for catman -c
 * Error message if unable to get file name
 */
				(void) fprintf(stderr,
					gettext("file not found\n"));
				(void) fflush(stderr);
				return (-1);
				}
							(void) fclose(md);
						}
					}
				}
				if (catmando && compargs)
					(void) sprintf(cmdbuf, "cat %s > %s",
						tmpdir, manpname_sgml);
				else
(void) sprintf(cmdbuf, " cat %s | tbl | eqn | %s %s - %s > %s",
	tmpdir, troffit ? troffcmd : "nroff -u0 -Tlp",
	macros, troffit ? "" : " | col -x", tmpname);
			} else
				if (catmando && compargs)
					(void) sprintf(cbp, " > %s",
						manpname_sgml);
				else
(void) sprintf(cbp, " | tbl | eqn | %s %s - %s > %s",
	troffit ? troffcmd : "nroff -u0 -Tlp",
	macros, troffit ? "" : " | col -x", tmpname);

		} else
(void) sprintf(cbp, "%s %s %s%s > %s",
	troffit ? troffcmd : "nroff -u0 -Tlp",
	macros, pipestage == 0 ? manpname : "-",
	troffit ? "" : " | col -x", tmpname);

		/* Reformat the page. */
		if (sys(cmdbuf)) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * Error message if sys(%s) failed
 */
			(void) fprintf(stderr, gettext(
				"sys(%s) fail!\n"), cmdbuf);
			(void) fprintf(stderr, gettext(" aborted (sorry)\n"));
			(void) fflush(stderr);
			(void) unlink(tmpname);
			/* release memory for tmpname */
			if (!catmando)
				free(tmpname);
			return (-1);
		}

		(void) unlink(tmpdir);

		if (catmando)
			return (1);

		/*
		 * Attempt to move the cat page to its proper home.
		 */
		(void) sprintf(cmdbuf,
			"trap '' 1 15; /usr/bin/mv -f %s %s 2> /dev/null",
			tmpname,
			catpname);
		if (sys(cmdbuf))
			updatedcat = 0;
		else if (debug == 0)
			(void) chmod(catpname, 0644);

		if (debug) {
			/* release memory for tmpname */
			if (!catmando)
				free(tmpname);
			(void) unlink(tmpname);
			return (1);
		}

		(void) fprintf(stderr, gettext(" done\n"));
		(void) fflush(stderr);
	}

	/*
	 * Save file name (dup if necessary)
	 * to view later
	 * fix for 1123802 - don't save names if we are invoked as catman
	 */
	if (!catmando) {
		char	**tmpp;
		int	dup;
		char	*newpage;

		if (regencat && !updatedcat)
			newpage = tmpname;
		else {
			newpage = strdup(catpname);
			if (newpage == NULL)
				malloc_error();
		}
		/* make sure we don't add a dup */
		dup = 0;
		for (tmpp = pages; tmpp < endp; tmpp++) {
			if (strcmp(*tmpp, newpage) == 0) {
				dup = 1;
				break;
			}
		}
		if (!dup)
			*endp++ = newpage;
		if (endp >= &pages[MAXPAGES]) {
			fprintf(stderr,
			    gettext("Internal pages array overflow!\n"));
			exit(1);
		}
	}

	return (regencat);
}

/*
 * Add <localedir> to the path.
 */

static char *
addlocale(char *path)
{

	char *tmp;

	tmp = malloc(strlen(path) + strlen(localedir) + 2);
	if (tmp == NULL)
		malloc_error();
	(void) sprintf(tmp, "%s/%s", path, localedir);
	return (tmp);

}

/*
 * From the configuration file "man.cf", get the order of suffices of
 * sub-mandirs to be used in the search path for a given mandir.
 */

static char *
check_config(char *path)
{
	FILE *fp;
	static char submandir[BUFSIZ];
	char *sect;
	char fname[MAXPATHLEN];

	(void) sprintf(fname, "%s/%s", path, CONFIG);

	if ((fp = fopen(fname, "r")) == NULL)
		return (NULL);
	else {
		if (get_manconfig(fp, submandir) == -1) {
			(void) fclose(fp);
			return (NULL);
		}

		(void) fclose(fp);

		sect = strchr(submandir, '=');
		if (sect != NULL)
			return (++sect);
		else
			return (NULL);
	}
}

/*
 *  This routine is for getting the MANSECTS entry from man.cf.
 *  It sets submandir to the line in man.cf that contains
 *	MANSECTS=sections[,sections]...
 */

static int
get_manconfig(FILE *fp, char *submandir)
{
	char *s, *t, *rc;
	char buf[BUFSIZ];

	while ((rc = fgets(buf, sizeof (buf), fp)) != NULL) {

		/*
		 * skip leading blanks
		 */
		for (t = buf; *t != '\0'; t++) {
			if (!isspace(*t))
				break;
		}
		/*
		 * skip line that starts with '#' or empty line
		 */
		if (*t == '#' || *t == '\0')
			continue;

		if (strstr(buf, "MANSECTS") != NULL)
			break;
	}

	/*
	 * the man.cf file doesn't have a MANSECTS entry
	 */
	if (rc == NULL)
		return (-1);

	s = strchr(buf, '\n');
	*s = '\0';	/* replace '\n' with '\0' */

	(void) strcpy(submandir, buf);
	return (0);
}

static void
malloc_error(void)
{
	(void) fprintf(stderr, gettext(
		"Memory allocation failed.\n"));
	exit(1);
}

static int
sgmlcheck(const char *s1)
{
	const char	*s2 = SGML_SYMBOL;
	int	len;

	while (*s1) {
		/*
		 * Assume the first character of SGML_SYMBOL(*s2) is '<'.
		 * Therefore, not necessary to do toupper(*s1) here.
		 */
		if (*s1 == *s2) {
			/*
			 * *s1 is '<'.  Check the following substring matches
			 * with "!DOCTYPE".
			 */
			s1++;
			if (strncasecmp(s1, s2 + 1, SGML_SYMBOL_LEN - 1)
				== 0) {
				/*
				 * SGML_SYMBOL found
				 */
				return (1);
			}
			continue;
		} else if (isascii(*s1)) {
			/*
			 * *s1 is an ASCII char
			 * Skip one character
			 */
			s1++;
			continue;
		} else {
			/*
			 * *s1 is a non-ASCII char or
			 * the first byte of the multibyte char.
			 * Skip one character
			 */
			len = mblen(s1, MB_CUR_MAX);
			if (len == -1)
				len = 1;
			s1 += len;
			continue;
		}
	}
	/*
	 * SGML_SYMBOL not found
	 */
	return (0);
}

#ifdef notdef
/*
 * This routine is for debugging purposes. It prints out all the
 * mandir paths.
 */

printmandir(manp)
struct man_node *manp;
{
	struct man_node *p;

	(void) fprintf(stdout,
		"in printmandir, printing each mandir path ...\n");
	for (p = manp; p != NULL; p = p->next) {
		(void) printf("\tpath = %s\n", p->path);
	}
}

/*
 * This routine is for debugging purposes. It prints out the
 * corresponding sections (submandir directories) of a mandir.
 */

void
printsect(char **s)
{
	char **p;

	(void) fprintf(stdout, "in printsect, printing sections ... \n");
	for (p = s; *p; p++)
		(void) printf("\t%s\n", *p);
}
#endif
