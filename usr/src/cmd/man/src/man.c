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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012, Josef 'Jeff' Sipek <jeffpc@31bits.net>. All rights reserved.
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
#define	MAXPAGES	128	/* max # for multiple pages */
#define	PLEN		3	/* prefix length {man, cat, fmt} */
#define	TMPLEN		7	/* length of tmpfile prefix */
#define	MAXTOKENS 	64

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
		*p_troff,
		*p_stdin_char;
} preprocessors [] = {
	{'c',	"cw",				"cw",		"-"},
	{'e',	"neqn /usr/share/lib/pub/eqnchar",
			"eqn /usr/share/lib/pub/eqnchar",	"-"},
	{'p',	"gpic",				"gpic",		"-"},
	{'r',	"refer",			"refer",	"-"},
	{'t',	"tbl",				"tbl",		""},
	{'v',	"vgrind -f",			"vgrind -f",	"-"},
	{0,	0,				0,		0}
};

struct suffix {
	char *ds;
	char *fs;
};

/*
 * Flags that control behavior of build_manpath()
 *
 *   BMP_ISPATH 	pathv is a vector constructed from PATH.
 *                	Perform appropriate path translations for
 * 			manpath.
 *   BMP_APPEND_MANDIR	Add /usr/share/man to the end if it
 *			hasn't already appeared earlier.
 *   BMP_FALLBACK_MANDIR Append /usr/share/man only if no other
 *			manpath (including derived from PATH)
 * 			elements are valid.
 */
#define	BMP_ISPATH		1
#define	BMP_APPEND_MANDIR	2
#define	BMP_FALLBACK_MANDIR	4

/*
 * When doing equality comparisons of directories, device and inode
 * comparisons are done.  The dupsec and dupnode structures are used
 * to form a list of lists for this processing.
 */
struct secnode {
	char		*secp;
	struct secnode	*next;
};
struct dupnode {
	dev_t		dev;	/* from struct stat st_dev */
	ino_t		ino;	/* from struct stat st_ino */
	struct secnode	*secl;	/* sections already considered */
	struct dupnode	*next;
};

/*
 * Map directories that may appear in PATH to the corresponding
 * man directory
 */
static struct pathmap {
	char	*bindir;
	char	*mandir;
	dev_t	dev;
	ino_t	ino;
} bintoman[] = {
	{"/sbin",		"/usr/share/man,1m",			0, 0},
	{"/usr/sbin",		"/usr/share/man,1m",			0, 0},
	{"/usr/ucb",		"/usr/share/man,1b",			0, 0},
	{"/usr/bin/X11",	"/usr/X11/share/man",			0, 0},
	/*
	 * Restrict to section 1 so that whatis /usr/{,xpg4,xpg6}/bin/ls
	 * does not confuse users with section 1 and 1b
	 */
	{"/usr/bin",		"/usr/share/man,1,1m,1s,1t,1c", 	0, 0},
	{"/usr/xpg4/bin",	"/usr/share/man,1",			0, 0},
	{"/usr/xpg6/bin",	"/usr/share/man,1",			0, 0},
	{NULL,			NULL,					0, 0}
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
usage:\tman [-] [-adFlprt] [-M path] [-T macro-package ] [ -s section ] \
name ...\n\
\tman [-M path] -k keyword ...\n\tman [-M path] -f file ..."
#define	CATMAN_USAGE "\
usage:\tcatman [-p] [-c|-ntw] [-M path] [-T macro-package ] [sections]"

static char *opts[] = {
	"FfkrpP:M:T:ts:lad",	/* man */
	"wpnP:M:T:tc"		/* catman */
};

struct man_node {
	char *path;		/* mandir path */
	char **secv;		/* submandir suffices */
	int  defsrch;		/* hint for man -p to avoid section list */
	int  frompath;		/* hint for man -d and catman -p */
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
static int	printmp;

static char	*CAT	= CAT_;
static char	macros[MAXPATHLEN];
static char	*mansec;
static char	*pager;
static char	*troffcmd;
static char	*troffcat;
static char	**subdirs;

static char *check_config(char *);
static struct man_node *build_manpath(char **, int);
static void getpath(struct man_node *, char **);
static void getsect(struct man_node *, char **);
static void get_all_sect(struct man_node *);
static void catman(struct man_node *, char **, int);
static int makecat(char *, char **, int);
static int getdirs(char *, char ***, short);
static void whatapro(struct man_node *, char *, int);
static void lookup_windex(char *, char *, char **);
static int icmp(wchar_t *, wchar_t *);
static void more(char **, int);
static void cleanup(char **);
static void bye(int);
static char **split(char *, char);
static void freev(char **);
static void fullpaths(struct man_node **);
static void lower(char *);
static int cmp(const void *, const void *);
static int manual(struct man_node *, char *);
static void mandir(char **, char *, char *);
static void sortdir(DIR *, char ***);
static int searchdir(char *, char *, char *);
static int windex(char **, char *, char *);
static void section(struct suffix *, char *);
static int bfsearch(FILE *, char **, char *, char **);
static int compare(char *, char *, char **);
static int format(char *, char *, char *, char *);
static char *addlocale(char *);
static int get_manconfig(FILE *, char *);
static void	malloc_error(void);
static int	sgmlcheck(const char *);
static char *map_section(char *, char *);
static void free_manp(struct man_node *manp);
static void init_bintoman(void);
static char *path_to_manpath(char *);
static int dupcheck(struct man_node *, struct dupnode **);
static void free_dupnode(struct dupnode *);
static void print_manpath(struct man_node *, char *);

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
	char **pathv;
	char *cmdname;
	char *manpath = NULL;
	static struct man_node	*manpage = NULL;
	int bmp_flags = 0;
	int err = 0;

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
			debug++;
			break;
		/*
		 * man and catman use -p differently.  In catman it
		 * enables debug mode and in man it prints the (possibly
		 * derived from PATH or name operand) MANPATH.
		 */
		case 'p':
			if (catmando == 0) {
				printmp++;
			} else {
				debug++;
			}
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
	 *	(man -p and catman don't need args)
	 */
	if (badopts || (!catmando && !printmp && optind == argc)) {
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

	init_bintoman();

	if (manpath == NULL && (manpath = getenv("MANPATH")) == NULL) {
		if ((manpath = getenv("PATH")) != NULL) {
			bmp_flags = BMP_ISPATH | BMP_APPEND_MANDIR;
		} else {
			manpath = MANDIR;
		}
	}

	pathv = split(manpath, ':');

	manpage = build_manpath(pathv, bmp_flags);

	/* release pathv allocated by split() */
	freev(pathv);

	/*
	 * Since we can't make use of GNU troff, set the path to ensure we
	 * find the one in /usr/bin first.
	 */
	if (putenv("PATH=/usr/bin") != 0) {
		perror("putenv");
		exit(1);
	}

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

	/*
	 * "man -p" without operands
	 */
	if ((printmp != 0) && (optind == argc)) {
		print_manpath(manpage, NULL);
		exit(0);
	}

	for (; optind < argc; optind++) {
		if (strcmp(argv[optind], "-") == 0) {
			nomore++;
			CAT = CAT_S;
		} else {
			char *cmd;
			static struct man_node *mp;
			char *pv[2];

			/*
			 * If full path to command specified, customize
			 * manpath accordingly
			 */
			if ((cmd = strrchr(argv[optind], '/')) != NULL) {
				*cmd = '\0';
				if ((pv[0] = strdup(argv[optind])) == NULL) {
					malloc_error();
				}
				pv[1] = NULL;
				*cmd = '/';
				mp = build_manpath(pv,
				    BMP_ISPATH|BMP_FALLBACK_MANDIR);
			} else {
				mp = manpage;
			}

			if (whatis) {
				whatapro(mp, argv[optind], apropos);
			} else if (printmp != 0) {
				print_manpath(mp, argv[optind]);
			} else {
				err += manual(mp, argv[optind]);
			}

			if (mp != NULL && mp != manpage) {
				free(pv[0]);
				free_manp(mp);
			}
		}
	}
	return (err == 0 ? 0 : 1);
	/*NOTREACHED*/
}

/*
 * This routine builds the manpage structure from MANPATH or PATH,
 * depending on flags.  See BMP_* definitions above for valid
 * flags.
 *
 * Assumes pathv elements were malloc'd, as done by split().
 * Elements may be freed and reallocated to have different contents.
 */

static struct man_node *
build_manpath(char **pathv, int flags)
{
	struct man_node *manpage = NULL;
	struct man_node *currp = NULL;
	struct man_node *lastp = NULL;
	char **p;
	char **q;
	char *mand = NULL;
	char *mandir = MANDIR;
	int s;
	struct dupnode *didup = NULL;
	struct stat sb;

	s = sizeof (struct man_node);
	for (p = pathv; *p; ) {

		if (flags & BMP_ISPATH) {
			if ((mand = path_to_manpath(*p)) == NULL) {
				goto next;
			}
			free(*p);
			*p = mand;
		}
		q = split(*p, ',');
		if (stat(q[0], &sb) != 0 || (sb.st_mode & S_IFDIR) == 0) {
			freev(q);
			goto next;
		}

		if (access(q[0], R_OK|X_OK) != 0) {
			if (catmando) {
				(void) fprintf(stderr,
				    gettext("%s is not accessible.\n"),
				    q[0]);
				(void) fflush(stderr);
			}
		} else {

			/*
			 * Some element exists.  Do not append MANDIR as a
			 * fallback.
			 */
			flags &= ~BMP_FALLBACK_MANDIR;

			if ((currp = (struct man_node *)calloc(1, s)) == NULL) {
				malloc_error();
			}

			currp->frompath = (flags & BMP_ISPATH);

			if (manpage == NULL) {
				lastp = manpage = currp;
			}

			getpath(currp, p);
			getsect(currp, p);

			/*
			 * If there are no new elements in this path,
			 * do not add it to the manpage list
			 */
			if (dupcheck(currp, &didup) != 0) {
				freev(currp->secv);
				free(currp);
			} else {
				currp->next = NULL;
				if (currp != manpage) {
					lastp->next = currp;
				}
				lastp = currp;
			}
		}
		freev(q);
next:
		/*
		 * Special handling of appending MANDIR.
		 * After all pathv elements have been processed, append MANDIR
		 * if needed.
		 */
		if (p == &mandir) {
			break;
		}
		p++;
		if (*p != NULL) {
			continue;
		}
		if (flags & (BMP_APPEND_MANDIR|BMP_FALLBACK_MANDIR)) {
			p = &mandir;
			flags &= ~BMP_ISPATH;
		}
	}

	free_dupnode(didup);

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
		if (debug) {
			if (manp->frompath != 0) {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. /usr/share/man: derived from PATH, MANSECTS=,1b
 */
				(void) printf(gettext(
				    "%s: derived from PATH, MANSECTS=%s\n"),
				    manp->path, sections);
			} else {
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. /usr/share/man: from -M option, MANSECTS=,1,2,3c
 */
				(void) fprintf(stdout, gettext(
				    "%s: from -M option, MANSECTS=%s\n"),
				    manp->path, sections);
			}
		}
		manp->secv = split(++sections, ',');
		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);

		if (*manp->secv == NULL)
			get_all_sect(manp);
	} else if ((sections = check_config(*pv)) != NULL) {
		manp->defsrch = 1;
/*
 * TRANSLATION_NOTE - message for man -d or catman -p
 * ex. /usr/share/man: from man.cf, MANSECTS=1,1m,1c
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
		manp->defsrch = 1;
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
	char *prev = NULL;
	char *tmp = NULL;
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

	for (dv = dirv, p = manp->secv; *dv; dv++) {
		plen = PLEN;
		if (match(*dv, SGMLDIR, PLEN+1))
			++plen;

		if (strcmp(*dv, CONFIG) == 0) {
			/* release memory allocated by sortdir */
			free(*dv);
			continue;
		}

		if (tmp != NULL)
			free(tmp);
		tmp = strdup(*dv + plen);
		if (tmp == NULL)
			malloc_error();
		(void) sprintf(tmp, "%s", *dv + plen);

		if (prev != NULL) {
			if (strcmp(prev, tmp) == 0) {
				/* release memory allocated by sortdir */
				free(*dv);
				continue;
			}
		}

		if (prev != NULL)
			free(prev);
		prev = strdup(*dv + plen);
		if (prev == NULL)
			malloc_error();
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
	struct dupnode *dnp = NULL;
	char   **realsecv;
	/*
	 * May be overwritten in dupcheck() so must be kept out of .rodata.
	 */
	char	fakename[] = " catman ";
	char	*fakesecv[2];

	fakesecv[0] = fakename;
	fakesecv[1] = NULL;

	for (p = manp; p != NULL; p = p->next) {
		/*
		 * prevent catman from doing very heavy lifting multiple
		 * times on some directory
		 */
		realsecv = p->secv;
		p->secv = fakesecv;
		if (dupcheck(p, &dnp) != 0) {
			p->secv = realsecv;
			continue;
		}

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
	free_dupnode(dnp);
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
				lookup_windex(whatpath, p, b->secv);
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

		lookup_windex(whatpath, p, b->secv);
	}
}


static void
lookup_windex(char *whatpath, char *word, char **secv)
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
		if (bfsearch(fp, matches, word, secv))
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
 * Free a vector allocated by split();
 */
static void
freev(char **v)
{
	int i;
	if (v != NULL) {
		for (i = 0; v[i] != NULL; i++) {
			free(v[i]);
		}
		free(v);
	}
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

static int
manual(struct man_node *manp, char *name)
{
	struct man_node *p;
	struct man_node *local;
	int ndirs = 0;
	char *ldir;
	char *ldirs[2];
	char *fullname = name;
	char *slash;

	if ((slash = strrchr(name, '/')) != NULL) {
		name = slash + 1;
	}

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
				local = build_manpath(ldirs, 0);
				if (force ||
				    windex(local->secv, ldir, name) < 0)
					mandir(local->secv, ldir, name);
				free_manp(local);
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
			(void) fprintf(stderr, gettext("No entry for %s in "
			    "section(s) %s of the manual.\n"),
			    fullname, mansec);
		} else {
			(void) fprintf(stderr, gettext(
			    "No manual entry for %s.\n"), fullname, mansec);
		}

		if (sman_no_man_no_sroff)
			(void) fprintf(stderr, gettext("(An SGML manpage was "
			    "found for '%s' but it cannot be displayed.)\n"),
			    fullname, mansec);
	}
	sman_no_man_no_sroff = 0;
	return (!found);
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
			} else if (strncasecmp(*secv, *dv+plen, len) != 0) {
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
	struct suffix	psecs[MAXPAGES+1];
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

	if (bfsearch(fp, matches, name, NULL) == 0) {
		(void) fclose(fp);
		return (-1); /* force search in mandir */
	}

	(void) fclose(fp);

	/*
	 * Save and split sections
	 * section() allocates memory for sp->ds
	 */
	for (sp = psecs, vp = matches; *vp; vp++, sp++) {
		if ((sp - psecs) < MAXPAGES) {
			section(sp, *vp);
		} else {
			if (debug)
				(void) fprintf(stderr, gettext(
				    "too many sections in %s windex entry\n"),
				    name);

			/* Setting sp->ds to NULL signifies end-of-data. */
			sp->ds = 0;
			goto finish;
		}
	}

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
bfsearch(FILE *fp, char **matchv, char *key, char **secv)
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
		switch (compare(key, entry, secv)) {
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
		switch (compare(key, entry, secv)) {
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
		switch (compare(key, entry, secv)) {
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
compare(char *key, char *entry, char **secv)
{
	char	*entbuf;
	char	*s;
	int	comp, mlen;
	int	mbcurmax = MB_CUR_MAX;
	char 	*secp = NULL;
	int	rv;
	int	eblen;

	entbuf = strdup(entry);
	if (entbuf == NULL) {
		malloc_error();
	}
	eblen = strlen(entbuf);

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
	/*
	 * Find the section within parantheses
	 */
	if (secv != NULL && (s - entbuf) < eblen) {
		if ((secp = strchr(s + 1, ')')) != NULL) {
			*secp = '\0';
			if ((secp = strchr(s + 1, '(')) != NULL) {
				secp++;
			}
		}
	}

	comp = strcmp(key, entbuf);
	if (comp == 0) {
		if (secp == NULL) {
			rv = 0;
		} else {
			while (*secv != NULL) {
				if ((strcmp(*secv, secp)) == 0) {
					rv = 0;
					break;
				}
				secv++;
			}
		}
	} else if (comp < 0) {
		rv = -2;
	} else {
		rv = 2;
	}
	free(entbuf);
	return (rv);
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

		/*
		 * If this is a directory, just ignore it.
		 */
		if (fstat(fileno(md), &statb) == NULL) {
			if (S_ISDIR(statb.st_mode)) {
				if (debug) {
					(void) fprintf(stderr,
					    "\tignoring directory %s\n",
					    manpname);
					(void) fflush(stderr);
				}
				(void) fclose(md);
				return (-1);
			}
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
				    pipestage++ == 0 ? manpname :
				    pp->p_stdin_char);
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

		tmpdir[0] = '\0';
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

		if (tmpdir[0] != '\0')
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

/*
 * Initializes the bintoman array with appropriate device and inode info
 */

static void
init_bintoman(void)
{
	int i;
	struct stat sb;

	for (i = 0; bintoman[i].bindir != NULL; i++) {
		if (stat(bintoman[i].bindir, &sb) == 0) {
			bintoman[i].dev = sb.st_dev;
			bintoman[i].ino = sb.st_ino;
		} else {
			bintoman[i].dev = NODEV;
		}
	}
}

/*
 * If a duplicate is found, return 1
 * If a duplicate is not found, add it to the dupnode list and return 0
 */
static int
dupcheck(struct man_node *mnp, struct dupnode **dnp)
{
	struct dupnode	*curdnp;
	struct secnode	*cursnp;
	struct stat 	sb;
	int 		i;
	int		rv = 1;
	int		dupfound;

	/*
	 * If the path doesn't exist, treat it as a duplicate
	 */
	if (stat(mnp->path, &sb) != 0) {
		return (1);
	}

	/*
	 * If no sections were found in the man dir, treat it as duplicate
	 */
	if (mnp->secv == NULL) {
		return (1);
	}

	/*
	 * Find the dupnode structure for the previous time this directory
	 * was looked at.  Device and inode numbers are compared so that
	 * directories that are reached via different paths (e.g. /usr/man vs.
	 * /usr/share/man) are treated as equivalent.
	 */
	for (curdnp = *dnp; curdnp != NULL; curdnp = curdnp->next) {
		if (curdnp->dev == sb.st_dev && curdnp->ino == sb.st_ino) {
			break;
		}
	}

	/*
	 * First time this directory has been seen.  Add a new node to the
	 * head of the list.  Since all entries are guaranteed to be unique
	 * copy all sections to new node.
	 */
	if (curdnp == NULL) {
		if ((curdnp = calloc(1, sizeof (struct dupnode))) == NULL) {
			malloc_error();
		}
		for (i = 0; mnp->secv[i] != NULL; i++) {
			if ((cursnp = calloc(1, sizeof (struct secnode)))
			    == NULL) {
				malloc_error();
			}
			cursnp->next = curdnp->secl;
			curdnp->secl = cursnp;
			if ((cursnp->secp = strdup(mnp->secv[i])) == NULL) {
				malloc_error();
			}
		}
		curdnp->dev = sb.st_dev;
		curdnp->ino = sb.st_ino;
		curdnp->next = *dnp;
		*dnp = curdnp;
		return (0);
	}

	/*
	 * Traverse the section vector in the man_node and the section list
	 * in dupnode cache to eliminate all duplicates from man_node
	 */
	for (i = 0; mnp->secv[i] != NULL; i++) {
		dupfound = 0;
		for (cursnp = curdnp->secl; cursnp != NULL;
		    cursnp = cursnp->next) {
			if (strcmp(mnp->secv[i], cursnp->secp) == 0) {
				dupfound = 1;
				break;
			}
		}
		if (dupfound) {
			mnp->secv[i][0] = '\0';
			continue;
		}


		/*
		 * Update curdnp and set return value to indicate that this
		 * was not all duplicates.
		 */
		if ((cursnp = calloc(1, sizeof (struct secnode))) == NULL) {
			malloc_error();
		}
		cursnp->next = curdnp->secl;
		curdnp->secl = cursnp;
		if ((cursnp->secp = strdup(mnp->secv[i])) == NULL) {
			malloc_error();
		}
		rv = 0;
	}

	return (rv);
}

/*
 * Given a bin directory, return the corresponding man directory.
 * Return string must be free()d by the caller.
 *
 * NULL will be returned if no matching man directory can be found.
 */

static char *
path_to_manpath(char *bindir)
{
	char	*mand, *p;
	int	i;
	struct stat	sb;

	/*
	 * First look for known translations for specific bin paths
	 */
	if (stat(bindir, &sb) != 0) {
		return (NULL);
	}
	for (i = 0; bintoman[i].bindir != NULL; i++) {
		if (sb.st_dev == bintoman[i].dev &&
		    sb.st_ino == bintoman[i].ino) {
			if ((mand = strdup(bintoman[i].mandir)) == NULL) {
				malloc_error();
			}
			if ((p = strchr(mand, ',')) != NULL) {
				*p = '\0';
			}
			if (stat(mand, &sb) != 0) {
				free(mand);
				return (NULL);
			}
			if (p != NULL) {
				*p = ',';
			}
			return (mand);
		}
	}

	/*
	 * No specific translation found.  Try `dirname $bindir`/man
	 * and `dirname $bindir`/share/man
	 */
	if ((mand = malloc(PATH_MAX)) == NULL) {
		malloc_error();
	}

	if (strlcpy(mand, bindir, PATH_MAX) >= PATH_MAX) {
		free(mand);
		return (NULL);
	}

	/*
	 * Advance to end of buffer, strip trailing /'s then remove last
	 * directory component.
	 */
	for (p = mand; *p != '\0'; p++)
		;
	for (; p > mand && *p == '/'; p--)
		;
	for (; p > mand && *p != '/'; p--)
		;
	if (p == mand && *p == '.') {
		if (realpath("..", mand) == NULL) {
			free(mand);
			return (NULL);
		}
		for (; *p != '\0'; p++)
			;
	} else {
		*p = '\0';
	}

	if (strlcat(mand, "/man", PATH_MAX) >= PATH_MAX) {
		free(mand);
		return (NULL);
	}

	if ((stat(mand, &sb) == 0) && S_ISDIR(sb.st_mode)) {
		return (mand);
	}

	/*
	 * Strip the /man off and try /share/man
	 */
	*p = '\0';
	if (strlcat(mand, "/share/man", PATH_MAX) >= PATH_MAX) {
		free(mand);
		return (NULL);
	}
	if ((stat(mand, &sb) == 0) && S_ISDIR(sb.st_mode)) {
		return (mand);
	}

	/*
	 * No man or share/man directory found
	 */
	free(mand);
	return (NULL);
}

/*
 * Free a linked list of dupnode structs
 */
void
free_dupnode(struct dupnode *dnp) {
	struct dupnode *dnp2;
	struct secnode *snp;

	while (dnp != NULL) {
		dnp2 = dnp;
		dnp = dnp->next;
		while (dnp2->secl != NULL) {
			snp = dnp2->secl;
			dnp2->secl = dnp2->secl->next;
			free(snp->secp);
			free(snp);
		}
		free(dnp2);
	}
}

/*
 * prints manp linked list to stdout.
 *
 * If namep is NULL, output can be used for setting MANPATH.
 *
 * If namep is not NULL output is two columns.  First column is the string
 * pointed to by namep.  Second column is a MANPATH-compatible representation
 * of manp linked list.
 */
void
print_manpath(struct man_node *manp, char *namep)
{
	char colon[2];
	char **secp;

	if (namep != NULL) {
		(void) printf("%s ", namep);
	}

	colon[0] = '\0';
	colon[1] = '\0';

	for (; manp != NULL; manp = manp->next) {
		(void) printf("%s%s", colon, manp->path);
		colon[0] = ':';

		/*
		 * If man.cf or a directory scan was used to create section
		 * list, do not print section list again.  If the output of
		 * man -p is used to set MANPATH, subsequent runs of man
		 * will re-read man.cf and/or scan man directories as
		 * required.
		 */
		if (manp->defsrch != 0) {
			continue;
		}

		for (secp = manp->secv; *secp != NULL; secp++) {
			/*
			 * Section deduplication may have eliminated some
			 * sections from the vector. Avoid displaying this
			 * detail which would appear as ",," in output
			 */
			if ((*secp)[0] != '\0') {
				(void) printf(",%s", *secp);
			}
		}
	}
	(void) printf("\n");
}
