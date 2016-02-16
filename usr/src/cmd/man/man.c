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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2016 Nexenta Systems, Inc.
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
 * Find and display reference manual pages. This version includes makewhatis
 * functionality as well.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/types.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <locale.h>
#include <malloc.h>
#include <memory.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "man.h"


/* Mapping of old directories to new directories */
static const struct map_entry {
	char	*old_name;
	char	*new_name;
} map[] = {
	{ "3b",		"3ucb"		},
	{ "3e",		"3elf"		},
	{ "3g",		"3gen"		},
	{ "3k",		"3kstat"	},
	{ "3n",		"3socket"	},
	{ "3r",		"3rt"		},
	{ "3s",		"3c"		},
	{ "3t",		"3thr"		},
	{ "3x",		"3curses"	},
	{ "3xc",	"3xcurses"	},
	{ "3xn",	"3xnet"		},
	{ NULL,		NULL		}
};

struct suffix {
	char *ds;
	char *fs;
};

/*
 * Flags that control behavior of build_manpath()
 *
 *   BMP_ISPATH 		pathv is a vector constructed from PATH.
 *                		Perform appropriate path translations for
 * 				manpath.
 *   BMP_APPEND_DEFMANDIR	Add DEFMANDIR to the end if it hasn't
 *				already appeared earlier.
 *   BMP_FALLBACK_DEFMANDIR	Append /usr/share/man only if no other
 *				manpath (including derived from PATH)
 * 				elements are valid.
 */
#define	BMP_ISPATH		1
#define	BMP_APPEND_DEFMANDIR	2
#define	BMP_FALLBACK_DEFMANDIR	4

/*
 * When doing equality comparisons of directories, device and inode
 * comparisons are done.  The secnode and dupnode structures are used
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
 * man directory.
 */
static struct pathmap {
	char	*bindir;
	char	*mandir;
	dev_t	dev;
	ino_t	ino;
} bintoman[] = {
	{ "/sbin",		"/usr/share/man,1m",		0, 0 },
	{ "/usr/sbin",		"/usr/share/man,1m",		0, 0 },
	{ "/usr/ucb",		"/usr/share/man,1b",		0, 0 },
	{ "/usr/bin",		"/usr/share/man,1,1m,1s,1t,1c", 0, 0 },
	{ "/usr/xpg4/bin",	"/usr/share/man,1",		0, 0 },
	{ "/usr/xpg6/bin",	"/usr/share/man,1",		0, 0 },
	{ NULL,			NULL,				0, 0 }
};

struct man_node {
	char		*path;		/* mandir path */
	char		**secv;		/* submandir suffices */
	int		defsrch;	/* hint for man -p */
	int		frompath;	/* hint for man -d */
	struct man_node *next;
};

static int	all = 0;
static int	apropos = 0;
static int	debug = 0;
static int	found = 0;
static int	list = 0;
static int	makewhatis = 0;
static int	printmp = 0;
static int	sargs = 0;
static int	psoutput = 0;
static int	lintout = 0;
static int	whatis = 0;
static int	makewhatishere = 0;

static char	*mansec;
static char	*pager = NULL;

static char	*addlocale(char *);
static struct man_node *build_manpath(char **, int);
static void	do_makewhatis(struct man_node *);
static char	*check_config(char *);
static int	cmp(const void *, const void *);
static int	dupcheck(struct man_node *, struct dupnode **);
static int	format(char *, char *, char *, char *);
static void	free_dupnode(struct dupnode *);
static void	free_manp(struct man_node *manp);
static void	freev(char **);
static void	fullpaths(struct man_node **);
static void	get_all_sect(struct man_node *);
static int	getdirs(char *, char ***, int);
static void	getpath(struct man_node *, char **);
static void	getsect(struct man_node *, char **);
static void	init_bintoman(void);
static void	lower(char *);
static void	mandir(char **, char *, char *, int);
static int	manual(struct man_node *, char *);
static char	*map_section(char *, char *);
static char	*path_to_manpath(char *);
static void	print_manpath(struct man_node *);
static void	search_whatis(char *, char *);
static int	searchdir(char *, char *, char *);
static void	sortdir(DIR *, char ***);
static char	**split(char *, char);
static void	usage_man(void);
static void	usage_whatapro(void);
static void	usage_catman(void);
static void	usage_makewhatis(void);
static void	whatapro(struct man_node *, char *);

static char	language[MAXPATHLEN]; 	/* LC_MESSAGES */
static char	localedir[MAXPATHLEN];	/* locale specific path component */

static char	*newsection = NULL;

static int	manwidth = 0;

extern const char	*__progname;

int
main(int argc, char **argv)
{
	int		c, i;
	char		**pathv;
	char		*manpath = NULL;
	static struct man_node *mandirs = NULL;
	int		bmp_flags = 0;
	int		ret = 0;
	char		*opts;
	char		*mwstr;
	int		catman = 0;

	(void) setlocale(LC_ALL, "");
	(void) strcpy(language, setlocale(LC_MESSAGES, (char *)NULL));
	if (strcmp("C", language) != 0)
		(void) strlcpy(localedir, language, MAXPATHLEN);

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (strcmp(__progname, "apropos") == 0) {
		apropos++;
		opts = "M:ds:";
	} else if (strcmp(__progname, "whatis") == 0) {
		apropos++;
		whatis++;
		opts = "M:ds:";
	} else if (strcmp(__progname, "catman") == 0) {
		catman++;
		makewhatis++;
		opts = "P:M:w";
	} else if (strcmp(__progname, "makewhatis") == 0) {
		makewhatis++;
		makewhatishere++;
		manpath = ".";
		opts = "";
	} else {
		opts = "FM:P:T:adfklprs:tw";
		if (argc > 1 && strcmp(argv[1], "-") == 0) {
			pager = "cat";
			optind++;
		}
	}

	opterr = 0;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 'M':	/* Respecify path for man pages */
			manpath = optarg;
			break;
		case 'a':
			all++;
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			whatis++;
			/*FALLTHROUGH*/
		case 'k':
			apropos++;
			break;
		case 'l':
			list++;
			all++;
			break;
		case 'p':
			printmp++;
			break;
		case 's':
			mansec = optarg;
			sargs++;
			break;
		case 'r':
			lintout++;
			break;
		case 't':
			psoutput++;
			break;
		case 'T':
		case 'P':
		case 'F':
			/* legacy options, compatibility only and ignored */
			break;
		case 'w':
			makewhatis++;
			break;
		case '?':
		default:
			if (apropos)
				usage_whatapro();
			else if (catman)
				usage_catman();
			else if (makewhatishere)
				usage_makewhatis();
			else
				usage_man();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		if (apropos) {
			(void) fprintf(stderr, gettext("%s what?\n"),
			    __progname);
			exit(1);
		} else if (!printmp && !makewhatis) {
			(void) fprintf(stderr,
			    gettext("What manual page do you want?\n"));
			exit(1);
		}
	}

	init_bintoman();
	if (manpath == NULL && (manpath = getenv("MANPATH")) == NULL) {
		if ((manpath = getenv("PATH")) != NULL)
			bmp_flags = BMP_ISPATH | BMP_APPEND_DEFMANDIR;
		else
			manpath = DEFMANDIR;
	}
	pathv = split(manpath, ':');
	mandirs = build_manpath(pathv, bmp_flags);
	freev(pathv);
	fullpaths(&mandirs);

	if (makewhatis) {
		do_makewhatis(mandirs);
		exit(0);
	}

	if (printmp) {
		print_manpath(mandirs);
		exit(0);
	}

	/* Collect environment information */
	if (isatty(STDOUT_FILENO) && (mwstr = getenv("MANWIDTH")) != NULL &&
	    *mwstr != '\0') {
		if (strcasecmp(mwstr, "tty") == 0) {
			struct winsize	ws;

			if (ioctl(0, TIOCGWINSZ, &ws) != 0)
				warn("TIOCGWINSZ");
			else
				manwidth = ws.ws_col;
		} else {
			manwidth = (int)strtol(mwstr, (char **)NULL, 10);
			if (manwidth < 0)
				manwidth = 0;
		}
	}
	if (manwidth != 0) {
		DPRINTF("-- Using non-standard page width: %d\n", manwidth);
	}

	if (pager == NULL) {
		if ((pager = getenv("PAGER")) == NULL || *pager == '\0')
			pager = PAGER;
	}
	DPRINTF("-- Using pager: %s\n", pager);

	for (i = 0; i < argc; i++) {
		char		*cmd;
		static struct man_node *mp;
		char		*pv[2];

		/*
		 * If full path to command specified, customize
		 * the manpath accordingly.
		 */
		if ((cmd = strrchr(argv[i], '/')) != NULL) {
			*cmd = '\0';
			if ((pv[0] = strdup(argv[i])) == NULL)
				err(1, "strdup");
			pv[1] = NULL;
			*cmd = '/';
			mp = build_manpath(pv,
			    BMP_ISPATH | BMP_FALLBACK_DEFMANDIR);
		} else {
			mp = mandirs;
		}

		if (apropos)
			whatapro(mp, argv[i]);
		else
			ret += manual(mp, argv[i]);

		if (mp != NULL && mp != mandirs) {
			free(pv[0]);
			free_manp(mp);
		}
	}

	return (ret == 0 ? 0 : 1);
}

/*
 * This routine builds the manpage structure from MANPATH or PATH,
 * depending on flags.  See BMP_* definitions above for valid
 * flags.
 */
static struct man_node *
build_manpath(char **pathv, int flags)
{
	struct man_node *manpage = NULL;
	struct man_node *currp = NULL;
	struct man_node *lastp = NULL;
	char		**p;
	char		**q;
	char		*mand = NULL;
	char		*mandir = DEFMANDIR;
	int		s;
	struct dupnode	*didup = NULL;
	struct stat	sb;

	s = sizeof (struct man_node);
	for (p = pathv; *p != NULL; ) {
		if (flags & BMP_ISPATH) {
			if ((mand = path_to_manpath(*p)) == NULL)
				goto next;
			free(*p);
			*p = mand;
		}
		q = split(*p, ',');
		if (stat(q[0], &sb) != 0 || (sb.st_mode & S_IFDIR) == 0) {
			freev(q);
			goto next;
		}

		if (access(q[0], R_OK | X_OK) == 0) {
			/*
			 * Some element exists.  Do not append DEFMANDIR as a
			 * fallback.
			 */
			flags &= ~BMP_FALLBACK_DEFMANDIR;

			if ((currp = (struct man_node *)calloc(1, s)) == NULL)
				err(1, "calloc");

			currp->frompath = (flags & BMP_ISPATH);

			if (manpage == NULL)
				lastp = manpage = currp;

			getpath(currp, p);
			getsect(currp, p);

			/*
			 * If there are no new elements in this path,
			 * do not add it to the manpage list.
			 */
			if (dupcheck(currp, &didup) != 0) {
				freev(currp->secv);
				free(currp);
			} else {
				currp->next = NULL;
				if (currp != manpage)
					lastp->next = currp;
				lastp = currp;
			}
		}
		freev(q);
next:
		/*
		 * Special handling of appending DEFMANDIR. After all pathv
		 * elements have been processed, append DEFMANDIR if needed.
		 */
		if (p == &mandir)
			break;
		p++;
		if (*p != NULL)
			continue;
		if (flags & (BMP_APPEND_DEFMANDIR | BMP_FALLBACK_DEFMANDIR)) {
			p = &mandir;
			flags &= ~BMP_ISPATH;
		}
	}

	free_dupnode(didup);

	return (manpage);
}

/*
 * Store the mandir path into the manp structure.
 */
static void
getpath(struct man_node *manp, char **pv)
{
	char	*s = *pv;
	int	i = 0;

	while (*s != '\0' && *s != ',')
		i++, s++;

	if ((manp->path = (char *)malloc(i + 1)) == NULL)
		err(1, "malloc");
	(void) strlcpy(manp->path, *pv, i + 1);
}

/*
 * Store the mandir's corresponding sections (submandir
 * directories) into the manp structure.
 */
static void
getsect(struct man_node *manp, char **pv)
{
	char	*sections;
	char	**sectp;

	/* Just store all sections when doing makewhatis or apropos/whatis */
	if (makewhatis || apropos) {
		manp->defsrch = 1;
		DPRINTF("-- Adding %s\n", manp->path);
		manp->secv = NULL;
		get_all_sect(manp);
	} else if (sargs) {
		DPRINTF("-- Adding %s: sections=%s\n", manp->path, mansec);
		manp->secv = split(mansec, ',');
		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);
	} else if ((sections = strchr(*pv, ',')) != NULL) {
		sections++;
		DPRINTF("-- Adding %s: sections=%s\n", manp->path, sections);
		manp->secv = split(sections, ',');
		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);
		if (*manp->secv == NULL)
			get_all_sect(manp);
	} else if ((sections = check_config(*pv)) != NULL) {
		manp->defsrch = 1;
		DPRINTF("-- Adding %s: sections=%s (from %s)\n", manp->path,
		    sections, CONFIG);
		manp->secv = split(sections, ',');
		for (sectp = manp->secv; *sectp; sectp++)
			lower(*sectp);
		if (*manp->secv == NULL)
			get_all_sect(manp);
	} else {
		manp->defsrch = 1;
		DPRINTF("-- Adding %s: default search order\n", manp->path);
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
	DIR	*dp;
	char	**dirv;
	char	**dv;
	char	**p;
	char	*prev = NULL;
	char 	*tmp = NULL;
	int	maxentries = MAXTOKENS;
	int	entries = 0;

	if ((dp = opendir(manp->path)) == 0)
		return;

	sortdir(dp, &dirv);

	(void) closedir(dp);

	if (manp->secv == NULL) {
		if ((manp->secv = malloc(maxentries * sizeof (char *))) == NULL)
			err(1, "malloc");
	}

	for (dv = dirv, p = manp->secv; *dv; dv++) {
		if (strcmp(*dv, CONFIG) == 0) {
			free(*dv);
			continue;
		}

		free(tmp);
		if ((tmp = strdup(*dv + 3)) == NULL)
			err(1, "strdup");

		if (prev != NULL && strcmp(prev, tmp) == 0) {
			free(*dv);
			continue;
		}

		free(prev);
		if ((prev = strdup(*dv + 3)) == NULL)
			err(1, "strdup");

		if ((*p = strdup(*dv + 3)) == NULL)
			err(1, "strdup");

		p++; entries++;

		if (entries == maxentries) {
			maxentries += MAXTOKENS;
			if ((manp->secv = realloc(manp->secv,
			    sizeof (char *) * maxentries)) == NULL)
				err(1, "realloc");
			p = manp->secv + entries;
		}
		free(*dv);
	}
	free(tmp);
	free(prev);
	*p = NULL;
	free(dirv);
}

/*
 * Build whatis databases.
 */
static void
do_makewhatis(struct man_node *manp)
{
	struct man_node *p;
	char		*ldir;

	for (p = manp; p != NULL; p = p->next) {
		ldir = addlocale(p->path);
		if (*localedir != '\0' && getdirs(ldir, NULL, 0) > 0)
			mwpath(ldir);
		free(ldir);
		mwpath(p->path);
	}
}

/*
 * Count mandirs under the given manpath
 */
static int
getdirs(char *path, char ***dirv, int flag)
{
	DIR		*dp;
	struct dirent	*d;
	int		n = 0;
	int		maxentries = MAXDIRS;
	char		**dv = NULL;

	if ((dp = opendir(path)) == NULL)
		return (0);

	if (flag) {
		if ((*dirv = malloc(sizeof (char *) *
		    maxentries)) == NULL)
			err(1, "malloc");
		dv = *dirv;
	}
	while ((d = readdir(dp))) {
		if (strncmp(d->d_name, "man", 3) != 0)
			continue;
		n++;

		if (flag) {
			if ((*dv = strdup(d->d_name + 3)) == NULL)
				err(1, "strdup");
			dv++;
			if ((dv - *dirv) == maxentries) {
				int	entries = maxentries;

				maxentries += MAXTOKENS;
				if ((*dirv = realloc(*dirv,
				    sizeof (char *) * maxentries)) == NULL)
					err(1, "realloc");
				dv = *dirv + entries;
			}
		}
	}

	(void) closedir(dp);
	return (n);
}


/*
 * Find matching whatis or apropos entries.
 */
static void
whatapro(struct man_node *manp, char *word)
{
	char		whatpath[MAXPATHLEN];
	struct man_node *b;
	char		*ldir;

	for (b = manp; b != NULL; b = b->next) {
		if (*localedir != '\0') {
			ldir = addlocale(b->path);
			if (getdirs(ldir, NULL, 0) != 0) {
				(void) snprintf(whatpath, sizeof (whatpath),
				    "%s/%s", ldir, WHATIS);
				search_whatis(whatpath, word);
			}
			free(ldir);
		}
		(void) snprintf(whatpath, sizeof (whatpath), "%s/%s", b->path,
		    WHATIS);
		search_whatis(whatpath, word);
	}
}

static void
search_whatis(char *whatpath, char *word)
{
	FILE		*fp;
	char		*line = NULL;
	size_t		linecap = 0;
	char		*pkwd;
	regex_t		preg;
	char		**ss = NULL;
	char		s[MAXNAMELEN];
	int		i;

	if ((fp = fopen(whatpath, "r")) == NULL) {
		perror(whatpath);
		return;
	}

	DPRINTF("-- Found %s: %s\n", WHATIS, whatpath);

	/* Build keyword regex */
	if (asprintf(&pkwd, "%s%s%s", (whatis) ? "\\<" : "",
	    word, (whatis) ? "\\>" : "") == -1)
		err(1, "asprintf");

	if (regcomp(&preg, pkwd, REG_BASIC | REG_ICASE | REG_NOSUB) != 0)
		err(1, "regcomp");

	if (sargs)
		ss = split(mansec, ',');

	while (getline(&line, &linecap, fp) > 0) {
		if (regexec(&preg, line, 0, NULL, 0) == 0) {
			if (sargs) {
				/* Section-restricted search */
				for (i = 0; ss[i] != NULL; i++) {
					(void) snprintf(s, sizeof (s), "(%s)",
					    ss[i]);
					if (strstr(line, s) != NULL) {
						(void) printf("%s", line);
						break;
					}
				}
			} else {
				(void) printf("%s", line);
			}
		}
	}

	if (ss != NULL)
		freev(ss);
	free(pkwd);
	(void) fclose(fp);
}


/*
 * Split a string by specified separator.
 */
static char **
split(char *s1, char sep)
{
	char	**tokv, **vp;
	char	*mp = s1, *tp;
	int	maxentries = MAXTOKENS;
	int	entries = 0;

	if ((tokv = vp = malloc(maxentries * sizeof (char *))) == NULL)
		err(1, "malloc");

	for (; mp && *mp; mp = tp) {
		tp = strchr(mp, sep);
		if (mp == tp) {
			tp++;
			continue;
		}
		if (tp) {
			size_t	len;

			len = tp - mp;
			if ((*vp = (char *)malloc(sizeof (char) *
			    len + 1)) == NULL)
				err(1, "malloc");
			(void) strncpy(*vp, mp, len);
			*(*vp + len) = '\0';
			tp++;
			vp++;
		} else {
			if ((*vp = strdup(mp)) == NULL)
				err(1, "strdup");
			vp++;
		}
		entries++;
		if (entries == maxentries) {
			maxentries += MAXTOKENS;
			if ((tokv = realloc(tokv,
			    maxentries * sizeof (char *))) == NULL)
				err(1, "realloc");
			vp = tokv + entries;
		}
	}
	*vp = 0;

	return (tokv);
}

/*
 * Free a vector allocated by split()
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
 */
static void
fullpaths(struct man_node **manp_head)
{
	char		*cwd = NULL;
	char		*p;
	int		cwd_gotten = 0;
	struct man_node *manp = *manp_head;
	struct man_node *b;
	struct man_node *prev = NULL;

	for (b = manp; b != NULL; b = b->next) {
		if (*(b->path) == '/') {
			prev = b;
			continue;
		}

		if (!cwd_gotten) {
			cwd = getcwd(NULL, MAXPATHLEN);
			cwd_gotten = 1;
		}

		if (cwd) {
			/* Relative manpath with cwd: make absolute */
			if (asprintf(&p, "%s/%s", cwd, b->path) == -1)
				err(1, "asprintf");
			free(b->path);
			b->path = p;
		} else {
			/* Relative manpath but no cwd: omit path entry */
			if (prev)
				prev->next = b->next;
			else
				*manp_head = b->next;

			free_manp(b);
		}
	}
	free(cwd);
}

/*
 * Free a man_node structure and its contents
 */
static void
free_manp(struct man_node *manp)
{
	char	**p;

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
 * Map (in place) to lower case.
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
 * Compare function for qsort().
 * Sort first by section, then by prefix.
 */
static int
cmp(const void *arg1, const void *arg2)
{
	int	n;
	char	**p1 = (char **)arg1;
	char	**p2 = (char **)arg2;

	/* By section */
	if ((n = strcmp(*p1 + 3, *p2 + 3)) != 0)
		return (n);

	/* By prefix reversed */
	return (strncmp(*p2, *p1, 3));
}


/*
 * Find a manpage.
 */
static int
manual(struct man_node *manp, char *name)
{
	struct man_node *p;
	struct man_node *local;
	int		ndirs = 0;
	char		*ldir;
	char		*ldirs[2];
	char		*fullname = name;
	char		*slash;

	if ((slash = strrchr(name, '/')) != NULL)
		name = slash + 1;

	/* For each path in MANPATH */
	found = 0;

	for (p = manp; p != NULL; p = p->next) {
		DPRINTF("-- Searching mandir: %s\n", p->path);

		if (*localedir != '\0') {
			ldir = addlocale(p->path);
			ndirs = getdirs(ldir, NULL, 0);
			if (ndirs != 0) {
				ldirs[0] = ldir;
				ldirs[1] = NULL;
				local = build_manpath(ldirs, 0);
				DPRINTF("-- Locale specific subdir: %s\n",
				    ldir);
				mandir(local->secv, ldir, name, 1);
				free_manp(local);
			}
			free(ldir);
		}

		/*
		 * Locale mandir not valid, man page in locale
		 * mandir not found, or -a option present
		 */
		if (ndirs == 0 || !found || all)
			mandir(p->secv, p->path, name, 0);

		if (found && !all)
			break;
	}

	if (!found) {
		if (sargs) {
			(void) fprintf(stderr, gettext(
			    "No manual entry for %s in section(s) %s\n"),
			    fullname, mansec);
		} else {
			(void) fprintf(stderr,
			    gettext("No manual entry for %s\n"), fullname);
		}

	}

	return (!found);
}


/*
 * For a specified manual directory, read, store and sort section subdirs.
 * For each section specified, find and search matching subdirs.
 */
static void
mandir(char **secv, char *path, char *name, int lspec)
{
	DIR	*dp;
	char	**dirv;
	char	**dv, **pdv;
	int	len, dslen;

	if ((dp = opendir(path)) == NULL)
		return;

	if (lspec)
		DPRINTF("-- Searching mandir: %s\n", path);

	sortdir(dp, &dirv);

	/* Search in the order specified by MANSECTS */
	for (; *secv; secv++) {
		len = strlen(*secv);
		for (dv = dirv; *dv; dv++) {
			dslen = strlen(*dv + 3);
			if (dslen > len)
				len = dslen;
			if (**secv == '\\') {
				if (strcmp(*secv + 1, *dv + 3) != 0)
					continue;
			} else if (strncasecmp(*secv, *dv + 3, len) != 0) {
				if (!all &&
				    (newsection = map_section(*secv, path))
				    == NULL) {
					continue;
				}
				if (newsection == NULL)
					newsection = "";
				if (strncmp(newsection, *dv + 3, len) != 0) {
					continue;
				}
			}

			if (searchdir(path, *dv, name) == 0)
				continue;

			if (!all) {
				pdv = dirv;
				while (*pdv) {
					free(*pdv);
					pdv++;
				}
				(void) closedir(dp);
				free(dirv);
				return;
			}

			if (all && **dv == 'm' && *(dv + 1) &&
			    strcmp(*(dv + 1) + 3, *dv + 3) == 0)
					dv++;
		}
	}
	pdv = dirv;
	while (*pdv != NULL) {
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
	struct dirent	*d;
	char		**dv;
	int		maxentries = MAXDIRS;
	int		entries = 0;

	if ((dv = *dirv = malloc(sizeof (char *) *
	    maxentries)) == NULL)
		err(1, "malloc");
	dv = *dirv;

	while ((d = readdir(dp))) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;

		if (strncmp(d->d_name, "man", 3) == 0 ||
		    strncmp(d->d_name, "cat", 3) == 0) {
			if ((*dv = strdup(d->d_name)) == NULL)
				err(1, "strdup");
			dv++;
			entries++;
			if (entries == maxentries) {
				maxentries += MAXDIRS;
				if ((*dirv = realloc(*dirv,
				    sizeof (char *) * maxentries)) == NULL)
					err(1, "realloc");
				dv = *dirv + entries;
			}
		}
	}
	*dv = 0;

	qsort((void *)*dirv, dv - *dirv, sizeof (char *), cmp);

}


/*
 * Search a section subdir for a given manpage.
 */
static int
searchdir(char *path, char *dir, char *name)
{
	DIR		*sdp;
	struct dirent	*sd;
	char		sectpath[MAXPATHLEN];
	char		file[MAXNAMLEN];
	char		dname[MAXPATHLEN];
	char		*last;
	int		nlen;

	(void) snprintf(sectpath, sizeof (sectpath), "%s/%s", path, dir);
	(void) snprintf(file, sizeof (file), "%s.", name);

	if ((sdp = opendir(sectpath)) == NULL)
		return (0);

	while ((sd = readdir(sdp))) {
		char	*pname;

		if ((pname = strdup(sd->d_name)) == NULL)
			err(1, "strdup");
		if ((last = strrchr(pname, '.')) != NULL &&
		    (strcmp(last, ".gz") == 0 || strcmp(last, ".bz2") == 0))
			*last = '\0';
		last = strrchr(pname, '.');
		nlen = last - pname;
		(void) snprintf(dname, sizeof (dname), "%.*s.", nlen, pname);
		if (strcmp(dname, file) == 0 ||
		    strcmp(pname, name) == 0) {
			(void) format(path, dir, name, sd->d_name);
			(void) closedir(sdp);
			free(pname);
			return (1);
		}
		free(pname);
	}
	(void) closedir(sdp);

	return (0);
}

/*
 * Check the hash table of old directory names to see if there is a
 * new directory name.
 */
static char *
map_section(char *section, char *path)
{
	int	i;
	char	fullpath[MAXPATHLEN];

	if (list)  /* -l option fall through */
		return (NULL);

	for (i = 0; map[i].new_name != NULL; i++) {
		if (strcmp(section, map[i].old_name) == 0) {
			(void) snprintf(fullpath, sizeof (fullpath),
			    "%s/man%s", path, map[i].new_name);
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
 * Format the manpage.
 */
static int
format(char *path, char *dir, char *name, char *pg)
{
	char		manpname[MAXPATHLEN], catpname[MAXPATHLEN];
	char		cmdbuf[BUFSIZ], tmpbuf[BUFSIZ];
	char		*cattool;
	struct stat	sbman, sbcat;

	found++;

	if (list) {
		(void) printf(gettext("%s(%s)\t-M %s\n"), name, dir + 3, path);
		return (-1);
	}

	(void) snprintf(manpname, sizeof (manpname), "%s/man%s/%s", path,
	    dir + 3, pg);
	(void) snprintf(catpname, sizeof (catpname), "%s/cat%s/%s", path,
	    dir + 3, pg);

	/* Can't do PS output if manpage doesn't exist */
	if (stat(manpname, &sbman) != 0 && (psoutput|lintout))
		return (-1);

	/*
	 * If both manpage and catpage do not exist, manpname is
	 * broken symlink, most likely.
	 */
	if (stat(catpname, &sbcat) != 0 && stat(manpname, &sbman) != 0)
		err(1, "%s", manpname);

	/* Setup cattool */
	if (fnmatch("*.gz", manpname, 0) == 0)
		cattool = "gzcat";
	else if (fnmatch("*.bz2", manpname, 0) == 0)
		cattool = "bzcat";
	else
		cattool = "cat";

	if (psoutput) {
		(void) snprintf(cmdbuf, BUFSIZ,
		    "cd %s; %s %s | mandoc -Tps | lp -Tpostscript",
		    path, cattool, manpname);
		DPRINTF("-- Using manpage: %s\n", manpname);
		goto cmd;
	} else if (lintout) {
		(void) snprintf(cmdbuf, BUFSIZ,
		    "cd %s; %s %s | mandoc -Tlint",
		    path, cattool, manpname);
		DPRINTF("-- Linting manpage: %s\n", manpname);
		goto cmd;
	}

	/*
	 * Output catpage if:
	 * - manpage doesn't exist
	 * - output width is standard and catpage is recent enough
	 */
	if (stat(manpname, &sbman) != 0 || (manwidth == 0 &&
	    stat(catpname, &sbcat) == 0 && sbcat.st_mtime >= sbman.st_mtime)) {
		DPRINTF("-- Using catpage: %s\n", catpname);
		(void) snprintf(cmdbuf, BUFSIZ, "%s %s", pager, catpname);
		goto cmd;
	}

	DPRINTF("-- Using manpage: %s\n", manpname);
	if (manwidth > 0)
		(void) snprintf(tmpbuf, BUFSIZ, "-Owidth=%d ", manwidth);
	(void) snprintf(cmdbuf, BUFSIZ, "cd %s; %s %s | mandoc %s| %s",
	    path, cattool, manpname, (manwidth > 0) ? tmpbuf : "", pager);

cmd:
	DPRINTF("-- Command: %s\n", cmdbuf);

	if (!debug)
		return (system(cmdbuf) == 0);
	else
		return (0);
}

/*
 * Add <localedir> to the path.
 */
static char *
addlocale(char *path)
{
	char	*tmp;

	if (asprintf(&tmp, "%s/%s", path, localedir) == -1)
		err(1, "asprintf");

	return (tmp);
}

/*
 * Get the order of sections from man.cf.
 */
static char *
check_config(char *path)
{
	FILE		*fp;
	char		*rc = NULL;
	char		*sect = NULL;
	char		fname[MAXPATHLEN];
	char		*line = NULL;
	char		*nl;
	size_t		linecap = 0;

	(void) snprintf(fname, MAXPATHLEN, "%s/%s", path, CONFIG);

	if ((fp = fopen(fname, "r")) == NULL)
		return (NULL);

	while (getline(&line, &linecap, fp) > 0) {
		if ((rc = strstr(line, "MANSECTS=")) != NULL)
			break;
	}

	(void) fclose(fp);

	if (rc != NULL) {
		if ((nl = strchr(rc, '\n')) != NULL)
			*nl = '\0';
		sect = strchr(rc, '=') + 1;
	}

	return (sect);
}

/*
 * Initialize the bintoman array with appropriate device and inode info.
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
 * If a duplicate is found, return 1.
 * If a duplicate is not found, add it to the dupnode list and return 0.
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

	/* If the path doesn't exist, treat it as a duplicate */
	if (stat(mnp->path, &sb) != 0)
		return (1);

	/* If no sections were found in the man dir, treat it as duplicate */
	if (mnp->secv == NULL)
		return (1);

	/*
	 * Find the dupnode structure for the previous time this directory
	 * was looked at.  Device and inode numbers are compared so that
	 * directories that are reached via different paths (e.g. /usr/man and
	 * /usr/share/man) are treated as equivalent.
	 */
	for (curdnp = *dnp; curdnp != NULL; curdnp = curdnp->next) {
		if (curdnp->dev == sb.st_dev && curdnp->ino == sb.st_ino)
			break;
	}

	/*
	 * First time this directory has been seen. Add a new node to the
	 * head of the list. Since all entries are guaranteed to be unique
	 * copy all sections to new node.
	 */
	if (curdnp == NULL) {
		if ((curdnp = calloc(1, sizeof (struct dupnode))) == NULL)
			err(1, "calloc");
		for (i = 0; mnp->secv[i] != NULL; i++) {
			if ((cursnp = calloc(1, sizeof (struct secnode)))
			    == NULL)
				err(1, "calloc");
			cursnp->next = curdnp->secl;
			curdnp->secl = cursnp;
			if ((cursnp->secp = strdup(mnp->secv[i])) == NULL)
				err(1, "strdup");
		}
		curdnp->dev = sb.st_dev;
		curdnp->ino = sb.st_ino;
		curdnp->next = *dnp;
		*dnp = curdnp;
		return (0);
	}

	/*
	 * Traverse the section vector in the man_node and the section list
	 * in dupnode cache to eliminate all duplicates from man_node.
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
		if ((cursnp = calloc(1, sizeof (struct secnode))) == NULL)
			err(1, "calloc");
		cursnp->next = curdnp->secl;
		curdnp->secl = cursnp;
		if ((cursnp->secp = strdup(mnp->secv[i])) == NULL)
			err(1, "strdup");
		rv = 0;
	}

	return (rv);
}

/*
 * Given a bindir, return corresponding mandir.
 */
static char *
path_to_manpath(char *bindir)
{
	char		*mand, *p;
	int		i;
	struct stat	sb;

	/* First look for known translations for specific bin paths */
	if (stat(bindir, &sb) != 0) {
		return (NULL);
	}
	for (i = 0; bintoman[i].bindir != NULL; i++) {
		if (sb.st_dev == bintoman[i].dev &&
		    sb.st_ino == bintoman[i].ino) {
			if ((mand = strdup(bintoman[i].mandir)) == NULL)
				err(1, "strdup");
			if ((p = strchr(mand, ',')) != NULL)
				*p = '\0';
			if (stat(mand, &sb) != 0) {
				free(mand);
				return (NULL);
			}
			if (p != NULL)
				*p = ',';
			return (mand);
		}
	}

	/*
	 * No specific translation found.  Try `dirname $bindir`/share/man
	 * and `dirname $bindir`/man
	 */
	if ((mand = malloc(MAXPATHLEN)) == NULL)
		err(1, "malloc");
	if (strlcpy(mand, bindir, MAXPATHLEN) >= MAXPATHLEN) {
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

	if (strlcat(mand, "/share/man", MAXPATHLEN) >= MAXPATHLEN) {
		free(mand);
		return (NULL);
	}

	if ((stat(mand, &sb) == 0) && S_ISDIR(sb.st_mode)) {
		return (mand);
	}

	/*
	 * Strip the /share/man off and try /man
	 */
	*p = '\0';
	if (strlcat(mand, "/man", MAXPATHLEN) >= MAXPATHLEN) {
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
 * Free a linked list of dupnode structs.
 */
void
free_dupnode(struct dupnode *dnp)
{
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
 * Print manp linked list to stdout.
 */
void
print_manpath(struct man_node *manp)
{
	char	colon[2] = "\0\0";
	char	**secp;

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
		if (manp->defsrch != 0)
			continue;

		for (secp = manp->secv; *secp != NULL; secp++) {
			/*
			 * Section deduplication may have eliminated some
			 * sections from the vector. Avoid displaying this
			 * detail which would appear as ",," in output
			 */
			if ((*secp)[0] != '\0')
				(void) printf(",%s", *secp);
		}
	}
	(void) printf("\n");
}

static void
usage_man(void)
{

	(void) fprintf(stderr, gettext(
"usage: man [-alptw] [-M path] [-s section] name ...\n"
"       man [-M path] [-s section] -k keyword ...\n"
"       man [-M path] [-s section] -f keyword ...\n"));

	exit(1);
}

static void
usage_whatapro(void)
{

	(void) fprintf(stderr, gettext(
"usage: %s [-M path] [-s section] keyword ...\n"),
	    whatis ? "whatis" : "apropos");

	exit(1);
}

static void
usage_catman(void)
{
	(void) fprintf(stderr, gettext(
"usage: catman [-M path] [-w]\n"));

	exit(1);
}

static void
usage_makewhatis(void)
{
	(void) fprintf(stderr, gettext("usage: makewhatis\n"));

	exit(1);
}
