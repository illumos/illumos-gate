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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013 Andrew Stormont.  All rights reserved.
 */


/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*	Parts of this product may be derived from		*/
/*	Mortice Kern Systems Inc. and Berkeley 4.3 BSD systems.	*/
/*	licensed from  Mortice Kern Systems Inc. and 		*/
/*	the University of California.				*/

/*
 * Copyright 1985, 1990 by Mortice Kern Systems Inc.  All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/acl.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <wait.h>
#include <fnmatch.h>
#include <langinfo.h>
#include <ftw.h>
#include <libgen.h>
#include <err.h>
#include <regex.h>
#include "getresponse.h"

#define	A_DAY		(long)(60*60*24)	/* a day full of seconds */
#define	A_MIN		(long)(60)
#define	BLKSIZ		512
#define	round(x, s)	(((x)+(s)-1)&~((s)-1))
#ifndef FTW_SLN
#define	FTW_SLN		7
#endif
#define	LINEBUF_SIZE		LINE_MAX	/* input or output lines */
#define	REMOTE_FS		"/etc/dfs/fstypes"
#define	N_FSTYPES		20
#define	SHELL_MAXARGS		253	/* see doexec() for description */

/*
 * This is the list of operations
 * F_USER and F_GROUP are named to avoid conflict with USER and GROUP defined
 * in sys/acl.h
 */

enum Command
{
	PRINT,
	ACL, AMIN, AND, ATIME, CMIN, CPIO, CSIZE, CTIME, DEPTH, EXEC, F_GROUP,
	F_GROUPACL, F_USER, F_USERACL, FOLLOW, FSTYPE, INAME, INUM, IPATH,
	IREGEX,	LINKS, LOCAL, LPAREN, LS, MAXDEPTH, MINDEPTH, MMIN, MOUNT,
	MTIME, NAME, NCPIO, NEWER, NOGRP, NOT, NOUSER, OK, OR, PATH, PERM,
	PRINT0, PRUNE, REGEX, RPAREN, SIZE, TYPE, VARARGS, XATTR, DELETE
};

enum Type
{
	Unary, Id, Num, Str, Exec, Cpio, Op
};

struct Args
{
	char		name[10];
	enum Command	action;
	enum Type	type;
};

/*
 * Except for pathnames, these are the only legal arguments
 */
static struct Args commands[] =
{
	"!",		NOT,		Op,
	"(",		LPAREN,		Unary,
	")",		RPAREN,		Unary,
	"-a",		AND,		Op,
	"-acl",		ACL,		Unary,
	"-amin",	AMIN,		Num,
	"-and",		AND,		Op,
	"-atime",	ATIME,		Num,
	"-cmin",	CMIN,		Num,
	"-cpio",	CPIO,		Cpio,
	"-ctime",	CTIME,		Num,
	"-depth",	DEPTH,		Unary,
	"-delete",	DELETE,		Unary,
	"-exec",	EXEC,		Exec,
	"-follow",	FOLLOW,		Unary,
	"-fstype",	FSTYPE,		Str,
	"-group",	F_GROUP,	Num,
	"-groupacl",	F_GROUPACL,	Num,
	"-iname",	INAME,		Str,
	"-inum",	INUM,		Num,
	"-ipath",	IPATH,		Str,
	"-iregex",	IREGEX,		Str,
	"-links",	LINKS,		Num,
	"-local",	LOCAL,		Unary,
	"-ls",		LS,		Unary,
	"-maxdepth",	MAXDEPTH,	Num,
	"-mindepth",	MINDEPTH,	Num,
	"-mmin",	MMIN,		Num,
	"-mount",	MOUNT,		Unary,
	"-mtime",	MTIME,		Num,
	"-name",	NAME,		Str,
	"-ncpio",	NCPIO,		Cpio,
	"-newer",	NEWER,		Str,
	"-nogroup",	NOGRP,		Unary,
	"-not",		NOT,		Op,
	"-nouser",	NOUSER,		Unary,
	"-o",		OR,		Op,
	"-ok",		OK,		Exec,
	"-or",		OR,		Op,
	"-path",	PATH,		Str,
	"-perm",	PERM,		Num,
	"-print",	PRINT,		Unary,
	"-print0",	PRINT0,		Unary,
	"-prune",	PRUNE,		Unary,
	"-regex",	REGEX,		Str,
	"-size",	SIZE,		Num,
	"-type",	TYPE,		Num,
	"-user",	F_USER,		Num,
	"-useracl",	F_USERACL,	Num,
	"-xattr",	XATTR,		Unary,
	"-xdev",	MOUNT,		Unary,
	NULL,		0,		0
};

union Item
{
	struct Node	*np;
	struct Arglist	*vp;
	time_t		t;
	char		*cp;
	char		**ap;
	long		l;
	int		i;
	long long	ll;
};

struct Node
{
	struct Node	*next;
	enum Command	action;
	enum Type	type;
	union Item	first;
	union Item	second;
};

/* if no -print, -exec or -ok replace "expression" with "(expression) -print" */
static	struct	Node PRINT_NODE = { 0, PRINT, 0, 0};
static	struct	Node LPAREN_NODE = { 0, LPAREN, 0, 0};


/*
 * Prototype variable size arglist buffer
 */

struct Arglist
{
	struct Arglist	*next;
	char		*end;
	char		*nextstr;
	char		**firstvar;
	char		**nextvar;
	char		*arglist[1];
};


static int		compile();
static int		execute();
static int		doexec(char *, char **, int *);
static int		dodelete(char *, struct stat *, struct FTW *);
static struct Args	*lookup();
static int		ok();
static void		usage(void)	__NORETURN;
static struct Arglist	*varargs();
static int		list();
static char		*getgroup();
static FILE		*cmdopen();
static int		cmdclose();
static char		*getshell();
static void 		init_remote_fs();
static char		*getname();
static int		readmode();
static mode_t		getmode();
static char		*gettail();


static int walkflags = FTW_CHDIR|FTW_PHYS|FTW_ANYERR|FTW_NOLOOP;
static struct Node	*topnode;
static struct Node	*freenode;	/* next free node we may use later */
static char		*cpio[] = { "cpio", "-o", 0 };
static char		*ncpio[] = { "cpio", "-oc", 0 };
static char		*cpiol[] = { "cpio", "-oL", 0 };
static char		*ncpiol[] = { "cpio", "-ocL", 0 };
static time_t		now;
static FILE		*output;
static char		*dummyarg = (char *)-1;
static int		lastval;
static int		varsize;
static struct Arglist	*lastlist;
static char		*cmdname;
static char		*remote_fstypes[N_FSTYPES+1];
static int		fstype_index = 0;
static int		action_expression = 0;	/* -print, -exec, or -ok */
static int		error = 0;
static int		paren_cnt = 0;	/* keeps track of parentheses */
static int		Eflag = 0;
static int		hflag = 0;
static int		lflag = 0;
/* set when doexec()-invoked utility returns non-zero */
static int		exec_exitcode = 0;
static regex_t		*preg = NULL;
static int		npreg = 0;
static int		mindepth = -1, maxdepth = -1;
extern char		**environ;

int
main(int argc, char **argv)
{
	char *cp;
	int c;
	int paths;
	char *cwdpath;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	cmdname = argv[0];
	if (time(&now) == (time_t)(-1)) {
		(void) fprintf(stderr, gettext("%s: time() %s\n"),
		    cmdname, strerror(errno));
		exit(1);
	}
	while ((c = getopt(argc, argv, "EHL")) != -1) {
		switch (c) {
		case 'E':
			Eflag = 1;
			break;
		case 'H':
			hflag = 1;
			lflag = 0;
			break;
		case 'L':
			hflag = 0;
			lflag = 1;
			break;
		case '?':
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		(void) fprintf(stderr,
		    gettext("%s: insufficient number of arguments\n"), cmdname);
		usage();
	}

	for (paths = 0; (cp = argv[paths]) != 0; ++paths) {
		if (*cp == '-')
			break;
		else if ((*cp == '!' || *cp == '(') && *(cp+1) == 0)
			break;
	}

	if (paths == 0) /* no path-list */
		usage();

	output = stdout;

	/* lflag is the same as -follow */
	if (lflag)
		walkflags &= ~FTW_PHYS;

	/* allocate enough space for the compiler */
	topnode = malloc((argc + 1) * sizeof (struct Node));
	(void) memset(topnode, 0, (argc + 1) * sizeof (struct Node));

	if (compile(argv + paths, topnode, &action_expression) == 0) {
		/* no expression, default to -print */
		(void) memcpy(topnode, &PRINT_NODE, sizeof (struct Node));
	} else if (!action_expression) {
		/*
		 * if no action expression, insert an LPAREN node above topnode,
		 * with a PRINT node as its next node
		 */
		struct Node *savenode;

		if (freenode == NULL) {
			(void) fprintf(stderr, gettext("%s: can't append -print"
			    " implicitly; try explicit -print option\n"),
			    cmdname);
			exit(1);
		}
		savenode = topnode;
		topnode = freenode++;
		(void) memcpy(topnode, &LPAREN_NODE, sizeof (struct Node));
		topnode->next = freenode;
		topnode->first.np = savenode;
		(void) memcpy(topnode->next, &PRINT_NODE, sizeof (struct Node));
	}

	while (paths--) {
		char *curpath;
		struct stat sb;

		curpath = *(argv++);

		/*
		 * If -H is specified, it means we walk the first
		 * level (pathname on command line) logically, following
		 * symlinks, but lower levels are walked physically.
		 * We use our own secret interface to nftw() to change
		 * the from stat to lstat after the top level is walked.
		 */
		if (hflag) {
			if (stat(curpath, &sb) < 0 && errno == ENOENT)
				walkflags &= ~FTW_HOPTION;
			else
				walkflags |= FTW_HOPTION;
		}

		/*
		 * We need this check as nftw needs a CWD and we have no
		 * way of returning back from that code with a meaningful
		 * error related to this
		 */
		if ((cwdpath = getcwd(NULL, PATH_MAX)) == NULL) {
			if ((errno == EACCES) && (walkflags & FTW_CHDIR)) {
				/*
				 * A directory above cwd is inaccessible,
				 * so don't do chdir(2)s. Slower, but at least
				 * it works.
				 */
				walkflags &= ~FTW_CHDIR;
				free(cwdpath);
			} else {
				(void) fprintf(stderr,
				    gettext("%s : cannot get the current "
				    "working directory\n"), cmdname);
				exit(1);
			}
		} else
			free(cwdpath);


		if (nftw(curpath, execute, 1000, walkflags)) {
			(void) fprintf(stderr,
			    gettext("%s: cannot open %s: %s\n"),
			    cmdname, curpath, strerror(errno));
			error = 1;
		}

	}

	/* execute any remaining variable length lists */
	while (lastlist) {
		if (lastlist->end != lastlist->nextstr) {
			*lastlist->nextvar = 0;
			(void) doexec((char *)0, lastlist->arglist,
			    &exec_exitcode);
		}
		lastlist = lastlist->next;
	}
	if (output != stdout)
		return (cmdclose(output));
	return ((exec_exitcode != 0) ? exec_exitcode : error);
}

/*
 * compile the arguments
 */

static int
compile(argv, np, actionp)
char **argv;
struct Node *np;
int *actionp;
{
	char *b;
	char **av;
	struct Node *oldnp = topnode;
	struct Args *argp;
	char **com;
	int i;
	enum Command wasop = PRINT;

	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(1);
	}

	for (av = argv; *av && (argp = lookup(*av)); av++) {
		np->next = 0;
		np->action = argp->action;
		np->type = argp->type;
		np->second.i = 0;
		if (argp->type == Op) {
			if (wasop == NOT || (wasop && np->action != NOT)) {
				(void) fprintf(stderr,
				gettext("%s: operand follows operand\n"),
						cmdname);
				exit(1);
			}
			if (np->action != NOT && oldnp == 0)
				goto err;
			wasop = argp->action;
		} else {
			wasop = PRINT;
			if (argp->type != Unary) {
				if (!(b = *++av)) {
					(void) fprintf(stderr,
					gettext("%s: incomplete statement\n"),
							cmdname);
					exit(1);
				}
				if (argp->type == Num) {
					if (((argp->action == MAXDEPTH) ||
					    (argp->action == MINDEPTH)) &&
					    ((int)strtol(b, (char **)NULL,
					    10) < 0))
						errx(1,
					gettext("%s: value must be positive"),
						    (argp->action == MAXDEPTH) ?
						    "maxdepth" : "mindepth");
					if ((argp->action != PERM) ||
					    (*b != '+')) {
						if (*b == '+' || *b == '-') {
							np->second.i = *b;
							b++;
						}
					}
				}
			}
		}
		switch (argp->action) {
		case AND:
			break;
		case NOT:
			break;
		case OR:
			np->first.np = topnode;
			topnode = np;
			oldnp->next = 0;
			break;

		case LPAREN: {
			struct Node *save = topnode;
			topnode = np+1;
			paren_cnt++;
			i = compile(++av, topnode, actionp);
			np->first.np = topnode;
			topnode = save;
			av += i;
			oldnp = np;
			np += i + 1;
			oldnp->next = np;
			continue;
		}

		case RPAREN:
			if (paren_cnt <= 0) {
				(void) fprintf(stderr,
				    gettext("%s: unmatched ')'\n"),
				    cmdname);
				exit(1);
			}
			paren_cnt--;
			if (oldnp == 0)
				goto err;
			if (oldnp->type == Op) {
				(void) fprintf(stderr,
				    gettext("%s: cannot immediately"
				    " follow an operand with ')'\n"),
				    cmdname);
				exit(1);
			}
			oldnp->next = 0;
			return (av-argv);

		case FOLLOW:
			walkflags &= ~FTW_PHYS;
			break;
		case MOUNT:
			walkflags |= FTW_MOUNT;
			break;
		case DEPTH:
			walkflags |= FTW_DEPTH;
			break;
		case DELETE:
			walkflags |= (FTW_DEPTH | FTW_PHYS);
			walkflags &= ~FTW_CHDIR;
			(*actionp)++;
			break;

		case LOCAL:
			np->first.l = 0L;
			np->first.ll = 0LL;
			np->second.i = '+';
			/*
			 * Make it compatible to df -l for
			 * future enhancement. So, anything
			 * that is not remote, then it is
			 * local.
			 */
			init_remote_fs();
			break;

		case SIZE:
			if (b[strlen(b)-1] == 'c')
				np->action = CSIZE;
			/*FALLTHROUGH*/
		case INUM:
			np->first.ll = atoll(b);
			break;

		case CMIN:
		case CTIME:
		case MMIN:
		case MTIME:
		case AMIN:
		case ATIME:
		case LINKS:
			np->first.l = atol(b);
			break;

		case F_USER:
		case F_GROUP:
		case F_USERACL:
		case F_GROUPACL: {
			struct	passwd	*pw;
			struct	group *gr;
			long value;
			char *q;

			value = -1;
			if (argp->action == F_USER ||
			    argp->action == F_USERACL) {
				if ((pw = getpwnam(b)) != 0)
					value = (long)pw->pw_uid;
			} else {
				if ((gr = getgrnam(b)) != 0)
					value = (long)gr->gr_gid;
			}
			if (value == -1) {
				errno = 0;
				value = strtol(b, &q, 10);
				if (errno != 0 || q == b || *q != '\0') {
					(void) fprintf(stderr, gettext(
					    "%s: cannot find %s name\n"),
						cmdname, *av);
					exit(1);
				}
			}
			np->first.l = value;
			break;
		}

		case EXEC:
		case OK:
			walkflags &= ~FTW_CHDIR;
			np->first.ap = av;
			(*actionp)++;
			for (;;) {
				if ((b = *av) == 0) {
					(void) fprintf(stderr,
					gettext("%s: incomplete statement\n"),
						cmdname);
					exit(1);
				}
				if (strcmp(b, ";") == 0) {
					*av = 0;
					break;
				} else if (strcmp(b, "{}") == 0)
					*av = dummyarg;
				else if (strcmp(b, "+") == 0 &&
					av[-1] == dummyarg &&
					np->action == EXEC) {
					av[-1] = 0;
					np->first.vp = varargs(np->first.ap);
					np->action = VARARGS;
					break;
				}
				av++;
			}
			break;

		case NAME:
		case INAME:
		case PATH:
		case IPATH:
			np->first.cp = b;
			break;
		case REGEX:
		case IREGEX: {
			int error;
			size_t errlen;
			char *errmsg;

			if ((preg = realloc(preg, (npreg + 1) *
			    sizeof (regex_t))) == NULL)
				err(1, "realloc");
			if ((error = regcomp(&preg[npreg], b,
			    ((np->action == IREGEX) ? REG_ICASE : 0) |
			    ((Eflag) ? REG_EXTENDED : 0))) != 0) {
				errlen = regerror(error, &preg[npreg], NULL, 0);
				if ((errmsg = malloc(errlen)) == NULL)
					err(1, "malloc");
				(void) regerror(error, &preg[npreg], errmsg,
				    errlen);
				errx(1, gettext("RE error: %s"), errmsg);
			}
			npreg++;
			break;
		}
		case PERM:
			if (*b == '-')
				++b;

			if (readmode(b) != NULL) {
				(void) fprintf(stderr, gettext(
				    "find: -perm: Bad permission string\n"));
				usage();
			}
			np->first.l = (long)getmode((mode_t)0);
			break;
		case TYPE:
			i = *b;
			np->first.l =
			    i == 'd' ? S_IFDIR :
			    i == 'b' ? S_IFBLK :
			    i == 'c' ? S_IFCHR :
#ifdef S_IFIFO
			    i == 'p' ? S_IFIFO :
#endif
			    i == 'f' ? S_IFREG :
#ifdef S_IFLNK
			    i == 'l' ? S_IFLNK :
#endif
#ifdef S_IFSOCK
			    i == 's' ? S_IFSOCK :
#endif
#ifdef S_IFDOOR
			    i == 'D' ? S_IFDOOR :
#endif
			    0;
			break;

		case CPIO:
			if (walkflags & FTW_PHYS)
				com = cpio;
			else
				com = cpiol;
			goto common;

		case NCPIO: {
			FILE *fd;

			if (walkflags & FTW_PHYS)
				com = ncpio;
			else
				com = ncpiol;
		common:
			/* set up cpio */
			if ((fd = fopen(b, "w")) == NULL) {
				(void) fprintf(stderr,
					gettext("%s: cannot create %s\n"),
					cmdname, b);
				exit(1);
			}

			np->first.l = (long)cmdopen("cpio", com, "w", fd);
			(void) fclose(fd);
			walkflags |= FTW_DEPTH;
			np->action = CPIO;
		}
			/*FALLTHROUGH*/
		case PRINT:
		case PRINT0:
			(*actionp)++;
			break;

		case NEWER: {
			struct stat statb;
			if (stat(b, &statb) < 0) {
				(void) fprintf(stderr,
					gettext("%s: cannot access %s\n"),
					cmdname, b);
				exit(1);
			}
			np->first.l = statb.st_mtime;
			np->second.i = '+';
			break;
		}

		case PRUNE:
		case NOUSER:
		case NOGRP:
			break;
		case FSTYPE:
			np->first.cp = b;
			break;
		case LS:
			(*actionp)++;
			break;
		case XATTR:
			break;
		case ACL:
			break;
		case MAXDEPTH:
			maxdepth = (int)strtol(b, (char **)NULL, 10);
			break;
		case MINDEPTH:
			mindepth = (int)strtol(b, (char **)NULL, 10);
			break;
		}

		oldnp = np++;
		oldnp->next = np;
	}

	if ((*av) || (wasop))
		goto err;

	if (paren_cnt != 0) {
		(void) fprintf(stderr, gettext("%s: unmatched '('\n"),
		cmdname);
		exit(1);
	}

	/* just before returning, save next free node from the list */
	freenode = oldnp->next;
	oldnp->next = 0;
	return (av-argv);
err:
	if (*av)
		(void) fprintf(stderr,
		    gettext("%s: bad option %s\n"), cmdname, *av);
	else
		(void) fprintf(stderr, gettext("%s: bad option\n"), cmdname);
	usage();
	/*NOTREACHED*/
}

/*
 * print out a usage message
 */

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("%s: [-E] [-H | -L] path-list predicate-list\n"), cmdname);
	exit(1);
}

/*
 * This is the function that gets executed at each node
 */

static int
execute(name, statb, type, state)
char *name;
struct stat *statb;
int type;
struct FTW *state;
{
	struct Node *np = topnode;
	int val;
	time_t t;
	long l;
	long long ll;
	int not = 1;
	char *filename;
	int cnpreg = 0;

	if (type == FTW_NS) {
		(void) fprintf(stderr, gettext("%s: stat() error %s: %s\n"),
			cmdname, name, strerror(errno));
		error = 1;
		return (0);
	} else if (type == FTW_DNR) {
		(void) fprintf(stderr, gettext("%s: cannot read dir %s: %s\n"),
			cmdname, name, strerror(errno));
		error = 1;
	} else if (type == FTW_SLN && lflag == 1) {
		(void) fprintf(stderr,
			gettext("%s: cannot follow symbolic link %s: %s\n"),
			cmdname, name, strerror(errno));
		error = 1;
	} else if (type == FTW_DL) {
		(void) fprintf(stderr, gettext("%s: cycle detected for %s\n"),
			cmdname, name);
		error = 1;
		return (0);
	}

	if ((maxdepth != -1 && state->level > maxdepth) ||
	    (mindepth != -1 && state->level < mindepth))
		return (0);

	while (np) {
		switch (np->action) {
		case NOT:
			not = !not;
			np = np->next;
			continue;

		case AND:
			np = np->next;
			continue;

		case OR:
			if (np->first.np == np) {
				/*
				 * handle naked OR (no term on left hand side)
				 */
				(void) fprintf(stderr,
				    gettext("%s: invalid -o construction\n"),
				    cmdname);
				exit(2);
			}
			/* FALLTHROUGH */
		case LPAREN: {
			struct Node *save = topnode;
			topnode = np->first.np;
			(void) execute(name, statb, type, state);
			val = lastval;
			topnode = save;
			if (np->action == OR) {
				if (val)
					return (0);
				val = 1;
			}
			break;
		}

		case LOCAL: {
			int	nremfs;
			val = 1;
			/*
			 * If file system type matches the remote
			 * file system type, then it is not local.
			 */
			for (nremfs = 0; nremfs < fstype_index; nremfs++) {
				if (strcmp(remote_fstypes[nremfs],
						statb->st_fstype) == 0) {
					val = 0;
					break;
				}
			}
			break;
		}

		case TYPE:
			l = (long)statb->st_mode&S_IFMT;
			goto num;

		case PERM:
			l = (long)statb->st_mode&07777;
			if (np->second.i == '-')
				val = ((l&np->first.l) == np->first.l);
			else
				val = (l == np->first.l);
			break;

		case INUM:
			ll = (long long)statb->st_ino;
			goto llnum;
		case NEWER:
			l = statb->st_mtime;
			goto num;
		case ATIME:
			t = statb->st_atime;
			goto days;
		case CTIME:
			t = statb->st_ctime;
			goto days;
		case MTIME:
			t = statb->st_mtime;
		days:
			l = (now-t)/A_DAY;
			goto num;
		case MMIN:
			t = statb->st_mtime;
			goto mins;
		case AMIN:
			t = statb->st_atime;
			goto mins;
		case CMIN:
			t = statb->st_ctime;
			goto mins;
		mins:
			l = (now-t)/A_MIN;
			goto num;
		case CSIZE:
			ll = (long long)statb->st_size;
			goto llnum;
		case SIZE:
			ll = (long long)round(statb->st_size, BLKSIZ)/BLKSIZ;
			goto llnum;
		case F_USER:
			l = (long)statb->st_uid;
			goto num;
		case F_GROUP:
			l = (long)statb->st_gid;
			goto num;
		case LINKS:
			l = (long)statb->st_nlink;
			goto num;
		llnum:
			if (np->second.i == '+')
				val = (ll > np->first.ll);
			else if (np->second.i == '-')
				val = (ll < np->first.ll);
			else
				val = (ll == np->first.ll);
			break;
		num:
			if (np->second.i == '+')
				val = (l > np->first.l);
			else if (np->second.i == '-')
				val = (l < np->first.l);
			else
				val = (l == np->first.l);
			break;
		case OK:
			val = ok(name, np->first.ap);
			break;
		case EXEC:
			val = doexec(name, np->first.ap, NULL);
			break;
		case DELETE:
			val = dodelete(name, statb, state);
			break;

		case VARARGS: {
			struct Arglist *ap = np->first.vp;
			char *cp;
			cp = ap->nextstr - (strlen(name)+1);
			if (cp >= (char *)(ap->nextvar+3)) {
				/* there is room just copy the name */
				val = 1;
				(void) strcpy(cp, name);
				*ap->nextvar++ = cp;
				ap->nextstr = cp;
			} else {
				/* no more room, exec command */
				*ap->nextvar++ = name;
				*ap->nextvar = 0;
				val = 1;
				(void) doexec((char *)0, ap->arglist,
				    &exec_exitcode);
				ap->nextstr = ap->end;
				ap->nextvar = ap->firstvar;
			}
			break;
		}

		case DEPTH:
		case MOUNT:
		case FOLLOW:
			val = 1;
			break;

		case NAME:
		case INAME:
		case PATH:
		case IPATH: {
			char *path;
			int fnmflags = 0;

			if (np->action == INAME || np->action == IPATH)
				fnmflags = FNM_IGNORECASE;

			/*
			 * basename(3c) may modify name, so
			 * we need to pass another string
			 */
			if ((path = strdup(name)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: cannot strdup() %s: %s\n"),
				    cmdname, name, strerror(errno));
				exit(2);
			}
			/*
			 * XPG4 find should not treat a leading '.' in a
			 * filename specially for pattern matching.
			 * /usr/bin/find  will not pattern match a leading
			 * '.' in a filename, unless '.' is explicitly
			 * specified.
			 */
#ifndef XPG4
			fnmflags |= FNM_PERIOD;
#endif

			val = !fnmatch(np->first.cp,
			    (np->action == NAME || np->action == INAME)
				? basename(path) : path, fnmflags);
			free(path);
			break;
		}

		case PRUNE:
			if (type == FTW_D)
				state->quit = FTW_PRUNE;
			val = 1;
			break;
		case NOUSER:
			val = ((getpwuid(statb->st_uid)) == 0);
			break;
		case NOGRP:
			val = ((getgrgid(statb->st_gid)) == 0);
			break;
		case FSTYPE:
			val = (strcmp(np->first.cp, statb->st_fstype) == 0);
			break;
		case CPIO:
			output = (FILE *)np->first.l;
			(void) fprintf(output, "%s\n", name);
			val = 1;
			break;
		case PRINT:
		case PRINT0:
			(void) fprintf(stdout, "%s%c", name,
			    (np->action == PRINT) ? '\n' : '\0');
			val = 1;
			break;
		case LS:
			(void) list(name, statb);
			val = 1;
			break;
		case XATTR:
			filename = (walkflags & FTW_CHDIR) ?
				gettail(name) : name;
			val = (pathconf(filename, _PC_XATTR_EXISTS) == 1);
			break;
		case ACL:
			/*
			 * Need to get the tail of the file name, since we have
			 * already chdir()ed into the directory (performed in
			 * nftw()) of the file
			 */
			filename = (walkflags & FTW_CHDIR) ?
				gettail(name) : name;
			val = acl_trivial(filename);
			break;
		case F_USERACL:
		case F_GROUPACL: {
			int i;
			acl_t *acl;
			void *acl_entry;
			aclent_t *p1;
			ace_t *p2;

			filename = (walkflags & FTW_CHDIR) ?
			    gettail(name) : name;
			val = 0;
			if (acl_get(filename, 0, &acl) != 0)
				break;
			for (i = 0, acl_entry = acl->acl_aclp;
			    i != acl->acl_cnt; i++) {
				if (acl->acl_type == ACLENT_T) {
					p1 = (aclent_t *)acl_entry;
					if (p1->a_id == np->first.l) {
						val = 1;
						acl_free(acl);
						break;
					}
				} else {
					p2 = (ace_t *)acl_entry;
					if (p2->a_who == np->first.l) {
						val = 1;
						acl_free(acl);
						break;
					}
				}
				acl_entry = ((char *)acl_entry +
				    acl->acl_entry_size);
			}
			acl_free(acl);
			break;
		}
		case IREGEX:
		case REGEX: {
			regmatch_t pmatch;

			val = 0;
			if (regexec(&preg[cnpreg], name, 1, &pmatch, NULL) == 0)
				val = ((pmatch.rm_so == 0) &&
				    (pmatch.rm_eo == strlen(name)));
			cnpreg++;
			break;
		}
		case MAXDEPTH:
			if (state->level == maxdepth && type == FTW_D)
				state->quit = FTW_PRUNE;
			/* FALLTHROUGH */
		case MINDEPTH:
			val = 1;
			break;
		}
		/*
		 * evaluate 'val' and 'not' (exclusive-or)
		 * if no inversion (not == 1), return only when val == 0
		 * (primary not true). Otherwise, invert the primary
		 * and return when the primary is true.
		 * 'Lastval' saves the last result (fail or pass) when
		 * returning back to the calling routine.
		 */
		if (val^not) {
			lastval = 0;
			return (0);
		}
		lastval = 1;
		not = 1;
		np = np->next;
	}
	return (0);
}

/*
 * code for the -ok option
 */

static int
ok(name, argv)
char *name;
char *argv[];
{
	int  c;
	int i = 0;
	char resp[LINE_MAX + 1];

	(void) fflush(stdout); 	/* to flush possible `-print' */

	if ((*argv != dummyarg) && (strcmp(*argv, name)))
		(void) fprintf(stderr, "< %s ... %s >?   ", *argv, name);
	else
		(void) fprintf(stderr, "< {} ... %s >?   ", name);

	(void) fflush(stderr);

	while ((c = getchar()) != '\n') {
		if (c == EOF)
			exit(2);
		if (i < LINE_MAX)
			resp[i++] = c;
	}
	resp[i] = '\0';

	if (yes_check(resp))
		return (doexec(name, argv, NULL));
	else
		return (0);
}

/*
 * execute argv with {} replaced by name
 *
 * Per XPG6, find must exit non-zero if an invocation through
 * -exec, punctuated by a plus sign, exits non-zero, so set
 * exitcode if we see a non-zero exit.
 * exitcode should be NULL when -exec or -ok is not punctuated
 * by a plus sign.
 */

static int
doexec(char *name, char *argv[], int *exitcode)
{
	char *cp;
	char **av = argv;
	char *newargs[1 + SHELL_MAXARGS + 1];
	int dummyseen = 0;
	int i, j, status, rc, r = 0;
	int exit_status = 0;
	pid_t pid, pid1;

	(void) fflush(stdout);	  /* to flush possible `-print' */
	if (name) {
		while (cp = *av++) {
			if (cp == dummyarg) {
				dummyseen = 1;
				av[-1] = name;
			}

		}
	}
	if (argv[0] == NULL)    /* null command line */
		return (r);

	if ((pid = fork()) == -1) {
		/* fork failed */
		if (exitcode != NULL)
			*exitcode = 1;
		return (0);
	}
	if (pid != 0) {
		/* parent */
		do {
			/* wait for child to exit */
			if ((rc = wait(&r)) == -1 && errno != EINTR) {
				(void) fprintf(stderr,
				    gettext("wait failed %s"), strerror(errno));

				if (exitcode != NULL)
					*exitcode = 1;
				return (0);
			}
		} while (rc != pid);
	} else {
		/* child */
		(void) execvp(argv[0], argv);
		if (errno != E2BIG)
			exit(1);

		/*
		 * We are in a situation where argv[0] points to a
		 * script without the interpreter line, e.g. #!/bin/sh.
		 * execvp() will execute either /usr/bin/sh or
		 * /usr/xpg4/bin/sh against the script, and you will be
		 * limited to SHELL_MAXARGS arguments. If you try to
		 * pass more than SHELL_MAXARGS arguments, execvp()
		 * fails with E2BIG.
		 * See usr/src/lib/libc/port/gen/execvp.c.
		 *
		 * In this situation, process the argument list by
		 * packets of SHELL_MAXARGS arguments with respect of
		 * the following rules:
		 * 1. the invocations have to complete before find exits
		 * 2. only one invocation can be running at a time
		 */

		i = 1;
		newargs[0] = argv[0];

		while (argv[i]) {
			j = 1;
			while (j <= SHELL_MAXARGS && argv[i]) {
				newargs[j++] = argv[i++];
			}
			newargs[j] = NULL;

			if ((pid1 = fork()) == -1) {
				/* fork failed */
				exit(1);
			}
			if (pid1 == 0) {
				/* child */
				(void) execvp(newargs[0], newargs);
				exit(1);
			}

			status = 0;

			do {
				/* wait for the child to exit */
				if ((rc = wait(&status)) == -1 &&
				    errno != EINTR) {
					(void) fprintf(stderr,
					    gettext("wait failed %s"),
					    strerror(errno));
					exit(1);
				}
			} while (rc != pid1);

			if (status)
				exit_status = 1;
		}
		/* all the invocations have completed */
		exit(exit_status);
	}

	if (name && dummyseen) {
		for (av = argv; cp = *av++; ) {
			if (cp == name)
				av[-1] = dummyarg;
		}
	}

	if (r && exitcode != NULL)
		*exitcode = 3; /* use to indicate error in cmd invocation */

	return (!r);
}

static int
dodelete(char *name, struct stat *statb, struct FTW *state)
{
	char *fn;
	int rc = 0;

	/* restrict symlinks */
	if ((walkflags & FTW_PHYS) == 0) {
		(void) fprintf(stderr,
		    gettext("-delete is not allowed when symlinks are "
		    "followed.\n"));
		return (1);
	}

	fn = name + state->base;
	if (strcmp(fn, ".") == 0) {
		/* nothing to do */
		return (1);
	}

	if (strchr(fn, '/') != NULL) {
		(void) fprintf(stderr,
		    gettext("-delete with relative path is unsafe."));
		return (1);
	}

	if (S_ISDIR(statb->st_mode)) {
		/* delete directory */
		rc = rmdir(name);
	} else {
		/* delete file */
		rc = unlink(name);
	}

	if (rc < 0) {
		/* operation failed */
		(void) fprintf(stderr, gettext("delete failed %s: %s\n"),
		    name, strerror(errno));
		return (1);
	}

	return (1);
}

/*
 *  Table lookup routine
 */
static struct Args *
lookup(word)
char *word;
{
	struct Args *argp = commands;
	int second;
	if (word == 0 || *word == 0)
		return (0);
	second = word[1];
	while (*argp->name) {
		if (second == argp->name[1] && strcmp(word, argp->name) == 0)
			return (argp);
		argp++;
	}
	return (0);
}


/*
 * Get space for variable length argument list
 */

static struct Arglist *
varargs(com)
char **com;
{
	struct Arglist *ap;
	int n;
	char **ep;
	if (varsize == 0) {
		n = 2*sizeof (char **);
		for (ep = environ; *ep; ep++)
			n += (strlen(*ep)+sizeof (ep) + 1);
		varsize = sizeof (struct Arglist)+ARG_MAX-PATH_MAX-n-1;
	}
	ap = (struct Arglist *)malloc(varsize+1);
	ap->end = (char *)ap + varsize;
	ap->nextstr = ap->end;
	ap->nextvar = ap->arglist;
	while (*ap->nextvar++ = *com++);
	ap->nextvar--;
	ap->firstvar = ap->nextvar;
	ap->next = lastlist;
	lastlist = ap;
	return (ap);
}

/*
 * filter command support
 * fork and exec cmd(argv) according to mode:
 *
 *	"r"	with fp as stdin of cmd (default stdin), cmd stdout returned
 *	"w"	with fp as stdout of cmd (default stdout), cmd stdin returned
 */

#define	CMDERR	((1<<8)-1)	/* command error exit code		*/
#define	MAXCMDS	8		/* max # simultaneous cmdopen()'s	*/

static struct			/* info for each cmdopen()		*/
{
	FILE	*fp;		/* returned by cmdopen()		*/
	pid_t	pid;		/* pid used by cmdopen()		*/
} cmdproc[MAXCMDS];

static FILE *
cmdopen(cmd, argv, mode, fp)
char	*cmd;
char	**argv;
char	*mode;
FILE	*fp;
{
	int	proc;
	int	cmdfd;
	int	usrfd;
	int		pio[2];

	switch (*mode) {
	case 'r':
		cmdfd = 1;
		usrfd = 0;
		break;
	case 'w':
		cmdfd = 0;
		usrfd = 1;
		break;
	default:
		return (0);
	}

	for (proc = 0; proc < MAXCMDS; proc++)
		if (!cmdproc[proc].fp)
			break;
	if (proc >= MAXCMDS)
		return (0);

	if (pipe(pio))
		return (0);

	switch (cmdproc[proc].pid = fork()) {
	case -1:
		return (0);
	case 0:
		if (fp && fileno(fp) != usrfd) {
			(void) close(usrfd);
			if (dup2(fileno(fp), usrfd) != usrfd)
				_exit(CMDERR);
			(void) close(fileno(fp));
		}
		(void) close(cmdfd);
		if (dup2(pio[cmdfd], cmdfd) != cmdfd)
			_exit(CMDERR);
		(void) close(pio[cmdfd]);
		(void) close(pio[usrfd]);
		(void) execvp(cmd, argv);
		if (errno == ENOEXEC) {
			char	**p;
			char		**v;

			/*
			 * assume cmd is a shell script
			 */

			p = argv;
			while (*p++);
			if (v = (char **)malloc((p - argv + 1) *
					sizeof (char **))) {
				p = v;
				*p++ = cmd;
				if (*argv) argv++;
				while (*p++ = *argv++);
				(void) execv(getshell(), v);
			}
		}
		_exit(CMDERR);
		/*NOTREACHED*/
	default:
		(void) close(pio[cmdfd]);
		return (cmdproc[proc].fp = fdopen(pio[usrfd], mode));
	}
}

/*
 * close a stream opened by cmdopen()
 * -1 returned if cmdopen() had a problem
 * otherwise exit() status of command is returned
 */

static int
cmdclose(fp)
FILE	*fp;
{
	int	i;
	pid_t	p, pid;
	int		status;

	for (i = 0; i < MAXCMDS; i++)
		if (fp == cmdproc[i].fp) break;
	if (i >= MAXCMDS)
		return (-1);
	(void) fclose(fp);
	cmdproc[i].fp = 0;
	pid = cmdproc[i].pid;
	while ((p = wait(&status)) != pid && p != (pid_t)-1);
	if (p == pid) {
		status = (status >> 8) & CMDERR;
		if (status == CMDERR)
			status = -1;
	}
	else
		status = -1;
	return (status);
}

/*
 * return pointer to the full path name of the shell
 *
 * SHELL is read from the environment and must start with /
 *
 * if set-uid or set-gid then the executable and its containing
 * directory must not be writable by the real user
 *
 * /usr/bin/sh is returned by default
 */

char *
getshell()
{
	char	*s;
	char	*sh;
	uid_t	u;
	int	j;

	if (((sh = getenv("SHELL")) != 0) && *sh == '/') {
		if (u = getuid()) {
			if ((u != geteuid() || getgid() != getegid()) &&
			    access(sh, 2) == 0)
				goto defshell;
			s = strrchr(sh, '/');
			*s = 0;
			j = access(sh, 2);
			*s = '/';
			if (!j) goto defshell;
		}
		return (sh);
	}
defshell:
	return ("/usr/bin/sh");
}

/*
 * the following functions implement the added "-ls" option
 */

#include <utmpx.h>
#include <sys/mkdev.h>

struct		utmpx utmpx;
#define	NMAX	(sizeof (utmpx.ut_name))
#define	SCPYN(a, b)	(void) strncpy(a, b, NMAX)

#define	NUID	64
#define	NGID	64

static struct ncache {
	int	id;
	char	name[NMAX+1];
} nc[NUID], gc[NGID];

/*
 * This function assumes that the password file is hashed
 * (or some such) to allow fast access based on a name key.
 */
static char *
getname(uid_t uid)
{
	struct passwd *pw;
	int cp;

#if	(((NUID) & ((NUID) - 1)) != 0)
	cp = uid % (NUID);
#else
	cp = uid & ((NUID) - 1);
#endif
	if (nc[cp].id == uid && nc[cp].name[0])
		return (nc[cp].name);
	pw = getpwuid(uid);
	if (!pw)
		return (0);
	nc[cp].id = uid;
	SCPYN(nc[cp].name, pw->pw_name);
	return (nc[cp].name);
}

/*
 * This function assumes that the group file is hashed
 * (or some such) to allow fast access based on a name key.
 */
static char *
getgroup(gid_t gid)
{
	struct group *gr;
	int cp;

#if	(((NGID) & ((NGID) - 1)) != 0)
	cp = gid % (NGID);
#else
	cp = gid & ((NGID) - 1);
#endif
	if (gc[cp].id == gid && gc[cp].name[0])
		return (gc[cp].name);
	gr = getgrgid(gid);
	if (!gr)
		return (0);
	gc[cp].id = gid;
	SCPYN(gc[cp].name, gr->gr_name);
	return (gc[cp].name);
}

#define	permoffset(who)		((who) * 3)
#define	permission(who, type)	((type) >> permoffset(who))
#define	kbytes(bytes)		(((bytes) + 1023) / 1024)

static int
list(file, stp)
	char *file;
	struct stat *stp;
{
	char pmode[32], uname[32], gname[32], fsize[32], ftime[32];
	int trivial;

/*
 * Each line below contains the relevant permission (column 1) and character
 * shown when  the corresponding execute bit is either clear (column 2)
 * or set (column 3)
 * These permissions are as shown by ls(1b)
 */
	static long special[] = {	S_ISUID, 'S', 's',
					S_ISGID, 'S', 's',
					S_ISVTX, 'T', 't' };

	static time_t sixmonthsago = -1;
#ifdef	S_IFLNK
	char flink[MAXPATHLEN + 1];
#endif
	int who;
	char *cp;
	char *tailname;
	time_t now;
	long long ksize;

	if (file == NULL || stp == NULL)
		return (-1);

	(void) time(&now);
	if (sixmonthsago == -1)
		sixmonthsago = now - 6L*30L*24L*60L*60L;

	switch (stp->st_mode & S_IFMT) {
#ifdef	S_IFDIR
	case S_IFDIR:	/* directory */
		pmode[0] = 'd';
		break;
#endif
#ifdef	S_IFCHR
	case S_IFCHR:	/* character special */
		pmode[0] = 'c';
		break;
#endif
#ifdef	S_IFBLK
	case S_IFBLK:	/* block special */
		pmode[0] = 'b';
		break;
#endif
#ifdef	S_IFIFO
	case S_IFIFO:	/* fifo special */
		pmode[0] = 'p';
		break;
#endif
#ifdef	S_IFLNK
	case S_IFLNK:	/* symbolic link */
		pmode[0] = 'l';
		break;
#endif
#ifdef	S_IFSOCK
	case S_IFSOCK:	/* socket */
		pmode[0] = 's';
		break;
#endif
#ifdef	S_IFDOOR
	case S_IFDOOR:	/* door */
		pmode[0] = 'D';
		break;
#endif
#ifdef	S_IFREG
	case S_IFREG:	/* regular */
		pmode[0] = '-';
		break;
#endif
	default:
		pmode[0] = '?';
		break;
	}

	for (who = 0; who < 3; who++) {
		int is_exec =  stp->st_mode & permission(who, S_IEXEC)? 1 : 0;

		if (stp->st_mode & permission(who, S_IREAD))
			pmode[permoffset(who) + 1] = 'r';
		else
			pmode[permoffset(who) + 1] = '-';

		if (stp->st_mode & permission(who, S_IWRITE))
			pmode[permoffset(who) + 2] = 'w';
		else
			pmode[permoffset(who) + 2] = '-';

		if (stp->st_mode & special[who * 3])
			pmode[permoffset(who) + 3] =
				special[who * 3 + 1 + is_exec];
		else if (is_exec)
			pmode[permoffset(who) + 3] = 'x';
		else
			pmode[permoffset(who) + 3] = '-';
	}

	/*
	 * Need to get the tail of the file name, since we have
	 * already chdir()ed into the directory of the file
	 */

	tailname = gettail(file);

	trivial = acl_trivial(tailname);
	if (trivial == -1)
		trivial =  0;

	if (trivial == 1)
		pmode[permoffset(who) + 1] = '+';
	else
		pmode[permoffset(who) + 1] = ' ';

	pmode[permoffset(who) + 2] = '\0';

	/*
	 * Prepare uname and gname.  Always add a space afterwards
	 * to keep columns from running together.
	 */
	cp = getname(stp->st_uid);
	if (cp != NULL)
		(void) sprintf(uname, "%-8s ", cp);
	else
		(void) sprintf(uname, "%-8u ", stp->st_uid);

	cp = getgroup(stp->st_gid);
	if (cp != NULL)
		(void) sprintf(gname, "%-8s ", cp);
	else
		(void) sprintf(gname, "%-8u ", stp->st_gid);

	if (pmode[0] == 'b' || pmode[0] == 'c')
		(void) sprintf(fsize, "%3ld,%4ld",
			major(stp->st_rdev), minor(stp->st_rdev));
	else {
		(void) sprintf(fsize, (stp->st_size < 100000000) ?
			"%8lld" : "%lld", stp->st_size);
#ifdef	S_IFLNK
		if (pmode[0] == 'l') {


			who = readlink(tailname, flink, sizeof (flink) - 1);

			if (who >= 0)
				flink[who] = '\0';
			else
				flink[0] = '\0';
		}
#endif
	}

	cp = ctime(&stp->st_mtime);
	if (stp->st_mtime < sixmonthsago || stp->st_mtime > now)
		(void) sprintf(ftime, "%-7.7s %-4.4s", cp + 4, cp + 20);
	else
		(void) sprintf(ftime, "%-12.12s", cp + 4);

	(void) printf((stp->st_ino < 100000) ? "%5llu " :
		"%llu ", stp->st_ino);  /* inode #	*/
#ifdef	S_IFSOCK
	ksize = (long long) kbytes(ldbtob(stp->st_blocks)); /* kbytes */
#else
	ksize = (long long) kbytes(stp->st_size); /* kbytes */
#endif
	(void) printf((ksize < 10000) ? "%4lld " : "%lld ", ksize);
	(void) printf("%s %2ld %s%s%s %s %s%s%s\n",
		pmode,					/* protection	*/
		stp->st_nlink,				/* # of links	*/
		uname,					/* owner	*/
		gname,					/* group	*/
		fsize,					/* # of bytes	*/
		ftime,					/* modify time	*/
		file,					/* name		*/
#ifdef	S_IFLNK
		(pmode[0] == 'l') ? " -> " : "",
		(pmode[0] == 'l') ? flink  : ""		/* symlink	*/
#else
		"",
		""
#endif
);

	return (0);
}

static char *
new_string(char *s)
{
	char *p = strdup(s);

	if (p)
		return (p);
	(void) fprintf(stderr, gettext("%s: out of memory\n"), cmdname);
	exit(1);
	/*NOTREACHED*/
}

/*
 * Read remote file system types from REMOTE_FS into the
 * remote_fstypes array.
 */
static void
init_remote_fs()
{
	FILE    *fp;
	char    line_buf[LINEBUF_SIZE];

	if ((fp = fopen(REMOTE_FS, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: Warning: can't open %s, ignored\n"),
		    REMOTE_FS, cmdname);
		/* Use default string name for NFS */
		remote_fstypes[fstype_index++] = "nfs";
		return;
	}

	while (fgets(line_buf, sizeof (line_buf), fp) != NULL) {
		char buf[LINEBUF_SIZE];

		/* LINTED - unbounded string specifier */
		(void) sscanf(line_buf, "%s", buf);
		remote_fstypes[fstype_index++] = new_string(buf);

		if (fstype_index == N_FSTYPES)
			break;
	}
	(void) fclose(fp);
}

#define	NPERM	30			/* Largest machine */

/*
 * The PERM struct is the machine that builds permissions.  The p_special
 * field contains what permissions need to be checked at run-time in
 * getmode().  This is one of 'X', 'u', 'g', or 'o'.  It contains '\0' to
 * indicate normal processing.
 */
typedef	struct	PERMST	{
	ushort_t	p_who;		/* Range of permission (e.g. ugo) */
	ushort_t	p_perm;		/* Bits to turn on, off, assign */
	uchar_t		p_op;		/* Operation: + - = */
	uchar_t		p_special;	/* Special handling? */
}	PERMST;

#ifndef	S_ISVTX
#define	S_ISVTX	0			/* Not .1 */
#endif

/* Mask values */
#define	P_A	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO) /* allbits */
#define	P_U	(S_ISUID|S_ISVTX|S_IRWXU)		/* user */
#define	P_G	(S_ISGID|S_ISVTX|S_IRWXG)		/* group */
#define	P_O	(S_ISVTX|S_IRWXO)			/* other */

static	int	iswho(int c);
static	int	isop(int c);
static	int	isperm(PERMST *pp, int c);

static	PERMST	machine[NPERM];		/* Permission construction machine */
static	PERMST	*endp;			/* Last used PERM structure */

static	uint_t	nowho;			/* No who for this mode (DOS kludge) */

/*
 * Read an ASCII string containing the symbolic/octal mode and
 * compile an automaton that recognizes it.  The return value
 * is NULL if everything is OK, otherwise it is -1.
 */
static int
readmode(ascmode)
const char *ascmode;
{
	const char *amode = ascmode;
	PERMST *pp;
	int seen_X;

	nowho = 0;
	seen_X = 0;
	pp = &machine[0];
	if (*amode >= '0' && *amode <= '7') {
		int mode;

		mode = 0;
		while (*amode >= '0' && *amode <= '7')
			mode = (mode<<3) + *amode++ - '0';
		if (*amode != '\0')
			return (-1);
#if	S_ISUID != 04000 || S_ISGID != 02000 || \
	S_IRUSR != 0400 || S_IWUSR != 0200 || S_IXUSR != 0100 || \
	S_IRGRP != 0040 || S_IWGRP != 0020 || S_IXGRP != 0010 || \
	S_IROTH != 0004 || S_IWOTH != 0002 || S_IXOTH != 0001
		/*
		 * There is no requirement of the octal mode bits being
		 * the same as the S_ macros.
		 */
	{
		mode_t mapping[] = {
			S_IXOTH, S_IWOTH, S_IROTH,
			S_IXGRP, S_IWGRP, S_IRGRP,
			S_IXUSR, S_IWUSR, S_IRUSR,
			S_ISGID, S_ISUID,
			0
		};
		int i, newmode = 0;

		for (i = 0; mapping[i] != 0; i++)
			if (mode & (1<<i))
				newmode |= mapping[i];
		mode = newmode;
	}
#endif
		pp->p_who = P_A;
		pp->p_perm = mode;
		pp->p_op = '=';
	} else	for (;;) {
		int t;
		int who = 0;

		while ((t = iswho(*amode)) != 0) {
			++amode;
			who |= t;
		}
		if (who == 0) {
			mode_t currmask;
			(void) umask(currmask = umask((mode_t)0));

			/*
			 * If no who specified, must use contents of
			 * umask to determine which bits to flip.  This
			 * is POSIX/V7/BSD behaviour, but not SVID.
			 */
			who = (~currmask)&P_A;
			++nowho;
		} else
			nowho = 0;
	samewho:
		if (!isop(pp->p_op = *amode++))
			return (-1);
		pp->p_perm = 0;
		pp->p_special = 0;
		while ((t = isperm(pp, *amode)) != 0) {
			if (pp->p_special == 'X') {
				seen_X = 1;

				if (pp->p_perm != 0) {
					ushort_t op;

					/*
					 * Remember the 'who' for the previous
					 * transformation.
					 */
					pp->p_who = who;
					pp->p_special = 0;

					op = pp->p_op;

					/* Keep 'X' separate */
					++pp;
					pp->p_special = 'X';
					pp->p_op = op;
				}
			} else if (seen_X) {
				ushort_t op;

				/* Remember the 'who' for the X */
				pp->p_who = who;

				op = pp->p_op;

				/* Keep 'X' separate */
				++pp;
				pp->p_perm = 0;
				pp->p_special = 0;
				pp->p_op = op;
			}
			++amode;
			pp->p_perm |= t;
		}

		/*
		 * These returned 0, but were actually parsed, so
		 * don't look at them again.
		 */
		switch (pp->p_special) {
		case 'u':
		case 'g':
		case 'o':
			++amode;
			break;
		}
		pp->p_who = who;
		switch (*amode) {
		case '\0':
			break;

		case ',':
			++amode;
			++pp;
			continue;

		default:
			++pp;
			goto samewho;
		}
		break;
	}
	endp = pp;
	return (NULL);
}

/*
 * Given a character from the mode, return the associated
 * value as who (user designation) mask or 0 if this isn't valid.
 */
static int
iswho(c)
int c;
{
	switch (c) {
	case 'a':
		return (P_A);

	case 'u':
		return (P_U);

	case 'g':
		return (P_G);

	case 'o':
		return (P_O);

	default:
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Return non-zero if this is a valid op code
 * in a symbolic mode.
 */
static int
isop(c)
int c;
{
	switch (c) {
	case '+':
	case '-':
	case '=':
		return (1);

	default:
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Return the permission bits implied by this character or 0
 * if it isn't valid.  Also returns 0 when the pseudo-permissions 'u', 'g', or
 * 'o' are used, and sets pp->p_special to the one used.
 */
static int
isperm(pp, c)
PERMST *pp;
int c;
{
	switch (c) {
	case 'u':
	case 'g':
	case 'o':
		pp->p_special = c;
		return (0);

	case 'r':
		return (S_IRUSR|S_IRGRP|S_IROTH);

	case 'w':
		return (S_IWUSR|S_IWGRP|S_IWOTH);

	case 'x':
		return (S_IXUSR|S_IXGRP|S_IXOTH);

#if S_ISVTX != 0
	case 't':
		return (S_ISVTX);
#endif

	case 'X':
		pp->p_special = 'X';
		return (S_IXUSR|S_IXGRP|S_IXOTH);

#if S_ISVTX != 0
	case 'a':
		return (S_ISVTX);
#endif

	case 'h':
		return (S_ISUID);

	/*
	 * This change makes:
	 *	chmod +s file
	 * set the system bit on dos but means that
	 *	chmod u+s file
	 *	chmod g+s file
	 *	chmod a+s file
	 * are all like UNIX.
	 */
	case 's':
		return (nowho ? S_ISGID : S_ISGID|S_ISUID);

	default:
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Execute the automaton that is created by readmode()
 * to generate the final mode that will be used.  This
 * code is passed a starting mode that is usually the original
 * mode of the file being changed (or 0).  Note that this mode must contain
 * the file-type bits as well, so that S_ISDIR will succeed on directories.
 */
static mode_t
getmode(mode_t startmode)
{
	PERMST *pp;
	mode_t temp;
	mode_t perm;

	for (pp = &machine[0]; pp <= endp; ++pp) {
		perm = (mode_t)0;
		/*
		 * For the special modes 'u', 'g' and 'o', the named portion
		 * of the mode refers to after the previous clause has been
		 * processed, while the 'X' mode refers to the contents of the
		 * mode before any clauses have been processed.
		 *
		 * References: P1003.2/D11.2, Section 4.7.7,
		 *  lines 2568-2570, 2578-2583
		 */
		switch (pp->p_special) {
		case 'u':
			temp = startmode & S_IRWXU;
			if (temp & (S_IRUSR|S_IRGRP|S_IROTH))
				perm |= ((S_IRUSR|S_IRGRP|S_IROTH) &
				    pp->p_who);
			if (temp & (S_IWUSR|S_IWGRP|S_IWOTH))
				perm |= ((S_IWUSR|S_IWGRP|S_IWOTH) & pp->p_who);
			if (temp & (S_IXUSR|S_IXGRP|S_IXOTH))
				perm |= ((S_IXUSR|S_IXGRP|S_IXOTH) & pp->p_who);
			break;

		case 'g':
			temp = startmode & S_IRWXG;
			if (temp & (S_IRUSR|S_IRGRP|S_IROTH))
				perm |= ((S_IRUSR|S_IRGRP|S_IROTH) & pp->p_who);
			if (temp & (S_IWUSR|S_IWGRP|S_IWOTH))
				perm |= ((S_IWUSR|S_IWGRP|S_IWOTH) & pp->p_who);
			if (temp & (S_IXUSR|S_IXGRP|S_IXOTH))
				perm |= ((S_IXUSR|S_IXGRP|S_IXOTH) & pp->p_who);
			break;

		case 'o':
			temp = startmode & S_IRWXO;
			if (temp & (S_IRUSR|S_IRGRP|S_IROTH))
				perm |= ((S_IRUSR|S_IRGRP|S_IROTH) & pp->p_who);
			if (temp & (S_IWUSR|S_IWGRP|S_IWOTH))
				perm |= ((S_IWUSR|S_IWGRP|S_IWOTH) & pp->p_who);
			if (temp & (S_IXUSR|S_IXGRP|S_IXOTH))
				perm |= ((S_IXUSR|S_IXGRP|S_IXOTH) & pp->p_who);
			break;

		case 'X':
			perm = pp->p_perm;
			break;

		default:
			perm = pp->p_perm;
			break;
		}
		switch (pp->p_op) {
		case '-':
			startmode &= ~(perm & pp->p_who);
			break;

		case '=':
			startmode &= ~pp->p_who;
			/* FALLTHROUGH */
		case '+':
			startmode |= (perm & pp->p_who);
			break;
		}
	}
	return (startmode);
}

/*
 * Returns the last component of a path name, unless it is
 * an absolute path, in which case it returns the whole path
 */
static char
*gettail(char *fname)
{
	char	*base = fname;

	if (*fname != '/') {
		if ((base = strrchr(fname, '/')) != NULL)
			base++;
		else
			base = fname;
	}
	return (base);
}
