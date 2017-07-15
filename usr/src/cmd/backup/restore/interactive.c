/*
 * Copyright 1998,2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1985 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <setjmp.h>
#include <euc.h>
#include <widec.h>
#include "restore.h"
#include <ctype.h>
#include <limits.h>
#include <sys/wait.h>

extern eucwidth_t wp;

#define	round(a, b) ((((a) + (b) - 1) / (b)) * (b))

/*
 * Things to handle interruptions.
 */
static jmp_buf reset;
static int reset_OK;
static char *nextarg = NULL;

static int dontexpand;	/* co-routine state set in getnext, used in expandarg */

#ifdef __STDC__
static void getcmd(char *, char *, size_t, char *, size_t, struct arglist *);
static void expandarg(char *, struct arglist *);
static void printlist(char *, ino_t, char *, int);
static void formatf(struct arglist *);
static char *copynext(char *, char *, size_t);
static int fcmp(struct afile *, struct afile *);
static char *fmtentry(struct afile *);
static void setpagercmd(void);
static uint_t setpagerargs(char **);
#else
static void getcmd();
static void expandarg();
static void printlist();
static void formatf();
static char *copynext();
static int fcmp();
static char *fmtentry();
static void setpagercmd();
static uint_t setpagerargs();
#endif

/*
 * Read and execute commands from the terminal.
 */
void
#ifdef __STDC__
runcmdshell(void)
#else
runcmdshell()
#endif
{
	struct entry *np;
	ino_t ino;
	static struct arglist alist = { 0, 0, 0, 0, 0 };
	char curdir[MAXCOMPLEXLEN];
	char name[MAXCOMPLEXLEN];
	char cmd[BUFSIZ];

#ifdef	lint
	curdir[0] = '\0';
#endif	/* lint */

	canon("/", curdir, sizeof (curdir));
loop:
	if (setjmp(reset) != 0) {
		for (; alist.head < alist.last; alist.head++)
			freename(alist.head->fname);
		nextarg = NULL;
		volno = 0;
		goto loop;	/* make sure jmpbuf is up-to-date */
	}
	reset_OK = 1;
	getcmd(curdir, cmd, sizeof (cmd), name, sizeof (name), &alist);

	/*
	 * Using strncmp() to catch unique prefixes.
	 */
	switch (cmd[0]) {
	/*
	 * Add elements to the extraction list.
	 */
	case 'a':
		if (strncmp(cmd, "add", strlen(cmd)) != 0)
			goto bad;
		if (name[0] == '\0')
			break;
		ino = dirlookup(name);
		if (ino == 0)
			break;
		if (mflag)
			pathcheck(name);
		treescan(name, ino, addfile);
		break;
	/*
	 * Change working directory.
	 */
	case 'c':
		if (strncmp(cmd, "cd", strlen(cmd)) != 0)
			goto bad;
		if (name[0] == '\0')
			break;
		ino = dirlookup(name);
		if (ino == 0)
			break;
		if (inodetype(ino) == LEAF) {
			(void) fprintf(stderr,
				gettext("%s: not a directory\n"), name);
			break;
		}

		/* No need to canon(name), getcmd() did it for us */
		(void) strncpy(curdir, name, sizeof (curdir));
		curdir[sizeof (curdir) - 1] = '\0';
		break;
	/*
	 * Delete elements from the extraction list.
	 */
	case 'd':
		if (strncmp(cmd, "delete", strlen(cmd)) != 0)
			goto bad;
		if (name[0] == '\0')
			break;
		np = lookupname(name);
		if (np == NIL || (np->e_flags & NEW) == 0) {
			(void) fprintf(stderr,
				gettext("%s: not on extraction list\n"), name);
			break;
		}
		treescan(name, np->e_ino, deletefile);
		break;
	/*
	 * Extract the requested list.
	 */
	case 'e':
		if (strncmp(cmd, "extract", strlen(cmd)) != 0)
			goto bad;
		attrscan(0, addfile);
		createfiles();
		createlinks();
		setdirmodes();
		if (dflag)
			checkrestore();
		volno = 0;
		break;
	/*
	 * List available commands.
	 */
	case 'h':
		if (strncmp(cmd, "help", strlen(cmd)) != 0)
			goto bad;
		/*FALLTHROUGH*/
	case '?':
		/* ANSI string catenation, to shut cstyle up */
		(void) fprintf(stderr, "%s",
			gettext("Available commands are:\n"
"\tls [arg] - list directory\n"
"\tmarked [arg] - list items marked for extraction from directory\n"
"\tcd arg - change directory\n"
"\tpwd - print current directory\n"
"\tadd [arg] - add `arg' to list of files to be extracted\n"
"\tdelete [arg] - delete `arg' from list of files to be extracted\n"
"\textract - extract requested files\n"
"\tsetmodes - set modes of requested directories\n"
"\tquit - immediately exit program\n"
"\twhat - list dump header information\n"
"\tverbose - toggle verbose flag (useful with ``ls'')\n"
"\tpaginate - toggle pagination flag (affects ``ls'' and ``marked'')\n"
"\tsetpager - set pagination command and arguments\n"
"\thelp or `?' - print this list\n"
"If no `arg' is supplied, the current directory is used\n"));
		break;
	/*
	 * List a directory.
	 */
	case 'l':
	case 'm':
		if ((strncmp(cmd, "ls", strlen(cmd)) != 0) &&
		    (strncmp(cmd, "marked", strlen(cmd)) != 0))
			goto bad;
		if (name[0] == '\0')
			break;
		ino = dirlookup(name);
		if (ino == 0)
			break;
		printlist(name, ino, curdir, *cmd == 'm');
		break;
	/*
	 * Print current directory or enable pagination.
	 */
	case 'p':
		if (strlen(cmd) < 2)
			goto ambiguous;
		if (strncmp(cmd, "pwd", strlen(cmd)) == 0) {
			if (curdir[1] == '\0') {
				(void) fprintf(stderr, "/\n");
			} else {
				(void) fprintf(stderr, "%s\n", &curdir[1]);
			}
		} else if (strncmp(cmd, "paginate", strlen(cmd)) == 0) {
			if (paginating) {
				(void) fprintf(stderr,
				    gettext("paging disabled\n"));
				paginating = 0;
				break;
			}
			if (vflag) {
				(void) fprintf(stderr,
				    gettext("paging enabled (%s)\n"),
				    pager_catenated);
			} else {
				(void) fprintf(stderr,
				    gettext("paging enabled\n"));
			}
			if (dflag) {
				int index = 0;

				while (index < pager_len) {
					(void) fprintf(stderr,
					    ">>>pager_vector[%d] = `%s'\n",
					    index,
					    pager_vector[index] ?
						pager_vector[index] : "(null)");
					index += 1;
				}
			}
			paginating = 1;
		} else {
			goto bad;
		}
		break;
	/*
	 * Quit.
	 */
	case 'q':
		if (strncmp(cmd, "quit", strlen(cmd)) != 0)
			goto bad;
		reset_OK = 0;
		return;
	case 'x':
		if (strncmp(cmd, "xit", strlen(cmd)) != 0)
			goto bad;
		reset_OK = 0;
		return;
	/*
	 * Toggle verbose mode.
	 */
	case 'v':
		if (strncmp(cmd, "verbose", strlen(cmd)) != 0)
			goto bad;
		if (vflag) {
			(void) fprintf(stderr, gettext("verbose mode off\n"));
			vflag = 0;
			break;
		}
		(void) fprintf(stderr, gettext("verbose mode on\n"));
		vflag = 1;
		break;
	/*
	 * Just restore requested directory modes, or set pagination command.
	 */
	case 's':
		if (strlen(cmd) < 4)
			goto ambiguous;
		if (strncmp(cmd, "setmodes", strlen(cmd)) == 0) {
			setdirmodes();
		} else if (strncmp(cmd, "setpager", strlen(cmd)) == 0) {
			setpagercmd();
		} else {
			goto bad;
		}
		break;
	/*
	 * Print out dump header information.
	 */
	case 'w':
		if (strncmp(cmd, "what", strlen(cmd)) != 0)
			goto bad;
		printdumpinfo();
		break;
	/*
	 * Turn on debugging.
	 */
	case 'D':
		if (strncmp(cmd, "Debug", strlen(cmd)) != 0)
			goto bad;
		if (dflag) {
			(void) fprintf(stderr, gettext("debugging mode off\n"));
			dflag = 0;
			break;
		}
		(void) fprintf(stderr, gettext("debugging mode on\n"));
		dflag++;
		break;
	/*
	 * Unknown command.
	 */
	default:
	bad:
		(void) fprintf(stderr,
			gettext("%s: unknown command; type ? for help\n"), cmd);
		break;
	ambiguous:
		(void) fprintf(stderr,
		    gettext("%s: ambiguous command; type ? for help\n"), cmd);
		break;
	}
	goto loop;
}

static char input[MAXCOMPLEXLEN]; /* shared by getcmd() and setpagercmd() */
#define	rawname input	/* save space by reusing input buffer */

/*
 * Read and parse an interactive command.
 * The first word on the line is assigned to "cmd". If
 * there are no arguments on the command line, then "curdir"
 * is returned as the argument. If there are arguments
 * on the line they are returned one at a time on each
 * successive call to getcmd. Each argument is first assigned
 * to "name". If it does not start with "/" the pathname in
 * "curdir" is prepended to it. Finally "canon" is called to
 * eliminate any embedded ".." components.
 */
/* ARGSUSED */
static void
getcmd(curdir, cmd, cmdsiz, name, namesiz, ap)
	char *curdir, *cmd, *name;
	size_t cmdsiz, namesiz;
	struct arglist *ap;
{
	char *cp;
	char output[MAXCOMPLEXLEN];

	/*
	 * Check to see if still processing arguments.
	 */
	if (ap->head != ap->last) {
		(void) strncpy(name, ap->head->fname, namesiz);
		name[namesiz - 1] = '\0';
		/* double null terminate string */
		if ((strlen(name) + 2) > namesiz) {
			fprintf(stderr, gettext("name is too long, ignoring"));
			memset(name, 0, namesiz);
		} else {
			name[strlen(name) + 1] = '\0';
		}
		freename(ap->head->fname);
		ap->head++;
		return;
	}
	if (nextarg != NULL)
		goto getnext;
	/*
	 * Read a command line and trim off trailing white space.
	 */
readagain:
	do {
		(void) fprintf(stderr, "%s > ", progname);
		(void) fflush(stderr);
		(void) fgets(input, sizeof (input), terminal);
	} while (!feof(terminal) && input[0] == '\n');
	if (feof(terminal)) {
		(void) strncpy(cmd, "quit", cmdsiz);
		return;
	}
	/* trim off trailing white space and newline */
	for (cp = &input[strlen(input) - 2];
	    cp >= &input[0] && isspace((uchar_t)*cp);
	    cp--) {
		continue;
		/*LINTED [empty loop body]*/
	}
	*++cp = '\0';
	if ((strlen(input) + 2) > MAXCOMPLEXLEN) {
		fprintf(stderr, gettext("command is too long\n"));
		goto readagain;
	} else {
		/* double null terminate string */
		*(cp + 1) = '\0';
	}

	if (cp == &input[0])
		goto readagain;

	/*
	 * Copy the command into "cmd".
	 */
	cp = copynext(input, cmd, cmdsiz);
	ap->cmd = cmd;
	/*
	 * If no argument, use curdir as the default.
	 */
	if (*cp == '\0') {
		(void) strncpy(name, curdir, namesiz);
		name[namesiz - 1] = '\0';
		/* double null terminate string */
		if ((strlen(name) + 2) > namesiz) {
			fprintf(stderr, gettext("name is too long, ignoring"));
			memset(name, 0, namesiz);
		} else {
			name[strlen(name) + 1] = '\0';
		}
		return;
	}
	nextarg = cp;
	/*
	 * Find the next argument.
	 */
getnext:
	cp = copynext(nextarg, rawname, sizeof (rawname));
	if (*cp == '\0')
		nextarg = NULL;
	else
		nextarg = cp;
	/*
	 * If it an absolute pathname, canonicalize it and return it.
	 */
	if (rawname[0] == '/') {
		canon(rawname, name, namesiz);
	} else {
		/*
		 * For relative pathnames, prepend the current directory to
		 * it then canonicalize and return it.
		 */
		(void) snprintf(output, sizeof (output), "%s/%s",
		    curdir, rawname);
		canon(output, name, namesiz);
	}
	expandarg(name, ap);
	/*
	 * ap->head->fname guaranteed to be double null-terminated and
	 * no more than MAXCOMPLEXLEN characters long.
	 */
	assert(namesiz >= (MAXCOMPLEXLEN));
	(void) strcpy(name, ap->head->fname);
	/* double null terminate string */
	name[strlen(name) + 1] = '\0';
	freename(ap->head->fname);
	ap->head++;
#undef	rawname
}

/*
 * Strip off the next token of the input.
 */
static char *
copynext(input, output, outsize)
	char *input, *output;
	size_t outsize;
{
	char *cp, *bp, *limit;
	char quote;

	dontexpand = 0;
	/* skip to argument */
	for (cp = input; *cp != '\0' && isspace((uchar_t)*cp); cp++) {
		continue;
		/*LINTED [empty loop body]*/
	}
	bp = output;
	limit = output + outsize - 1; /* -1 for the trailing \0 */
	while (!isspace((uchar_t)*cp) && *cp != '\0' && bp < limit) {
		/*
		 * Handle back slashes.
		 */
		if (*cp == '\\') {
			if (*++cp == '\0') {
				(void) fprintf(stderr, gettext(
				    "command lines cannot be continued\n"));
				continue;
			}
			*bp++ = *cp++;
			continue;
		}
		/*
		 * The usual unquoted case.
		 */
		if (*cp != '\'' && *cp != '"') {
			*bp++ = *cp++;
			continue;
		}
		/*
		 * Handle single and double quotes.
		 */
		quote = *cp++;
		dontexpand = 1;
		while (*cp != quote && *cp != '\0' && bp < limit)
			*bp++ = *cp++;
		if (*cp++ == '\0') {
			(void) fprintf(stderr,
			    gettext("missing %c\n"), (uchar_t)quote);
			cp--;
			continue;
		}
	}
	*bp = '\0';
	if ((strlen(output) + 2) > outsize) {
		fprintf(stderr, gettext(
		    "name is too long, ignoring"));
		memset(output, 0, outsize);
	} else {
		/* double null terminate string */
		*(bp + 1) = '\0';
	}
	return (cp);
}

/*
 * Canonicalize file names to always start with ``./'' and
 * remove any imbedded "." and ".." components.
 *
 * The pathname "canonname" is returned double null terminated.
 */
void
canon(rawname, canonname, limit)
	char *rawname, *canonname;
	size_t limit;
{
	char *cp, *np, *prefix;
	uint_t len;

	assert(limit > 3);
	if (strcmp(rawname, ".") == 0 || strncmp(rawname, "./", 2) == 0)
		prefix = "";
	else if (rawname[0] == '/')
		prefix = ".";
	else
		prefix = "./";
	(void) snprintf(canonname, limit, "%s%s", prefix, rawname);
	/*
	 * Eliminate multiple and trailing '/'s
	 */
	for (cp = np = canonname; *np != '\0'; cp++) {
		*cp = *np++;
		while (*cp == '/' && *np == '/')
			np++;
	}
	*cp = '\0';
	if ((strlen(canonname) + 2) > limit) {
		fprintf(stderr,
		    gettext("canonical name is too long, ignoring name\n"));
		memset(canonname, 0, limit);
	} else {
		/* double null terminate string */
		*(cp + 1) = '\0';
	}

	if (*--cp == '/')
		*cp = '\0';
	/*
	 * Eliminate extraneous "." and ".." from pathnames.  Uses
	 * memmove(), as strcpy() might do the wrong thing for these
	 * small overlaps.
	 */
	np = canonname;
	while (*np != '\0') {
		np++;
		cp = np;
		while (*np != '/' && *np != '\0')
			np++;
		if (np - cp == 1 && *cp == '.') {
			cp--;
			len = strlen(np);
			(void) memmove(cp, np, len);
			*(cp + len) = '\0';
			/* double null terminate string */
			*(cp + len + 1) = '\0';
			np = cp;
		}
		if (np - cp == 2 && strncmp(cp, "..", 2) == 0) {
			cp--;
			/* find beginning of name */
			while (cp > &canonname[1] && *--cp != '/') {
				continue;
				/*LINTED [empty loop body]*/
			}
			len = strlen(np);
			(void) memmove(cp, np, len);
			*(cp + len) = '\0';
			/* double null terminate string */
			*(cp + len + 1) = '\0';
			np = cp;
		}
	}
}

/*
 * globals (file name generation)
 *
 * "*" in params matches r.e ".*"
 * "?" in params matches r.e. "."
 * "[...]" in params matches character class
 * "[...a-z...]" in params matches a through z.
 */
static void
expandarg(arg, ap)
	char *arg;
	struct arglist *ap;
{
	static struct afile single;
	int size;

	ap->head = ap->last = (struct afile *)0;
	if (dontexpand)
		size = 0;
	else
		size = expand(arg, 0, ap);
	if (size == 0) {
		struct entry *ep;

		ep = lookupname(arg);
		single.fnum = ep ? ep->e_ino : 0;
		single.fname = savename(arg);
		ap->head = &single;
		ap->last = ap->head + 1;
		return;
	}
	if ((ap->last - ap->head) > ULONG_MAX) {
		(void) fprintf(stderr,
		    gettext("Argument expansion too large to sort\n"));
	} else {
		/* LINTED pointer arith just range-checked */
		qsort((char *)ap->head, (size_t)(ap->last - ap->head),
		    sizeof (*ap->head),
		    (int (*)(const void *, const void *)) fcmp);
	}
}

/*
 * Do an "ls" style listing of a directory
 */
static void
printlist(name, ino, basename, marked_only)
	char *name;
	ino_t ino;
	char *basename;
	int marked_only;
{
	struct afile *fp;
	struct direct *dp;
	static struct arglist alist = { 0, 0, 0, 0, "ls" };
	struct afile single;
	struct entry *np;
	RST_DIR *dirp;
	int list_entry;

	if ((dirp = rst_opendir(name)) == NULL) {
		single.fnum = ino;
		if (strncmp(name, basename, strlen(basename)) == 0)
			single.fname = savename(name + strlen(basename) + 1);
		else
			single.fname = savename(name);
		alist.head = &single;
		alist.last = alist.head + 1;
		if (alist.base != NULL) {
			free(alist.base);
			alist.base = NULL;
		}
	} else {
		alist.head = (struct afile *)0;
		(void) fprintf(stderr, "%s:\n", name);
		while (dp = rst_readdir(dirp)) {
			if (dp == NULL || dp->d_ino == 0) {
				rst_closedir(dirp);
				dirp = NULL;
				break;
			}
			if (!dflag && BIT(dp->d_ino, dumpmap) == 0)
				continue;
			if (vflag == 0 &&
			    (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0))
				continue;
			list_entry = 1;
			if (marked_only) {
				np = lookupino(dp->d_ino);
				if ((np == NIL) || ((np->e_flags & NEW) == 0))
					list_entry = 0;
			}
			if (list_entry) {
				if (!mkentry(dp->d_name, dp->d_ino, &alist)) {
					rst_closedir(dirp);
					return;
				}
			}
		}
	}
	if (alist.head != 0) {
		if ((alist.last - alist.head) > ULONG_MAX) {
			(void) fprintf(stderr,
			    gettext("Directory too large to sort\n"));
		} else {
			qsort((char *)alist.head,
			    /* LINTED range-checked */
			    (size_t)(alist.last - alist.head),
			    sizeof (*alist.head),
			    (int (*)(const void *, const void *)) fcmp);
		}
		formatf(&alist);
		for (fp = alist.head; fp < alist.last; fp++)
			freename(fp->fname);
		alist.head = NULL;
		/*
		 * Don't free alist.base, as we'll probably be called
		 * again, and might as well re-use what we've got.
		 */
	}
	if (dirp != NULL) {
		(void) fprintf(stderr, "\n");
		rst_closedir(dirp);
	}
}

/*
 * Print out a pretty listing of a directory
 */
static void
formatf(ap)
	struct arglist *ap;
{
	struct afile *fp;
	struct entry *np;
	/* LINTED: result fits into an int */
	int nentry = (int)(ap->last - ap->head);
	int i, j;
	uint_t len, w, width = 0, columns, lines;
	char *cp;
	FILE *output = stderr;

	if (ap->head == ap->last)
		return;

	if (paginating) {
		int fds[2];

		if (pipe(fds) < 0) {
			perror(gettext("could not create pipe"));
			goto no_page;
		}

		switch (fork()) {
		case -1:
			perror(gettext("could not fork"));
			goto no_page;
		case 0:
			/*
			 * Make sure final output still ends up in
			 * the same place.
			 */
			(void) dup2(fileno(stderr), fileno(stdout));
			(void) close(fds[0]);
			(void) dup2(fds[1], fileno(stdin));
			execvp(pager_vector[0], pager_vector);
			perror(gettext("execvp of pager failed"));
			exit(1);
			/*NOTREACHED*/
		default:
			(void) close(fds[1]);
			output = fdopen(fds[0], "w");
			if (output != (FILE *)NULL) {
				break;
			}
			perror(gettext("could not open pipe to pager"));
			output = stderr;
		no_page:
			(void) fprintf(stderr,
			    gettext("pagination disabled\n"));
			paginating = 0;
		}
	}

	for (fp = ap->head; fp < ap->last; fp++) {
		fp->ftype = inodetype(fp->fnum);
		np = lookupino(fp->fnum);
		if (np != NIL)
			fp->fflags = np->e_flags;
		else
			fp->fflags = 0;
		len = strlen(fmtentry(fp));
		if (len > width)
			width = len;
	}
	width += 2;
	columns = 80 / width;
	if (columns == 0)
		columns = 1;
	lines = (nentry + columns - 1) / columns;
	for (i = 0; i < lines && !ferror(output); i++) {
		for (j = 0; j < columns && !ferror(output); j++) {
			fp = ap->head + j * lines + i;
			cp = fmtentry(fp);
			(void) fprintf(output, "%s", cp);
			if (fp + lines >= ap->last) {
				(void) fprintf(output, "\n");
				break;
			}
			w = strlen(cp);
			while (w < width) {
				w++;
				if (fprintf(output, " ") < 0)
					break;
			}
		}
	}

	if (paginating) {
		(void) fclose(output);
		(void) wait((int *)NULL);
	}
}

/*
 * Comparison routine for qsort.
 */
static int
fcmp(f1, f2)
	struct afile *f1, *f2;
{

	return (strcoll(f1->fname, f2->fname));
}

/*
 * Format a directory entry.
 */
static char *
fmtentry(fp)
	struct afile *fp;
{
	static char fmtres[MAXCOMPLEXLEN];
	static int precision = 0;
	ino_t i;
	char *cp, *dp, *limit;

	if (!vflag) {
		/* MAXCOMPLEXLEN assumed to be >= 1 */
		fmtres[0] = '\0';
	} else {
		if (precision == 0) {
			for (i = maxino; i != 0; i /= 10)
				precision++;
			if (sizeof (fmtres) < (unsigned)(precision + 2)) {
				(void) fprintf(stderr, gettext(
"\nInternal check failed, minimum width %d exceeds available size %d\n"),
				    (precision + 2), sizeof (fmtres));
				done(1);
			}
		}
		(void) snprintf(fmtres, sizeof (fmtres), "%*ld ",
		    precision, fp->fnum);
	}
	dp = &fmtres[strlen(fmtres)];
	limit = fmtres + sizeof (fmtres) - 1;
	if (dflag && BIT(fp->fnum, dumpmap) == 0)
		*dp++ = '^';
	else if ((fp->fflags & NEW) != 0)
		*dp++ = '*';
	else
		*dp++ = ' ';
	for (cp = fp->fname; *cp && dp < limit; cp++)
		/* LINTED: precedence ok, can't fix system macro */
		if (!vflag && (!ISPRINT(*cp, wp)))
			*dp++ = '?';
		else
			*dp++ = *cp;
	if (fp->ftype == NODE && dp < limit)
		*dp++ = '/';
	*dp++ = 0;
	return (fmtres);
}

/*
 * respond to interrupts
 */
/* ARGSUSED */
void
onintr(sig)
	int	sig;
{
	char	buf[300];

	if (command == 'i' && reset_OK)
		longjmp(reset, 1);

	(void) snprintf(buf, sizeof (buf),
	    gettext("%s interrupted, continue"), progname);
	if (reply(buf) == FAIL)
		done(1);
}
/*
 * Set up pager_catenated and pager_vector.
 */
void
#ifdef __STDC__
initpagercmd(void)
#else
initpagercmd()
#endif
{
	char *cp;

	cp = getenv("PAGER");
	if (cp != NULL)
		pager_catenated = strdup(cp);
	if ((pager_catenated == NULL) || (*pager_catenated == '\0')) {
		if (pager_catenated != NULL)
			free(pager_catenated);
		pager_catenated = strdup(DEF_PAGER);
	}
	if (pager_catenated == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		done(1);
	}

	pager_vector = (char **)malloc(sizeof (char *));
	if (pager_vector == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		done(1);
	}

	pager_len = 1;
	cp = pager_catenated;
	(void) setpagerargs(&cp);
}


/*
 * Resets pager_catenated and pager_vector from user input.
 */
void
#ifdef __STDC__
setpagercmd(void)
#else
setpagercmd()
#endif
{
	uint_t catenate_length;
	int index;

	/*
	 * We'll get called immediately after setting a pager, due to
	 * our interaction with getcmd()'s internal state.  Don't do
	 * anything when that happens.
	 */
	if (*input == '\0')
		return;

	if (pager_len > 0) {
		for (index = 0; pager_vector[index] != (char *)NULL; index += 1)
			free(pager_vector[index]);
		free(pager_vector);
		free(pager_catenated);
	}

	pager_vector = (char **)malloc(2 * sizeof (char *));
	if (pager_vector == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		done(1);
	}

	pager_len = 2;
	pager_vector[0] = strdup(input);
	if (pager_vector[0] == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		done(1);
	}
	if (dflag)
		(void) fprintf(stderr, gettext("got command `%s'\n"), input);
	catenate_length = setpagerargs(&nextarg) + strlen(pager_vector[0]) + 1;
	pager_catenated = (char *)malloc(catenate_length *
		(size_t)sizeof (char));
	if (pager_catenated == (char *)NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		done(1);
	}
	for (index = 0; pager_vector[index] != (char *)NULL; index += 1) {
		if (index > 0)
			(void) strcat(pager_catenated, " ");
		(void) strcat(pager_catenated, pager_vector[index]);
	}
}


/*
 * Extract arguments for the pager command from getcmd()'s input buffer.
 */
static uint_t
setpagerargs(source)
	char	**source;
{
	char	word[MAXCOMPLEXLEN];
	char	*cp = *source;
	uint_t	length = 0;

	while ((cp != (char *)NULL) && (*cp != '\0')) {
		cp = copynext(cp, word, sizeof (word));
		if (dflag)
			fprintf(stderr, gettext("got word `%s'\n"), word);
		pager_vector = (char **)realloc(pager_vector,
			(size_t)sizeof (char *) * (pager_len + 1));
		if (pager_vector == (char **)NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			done(1);
		}
		pager_vector[pager_len - 1] = strdup(word);
		if (pager_vector[pager_len - 1] == (char *)NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			done(1);
		}
		length += strlen(word) + 1;
		pager_len += 1;
	}
	pager_vector[pager_len - 1] = (char *)NULL;
	*source = cp;
	return (length);
}
