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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	main functions
 */

#include <curses.h>	/* stdscr and TRUE */
#include <fcntl.h>	/* O_RDONLY */
#include <sys/types.h>	/* needed by stat.h */
#include <unistd.h>	/* O_RDONLY */
#include <unistd.h>	/* O_RDONLY */
#include <sys/stat.h>	/* stat */
#include <libgen.h>	/* O_RDONLY */
#include "global.h"
#include "version.h"	/* FILEVERSION and FIXVERSION */
#include "vp.h"		/* vpdirs and vpndirs */

#define	OPTSEPS	" \t"	/* CSCOPEOPTION separators */
#define	MINHOURS 4	/* minimum no activity timeout hours */

/* defaults for unset environment variables */
#define	EDITOR	"vi"
#define	SHELL	"sh"
#define	TMPDIR	"/tmp"

/*
 * note: these digraph character frequencies were calculated from possible
 * printable digraphs in the cross-reference for the C compiler
 */
char	dichar1[] = " teisaprnl(of)=c";	/* 16 most frequent first chars */
char	dichar2[] = " tnerpla";		/* 8 most frequent second chars */
					/* using the above as first chars */
char	dicode1[256];		/* digraph first character code */
char	dicode2[256];		/* digraph second character code */

char	*editor, *home, *shell;	/* environment variables */
BOOL	compress = YES;		/* compress the characters in the crossref */
int	cscopedepth;		/* cscope invocation nesting depth */
char	currentdir[PATHLEN + 1]; /* current directory */
BOOL	dbtruncated;		/* database symbols are truncated to 8 chars */
char	**dbvpdirs;		/* directories (including current) in */
				/* database view path */
int	dbvpndirs;		/* # of directories in database view path */
int	dispcomponents = 1;	/* file path components to display */
BOOL	editallprompt = YES;	/* prompt between editing files */
int	fileargc;		/* file argument count */
char	**fileargv;		/* file argument values */
int	fileversion;		/* cross-reference file version */
BOOL	incurses;		/* in curses */
INVCONTROL invcontrol;		/* inverted file control structure */
BOOL	invertedindex;		/* the database has an inverted index */
BOOL	isuptodate;		/* consider the crossref up-to-date */
BOOL	linemode;		/* use line oriented user interface */
char	*namefile;		/* file of file names */
char	*newinvname;		/* new inverted index file name */
char	*newinvpost;		/* new inverted index postings file name */
char	*newreffile;		/* new cross-reference file name */
FILE	*newrefs;		/* new cross-reference */
BOOL	noacttimeout;		/* no activity timeout occurred */
BOOL	ogs;			/* display OGS book and subsystem names */
FILE	*postings;		/* new inverted index postings */
char	*prependpath;		/* prepend path to file names */
BOOL	returnrequired;		/* RETURN required after selection number */
int	symrefs = -1;		/* cross-reference file */
char	temp1[PATHLEN + 1];	/* temporary file name */
char	temp2[PATHLEN + 1];	/* temporary file name */
long	totalterms;		/* total inverted index terms */
BOOL	truncatesyms;		/* truncate symbols to 8 characters */

static	BOOL	buildonly;		/* only build the database */
static	BOOL	fileschanged;		/* assume some files changed */
static	char	*invname = INVNAME;	/* inverted index to the database */
static	char	*invpost = INVPOST;	/* inverted index postings */
static	unsigned noacttime;		/* no activity timeout in seconds */
static	BOOL	onesearch;		/* one search only in line mode */
static	char	*reffile = REFFILE;	/* cross-reference file path name */
static	char	*reflines;		/* symbol reference lines file */
static	char	*tmpdir;		/* temporary directory */
static	long	traileroffset;		/* file trailer offset */
static	BOOL	unconditional;		/* unconditionally build database */

static void options(int argc, char **argv);
static void printusage(void);
static void removeindex(void);
static void cannotindex(void);
static void initcompress(void);
static void opendatabase(void);
static void closedatabase(void);
static void build(void);
static int compare(const void *s1, const void *s2);
static char *getoldfile(void);
static void putheader(char *dir);
static void putlist(char **names, int count);
static BOOL samelist(FILE *oldrefs, char **names, int count);
static void skiplist(FILE *oldrefs);
static void copydata(void);
static void copyinverted(void);
static void putinclude(char *s);
static void movefile(char *new, char *old);
static void timedout(int sig);

int
main(int argc, char **argv)
{
	int	envc;			/* environment argument count */
	char	**envv;			/* environment argument list */
	FILE	*names;			/* name file pointer */
	int	oldnum;			/* number in old cross-ref */
	char	path[PATHLEN + 1];	/* file path */
	FILE	*oldrefs;	/* old cross-reference file */
	char	*s;
	int	c, i;
	pid_t	pid;

	/* save the command name for messages */
	argv0 = basename(argv[0]);

	/* get the current directory for build() and line-oriented P command */
	if (mygetwd(currentdir) == NULL) {
		(void) fprintf(stderr,
		    "cscope: warning: cannot get current directory name\n");
		(void) strcpy(currentdir, "<unknown>");
	}
	/* initialize any view path; (saves time since currendir is known) */
	vpinit(currentdir);
	dbvpndirs = vpndirs; /* number of directories in database view path */
	/* directories (including current) in database view path */
	dbvpdirs = vpdirs;

	/* the first source directory is the current directory */
	sourcedir(".");

	/* read the environment */
	editor = mygetenv("EDITOR", EDITOR);
	editor = mygetenv("VIEWER", editor);	/* use viewer if set */
	home = getenv("HOME");
	shell = mygetenv("SHELL", SHELL);
	tmpdir = mygetenv("TMPDIR", TMPDIR);
	/* increment nesting depth */
	cscopedepth = atoi(mygetenv("CSCOPEDEPTH", "0"));
	(void) sprintf(path, "CSCOPEDEPTH=%d", ++cscopedepth);
	(void) putenv(stralloc(path));
	if ((s = getenv("CSCOPEOPTIONS")) != NULL) {

		/* parse the environment option string */
		envc = 1;
		envv = mymalloc(sizeof (char *));
		s = strtok(stralloc(s), OPTSEPS);
		while (s != NULL) {
			envv = myrealloc(envv, ++envc * sizeof (char *));
			envv[envc - 1] = stralloc(s);
			s = strtok((char *)NULL, OPTSEPS);
		}
		/* set the environment options */
		options(envc, envv);
	}
	/* set the command line options */
	options(argc, argv);

	/* create the temporary file names */
	pid = getpid();
	(void) sprintf(temp1, "%s/cscope%d.1", tmpdir, (int)pid);
	(void) sprintf(temp2, "%s/cscope%d.2", tmpdir, (int)pid);

	/* if running in the foreground */
	if (signal(SIGINT, SIG_IGN) != SIG_IGN) {

		/* cleanup on the interrupt and quit signals */
		(void) signal(SIGINT, myexit);
		(void) signal(SIGQUIT, myexit);
	}

	/* cleanup on the hangup signal */
	(void) signal(SIGHUP, myexit);
	/* if the database path is relative and it can't be created */
	if (reffile[0] != '/' && access(".", WRITE) != 0) {

		/* if the database may not be up-to-date or can't be read */
		(void) sprintf(path, "%s/%s", home, reffile);
		if (isuptodate == NO || access(reffile, READ) != 0) {

			/* put it in the home directory */
			reffile = stralloc(path);
			(void) sprintf(path, "%s/%s", home, invname);
			invname = stralloc(path);
			(void) sprintf(path, "%s/%s", home, invpost);
			invpost = stralloc(path);
			(void) fprintf(stderr,
			    "cscope: symbol database will be %s\n", reffile);
		}
	}
	/* if the cross-reference is to be considered up-to-date */
	if (isuptodate == YES) {
		if ((oldrefs = vpfopen(reffile, "r")) == NULL) {
			cannotopen(reffile);
			exit(1);
		}
		/*
		 * get the crossref file version but skip the current
		 * directory
		 */
		if (fscanf(oldrefs, "cscope %d %*s", &fileversion) != 1) {
			(void) fprintf(stderr,
			    "cscope: cannot read file version from file %s\n",
			    reffile);
			exit(1);
		}
		if (fileversion >= 8) {

			/* override these command line options */
			compress = YES;
			invertedindex = NO;

			/* see if there are options in the database */
			for (;;) {
				/* no -q leaves multiple blanks */
				while ((c = getc(oldrefs)) == ' ') {
					;
				}
				if (c != '-') {
					(void) ungetc(c, oldrefs);
					break;
				}
				switch (c = getc(oldrefs)) {
				case 'c':	/* ASCII characters only */
					compress = NO;
					break;
				case 'q':	/* quick search */
					invertedindex = YES;
					(void) fscanf(oldrefs,
					    "%ld", &totalterms);
					break;
				case 'T':
					/* truncate symbols to 8 characters */
					dbtruncated = YES;
					truncatesyms = YES;
					break;
				}
			}
			initcompress();

			/* seek to the trailer */
			if (fscanf(oldrefs, "%ld", &traileroffset) != 1) {
				(void) fprintf(stderr,
				    "cscope: cannot read trailer offset from "
				    "file %s\n", reffile);
				exit(1);
			}
			if (fseek(oldrefs, traileroffset, 0) != 0) {
				(void) fprintf(stderr,
				    "cscope: cannot seek to trailer in "
				    "file %s\n", reffile);
				exit(1);
			}
		}
		/*
		 * read the view path for use in converting relative paths to
		 * full paths
		 *
		 * note: don't overwrite vp[n]dirs because this can cause
		 * the wrong database index files to be found in the viewpath
		 */
		if (fileversion >= 13) {
			if (fscanf(oldrefs, "%d", &dbvpndirs) != 1) {
				(void) fprintf(stderr,
				    "cscope: cannot read view path size from "
				    "file %s\n", reffile);
				exit(1);
			}
			if (dbvpndirs > 0) {
				dbvpdirs = mymalloc(
				    dbvpndirs * sizeof (char *));
				for (i = 0; i < dbvpndirs; ++i) {
					if (fscanf(oldrefs, "%s", path) != 1) {
						(void) fprintf(stderr,
						    "cscope: cannot read view "
						    "path from file %s\n",
						    reffile);
						exit(1);
					}
					dbvpdirs[i] = stralloc(path);
				}
			}
		}
		/* skip the source and include directory lists */
		skiplist(oldrefs);
		skiplist(oldrefs);

		/* get the number of source files */
		if (fscanf(oldrefs, "%d", &nsrcfiles) != 1) {
			(void) fprintf(stderr,
			    "cscope: cannot read source file size from "
			    "file %s\n", reffile);
			exit(1);
		}
		/* get the source file list */
		srcfiles = mymalloc(nsrcfiles * sizeof (char *));
		if (fileversion >= 9) {

			/* allocate the string space */
			if (fscanf(oldrefs, "%d", &oldnum) != 1) {
				(void) fprintf(stderr,
				    "cscope: cannot read string space size "
				    "from file %s\n", reffile);
				exit(1);
			}
			s = mymalloc(oldnum);
			(void) getc(oldrefs);	/* skip the newline */

			/* read the strings */
			if (fread(s, oldnum, 1, oldrefs) != 1) {
				(void) fprintf(stderr,
				    "cscope: cannot read source file names "
				    "from file %s\n", reffile);
				exit(1);
			}
			/* change newlines to nulls */
			for (i = 0; i < nsrcfiles; ++i) {
				srcfiles[i] = s;
				for (++s; *s != '\n'; ++s) {
					;
				}
				*s = '\0';
				++s;
			}
			/* if there is a file of source file names */
			if (namefile != NULL &&
			    (names = vpfopen(namefile, "r")) != NULL ||
			    (names = vpfopen(NAMEFILE, "r")) != NULL) {

				/* read any -p option from it */
				while (fscanf(names, "%s", path) == 1 &&
				    *path == '-') {
					i = path[1];
					s = path + 2;	/* for "-Ipath" */
					if (*s == '\0') {
						/* if "-I path" */
						(void) fscanf(names,
						    "%s", path);
						s = path;
					}
					switch (i) {
					case 'p':
						/* file path components */
						/* to display */
						if (*s < '0' || *s > '9') {
							(void) fprintf(stderr,
							    "cscope: -p option "
							    "in file %s: "
							    "missing or "
							    "invalid numeric "
							    "value\n",
							    namefile);
						}
						dispcomponents = atoi(s);
					}
				}
				(void) fclose(names);
			}
		} else {
			for (i = 0; i < nsrcfiles; ++i) {
				if (fscanf(oldrefs, "%s", path) != 1) {
					(void) fprintf(stderr,
					    "cscope: cannot read source file "
					    "name from file %s\n", reffile);
					exit(1);
				}
				srcfiles[i] = stralloc(path);
			}
		}
		(void) fclose(oldrefs);
	} else {
		/* get source directories from the environment */
		if ((s = getenv("SOURCEDIRS")) != NULL) {
			sourcedir(s);
		}
		/* make the source file list */
		srcfiles = mymalloc(msrcfiles * sizeof (char *));
		makefilelist();
		if (nsrcfiles == 0) {
			(void) fprintf(stderr,
			    "cscope: no source files found\n");
			printusage();
			exit(1);
		}
		/* get include directories from the environment */
		if ((s = getenv("INCLUDEDIRS")) != NULL) {
			includedir(s);
		}
		/* add /usr/include to the #include directory list */
		includedir("/usr/include");

		/* initialize the C keyword table */
		initsymtab();

		/* create the file name(s) used for a new cross-reference */
		(void) strcpy(path, reffile);
		s = basename(path);
		*s = '\0';
		(void) strcat(path, "n");
		++s;
		(void) strcpy(s, basename(reffile));
		newreffile = stralloc(path);
		(void) strcpy(s, basename(invname));
		newinvname = stralloc(path);
		(void) strcpy(s, basename(invpost));
		newinvpost = stralloc(path);

		/* build the cross-reference */
		initcompress();
		build();
		if (buildonly == YES) {
			exit(0);
		}
	}
	opendatabase();

	/*
	 * removing a database will not release the disk space if a cscope
	 * process has the file open, so a project may want unattended cscope
	 * processes to exit overnight, including their subshells and editors
	 */
	if (noacttime) {
		(void) signal(SIGALRM, timedout);
		(void) alarm(noacttime);
	}
	/*
	 * if using the line oriented user interface so cscope can be a
	 * subprocess to emacs or samuel
	 */
	if (linemode == YES) {
		if (*pattern != '\0') {		/* do any optional search */
			if (search() == YES) {
				while ((c = getc(refsfound)) != EOF) {
					(void) putchar(c);
				}
			}
		}
		if (onesearch == YES) {
			myexit(0);
		}
		for (;;) {
			char buf[PATLEN + 2];
			if (noacttime) {
				(void) alarm(noacttime);
			}
			(void) printf(">> ");
			(void) fflush(stdout);
			if (fgets(buf, sizeof (buf), stdin) == NULL) {
				myexit(0);
			}
			/* remove any trailing newline character */
			if (*(s = buf + strlen(buf) - 1) == '\n') {
				*s = '\0';
			}
			switch (*buf) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':	/* samuel only */
				field = *buf - '0';
				(void) strcpy(pattern, buf + 1);
				(void) search();
				(void) printf("cscope: %d lines\n", totallines);
				while ((c = getc(refsfound)) != EOF) {
					(void) putchar(c);
				}
				break;

			case 'c':	/* toggle caseless mode */
			case ctrl('C'):
				if (caseless == NO) {
					caseless = YES;
				} else {
					caseless = NO;
				}
				egrepcaseless(caseless);
				break;

			case 'r':	/* rebuild database cscope style */
			case ctrl('R'):
				freefilelist();
				makefilelist();
				/* FALLTHROUGH */

			case 'R':	/* rebuild database samuel style */
				rebuild();
				(void) putchar('\n');
				break;

			case 'C':	/* clear file names */
				freefilelist();
				(void) putchar('\n');
				break;

			case 'F':	/* add a file name */
				(void) strcpy(path, buf + 1);
				if (infilelist(path) == NO &&
				    vpaccess(path, READ) == 0) {
					addsrcfile(path);
				}
				(void) putchar('\n');
				break;

			case 'P':	/* print the path to the files */
				if (prependpath != NULL) {
					(void) puts(prependpath);
				} else {
					(void) puts(currentdir);
				}
				break;

			case 'q':	/* quit */
			case ctrl('D'):
			case ctrl('Z'):
				myexit(0);

			default:
				(void) fprintf(stderr,
				    "cscope: unknown command '%s'\n", buf);
				break;
			}
		}
		/* NOTREACHED */
	}
	/* pause before clearing the screen if there have been error messages */
	if (errorsfound == YES) {
		errorsfound = NO;
		askforreturn();
	}
	(void) signal(SIGINT, SIG_IGN);	/* ignore interrupts */
	(void) signal(SIGPIPE, SIG_IGN); /* | command can cause pipe signal */
	/* initialize the curses display package */
	(void) initscr();	/* initialize the screen */
	setfield();	/* set the initial cursor position */
	entercurses();
	(void) keypad(stdscr, TRUE);	/* enable the keypad */
	dispinit();	/* initialize display parameters */
	putmsg("");	/* clear any build progress message */
	display();	/* display the version number and input fields */

	/* do any optional search */
	if (*pattern != '\0') {
		atfield();		/* move to the input field */
		(void) command(ctrl('A'));	/* search */
		display();		/* update the display */
	} else if (reflines != NULL) {
		/* read any symbol reference lines file */
		(void) readrefs(reflines);
		display();		/* update the display */
	}
	for (;;) {
		if (noacttime) {
			(void) alarm(noacttime);
		}
		atfield();	/* move to the input field */

		/* exit if the quit command is entered */
		if ((c = mygetch()) == EOF || c == ctrl('D') ||
		    c == ctrl('Z')) {
			break;
		}
		/* execute the commmand, updating the display if necessary */
		if (command(c) == YES) {
			display();
		}
	}
	/* cleanup and exit */
	myexit(0);
	/* NOTREACHED */
	return (0);
}

static void
options(int argc, char **argv)
{
	char	path[PATHLEN + 1];	/* file path */
	int	c;
	char	*s;

	while (--argc > 0 && (*++argv)[0] == '-') {
		for (s = argv[0] + 1; *s != '\0'; s++) {
			/* look for an input field number */
			if (isdigit(*s)) {
				field = *s - '0';
				if (*++s == '\0' && --argc > 0) {
					s = *++argv;
				}
				if (strlen(s) > PATLEN) {
					(void) fprintf(stderr,
					    "cscope: pattern too long, cannot "
					    "be > %d characters\n", PATLEN);
					exit(1);
				}
				(void) strcpy(pattern, s);
				goto nextarg;
			}
			switch (*s) {
			case '-':	/* end of options */
				--argc;
				++argv;
				goto lastarg;
			case 'V':	/* print the version number */
				(void) fprintf(stderr,
				    "%s: version %d%s\n", argv0,
				    FILEVERSION, FIXVERSION);
				exit(0);
				/*NOTREACHED*/
			case 'b':	/* only build the cross-reference */
				buildonly = YES;
				break;
			case 'c':	/* ASCII characters only in crossref */
				compress = NO;
				break;
			case 'C':
				/* turn on caseless mode for symbol searches */
				caseless = YES;
				/* simulate egrep -i flag */
				egrepcaseless(caseless);
				break;
			case 'd':	/* consider crossref up-to-date */
				isuptodate = YES;
				break;
			case 'e':	/* suppress ^E prompt between files */
				editallprompt = NO;
				break;
			case 'L':
				onesearch = YES;
				/* FALLTHROUGH */
			case 'l':
				linemode = YES;
				break;
			case 'o':
				/* display OGS book and subsystem names */
				ogs = YES;
				break;
			case 'q':	/* quick search */
				invertedindex = YES;
				break;
			case 'r':	/* display as many lines as possible */
				returnrequired = YES;
				break;
			case 'T':	/* truncate symbols to 8 characters */
				truncatesyms = YES;
				break;
			case 'u':
				/* unconditionally build the cross-reference */
				unconditional = YES;
				break;
			case 'U':	/* assume some files have changed */
				fileschanged = YES;
				break;
			case 'f':	/* alternate cross-reference file */
			case 'F':	/* symbol reference lines file */
			case 'i':	/* file containing file names */
			case 'I':	/* #include file directory */
			case 'p':	/* file path components to display */
			case 'P':	/* prepend path to file names */
			case 's':	/* additional source file directory */
			case 'S':
			case 't':	/* no activity timeout in hours */
				c = *s;
				if (*++s == '\0' && --argc > 0) {
					s = *++argv;
				}
				if (*s == '\0') {
					(void) fprintf(stderr,
					    "%s: -%c option: missing or empty "
					    "value\n", argv0, c);
					goto usage;
				}
				switch (c) {
				case 'f':
					/* alternate cross-reference file */
					reffile = s;
					(void) strcpy(path, s);
					/* System V has a 14 character limit */
					s = basename(path);
					if ((int)strlen(s) > 11) {
						s[11] = '\0';
					}
					s = path + strlen(path);
					(void) strcpy(s, ".in");
					invname = stralloc(path);
					(void) strcpy(s, ".po");
					invpost = stralloc(path);
					break;
				case 'F':
					/* symbol reference lines file */
					reflines = s;
					break;
				case 'i':	/* file containing file names */
					namefile = s;
					break;
				case 'I':	/* #include file directory */
					includedir(s);
					break;
				case 'p':
					/* file path components to display */
					if (*s < '0' || *s > '9') {
						(void) fprintf(stderr,
						    "%s: -p option: missing "
						    "or invalid numeric "
						    "value\n", argv0);
						goto usage;
					}
					dispcomponents = atoi(s);
					break;
				case 'P':	/* prepend path to file names */
					prependpath = s;
					break;
				case 's':
				case 'S':
					/* additional source directory */
					sourcedir(s);
					break;
				case 't':
					/* no activity timeout in hours */
					if (*s < '1' || *s > '9') {
						(void) fprintf(stderr,
						    "%s: -t option: missing or "
						    "invalid numeric value\n",
						    argv0);
						goto usage;
					}
					c = atoi(s);
					if (c < MINHOURS) {
						(void) fprintf(stderr,
						    "cscope: minimum timeout "
						    "is %d hours\n", MINHOURS);
						(void) sleep(3);
						c = MINHOURS;
					}
					noacttime = c * 3600;
					break;
				}
				goto nextarg;
			default:
				(void) fprintf(stderr,
				    "%s: unknown option: -%c\n", argv0, *s);
			usage:
				printusage();
				exit(1);
			}
		}
nextarg:	continue;
	}
lastarg:
	/* save the file arguments */
	fileargc = argc;
	fileargv = argv;
}

static void
printusage(void)
{
	(void) fprintf(stderr,
	    "Usage:  cscope [-bcdelLoqrtTuUV] [-f file] [-F file] [-i file] "
	    "[-I dir] [-s dir]\n");
	(void) fprintf(stderr,
	    "               [-p number] [-P path] [-[0-8] pattern] "
	    "[source files]\n");
	(void) fprintf(stderr,
	    "-b		Build the database only.\n");
	(void) fprintf(stderr,
	    "-c		Use only ASCII characters in the database file, "
	    "that is,\n");
	(void) fprintf(stderr,
	    "		do not compress the data.\n");
	(void) fprintf(stderr,
	    "-d		Do not update the database.\n");
	(void) fprintf(stderr,
	    "-f \"file\"	Use \"file\" as the database file name "
	    "instead of\n");
	(void) fprintf(stderr,
	    "		the default (cscope.out).\n");
	(void) fprintf(stderr,
	    "-F \"file\"	Read symbol reference lines from file, just\n");
/* BEGIN CSTYLED */
	(void) fprintf(stderr,
	    "		like the \"<\" command.\n");
/* END CSTYLED */
	(void) fprintf(stderr,
	    "-i \"file\"	Read any -I, -p, -q, and -T options and the\n");
	(void) fprintf(stderr,
	    "		list of source files from \"file\" instead of the \n");
	(void) fprintf(stderr,
	    "		default (cscope.files).\n");
	(void) fprintf(stderr,
	    "-I \"dir\"	Look in \"dir\" for #include files.\n");
	(void) fprintf(stderr,
	    "-q		Build an inverted index for quick symbol seaching.\n");
	(void) fprintf(stderr,
	    "-s \"dir\"	Look in \"dir\" for additional source files.\n");
}

static void
removeindex(void)
{
	(void) fprintf(stderr,
	    "cscope: removed files %s and %s\n", invname, invpost);
	(void) unlink(invname);
	(void) unlink(invpost);
}

static void
cannotindex(void)
{
	(void) fprintf(stderr,
	    "cscope: cannot create inverted index; ignoring -q option\n");
	invertedindex = NO;
	errorsfound = YES;
	(void) fprintf(stderr,
	    "cscope: removed files %s and %s\n", newinvname, newinvpost);
	(void) unlink(newinvname);
	(void) unlink(newinvpost);
	removeindex();	/* remove any existing index to prevent confusion */
}

void
cannotopen(char *file)
{
	char	msg[MSGLEN + 1];

	(void) sprintf(msg, "Cannot open file %s", file);
	putmsg(msg);
}

void
cannotwrite(char *file)
{
	char	msg[MSGLEN + 1];

	(void) sprintf(msg, "Removed file %s because write failed", file);
	myperror(msg);	/* display the reason */
	(void) unlink(file);
	myexit(1);	/* calls exit(2), which closes files */
}

/* set up the digraph character tables for text compression */

static void
initcompress(void)
{
	int	i;

	if (compress == YES) {
		for (i = 0; i < 16; ++i) {
			dicode1[(unsigned)(dichar1[i])] = i * 8 + 1;
		}
		for (i = 0; i < 8; ++i) {
			dicode2[(unsigned)(dichar2[i])] = i + 1;
		}
	}
}

/* open the database */

static void
opendatabase(void)
{
	if ((symrefs = vpopen(reffile, O_RDONLY)) == -1) {
		cannotopen(reffile);
		myexit(1);
	}
	blocknumber = -1;	/* force next seek to read the first block */

	/* open any inverted index */
	if (invertedindex == YES &&
	    invopen(&invcontrol, invname, invpost, INVAVAIL) == -1) {
		askforreturn();		/* so user sees message */
		invertedindex = NO;
	}
}

/* close the database */

static void
closedatabase(void)
{
	(void) close(symrefs);
	if (invertedindex == YES) {
		invclose(&invcontrol);
		nsrcoffset = 0;
		npostings = 0;
	}
}

/* rebuild the database */

void
rebuild(void)
{
	closedatabase();
	build();
	opendatabase();

	/* revert to the initial display */
	if (refsfound != NULL) {
		(void) fclose(refsfound);
		refsfound = NULL;
	}
	*lastfilepath = '\0';	/* last file may have new path */
}

/* build the cross-reference */

static void
build(void)
{
	int	i;
	FILE	*oldrefs;	/* old cross-reference file */
	time_t	reftime;	/* old crossref modification time */
	char	*file;			/* current file */
	char	*oldfile;		/* file in old cross-reference */
	char	newdir[PATHLEN + 1];	/* directory in new cross-reference */
	char	olddir[PATHLEN + 1];	/* directory in old cross-reference */
	char	oldname[PATHLEN + 1];	/* name in old cross-reference */
	int	oldnum;			/* number in old cross-ref */
	struct	stat statstruct;	/* file status */
	int	firstfile;		/* first source file in pass */
	int	lastfile;		/* last source file in pass */
	int	built = 0;		/* built crossref for these files */
	int	copied = 0;		/* copied crossref for these files */
	BOOL	interactive = YES;	/* output progress messages */

	/*
	 * normalize the current directory relative to the home directory so
	 * the cross-reference is not rebuilt when the user's login is moved
	 */
	(void) strcpy(newdir, currentdir);
	if (strcmp(currentdir, home) == 0) {
		(void) strcpy(newdir, "$HOME");
	} else if (strncmp(currentdir, home, strlen(home)) == 0) {
		(void) sprintf(newdir, "$HOME%s", currentdir + strlen(home));
	}
	/* sort the source file names (needed for rebuilding) */
	qsort((char *)srcfiles, (unsigned)nsrcfiles, sizeof (char *), compare);

	/*
	 * if there is an old cross-reference and its current directory
	 * matches or this is an unconditional build
	 */
	if ((oldrefs = vpfopen(reffile, "r")) != NULL && unconditional == NO &&
	    fscanf(oldrefs, "cscope %d %s", &fileversion, olddir) == 2 &&
	    (strcmp(olddir, currentdir) == 0 || /* remain compatible */
	    strcmp(olddir, newdir) == 0)) {

		/* get the cross-reference file's modification time */
		(void) fstat(fileno(oldrefs), &statstruct);
		reftime = statstruct.st_mtime;
		if (fileversion >= 8) {
			BOOL	oldcompress = YES;
			BOOL	oldinvertedindex = NO;
			BOOL	oldtruncatesyms = NO;
			int	c;

			/* see if there are options in the database */
			for (;;) {
				while ((c = getc(oldrefs)) == ' ') {
				}
				if (c != '-') {
					(void) ungetc(c, oldrefs);
					break;
				}
				switch (c = getc(oldrefs)) {
				case 'c':	/* ASCII characters only */
					oldcompress = NO;
					break;
				case 'q':	/* quick search */
					oldinvertedindex = YES;
					(void) fscanf(oldrefs,
					    "%ld", &totalterms);
					break;
				case 'T':
					/* truncate symbols to 8 characters */
					oldtruncatesyms = YES;
					break;
				}
			}
			/* check the old and new option settings */
			if (oldcompress != compress ||
			    oldtruncatesyms != truncatesyms) {
				(void) fprintf(stderr,
				    "cscope: -c or -T option mismatch between "
				    "command line and old symbol database\n");
				goto force;
			}
			if (oldinvertedindex != invertedindex) {
				(void) fprintf(stderr,
				    "cscope: -q option mismatch between "
				    "command line and old symbol database\n");
				if (invertedindex == NO) {
					removeindex();
				}
				goto outofdate;
			}
			/* seek to the trailer */
			if (fscanf(oldrefs, "%ld", &traileroffset) != 1 ||
			    fseek(oldrefs, traileroffset, 0) == -1) {
				(void) fprintf(stderr,
				    "cscope: incorrect symbol database file "
				    "format\n");
				goto force;
			}
		}
		/* if assuming that some files have changed */
		if (fileschanged == YES) {
			goto outofdate;
		}
		/* see if the view path is the same */
		if (fileversion >= 13 &&
		    samelist(oldrefs, vpdirs, vpndirs) == NO) {
			goto outofdate;
		}
		/* see if the directory lists are the same */
		if (samelist(oldrefs, srcdirs, nsrcdirs) == NO ||
		    samelist(oldrefs, incdirs, nincdirs) == NO ||
		    fscanf(oldrefs, "%d", &oldnum) != 1 ||
		    fileversion >= 9 && fscanf(oldrefs, "%*s") != 0) {
			/* skip the string space size */
			goto outofdate;
		}
		/*
		 * see if the list of source files is the same and
		 * none have been changed up to the included files
		 */
		for (i = 0; i < nsrcfiles; ++i) {
			if (fscanf(oldrefs, "%s", oldname) != 1 ||
			    strnotequal(oldname, srcfiles[i]) ||
			    vpstat(srcfiles[i], &statstruct) != 0 ||
			    statstruct.st_mtime > reftime) {
				goto outofdate;
			}
		}
		/* the old cross-reference is up-to-date */
		/* so get the list of included files */
		while (i++ < oldnum && fscanf(oldrefs, "%s", oldname) == 1) {
			addsrcfile(oldname);
		}
		(void) fclose(oldrefs);
		return;

outofdate:
		/* if the database format has changed, rebuild it all */
		if (fileversion != FILEVERSION) {
			(void) fprintf(stderr,
			    "cscope: converting to new symbol database file "
			    "format\n");
			goto force;
		}
		/* reopen the old cross-reference file for fast scanning */
		if ((symrefs = vpopen(reffile, O_RDONLY)) == -1) {
			cannotopen(reffile);
			myexit(1);
		}
		/* get the first file name in the old cross-reference */
		blocknumber = -1;
		(void) readblock();	/* read the first cross-ref block */
		(void) scanpast('\t');	/* skip the header */
		oldfile = getoldfile();
	} else {	/* force cross-referencing of all the source files */
force:
		reftime = 0;
		oldfile = NULL;
	}
	/* open the new cross-reference file */
	if ((newrefs = fopen(newreffile, "w")) == NULL) {
		cannotopen(newreffile);
		myexit(1);
	}
	if (invertedindex == YES && (postings = fopen(temp1, "w")) == NULL) {
		cannotopen(temp1);
		cannotindex();
	}
	(void) fprintf(stderr, "cscope: building symbol database\n");
	putheader(newdir);
	fileversion = FILEVERSION;
	if (buildonly == YES && !isatty(0)) {
		interactive = NO;
	} else {
		initprogress();
	}
	/* output the leading tab expected by crossref() */
	dbputc('\t');

	/*
	 * make passes through the source file list until the last level of
	 * included files is processed
	 */
	firstfile = 0;
	lastfile = nsrcfiles;
	if (invertedindex == YES) {
		srcoffset = mymalloc((nsrcfiles + 1) * sizeof (long));
	}
	for (;;) {

		/* get the next source file name */
		for (fileindex = firstfile; fileindex < lastfile; ++fileindex) {
			/* display the progress about every three seconds */
			if (interactive == YES && fileindex % 10 == 0) {
				if (copied == 0) {
					progress("%ld files built",
					    (long)built, 0L);
				} else {
					progress("%ld files built, %ld "
					    "files copied", (long)built,
					    (long)copied);
				}
			}
			/* if the old file has been deleted get the next one */
			file = srcfiles[fileindex];
			while (oldfile != NULL && strcmp(file, oldfile) > 0) {
				oldfile = getoldfile();
			}
			/*
			 * if there isn't an old database or this is
			 * a new file
			 */
			if (oldfile == NULL || strcmp(file, oldfile) < 0) {
				crossref(file);
				++built;
			} else if (vpstat(file, &statstruct) == 0 &&
			    statstruct.st_mtime > reftime) {
				/* if this file was modified */
				crossref(file);
				++built;

				/*
				 * skip its old crossref so modifying the last
				 * source file does not cause all included files
				 * to be built.  Unfortunately a new file that
				 * is alphabetically last will cause all
				 * included files to be built, but this is
				 * less likely
				 */
				oldfile = getoldfile();
			} else {	/* copy its cross-reference */
				putfilename(file);
				if (invertedindex == YES) {
					copyinverted();
				} else {
					copydata();
				}
				++copied;
				oldfile = getoldfile();
			}
		}
		/* see if any included files were found */
		if (lastfile == nsrcfiles) {
			break;
		}
		firstfile = lastfile;
		lastfile = nsrcfiles;
		if (invertedindex == YES) {
			srcoffset = myrealloc(srcoffset,
			    (nsrcfiles + 1) * sizeof (long));
		}
		/* sort the included file names */
		qsort((char *)&srcfiles[firstfile],
		    (unsigned)(lastfile - firstfile), sizeof (char *), compare);
	}
	/* add a null file name to the trailing tab */
	putfilename("");
	dbputc('\n');

	/* get the file trailer offset */

	traileroffset = dboffset;

	/*
	 * output the view path and source and include directory and
	 * file lists
	 */
	putlist(vpdirs, vpndirs);
	putlist(srcdirs, nsrcdirs);
	putlist(incdirs, nincdirs);
	putlist(srcfiles, nsrcfiles);
	if (fflush(newrefs) == EOF) {
		/* rewind doesn't check for write failure */
		cannotwrite(newreffile);
		/* NOTREACHED */
	}
	/* create the inverted index if requested */
	if (invertedindex == YES) {
		char	sortcommand[PATHLEN + 1];

		if (fflush(postings) == EOF) {
			cannotwrite(temp1);
			/* NOTREACHED */
		}
		(void) fstat(fileno(postings), &statstruct);
		(void) fprintf(stderr,
		    "cscope: building symbol index: temporary file size is "
		    "%ld bytes\n", statstruct.st_size);
		(void) fclose(postings);
	/*
	 * sort -T is broken until it is fixed we don't have too much choice
	 */
	/*
	 * (void) sprintf(sortcommand, "sort -y -T %s %s", tmpdir, temp1);
	 */
	(void) sprintf(sortcommand, "LC_ALL=C sort %s", temp1);
		if ((postings = popen(sortcommand, "r")) == NULL) {
			(void) fprintf(stderr,
			    "cscope: cannot open pipe to sort command\n");
			cannotindex();
		} else {
			if ((totalterms = invmake(newinvname, newinvpost,
			    postings)) > 0) {
				movefile(newinvname, invname);
				movefile(newinvpost, invpost);
			} else {
				cannotindex();
			}
			(void) pclose(postings);
		}
		(void) unlink(temp1);
		(void) free(srcoffset);
		(void) fprintf(stderr,
		    "cscope: index has %ld references to %ld symbols\n",
		    npostings, totalterms);
	}
	/* rewrite the header with the trailer offset and final option list */
	rewind(newrefs);
	putheader(newdir);
	(void) fclose(newrefs);

	/* close the old database file */
	if (symrefs >= 0) {
		(void) close(symrefs);
	}
	if (oldrefs != NULL) {
		(void) fclose(oldrefs);
	}
	/* replace it with the new database file */
	movefile(newreffile, reffile);
}

/* string comparison function for qsort */

static int
compare(const void *s1, const void *s2)
{
	return (strcmp((char *)s1, (char *)s2));
}

/* get the next file name in the old cross-reference */

static char *
getoldfile(void)
{
	static	char	file[PATHLEN + 1];	/* file name in old crossref */

	if (blockp != NULL) {
		do {
			if (*blockp == NEWFILE) {
				skiprefchar();
				getstring(file);
				if (file[0] != '\0') {
					/* if not end-of-crossref */
					return (file);
				}
				return (NULL);
			}
		} while (scanpast('\t') != NULL);
	}
	return (NULL);
}

/*
 * output the cscope version, current directory, database format options, and
 * the database trailer offset
 */

static void
putheader(char *dir)
{
	dboffset = fprintf(newrefs, "cscope %d %s", FILEVERSION, dir);
	if (compress == NO) {
		dboffset += fprintf(newrefs, " -c");
	}
	if (invertedindex == YES) {
		dboffset += fprintf(newrefs, " -q %.10ld", totalterms);
	} else {
		/*
		 * leave space so if the header is overwritten without -q
		 * because writing the inverted index failed, the header is
		 * the same length
		 */
		dboffset += fprintf(newrefs, "              ");
	}
	if (truncatesyms == YES) {
		dboffset += fprintf(newrefs, " -T");
	}
	dbfprintf(newrefs, " %.10ld\n", traileroffset);
}

/* put the name list into the cross-reference file */

static void
putlist(char **names, int count)
{
	int	i, size = 0;

	(void) fprintf(newrefs, "%d\n", count);
	if (names == srcfiles) {

		/* calculate the string space needed */
		for (i = 0; i < count; ++i) {
			size += strlen(names[i]) + 1;
		}
		(void) fprintf(newrefs, "%d\n", size);
	}
	for (i = 0; i < count; ++i) {
		if (fputs(names[i], newrefs) == EOF ||
		    putc('\n', newrefs) == EOF) {
			cannotwrite(newreffile);
			/* NOTREACHED */
		}
	}
}

/* see if the name list is the same in the cross-reference file */

static BOOL
samelist(FILE *oldrefs, char **names, int count)
{
	char	oldname[PATHLEN + 1];	/* name in old cross-reference */
	int	oldcount;
	int	i;

	/* see if the number of names is the same */
	if (fscanf(oldrefs, "%d", &oldcount) != 1 ||
	    oldcount != count) {
		return (NO);
	}
	/* see if the name list is the same */
	for (i = 0; i < count; ++i) {
		if (fscanf(oldrefs, "%s", oldname) != 1 ||
		    strnotequal(oldname, names[i])) {
			return (NO);
		}
	}
	return (YES);
}

/* skip the list in the cross-reference file */

static void
skiplist(FILE *oldrefs)
{
	int	i;

	if (fscanf(oldrefs, "%d", &i) != 1) {
		(void) fprintf(stderr,
		    "cscope: cannot read list size from file %s\n", reffile);
		exit(1);
	}
	while (--i >= 0) {
		if (fscanf(oldrefs, "%*s") != 0) {
			(void) fprintf(stderr,
			    "cscope: cannot read list name from file %s\n",
			    reffile);
			exit(1);
		}
	}
}

/* copy this file's symbol data */

static void
copydata(void)
{
	char	symbol[PATLEN + 1];
	char	*cp;

	setmark('\t');
	cp = blockp;
	for (;;) {
		/* copy up to the next \t */
		do {	/* innermost loop optimized to only one test */
			while (*cp != '\t') {
				dbputc(*cp++);
			}
		} while (*++cp == '\0' && (cp = readblock()) != NULL);
		dbputc('\t');	/* copy the tab */

		/* get the next character */
		if (*(cp + 1) == '\0') {
			cp = readblock();
		}
		/* exit if at the end of this file's data */
		if (cp == NULL || *cp == NEWFILE) {
			break;
		}
		/* look for an #included file */
		if (*cp == INCLUDE) {
			blockp = cp;
			putinclude(symbol);
			putstring(symbol);
			setmark('\t');
			cp = blockp;
		}
	}
	blockp = cp;
}

/* copy this file's symbol data and output the inverted index postings */

static void
copyinverted(void)
{
	char	*cp;
	int	c;
	int	type;	/* reference type (mark character) */
	char	symbol[PATLEN + 1];

	/* note: this code was expanded in-line for speed */
	/* while (scanpast('\n') != NULL) { */
	/* other macros were replaced by code using cp instead of blockp */
	cp = blockp;
	for (;;) {
		setmark('\n');
		do {	/* innermost loop optimized to only one test */
			while (*cp != '\n') {
				dbputc(*cp++);
			}
		} while (*++cp == '\0' && (cp = readblock()) != NULL);
		dbputc('\n');	/* copy the newline */

		/* get the next character */
		if (*(cp + 1) == '\0') {
			cp = readblock();
		}
		/* exit if at the end of this file's data */
		if (cp == NULL) {
			break;
		}
		switch (*cp) {
		case '\n':
			lineoffset = dboffset + 1;
			continue;
		case '\t':
			dbputc('\t');
			blockp = cp;
			type = getrefchar();
			switch (type) {
			case NEWFILE:		/* file name */
				return;
			case INCLUDE:		/* #included file */
				putinclude(symbol);
				goto output;
			}
			dbputc(type);
			skiprefchar();
			getstring(symbol);
			goto output;
		}
		c = *cp;
		if (c & 0200) {	/* digraph char? */
			c = dichar1[(c & 0177) / 8];
		}
		/* if this is a symbol */
		if (isalpha(c) || c == '_') {
			blockp = cp;
			getstring(symbol);
			type = ' ';
		output:
			putposting(symbol, type);
			putstring(symbol);
			if (blockp == NULL) {
				return;
			}
			cp = blockp;
		}
	}
	blockp = cp;
}

/* process the #included file in the old database */

static void
putinclude(char *s)
{
	dbputc(INCLUDE);
	skiprefchar();
	getstring(s);
	incfile(s + 1, *s);
}

/* replace the old file with the new file */

static void
movefile(char *new, char *old)
{
	(void) unlink(old);
	if (link(new, old) == -1) {
		(void) perror("cscope");
		(void) fprintf(stderr,
		    "cscope: cannot link file %s to file %s\n", new, old);
		myexit(1);
	}
	if (unlink(new) == -1) {
		(void) perror("cscope");
		(void) fprintf(stderr, "cscope: cannot unlink file %s\n", new);
		errorsfound = YES;
	}
}

/* enter curses mode */

void
entercurses(void)
{
	incurses = YES;
	(void) nonl();		/* don't translate an output \n to \n\r */
	(void) cbreak();	/* single character input */
	(void) noecho();	/* don't echo input characters */
	(void) clear();		/* clear the screen */
	initmouse();		/* initialize any mouse interface */
	drawscrollbar(topline, nextline, totallines);
	atfield();
}

/* exit curses mode */

void
exitcurses(void)
{
	/* clear the bottom line */
	(void) move(LINES - 1, 0);
	(void) clrtoeol();
	(void) refresh();

	/* exit curses and restore the terminal modes */
	(void) endwin();
	incurses = NO;

	/* restore the mouse */
	cleanupmouse();
	(void) fflush(stdout);
}

/* no activity timeout occurred */

static void
timedout(int sig)
{
	/* if there is a child process, don't exit until it does */
	if (childpid) {
		closedatabase();
		noacttimeout = YES;
		return;
	}
	exitcurses();
	(void) fprintf(stderr, "cscope: no activity for %d hours--exiting\n",
	    noacttime / 3600);
	myexit(sig);
}

/* cleanup and exit */

void
myexit(int sig)
{
	/* deleted layer causes multiple signals */
	(void) signal(SIGHUP, SIG_IGN);
	/* remove any temporary files */
	if (temp1[0] != '\0') {
		(void) unlink(temp1);
		(void) unlink(temp2);
	}
	/* restore the terminal to its original mode */
	if (incurses == YES) {
		exitcurses();
	}

	/* dump core for debugging on the quit signal */
	if (sig == SIGQUIT) {
		(void) abort();
	}
	exit(sig);
}
