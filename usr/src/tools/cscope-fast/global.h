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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	global type, data, and function definitions
 */

#include <ctype.h>	/* isalpha, isdigit, etc. */
#include <signal.h>	/* SIGINT and SIGQUIT */
#include <stdio.h>	/* standard I/O package */
#include <sys/types.h>
#include "constants.h"	/* misc. constants */
#include "invlib.h"	/* inverted index library */
#include "library.h"	/* library function return values */
#include "mouse.h"	/* mouse interface */
#define	SIGTYPE void

typedef	enum	{		/* boolean data type */
	NO,
	YES
} BOOL;

typedef	enum	{		/* findinit return code */
	NOERROR,
	NOTSYMBOL,
	REGCMPERROR
} FINDINIT;

typedef	struct	history	{		/* command history */
	int	field;
	char	*text;
	struct	history *previous;
	struct	history *next;
} HISTORY;

typedef	enum	{			/* keyword type */
	DECL,	/* type declaration */
	FLOW,	/* control flow (do, if, for, while, switch, etc.) */
	MISC	/* misc.: sizeof or table placeholder for compression */
} KEYWORD;

/* digraph data for text compression */
extern	char	dichar1[];	/* 16 most frequent first chars */
extern	char	dichar2[];	/* 8 most frequent second chars */
				/* using the above as first chars */
extern	char	dicode1[];	/* digraph first character code */
extern	char	dicode2[];	/* digraph second character code */

/* main.c global data */
extern	char	*editor, *home, *shell;	/* environment variables */
extern	BOOL	compress;	/* compress the characters in the crossref */
extern	int	cscopedepth;	/* cscope invocation nesting depth */
extern	char	currentdir[];	/* current directory */
extern	BOOL	dbtruncated;	/* database symbols are truncated to 8 chars */
extern	char	**dbvpdirs;	/* directories (including current) in */
				/* database view path */
extern	int	dbvpndirs;	/* number of directories in database */
				/* view path */
extern	int	dispcomponents;	/* file path components to display */
extern	BOOL	editallprompt;	/* prompt between editing files */
extern	int	fileargc;	/* file argument count */
extern	char	**fileargv;	/* file argument values */
extern	int	fileversion;	/* cross-reference file version */
extern	BOOL	incurses;	/* in curses */
extern	INVCONTROL invcontrol;	/* inverted file control structure */
extern	BOOL	invertedindex;	/* the database has an inverted index */
extern	BOOL	isuptodate;	/* consider the crossref up-to-date */
extern	BOOL	linemode;	/* use line oriented user interface */
extern	char	*namefile;	/* file of file names */
extern	char	*newreffile;	/* new cross-reference file name */
extern	FILE	*newrefs;	/* new cross-reference */
extern	BOOL	noacttimeout;	/* no activity timeout occurred */
extern	BOOL	ogs;		/* display OGS book and subsystem names */
extern	FILE	*postings;	/* new inverted index postings */
extern	char	*prependpath;	/* prepend path to file names */
extern	BOOL	returnrequired;	/* RETURN required after selection number */
extern	int	symrefs;	/* cross-reference file */
extern	char	temp1[];	/* temporary file name */
extern	char	temp2[];	/* temporary file name */
extern	long	totalterms;	/* total inverted index terms */
extern	BOOL	truncatesyms;	/* truncate symbols to 8 characters */

/* command.c global data */
extern	BOOL	caseless;	/* ignore letter case when searching */
extern	BOOL	*change;	/* change this line */
extern	BOOL	changing;	/* changing text */
extern	char	newpat[];	/* new pattern */
extern	char	pattern[];	/* symbol or text pattern */

/* crossref.c global data */
extern	long	dboffset;	/* new database offset */
extern	BOOL	errorsfound;	/* prompt before clearing error messages */
extern	long	fileindex;	/* source file name index */
extern	long	lineoffset;	/* source line database offset */
extern	long	npostings;	/* number of postings */
extern	int	symbols;	/* number of symbols */

/* dir.c global data */
extern	char	**incdirs;	/* #include directories */
extern	char	**srcdirs;	/* source directories */
extern	char	**srcfiles;	/* source files */
extern	int	nincdirs;	/* number of #include directories */
extern	int	nsrcdirs;	/* number of source directories */
extern	int	nsrcfiles;	/* number of source files */
extern	int	msrcfiles;	/* maximum number of source files */

/* display.c global data */
extern	int	*displine;	/* screen line of displayed reference */
extern	int	disprefs;	/* displayed references */
extern	int	field;		/* input field */
extern	unsigned fldcolumn;	/* input field column */
extern	int	mdisprefs;	/* maximum displayed references */
extern	int	selectlen;		/* selection number field length */
extern	int	nextline;	/* next line to be shown */
extern	int	topline;	/* top line of page */
extern	int	bottomline;	/* bottom line of page */
extern	int	totallines;	/* total reference lines */
extern	FILE	*refsfound;	/* references found file */
extern	FILE	*nonglobalrefs;	/* non-global references file */

/* exec.c global data */
extern	pid_t	childpid;	/* child's process ID */

/* find.c global data */
extern	char	block[];	/* cross-reference file block */
extern	int	blocklen;	/* length of disk block read */
extern	char	blockmark;	/* mark character to be searched for */
extern	long	blocknumber;	/* block number */
extern	char	*blockp;	/* pointer to current character in block */
extern	char	lastfilepath[];	/* last file that full path was computed for */

/* lookup.c global data */
extern	struct	keystruct {
	char	*text;
	char	delim;
	KEYWORD	type;
	struct	keystruct *next;
} keyword[];

/* scanner.l global data */
extern	int	first;		/* buffer index for first char of symbol */
extern	int	last;		/* buffer index for last char of symbol */
extern	int	lineno;		/* symbol line number */
extern	FILE	*yyin;		/* input file descriptor */
extern	int	yyleng;		/* input line length */
extern	int	yylineno;	/* input line number */
#if hpux
extern	unsigned char	yytext[];	/* input line text */
#else
extern	char	yytext[];	/* input line text */
#endif

/* vpinit.c global data */
extern	char	*argv0;		/* command name */

/* cscope functions called from more than one function or between files */
/* cgrep.c */
void	egrepcaseless(int i);
char	*egrepinit(char *expression);
int	egrep(char *f, FILE *o, char *fo);

/* command.c */
BOOL	command(int commandc);
void	clearprompt(void);
BOOL	readrefs(char *filename);
BOOL	changestring(void);
void	mark(int i);

/* crossref.c */
void	crossref(char *srcfile);
void	savesymbol(int token);
void	putfilename(char *srcfile);
void	putposting(char *term, int type);
void	putstring(char *s);
void	warning(char *text);

/* dir.c */
void	sourcedir(char *dirlist);
void	includedir(char *dirlist);
void	makefilelist(void);
void	incfile(char *file, int type);
BOOL	infilelist(char *file);
void	addsrcfile(char *path);
void	freefilelist(void);

/* display.c */
void	dispinit(void);
void	display(void);
void	setfield(void);
void	atfield(void);
void	jumpback(int sig);
BOOL	search(void);
BOOL	writerefsfound(void);
void	countrefs(void);
void	myperror(char *text);
void	putmsg(char *msg);
void	clearmsg2(void);
void	putmsg2(char *msg);
void	seekline(int line);
void	ogsnames(char *file, char **subsystem, char **book);
char	*pathcomponents(char *path, int components);
void	strtoupper(char *s);

/* edit.c */
void	editref(int i);
void	editall(void);
void	edit(char *file, char *linenum);

/* find.c */
void	findsymbol(void);
void	finddef(void);
void	findallfcns(void);
void	findcalledby(void);
void	findcalling(void);
void	findassignments(void);
char	*findgreppat(void);
char	*findegreppat(char *egreppat);
void	findfile(void);
void	findinclude(void);
FINDINIT findinit(void);
void	findcleanup(void);
void	initprogress(void);
void	progress(char *format, long n1, long n2);
BOOL	match(void);
BOOL	matchrest(void);
void	getstring(char *s);
char	*scanpast(int c);
char	*readblock(void);
long	dbseek(long offset);

/* help.c */
void	help(void);

/* history.c */
void	addcmd(int f, char *s);
void	resetcmd(void);
HISTORY *currentcmd(void);
HISTORY *prevcmd(void);
HISTORY *nextcmd(void);

/* input.c */
void	catchint(int sig);
int	ungetch(int c);
int	mygetch(void);
int	getaline(char s[], size_t size, int firstchar, BOOL iscaseless);
void	askforchar(void);
void	askforreturn(void);
void	shellpath(char *out, int limit, char *in);

/* lookup.c */
void	initsymtab(void);
struct	keystruct *lookup(char *ident);
int	hash(char *s);

/* main.c */
void	rebuild(void);
void	entercurses(void);
void	exitcurses(void);
void	myexit(int sig) __NORETURN;
void	cannotopen(char *file);
void	cannotwrite(char *file);

/* menu.c */
void	initmenu(void);

extern void initscanner(char *srcfile);
extern int yylex(void);
extern int execute(char *, ...);
