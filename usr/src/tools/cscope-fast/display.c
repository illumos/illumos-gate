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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Gary Mills
 */

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	display functions
 */

#include "global.h"
#include "version.h"	/* FILEVERSION and FIXVERSION */
#include <curses.h>	/* COLS and LINES */
#include <setjmp.h>	/* jmp_buf */
#include <string.h>
#include <errno.h>

/* see if the function column should be displayed */
#define	displayfcn()	(field <= ASSIGN)

#define	MINCOLS	68	/* minimum columns for 3 digit Lines message numbers */

int	*displine;		/* screen line of displayed reference */
int	disprefs;		/* displayed references */
int	field;			/* input field */
unsigned fldcolumn;		/* input field column */
int	mdisprefs;		/* maximum displayed references */
int	selectlen;		/* selection number field length */
int	nextline;		/* next line to be shown */
int	topline = 1;		/* top line of page */
int	bottomline;		/* bottom line of page */
int	totallines;		/* total reference lines */
FILE	*refsfound;		/* references found file */
FILE	*nonglobalrefs;		/* non-global references file */

static	int	fldline;		/* input field line */
static	int	subsystemlen;		/* OGS subsystem name display */
					/* field length */
static	int	booklen;		/* OGS book name display field length */
static	int	filelen;		/* file name display field length */
static	int	fcnlen;			/* function name display field length */
static	jmp_buf	env;			/* setjmp/longjmp buffer */
static	int	lastdispline;		/* last displayed reference line */
static	char	lastmsg[MSGLEN + 1];	/* last message displayed */
static	int	numlen;			/* line number display field length */
static	char	depthstring[] = "Depth: ";
static	char	helpstring[] = "Press the ? key for help";


typedef char *(*FP)();	/* pointer to function returning a character pointer */

static	struct	{
	char	*text1;
	char	*text2;
	FP	findfcn;
	enum {
		EGREP,
		REGCMP
	} patterntype;
} fields[FIELDS + 1] = {
	/* last search is not part of the cscope display */
	{ "Find this", "C symbol",
	    (FP) findsymbol, REGCMP},
	{ "Find this", "definition",
	    (FP) finddef, REGCMP},
	{ "Find", "functions called by this function",
	    (FP) findcalledby, REGCMP},
	{ "Find", "functions calling this function",
	    (FP) findcalling, REGCMP},
	{ "Find", "assignments to",
	    (FP) findassignments, REGCMP},
	{ "Change this", "grep pattern",
	    findgreppat, EGREP},
	{ "Find this", "egrep pattern",
	    findegreppat, EGREP},
	{ "Find this", "file",
	    (FP) findfile, REGCMP},
	{ "Find", "files #including this file",
	    (FP) findinclude, REGCMP},
	{ "Find all", "function/class definitions",
	    (FP) findallfcns, REGCMP},
};

/* initialize display parameters */

void
dispinit(void)
{
	/* calculate the maximum displayed reference lines */
	lastdispline = FLDLINE - 2;
	mdisprefs = lastdispline - REFLINE + 1;
	if (mdisprefs <= 0) {
		(void) printw("cscope: window must be at least %d lines high",
		    FIELDS + 6);
		myexit(1);
	}
	if (COLS < MINCOLS) {
		(void) printw("cscope: window must be at least %d columns wide",
		    MINCOLS);
		myexit(1);
	}
	if (!mouse) {
		if (returnrequired == NO && mdisprefs > 9) {
			mdisprefs = 9;	/* single digit selection number */
		}
		/* calculate the maximum selection number width */
		(void) sprintf(newpat, "%d", mdisprefs);
		selectlen = strlen(newpat);
	}
	/* allocate the displayed line array */
	displine = (int *)mymalloc(mdisprefs * sizeof (int));
}

/* display a page of the references */

void
display(void)
{
	char	*subsystem;		/* OGS subsystem name */
	char	*book;			/* OGS book name */
	char	file[PATHLEN + 1];	/* file name */
	char	function[PATLEN + 1];	/* function name */
	char	linenum[NUMLEN + 1];	/* line number */
	int	screenline;		/* screen line number */
	int	width;			/* source line display width */
	int	i;
	char	*s;

	(void) erase();

	/* if there are no references */
	if (totallines == 0) {
		if (*lastmsg != '\0') {
			(void) addstr(lastmsg);	/* redisplay any message */
		} else {
			(void) printw("Cscope version %d%s", FILEVERSION,
			    FIXVERSION);
			(void) move(0, COLS - (int)sizeof (helpstring));
			(void) addstr(helpstring);
		}
	} else {	/* display the pattern */
		if (changing == YES) {
			(void) printw("Change \"%s\" to \"%s\"",
			    pattern, newpat);
		} else {
			(void) printw("%c%s: %s",
			    toupper(fields[field].text2[0]),
			    fields[field].text2 + 1, pattern);
		}
		/* display the cscope invocation nesting depth */
		if (cscopedepth > 1) {
			(void) move(0, COLS - (int)sizeof (depthstring) - 2);
			(void) addstr(depthstring);
			(void) printw("%d", cscopedepth);
		}
		/* display the column headings */
		(void) move(2, selectlen + 1);
		if (ogs == YES && field != FILENAME) {
			(void) printw("%-*s ", subsystemlen, "Subsystem");
			(void) printw("%-*s ", booklen, "Book");
		}
		if (dispcomponents > 0) {
			(void) printw("%-*s ", filelen, "File");
		}
		if (displayfcn()) {
			(void) printw("%-*s ", fcnlen, "Function");
		}
		if (field != FILENAME) {
			(void) addstr("Line");
		}
		(void) addch('\n');

		/* if at end of file go back to beginning */
		if (nextline > totallines) {
			seekline(1);
		}
		/* calculate the source text column */
		width = COLS - selectlen - numlen - 2;
		if (ogs == YES) {
			width -= subsystemlen + booklen + 2;
		}
		if (dispcomponents > 0) {
			width -= filelen + 1;
		}
		if (displayfcn()) {
			width -= fcnlen + 1;
		}
		/*
		 * until the max references have been displayed or
		 * there is no more room
		 */
		topline = nextline;
		for (disprefs = 0, screenline = REFLINE;
		    disprefs < mdisprefs && screenline <= lastdispline;
		    ++disprefs, ++screenline) {
			/* read the reference line */
			if (fscanf(refsfound, "%s%s%s %[^\n]", file, function,
			    linenum, yytext) < 4) {
				break;
			}
			++nextline;
			displine[disprefs] = screenline;

			/* if no mouse, display the selection number */
			if (!mouse) {
				(void) printw("%*d", selectlen, disprefs + 1);
			}
			/* display any change mark */
			if (changing == YES &&
			    change[topline + disprefs - 1] == YES) {
				(void) addch('>');
			} else {
				(void) addch(' ');
			}
			/* display the file name */
			if (field == FILENAME) {
				(void) printw("%-.*s\n", COLS - 3, file);
				continue;
			}
			/* if OGS, display the subsystem and book names */
			if (ogs == YES) {
				ogsnames(file, &subsystem, &book);
				(void) printw("%-*.*s ", subsystemlen,
				    subsystemlen, subsystem);
				(void) printw("%-*.*s ", booklen, booklen,
				    book);
			}
			/* display the requested path components */
			if (dispcomponents > 0) {
				(void) printw("%-*.*s ", filelen, filelen,
				    pathcomponents(file, dispcomponents));
			}
			/* display the function name */
			if (displayfcn()) {
				(void) printw("%-*.*s ", fcnlen, fcnlen,
				    function);
			}
			/* display the line number */
			(void) printw("%*s ", numlen, linenum);

			/* there may be tabs in egrep output */
			while ((s = strchr(yytext, '\t')) != NULL) {
				*s = ' ';
			}
			/* display the source line */
			s = yytext;
			for (;;) {
				/* see if the source line will fit */
				if ((i = strlen(s)) > width) {
					/* find the nearest blank */
					for (i = width; s[i] != ' ' && i > 0;
					    --i) {
					}
					if (i == 0) {
						i = width;	/* no blank */
					}
				}
				/* print up to this point */
				(void) printw("%.*s", i, s);
				s += i;

				/* if line didn't wrap around */
				if (i < width) {
					/* go to next line */
					(void) addch('\n');
				}
				/* skip blanks */
				while (*s == ' ') {
					++s;
				}
				/* see if there is more text */
				if (*s == '\0') {
					break;
				}
				/* if the source line is too long */
				if (++screenline > lastdispline) {
					/*
					 * if this is the first displayed line,
					 * display what will fit on the screen
					 */
					if (topline == nextline - 1) {
						goto endrefs;
					}
					/* erase the reference */
					while (--screenline >=
					    displine[disprefs]) {
						(void) move(screenline, 0);
						(void) clrtoeol();
					}
					++screenline;

					/*
					 * go back to the beginning of this
					 * reference
					 */
					--nextline;
					seekline(nextline);
					goto endrefs;
				}
				/* indent the continued source line */
				(void) move(screenline, COLS - width);
			}

		}
	endrefs:
		/* check for more references */
		bottomline = nextline;
		if (bottomline - topline < totallines) {
			(void) move(FLDLINE - 1, 0);
			(void) standout();
			(void) printw("%*s", selectlen + 1, "");
			if (bottomline - 1 == topline) {
				(void) printw("Line %d", topline);
			} else {
				(void) printw("Lines %d-%d", topline,
				    bottomline - 1);
			}
			(void) printw(" of %d, press the space bar to "
			    "display next lines", totallines);
			(void) standend();
		}
	}
	/* display the input fields */
	(void) move(FLDLINE, 0);
	for (i = 0; i < FIELDS; ++i) {
		(void) printw("%s %s:\n", fields[i].text1, fields[i].text2);
	}
	drawscrollbar(topline, nextline, totallines);
}

/* set the cursor position for the field */
void
setfield(void)
{
	fldline = FLDLINE + field;
	fldcolumn = strlen(fields[field].text1) +
	    strlen(fields[field].text2) + 3;
}

/* move to the current input field */

void
atfield(void)
{
	(void) move(fldline, (int)fldcolumn);
}

/* search for the symbol or text pattern */

/*ARGSUSED*/
SIGTYPE
jumpback(int sig)
{
	longjmp(env, 1);
}

BOOL
search(void)
{
	char	*egreperror = NULL;	/* egrep error message */
	FINDINIT rc = NOERROR;		/* findinit return code */
	SIGTYPE	(*volatile savesig)() = SIG_DFL; /* old value of signal */
	FP	f;			/* searching function */
	char	*s;
	int	c;

	/* note: the pattern may have been a cscope argument */
	if (caseless == YES) {
		for (s = pattern; *s != '\0'; ++s) {
			*s = tolower(*s);
		}
	}
	/* open the references found file for writing */
	if (writerefsfound() == NO) {
		return (NO);
	}
	/* find the pattern - stop on an interrupt */
	if (linemode == NO) {
		putmsg("Searching");
	}
	initprogress();
	if (setjmp(env) == 0) {
		savesig = signal(SIGINT, jumpback);
		f = fields[field].findfcn;
		if (fields[field].patterntype == EGREP) {
			egreperror = (*f)(pattern);
		} else {
			if ((nonglobalrefs = fopen(temp2, "w")) == NULL) {
				cannotopen(temp2);
				return (NO);
			}
			if ((rc = findinit()) == NOERROR) {
				(void) dbseek(0L); /* goto the first block */
				(*f)();
				findcleanup();

				/* append the non-global references */
				(void) freopen(temp2, "r", nonglobalrefs);
				while ((c = getc(nonglobalrefs)) != EOF) {
					(void) putc(c, refsfound);
				}
			}
			(void) fclose(nonglobalrefs);
		}
	}
	(void) signal(SIGINT, savesig);
	/* reopen the references found file for reading */
	(void) freopen(temp1, "r", refsfound);
	nextline = 1;
	totallines = 0;

	/* see if it is empty */
	if ((c = getc(refsfound)) == EOF) {
		if (egreperror != NULL) {
			(void) sprintf(lastmsg, "Egrep %s in this pattern: %s",
			    egreperror, pattern);
		} else if (rc == NOTSYMBOL) {
			(void) sprintf(lastmsg, "This is not a C symbol: %s",
			    pattern);
		} else if (rc == REGCMPERROR) {
			(void) sprintf(lastmsg,
			    "Error in this regcmp(3X) regular expression: %s",
			    pattern);
		} else {
			(void) sprintf(lastmsg, "Could not find the %s: %s",
			    fields[field].text2, pattern);
		}
		return (NO);
	}
	/* put back the character read */
	(void) ungetc(c, refsfound);

	countrefs();
	return (YES);
}

/* open the references found file for writing */

BOOL
writerefsfound(void)
{
	if (refsfound == NULL) {
		if ((refsfound = fopen(temp1, "w")) == NULL) {
			cannotopen(temp1);
			return (NO);
		}
	} else if (freopen(temp1, "w", refsfound) == NULL) {
		putmsg("Cannot reopen temporary file");
		return (NO);
	}
	return (YES);
}

/* count the references found */

void
countrefs(void)
{
	char	*subsystem;		/* OGS subsystem name */
	char 	*book;			/* OGS book name */
	char	file[PATHLEN + 1];	/* file name */
	char	function[PATLEN + 1];	/* function name */
	char	linenum[NUMLEN + 1];	/* line number */
	int	i;

	/*
	 * count the references found and find the length of the file,
	 * function, and line number display fields
	 */
	subsystemlen = 9;	/* strlen("Subsystem") */
	booklen = 4;		/* strlen("Book") */
	filelen = 4;		/* strlen("File") */
	fcnlen = 8;		/* strlen("Function") */
	numlen = 0;
	while ((i = fscanf(refsfound, "%250s%250s%6s %5000[^\n]", file,
	    function, linenum, yytext)) != EOF) {
		if (i != 4 || !isgraph(*file) ||
		    !isgraph(*function) || !isdigit(*linenum)) {
			putmsg("File does not have expected format");
			totallines = 0;
			return;
		}
		if ((i = strlen(pathcomponents(file,
		    dispcomponents))) > filelen) {
			filelen = i;
		}
		if (ogs == YES) {
			ogsnames(file, &subsystem, &book);
			if ((i = strlen(subsystem)) > subsystemlen) {
				subsystemlen = i;
			}
			if ((i = strlen(book)) > booklen) {
				booklen = i;
			}
		}
		if ((i = strlen(function)) > fcnlen) {
			fcnlen = i;
		}
		if ((i = strlen(linenum)) > numlen) {
			numlen = i;
		}
		++totallines;
	}
	rewind(refsfound);

	/* restrict the width of displayed columns */
	i = (COLS - 5) / 3;
	if (ogs == YES) {
		i = (COLS - 7) / 5;
	}
	if (filelen > i && i > 4) {
		filelen = i;
	}
	if (subsystemlen > i && i > 9) {
		subsystemlen = i;
	}
	if (booklen > i && i > 4) {
		booklen = i;
	}
	if (fcnlen > i && i > 8) {
		fcnlen = i;
	}
}

/* print error message on system call failure */

void
myperror(char *text)
{
	char	msg[MSGLEN + 1];	/* message */

	(void) sprintf(msg, "%s: %s", text, strerror(errno));
	putmsg(msg);
}

/* putmsg clears the message line and prints the message */

void
putmsg(char *msg)
{
	if (incurses == NO) {
		*msg = tolower(*msg);
		(void) fprintf(stderr, "cscope: %s\n", msg);
	} else {
		(void) move(MSGLINE, 0);
		(void) clrtoeol();
		(void) addstr(msg);
		(void) refresh();
	}
	(void) strncpy(lastmsg, msg, sizeof (lastmsg) - 1);
}

/* clearmsg2 clears the second message line */

void
clearmsg2(void)
{
	if (incurses == YES) {
		(void) move(MSGLINE + 1, 0);
		(void) clrtoeol();
	}
}

/* putmsg2 clears the second message line and prints the message */

void
putmsg2(char *msg)
{
	if (incurses == NO) {
		putmsg(msg);
	} else {
		clearmsg2();
		(void) addstr(msg);
		(void) refresh();
	}
}

/* position the references found file at the specified line */

void
seekline(int line)
{
	int	c;

	/* verify that there is a references found file */
	if (refsfound == NULL) {
		return;
	}
	/* go to the beginning of the file */
	rewind(refsfound);

	/* find the requested line */
	nextline = 1;
	while (nextline < line && (c = getc(refsfound)) != EOF) {
		if (c == '\n') {
			nextline++;
		}
	}
}

/* get the OGS subsystem and book names */

void
ogsnames(char *file, char **subsystem, char **book)
{
	static	char	buf[PATHLEN + 1];
	char	*s, *slash;

	*subsystem = *book = "";
	(void) strcpy(buf, file);
	s = buf;
	if (*s == '/') {
		++s;
	}
	while ((slash = strchr(s, '/')) != NULL) {
		*slash = '\0';
		if ((int)strlen(s) >= 3 && strncmp(slash - 3, ".ss", 3) == 0) {
			*subsystem = s;
			s = slash + 1;
			if ((slash = strchr(s, '/')) != NULL) {
				*book = s;
				*slash = '\0';
			}
			break;
		}
		s = slash + 1;
	}
}

/* get the requested path components */

char *
pathcomponents(char *path, int components)
{
	int	i;
	char	*s;

	s = path + strlen(path) - 1;
	for (i = 0; i < components; ++i) {
		while (s > path && *--s != '/') {
			;
		}
	}
	if (s > path && *s == '/') {
		++s;
	}
	return (s);
}
