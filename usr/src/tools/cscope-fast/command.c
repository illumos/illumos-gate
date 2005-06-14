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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol or text cross-reference
 *
 *	command functions
 */

#include <curses.h>	/* KEY_.* */
#include <fcntl.h>	/* O_RDONLY */
#include <unistd.h>
#include <stdio.h>
#include "global.h"
#include "library.h"

BOOL	caseless;		/* ignore letter case when searching */
BOOL	*change;		/* change this line */
BOOL	changing;		/* changing text */
char	newpat[PATLEN + 1];	/* new pattern */
char	pattern[PATLEN + 1];	/* symbol or text pattern */

static	char	appendprompt[] = "Append to file: ";
static	char	pipeprompt[] = "Pipe to shell command: ";
static	char	readprompt[] = "Read from file: ";
static	char	selectionprompt[] = "Selection: ";
static	char	toprompt[] = "To: ";

static void scrollbar(MOUSEEVENT *p);

/* execute the command */

BOOL
command(int commandc)
{
	char	filename[PATHLEN + 1];	/* file path name */
	MOUSEEVENT *p;			/* mouse data */
	int	c, i;
	FILE	*file;
	HISTORY *curritem, *item;	/* command history */
	char	*s;

	switch (commandc) {

	case ctrl('C'):	/* toggle caseless mode */
		if (caseless == NO) {
			caseless = YES;
			putmsg2("Caseless mode is now ON");
		} else {
			caseless = NO;
			putmsg2("Caseless mode is now OFF");
		}
		egrepcaseless(caseless);	/* turn on/off -i flag */
		return (NO);

	case ctrl('R'):	/* rebuild the cross reference */
		if (isuptodate == YES) {
			putmsg("The -d option prevents rebuilding the "
			    "symbol database");
			return (NO);
		}
		exitcurses();
		freefilelist();		/* remake the source file list */
		makefilelist();
		rebuild();
		if (errorsfound == YES) {
			errorsfound = NO;
			askforreturn();
		}
		entercurses();
		putmsg("");		/* clear any previous message */
		totallines = 0;
		topline = nextline = 1;
		break;

	case ctrl('X'):	/* mouse selection */
		if ((p = getmouseevent()) == NULL) {
			return (NO);	/* unknown control sequence */
		}
		/* if the button number is a scrollbar tag */
		if (p->button == '0') {
			scrollbar(p);
			break;
		}
		/* ignore a sweep */
		if (p->x2 >= 0) {
			return (NO);
		}
		/* if this is a line selection */
		if (p->y1 < FLDLINE) {

			/* find the selected line */
			/* note: the selection is forced into range */
			for (i = disprefs - 1; i > 0; --i) {
				if (p->y1 >= displine[i]) {
					break;
				}
			}
			/* display it in the file with the editor */
			editref(i);
		} else {	/* this is an input field selection */
			field = mouseselection(p, FLDLINE, FIELDS);
			setfield();
			resetcmd();
			return (NO);
		}
		break;

	case '\t':	/* go to next input field */
	case '\n':
	case '\r':
	case ctrl('N'):
	case KEY_DOWN:
	case KEY_ENTER:
	case KEY_RIGHT:
		field = (field + 1) % FIELDS;
		setfield();
		resetcmd();
		return (NO);

	case ctrl('P'):	/* go to previous input field */
	case KEY_UP:
	case KEY_LEFT:
		field = (field + (FIELDS - 1)) % FIELDS;
		setfield();
		resetcmd();
		return (NO);
	case KEY_HOME:	/* go to first input field */
		field = 0;
		setfield();
		resetcmd();
		return (NO);

	case KEY_LL:	/* go to last input field */
		field = FIELDS - 1;
		setfield();
		resetcmd();
		return (NO);
	case ' ':	/* display next page */
	case '+':
	case ctrl('V'):
	case KEY_NPAGE:
		/* don't redisplay if there are no lines */
		if (totallines == 0) {
			return (NO);
		}
		/*
		 * note: seekline() is not used to move to the next
		 * page because display() leaves the file pointer at
		 * the next page to optimize paging forward
		 */
		break;

	case '-':	/* display previous page */
	case KEY_PPAGE:
		/* don't redisplay if there are no lines */
		if (totallines == 0) {
			return (NO);
		}
		i = topline;		/* save the current top line */
		nextline = topline;	/* go back to this page */

		/* if on first page but not at beginning, go to beginning */
		if (nextline > 1 && nextline <= mdisprefs) {
			nextline = 1;
		} else {	/* go back the maximum displayable lines */
			nextline -= mdisprefs;

			/* if this was the first page, go to the last page */
			if (nextline < 1) {
				nextline = totallines - mdisprefs + 1;
				if (nextline < 1) {
					nextline = 1;
				}
				/* old top is past last line */
				i = totallines + 1;
			}
		}
		/*
		 * move down til the bottom line is just before the
		 * previous top line
		 */
		c = nextline;
		for (;;) {
			seekline(nextline);
			display();
			if (i - bottomline <= 0) {
				break;
			}
			nextline = ++c;
		}
		return (NO);	/* display already up to date */

	case '>':	/* write or append the lines to a file */
		if (totallines == 0) {
			putmsg("There are no lines to write to a file");
		} else {	/* get the file name */
			(void) move(PRLINE, 0);
			(void) addstr("Write to file: ");
			s = "w";
			if ((c = mygetch()) == '>') {
				(void) move(PRLINE, 0);
				(void) addstr(appendprompt);
				c = '\0';
				s = "a";
			}
			if (c != '\r' && c != '\n' && c != KEY_ENTER &&
			    c != KEY_BREAK &&
			    getline(newpat, COLS - sizeof (appendprompt), c,
			    NO) > 0) {
				shellpath(filename, sizeof (filename), newpat);
				if ((file = fopen(filename, s)) == NULL) {
					cannotopen(filename);
				} else {
					seekline(1);
					while ((c = getc(refsfound)) != EOF) {
						(void) putc(c, file);
					}
					seekline(topline);
					(void) fclose(file);
				}
			}
			clearprompt();
		}
		return (NO);	/* return to the previous field */

	case '<':	/* read lines from a file */
		(void) move(PRLINE, 0);
		(void) addstr(readprompt);
		if (getline(newpat, COLS - sizeof (readprompt), '\0',
		    NO) > 0) {
			clearprompt();
			shellpath(filename, sizeof (filename), newpat);
			if (readrefs(filename) == NO) {
				putmsg2("Ignoring an empty file");
				return (NO);
			}
			return (YES);
		}
		clearprompt();
		return (NO);

	case '^':	/* pipe the lines through a shell command */
	case '|':	/* pipe the lines to a shell command */
		if (totallines == 0) {
			putmsg("There are no lines to pipe to a shell command");
			return (NO);
		}
		/* get the shell command */
		(void) move(PRLINE, 0);
		(void) addstr(pipeprompt);
		if (getline(newpat,
		    COLS - sizeof (pipeprompt), '\0', NO) == 0) {
			clearprompt();
			return (NO);
		}
		/* if the ^ command, redirect output to a temp file */
		if (commandc == '^') {
			(void) strcat(strcat(newpat, " >"), temp2);
		}
		exitcurses();
		if ((file = mypopen(newpat, "w")) == NULL) {
			(void) fprintf(stderr,
			    "cscope: cannot open pipe to shell command: %s\n",
			    newpat);
		} else {
			seekline(1);
			while ((c = getc(refsfound)) != EOF) {
				(void) putc(c, file);
			}
			seekline(topline);
			(void) mypclose(file);
		}
		if (commandc == '^') {
			if (readrefs(temp2) == NO) {
				putmsg("Ignoring empty output of ^ command");
			}
		}
		askforreturn();
		entercurses();
		break;

	case ctrl('L'):	/* redraw screen */
	case KEY_CLEAR:
		(void) clearok(curscr, TRUE);
		(void) wrefresh(curscr);
		drawscrollbar(topline, bottomline, totallines);
		return (NO);

	case '!':	/* shell escape */
		(void) execute(shell, shell, (char *)NULL);
		seekline(topline);
		break;

	case '?':	/* help */
		(void) clear();
		help();
		(void) clear();
		seekline(topline);
		break;

	case ctrl('E'):	/* edit all lines */
		editall();
		break;

	case ctrl('A'):	/* repeat last pattern */
	case ctrl('Y'):	/* (old command) */
		if (*pattern != '\0') {
			(void) addstr(pattern);
			goto repeat;
		}
		break;

	case ctrl('B'):		/* cmd history back */
	case ctrl('F'):		/* cmd history fwd */
		curritem = currentcmd();
		item = (commandc == ctrl('F')) ? nextcmd() : prevcmd();
		clearmsg2();
		if (curritem == item) {
			/* inform user that we're at history end */
			putmsg2(
			    "End of input field and search pattern history");
		}
		if (item) {
			field = item->field;
			setfield();
			atfield();
			(void) addstr(item->text);
			(void) strcpy(pattern, item->text);
			switch (c = mygetch()) {
			case '\r':
			case '\n':
			case KEY_ENTER:
				goto repeat;
			default:
				ungetch(c);
				atfield();
				(void) clrtoeol(); /* clear current field */
				break;
			}
		}
		return (NO);

	case '\\':	/* next character is not a command */
		(void) addch('\\');	/* display the quote character */

		/* get a character from the terminal */
		if ((commandc = mygetch()) == EOF) {
			return (NO);	/* quit */
		}
		(void) addstr("\b \b");	/* erase the quote character */
		goto ispat;

	case '.':
		atfield();	/* move back to the input field */
		/* FALLTHROUGH */
	default:
		/* edit a selected line */
		if (isdigit(commandc) && commandc != '0' && !mouse) {
			if (returnrequired == NO) {
				editref(commandc - '1');
			} else {
				(void) move(PRLINE, 0);
				(void) addstr(selectionprompt);
				if (getline(newpat,
				    COLS - sizeof (selectionprompt), commandc,
				    NO) > 0 &&
				    (i = atoi(newpat)) > 0) {
					editref(i - 1);
				}
				clearprompt();
			}
		} else if (isprint(commandc)) {
			/* this is the start of a pattern */
ispat:
			if (getline(newpat, COLS - fldcolumn - 1, commandc,
			    caseless) > 0) {
					(void) strcpy(pattern, newpat);
					resetcmd();	/* reset history */
repeat:
				addcmd(field, pattern);	/* add to history */
				if (field == CHANGE) {
					/* prompt for the new text */
					(void) move(PRLINE, 0);
					(void) addstr(toprompt);
					(void) getline(newpat,
					    COLS - sizeof (toprompt), '\0', NO);
				}
				/* search for the pattern */
				if (search() == YES) {
					switch (field) {
					case DEFINITION:
					case FILENAME:
						if (totallines > 1) {
							break;
						}
						topline = 1;
						editref(0);
						break;
					case CHANGE:
						return (changestring());
					}
				} else if (field == FILENAME &&
				    access(newpat, READ) == 0) {
					/* try to edit the file anyway */
					edit(newpat, "1");
				}
			} else {	/* no pattern--the input was erased */
				return (NO);
			}
		} else {	/* control character */
			return (NO);
		}
	}
	return (YES);
}

/* clear the prompt line */

void
clearprompt(void)
{
	(void) move(PRLINE, 0);
	(void) clrtoeol();
}

/* read references from a file */

BOOL
readrefs(char *filename)
{
	FILE	*file;
	int	c;

	if ((file = fopen(filename, "r")) == NULL) {
		cannotopen(filename);
		return (NO);
	}
	if ((c = getc(file)) == EOF) {	/* if file is empty */
		return (NO);
	}
	totallines = 0;
	nextline = 1;
	if (writerefsfound() == YES) {
		(void) putc(c, refsfound);
		while ((c = getc(file)) != EOF) {
			(void) putc(c, refsfound);
		}
		(void) fclose(file);
		(void) freopen(temp1, "r", refsfound);
		countrefs();
	}
	return (YES);
}

/* change one text string to another */

BOOL
changestring(void)
{
	char	buf[PATLEN + 1];	/* input buffer */
	char	newfile[PATHLEN + 1];	/* new file name */
	char	oldfile[PATHLEN + 1];	/* old file name */
	char	linenum[NUMLEN + 1];	/* file line number */
	char	msg[MSGLEN + 1];	/* message */
	FILE	*script;		/* shell script file */
	BOOL	anymarked = NO;		/* any line marked */
	MOUSEEVENT *p;			/* mouse data */
	int	c, i;
	char	*s;

	/* open the temporary file */
	if ((script = fopen(temp2, "w")) == NULL) {
		cannotopen(temp2);
		return (NO);
	}
	/* create the line change indicators */
	change = (BOOL *)mycalloc((unsigned)totallines, sizeof (BOOL));
	changing = YES;
	initmenu();

	/* until the quit command is entered */
	for (;;) {
		/* display the current page of lines */
		display();
	same:
		/* get a character from the terminal */
		(void) move(PRLINE, 0);
		(void) addstr(
		    "Select lines to change (press the ? key for help): ");
		if ((c = mygetch()) == EOF || c == ctrl('D') ||
		    c == ctrl('Z')) {
			break;	/* change lines */
		}
		/* see if the input character is a command */
		switch (c) {
		case ' ':	/* display next page */
		case '+':
		case ctrl('V'):
		case KEY_NPAGE:
		case '-':	/* display previous page */
		case KEY_PPAGE:
		case '!':	/* shell escape */
		case '?':	/* help */
			(void) command(c);
			break;

		case ctrl('L'):	/* redraw screen */
		case KEY_CLEAR:
			(void) command(c);
			goto same;

		case ESC:	/* kept for backwards compatibility */
			/* FALLTHROUGH */

		case '\r':	/* don't change lines */
		case '\n':
		case KEY_ENTER:
		case KEY_BREAK:
		case ctrl('G'):
			clearprompt();
			goto nochange;

		case '*':	/* mark/unmark all displayed lines */
			for (i = 0; topline + i < nextline; ++i) {
				mark(i);
			}
			goto same;

		case 'a':	/* mark/unmark all lines */
			for (i = 0; i < totallines; ++i) {
				if (change[i] == NO) {
					change[i] = YES;
				} else {
					change[i] = NO;
				}
			}
			/* show that all have been marked */
			seekline(totallines);
			break;
		case ctrl('X'):	/* mouse selection */
			if ((p = getmouseevent()) == NULL) {
				goto same;	/* unknown control sequence */
			}
			/* if the button number is a scrollbar tag */
			if (p->button == '0') {
				scrollbar(p);
				break;
			}
			/* find the selected line */
			/* note: the selection is forced into range */
			for (i = disprefs - 1; i > 0; --i) {
				if (p->y1 >= displine[i]) {
					break;
				}
			}
			mark(i);
			goto same;
		default:
			/* if a line was selected */
			if (isdigit(c) && c != '0' && !mouse) {
				if (returnrequired == NO) {
					mark(c - '1');
				} else {
					clearprompt();
					(void) move(PRLINE, 0);
					(void) addstr(selectionprompt);
					if (getline(buf,
					    COLS - sizeof (selectionprompt), c,
					    NO) > 0 &&
					    (i = atoi(buf)) > 0) {
						mark(i - 1);
					}
				}
			}
			goto same;
		}
	}
	/* for each line containing the old text */
	(void) fprintf(script, "ed - <<\\!\nH\n");
	*oldfile = '\0';
	seekline(1);
	for (i = 0; fscanf(refsfound, "%s%*s%s%*[^\n]", newfile, linenum) == 2;
	    ++i) {
		/* see if the line is to be changed */
		if (change[i] == YES) {
			anymarked = YES;

			/* if this is a new file */
			if (strcmp(newfile, oldfile) != 0) {

				/* make sure it can be changed */
				if (access(newfile, WRITE) != 0) {
					(void) sprintf(msg,
					    "Cannot write to file %s",
					    newfile);
					putmsg(msg);
					anymarked = NO;
					break;
				}
				/* if there was an old file */
				if (*oldfile != '\0') {
					(void) fprintf(script,
					    "w\n");	/* save it */
				}
				/* edit the new file */
				(void) strcpy(oldfile, newfile);
				(void) fprintf(script, "e %s\n", oldfile);
			}
			/* output substitute command */
			(void) fprintf(script,
			    "%ss/", linenum);	/* change */
			for (s = pattern; *s != '\0'; ++s) {	/* old text */
				if (*s == '/') {
					(void) putc('\\', script);
				}
				(void) putc(*s, script);
			}
			(void) putc('/', script);			/* to */
			for (s = newpat; *s != '\0'; ++s) {	/* new text */
				if (strchr("/\\&", *s) != NULL) {
					(void) putc('\\', script);
				}
				(void) putc(*s, script);
			}
			(void) fprintf(script, "/gp\n");	/* and print */
		}
	}
	(void) fprintf(script, "w\nq\n!\n");	/* write and quit */
	(void) fclose(script);
	clearprompt();

	/* if any line was marked */
	if (anymarked == YES) {
		/* edit the files */
		(void) refresh();
		(void) fprintf(stderr, "Changed lines:\n\r");
		(void) execute(shell, shell, temp2, (char *)NULL);
		askforreturn();
	}
nochange:
	changing = NO;
	initmenu();
	free(change);
	seekline(topline);
	return (YES);	/* clear any marks on exit without change */
}

/* mark/unmark this displayed line to be changed */

void
mark(int i)
{
	int	j;

	j = i + topline - 1;
	if (j < totallines) {
		(void) move(displine[i], selectlen);
		if (change[j] == NO) {
			change[j] = YES;
			(void) addch('>');
		} else {
			change[j] = NO;
			(void) addch(' ');
		}
	}
}

/* scrollbar actions */

static void
scrollbar(MOUSEEVENT *p)
{
	/* reposition list if it makes sense */
	if (totallines == 0) {
		return;
	}
	switch (p->percent) {

	case 101: /* scroll down one page */
		if (nextline + mdisprefs > totallines) {
			nextline = totallines - mdisprefs + 1;
		}
		break;

	case 102: /* scroll up one page */
		nextline = topline - mdisprefs;
		if (nextline < 1) {
			nextline = 1;
		}
		break;

	case 103: /* scroll down one line */
		nextline = topline + 1;
		break;

	case 104: /* scroll up one line */
		if (topline > 1) {
			nextline = topline - 1;
		}
		break;
	default:
		nextline = p->percent * totallines / 100;
	}
	seekline(nextline);
}
