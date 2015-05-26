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
 * Copyright 2015 Gary Mills
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	terminal input functions
 */

#include "global.h"
#include <curses.h>	/* KEY_BACKSPACE, KEY_BREAK, and KEY_ENTER */
#include <setjmp.h>	/* jmp_buf */

static	jmp_buf	env;		/* setjmp/longjmp buffer */
static	int	prevchar;	/* previous, ungotten character */

/* catch the interrupt signal */

/*ARGSUSED*/
SIGTYPE
catchint(int sig)
{
	(void) signal(SIGINT, catchint);
	longjmp(env, 1);
}

/* unget a character */

int
ungetch(int c)
{
	prevchar = c;
	return (0);
}

/* get a character from the terminal */

int
mygetch(void)
{
	SIGTYPE	(*volatile savesig)() = SIG_DFL; /* old value of signal */
	int	c;

	/* change an interrupt signal to a break key character */
	if (setjmp(env) == 0) {
		savesig = signal(SIGINT, catchint);
		(void) refresh();	/* update the display */
		reinitmouse();	/* curses can change the menu number */
		if (prevchar) {
			c = prevchar;
			prevchar = 0;
		} else {
			c = getch();	/* get a character from the terminal */
		}
	} else {	/* longjmp to here from signal handler */
		c = KEY_BREAK;
	}
	(void) signal(SIGINT, savesig);
	return (c);
}

/* get a line from the terminal in non-canonical mode */

int
getaline(char s[], size_t size, int firstchar, BOOL iscaseless)
{
	int	c, i = 0;
	int	j;

	/* if a character already has been typed */
	if (firstchar != '\0') {
		if (iscaseless == YES) {
			firstchar = tolower(firstchar);
		}
		(void) addch((unsigned)firstchar);	/* display it */
		s[i++] = firstchar;	/* save it */
	}
	/* until the end of the line is reached */
	while ((c = mygetch()) != '\r' && c != '\n' && c != KEY_ENTER &&
	    c != '\003' && c != KEY_BREAK) {
		if (c == erasechar() || c == '\b' ||		/* erase */
		    c == KEY_BACKSPACE) {
			if (i > 0) {
				(void) addstr("\b \b");
				--i;
			}
		} else if (c == killchar()) {			/* kill */
			for (j = 0; j < i; ++j) {
				(void) addch('\b');
			}
			for (j = 0; j < i; ++j) {
				(void) addch(' ');
			}
			for (j = 0; j < i; ++j) {
				(void) addch('\b');
			}
			i = 0;
		} else if (isprint(c) || c == '\t') {		/* printable */
			if (iscaseless == YES) {
				c = tolower(c);
			}
			/* if it will fit on the line */
			if (i < size) {
				(void) addch((unsigned)c);	/* display it */
				s[i++] = c;		/* save it */
			}
		} else if (c == ctrl('X')) {
			/* mouse */
			(void) getmouseevent(); 	/* ignore it */
		} else if (c == EOF) {			/* end-of-file */
			break;
		}
		/* return on an empty line to allow a command to be entered */
		if (firstchar != '\0' && i == 0) {
			break;
		}
	}
	s[i] = '\0';
	return (i);
}

/* ask user to enter a character after reading the message */

void
askforchar(void)
{
	(void) addstr("Type any character to continue: ");
	(void) mygetch();
}

/* ask user to press the RETURN key after reading the message */

void
askforreturn(void)
{
	if (linemode == NO) {
		(void) fprintf(stderr, "Press the RETURN key to continue: ");
		(void) getchar();
	}
}

/* expand the ~ and $ shell meta characters in a path */

void
shellpath(char *out, int limit, char *in)
{
	char	*lastchar;
	char	*s, *v;

	/* skip leading white space */
	while (isspace(*in)) {
		++in;
	}
	lastchar = out + limit - 1;

	/*
	 * a tilde (~) by itself represents $HOME; followed by a name it
	 * represents the $LOGDIR of that login name
	 */
	if (*in == '~') {
		*out++ = *in++;	/* copy the ~ because it may not be expanded */

		/* get the login name */
		s = out;
		while (s < lastchar && *in != '/' && *in != '\0' &&
		    !isspace(*in)) {
			*s++ = *in++;
		}
		*s = '\0';

		/* if the login name is null, then use $HOME */
		if (*out == '\0') {
			v = getenv("HOME");
		} else {	/* get the home directory of the login name */
			v = logdir(out);
		}
		/* copy the directory name */
		if (v != NULL) {
			(void) strcpy(out - 1, v);
			out += strlen(v) - 1;
		} else {
			/* login not found so ~ must be part of the file name */
			out += strlen(out);
		}
	}
	/* get the rest of the path */
	while (out < lastchar && *in != '\0' && !isspace(*in)) {

		/* look for an environment variable */
		if (*in == '$') {
			/* copy the $ because it may not be expanded */
			*out++ = *in++;

			/* get the variable name */
			s = out;
			while (s < lastchar && *in != '/' && *in != '\0' &&
			    !isspace(*in)) {
				*s++ = *in++;
			}
			*s = '\0';

			/* get its value */
			if ((v = getenv(out)) != NULL) {
				(void) strcpy(out - 1, v);
				out += strlen(v) - 1;
			} else {
				/*
				 * var not found, so $ must be part of
				 * the file name
				 */
				out += strlen(out);
			}
		} else {	/* ordinary character */
			*out++ = *in++;
		}
	}
	*out = '\0';
}
