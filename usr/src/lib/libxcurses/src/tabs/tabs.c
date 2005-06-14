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
/*
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	tabs.c			
 *
 *	Copyright 1990, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	PORTABILITY:
 *	POSIX.2a UPE full support
 *	SVID 3 full support except +m option is stubbed
 *	XPG full support except +m option is stubbed
 *
 *	SYNOPSIS:
 *	tabs [-T term] [+m[n]] [-n]
 *	tabs [-T term] [+m[n]] -t tablist 
 *	tabs [-T term] [+m[n]] n1[,n2,...]
 *	tabs [-T term] [+m[n]] tabspec
 *	
 *	DESCRIPTION:
 *	The tabs utility shall display a series of characters that first clears
 *	the hardware terminal tab settings and then initializes the tab stops
 *	at the specified positions.
 *
 *	The phrase "tab-stop position N" shall be taken to mean that, from the
 *	start of a line of output, tabbing to position N shall cause the next
 *	character output to be in the (N+1)th column position on that line.
 *	The maximum number of tab stops allowed is terminal dependent.
 *
 *	'tabspec' is one of the following:
 *
 *	Assembler:
 *	-a	1,10,16,36,72
 *	-a2	1,10,16,40,72
 *	-u	1,12,20,44
 *
 *	COBOL:
 *	-c	1,8,12,16,20,55
 *	-c2	1,6,10,14,49
 *	-c3	1,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,67
 *
 *	FORTRAN:
 *	-f	1,7,11,15,19,23
 *
 *	PL/I:
 *	-p	1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61
 *
 *	SNOBOL:
 *	-s	1,10,55
 *
 *
 *	EXIT STATUS:
 *	0	successful completion.
 *
 *	>0	An error occured.
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: tabs.c 1.20 1995/09/21 21:00:28 ant Exp $";
#endif
#endif

#include <mks.h>
#include <curses.h>
#define SINGLE	1		/* only one terminal to be concerned about */
#include <term.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *_cmdname;


/* Exit Status */
#define SUCCESS		0
#define NOT_DEFINED	1
#define USAGE		2
#define BAD_TERMINAL	3
#define NOT_VALID	4
#define ERROR		5

#define NO_FORM	0
#define N_FORM	1	/* tabs [-T term] [+m[n]] [-<n>] */
#define T_FORM	2	/* tabs [-T term] [+m[n]] -t tablist */
#define P_FORM	3	/* tabs [-T term] [+m[n]] n1[,n2,...]  and
			 * tabs [-T term] [+m[n]] tabspec 
			 */ 


static int form = NO_FORM;
static int n_width = 8;
static int margin = 0;
static wchar_t *tablist;

typedef struct {
	char *option;
	char *list;
} predefined;

static predefined tabspec[] = {
	{ "a", "1,10,16,36,72" },
	{ "a2", "1,10,16,40,72" },
	{ "u", "1,12,20,44" },
	{ "c", "1,8,12,16,20,55" },
	{ "c2", "1,6,10,14,49" },
	{ "c3", "1,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,67" },
	{ "f", "1,7,11,15,19,23" },
	{ "p", "1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61" },
	{ "s", "1,10,55" },
	{ NULL, NULL }
};

static char *term_name;
static char dumb_term[] = "dumb";
static char missing_tablist[] = m_textstr(1828, "Missing tab list after -t.\n", "E");
static char missing_terminal[] = m_textstr(1829, "Missing terminal type after -T.\n", "E");
static char unknown_option[] = m_textstr(433, "Unknown option \"-%s\".\n", "E option");
static char bad_list[] = m_textstr(1830, "Illegal tabs in \"%s\".\n", "E tablist");
static char no_margins[] = m_textstr(1831, "Cannot set margins on terminal \"%s\".\n", "E term");
static char no_tabs[] = m_textstr(1832, "Cannot set tabs on terminal \"%s\".\n", "E term");
static char not_ascending[] = m_textstr(1833, "\"%s\" are not in ascending order.\n", "E tablist");
static char usage_msg[] = m_textstr(1834, "\
Usage: tabs [-T term] [+m[n]] [-n]\n\
       tabs [-T term] [+m[n]] -t <tablist>\n\
       tabs [-T term] [+m[n]] n1[,n2,...]\n\
       tabs [-T term] [+m[n]] -a|a2|u|c|c2|c3|f|p|s\n", "U");


STATREF int do_tabs ANSI((void));
STATREF void err_msg ANSI((char *fmt, ...));	/* GENTEXT: err_msg */
STATREF void mvcol ANSI((int oc, int nc));
STATREF void set_every ANSI((int n));
STATREF void set_tab_at ANSI((int x));
STATREF int usage ANSI((void));


/*f
 * mainline for tabs
 */
int 
main(argc, argv)
int argc;
char **argv;
{
	char *ap;
	int i;
	int err_code;
	predefined *p;
	setlocale(LC_ALL, "");
	_cmdname = m_cmdname(*argv);
	if ((term_name = getenv("TERM")) == NULL)
		term_name = dumb_term;
	while (0 < --argc && (**++argv == '-' || **argv == '+')) {
		ap = &argv[0][1];

		/* Check for standard io '-' */
		if (*ap == '\0')
			break;
		/* End option list '--'? */
		if (*ap == '-' && ap[1] == '\0') {
			++argv;
			--argc;
			break;
		}
		if (**argv == '-') {
			/* '-xyz...' or '-xyzF<parm>' or '-xyzF <parm>' */ 
			for (;*ap != '\0'; ++ap) {
				switch (*ap) {
				case 't':
					if (form != NO_FORM) 
						return (usage());
					form = T_FORM;
					if (*++ap != '\0') {
						tablist = m_mbstowcsdup(ap);
						break;
					} else if (1 < argc) {
						tablist = m_mbstowcsdup(*++argv);
						--argc;
						break;
					}
					err_msg(missing_tablist); 
					return (usage());
					break;
				case 'T':
					/* '-T<term>' or '-T <term>' */
					if (*++ap != '\0') {
						term_name = ap;
						break;
					} else if (1 < argc) {
						term_name = *++argv;
						--argc;
						break;
					}
					err_msg(missing_terminal); 
					return (usage());
				default:
					if (isdigit(*ap)) {
						if (form != NO_FORM)
							return (usage());
						form = N_FORM;
						n_width =  *ap - '0';
						continue;
					}
					for (p = tabspec; 
					     p->option != NULL 
					     && strcmp(p->option, ap) != 0; 
					     ++p)
						;
					if (p->option != NULL) {
						form = P_FORM;
						tablist = m_mbstowcsdup(p->list);
						break;
					}
					err_msg(unknown_option, ap);
					return (usage());
				}
				break;
			}
		} else {
			/* All '+' options. */
			if (*ap == 'm') {
				margin = (int) strtol(++ap, NULL, 0);
				if (margin == 0) 
					margin = 10;
			} else {
				err_msg(unknown_option, ap);
				return (usage());
			}
		}
	}
	if (form == NO_FORM) {
		switch (argc) {
		case 0:
			form = N_FORM;
			break;
		case 1:
			form = P_FORM;
			tablist = m_mbstowcsdup(*argv);
			break;
		default:
			return (usage());
		}
	} else if (0 < argc) {
		return (usage());
	}
	(void) setupterm(term_name, fileno(stdout), &err_code);
	switch (err_code) {
	case 1:
		break;
	case 0:
		err_msg(m_textstr(202, "Unknown terminal \"%s\".\n", "E term"), term_name);
		return (BAD_TERMINAL);
	case -1:
		err_msg(m_textstr(203, "No terminfo database.\n", "E"));
		return (BAD_TERMINAL);
	}
	if (save_cursor != NULL)
		putp(save_cursor);
	err_code = do_tabs();
	if (restore_cursor != NULL)
		putp(restore_cursor);
	else
		mvcol(0, 0);
	return (err_code);
}

/*f
 * actually do tabs
 */
STATIC int
do_tabs()
{
	int oc = 0;
	int nc = 0;
	wchar_t *p = tablist;
	if (clear_all_tabs == NULL || set_tab == NULL) {
		err_msg(no_tabs, term_name);
		return (NOT_DEFINED);
	}
	mvcol(0, 0);
	putp(clear_all_tabs);
#if 0	/* margins are not yet supported in terminfo */
	if (clear_margins == NULL || set_left_margin == NULL) {
		err_msg(no_margins, term_name);
		return (NOT_DEFINED);
	} else {
		putp(clear_margins);
		mvcol(0, margin);
		putp(set_left_margin);
	}
#endif
	switch (form) {
	case N_FORM:
		if (0 < n_width)
			set_every(n_width);
		break;
	case T_FORM:
		nc = (int) wcstol(p, &p, 0);
		if (p == tablist || nc < 0) {
			err_msg(bad_list, tablist);
			return (NOT_VALID);
		}
		if (*p == '\0') {
			set_every(nc);
			break;
		} 
		do {
			if (nc <= oc) {
				err_msg(not_ascending, tablist);
				return (NOT_VALID);
			}
			if (*p != '\0' && *p != ',' && !iswblank(*p)) {
				err_msg(bad_list, tablist);
				return (NOT_VALID);
			}
			++p;
			oc = nc;
			set_tab_at(nc);
			nc = (int) wcstol(p, &p, 0);
		} while (nc != 0);
		break;
	case P_FORM:
		if (*p == '+' || *p == '-') {
			err_msg(bad_list, tablist);
			return (NOT_VALID);
		}
		for (;;) {
			nc += (int) wcstol(p, &p, 0);
			if (nc == 0)
				break;
			if (nc <= oc) {
				err_msg(not_ascending, tablist);
				return (NOT_VALID);
			}
			if (*p != '\0' && *p != ',' && !iswblank(*p)) {
				err_msg(bad_list, tablist);
				return (NOT_VALID);
			}
			++p;
			oc = nc;
			set_tab_at(nc);
			if (*p == '+')
				++p;
			else
				nc = 0;
		}
		break;
	}
	return (SUCCESS);
}

/*f
 *	Set a tab every n columns starting with column 0.
 */
STATIC void
set_every(n)
int n;
{
	int x;
	for (x = 0; x < columns; x += n)
		set_tab_at(x);
}

/*f
 *	Set tab at column x. Assume that cursor has been positioned at the
 *	start of the line before settiing the first tab.
 */
STATIC void
set_tab_at(x)
int x;
{
	static int col = 0;
	mvcol(col, x);
	putp(set_tab);
	col = x;
}

/*f
 *	Move the cursor on the current row from column 'col' to column 'x'.
 *	We can't use mvcur() because we have no idea what row we're on.
 */
STATIC void
mvcol(oc, nc)
int oc, nc;
{
	int diff = nc - oc;
	if (nc == 0) {
		putchar('\r');
	} else if (column_address != NULL) {
		putp(tparm(column_address, nc, 0, 0, 0, 0, 0, 0, 0, 0));
	} else if (parm_right_cursor != NULL) {
		putp(tparm(parm_right_cursor, diff, 0, 0, 0, 0, 0, 0, 0, 0));
	} else if (cursor_right != NULL) {
		while (diff--)
			putp(cursor_right);
	} else {
		while (diff--)
			putchar(' ');
	}
}

/*f
 * usage message for tabs
 */
STATIC int 
usage()
{
	(void) fprintf(stderr, m_strmsg(usage_msg));
	return (USAGE);
}

/*f
 * display error message
 */
STATIC void 
err_msg VARARG1(char*, fmt)
{
	va_list ap;
	(void) fprintf(stderr, "%s: ", _cmdname);
	va_start(ap, fmt);
	(void) vfprintf(stderr, m_strmsg(fmt), ap);
	va_end(ap);
}
