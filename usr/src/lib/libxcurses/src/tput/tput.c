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
 *	tput.c			
 *
 *	Copyright 1990, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	PORTABILITY:
 *	SVID 3 - fully
 *	POSIX.2a UPE - needs clarification between SVID 3 exit statues.
 *		       In particular exit 1 and 4 for string capnames.
 *	not in XPG 3
 *
 *	SYNOPSIS:
 *	tput [-T<term>] capname [parm1..parm9]
 *	tput [-T<term>] -S
 *	
 *	DESCRIPTION:
 *	tput lets you change your terminal's characteristics. The capname
 *	argument indicates how you want to change the characteristics.
 *	Some special capnames are:
 *
 *	clear		clear the screen 
 *	init		initialize terminal in an implemenation-defined way 
 *	reset		reset terminal in an implemenation-defined way 
 *	longname	print the full name of the ternminal (SVID)
 *
 *	Other capnames are supported and may take from 0 to 9 parameters. A
 *	list of them can be found in the SVID 3, vol 3. (SVID)
 *
 *	tput does its work by outputting approriate character sequences to the
 *	standard output. These character sequences are terminal-specific. If
 *	you specify  -T <type>, tput assumes that your terminal has the
 *	specified type and will issue sequences appropriate to that terminal.
 *
 *	If you do not specify -T, tput looks for an environment variable
 *	named TERM. If TERM exists, its value is assumed to give the terminal
 *	type. If TERM does not exist, tput assumes a default terminal type.
 *
 *	The  -S  option allows more than one capability per invocation of tput.
 *	The capabilities must be passed to tput from the standard input instead
 *	of the comamnd line. Only one capname is allowed per line. 
 *
 *	EXIT STATUS	
 *	tput may return the following status values:
 *
 *	0	Either a boolean capname is set true or a string capname was
 *		successfully written to the terminal.
 *
 *	1	No error message is printed. Returned if a boolean capname is 
 *		false or a string capname is not defined for the terminal.(SVID)
 *
 *	2	Usage error.
 *
 *	3	Unknown terminal <term> or no terminfo database.
 *
 *	4	Unknown terminfo capability <capname>.
 *
 *	>4	An error occured. 
 *
 *
 *	NOTE 1: If the Caps file that describes the terminfo database changes
 *	then a new term.h will be required.  See CURSES/tic related tools.
 *
 *	NOTE 2: tput has knowledge about the TERMINAL structure.
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: tput.c 1.28 1995/04/12 09:28:05 ross Exp $";
#endif
#endif

#include <mks.h>
#include <curses.h>
#include <term.h>
#include <ctype.h>
#include <limits.h>
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

static int S_flag = 0;
static char *term_name;
static char dumb_term[] = "dumb";
static char usage_msg[] = m_textstr(4931, "\
Usage: tput [-W] [-Tterm] capname [parm1..parm9]\n\
       tput [-W] [-Tterm] -S\n", "U");

STATREF void build_argv ANSI((int *ac, char ***av));
STATREF int do_tput ANSI((int _argc, char **_argv));
STATREF void init ANSI((void));
STATREF void reset ANSI((void));
STATREF int usage ANSI((void));
STATREF void err_msg ANSI((char *fmt, ...));	/* GENTEXT: err_msg */
STATREF void cat ANSI((char *_Fn));

/*f
 * mainline for tput
 */
int 
main(argc, argv)
int argc;
char **argv;
{
	int opt;
	int err_code;
	setlocale(LC_ALL, "");
	_cmdname = m_cmdname(*argv);
	if ((term_name = getenv("TERM")) == NULL) {
		term_name = dumb_term;
	} else {
		term_name = m_strdup(term_name);
	}

	/* Default uses the terminfo database without modification. */
	use_env(0);

	while ((opt = getopt(argc, argv, "ST:W")) != -1) {
		switch (opt) {
		case 'W':
			/* Environment/window size are consulted and may
			 * alter the database entries for lines and columns.
			 */ 
			use_env(1);
			break;
		case 'S':
			S_flag = 1;
			break;

		case 'T':
			term_name = optarg;
			break;

		default:
			return (usage());
		}
	}

	argc -= optind;
	argv += optind;

	if ((S_flag ^ (argc <= 0)) == 1)
		return (usage());
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
	do {
		if (S_flag) {
			build_argv(&argc, &argv);
			if (argc <= 0)
				break;
		}
		err_code = do_tput(argc, argv);
	} while (S_flag && err_code == SUCCESS);
	return (err_code);
}

/*f
 *	Get an input line from stdin and then break it up into an argv array.
 *	If EOF is reached then S_flag is set to 0. Only the first 10 strings
 *	are of any interest. Any extra are ignored. 
 */
STATIC void 
build_argv(ac, av)
int *ac;
char ***av;
{
	int i = 0;
	char *p;
	static char *v[10+1];
	static char buf[LINE_MAX];
	if ((*v = fgets(buf, LINE_MAX, stdin)) == NULL) {
		/* End of file or input error */
		S_flag = 0;
	} else {
		if ((p = strchr(buf, '\n')) != NULL)
			*p = '\0';
		for (p = buf; i < 10;) {
			while (isspace(*(unsigned char*) p))
				++p;
			if (*p == '\0')
				break;
			v[i++] = p;
			while (!isspace(*(unsigned char*) p) && *p != '\0')
				++p;
			if (*p == '\0')
				break;	
			*p++ = '\0';
		}
	}
	v[i] = NULL;
	*ac = i;
	*av = v;
}

/*f
 * 
 */
STATIC int
do_tput(_argc, _argv)
int _argc;
char **_argv;
{
	int i;
	long q[9];
	const char *p;
	char *end_num;

	if (strcmp(*_argv, "init") == 0)
		init();
	else if (strcmp(*_argv, "reset") == 0)
		reset();
	else if (strcmp(*_argv, "longname") == 0)
		(void) printf("%s\n", longname());
	else if ((i = tigetflag(*_argv)) != -1)
		return (!i);
	else if ((i = tigetnum(*_argv)) != -2)
		(void) printf("%d\n", i);
	else if ((p = tigetstr(*_argv)) != (char*) -1) {
		if (p == NULL)
			return (NOT_DEFINED);
		for (i = 0; i < 9; ++i) {
			if (1 < _argc) {
				--_argc;
				q[i] = strtol(*++_argv, &end_num, 0);
				if (*end_num != '\0') {
					/* The parameter must be a string
					 * so we save the pointer instead.
					 */
					q[i] = (long) *_argv;
				}
			} else {
				q[i] = 0L;
			} 
		}
		(void) putp(tparm(p, q[0], q[1], q[2], q[3],
			q[4], q[5], q[6], q[7], q[8]
		));
		fflush(stdout);
	} else {
		err_msg(m_textstr(1864, "Unknown terminfo capability \"%s\".\n", "E action"), *_argv);
		return (NOT_VALID);
	}
	return (SUCCESS);
}

/*f
 * 
 */
STATIC void
init()
{
	if (init_prog != NULL)
		(void) system(init_prog);
	if (init_1string != NULL)
		putp(init_1string);
	if (init_2string != NULL)
		putp(init_2string);
#if 0	/* currently not supported by our terminfo database */
	if (clear_margins != NULL)
		putp(clear_margins);
	if (set_left_margin != NULL)
		putp(set_left_margin);
	if (set_right_margin != NULL)
		putp(set_right_margin);
#endif
	/* TODO: setting of tabs using clear_all_tabs & set_tab. */ 
	if (init_file != NULL)
		cat(init_file);
	if (init_3string != NULL)
		putp(init_3string);
}

/*f
 * 
 */
STATIC void
reset()
{
	if (reset_1string != NULL)
		putp(reset_1string);
	if (reset_2string != NULL)
		putp(reset_2string);
	if (reset_file != NULL)
		cat(reset_file);
	if (reset_3string != NULL)
		putp(reset_3string);
}

/*f
 * usage message for tput
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

/*
 *  Print a file via putp().
 */
STATIC void
cat(fn)
char *fn;
{
	FILE *fp;
	char buf[LINE_MAX+1];
	if ((fp = fopen(fn, "rb")) == NULL)
		return;
	while (fgets(buf, LINE_MAX, fp) != NULL)
		putp(buf);
	(void) fclose(fp);
}
