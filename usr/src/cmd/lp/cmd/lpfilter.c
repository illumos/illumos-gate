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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <locale.h>

#include "lp.h"
#include "access.h"
#include "filters.h"
#include "msgs.h"

#define	WHO_AM_I	I_AM_LPFILTER
#include "oam.h"

#define	OPT_LIST	"f:F:ixl"

int			add_filter(),
			reload_filter(),
			delete_filter(),
			list_filter();

static void		alert_spooler(),
			same_complaints();

static char		*opt();

/*
 * Unfortunately, the LP requirements show the listing of a filter
 * to be in a different order than the stored filter table. We can't
 * change the stored version because it's the same as UNISON uses.
 * So, we can't reuse the "FL_..." #defines found in "filters.h".
 * But the following have similar use.
 */
#define FL_MAX_P	FL_MAX
# define FL_IGN_P	8
# define FL_PTYPS_P	2
# define FL_PRTRS_P	3
# define FL_ITYPS_P	0
# define FL_NAME_P	7
# define FL_OTYPS_P	1
# define FL_TYPE_P	4
# define FL_CMD_P	5
# define FL_TMPS_P	6

#define	TABLE		0
#define	TABLE_I		1

static struct headings {
	char			*v;
	short			len;
}		headings[FL_MAX_P] = {

#define	ENTRY(X)	X, sizeof(X)-1
	ENTRY("Input types:"),
	ENTRY("Output types:"),
	ENTRY("Printer types:"),
	ENTRY("Printers:"),
	ENTRY("Filter type:"),
	ENTRY("Command:"),
	ENTRY("Options:"),
	ENTRY(""),
	ENTRY("")
#undef	ENTRY

};

/**
 ** usage()
 **/

void			usage ()
{
	(void) printf (gettext(
"usage:\n"
"\n"
"  (add or change filter)\n"
"    lpfilter -f filter-name {-F path-name | -}\n"
"\n"
"  (restore delivered filter)\n"
"    lpfilter -f filter-name -i\n"
"\n"
"  (list a filter)\n"
"    lpfilter -f filter-name -l\n"
"\n"
"  (list all filters)\n"
"    lpfilter -f \"all\" -l\n"
"\n"
"  (delete filter)\n"
"    lpfilter -f filter-name -x\n"));

	return;
}

/**
 ** main()
 **/

int			main (argc, argv)
	int			argc;
	char			*argv[];
{
	extern int		optind,
				opterr,
				optopt,
				getopt();

	extern char		*optarg;

	int			c,
				(*action)(),
				(*newaction)();

	FILE			*input;

	char			*filter,
				*p;
	char			stroptsw[] = "-X";


	(void) setlocale (LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (!is_user_admin()) {
		LP_ERRMSG (ERROR, E_LP_NOTADM);
		exit (1);
	}

	action = 0;
	input = 0;
	filter = 0;

	opterr = 0;

	while ((c = getopt(argc, argv, OPT_LIST)) != -1) switch (c) {

	case 'f':
		if (filter)
			LP_ERRMSG1 (WARNING, E_LP_2MANY, 'f');
		filter = optarg;
		if (
			STREQU(NAME_ANY, filter)
		     || STREQU(NAME_NONE, filter)
		) {
			LP_ERRMSG (ERROR, E_LP_ANYNONE);
			exit (1);
		} else if (!syn_name(filter)) {
			LP_ERRMSG1 (ERROR, E_LP_NOTNAME, filter);
			exit (1);
		} else if (!*filter)
			filter = NAME_ALL;
		break;

	case 'F':
		if (input)
			LP_ERRMSG1 (WARNING, E_LP_2MANY, 'F');
		if (!(input = fopen(optarg, "r"))) {
			LP_ERRMSG1 (ERROR, E_FL_OPEN, optarg);
			exit (1);
		}
		newaction = add_filter;
		goto Check;

	case 'i':
		newaction = reload_filter;
		goto Check;

	case 'x':
		newaction = delete_filter;
		goto Check;

	case 'l':
		newaction = list_filter;
Check:		if (action && newaction != action) {
			LP_ERRMSG2 (
				ERROR,
				E_LP_AMBIG,
				opt(action),
				opt(newaction)
			);
			exit (1);
		}
		action = newaction;
		break;

	default:
		if (optopt == '?') {
			usage ();
			exit (0);
		}
		stroptsw[1] = optopt;
		if (strchr(OPT_LIST, optopt))
			LP_ERRMSG1 (ERROR, E_LP_OPTARG, stroptsw);
		else
			LP_ERRMSG1 (ERROR, E_LP_OPTION, stroptsw);
		exit (1);

	}

	if (optind < argc && STREQU(argv[optind], "-"))
		if (action) {
	 		LP_ERRMSG2 (ERROR, E_LP_AMBIG, opt(action), "-");
			exit (1);
		} else {
			action = add_filter;
			optind++;
		}

	if (!filter) {
		LP_ERRMSG (ERROR, E_FL_NOFILT);
		exit (1);
	}

	if (!action) {
		LP_ERRMSG (ERROR, E_FL_NOACT);
		exit (1);
	}

	if (optind < argc)
		LP_ERRMSG1 (WARNING, E_FL_IGNORE, argv[optind]);

	return ((*action)(filter, input));
}

/**
 ** add_filter()
 **/

int			add_filter (filter, input)
	char			*filter;
	FILE			*input;
{
	register FILTER		*pf,
				*store,
				*ps;

	register int		fld;

	register char		*p;

	char			buf[3 * BUFSIZ],
				*file;

	int			line,
				bad_headings,
				real_fields[FL_MAX],
				at_least_one,
				ret;

	FILTER			flbuf;


	/*
	 * First we read in the input and parse it into a filter,
	 * storing it in the filter buffer "flbuf". Keep track of
	 * which fields have been given, to avoid overwriting unchanged
	 * fields later.
	 */

	if (!input)
		input = stdin;

	for (fld = 0; fld < FL_MAX; fld++)
		real_fields[fld] = 0;
	flbuf.templates = 0;

	line = bad_headings = 0;
	while (fgets(buf, sizeof(buf), input) != NULL) {

		buf[strlen(buf) - 1] = 0;

		line++;

		p = buf + strspn(buf, " \t");
		if (!*p || *p == '#')
			continue;

		for (fld = 0; fld < FL_MAX; fld++)
			if (
				headings[fld].v
			     && headings[fld].len
			     && CS_STRNEQU(
					p,
					headings[fld].v,
					headings[fld].len
				)
			) {
				real_fields[fld] = 1;
				p += headings[fld].len + 1;
				break;
			}

		if (fld >= FL_MAX) {

			if (bad_headings++ >= 5) {
				LP_ERRMSG (ERROR, E_FL_GARBAGE);
				return (1);
			}
			LP_ERRMSG1 (WARNING, E_FL_HEADING, line);

		} else switch (fld) {

			case FL_IGN_P:
			case FL_NAME_P:
				break;
			case FL_CMD_P:
				flbuf.command = strdup(strip(p));
				break;
			case FL_TYPE_P:
				flbuf.type = s_to_filtertype(strip(p));
				break;
			case FL_PTYPS_P:
				flbuf.printer_types = getlist(p, LP_WS, LP_SEP);
				break;
			case FL_ITYPS_P:
				flbuf.input_types = getlist(p, LP_WS, LP_SEP);
				break;
			case FL_OTYPS_P:
				flbuf.output_types = getlist(p, LP_WS, LP_SEP);
				break;
			case FL_PRTRS_P:
				flbuf.printers = getlist(p, LP_WS, LP_SEP);
				break;
			case FL_TMPS_P:
				if (flbuf.templates) {
					char			**temp;

					temp = getlist(p, "", LP_SEP);
					mergelist (&(flbuf.templates), temp);
					freelist (temp);
				} else
					flbuf.templates = getlist(p, "", LP_SEP);
				break;

		}

	}
	if (ferror(input)) {
		LP_ERRMSG (ERROR, E_FL_READ);
		return (1);
	}

	/*
	 * We have the input stored, now get the current copy of the
	 * filter(s). If no filter exists, we create it.
	 */

	if (STREQU(NAME_ALL, filter)) {

		/*
		 * Adding ``all'' means changing all filters to reflect
		 * the information in the input. We'll preload the
		 * filters so that we know how many there are.
		 */
		if (
			!(file = getfilterfile(FILTERTABLE))
		     || loadfilters(file) == -1
		) {
			switch (errno) {
			case ENOENT:
				LP_ERRMSG (ERROR, E_FL_NOTALL);
				break;
			default:
				same_complaints (FILTERTABLE, TABLE);
				break;
			}
			return (1);
		}

		store = (FILTER *)malloc((nfilters + 1) * sizeof(FILTER));
		if (!store) {
			LP_ERRMSG (ERROR, E_LP_MALLOC);
			return (1);
		}

		for (ps = store; (pf = getfilter(filter)); )
			*ps++ = *pf;
		ps->name = 0;

		switch (errno) {
		case ENOENT:
			if (ps - store != nfilters) {
				LP_ERRMSG1 (
					ERROR,
					E_FL_STRANGE,
					getfilterfile(FILTERTABLE)
				);
				return (1);
			}
			break;
		default:
			same_complaints (FILTERTABLE, TABLE);
			return (1);
		}

	} else {

		store = (FILTER *)malloc(2 * sizeof(FILTER));
		if (!store) {
			LP_ERRMSG (ERROR, E_LP_MALLOC);
			return (1);
		}

		if ((pf = getfilter(filter))) {
			store[0] = *pf;
		} else
			switch (errno) {
			case ENOENT:
				/*
				 * We must be adding a new filter, so
				 * set up default values. Check that
				 * we'll have something reasonable to add.
				 */
				pf = store;
				pf->name = strdup(filter);
				pf->command = 0;
				pf->type = fl_slow;
				pf->printer_types = 0;
				pf->printers = 0;
				pf->input_types = 0;
				pf->output_types = 0;
				pf->templates = 0;
				if (!flbuf.command) {
					LP_ERRMSG (ERROR, E_FL_NOCMD);
					return (1);
				}
				break;
			default:
				same_complaints (FILTERTABLE, TABLE);
				return (1);
			}

		store[1].name = 0;

	}

	at_least_one = ret = 0;
	for (ps = store; ps->name; ps++) {

		for (fld = 0; fld < FL_MAX; fld++)
			if (real_fields[fld]) switch(fld) {
			case FL_IGN_P:
			case FL_NAME_P:
				break;
			case FL_CMD_P:
				ps->command = flbuf.command;
				break;
			case FL_TYPE_P:
				ps->type = flbuf.type;
				break;
			case FL_PTYPS_P:
				ps->printer_types = flbuf.printer_types;
				break;
			case FL_ITYPS_P:
				ps->input_types = flbuf.input_types;
				break;
			case FL_OTYPS_P:
				ps->output_types = flbuf.output_types;
				break;
			case FL_PRTRS_P:
				ps->printers = flbuf.printers;
				break;
			case FL_TMPS_P:
				ps->templates = flbuf.templates;
				break;
			}

		if (putfilter(ps->name, ps) == -1) {
			if (errno == EBADF)  switch (lp_errno) {
			case LP_ETEMPLATE:
				LP_ERRMSG (ERROR, E_FL_BADTEMPLATE);
				break;
			case LP_EKEYWORD:
				LP_ERRMSG (ERROR, E_FL_BADKEY);
				break;
			case LP_EPATTERN:
				LP_ERRMSG (ERROR, E_FL_BADPATT);
				break;
			case LP_EREGEX:
			{
				char *			why;

				extern int		regerrno;


				switch (regerrno) {
				case 11:
					why = "range endpoint too large";
					break;
				case 16:
					why = "bad number";
					break;
				case 25:
					why = "\"\\digit\" out of range";
					break;
				case 36:
					why = "illegal or missing delimiter";
					break;
				case 41:
					why = "no remembered search string";
					break;
				case 42:
					why = "\\(...\\) imbalance";
					break;
				case 43:
					why = "too many \\(";
					break;
				case 44:
					why = "more than 2 numbers given in \\{...\\}";
					break;
				case 45:
					why = "} expected after \\";
					break;
				case 46:
					why = "first number exceeds second in \\{...\\}";
					break;
				case 49:
					why = "[...] imbalance";
					break;
				case 50:
					why = "regular expression overflow";
					break;
				}
				LP_ERRMSG1 (ERROR, E_FL_BADREGEX, why);
				break;
			}
			case LP_ERESULT:
				LP_ERRMSG (ERROR, E_FL_BADRESULT);
				break;
			case LP_ENOMEM:
				errno = ENOMEM;
				same_complaints (FILTERTABLE, TABLE);
				break;
			} else
				same_complaints (FILTERTABLE, TABLE);
			ret = 1;
			break;
		} else
			at_least_one = 1;

	}

	if (at_least_one)
		(void)alert_spooler ();

	return (ret);
}

/**
 ** reload_filter()
 **/

int			reload_filter (filter)
	char			*filter;
{
	register FILTER		*pf,
				*store,
				*ps;

	char			*factory_file;

	int			ret,
				at_least_one;

	/*
	 * ``Manually'' load the archived filters, so that a call
	 * to "getfilter()" will read from them instead of the regular
	 * table.
	 */
	if (
		!(factory_file = getfilterfile(FILTERTABLE_I))
	     || loadfilters(factory_file) == -1
	) {
		switch (errno) {
		case ENOENT:
			LP_ERRMSG (ERROR, E_FL_NOFACTY);
			break;
		default:
			same_complaints (FILTERTABLE_I, TABLE_I);
			break;
		}
		return (1);
	}

	if (STREQU(NAME_ALL, filter)) {

		store = (FILTER *)malloc((nfilters + 1) * sizeof(FILTER));
		if (!store) {
			LP_ERRMSG (ERROR, E_LP_MALLOC);
			return (1);
		}

		for (ps = store; (pf = getfilter(filter)); )
			*ps++ = *pf;
		ps->name = 0;

		switch (errno) {
		case ENOENT:
			if (ps - store != nfilters) {
				LP_ERRMSG1 (
					ERROR,
					E_FL_STRANGE,
					getfilterfile(FILTERTABLE_I)
				);
				return (1);
			}
			break;
		default:
			same_complaints (FILTERTABLE_I, TABLE_I);
			return (1);
		}

	} else {

		store = (FILTER *)malloc(2 * sizeof(FILTER));
		if (!store) {
			LP_ERRMSG (ERROR, E_LP_MALLOC);
			return (1);
		}

		if (!(pf = getfilter(filter))) switch (errno) {
		case ENOENT:
			LP_ERRMSG (ERROR, E_FL_FACTYNM);
			return (1);
		default:
			same_complaints (FILTERTABLE_I, TABLE_I);
			return (1);
		}

		store[0] = *pf;
		store[1].name = 0;

	}

	/*
	 * Having stored the archived filter(s) in our own area, clear
	 * the currently loaded table so that the subsequent calls to
	 * "putfilter()" will read in the regular table.
	 */
	trash_filters ();

	at_least_one = ret = 0;
	for (ps = store; ps->name; ps++)
		if (putfilter(ps->name, ps) == -1) {
			same_complaints (FILTERTABLE, TABLE);
			ret = 1;
			break;
		} else
			at_least_one = 1;

	if (at_least_one)
		(void)alert_spooler ();

	return (ret);
}

/**
 ** delete_filter()
 **/

int			delete_filter (filter)
	char			*filter;
{
	if (delfilter(filter) == -1) switch (errno) {
	case ENOENT:
		LP_ERRMSG1 (ERROR, E_FL_UNKFILT, filter);
		return (1);
	default:
		same_complaints (FILTERTABLE, TABLE);
		return (1);
	}

	(void)alert_spooler ();

	return (0);
}

/**
 ** list_filter()
 **/

static void		_list_filter();

int			list_filter (filter)
	char			*filter;
{
	register FILTER		*pf;

	char			*nl;

	if (STREQU(NAME_ALL, filter)) {

		nl = "";
		while ((pf = getfilter(filter))) {
			printf (gettext("%s(Filter \"%s\")\n"), nl, pf->name);
			_list_filter (pf);
			nl = "\n";
		}

		switch (errno) {
		case ENOENT:
			return (0);
		default:
			same_complaints (FILTERTABLE, TABLE);
			return (1);
		}

	} else {

		if ((pf = getfilter(filter))) {
			_list_filter (pf);
			return (0);
		}

		switch (errno) {
		case ENOENT:
			LP_ERRMSG1 (ERROR, E_FL_UNKFILT, filter);
			return (1);
		default:
			same_complaints (FILTERTABLE, TABLE);
			return (1);
		}

	}
}

static void		_list_filter (pf)
	register FILTER		*pf;
{
	register char		**pp,
				*sep;

	register int		fld;

	char *			head;


	for (fld = 0; fld < FL_MAX_P; fld++) switch (fld) {
	case FL_IGN_P:
	case FL_NAME_P:
		break;
	case FL_CMD_P:
		printf (
			"%s %s\n",
			headings[fld].v,
			(pf->command? pf->command : "")
		);
		break;
	case FL_TYPE_P:
		printf (
			"%s %s\n",
			headings[fld].v,
			(pf->type == fl_fast? FL_FAST : FL_SLOW)
		);
		break;
	case FL_PTYPS_P:
		pp = pf->printer_types;
		goto Lists;
	case FL_ITYPS_P:
		pp = pf->input_types;
		goto Lists;
	case FL_OTYPS_P:
		pp = pf->output_types;
		goto Lists;
	case FL_PRTRS_P:
		pp = pf->printers;
Lists:		printlist_qsep = 1;
		printlist_setup ("", "", LP_SEP, "");
		printf ("%s ", headings[fld].v);
		printlist (stdout, pp);
		printf ("\n");
		break;
	case FL_TMPS_P:
		head = makestr(headings[fld].v, " ", (char *)0);
		printlist_qsep = 1;
		printlist_setup (head, "", "\n", "\n");
		printlist (stdout, pf->templates);
		break;
	}

	return;
}

/**
 ** opt() - GENERATE OPTION FROM FUNCTION NAME
 **/

static char		*opt (fnc)
	int			(*fnc)();
{
	if (fnc == add_filter)
		return ("-F");
	else if (fnc == reload_filter)
		return ("-i");
	else if (fnc == list_filter)
		return ("-l");
	else if (fnc == delete_filter)
		return ("-x");
	else
		return ("-?");
}

/**
 ** alert_spooler() - TELL SPOOLER TO LOAD FILTER TABLE
 **/

static void		alert_spooler ()
{
	char			msgbuf[MSGMAX];

	int			mtype;

	short			status;

	/*
	 * If the attempt to open a message queue to the
	 * Spooler fails, assume it isn't running and just
	 * return--don't say anything, `cause the user may
	 * know. Any other failure deserves an error message.
	 */

	if (mopen() == -1)
		return;

	(void)putmessage (msgbuf, S_LOAD_FILTER_TABLE);

	if (msend(msgbuf) == -1)
		goto Error;
	if (mrecv(msgbuf, MSGMAX) == -1)
		goto Error;

	mtype = getmessage(msgbuf, R_LOAD_FILTER_TABLE, &status);
	if (mtype != R_LOAD_FILTER_TABLE) {
		LP_ERRMSG1 (ERROR, E_LP_BADREPLY, mtype);
		(void)mclose ();
		exit (1);
	}

	if (status == MOK)
		goto NoError;

Error:	LP_ERRMSG (ERROR, E_FL_NOSPLOAD);

NoError:(void)mclose ();
	return;

}

/**
 ** same_complaints() - PRINT COMMON ERROR MESSAGES
 **/

static void		same_complaints (table, type)
	char			*table;
	int			type;
{
	switch (errno) {
	case EACCES:
		if (type == TABLE)
			LP_ERRMSG1 (
				ERROR,
				E_FL_ACCESS,
				getfilterfile(table)
			);
		else
			LP_ERRMSG1 (
				ERROR,
				E_FL_ACCESSI,
				getfilterfile(table)
			);
		break;
	case EAGAIN:
	case EDEADLK:
		LP_ERRMSG1 (ERROR, E_LP_AGAIN, getfilterfile(table));
		break;
	default:
		LP_ERRMSG2 (
			ERROR,
			E_FL_UNKNOWN,
			getfilterfile(table),
			strerror(errno)
		);
		break;
	}
	return;
}
