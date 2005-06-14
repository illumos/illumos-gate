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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10	*/

#include "string.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"
#include <locale.h>

typedef struct execute {
	char			*list;
	void			(*func)();
	int			inquire_type;
	struct execute		*forward;
}			EXECUTE;

static int		r		= 0;
int			D		= 0,
			remote_cmd	= 0;

unsigned int		verbosity	= 0;

extern char		*optarg;

extern int		getopt(),
			optind,
			opterr,
			optopt;


static void		usage ( void );

#if	defined(CAN_DO_MODULES)
#define OPT_LIST	"a:c:do:p:rstu:v:f:TDS:lLRHP:"
#else
#define OPT_LIST	"a:c:do:p:rstu:v:f:TDS:lLRP:"
#endif

#define	QUEUE(LIST, FUNC, TYPE) \
	{ \
		next->list = LIST; \
		next->func = FUNC; \
		next->inquire_type = TYPE; \
		next->forward = (EXECUTE *)Malloc(sizeof(EXECUTE)); \
		(next = next->forward)->forward = 0; \
	}

/**
 ** parse() - PARSE COMMAND LINE OPTIONS
 **/

/*
 * This routine parses the command line, builds a linked list of
 * function calls desired, then executes them in the order they 
 * were received. This is necessary as we must apply -l to all 
 * options. So, we could either stash the calls away, or go
 * through parsing twice. I chose to build the linked list.
 */

void
parse(int argc, char **argv)
{
	int			optsw;
	int			ac;
	int			need_mount	= 0;

	char **			av;
	char *			p;
	char **			list;

	EXECUTE			linked_list;

	register EXECUTE *	next		= &linked_list;


	next->forward = 0;

	/*
	 * Add a fake value to the end of the "argv" list, to
	 * catch the case that a valued-option comes last.
	 */
	av = (char **)Malloc((argc + 2) * sizeof(char *));
	for (ac = 0; ac < argc; ac++)
		av[ac] = argv[ac];
	av[ac++] = "--";

	opterr = 0;

	while ((optsw = getopt(ac, (char * const *)av, OPT_LIST)) != -1) {

		switch(optsw) {

		/*
		 * These option letters MAY take a value. Check the value;
		 * if it begins with a '-', assume it's really the next
		 * argument.
		 */
		case 'a':
		case 'c':
		case 'o':
		case 'p':
		case 'u':
		case 'v':
		case 'f':
		case 'P':
		case 'S':
			if (*optarg == '-') {
				/*
				 * This will work if we were given
				 *
				 *	-x -foo
				 *
				 * but would fail if we were given
				 *
				 *	-x-foo
				 */
				optind--;
				optarg = NAME_ALL;
			}
			break;
		}
	
		switch(optsw) {
		case 'a':	/* acceptance status */
			QUEUE (optarg, do_accept, INQ_ACCEPT);
			break;

		case 'c':	/* class to printer mapping */
			QUEUE (optarg, do_class, 0);
			break;

		case 'd':	/* default destination */
			QUEUE (0, def, 0);
			break;

		case 'D':	/* Description of printers */
			D = 1;
			break;

		case 'f':	/* do forms */
			QUEUE (optarg, do_form, 0);
			need_mount = 1;
			break;

		case 'P':	/* do forms */
			QUEUE (optarg, do_paper, 0);
			break;

#if	defined(CAN_DO_MODULES)
		case 'H':	/* show modules pushed for printer */
			verbosity |= V_MODULES;
			break;
#endif

		case 'l':	/* verbose output */
			verbosity |= V_LONG;
			verbosity &= ~V_BITS;
			break;

		case 'L':	/* Local only */
			remote_cmd = 0;
			break;

		case 'o':	/* output for destinations */
			QUEUE (optarg, do_request, 0);
			break;

		case 'p':	/* printer status */
			QUEUE (optarg, do_printer, INQ_PRINTER);
			break;

		case 'R':	/* show rank in queue */
			verbosity |= V_RANK;
			break;

		case 'r':	/* is scheduler running? */
			QUEUE (0, running, 0);
			r = 1;
			break;

		case 's':	/* configuration summary */
			QUEUE (0, running, 0);
			QUEUE (0, def, 0);
			QUEUE (NAME_ALL, do_class, 0);
			QUEUE (NAME_ALL, do_device, 0);
			QUEUE (NAME_ALL, do_form, 0);
			QUEUE (NAME_ALL, do_charset, 0);
			r = 1;
			need_mount = 1;
			break;

		case 'S':	/* character set info */
			QUEUE (optarg, do_charset, 0);
			need_mount = 1;
			break;

		case 't':	/* print all info */
			QUEUE (0, running, 0);
			QUEUE (0, def, 0);
			QUEUE (NAME_ALL, do_class, 0);
			QUEUE (NAME_ALL, do_device, 0);
			QUEUE (NAME_ALL, do_accept, INQ_ACCEPT);
			QUEUE (NAME_ALL, do_printer, INQ_PRINTER);
			QUEUE (NAME_ALL, do_form, 0);
			QUEUE (NAME_ALL, do_charset, 0);
			QUEUE (NAME_ALL, do_request, 0);
			r = 1;
			need_mount = 1;
			break;

		case 'T':	/* (trace) special debugging output */
			verbosity |= V_BITS;
			verbosity &= ~V_LONG;
			break;

		case 'u':	/* output by user */
			QUEUE (optarg, do_user, INQ_USER);
			break;

		case 'v':	/* printers to devices mapping */
			QUEUE (optarg, do_device, 0);
			break;

		default:
			if (optopt == '?') {
				usage ();
				done (0);
			}

			(p = "-X")[1] = optopt;

			if (strchr(OPT_LIST, optopt))
				LP_ERRMSG1 (ERROR, E_LP_OPTARG, p);
			else
				LP_ERRMSG1 (ERROR, E_LP_USAGE, p);
			done(1);
			break;
		}

	}

#ifdef NEVER
	if (getenv("LPSTAT_NO_REMOTE"))
		remote_cmd = 0;
#endif NEVER

	/*
	 * Note: "argc" here, not "ac", to skip our fake option.
	 * We could use either "argv" or "av", since for the range
	 * of interest they're the same.
	 */

	list = 0;
	while (optind < argc)
		if (addlist(&list, av[optind++]) == -1) {
			LP_ERRMSG (ERROR, E_LP_MALLOC);
			done(1);
		}
	if (list)
		QUEUE (sprintlist(list), do_request, 0);

	if (argc == 1 || (verbosity & V_RANK) && argc == 2)
		QUEUE (getname(), do_user, INQ_USER);

	startup ();

	/*
		Linked list is completed, load up mount info if
		needed then do the requests
	*/

	if (need_mount) {
		inquire_type = INQ_STORE;
		do_printer (alllist);
	}

	for (next = &linked_list; next->forward; next = next->forward) {
		inquire_type = next->inquire_type;
		if (!next->list)
			(*next->func) ();
		else if (!*next->list)
			(*next->func) (alllist);
		else
			(*next->func) (getlist(next->list, LP_WS, LP_SEP));
	}

	return;
}

/**
 ** usage() - PRINT USAGE MESSAGE
 **/

static void
usage(void)
{

#if	defined(CAN_DO_MODULES)

	(void) printf (gettext(
"usage:\n"
"    lpstat [options] [request-ids]\n"
"	[-a printers,classes]		(show acceptance status)\n"
"	[-c classes]			(show available classes)\n"
"	[-d]				(show default destination)\n"
"	[-D]				(-p only: describe printers)\n"
"	[-f forms]			(show available forms)\n"
"	[-l]				(be verbose)\n"
"	[-o printers,classes,req-ids]	(show status of requests)\n"
"	[-p printers]			(show available printers)\n"
"	[-P]				(show paper types)\n"
"	[-R]				(show rank in queue)\n"
"	[-r]				(show status of Spooler)\n"
"	[-s]				(show summary status)\n"
"	[-S char-sets,print-wheels]	(show available \"fonts\")\n"
"	[-t]				(show status of everything)\n"
"	[-u users]			(show status of user requests)\n"
"	[-v printers [-H]]		(show devices used by printers)\n"
"		(\"all\" allowed with -a,-c,-f,-o,-p,-S,-u,-v options)\n"));
#else
 
        (void) printf (gettext(
"usage:\n"
"    lpstat [options] [request-ids]\n"
"        [-a printers,classes]           (show acceptance status)\n"
"        [-c classes]                    (show available classes)\n"
"        [-d]                            (show default destination)\n"
"        [-D]                            (-p only: describe printers)\n"
"        [-f forms]                      (show available forms)\n"
"        [-l]                            (be verbose)\n"
"        [-o printers,classes,req-ids]   (show status of requests)\n"
"        [-p printers]                   (show available printers)\n"
"        [-P]                            (show paper types)\n"
"        [-R]                            (show rank in queue)\n"
"        [-r]                            (show status of Spooler)\n"
"        [-s]                            (show summary status)\n"
"        [-S char-sets,print-wheels]     (show available \"fonts\")\n"
"        [-t]                            (show status of everything)\n"
"        [-u users]                      (show status of user requests)\n"
"        [-v printers]                   (show devices used by printers)\n"
"                (\"all\" allowed with -a,-c,-f,-o,-p,-S,-u,-v options)\n"));  
#endif
	return;
}
