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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.14	*/

#include "stdio.h"
#include "stdlib.h"
#include "signal.h"
#include "string.h"
#include "errno.h"
#if	defined(__STDC__)
#include "stdarg.h"
#else
#include "varargs.h"
#endif
#include "sys/types.h"

#include "lp.h"
#include "requests.h"
#include "msgs.h"

#define WHO_AM_I	I_AM_CANCEL
#include "oam.h"
#include <locale.h>

#define	OPT_LIST	"u:"

/*
 * There are no sections of code in this progam that have to be
 * protected from interrupts. We do want to catch them, however,
 * so we can clean up properly.
 */

char			*users = NULL;

void			startup(),
			cleanup(),
			cancel(),
			restart(),	/* a misnomer */
			ucancel();

#if	defined(__STDC__)
void			send_message ( int , ... );
void			recv_message ( int , ... );
#else
void			send_message(),
			recv_message();
#endif

/**
 ** usage()
 **/

void			usage ()
{
	(void) printf("%s\n", gettext("usage: cancel id ... printer ..."));
	(void) printf("%s\n", gettext("  or   cancel -u id-list printer ..."));

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

	int			c;

	char			*arg,
				*p,
				**users	= 0,
				**pu;

	setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;

	while ((c = getopt(argc, argv, OPT_LIST)) != -1) switch (c) {

	case 'u':
		if (users)
			LP_ERRMSG1 (WARNING, E_LP_2MANY, 'u');
		users = getlist(optarg, LP_WS, LP_SEP);
		break;

	default:
		if (optopt == '?') {
			usage ();
			exit (0);
		}
		(p = "-X")[1] = optopt;
		if (strchr(OPT_LIST, optopt))
			LP_ERRMSG1 (ERROR, E_LP_OPTARG, p);
		else
			LP_ERRMSG1 (ERROR, E_LP_OPTION, p);
		exit (1);

	}

	if (optind == argc && !users) {
		LP_ERRMSG (ERROR, E_CAN_NOACT);
		exit (1);
	}

	startup ();

	if (optind == argc)
		for (pu = users; *pu; pu++)
			ucancel (*pu, NAME_ALL);

	else while (optind < argc) {

		arg = argv[optind++];

		if (users) {
			if (isprinter(arg) || STREQU(NAME_ALL, arg))
				for (pu = users; *pu; pu++)
					ucancel (*pu, arg);
			else
				LP_ERRMSG1 (WARNING, E_CAN_BADARG, arg);
		} else
			if (isrequest(arg))
				cancel (arg);
			else if (isprinter(arg))
				restart (arg);
			else
				LP_ERRMSG1 (WARNING, E_CAN_BADARG, arg);

	}

	cleanup ();
	return (0);
}

/**
 ** cancel() - CANCEL ONE REQUEST
 **/

void			cancel (req)
	char			*req;
{
	short			status;

	/*
	 * Now try to cancel the request.
	 */

	send_message (S_CANCEL_REQUEST, req);
	recv_message (R_CANCEL_REQUEST, &status);

	switch (status) {

	case MOK:
		printf(gettext("request \"%s\" cancelled\n"), req);
		break;

	case MUNKNOWN:
	case MNOINFO:
		LP_ERRMSG1 (WARNING, E_LP_UNKREQID, req);
		break;

	case M2LATE:
		LP_ERRMSG1 (WARNING, E_LP_2LATE, req);
		break;

	case MNOPERM:
		LP_ERRMSG1 (WARNING, E_CAN_CANT, req);
		break;

	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
		cleanup ();
		exit (1);
	}
	return;
}

/**
 ** restart() - CANCEL REQUEST CURRENTLY PRINTING ON GIVEN PRINTER
 **/

void			restart (printer)
	char			*printer;
{
	char			*req_id,
				*s_ignore;

	short			status,
				h_ignore;

	long			l_ignore;


	/*
	 * Get the list of requests queued for this printer.
	 */

	send_message (S_INQUIRE_PRINTER_STATUS, printer);
	recv_message (
		R_INQUIRE_PRINTER_STATUS,
		&status,
		&s_ignore,	/* printer	*/
		&s_ignore,	/* form		*/
		&s_ignore,	/* print_wheel	*/
		&s_ignore,	/* dis_reason	*/
		&s_ignore,	/* rej_reason	*/
		&h_ignore,	/* p_status	*/
		&req_id,
		&l_ignore,	/* dis_date	*/
		&l_ignore	/* rej_date	*/
	);

	switch (status) {

	case MOK:
		if (!req_id || !*req_id)
			LP_ERRMSG1 (WARNING, E_LP_PNBUSY, printer);
		else
			cancel (req_id);
		break;

	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
		cleanup ();
		exit (1);

	}

	return;
}

/**
 ** ucancel()
 **/

void			ucancel (user, printer)
	char *			user;
	char *			printer;
{
	int			i;

	short			more;

	long			status;

	char *			req_id;
    

	send_message (S_CANCEL, printer, user, "");

	do {
		recv_message (R_CANCEL, &more, &status, &req_id);

		switch (status) {

		case MOK:
			printf(gettext("request \"%s\" cancelled\n"), req_id);
			break;

		case M2LATE:
			LP_ERRMSG1 (WARNING, E_LP_2LATE, req_id);
			break;

		case MNOPERM:
			LP_ERRMSG1 (WARNING, E_CAN_CANT, req_id);
			break;

		case MUNKNOWN:
		case MNOINFO:
			if (STREQU(user, NAME_ALL) && STREQU(printer, NAME_ALL))
				LP_ERRMSG (WARNING, E_CAN_ANYUSERANYP);
			else if (STREQU(user, NAME_ALL))
				LP_ERRMSG1 (WARNING, E_CAN_ANYUSERP, printer);
			else if (STREQU(printer, NAME_ALL))
				LP_ERRMSG1 (WARNING, E_CAN_NOUSERANYP, user);
			else
				LP_ERRMSG2 (WARNING, E_CAN_NOUSERP, printer, user);
			break;

		default:
			LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
			cleanup ();
			exit (1);
		}
    
	} while (more == MOKMORE);

	return;
}

/**
 ** startup() - OPEN MESSAGE QUEUE TO SPOOLER
 **/

void			startup ()
{
	void			catch();

	/*
	 * Open a private queue for messages to the Spooler.
	 * An error is deadly.
	 */
	if (mopen() == -1) {

		switch (errno) {
		case ENOMEM:
		case ENOSPC:
			LP_ERRMSG (ERROR, E_LP_MLATER);
			break;
		default:
			LP_ERRMSG (ERROR, E_LP_NEEDSCHED);
			break;
		}

		exit (1);
	}

	/*
	 * Now that the queue is open, quickly trap signals
	 * that we might get so we'll be able to close the
	 * queue again, regardless of what happens.
	 */
	if(signal(SIGHUP, SIG_IGN) != SIG_IGN)
		signal(SIGHUP, catch);
	if(signal(SIGINT, SIG_IGN) != SIG_IGN)
		signal(SIGINT, catch);
	if(signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		signal(SIGQUIT, catch);
	if(signal(SIGTERM, SIG_IGN) != SIG_IGN)
		signal(SIGTERM, catch);
}

/**
 ** catch() - CATCH INTERRUPT, HANGUP, ETC.
 **/

void			catch (sig)
	int			sig;
{
	signal (sig, SIG_IGN);
	cleanup ();
	exit (1);
}

/**
 ** cleanup() - CLOSE THE MESSAGE QUEUE TO THE SPOOLER
 **/

void			cleanup ()
{
	(void)mclose ();
	return;
}

/**
 ** send_message() - HANDLE MESSAGE SENDING TO SPOOLER
 **/

/*VARARGS1*/

void
#if	defined(__STDC__)
send_message (
	int			type,
	...
)
#else
send_message (type, va_alist)
	int			type;
	va_dcl
#endif
{
	va_list			ap;

	char			buffer[MSGMAX];


#if	defined(__STDC__)
	va_start (ap, type);
#else
	va_start (ap);
#endif

	switch (type) {

	case S_INQUIRE_PRINTER_STATUS:
	case S_CANCEL_REQUEST:
	case S_CANCEL:
		(void)_putmessage (buffer, type, ap);
		break;

	}

	va_end (ap);

	if (msend(buffer) == -1) {
		LP_ERRMSG (ERROR, E_LP_MSEND);
		cleanup ();
		exit (1);
	}

	return;
}

/**
 ** recv_message() - HANDLE MESSAGES BACK FROM SPOOLER
 **/

/*VARARGS1*/

void
#if	defined(__STDC__)
recv_message (
	int			type,
	...
)
#else
recv_message (type, va_alist)
	int			type;
	va_dcl
#endif
{
	va_list			ap;

	static char		buffer[MSGMAX];

	int			rc;


#if	defined(__STDC__)
	va_start (ap, type);
#else
	va_start (ap);
#endif

	if (mrecv(buffer, MSGMAX) != type) {
		LP_ERRMSG (ERROR, E_LP_MRECV);
		cleanup ();
		exit (1);
	}

	switch(type) {

	case R_INQUIRE_PRINTER_STATUS:
	case R_CANCEL_REQUEST:
	case R_CANCEL:
		rc = _getmessage(buffer, type, ap);
		if (rc != type) {
			LP_ERRMSG1 (ERROR, E_LP_BADREPLY, rc);
			cleanup ();
			exit (1);
		}
		break;

	}

	va_end (ap);

	return;
}
