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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "stdarg.h"
#include "lpsched.h"
#include <syslog.h>

static void log(char *, va_list);

/**
 ** open_logfile() - OPEN FILE FOR LOGGING MESSAGE
 **/

static int
open_logfile(char *name)
{
	char			path[80];

	snprintf(path, sizeof (path), "%s/%s", Lp_Logs, name);
	return (open_locked(path, "a", 0640));
}


/**
 ** fail() - LOG MESSAGE AND EXIT (ABORT IF DEBUGGING)
 **/

/*VARARGS1*/
void
fail(char *format, ...)
{
	va_list			ap;
    
	va_start (ap, format);
	log (format, ap);
	va_end (ap);

#if	defined(DEBUG)
	if (debug & DB_ABORT)
		abort ();
	else
#endif
		exit (1);
	/*NOTREACHED*/
}

/**
 ** note() - LOG MESSAGE
 **/

/*VARARGS1*/
void
note(char *format, ...)
{
	va_list			ap;

	va_start (ap, format);
	log (format, ap);
	va_end (ap);
}



/**
 ** mallocfail() - COMPLAIN ABOUT MEMORY ALLOCATION FAILURE
 **/

void
mallocfail(void)
{
	fail ("Memory allocation failed!\n");
	/*NOTREACHED*/
}

/**
 ** log() - LOW LEVEL ROUTINE THAT LOGS MESSSAGES
 **/

static void
log(char *format, va_list ap)
{
	int			close_it;
	int			fd;
	static int		nodate	= 0;
	char buf[BUFSIZ];

	vsyslog(LOG_DEBUG, format, ap);

	if (!am_in_background) {
		fd = 1;
		close_it = 0;
	} else {
		if ((fd = open_logfile("lpsched")) < 0)
			return;
		close_it = 1;
	}

	if (am_in_background && !nodate) {
		time_t curtime;
		struct tm *tm;

		time(&curtime);
		if ((tm = localtime(&curtime)) != NULL)
			fdprintf (fd, "%.2d/%.2d %.2d:%.2d:%.2d: ", 
			 	tm->tm_mon+1, tm->tm_mday, tm->tm_hour,
				tm->tm_min, tm->tm_sec);
		else
			fdprintf(fd, "bad date: ");
	}
	nodate = 0;

	vsnprintf (buf, sizeof (buf),  format, ap);
	write(fd, buf, strlen(buf));
	if (format[strlen(format) - 1] != '\n')
		nodate = 1;

	if (close_it)
		close(fd);
}

/**
 ** execlog()
 **/

/*VARARGS1*/
void
execlog(char *format, ...)
{
	va_list			ap;

#if	defined(DEBUG)
	int			fd	= open_logfile("exec");
	char			buf[BUFSIZ];
	EXEC *			ep;
	static int		nodate	= 0;

	va_start (ap, format);
	if (fd >= 0) {
		if (!nodate) {
			time_t now = time((time_t *)0);

			fdprintf (fd, "%24.24s: ", ctime(&now));
		}
		nodate = 0;
		if (!STREQU(format, "%e")) {
			vsnprintf (buf, sizeof (buf), format, ap);
			write(fd, buf, strlen(buf));
			if (format[strlen(format) - 1] != '\n')
				nodate = 1;
		} else switch ((ep = va_arg(ap, EXEC *))->type) {
		case EX_INTERF:
			fdprintf(fd, "      EX_INTERF %s %s\n",
				ep->ex.printer->printer->name,
				ep->ex.printer->request->secure->req_id);
			break;
		case EX_SLOWF:
			fdprintf(fd, "      EX_SLOWF %s\n",
				ep->ex.request->secure->req_id);
			break;
		case EX_ALERT:
			fdprintf(fd, "      EX_ALERT %s\n",
				ep->ex.printer->printer->name);
			break;
		case EX_FAULT_MESSAGE:
			fdprintf(fd, "      EX_FAULT_MESSAGE %s\n",
				ep->ex.printer->printer->name);
			break;
		case EX_FORM_MESSAGE:
			fdprintf(fd, "      EX_FORM_MESSAGE %s\n",
				ep->ex.form->form->name);
			break;
		case EX_FALERT:
			fdprintf(fd, "      EX_FALERT %s\n",
				ep->ex.form->form->name);
			break;
		case EX_PALERT:
			fdprintf(fd, "      EX_PALERT %s\n",
				ep->ex.pwheel->pwheel->name);
			break;
		case EX_NOTIFY:
			fdprintf(fd, "      EX_NOTIFY %s\n",
				ep->ex.request->secure->req_id);
			break;
		default:
			fdprintf (fd, "      EX_???\n");
			break;
		}
		close(fd);
	}
#endif
}
