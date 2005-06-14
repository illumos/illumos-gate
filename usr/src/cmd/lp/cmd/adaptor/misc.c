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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <sys/systeminfo.h>
#include <netdb.h>
#include <pwd.h>

#include <syslog.h>

#include "misc.h"

/* lpsched include files */
#include "lp.h"
#include "msgs.h"
#include "printers.h"

static char Msg[MSGMAX];


/*
 * Format and send message to lpsched
 * (die if any errors occur)
 */
/*VARARGS1*/
int
snd_msg(int type, ...)
{
	int rc = -1;
	va_list	ap;

	va_start(ap, type);
	if ((_putmessage(Msg, type, ap) >= 0) && (msend(Msg) >= 0))
		rc = 0;
	va_end(ap);
	return (rc);
}

/*
 * Recieve message from lpsched
 * (die if any errors occur)
 */
int
rcv_msg(int type, ...)
{
	int rc = -1;
	va_list ap;

	va_start(ap, type);
	if ((mrecv(Msg, MSGMAX) == type) && (_getmessage(Msg, type, ap) >= 0))
		rc = 0;
	va_end(ap);
	return (rc);
}


/*
 * id_no() pulls the job id number out of a request id in the format of
 *  printer-job_id
 */
int
id_no(const char *id)
{
	char *tmp;

	if ((id == NULL) || ((tmp = strrchr(id, '-')) == NULL))
		return (-1);
	tmp++;
	return (atoi(tmp));
}


/*
 * user_name() pulls the user name out of a string in the format of
 *  host!user or user@host
 */
char *
user_name(const char *user)
{
	static char result[BUFSIZ];
	char *tmp;

	if ((tmp = strchr(user, '@')) != NULL) {
		*tmp = '\0';
		snprintf(result, sizeof (result), "%s", user);
		*tmp = '@';
	} else if ((tmp = strrchr(user, '!')) != NULL)
		snprintf(result, sizeof (result), "%s", ++tmp);
	else
		snprintf(result, sizeof (result), "%s", user);

	return (result);
}


/*
 * host_name() pulls the host name out of a string in the format of
 *  host!user.  If no host exists, the local hostname is returned.
 */
char *
user_host(const char *user)
{
	static char host[MAXHOSTNAMELEN];
	char *tmp;

	snprintf(host, sizeof (host), "%s", user);
	if ((tmp = strrchr(user, '@')) != NULL) {
		snprintf(host, sizeof (host), "%s", ++tmp);
	} else if ((tmp = strrchr(user, '!')) != NULL) {
		*tmp = '\0';
		snprintf(host, sizeof (host), "%s", user);
		*tmp = '!';
	} else
		sysinfo(SI_HOSTNAME, host, sizeof (host));

	return (host);
}


/*
 * lpsched_server_available() opens the connection to lpsched
 */
int
lpsched_spooler_available(const char *printer)
{
	syslog(LOG_DEBUG, "lpsched_spooler_available(%s)",
		(printer ? printer : "NULL"));

	if (printer == NULL)
		return (-1);

	return (mopen());
}


/*
 * lpsched_spooler_accepting_jobs() will ask the spooler if it is currently
 * accepting jobs for the specified printer.  If it is, a 0 will be returned,
 * if not -1.
 */
int
lpsched_spooler_accepting_jobs(const char *printer)
{
	short status = 0,
		prstatus = 0;
	char *prname = NULL,
		*form = NULL,
		*pwheel = NULL,
		*dis_reason = NULL,
		*rej_reason = NULL,
		*reqid = NULL;
	time_t *dis_date = NULL,
		 *rej_date = NULL;

	syslog(LOG_DEBUG, "lpsched_spooler_accepting_jobs(%s)",
		(printer ? printer : "NULL"));

	if (printer == NULL)
		return (-1);

	if (isprinter((char *)printer)) {
		if ((snd_msg(S_INQUIRE_PRINTER_STATUS, printer) < 0) ||
		    (rcv_msg(R_INQUIRE_PRINTER_STATUS, &status, &prname, &form,
				&pwheel, &dis_reason, &rej_reason, &prstatus,
				&reqid, &dis_date, &rej_date) < 0))
			status = MUNKNOWN;
	} else if (isclass(printer)) {
		if ((snd_msg(S_INQUIRE_CLASS, printer) < 0) ||
		    (rcv_msg(R_INQUIRE_CLASS, &status, &prname,
				&prstatus, &rej_reason, &rej_date) < 0))
			status = MUNKNOWN;
	} else
		status = MUNKNOWN;

	if ((status == MOK) && ((prstatus & PS_REJECTED) != PS_REJECTED))
		return (0);
	else
		return (-1);
}


/*
 * lpsched_client_access() is intended to validate that the requesting host
 * has access to communicate with the scheduler.  In Solaris this currently
 * has no meaning.  The host is automatically allowed access.
 */
int
lpsched_client_access(const char *printer, const char *host)
{
	syslog(LOG_DEBUG, "lpsched_client_access(%s, %s)",
		(printer ? printer : "NULL"), (host ? host : "NULL"));

	if ((printer == NULL) || (host == NULL))
		return (-1);

	return (0);
}


/*
 * lpsched_restart_printer() is intended to restart processing of a queue.  In
 * the lpsched spooling paradigm, this does nothing since the restart is
 * automatically done at job submission.
 */
int
lpsched_restart_printer(const char *printer)
{
	syslog(LOG_DEBUG, "lpsched_restart_printer(%s)",
		(printer ? printer : "NULL"));

	if (printer == NULL)
		return (-1);

	return (0);
}


/*
 * lpsched_temp_dir() returns the location of the temporary disk space to
 * place transfered jobs.  An attempt is always made to make the requests and
 * tmp directory for the requesting host.  A NULL is returned upon failure to
 * locate a space.
 */
char *
lpsched_temp_dir(const char *printer, const char *host)
{
	char buf[BUFSIZ];
	mode_t  old_msk;
	struct passwd *p = NULL;

	syslog(LOG_DEBUG, "lpsched_temp_dir(%s, %s)",
		(printer ? printer : "NULL"), (host ? host : "NULL"));

	if ((printer == NULL) || (host == NULL))
		return (NULL);

	snprintf(buf, sizeof (buf), "%s/%s", Lp_Requests, host);
	old_msk = umask((mode_t)0);
	mkdir(buf, 0755);
	p = getpwnam("lp");
	if (p != NULL)
		chown(buf, p->pw_uid, p->pw_gid);
	snprintf(buf, sizeof (buf), "%s/%s", Lp_Tmp, host);
	mkdir(buf, 0775);
	if (p != NULL)
		chown(buf, p->pw_uid, p->pw_gid);
	(void) umask(old_msk);

	return (strdup(buf));
}
