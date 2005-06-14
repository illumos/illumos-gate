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
 * Copyright (c) 1995-1997,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <string.h>
#include <libintl.h>
#include <netdb.h>

#include <syslog.h>

/* lpsched include files */
#include "lp.h"
#include "msgs.h"
#include "printers.h"
#include "class.h"

#include "misc.h"

/* print NS include */
#include <print/ns.h>


static char *
cancel_requestor(const char *printer, const char *user, const char *host)
{
	static char buf[BUFSIZ];	/* This is larger than necessary */
	char *tmp, *s;
	ns_printer_t *pobj;

	if (((pobj = ns_printer_get_name(printer, NULL)) != NULL) &&
	    ((tmp = ns_get_value_string("user-equivalence", pobj)) != NULL) &&
	    (strcasecmp(tmp, "true") == 0) && ((strcmp(user, "root") != 0) ||
	    (strcmp(user, "lp") != 0)))
		host = "all";

	tmp = strdup(user);
	while ((s = strpbrk(tmp, "()")) != NULL)
		*s = '_';
	user = tmp;

	if ((strcmp(user, "root") == 0) || (strcmp(user, "lp") == 0)) {
		user = "all";		/* root/lp can cancel any request */
		if (strcmp(host, "all") != 0) {
			char thost[MAXHOSTNAMELEN];

			sysinfo(SI_HOSTNAME, thost, sizeof (thost));
			if (strcmp(host, thost) == 0)
				host = "all"; 	/* cancel from anywhere */
		}
	}

	snprintf(buf, sizeof (buf), "%s@%s", user, host);

	return (buf);
}


/*
 * lpsched_cancel_job() attempts to cancel an lpsched requests that match the
 * passed in criteria.  a message is written for each cancelation or
 * attempted cancelation
 */
int
lpsched_cancel_job(const char *printer, FILE *ofp, const char *requestor,
			const char *host, const char **list)
{
	short status;
	char **job_list = NULL;
	char *cancel_name;
	int first_job_only = 0;

	syslog(LOG_DEBUG, "cancel_job(%s, %d, %s, %s, 0x%x)",
		(printer ? printer : "NULL"), ofp, requestor, host, list);

	if ((printer == NULL) || (requestor == NULL) || (host == NULL) ||
	    (list == NULL))
		return (-1);

	/* if list is empty, then cancel only the first job */
	if ((*list == NULL) && (strcmp(requestor, "-all") != 0))
		first_job_only = 1;

	if (!isprinter((char *)printer) && !isclass((char *)printer)) {
		fprintf(ofp, gettext("unknown printer/class"));
		return (-1);
	}

	if (snd_msg(S_INQUIRE_REQUEST, "", printer, "", "", "") < 0) {
		fprintf(ofp, gettext("Failure to communicate with lpsched\n"));
		return (-1);
	}

	do {
		size_t	size;
		time_t	date;
		short	outcome;
		char *dest, *form, *pwheel, *file, *owner, *reqid;
		const char **list_ptr = list;
		char buf[BUFSIZ];

		if (rcv_msg(R_INQUIRE_REQUEST, &status, &reqid, &owner, &size,
				&date, &outcome, &dest, &form, &pwheel,
				&file) < 0) {
			fprintf(ofp,
			gettext("Failure to communicate with lpsched\n"));
			return (-1);
		}

		switch (status) {
		case MOK:
		case MOKMORE:

			/*
			 * if cancelling only the fist job, then add
			 * the first job to job_list and increment
			 * first_job_only so no more jobs get added
			 */
			if (first_job_only == 1) {
				snprintf(buf, sizeof (buf), "%s %s", owner,
				    reqid);
				appendlist(&job_list, buf);
				first_job_only++;
				break;
			} else if (first_job_only > 1)
				break;

			if (strcasecmp(requestor, "-all") == 0) {
				snprintf(buf, sizeof (buf), "%s %s", owner,
				    reqid);
				appendlist(&job_list, buf);
				break;
			}

			while ((list_ptr != NULL) && (*list_ptr != NULL)) {
				char *user = (char *)user_name(owner);
				int rid = id_no(reqid);
				int id = atoi(*list_ptr++);

				if ((rid == id) ||
				    (strcmp(user, list_ptr[-1]) == 0)) {
					snprintf(buf, sizeof (buf), "%s %s",
					    owner, reqid);
					appendlist(&job_list, buf);
				}
			}
			break;
		default:
			break;
		}
	} while (status == MOKMORE);

	if (strcasecmp(requestor, "-all") == 0)
		requestor = "root";

	cancel_name = cancel_requestor(printer, requestor, host);

	while ((job_list != NULL) && (*job_list != NULL)) {
		char *user = strtok(*job_list, " ");
		char *reqid = strtok(NULL, " ");

		syslog(LOG_DEBUG,
			"cancel %s, owned by %s, on %s, requested by %s\n",
			reqid, user, printer, cancel_name);

		if (snd_msg(S_CANCEL, printer, cancel_name, reqid) < 0) {
			fprintf(ofp,
			gettext("Failure to communicate with lpsched\n"));
			return (-1);
		}

		do {
			int status2;
			char *job_name = "unknown";

			if (rcv_msg(R_CANCEL, &status, &status2,
					&job_name) < 0) {
			fprintf(ofp,
			gettext("Failure to communicate with lpsched\n"));
				return (-1);
			}

			switch (status2) {
			case MOK:
			case MOKMORE:
				fprintf(ofp, gettext("%s: cancelled\n"),
					job_name);
				break;
			case MUNKNOWN:
			case MNOPERM:
				fprintf(ofp, gettext("%s: permission denied\n"),
					reqid);
				break;
				break;
			case M2LATE:
				fprintf(ofp, gettext("cannot dequeue %s\n"),
					job_name);
				break;
			default:
				fprintf(ofp,
					gettext("%s: cancel failed (%d)\n"),
					reqid, status2);
				break;
			}
		} while (status == MOKMORE);
		job_list++;
	}

	return (0);
}
