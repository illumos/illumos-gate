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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include "stdio.h"
#include "pwd.h"
#include "sys/types.h"

#include "lp.h"
#include "strings.h"
#include "msgs.h"
#include "requests.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"


/*
 * do_request()
 */

void
do_request(char **list)
{
	while (*list) {
		if (STREQU(NAME_ALL, *list)) {
			if (remote_cmd || verbosity & V_RANK) {
				send_message(S_INQUIRE_REQUEST_RANK,
					(remote_cmd ? 2 : 1),
					"", "", "", "", "");
				(void) output (R_INQUIRE_REQUEST_RANK);
			} else {
				send_message (S_INQUIRE_REQUEST,
				    "", "", "", "", "");
				(void) output (R_INQUIRE_REQUEST);
			}

		} else if (isrequest(*list)) {
			if (remote_cmd || verbosity & V_RANK) {
				send_message (S_INQUIRE_REQUEST_RANK,
					(remote_cmd ? 2 : 1),
					"", "", *list, "", "");
				switch (output(R_INQUIRE_REQUEST_RANK)) {
				case MNOINFO:
					LP_ERRMSG1 (ERROR,
					E_STAT_DONE, *list);
					exit_rc = 1;
					break;
				}
			} else {
				send_message (S_INQUIRE_REQUEST,
				    "", "", *list, "", "");
				switch (output(R_INQUIRE_REQUEST)) {
				case MNOINFO:
					LP_ERRMSG1 (ERROR,
					E_STAT_DONE, *list);
					exit_rc = 1;
					break;
				}
			}

		} else {
			if (remote_cmd || verbosity & V_RANK) {
				send_message(S_INQUIRE_REQUEST_RANK,
					(remote_cmd ? 2 : 1),
					"", *list, "", "", "");
				switch (output(R_INQUIRE_REQUEST_RANK)) {
				case MNOINFO:
					if (!isprinter(*list) &&
					    !isclass(*list)) {
						LP_ERRMSG1 (ERROR,
						E_STAT_BADSTAT, *list);
						exit_rc = 1;
					}
					break;
				}
			} else {
				send_message (S_INQUIRE_REQUEST,
				    "", *list, "", "", "");
				switch (output(R_INQUIRE_REQUEST)) {
				case MNOINFO:
					if (!isprinter(*list) &&
					    !isclass(*list)) {
						LP_ERRMSG1 (ERROR,
						E_STAT_BADSTAT, *list);
						exit_rc = 1;
					}
					break;
				}
			}

		}
		list++;
	}
	return;
}

/*
 * do_user()
 */

static char *user_name = NULL;

void
do_user(char **list)
{
	user_name = NULL;

	while (*list) {
		if (STREQU(NAME_ALL, *list)) {
			if (remote_cmd || verbosity & V_RANK) {
				send_message (S_INQUIRE_REQUEST_RANK,
					(remote_cmd ? 2 : 1),
					"", "", "", "", "");
				(void) output (R_INQUIRE_REQUEST_RANK);
			} else {
				send_message (S_INQUIRE_REQUEST,
				    "", "", "", "", "");
				(void) output (R_INQUIRE_REQUEST);
			}
		} else {
			user_name = *list;
			if (remote_cmd || verbosity & V_RANK) {
				send_message (S_INQUIRE_REQUEST_RANK,
					(remote_cmd ? 2 : 1),
					"", "", "", *list, "");
				switch (output(R_INQUIRE_REQUEST_RANK)) {
				case MNOINFO:
					if (!getpwnam(*list))
						LP_ERRMSG1 (WARNING,
						E_STAT_USER, *list);
					break;
				}
			} else {
				send_message (S_INQUIRE_REQUEST,
				    "", "", "", *list, "");
				switch (output(R_INQUIRE_REQUEST)) {
				case MNOINFO:
					if (!getpwnam(*list))
						LP_ERRMSG1 (WARNING,
						E_STAT_USER, *list);
					break;
				}
			}
		}
		list++;
	}
	user_name = NULL;
}


/*
 * putoline()
 */

void
putoline(char *request_id, char *user, char *slabel, long size, time_t clock,
	int state, char *printer, char *form, char *character_set, int rank)
{
	int showRank;
	char user_buf[LOGMAX];
	char date[SZ_DATE_BUFF];

	if ((slabel != NULL) && (slabel[0] != '\0'))
		snprintf(user_buf, sizeof (user_buf), "%s:%s", user, slabel);
	else
		snprintf(user_buf, sizeof (user_buf), "%s", user);

	/*
	 * This is the basic time format used in the output. It represents
	 * all times of the form "Dec 11 11:04" seen in the output.
	 */
	(void) strftime(date, sizeof (date), "%b %d %R", localtime(&clock));
	if (user_name)
		if (!strchr(user_name, '!')) {
			char buf[512];

			snprintf(buf, sizeof (buf), "all!%s", user_name);
			if (!bangequ(buf, user))
				return;
		}
		else if (!bangequ(user_name, user))
				return;


	showRank = (verbosity & V_RANK);
	if (showRank)
		(void) printf("%3d ", rank);

	(void) printf(
		"%-*s %-*s %*ld %s%s",
		((showRank) ? IDSIZE - 2 : IDSIZE),
		request_id,
		LOGMAX-1,
		user_buf,
		OSIZE,
		size,
		((showRank) ? "" : "  "),
		date);

	if (!(verbosity & (V_LONG|V_BITS))) {

		/*
		 * Unless the -l option is given, we show the CURRENT
		 * status. Check the status bits in reverse order of
		 * chronology, i.e. go with the bit that would have been
		 * set last. Old bits don't get cleared by the Spooler.
		 * We only have space for 21 characters!
		 */

		if (state & RS_NOTIFYING)
			(void) printf(gettext(" notifying user"));

		else if (state & RS_CANCELLED)
			(void) printf(gettext(" canceled"));

		else if (state & RS_PRINTED)
			(void) printf(gettext(" finished printing"));

		else if (state & RS_PRINTING)
			(void) printf(gettext(" on %s"), printer);

		else if (state & RS_ADMINHELD)
			(void) printf(gettext(" held by admin"));

		else if (state & RS_HELD)
			(void) printf(gettext(" being held"));

		else if (state & RS_FILTERED)
			(void) printf(gettext(" filtered"));

		else if (state & RS_FILTERING)
			(void) printf(gettext(" being filtered"));

		else if (state & RS_CHANGING)
			(void) printf(gettext(" held for change"));

	} else if (verbosity & V_BITS) {
		register char		*sep	= "\n	";

			BITPRINT (state, RS_HELD);
			BITPRINT (state, RS_FILTERING);
			BITPRINT (state, RS_FILTERED);
			BITPRINT (state, RS_PRINTING);
			BITPRINT (state, RS_PRINTED);
			BITPRINT (state, RS_CHANGING);
			BITPRINT (state, RS_CANCELLED);
			BITPRINT (state, RS_IMMEDIATE);
			BITPRINT (state, RS_FAILED);
			BITPRINT (state, RS_SENDING);
			BITPRINT (state, RS_NOTIFY);
			BITPRINT (state, RS_NOTIFYING);
			BITPRINT (state, RS_SENT);
			BITPRINT (state, RS_ADMINHELD);
			BITPRINT (state, RS_REFILTER);
			BITPRINT (state, RS_STOPPED);

	} else if (verbosity & V_LONG) {
		/*
		 * Here we show all the interesting states the job
		 * has gone through. Left to right they are in
		 * chronological order.
		 */

		if (state & RS_PRINTING) {
			(void) printf(gettext("\n\ton %s"), printer);
		} else if (state & RS_CANCELLED) {
			(void) printf(gettext("\n\tcanceled"));
		} else if (state & RS_FAILED) {
			(void) printf(gettext("\n\tfailed"));
		} else if (state & RS_PRINTED) {
			(void) printf(gettext("\n\tfinished on %s"), printer);
		/*
		 * WATCH IT! We make the request ID unusable after
		 * the next line.
		 */
		} else if (!STREQU(strtok(request_id, "-"), printer)) {
			(void) printf(gettext("\n\tassigned %s"), printer);
		} else {
			if (state & RS_SENT)
				(void)printf (
					gettext("\n\tqueued remotely for %s"),
					printer);
			else
				(void)printf (gettext("\n\tqueued for %s"),
					printer);
		}

		if (!(state & RS_DONE)) {
			if (form && *form) {
				(void) printf(gettext(", form %s"), form);
			}
			if (character_set && *character_set) {
				(void) printf(gettext(", charset %s"),
					character_set);
			}
		}

		if (state & RS_NOTIFYING) {
			(void) printf(gettext(", notifying user"));
		} else if (state & RS_CHANGING) {
			(void) printf(gettext(", held for change"));
		} else if (state & RS_ADMINHELD) {
			(void) printf(gettext(", held by admin"));
		} else if (state & RS_HELD) {
			(void) printf(gettext(", being held"));
		}

		if (state & RS_FILTERED) {
			(void) printf(gettext(", filtered"));
		} else if (state & RS_FILTERING) {
			(void) printf(gettext(", being filtered"));
		}
	}
	(void) printf("\n");
	return;
}
