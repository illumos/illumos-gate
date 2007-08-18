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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"

static char ERRNO_FMT[] = ": %s";

static char *pname = NULL;
static rcm_level_t message_priority = RCM_WARN;
static rcm_dst_t message_dst = RCD_STD;

static void dmesg(int level, char *msg);

/*PRINTFLIKE2*/
void
dprintfe(int level, char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vdprintfe(level, format, alist);
	va_end(alist);
}

/*PRINTFLIKE2*/
void
vdprintfe(int level, const char *format, va_list alist)
{
	char buf[LINELEN];
	char *c;
	int err = errno;

	*buf = 0;

	if ((strlen(buf) + 1) < LINELEN)
		(void) vsnprintf(buf + strlen(buf), LINELEN - 1 - strlen(buf),
		    format, alist);
	if ((c = strchr(buf, '\n')) == NULL) {
		if ((strlen(buf) + 1) < LINELEN)
			(void) snprintf(buf + strlen(buf), LINELEN - 1 -
			    strlen(buf), gettext(ERRNO_FMT), strerror(err));
	} else
		*c = 0;

	dmesg(level, buf);
}

#ifdef DEBUG_MSG
/*PRINTFLIKE1*/
void
debug(char *format, ...)
{
	va_list alist;

	if (get_message_priority() < RCM_DEBUG)
		return;

	va_start(alist, format);
	vdprintfe(RCM_DEBUG, format, alist);
	va_end(alist);
}

/*PRINTFLIKE1*/
void
debug_high(char *format, ...)
{
	va_list alist;

	if (get_message_priority() < RCM_DEBUG_HIGH)
		return;

	va_start(alist, format);
	vdprintfe(RCM_DEBUG_HIGH, format, alist);
	va_end(alist);
}
#endif /* DEBUG_MSG */

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	va_list alist;

	if (get_message_priority() < RCM_WARN)
		return;

	va_start(alist, format);
	vdprintfe(RCM_WARN, format, alist);
	va_end(alist);
}

/*PRINTFLIKE1*/
void
die(char *format, ...)
{
	va_list alist;

	if (get_message_priority() < RCM_ERR)
		return;

	va_start(alist, format);
	vdprintfe(RCM_ERR, format, alist);
	va_end(alist);

	exit(E_ERROR);
}

/*PRINTFLIKE1*/
void
info(char *format, ...)
{
	va_list alist;

	if (get_message_priority() < RCM_INFO)
		return;

	va_start(alist, format);
	vdprintfe(RCM_INFO, format, alist);
	va_end(alist);
}

char *
setprogname(char *arg0)
{
	char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;
	pname = p;
	return (pname);
}

/*
 * Output a message to the controlling tty or log, depending on which is
 * configured.  The message should contain no newlines.
 */
static void
dmesg(int level, char *msg)
{
	if (message_priority >= level) {
		FILE *fp;
		int syslog_severity = -1;

		switch (message_dst) {
		case RCD_STD:
			fp = level >= RCM_DEBUG ? stderr : stdout;

			if (pname != NULL) {
				(void) fputs(pname, fp);
				(void) fputs(": ", fp);
			}
			(void) fputs(msg, fp);
			(void) fputc('\n', fp);
			(void) fflush(fp);
			break;
		case RCD_SYSLOG:
			switch (level) {
			case RCM_ERR:
				syslog_severity = LOG_ERR;
				break;
			case RCM_WARN:
				syslog_severity = LOG_WARNING;
				break;
			case RCM_INFO:
				syslog_severity = LOG_INFO;
				break;
			case RCM_DEBUG:
				syslog_severity = LOG_DEBUG;
				break;
			}
			if (syslog_severity >= 0)
				(void) syslog(syslog_severity, "%s", msg);
			break;
		}
	}
}

rcm_level_t
get_message_priority(void)
{
	return (message_priority);
}

rcm_level_t
set_message_priority(rcm_level_t new_priority)
{
	rcm_level_t old_priority = message_priority;

	message_priority = new_priority;
	return (old_priority);
}

rcm_dst_t
set_message_destination(rcm_dst_t new_dst)
{
	rcm_dst_t old_dst = message_dst;

	if ((message_dst = new_dst) == RCD_SYSLOG)
		openlog(pname, LOG_ODELAY | LOG_PID, LOG_DAEMON);

	return (old_dst);
}

void
hrt2ts(hrtime_t hrt, timestruc_t *tsp)
{
	tsp->tv_sec = hrt / NANOSEC;
	tsp->tv_nsec = hrt % NANOSEC;
}

int
xatoi(char *p)
{
	int i;
	char *q;

	errno = 0;
	i = (int)strtol(p, &q, 10);
	if (errno != 0 || q == p || i < 0 || *q != '\0') {
		warn(gettext("illegal argument -- %s\n"), p);
		return (-1);
	} else {
		return (i);
	}
}

/*
 * get_running_zones() calls zone_list(2) to find out how many zones are
 * running.  It then calls zone_list(2) again to fetch the list of running
 * zones (stored in *zents).
 */
int
get_running_zones(uint_t *nzents, zone_entry_t **zents)
{
	zoneid_t *zids;
	uint_t nzents_saved;
	int i;
	zone_entry_t *zentp;
	zone_state_t zstate;

	*zents = NULL;
	if (zone_list(NULL, nzents) != 0) {
		warn(gettext("could not get zoneid list\n"));
		return (E_ERROR);
	}

again:
	if (*nzents == 0)
		return (E_SUCCESS);

	if ((zids = (zoneid_t *)calloc(*nzents, sizeof (zoneid_t))) == NULL) {
		warn(gettext("out of memory: zones will not be capped\n"));
		return (E_ERROR);
	}

	nzents_saved = *nzents;

	if (zone_list(zids, nzents) != 0) {
		warn(gettext("could not get zone list\n"));
		free(zids);
		return (E_ERROR);
	}
	if (*nzents != nzents_saved) {
		/* list changed, try again */
		free(zids);
		goto again;
	}

	*zents = calloc(*nzents, sizeof (zone_entry_t));
	if (*zents == NULL) {
		warn(gettext("out of memory: zones will not be capped\n"));
		free(zids);
		return (E_ERROR);
	}

	zentp = *zents;
	for (i = 0; i < *nzents; i++) {
		char name[ZONENAME_MAX];

		if (getzonenamebyid(zids[i], name, sizeof (name)) < 0) {
			warn(gettext("could not get name for "
			    "zoneid %d\n"), zids[i]);
			continue;
		}

		(void) strlcpy(zentp->zname, name, sizeof (zentp->zname));
		zentp->zid = zids[i];
		if (zone_get_state(name, &zstate) != Z_OK ||
		    zstate != ZONE_STATE_RUNNING)
			continue;


		zentp++;
	}
	*nzents = zentp - *zents;

	free(zids);
	return (E_SUCCESS);
}
