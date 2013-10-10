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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Chad Mynhier
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <zone.h>

#include <libintl.h>
#include <limits.h>
#include <wchar.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <errno.h>
#include <ctype.h>
#include <poll.h>
#include <project.h>

#include "prfile.h"
#include "prstat.h"
#include "prutil.h"

static char PRG_FMT[] = "%s: ";
static char ERR_FMT[] = ": %s\n";
static char *progname;
static char projbuf[PROJECT_BUFSZ];

#define	RLIMIT_NOFILE_MAX	32767

/*PRINTFLIKE1*/
void
Warn(char *format, ...)
{
	int err = errno;
	va_list alist;

	if (progname != NULL)
		(void) fprintf(stderr, PRG_FMT, progname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERR_FMT), strerror(err));
}

/*PRINTFLIKE1*/
void
Die(char *format, ...)
{
	int err = errno;
	va_list alist;

	if (progname != NULL)
		(void) fprintf(stderr, PRG_FMT, progname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERR_FMT), strerror(err));
	exit(1);
}

void
Progname(char *arg0)
{
	char *p = strrchr(arg0, '/');
	if (p == NULL)
		p = arg0;
	else
		p++;
	progname = p;
}

void
Usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage:\tprstat [-acHJLmrRtTvWZ] [-u euidlist] [-U uidlist]\n"
	    "\t[-p pidlist] [-P cpulist] [-C psrsetlist] [-h lgrouplist]\n"
	    "\t[-j projidlist] [-k taskidlist] [-z zoneidlist]\n"
	    "\t[-s key | -S key] [-n nprocs[,nusers]] [-d d|u]\n"
	    "\t[interval [counter]]\n"));
	exit(1);
}

int
Atoi(char *p)
{
	int i;
	char *q;
	errno = 0;
	i = (int)strtol(p, &q, 10);
	if (errno != 0 || q == p || i < 0 || *q != '\0')
		Die(gettext("illegal argument -- %s\n"), p);
		/*NOTREACHED*/
	else
		return (i);
	return (0);	/* keep gcc happy */
}

void
Format_size(char *str, size_t size, int length)
{
	char tag = 'K';
	if (size >= 10000) {
		size = (size + 512) / 1024;
		tag = 'M';
		if (size >= 10000) {
			size = (size + 512) / 1024;
			tag = 'G';
		}
	}
	(void) snprintf(str, length, "%4d%c", (int)size, tag);
}

void
Format_time(char *str, ulong_t time, int length)
{
	(void) snprintf(str, length, gettext("%3d:%2.2d:%2.2d"), /* hr:mm:ss */
	    (int)time/3600, (int)(time % 3600)/60, (int)time % 60);
}

void
Format_pct(char *str, float val, int length)
{
	if (val > (float)100)
		val = 100;
	if (val < 0)
		val = 0;

	if (val < (float)9.95)
		(void) snprintf(str, length, "%1.1f", val);
	else
		(void) snprintf(str, length, "%.0f", val);
}

void
Format_num(char *str, int num, int length)
{
	if (num >= 100000) {
		(void) snprintf(str, length, ".%1dM", num/100000);
	} else {
		if (num >= 1000)
			(void) snprintf(str, length, "%2dK", num/1000);
		else
			(void) snprintf(str, length, "%3d", num);
	}
}

void
Format_state(char *str, char state, processorid_t pr_id, int length)
{
	switch (state) {
	case 'S':
		(void) strncpy(str, "sleep", length);
		break;
	case 'R':
		(void) strncpy(str, "run", length);
		break;
	case 'Z':
		(void) strncpy(str, "zombie", length);
		break;
	case 'T':
		(void) strncpy(str, "stop", length);
		break;
	case 'I':
		(void) strncpy(str, "idle", length);
		break;
	case 'W':
		(void) strncpy(str, "wait", length);
		break;
	case 'O':
		(void) snprintf(str, length, "cpu%-3d", (int)pr_id);
		break;
	default:
		(void) strncpy(str, "?", length);
		break;
	}
}

void *
Realloc(void *ptr, size_t size)
{
	int	cnt = 0;
	void	*sav = ptr;

eagain:	if ((ptr = realloc(ptr, size)))
		return (ptr);

	if ((++cnt <= 3) && (errno == EAGAIN)) {
		Warn(gettext("realloc() failed, attempt %d"), cnt);
		(void) poll(NULL, 0, 5000); /* wait for 5 seconds */
		ptr = sav;
		goto eagain;
	}
	ptr = sav;
	Die(gettext("not enough memory"));
	/*NOTREACHED*/
	return (NULL);	/* keep gcc happy */
}

void *
Malloc(size_t size)
{
	return (Realloc(NULL, size));
}

void *
Zalloc(size_t size)
{
	return (memset(Realloc(NULL, size), 0, size));
}

int
Setrlimit()
{
	struct rlimit rlim;
	int fd_limit;
	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		Die(gettext("getrlimit failed"));
	fd_limit = rlim.rlim_cur;
	rlim.rlim_max = MIN(rlim.rlim_max, RLIMIT_NOFILE_MAX);
	rlim.rlim_cur = rlim.rlim_max;
	(void) enable_extended_FILE_stdio(-1, -1);
	if (setrlimit(RLIMIT_NOFILE, &rlim) == -1)
		return (fd_limit);
	else
		return (rlim.rlim_cur);
}

void
Priocntl(char *class)
{
	pcinfo_t pcinfo;
	pcparms_t pcparms;
	(void) strcpy(pcinfo.pc_clname, class);
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1) {
		Warn(gettext("cannot get real time class parameters"));
		return;
	}
	pcparms.pc_cid = pcinfo.pc_cid;
	((rtparms_t *)pcparms.pc_clparms)->rt_pri = 0;
	((rtparms_t *)pcparms.pc_clparms)->rt_tqsecs = 0;
	((rtparms_t *)pcparms.pc_clparms)->rt_tqnsecs = RT_NOCHANGE;
	if (priocntl(P_PID, getpid(), PC_SETPARMS, (caddr_t)&pcparms) == -1)
		Warn(gettext("cannot enter the real time class"));
}

void
getprojname(projid_t projid, char *str, size_t len, int noresolve,
    int trunc, size_t width)
{
	struct project proj;
	size_t n;

	if (noresolve || getprojbyid(projid, &proj, projbuf, PROJECT_BUFSZ) ==
	    NULL) {
		(void) snprintf(str, len, "%-6d", (int)projid);
	} else {
		n = mbstowcs(NULL, proj.pj_name, 0);
		if (n == (size_t)-1)
			(void) snprintf(str, len, "%-28s", "ERROR");
		else if (trunc && n > width)
			(void) snprintf(str, len, "%.*s%c", width - 1,
			    proj.pj_name, '*');
		else
			(void) snprintf(str, len, "%-28s", proj.pj_name);
	}
}

void
getzonename(zoneid_t zoneid, char *str, size_t len, int trunc, size_t width)
{
	char zone_name[ZONENAME_MAX];
	size_t n;

	if (getzonenamebyid(zoneid, zone_name, sizeof (zone_name)) < 0) {
		(void) snprintf(str, len, "%-6d", (int)zoneid);
	} else {
		n = mbstowcs(NULL, zone_name, 0);
		if (n == (size_t)-1)
			(void) snprintf(str, len, "%-28s", "ERROR");
		else if (trunc && n > width)
			(void) snprintf(str, len, "%.*s%c", width - 1,
			    zone_name, '*');
		else
			(void) snprintf(str, len, "%-28s", zone_name);
	}
}

/*
 * Remove all unprintable characters from process name
 */
void
stripfname(char *buf)
{
	int bytesleft = PRFNSZ;
	wchar_t wchar;
	int length;
	char *cp;

	buf[bytesleft - 1] = '\0';

	for (cp = buf; *cp != '\0'; cp += length) {
		length = mbtowc(&wchar, cp, MB_LEN_MAX);
		if (length <= 0) {
			*cp = '\0';
			break;
		}
		if (!iswprint(wchar)) {
			if (bytesleft <= length) {
				*cp = '\0';
				break;
			}
			(void) memmove(cp, cp + length, bytesleft - length);
			length = 0;
		}
		bytesleft -= length;
	}
}
