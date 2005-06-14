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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SA_TIME_H
#define	_SA_TIME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Exported interfaces for standalone's subset of libc's <time.h>.
 * All standalone code *must* use this header rather than libc's.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct	tm {
	int	tm_sec;		/* seconds after the minute */
	int	tm_min;		/* minutes after the hour */
	int	tm_hour;	/* hour since midnight */
	int	tm_mday;	/* day of the month */
	int	tm_mon;		/* months since January */
	int	tm_year;	/* years since 1900 */
	int	tm_wday;	/* days since Sunday */
	int	tm_yday;	/* Days since January 1 */
	int	tm_isdst;	/* flag for alternate daylight savings time */
};

extern time_t time(time_t *);
extern char *ctime(const time_t *t);
extern struct tm *gmtime(const time_t *);
extern struct tm *localtime(const time_t *);

/*
 * The following silly #defines are actually ripped off from <tzfile.h>.
 * Since <tzfile.h> is not a documented header, it seemed better to just
 * inline them here rather than having a full-blown <tzfile.h> of our own.
 */
#define	EPOCH_YEAR		1970
#define	EPOCH_WDAY		4
#define	SECS_PER_MIN		60
#define	DAYS_PER_WEEK		7
#define	DAYS_PER_NYEAR		365
#define	DAYS_PER_LYEAR		366
#define	MONS_PER_YEAR		12
#define	SECS_PER_HOUR		(SECS_PER_MIN * 60)
#define	SECS_PER_DAY		(SECS_PER_HOUR * 24)
#define	TM_YEAR_BASE		1900

#define	isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

#ifdef __cplusplus
}
#endif

#endif /* _SA_TIME_H */
