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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <values.h>
#include <locale.h>
#include <sys/stat.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/nsctl/nsctl.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#define	MAX_SESSION_LOG    (10 * 1024 * 1024)	/* allowable log file size */

static char	sessionlog[]	 =  "/var/adm/ds.log";
static char	sessionlog_bak[] =  "/var/adm/ds.log.bak";

static char *spcstime();

void
spcs_log(const char *product, spcs_s_info_t *status, const char *format, ...)
{
	struct  stat st;
	FILE   *fp = NULL;
	struct flock lk;
	va_list	ap;

	bzero(&lk, sizeof (lk));

	/*
	 * check the file size, if > than MAX_SESSION_LOG bytes make a .bak
	 * and truncate
	 */
	if (stat(sessionlog, &st) == 0) {
		if (st.st_size > MAX_SESSION_LOG) {
			rename(sessionlog, sessionlog_bak);
		}
	}

	va_start(ap, format);
	if ((fp = fopen(sessionlog, "a")) == (FILE *)NULL)
		goto fail;
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = (off_t)0;
	lk.l_len = (off_t)0;

	if (fcntl(fileno(fp), F_SETLKW, &lk) < 0)
		goto fail;


	fprintf(fp, "%s %s: ", spcstime(), product);
	(void) vfprintf(fp, format, ap);
	fputs("\n", fp);
	if (status)
		spcs_s_report(*status, fp);

	fflush(fp);

	lk.l_type = F_UNLCK;

	(void) fcntl(fileno(fp), F_SETLKW, &lk);

fail:
	if (fp)
		fclose(fp);
	va_end(ap);
}

/*
 * spcstime():  gets current time
 */
static char *
spcstime()
{
	static char timeptr[20];
	time_t tnow;

	tnow = time((time_t *)0);
	cftime(timeptr, "%b %d %T", &tnow);
	return (timeptr);
}
