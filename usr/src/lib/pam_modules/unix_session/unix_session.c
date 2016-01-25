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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <lastlog.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <signal.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <crypt.h>
#include <assert.h>
#include <nss_dbdefs.h>

#define	LASTLOG		"/var/adm/lastlog"

/*
 * pam_sm_close_session	- Terminate a PAM authenticated session
 */
/*ARGSUSED*/
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	int	i;
	int	debug = 0;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "nowarn") != 0)
			syslog(LOG_ERR, "illegal option %s", argv[i]);
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "pam_unix_session: inside pam_sm_close_session()");

	return (PAM_SUCCESS);
}

/*ARGSUSED*/
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	int	error;
	char    *ttyn, *rhost, *user;
	int	fdl;
	struct lastlog  newll;
	struct passwd pwd;
	char    buffer[NSS_BUFLEN_PASSWD];
	int	i;
	int	debug = 0;
	offset_t	offset;
	time_t  cur_time;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "nowarn") == 0)
			flags = flags | PAM_SILENT;
		else
			syslog(LOG_ERR, "illegal option %s", argv[i]);
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "pam_unix_session: inside pam_sm_open_session()");

	if ((error = pam_get_item(pamh, PAM_TTY, (void **)&ttyn))
	    != PAM_SUCCESS ||
	    (error = pam_get_item(pamh, PAM_USER, (void **)&user))
	    != PAM_SUCCESS ||
	    (error = pam_get_item(pamh, PAM_RHOST, (void **)&rhost))
	    != PAM_SUCCESS) {
		return (error);
	}

	if (user == NULL || *user == '\0')
		return (PAM_USER_UNKNOWN);

	/* report error if ttyn not set */
	if (ttyn == NULL)
		return (PAM_SESSION_ERR);

	if (getpwnam_r(user, &pwd, buffer, sizeof (buffer)) == NULL) {
		return (PAM_USER_UNKNOWN);
	}

	if ((fdl = open(LASTLOG, O_RDWR|O_CREAT|O_DSYNC, 0444)) >= 0) {
		/*
		 * The value of lastlog is read by the UNIX
		 * account management module
		 */
		offset = (offset_t)pwd.pw_uid *
		    (offset_t)sizeof (struct lastlog);

		if (llseek(fdl, offset, SEEK_SET) != offset) {
			syslog(LOG_ERR,
			    "pam_unix_session: Can't update lastlog: uid %d "
			    "too large", pwd.pw_uid);
			(void) close(fdl);
			return (PAM_SUCCESS);
		}
		/*
		 * use time32_t in case of _LP64
		 * since it's written in lastlog.h
		 */
		(void) time(&cur_time);

		bzero((char *)&newll, sizeof (struct lastlog));
#ifdef _LP64
		newll.ll_time = (time32_t)cur_time;
#else
		newll.ll_time = cur_time;
#endif
		if ((strncmp(ttyn, "/dev/", 5) == 0)) {
			(void) strlcpy(newll.ll_line,
			    (ttyn + sizeof ("/dev/")-1),
			    sizeof (newll.ll_line));
		} else {
			(void) strlcpy(newll.ll_line, ttyn,
			    sizeof (newll.ll_line));
		}
		if (rhost != NULL) {
			(void) strlcpy(newll.ll_host, rhost,
			    sizeof (newll.ll_host));
		}
		if (debug) {
			char	buf[26];

			(void) ctime_r((const time_t *)&cur_time, buf,
			    sizeof (buf));
			buf[24] = '\000';
			syslog(LOG_DEBUG, "pam_unix_session: "
			    "user = %s, time = %s, tty = %s, host = %s.",
			    user, buf, newll.ll_line, newll.ll_host);
		}
		if (write(fdl, (char *)&newll, sizeof (newll))
		    != sizeof (newll))
			syslog(LOG_ERR, "pam_unix_session: Can't write "
			    "lastlog: uid %d: %m", pwd.pw_uid);
		if (close(fdl) != 0)
			syslog(LOG_ERR, "pam_unix_session: Can't close "
			    "lastlog: uid %d: %m", pwd.pw_uid);
	}
	return (PAM_SUCCESS);
}
