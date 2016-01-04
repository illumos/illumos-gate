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
 * Copyright 2015 Lauri Tirkkonen.
 */

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

#define	LASTLOG_LEGACY		"/var/adm/lastlog"
struct lastlog_legacy {
#ifdef _LP64
	time32_t ll_time;
#else
	time_t	ll_time;
#endif
	char	ll_line[8];
	char	ll_host[16];
};

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
		else
			syslog(LOG_ERR, "illegal option %s", argv[i]);
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "pam_unix_session: inside pam_sm_close_session()");

	return (PAM_SUCCESS);
}

static int
lastlog_seek(int fdl, uid_t uid, boolean_t legacy)
{
	offset_t	offset;

	offset = uid;
	if (legacy)
		offset *= sizeof (struct lastlog_legacy);
	else
		offset *= sizeof (struct lastlog);

	if (llseek(fdl, offset, SEEK_SET) != offset) {
		syslog(LOG_ERR, "pam_unix_session: %slastlog seek failed for "
		    "uid %d: %m", (legacy ? "legacy " : ""), uid);
		return (-1);
	}
	return (0);
}

static int
lastlog_read(int fdl, uid_t uid, struct lastlog *out, boolean_t legacy)
{
	ssize_t			nread = 0;
	ssize_t			llsize;
	struct lastlog		ll;
	struct lastlog_legacy	ll_legacy;
	void			*llp;

	if (legacy) {
		llp = &ll_legacy;
		llsize = sizeof (ll_legacy);
	} else {
		llp = &ll;
		llsize = sizeof (ll);
	}

	if (lastlog_seek(fdl, uid, legacy) == -1)
		return (-1);

	while (nread < llsize) {
		ssize_t ret;
reread:
		ret = read(fdl, ((char *)llp) + nread, llsize - nread);
		if (ret < 0) {
			if (errno == EINTR)
				goto reread;
			syslog(LOG_ERR, "pam_unix_session: read %slastlog "
			    "failed for uid %d: %m", (legacy ? "legacy " : ""),
			    uid);
			return (-1);
		} else if (ret == 0) {
			if (nread == 0) {
				out->ll_time = 0;
				return (-1);
			}
			syslog(LOG_ERR, "pam_unix_session: %slastlog short "
			    "read for uid %d", (legacy ? "legacy " : ""), uid);
			return (-1);
		}
		nread += ret;
	}
	if (legacy) {
		out->ll_time = ll_legacy.ll_time;
		ll_legacy.ll_line[sizeof (ll_legacy.ll_line) - 1] = '\0';
		ll_legacy.ll_host[sizeof (ll_legacy.ll_host) - 1] = '\0';
		(void) strlcpy(out->ll_line, ll_legacy.ll_line,
		    sizeof (out->ll_line));
		(void) strlcpy(out->ll_host, ll_legacy.ll_host,
		    sizeof (out->ll_line));
	} else {
		out->ll_time = ll.ll_time;
		ll.ll_line[sizeof (ll.ll_line) - 1] = '\0';
		ll.ll_host[sizeof (ll.ll_host) - 1] = '\0';
		(void) strlcpy(out->ll_line, ll.ll_line,
		    sizeof (out->ll_line));
		(void) strlcpy(out->ll_host, ll.ll_host,
		    sizeof (out->ll_host));
	}
	return (0);
}

static int
lastlog_write(int fdl, uid_t uid, const struct lastlog *ll)
{
	ssize_t		nwritten = 0;
	if (lastlog_seek(fdl, uid, B_FALSE))
		return (-1);

	while (nwritten < sizeof (*ll)) {
		ssize_t ret;
rewrite:
		ret = write(fdl, ((char *)ll) + nwritten,
		    sizeof (*ll) - nwritten);
		if (ret < 0) {
			if (errno == EINTR)
				goto rewrite;
			syslog(LOG_ERR, "pam_unix_session: write lastlog "
			    "failed for uid %d: %m", uid);
			return (-1);
		} else if (ret == 0) {
			syslog(LOG_ERR, "pam_unix_session: lastlog short "
			    "write for uid %d", uid);
			return (-1);
		}
		nwritten += ret;
	}
	return (0);
}

/*ARGSUSED*/
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
	const char **argv)
{
	int	error;
	char    *ttyn, *rhost, *user;
	int	fdl;
	struct lastlog	newll = { 0 };
	struct lastlog	legacyll;
	struct lastlog	ll;
	struct lastlog	*llp = NULL;
	struct passwd pwd;
	char    buffer[NSS_BUFLEN_PASSWD];
	int	i;
	int	debug = 0;
	time_t	cur_time;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
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

	ll.ll_time = 0;
reopenll_ro:
	fdl = open(_PATH_LASTLOG, O_RDONLY);
	if (fdl < 0) {
		if (errno == EINTR)
			goto reopenll_ro;
		if (errno != ENOENT)
			syslog(LOG_ERR, "pam_unix_session: unable to open "
			    "lastlog for uid %d: %m", pwd.pw_uid);
	} else {
		if (lastlog_read(fdl, pwd.pw_uid, &ll, B_FALSE) == 0)
			llp = &ll;
		(void) close(fdl);
	}

	if ((fdl = open(LASTLOG_LEGACY, O_RDONLY)) >= 0) {
		if (lastlog_read(fdl, pwd.pw_uid, &legacyll, B_TRUE) == 0 &&
		    legacyll.ll_time > ll.ll_time)
			llp = &legacyll;
		(void) close(fdl);
	}

	if (llp != NULL && llp->ll_time != 0 && !(flags & PAM_SILENT)) {
		char timestr[26];
		char msg[PAM_MAX_MSG_SIZE];
		int ret;
		time_t t = llp->ll_time;
		(void) ctime_r(&t, timestr, sizeof (timestr));
		timestr[strcspn(timestr, "\n")] = '\0';
		if (strcmp(llp->ll_host, "") != 0) {
			ret = snprintf(msg, PAM_MAX_MSG_SIZE,
			    "Last login: %s from %s", timestr, llp->ll_host);
		} else if (strcmp(llp->ll_line, "") != 0) {
			ret = snprintf(msg, PAM_MAX_MSG_SIZE,
			    "Last login: %s on %s", timestr, llp->ll_line);
		} else {
			ret = snprintf(msg, PAM_MAX_MSG_SIZE,
			    "Last login: %s", timestr);
		}
		if (!(ret < 0 || ret >= PAM_MAX_MSG_SIZE)) {
			(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, &msg,
			    NULL);
		}
	}

reopenll_rw:
	fdl = open(_PATH_LASTLOG, O_RDWR|O_CREAT|O_DSYNC, 0444);
	if (fdl < 0) {
		if (errno == EINTR)
			goto reopenll_rw;
		syslog(LOG_ERR, "pam_unix_session: unable to open lastlog for "
		    "writing for uid %d: %m", pwd.pw_uid);
		return (PAM_SUCCESS);
	}

	(void) time(&cur_time);

	newll.ll_time = cur_time;
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
	(void) lastlog_write(fdl, pwd.pw_uid, &newll);
	if (close(fdl) < 0) {
		syslog(LOG_ERR, "pam_unix_session: unable to close lastlog for"
		    " uid %d: %m", pwd.pw_uid);
	}
	return (PAM_SUCCESS);
}
