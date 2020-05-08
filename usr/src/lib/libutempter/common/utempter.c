/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009 Ed Schouten <ed@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>

static int last_fd = -1;

static void
utempter_update_utmpx(int type, int fd, const char *host)
{
	struct utmpx ut;
	struct passwd *pw;
	uid_t uid;

	(void) memset(&ut, 0, sizeof (ut));
	ut.ut_type = type;
	ut.ut_pid = getpid();
	ut.ut_session = getsid(0);
	(void) gettimeofday(&ut.ut_tv, NULL);
	if (snprintf(ut.ut_id, sizeof (ut.ut_id), "f%d", fd) >=
	    sizeof (ut.ut_id))
		return;
	uid = getuid();
	if ((pw = getpwuid(uid)) == NULL)
		return;
	(void) strlcpy(ut.ut_user, pw->pw_name, sizeof (ut.ut_user));

	if (type == DEAD_PROCESS) {
		struct utmpx *ut1;
		struct utmpx ut2;

		(void) memset(&ut2, 0, sizeof (ut2));
		ut2.ut_type = USER_PROCESS;
		if (snprintf(ut2.ut_id, sizeof (ut2.ut_id), "f%d", fd) >=
		    sizeof (ut2.ut_id))
			return;
		if ((ut1 = getutxid(&ut2)) == NULL)
			return;
		(void) strlcpy(ut.ut_line, ut1->ut_line, sizeof (ut.ut_line));
	} else {
		char *line = ptsname(fd);
		if (line == NULL)
			return;
		(void) strlcpy(ut.ut_line, line + strlen("/dev/"),
		    sizeof (ut.ut_line));
	}

	if (host != NULL) {
		(void) strlcpy(ut.ut_host, host, sizeof (ut.ut_host));
		ut.ut_syslen = strlen(ut.ut_host) + 1;
	}

	setutxent();
	(void) pututxline(&ut);
	endutxent();
}

int
utempter_add_record(int fd, const char *host)
{
	utempter_update_utmpx(USER_PROCESS, fd, host);
	last_fd = fd;
	return (0);
}

int
utempter_remove_record(int fd)
{
	utempter_update_utmpx(DEAD_PROCESS, fd, NULL);
	if (last_fd == fd)
		last_fd = -1;
	return (0);
}

int
utempter_remove_added_record(void)
{
	if (last_fd < 0)
		return (0);
	utempter_update_utmpx(DEAD_PROCESS, last_fd, NULL);
	last_fd = -1;
	return (0);
}

void
addToUtmp(const char *pty __unused, const char *host, int fd)
{
	(void) utempter_add_record(fd, host);
}

void
removeFromUtmp(void)
{
	(void) utempter_remove_added_record();
}

void
removeLineFromUtmp(const char *pty __unused, int fd)
{
	(void) utempter_remove_record(fd);
}
