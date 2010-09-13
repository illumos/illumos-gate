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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * General utility routines.
 */

#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <libintl.h>
#include <unistd.h>
#include "inetd_impl.h"


/* size of buffer used in msg() to expand printf() like messages into */
#define	MSG_BUF_SIZE		1024

/* number of pollfd we grow the pollfd array by at a time in set_pollfd() */
#define	POLLFDS_GROWTH_SIZE	16

/* enumeration of message types supported by msg() */
typedef enum {
	MT_ERROR,
	MT_DEBUG,
	MT_WARN
} si_msg_type_t;

/*
 * Collection of information for each method type.
 * NOTE:  This table is indexed into using the instance_method_t
 * enumeration, so the ordering needs to be kept in synch.
 */
method_type_info_t methods[] = {
	{IM_START, START_METHOD_NAME, IIS_NONE},
	{IM_ONLINE, ONLINE_METHOD_NAME, IIS_ONLINE},
	{IM_OFFLINE, OFFLINE_METHOD_NAME, IIS_OFFLINE},
	{IM_DISABLE, DISABLE_METHOD_NAME, IIS_DISABLED},
	{IM_REFRESH, REFRESH_METHOD_NAME, IIS_ONLINE},
	{IM_NONE, "none", IIS_NONE}
};

struct pollfd	*poll_fds = NULL;
nfds_t		num_pollfds;

boolean_t	syslog_open = B_FALSE;
boolean_t	debug_enabled = B_FALSE;

void
msg_init(void)
{
	openlog(SYSLOG_IDENT, LOG_PID|LOG_CONS, LOG_DAEMON);
	syslog_open = B_TRUE;
}

void
msg_fini(void)
{
	syslog_open = B_FALSE;
	closelog();
}

/*
 * Outputs a msg. If 'type' is set tp MT_ERROR or MT_WARN the message goes
 * to syslog with severitys LOG_ERROR and LOG_WARN respectively. For all
 * values of 'type' the message is written to the debug log file, if it
 * was openable when inetd started.
 */
static void
msg(si_msg_type_t type, const char *format, va_list ap)
{
	/*
	 * Use a stack buffer so we stand more chance of reporting a
	 * memory shortage failure.
	 */
	char		buf[MSG_BUF_SIZE];

	if (!syslog_open)
		return;

	(void) vsnprintf(buf, sizeof (buf), format, ap);

	/*
	 * Log error and warning messages to syslog with appropriate severity.
	 */
	if (type == MT_ERROR) {
		syslog(LOG_ERR, "%s", buf);
	} else if (type == MT_WARN) {
		syslog(LOG_WARNING, "%s", buf);
	} else if (debug_enabled && type == MT_DEBUG) {
		syslog(LOG_DEBUG, "%s", buf);
	}
}

/*
 * Output a warning message. Unlike error_msg(), syslog doesn't get told
 * to log to the console if syslogd isn't around.
 */
void
warn_msg(const char *format, ...)
{
	va_list ap;

	closelog();
	openlog(SYSLOG_IDENT, LOG_PID, LOG_DAEMON);

	va_start(ap, format);
	msg(MT_WARN, format, ap);
	va_end(ap);

	closelog();
	openlog(SYSLOG_IDENT, LOG_PID|LOG_CONS, LOG_DAEMON);
}

void
debug_msg(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	msg(MT_DEBUG, format, ap);
	va_end(ap);
}

void
error_msg(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	msg(MT_ERROR, format, ap);
	va_end(ap);
}

void
poll_fini(void)
{
	if (poll_fds != NULL) {
		free(poll_fds);
		poll_fds = NULL;
	}
}

struct pollfd *
find_pollfd(int fd)
{
	nfds_t n;

	for (n = 0; n < num_pollfds; n++) {
		if (poll_fds[n].fd == fd)
			return (&(poll_fds[n]));
	}
	return (NULL);
}

int
set_pollfd(int fd, uint16_t events)
{
	struct pollfd	*p;
	int		i;

	p = find_pollfd(fd);
	if ((p == NULL) && ((p = find_pollfd(-1)) == NULL)) {
		if ((p = realloc(poll_fds,
		    ((num_pollfds + POLLFDS_GROWTH_SIZE) *
		    sizeof (struct pollfd)))) == NULL) {
			return (-1);
		}
		poll_fds = p;

		for (i = 1; i < POLLFDS_GROWTH_SIZE; i++)
			poll_fds[num_pollfds + i].fd = -1;

		p = &poll_fds[num_pollfds];
		num_pollfds += POLLFDS_GROWTH_SIZE;
	}

	p->fd = fd;
	p->events = events;
	p->revents = 0;

	return (0);
}

void
clear_pollfd(int fd)
{
	struct pollfd *p;

	if ((p = find_pollfd(fd)) != NULL) {
		p->fd = -1;
		p->events = 0;
		p->revents = 0;
	}
}

boolean_t
isset_pollfd(int fd)
{
	struct pollfd *p = find_pollfd(fd);

	return ((p != NULL) && (p->revents & POLLIN));
}

/*
 * An extension of read() that keeps retrying until either the full request has
 * completed, the other end of the connection/pipe is closed, no data is
 * readable for a non-blocking socket/pipe, or an unexpected error occurs.
 * Returns 0 if the data is successfully read, 1 if the other end of the pipe/
 * socket is closed or there's nothing to read from a non-blocking socket/pipe,
 * else -1 if an unexpected error occurs.
 */
int
safe_read(int fd, void *buf, size_t sz)
{
	int	ret;
	size_t  cnt = 0;
	char    *cp = (char *)buf;

	if (sz == 0)
		return (0);

	do {
		switch (ret = read(fd, cp + cnt, sz - cnt)) {
		case 0:			/* other end of pipe/socket closed */
			return (1);
		case -1:
			if (errno == EAGAIN) {		/* nothing to read */
				return (1);
			} else if (errno != EINTR) {
				error_msg(gettext("Unexpected read error: %s"),
				    strerror(errno));
				return (-1);
			}
			break;

		default:
			cnt += ret;
		}
	} while (cnt != sz);

	return (0);
}

/*
 * Return B_TRUE if instance 'inst' has exceeded its configured maximum
 * concurrent copies limit, else B_FALSE.
 */
boolean_t
copies_limit_exceeded(instance_t *inst)
{
	/* any value <=0 means that copies limits are disabled */
	return ((inst->config->basic->max_copies > 0) &&
	    (inst->copies >= inst->config->basic->max_copies));
}

/*
 * Cancel the method/con-rate offline timer associated with the instance.
 */
void
cancel_inst_timer(instance_t *inst)
{
	(void) iu_cancel_timer(timer_queue, inst->timer_id, NULL);
	inst->timer_id = -1;
}

/*
 * Cancel the bind retry timer associated with the instance.
 */
void
cancel_bind_timer(instance_t *inst)
{
	(void) iu_cancel_timer(timer_queue, inst->bind_timer_id, NULL);
	inst->bind_timer_id = -1;
}

void
enable_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	(void) fcntl(fd, F_SETFL, (flags & ~O_NONBLOCK));
}

void
disable_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	(void) fcntl(fd, F_SETFL, (flags | O_NONBLOCK));
}
