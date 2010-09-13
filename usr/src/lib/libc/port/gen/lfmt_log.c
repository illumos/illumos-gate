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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* lfmt_log() - log info */

#include "lint.h"
#include <mtlib.h>
#include <pfmt.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <fcntl.h>
#include <errno.h>
#include <synch.h>
#include <thread.h>
#include "pfmt_data.h"
#include <time.h>
#include <stropts.h>
#include <unistd.h>
#include <strings.h>
#include <sys/uio.h>

#define	MAXMSG	1024
#define	LOGNAME		"/dev/conslog"
#define	LOG_CONSOLE	"/dev/console"

int
__lfmt_log(const char *text, const char *sev, va_list args, long flag, int ret)
{
	static int fd = -1;
	struct strbuf dat;
	int msg_offset;
	long len;
	union {
		long	flag;
		char	buf[MAXMSG];
	} msg;
	int err;
	int fdd;

	len = ret + sizeof (long) + 3;

	if (len > sizeof (msg)) {
		errno = ERANGE;
		return (-2);
	}

	msg.flag = flag;
	msg_offset = (int)sizeof (long);

	lrw_rdlock(&_rw_pfmt_label);
	if (*__pfmt_label)
		msg_offset += strlcpy(msg.buf + msg_offset, __pfmt_label,
		    sizeof (msg.buf) - msg_offset);
	lrw_unlock(&_rw_pfmt_label);

	if (sev)
		msg_offset += sprintf(msg.buf + msg_offset, sev, flag & 0xff);

	msg_offset += 1 + vsprintf(msg.buf + msg_offset, text, args);
	msg.buf[msg_offset++] = '\0';

	if (fd == -1 &&
	    ((fd = open(LOGNAME, O_WRONLY)) == -1 ||
	    fcntl(fd, F_SETFD, 1) == -1))
		return (-2);

	dat.maxlen = MAXMSG;
	dat.len = (int)msg_offset;
	dat.buf = msg.buf;

	if (putmsg(fd, 0, &dat, 0) == -1) {
		(void) close(fd);
		return (-2);
	}

	/*
	 *  Display it to a console
	 */
	if ((flag & MM_CONSOLE) != 0) {
		char *p;
		time_t t;
		char buf[128];
		err = errno;
		fdd = open(LOG_CONSOLE, O_WRONLY);
		if (fdd != -1) {
			/*
			 * Use C locale for time stamp.
			 */
			(void) time(&t);
			(void) ctime_r(&t, buf, sizeof (buf));
			p = (char *)strrchr(buf, '\n');
			if (p != NULL)
				*p = ':';
			(void) write(fdd, buf, strlen(buf));
			(void) write(fdd, msg.buf + sizeof (long),
			    msg_offset - sizeof (long));
			(void) write(fdd, "\n", 1);
		} else
			return (-2);
		(void) close(fdd);
		errno = err;
	}
	return (ret);
}
