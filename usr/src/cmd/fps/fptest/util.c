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

#include <stdio.h>
#include <sys/systeminfo.h>
#include <strings.h>
#include <netdb.h>
#include <stdarg.h>
#include <sys/time.h>

#define	FPS_MAX_MSGLEN  4096 /* Max msg length including last null */
#define	FPS_TEST_NAME "fptest" /* Name of test app */
#define	FPS_VER_TEST    "1.0" /* Test Version */

void fps_msg(int msg_enable, const char *fmt, ...);
static const char *msg_get_hostname();

static const char *
msg_get_hostname(void) {
	static char hname[MAXHOSTNAMELEN+1];

	if (hname[0] == 0)
		sysinfo(SI_HOSTNAME, hname, MAXHOSTNAMELEN);

	return (hname);
}

void
fps_msg(int msg_enable, const char *fmt, ...)
{
	char  msg_buf[FPS_MAX_MSGLEN];
	char  *msg_ptr;
	struct tm tms;
	time_t ts;
	va_list  ap;

	va_start(ap, fmt);

	if (!msg_enable)
		return;

	if (NULL == fmt)
		return;

	time(&ts);
	localtime_r(&ts, &tms);

	msg_buf[0] = 0;
	strftime(msg_buf, sizeof (msg_buf), "%x %X ", &tms);

	msg_ptr = &msg_buf[strlen(msg_buf)];
	snprintf(msg_ptr, sizeof (msg_buf) - strlen(msg_buf) - 1,
	    "%s %s(%s).%s: ",
	    msg_get_hostname(),
	    FPS_TEST_NAME, FPS_VER_TEST,
	    "verbose");

	msg_ptr = &msg_buf[strlen(msg_buf)];

	vsnprintf(msg_ptr, sizeof (msg_buf) - strlen(msg_buf) - 1, fmt, ap);
	if (msg_buf[strlen(msg_buf)-1] != '\n')
		strcat(msg_buf, "\n");


	(void) fputs(msg_buf, stdout);

	va_end(ap);
}
