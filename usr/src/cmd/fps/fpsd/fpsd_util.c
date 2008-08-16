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

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <synch.h>
#include <syslog.h>
#include <pthread.h>
#include <thread.h>
#include <signal.h>
#include <limits.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/wait.h>
#include <sys/processor.h>
#include <ctype.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/swap.h>

#include <fpsapi.h>
#include "messages.h"
#include "fpsd.h"

/* Exported Functions */
void fps_door_handler(void *cookie, char *argp, size_t asize,
	door_desc_t  *dp, uint_t  n_desc);

/* Used by get_free_swap() */
static uint64_t
ctok(int clicks)
{
	static int factor = -1;

	if (factor == -1) factor = ((int)sysconf(_SC_PAGESIZE)) >> 10;
	return (clicks*factor);
}

/* return the available free swap space in unit of MB */
uint64_t
get_free_swap(void)
{
	struct anoninfo ai;
	unsigned freemem;

	if (swapctl(SC_AINFO, &ai) != -1) {
		/* in the unit of KB */
		freemem = (int)(ctok(ai.ani_max) - ctok(ai.ani_resv));
	}
	else
		freemem = 0;

	return (freemem/1024);
}

/*
 *  Wait for n secs. Don't use sleep due to signal behaviours.
 *  Also be aware of poll getting interrupted.
 */

void
fps_wait_secs(int secs)
{
	time_t cur = time(NULL);

	if (secs <= 0)
		return;

	do {
		if (poll(NULL, 0, secs*1000) == 0)
			break;
		secs -= (int)(time(NULL) - cur);
		cur   = time(NULL);
	} while (secs > 0);
}

/*ARGSUSED*/
void
fps_door_handler(void *cookie, char *argp, size_t asize,
	door_desc_t  *dp, uint_t  n_desc)
{
	fps_event_t	*evtp = NULL;
	fps_event_reply_t	reply;

	reply.result = -1;  /* -1 failure. 0 success */

	if (argp == NULL)
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);

	/*LINTED*/
	evtp  = (fps_event_t *)argp;

	if (cookie != FPS_DOOR_COOKIE)
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);

	fpsd_message(FPSD_NO_EXIT, FPS_INFO,
	    DOOR_HNDLR_MSG,
	    evtp->version, evtp->type, evtp->length);

	reply.result = 0;
	(void) door_return((char *)&reply, sizeof (reply), NULL, 0);

}
