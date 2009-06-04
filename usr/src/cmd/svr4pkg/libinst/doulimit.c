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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <stdio.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <locale.h>
#include <libintl.h>
#include <ctype.h>
#include <pkglib.h>
#include <libinst.h>

#define	ERR_SET_ULIMIT	"unable to set ulimit to <%ld> blocks"
#define	ERR_DO_ULIMIT	"An attempt was made to create a file larger than " \
			    "ULIMIT. Source of fault is unknown."
#define	ERR_SCRULIMIT	"Script <%s> attempted to create a file exceeding " \
			    "ULIMIT."

static char *script_name = NULL, *scr_error = NULL;
static struct rlimit ulimit = {RLIM_INFINITY, RLIM_INFINITY};
static struct rlimit dblimit = {RLIM_INFINITY, RLIM_INFINITY};
static int limit_is_set = 0, fail_return = 0;

void ulimit_quit();	/* XFSZ controlled signal handler. */
int clr_ulimit();	/* Clear the user supplied file size limit. */
void set_limit();	/* Called from installf to undo ulimit */
int set_ulimit(char *script, char *err_msg);
int assign_ulimit(char *fslimit);

extern int	warnflag;

void
set_limit()
{
	limit_is_set = 1;
}

int
clr_ulimit()
{
	if (limit_is_set) {
		if (script_name)
			free(script_name);
		script_name = NULL;
		if (scr_error)
			free(scr_error);
		scr_error = NULL;
		fail_return = 99;

		/* Clear out the limit to infinity. */
		return (setrlimit(RLIMIT_FSIZE, &dblimit));
	} else
		return (0);
}

/*
 * This sets up the ULIMIT facility for the signal retrieval. This sets up
 * the static pointers to the message constants for indicating where the
 * error occurred.
 */
int
set_ulimit(char *script, char *err_msg)
{
	int n;

	if (limit_is_set) {
		(void) signal(SIGXFSZ, ulimit_quit);
		if (script_name)
			free(script_name);
		script_name = strdup(script);
		if (scr_error)
			free(scr_error);
		scr_error = strdup(err_msg);
		fail_return = 99;

		n = setrlimit(RLIMIT_FSIZE, &ulimit);

		return (n);
	} else
		return (0);

}

/* Validate ULIMIT and set accordingly. */
int
assign_ulimit(char *fslimit)
{
	rlim_t limit;
	int cnt = 0;

	if (fslimit && *fslimit) {
		/* fslimit must be a simple unsigned integer. */
		do {
			if (!isdigit(fslimit[cnt]))
				return (-1);
		} while (fslimit[++cnt]);

		limit = atol(fslimit);

		ulimit.rlim_cur = (limit * 512); /* fslimit is in blocks */

		limit_is_set = 1;

		return (0);
	} else
		return (-1);
}

/*
 * This is the signal handler for ULIMIT.
 */
void
ulimit_quit(int n)
{
#ifdef lint
	int i = n;
	n = i;
#endif	/* lint */

	setrlimit(RLIMIT_FSIZE, &dblimit);
	signal(SIGXFSZ, SIG_IGN);

	if (script_name) {
		progerr(gettext(ERR_SCRULIMIT), script_name);
		if (scr_error)
			progerr("%s", scr_error);
	} else
		progerr(gettext(ERR_DO_ULIMIT));

	quit(fail_return);
}
