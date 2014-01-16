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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "netpr.h"
#include "netdebug.h"

extern char *strtok_r(char *, const char *, char **);

int
check_file(char * filename)
{
	struct stat status;

	if (filename  == NULL)
		return (-1);

	/* Checking read permission */
	if (access(filename, R_OK) < 0)
		return (-1);

	if (stat(filename, &status) < 0)
		return (-1);

	/* Checking for regular file */
	if (S_ISREG(status.st_mode) == 0) {
		errno = EISDIR;
		return (-1);
	}

	/* Checking for empty file */
	if (status.st_size == 0) {
		errno = ESRCH;
		return (-1);
	}
	return (status.st_size);
}


/*
 * allocate the space; fill with input
 */
char *
alloc_str(char * instr)
{
	char * outstr;

	outstr = (char *)malloc(strlen(instr) + 1);
	ASSERT(outstr, MALLOC_ERR);
	(void) memset(outstr, 0, strlen(instr) + 1);
	(void) strcpy(outstr, instr);

	return (outstr);
}

np_job_t *
init_job()
{
	np_job_t * job;

	if ((job = calloc(1, sizeof (*job))) != NULL) {
		job->protocol = BSD;
		job->banner = BANNER;
	}

	return (job);
}

void
tell_lptell(int type, char *fmt, ...)
{
	char msg[BUFSIZ];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(msg, sizeof (msg), fmt, ap);
	va_end(ap);

	if (msg == NULL)
		return;

	switch (type) {
	case ERRORMSG:
		(void) fprintf(stderr, "%%%%[PrinterError: %s ]%%%%\n", msg);
		break;
	case OKMSG:
		/* In this case, the message is the job request-id */
		(void) fprintf(stderr,
		"%%%%[job: %s status: ok source: Netpr]%%%%\n", msg);
		break;
	default:
		/* unknown type, ignore */
		break;
	}


}


/*
 * Parse destination
 * bsd: <printer_host>[:<printer_vendor_defined_name]
 * tcp: <printer_host>[:port_number]
 */

void
parse_dest(char * dest, char **str1, char **str2, char * sep)
{
	char * tmp;
	char * nexttok;

	*str1 = NULL;
	*str2 = NULL;

	if (dest != NULL) {
		tmp = (char *)strtok_r(dest, sep, &nexttok);
		if (tmp != NULL)
			*str1 = strdup(tmp);
		tmp = (char *)strtok_r(NULL, sep, &nexttok);
		if (tmp != NULL)
			*str2 = strdup(tmp);
	}

}

/*
 * void panic call
 * used with ASSERT macro; gives us a place to stop the debugger
 */
void
panic()
{
}
