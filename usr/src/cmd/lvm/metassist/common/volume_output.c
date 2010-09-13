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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "volume_output.h"
#include "volume_error.h"

static int max_verbosity = OUTPUT_QUIET;
static FILE *output = NULL;

/*
 * Set the maximum level of verbosity to be reported to the user.
 * Strings sent to oprintf() with a higher verbosity level than this
 * maximum level will not be reported to the user.
 *
 * @param       verbosity
 *              One of the predefined constants:
 *                OUTPUT_QUIET
 *                OUTPUT_TERSE
 *                OUTPUT_VERBOSE
 *                OUTPUT_DEBUG
 *
 * @param       stream
 *              The stream to print all qualifying output to.
 *
 * @return      0 on success, non-zero otherwise.
 */
int
set_max_verbosity(
	int verbosity,
	FILE *stream)
{
	int error = 0;

	switch (verbosity) {
	    case OUTPUT_QUIET:
	    case OUTPUT_TERSE:
	    case OUTPUT_VERBOSE:
	    case OUTPUT_DEBUG:
		max_verbosity = verbosity;
		output = stream;
	    break;

	    default:
		volume_set_error(
		    gettext("%d: invalid verbosity level"), verbosity);
		error = -1;
	}

	return (error);
}

/*
 * Get the maximum level of verbosity to be reported to the user.
 *
 * @return      OUTPUT_QUIET
 *
 * @return      OUTPUT_TERSE
 *
 * @return      OUTPUT_VERBOSE
 *
 * @return      OUTPUT_DEBUG
 */
int
get_max_verbosity()
{
	return (max_verbosity);
}

/*
 * Prints the given formatted string arguments to a predefined stream,
 * if the given verbosity is less than or equal to the set maximum
 * verbosity.
 *
 * @param       verbosity
 *              Same as for set_max_verbosity()
 *
 * @param       fmt, ...
 *              printf-style arguments
 *
 * @return      the number of characters output
 *              if successful
 *
 * @return      negative value
 *              if unsuccessful
 */
int
oprintf(
	int verbosity,
	char *fmt,
	...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = oprintf_va(verbosity, fmt, ap);
	va_end(ap);

	return (ret);
}

/*
 * Identical to oprintf but with a va_list instead of variable length
 * argument list.  This function is provided for external printf-style
 * wrappers.
 *
 * @param       verbosity
 *              Same as for set_max_verbosity()
 *
 * @param       fmt
 *              printf format string
 *
 * @param       ap
 *              a va_list containing remaining printf-style arguments
 *
 * @return      the number of characters output
 *              if successful
 *
 * @return      negative value
 *              if unsuccessful
 */
/*PRINTFLIKE2*/
int
oprintf_va(
	int verbosity,
	char *fmt,
	va_list ap)
{
	int ret = 0;

	/* Is this verbosity high enough to print? */
	if (output != NULL && verbosity <= max_verbosity) {
#ifdef DEBUG
	    if (getenv(METASSIST_DEBUG_ENV) != NULL) {
		time_t now = time(NULL);
		struct tm *time = localtime(&now);
		fprintf(output, "%.2d:%.2d:%.2d: ",
		    time->tm_hour, time->tm_min, time->tm_sec);
	    }
#endif
	    ret = vfprintf(output, fmt, ap);
	}

	return (ret);
}
