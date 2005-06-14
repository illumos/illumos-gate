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

#ifndef _VOLUME_OUTPUT_H
#define	_VOLUME_OUTPUT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>

#ifdef DEBUG
/*
 * The environment variable that must be set for metassist to
 * enable debug output
 */
#define	METASSIST_DEBUG_ENV	"METASSIST_DEBUG"
#endif

/* Verbosity levels */
#define	OUTPUT_QUIET	0
#define	OUTPUT_TERSE	1
#define	OUTPUT_VERBOSE	2
#define	OUTPUT_DEBUG	3

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
extern int set_max_verbosity(int verbosity, FILE *stream);

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
extern int get_max_verbosity();

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
extern int oprintf(int verbosity, char *fmt, ...);

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
extern int oprintf_va(int verbosity, char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_OUTPUT_H */
