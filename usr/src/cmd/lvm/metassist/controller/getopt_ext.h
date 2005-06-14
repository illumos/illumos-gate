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

#ifndef _GETOPTEXT_H
#define	_GETOPTEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returned chars for getopt_ext
 */

/* A non-option argument was found */
#define	GETOPT_NON_OPTION_ARG		1

/* All arguments have been parsed */
#define	GETOPT_DONE_PARSING		-1

/* An invalid option was found */
#define	GETOPT_ERR_INVALID_OPT		-2

/* An invalid non-option argument was found */
#define	GETOPT_ERR_INVALID_ARG		-3

/* No argument for valid option expecting an argument */
#define	GETOPT_ERR_MISSING_ARG		-4

/*
 * Function prototypes
 */

/*
 * Identical to getopt(3), except that
 *
 * 1. If "-" is the first character of optstring, each non-option argv
 *    element is handled as if it were the argument of an option with
 *    character code GETOPT_NON_OPTION_ARG.  The result is that
 *    GETOPT_DONE_PARSING will not be returned until the end of the
 *    argument list has been reached.
 *
 *    This mirrors the functionality provided by GNU getopt.
 *
 * 2. GETOPT_ERR_INVALID_OPT or GETOPT_ERR_MISSING_ARG is returned
 *    instead of '?'.  Subsequently "-?" can be used as a valid
 *    option.
 *
 * 3. GETOPT_DONE_PARSING, GETOPT_ERR_INVALID_ARG, or
 *    GETOPT_NON_OPTION_ARG is returned instead of -1.
 *
 * @param       argc
 *              The number of arguments in the array
 *
 * @param       argv
 *              The argument array
 *
 * @param       optstring
 *              The option letters, with ':' following options with
 *              required arguments.  See note about "-" as the first
 *              character.
 *
 * @return      GETOPT_ERR_INVALID_OPT
 *              if the option is not found in optstring
 *
 *              GETOPT_ERR_MISSING_ARG
 *              if the option requires an argument which is missing
 *
 *              GETOPT_ERR_INVALID_ARG
 *              if "-" is not the first character in optstring and a
 *              non-option argument is encountered
 *
 *              GETOPT_NON_OPTION_ARG
 *              if "-" is the first character in optstring and a
 *              non-option argument is encountered
 *
 *              GETOPT_DONE_PARSING
 *              if the end of the argument list is reached
 *
 *              <optopt>
 *              the option character itself, if none of the above
 *              scenarios applies.
 */
extern int getopt_ext(int argc, char * const argv[], const char *optstring);

#ifdef __cplusplus
}
#endif

#endif /* _GETOPTEXT_H */
