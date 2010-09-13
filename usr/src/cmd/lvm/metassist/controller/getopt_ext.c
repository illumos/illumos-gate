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

#include <stdio.h>
#include <string.h>
#include "volume_error.h"
#include "getopt_ext.h"

/*
 * Functions
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
extern int
getopt_ext(
    int argc,
    char * const argv[],
    const char *optstring)
{
	int c;
	int handle_non_options = (*optstring == '-');

	/* Is "-" the first character of optstring? */
	if (handle_non_options) {
	    /* getopt(3) doesn't understand "-" */
	    optstring++;
	}

	switch (c = getopt(argc, argv, optstring)) {

		/*
		 * getopt(3) returns -1 when 1) it encounters a non-option
		 * argument or 2) reaches the end of the argument list.
		 * Distinguish from the two possibilities.
		 */
	    case -1:
		if (optind < argc) {
		    optarg = argv[optind];

		    /* Non-option argument found */
		    if (handle_non_options) {
			/* Non-option arguments are valid */
			c = GETOPT_NON_OPTION_ARG;
			optind++;
		    } else {
			/* Non-option arguments are invalid */
			c = GETOPT_ERR_INVALID_ARG;
		    }
		} else {
		    /* End of the argument list reached */
		    c = GETOPT_DONE_PARSING;
		}
	    break;

		/*
		 * getopt(3) returns '?' when 1) the "-?" option is
		 * encountered, 2) an invalid option is given or 3) a
		 * valid option requiring an argument is found but no
		 * argument is specified.  Distinguish from the three
		 * possibilities.
		 */
	    case '?':
		/* Is this an error or was -? encountered? */
		if (optopt != '?') {
		    if (strchr(optstring, optopt) == NULL) {
			/* Invalid option */
			c = GETOPT_ERR_INVALID_OPT;
			optarg = argv[optind-1];
		    } else {
			/* Valid option without required argument */
			c = GETOPT_ERR_MISSING_ARG;
		    }
		}
	}

	return (c);
}
