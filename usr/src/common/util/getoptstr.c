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
 * Copyright 1992-1996,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * This file contains getoptstr(), which is getopt() for strings of arguments
 * (not arrays of strings).  It is used by the bootloader ({*fs,inet}boot) and
 * the kernel to process argument strings.
 */


#include "getoptstr.h"
#include <sys/null.h>


/*
 * This routine needs to be supplied by whatever uses this file.
 */
char *strchr(const char *s, int c);


#define	ISNTWORDCH(c)	((c) == '\0' || ISSPACE(c))


/*
 * Prepare a gos_params structure for use by getoptstr().
 */
void
getoptstr_init(struct gos_params *params)
{
	params->gos_pos = 1;
}

/*
 * Modeled after lib/libc/port/gen/getopt.c.
 *
 * With params->gos_opts set to a string of options and params->gos_strp set to
 * an argument string, getoptstr returns
 *   * the next option letter, where the options are given by the
 *     params->gos_opts string.  If the option is followed by a ':' in gos_opts,
 *     then params->gos_optargp will point to the beginning of the argument in
 *     the string, and params->gos_optarglen will contain its length.
 *   * -1 if "--" or a non-option argument is encountered.  In the former
 *     case, params->gos_strp is advanced to the next argument.
 *   * '?' if an illegal option is encountered or if an argument is not
 *     supplied for an option which requires one and ':' is not the first
 *     character of opts.  In both cases, the option letter is available in
 *     params->gos_last_opt, and in the former case, params->gos_errp will
 *     point to the offending character.
 *   * ':' if an argument is not supplied for an option which requires one and
 *     ':' is the first character of params->gos_opts.
 */
int
getoptstr(struct gos_params *params)
{
	char c;
	char *cp;

	/*
	 * const because we should update params.  Just make sure you don't
	 * use this after you update params->gos_strp.
	 */
	const char * const strp = params->gos_strp;


	if (params->gos_opts == NULL || strp == NULL)
		return (-1);

	if (params->gos_pos == 1) {
		/* At beginning of new word. */

		if (strp[0] == '\0' || strp[0] != '-')
			return (-1);
		if (ISNTWORDCH(strp[1])) {
			/* Lone dash. */
			return (-1);
		}

		/* Check for "--" */
		if (strp[1] == '-' && ISNTWORDCH(strp[2])) {
			params->gos_strp = &strp[2];
			SKIP_SPC(params->gos_strp);
			return (-1);
		}
	}

	params->gos_last_opt = c = strp[params->gos_pos];
	if (c == ':' || (cp = strchr(params->gos_opts, c)) == NULL) {
		/* Unrecognized option error. */
		params->gos_errp = &strp[params->gos_pos];
		++params->gos_pos;
		if (ISNTWORDCH(strp[params->gos_pos])) {
			params->gos_strp = &strp[params->gos_pos];
			SKIP_SPC(params->gos_strp);
			params->gos_pos = 1;
		}
		return ('?');
	}

	if (cp[1] == ':') {
		/* This option expects an argument. */

		params->gos_strp = &strp[params->gos_pos + 1];

		if (ISNTWORDCH(*params->gos_strp)) {
			/* The argument is in the next word. */
			SKIP_SPC(params->gos_strp);

			if (*params->gos_strp == '\0') {
				/* Not.  Missing argument. */
				params->gos_pos = 1;
				params->gos_optargp = NULL;
				return (params->gos_opts[0] == ':' ? ':' : '?');
			}
		}

		params->gos_optargp = params->gos_strp;

		/* Advance to the next word. */
		SKIP_WORD(params->gos_strp);
		params->gos_optarglen = params->gos_strp - params->gos_optargp;
		SKIP_SPC(params->gos_strp);

		params->gos_pos = 1;
	} else {
		++params->gos_pos;
		if (ISNTWORDCH(strp[params->gos_pos])) {
			params->gos_strp = &strp[params->gos_pos];
			SKIP_SPC(params->gos_strp);
			params->gos_pos = 1;
		}
		params->gos_optargp = NULL;
	}
	return (c);
}
