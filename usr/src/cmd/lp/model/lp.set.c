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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "stdio.h"

#include "lp.h"
#include "lp.set.h"

extern char		*getenv();

/**
 ** main()
 **/

int
main(int argc, char *argv[])
{
	static char		not_set[10]	= "H V W L S";

	int			exit_code;

	char			*TERM		= getenv("TERM");


	if (!TERM || !*TERM || tidbit(TERM, (char *)0) == -1)
		exit (1);

	/*
	 * Very simple calling sequence:
	 *
	 *	lpset horz-pitch vert-pitch width length char-set
	 *
	 * The first four can be scaled with 'i' (inches) or
	 * 'c' (centimeters). A pitch scaled with 'i' is same
	 * as an unscaled pitch.
	 * Blank arguments will skip the corresponding setting.
	 */
	if (argc != 6)
		exit (1);

	exit_code = 0;

	if (argv[1][0]) {
		switch (set_pitch(argv[1], 'H', 1)) {
		case E_SUCCESS:
			not_set[0] = ' ';
			break;
		case E_FAILURE:
			break;
		default:
			exit_code = 1;
			break;
		}
	} else
		not_set[0] = ' ';

	if (argv[2][0]) {
		switch (set_pitch(argv[2], 'V', 1)) {
		case E_SUCCESS:
			not_set[2] = ' ';
			break;
		case E_FAILURE:
			break;
		default:
			exit_code = 1;
			break;
		}
	} else
		not_set[2] = ' ';

	if (argv[3][0]) {
		switch (set_size(argv[3], 'W', 1)) {
		case E_SUCCESS:
			not_set[4] = ' ';
			break;
		case E_FAILURE:
			break;
		default:
			exit_code = 1;
			break;
		}
	} else
		not_set[4] = ' ';

	if (argv[4][0]) {
		switch (set_size(argv[4], 'L', 1)) {
		case E_SUCCESS:
			not_set[6] = ' ';
			break;
		case E_FAILURE:
			break;
		default:
			exit_code = 1;
			break;
		}
	} else
		not_set[6] = ' ';

	if (argv[5][0]) {
		switch (set_charset(argv[5], 1, TERM)) {
		case E_SUCCESS:
			not_set[8] = ' ';
			break;
		case E_FAILURE:
			break;
		default:
			exit_code = 1;
			break;
		}
	} else
		not_set[8] = ' ';

	fprintf (stderr, "%s\n", not_set);

	return (exit_code);
}
