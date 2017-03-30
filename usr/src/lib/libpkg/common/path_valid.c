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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#include <limits.h>
#include <string.h>
#include <sys/types.h>

/*
 * Name:		path_valid
 * Description:	Checks a string for being a valid path
 *
 * Arguments:	path - path to validate
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise.
 *		B_FALSE means path was null, too long (>PATH_MAX),
 *		or too short (<1)
 */
boolean_t
path_valid(char *path)
{
	if (path == NULL) {
		return (B_FALSE);
	} else if (strlen(path) > PATH_MAX) {
		return (B_FALSE);
	} else if (strlen(path) >= 1) {
		return (B_TRUE);
	} else {
		/* path < 1 */
		return (B_FALSE);
	}
}
