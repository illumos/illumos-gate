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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "pkglib.h"

/*
 * Name:	fmkdir
 * Description:	force the creation of a directory, even if the current
 *		node exists and is not a directory
 * Arguments:	a_path - pointer to string representing the path to the
 *			directory to create
 *		a_mode - mode(2) bits to set the path to if created
 * returns: 0 - directory created
 *	    1 - could not remove existing non-directory node
 *	    2 - could not create specified new directory
 */
int
fmkdir(char *a_path, int a_mode)
{
	if (access(a_path, F_OK) == 0) {
		if (rrmdir(a_path) != 0) {
			return (1);
		}
	}

	if (mkdir(a_path, a_mode) != 0) {
		return (2);
	}

	return (0);
}
