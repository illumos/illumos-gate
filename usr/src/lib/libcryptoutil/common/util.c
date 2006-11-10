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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cryptoutil.h>
#include <strings.h>
#include <stdio.h>
#include <tzfile.h>

/*
 * This function returns a fullpath based on the "dir" and "filepath" input
 * arugments.
 * - If the filepath specified does not start with a "/" and the directory
 *   is also given, prepend the directory to the filename.
 * - If only dir or filepath is given, this function returns a copy of the
 *   given argument.
 * - If the filepath is fully qualified already and the "dir" is also
 *   given, return NULL to indicate an error.
 */
char *
get_fullpath(char *dir, char *filepath)
{
	char *fullpath = NULL;
	int pathlen = 0;
	int dirlen = 0;

	if (filepath != NULL)
		pathlen = strlen(filepath);

	if (dir != NULL)
		dirlen = strlen(dir);

	if (pathlen > 0 && dirlen > 0) {
		if (filepath[0] != '/') {
			int len = pathlen + dirlen + 2;
			fullpath = (char *)malloc(len);
			if (fullpath != NULL)
				(void) snprintf(fullpath, len, "%s/%s",
				    dir, filepath);
		} else {
			return (NULL);
		}
	} else if (pathlen > 0) {
		fullpath = (char *)strdup(filepath);
	} else if (dirlen > 0) {
		fullpath = (char *)strdup(dir);
	}

	return (fullpath);
}

/*
 * This function converts the input string to the value of time
 * in seconds.
 * - If the input string is NULL, return zero second.
 * - The input string needs to be in the form of:
 *   number-second(s), number-minute(s), number-hour(s) or
 *   number-day(s).
 */
int
str2lifetime(char *ltimestr, uint32_t *ltime)
{
	int num;
	char timetok[10];

	if (ltimestr == NULL || !strlen(ltimestr)) {
		*ltime = 0;
		return (0);
	}

	(void) memset(timetok, 0, sizeof (timetok));
	if (sscanf(ltimestr, "%d-%08s", &num, timetok) != 2)
		return (-1);

	if (!strcasecmp(timetok, "second") ||
		!strcasecmp(timetok, "seconds")) {
		*ltime = num;
	} else if (!strcasecmp(timetok, "minute") ||
		!strcasecmp(timetok, "minutes")) {
		*ltime = num * SECSPERMIN;
	} else if (!strcasecmp(timetok, "day") ||
	    !strcasecmp(timetok, "days")) {
		*ltime = num * SECSPERDAY;
	} else if (!strcasecmp(timetok, "hour") ||
		!strcasecmp(timetok, "hours")) {
		*ltime = num * SECSPERHOUR;
	} else {
		*ltime = 0;
		return (-1);
	}

	return (0);
}
