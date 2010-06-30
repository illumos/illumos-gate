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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */



/*
 * System includes
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <assert.h>
#include <locale.h>
#include <libintl.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

#define	isdot(x)	((x[0] == '.') && (!x[1] || (x[1] == '/')))
#define	isdotdot(x)	((x[0] == '.') && (x[1] == '.') && \
		    (!x[2] || (x[2] == '/')))

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	z_make_zone_root
 * Description:	Given its zonepath, generate a string representing the
 *              mountpoint of where the root path for a nonglobal zone is
 *              mounted.  The zone is mounted using 'zoneadm', which mounts
 *              the zone's filesystems wrt <zonepath>/lu/a
 * Arguments:	zone_path - non-NULL pointer to string representing zonepath
 * Returns:	char *	- pointer to string representing zonepath of zone
 *		NULL	- if zone_path is NULL.
 * Notes:	The string returned is in static storage and should not be
 *              free()ed by the caller.
 */
char *
z_make_zone_root(char *zone_path)
{
	static char	zone_root_buf[MAXPATHLEN];

	if (zone_path == NULL)
		return (NULL);

	(void) snprintf(zone_root_buf, MAXPATHLEN, "%s%slu/a", zone_path,
	    (zone_path[0] != '\0' &&
	    zone_path[strlen(zone_path) - 1] == '/') ? "" : "/");

	return (zone_root_buf);
}

void
z_path_canonize(char *a_file)
{
	char	*pt;
	char	*last;
	int	level;

	/* remove references such as "./" and "../" and "//" */
	for (pt = a_file; *pt; /* void */) {
		if (isdot(pt)) {
			(void) strcpy(pt, pt[1] ? pt+2 : pt+1);
		} else if (isdotdot(pt)) {
			level = 0;
			last = pt;
			do {
				level++;
				last += 2;
				if (*last) {
					last++;
				}
			} while (isdotdot(last));
			--pt; /* point to previous '/' */
			while (level--) {
				if (pt <= a_file) {
					return;
				}
				while ((*--pt != '/') && (pt > a_file))
					;
			}
			if (*pt == '/') {
				pt++;
			}
			(void) strcpy(pt, last);
		} else {
			while (*pt && (*pt != '/')) {
				pt++;
			}
			if (*pt == '/') {
				while (pt[1] == '/') {
					(void) strcpy(pt, pt+1);
				}
				pt++;
			}
		}
	}

	if ((--pt > a_file) && (*pt == '/')) {
		*pt = '\0';
	}
}

void
z_canoninplace(char *src)
{
	char *dst;
	char *src_start;

	/* keep a ptr to the beginning of the src string */
	src_start = src;

	dst = src;
	while (*src) {
		if (*src == '/') {
			*dst++ = '/';
			while (*src == '/')
				src++;
		} else
			*dst++ = *src++;
	}

	/*
	 * remove any trailing slashes, unless the whole string is just "/".
	 * If the whole string is "/" (i.e. if the last '/' cahr in dst
	 * in the beginning of the original string), just terminate it
	 * and return "/".
	 */
	if ((*(dst - 1) == '/') && ((dst - 1) != src_start))
		dst--;
	*dst = '\0';
}
