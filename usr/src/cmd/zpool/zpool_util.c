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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <libgen.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "zpool_util.h"

/*
 * Utility function to guarantee malloc() success.
 */
void *
safe_malloc(size_t size)
{
	void *data;

	if ((data = calloc(1, size)) == NULL) {
		(void) fprintf(stderr, "internal error: out of memory\n");
		exit(1);
	}

	return (data);
}

/*
 * Same as above, but for strdup()
 */
char *
safe_strdup(const char *str)
{
	char *ret;

	if ((ret = strdup(str)) == NULL) {
		(void) fprintf(stderr, "internal error: out of memory\n");
		exit(1);
	}

	return (ret);
}

/*
 * Display an out of memory error message and abort the current program.
 */
void
no_memory(void)
{
	assert(errno == ENOMEM);
	(void) fprintf(stderr,
	    gettext("internal error: out of memory\n"));
	exit(1);
}

/*
 * Given a vdev, return the name to display in iostat.  If the vdev has a path,
 * we use that, stripping off any leading "/dev/dsk/"; if not, we use the type.
 * We also check if this is a whole disk, in which case we strip off the
 * trailing 's0' slice name.
 */
char *
vdev_get_name(nvlist_t *nv)
{
	char *path;
	uint64_t wholedisk;

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0) {

		if (strncmp(path, "/dev/dsk/", 9) == 0)
			path += 9;

		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_WHOLE_DISK,
		    &wholedisk) == 0 && wholedisk) {
			char *tmp = safe_strdup(path);
			tmp[strlen(path) - 2] = '\0';
			return (tmp);
		}
	} else {
		verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &path) == 0);
	}

	return (safe_strdup(path));
}
