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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file.c - file dependency vertex code
 *
 *   In principle, file dependencies should be retested on mount/unmount
 *   events, and dependency error flow used to determine whether a lost file
 *   affects the dependent service.  If mount/unmount events are not available,
 *   the kstat facility (which registers or deregisters a statistic at
 *   mount/umount) could be used as an indirect filesystem event detector.
 *
 *   In practice, file dependencies are checked only for existence at start
 *   time.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <startd.h>

int
file_ready(graph_vertex_t *v)
{
	char *fn;
	struct stat sbuf;
	int r;
	char *file_fmri = v->gv_name;

	/*
	 * Advance through file: FMRI until we have an absolute file path.
	 */
	if (strncmp(file_fmri, "file:///", sizeof ("file:///") - 1) == 0) {
		fn = file_fmri + sizeof ("file://") - 1;
	} else if (strncmp(file_fmri, "file://localhost/",
		sizeof ("file://localhost/") - 1) == 0) {
		fn = file_fmri + sizeof ("file://localhost") - 1;
	} else if (strncmp(file_fmri, "file://", sizeof ("file://") - 1)
	    == 0) {
		fn = file_fmri + sizeof ("file://") - 1;

		/*
		 * Again, search for the next '/'.
		 */
		if ((fn = strchr(fn, '/')) == NULL)
			return (0);
	}

	/*
	 * If stat(2) succeeds for that path, then the dependency is satisfied.
	 */
	do {
		r = stat(fn, &sbuf);
	} while (r == -1 && errno == EINTR);

	return (r == -1 ? 0 : 1);
}
