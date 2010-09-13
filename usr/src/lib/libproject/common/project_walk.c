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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/syscall.h>

#include <project.h>
#include <stdlib.h>
#include <errno.h>

static size_t
projlist(id_t *idbuf, size_t idbufsz)
{
	return (syscall(SYS_tasksys, 3, 0, 0, idbuf, idbufsz));
}

int
project_walk(int (*callback)(projid_t, void *), void *init_data)
{
	int ret = 0;
	projid_t *projids = NULL;
	projid_t *curr_projid;
	size_t sz;
	size_t osz = 0;

	while ((sz = projlist(projids, osz * sizeof (projid_t))) != osz) {
		osz = sz;
		curr_projid = projids;
		if ((projids = realloc(projids, sz * sizeof (projid_t)))
		    == NULL) {
			/*
			 * If realloc() fails, we return ENOMEM.
			 */
			if (errno == EAGAIN)
				errno = ENOMEM;
			if (curr_projid != NULL)
				free(curr_projid);
			return (-1);
		}
	}

	for (curr_projid = projids; curr_projid < projids + sz; curr_projid++) {
		if (ret = callback(*curr_projid, init_data))
			break;
	}

	free(projids);
	return (ret);
}
