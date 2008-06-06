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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma	weak _link = link

#include "lint.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

extern	int __xpg4; /* defined in port/gen/xpg4.c; 0 if not xpg4/xpg4v2 */

extern int __link(const char *existing, const char *new);

int
link(const char *existing, const char *new)
{
	int 	sz;
	char 	linkbuf[PATH_MAX + 1];

	/*
	 * XPG4v2 link() requires that the link count of a symbolic
	 * link target be updated rather than the link itself.  This
	 * matches SunOS 4.x and other BSD based implementations.
	 * However, the SVR4 merge apparently introduced the change
	 * that allowed link(src, dest) when "src" was a symbolic link,
	 * to create "dest" as a hard link to "src".  Hence, the link
	 * count of the symbolic link is updated rather than the target
	 * of the symbolic link. This latter behavior remains for
	 * non-XPG4 based environments. For a more detailed discussion,
	 * see bug 1256170.
	 */
	if (__xpg4 != 0) {
		if ((sz = resolvepath(existing, linkbuf, PATH_MAX)) == -1)
			return (-1);
		linkbuf[sz] = '\0';
		existing = linkbuf;
	}
	return (__link(existing, new));
}
