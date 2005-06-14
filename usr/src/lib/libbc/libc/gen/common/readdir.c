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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include <sys/param.h>
#include <dirent.h>

/*
 * get next entry in a directory.
 */
struct dirent *
readdir(dirp)
	register DIR *dirp;
{
	register struct dirent *dp;
	int saveloc = 0;

next:
        if (dirp->dd_size != 0) {
                dp = (struct dirent *)&dirp->dd_buf[dirp->dd_loc];
                saveloc = dirp->dd_loc;   /* save for possible EOF */
                dirp->dd_loc += dp->d_reclen;
        }
        if (dirp->dd_loc >= dirp->dd_size)
                dirp->dd_loc = dirp->dd_size = 0;

        if (dirp->dd_size == 0  /* refill buffer */
          && (dirp->dd_size = getdents(dirp->dd_fd, dirp->dd_buf, dirp->dd_bsize)
             ) <= 0
           ) {
                if (dirp->dd_size == 0) /* This means EOF */
                        dirp->dd_loc = saveloc;  /* EOF so save for telldir */
                return (NULL);    /* error or EOF */
        }

        dp = (struct dirent *)&dirp->dd_buf[dirp->dd_loc];
	if (dp->d_reclen <= 0)
		return (NULL);
	if (dp->d_fileno == 0)
		goto next;
	dirp->dd_off = dp->d_off;
        return(dp);
}
