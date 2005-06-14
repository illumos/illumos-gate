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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * m_pathmax: mks specific library routine.
 *
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_pathma.c 1.4 1992/06/19 17:28:24 gord Exp $";
#endif
#endif /* M_RCSID */

#include <mks.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#ifdef m_pathmax	
#undef m_pathmax	 /* in case its #define'd in mks.h */
#endif

/*f
 * m_pathmax()
 *  - Determine current configuration value for PC_PATH_MAX
 *    relative to 'path'.
 *  - If 'path' is NULL, then relative to "/"
 *  - Return:
 *      configuration value
 *      or M_PATH_MAX if configuration value is indeterminate
 *      or -1 and errno is set if there's a problem with 'path'
 */
int
m_pathmax(path)
char* path;
{
        int x;

        if (path == NULL)
                path = "/";

        errno = 0;
        x = pathconf(path, _PC_PATH_MAX);
        if (x == -1) {
                if (errno == 0) {
			/*
                         * unlimited size - so we use M_PATH_MAX
			 *
                         * M_PATH_MAX defined in mkslocal.h
                         * - use a sufficiently LARGE number (e.g 1024 or 2048)
                         */
			if (M_PATH_MAX < _POSIX_PATH_MAX) {
				printf("m_pathmax(): Assert failure: ");
				printf("M_PATH_MAX < _POSIX_PATH_MAX\n");
				(void) exit(126);
			}
                        return M_PATH_MAX;
                } else {
                        /* ASSUME: cannot get errno = EINVAL because PC_PATH_MAX                         *         must be supported, and must
                         *         be associated with all *valid* 'path's
                         *         (if 'path' is not valid, then we
			 *          should get ENOENT or ENOTDIR,
			 *          not EINVAL)
                         */
                        if (errno == EINVAL) {
				printf("m_pathmax(): Assert failure: ");
				printf("pathconf() = -1 and errno = EINVAL\n");
				(void) exit(126);
			}
                        return -1;
                }
        }

        return x;
}

#ifdef TEST
/* 
 * compile with 
 *      "make m_pathma COPTS=TEST"  - using MKS make and MKS environment
 * or
 *       "cc -o m_pathma -DTEST m_pathma.c"   - to get sunos std libraries
 *  
 */
main(argc, argv)
int argc;
char ** argv;
{
    if (argc > 1) {
	    int x;
	    x = m_pathmax(argv[1]);
	    printf("m_pathmax('%s') returns %d\n", argv[1], x );
	    if (x == -1)
#ifdef __STDC__
	       printf("errno = %d (%s)\n", errno, strerror(errno));
#else
	       printf("errno = %d \n", errno);
#endif
    } else
         printf("usage: %s filename\n", argv[0]);

}
#endif /* TEST */
