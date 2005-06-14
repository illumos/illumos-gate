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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

# include	<unistd.h>
# include	<string.h>
# include	<stropts.h>
# include	<errno.h>
# include	<stdlib.h>

# include	"lp.h"
# include	"msgs.h"

#if	defined(__STDC__)
MESG * mcreate ( char * path )
#else
MESG * mcreate (path)
    char	*path;
#endif
{
    int			fds[2];
    MESG		*md;

    if (pipe(fds) != 0)
	return(NULL);

#if	!defined(NOCONNLD)
    if (ioctl(fds[1], I_PUSH, "connld") != 0)
	return(NULL);
#endif

    if (fattach(fds[1], path) != 0)
        return(NULL);

    if ((md = (MESG *)Malloc(MDSIZE)) == NULL)
	return(NULL);
    
    memset(md, 0, sizeof (MESG));
    md->admin = 1;
    md->file = Strdup(path);
    md->gid = getgid();
    md->readfd = fds[0];
    md->state = MDS_IDLE;
    md->type = MD_MASTER;
    md->uid = getuid();
#if 1
    md->writefd = fds[1];
#else
    md->writefd = fds[0];
    close(fds[1]);
#endif
    
    return(md);
}
