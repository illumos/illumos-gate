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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*LINTLIBRARY*/
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

/*
 *	This function returns the identifier of the filesystem that
 *	the path arguement resides on.  If any errors occur, it
 *	return s5 as a default.
 */

#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>

static char fs_buf[FSTYPSZ];
static char fs_default[]="s5";

char *
path_to_fstype(path)
char *path;
{
	struct statfs stat_buf;

	if ( statfs(path,&stat_buf,sizeof(struct statfs),0) ) {
		return(fs_default);
	}

	if ( sysfs(GETFSTYP,stat_buf.f_fstyp,fs_buf) ) {
		return(fs_default);
	}

	return(fs_buf);
}
