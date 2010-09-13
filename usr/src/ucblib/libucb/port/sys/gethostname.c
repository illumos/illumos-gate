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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <unistd.h>
#include <errno.h>

int
gethostname(char *name, int namelen)
{
	int	error;

	error = sysinfo(SI_HOSTNAME, name, namelen);
	/*
	 * error > 0 ==> number of bytes to hold name
	 * and is discarded since gethostname only
	 * cares if it succeeded or failed
	 */
	return (error == -1 ? -1 : 0);
}

int
sethostname(char *name, int namelen)
{
	int	error;

	/*
	 * Check if superuser
	 */
	if (getuid()) {
		errno = EPERM;
		return (-1);
	}
	error = sysinfo(SI_SET_HOSTNAME, name, namelen);
	return (error == -1 ? -1 : 0);
}
