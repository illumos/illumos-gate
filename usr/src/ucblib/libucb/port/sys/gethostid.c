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
#include <stdlib.h>

#define	HOSTIDLEN	40

long
gethostid(void)
{
	char	name[HOSTIDLEN], *end;
	unsigned long	hostid;
	int	error;

	error = sysinfo(SI_HW_SERIAL, name, HOSTIDLEN);
	/*
	 * error > 0 ==> number of bytes to hold name
	 * and is discarded since gethostid only
	 * cares if it succeeded or failed
	 */
	if (error == -1)
		return (-1);
	else {
		hostid = strtoul(name, &end, 10);
		if (hostid == 0 && end == name) {
			return (-1);
		}
		return ((long) hostid);
	}
}
