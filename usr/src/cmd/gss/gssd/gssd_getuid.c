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
 * Copyright (c) 1995,1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Routines to set gssd value of uid and replace getuid libsys call.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>

uid_t gssd_uid;

void
set_gssd_uid(uid)
	uid_t	uid;
{

	/*
	 * set the value of gssd_uid, so it can be retrieved when getuid()
	 * is called by the underlying mechanism libraries
	 */
	printf(gettext("set_gssd_uid called with uid = %d\n"), uid);
	gssd_uid = uid;
}

uid_t
getuid(void)

{

	/*
	 * return the value set when one of the gssd procedures was
	 * entered. This is the value of the uid under which the
	 * underlying mechanism library must operate in order to
	 * get the user's credentials. This call is necessary since
	 * gssd runs as root and credentials are many times stored
	 * in files and directories specific to the user
	 */
	printf(gettext(
		"getuid called and returning gsssd_uid = %d\n"), gssd_uid);
	return (gssd_uid);
}
