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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

static uid_t krb5_cc_uid;

void
set_gssd_uid(uid_t uid)
{
	/*
	 * set the value of krb5_cc_uid, so it can be retrieved when
	 * app_krb5_user_uid() is called by the underlying mechanism libraries.
	 */
	printf(gettext("set_gssd_uid called with uid = %d\n"), uid);
	krb5_cc_uid = uid;
}

uid_t
app_krb5_user_uid(void)
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
		"getuid called and returning gsssd_uid = %d\n"), krb5_cc_uid);
	return (krb5_cc_uid);
}
