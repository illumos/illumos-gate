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

#include	<sys/types.h>
#include	<unistd.h>
#include	<dlfcn.h>
#include	"k5-int.h"

#define		KRB5_UID	"app_krb5_user_uid"

/*
 * mech_krb5 makes various calls to getuid().  When employed by gssd(8) and
 * ktkt_warnd(8), app_krb5_user_uid() is used to select a given user's
 * credential cache, rather than the id of the process.
 */
uid_t
krb5_getuid()
{
	static uid_t	(*gptr)() = NULL;
	void		*handle;

	if (gptr == NULL) {
		/*
		 * Specifically look for app_krb5_user_uid() in the application,
		 * and don't fall into an exhaustive search through all of the
		 * process dependencies.  This interface is suplied from
		 * gssd(8) and ktkt_warnd(8).
		 */
		if (((handle = dlopen(0, (RTLD_LAZY | RTLD_FIRST))) == NULL) ||
		    ((gptr = (uid_t (*)())dlsym(handle, KRB5_UID)) == NULL)) {
			/*
			 * Fall back to the default getuid(), which is probably
			 * libc.
			 */
			gptr = &getuid;
		}
	}

	/*
	 * Return the appropriate uid.  Note, if a default getuid() couldn't
	 * be found, the getuid assignment would have failed to relocate, and
	 * hence this module would fail to load.
	 */
	return ((*gptr)());
}
