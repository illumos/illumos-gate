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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ns_sldap.h"
#include "ns_internal.h"
#include <syslog.h>

#pragma init(ns_ldap_init)

thread_key_t ns_mtckey;

static void
ns_ldap_init()
{
	get_environment();	/* load environment debugging options */

	/*
	 * ns_mtckey is needed to allow the sharing of an
	 * ldap connection among multiple threads. Used
	 * mainly in ns_connect.c.
	 */
	if (thr_keycreate(&ns_mtckey, ns_tsd_cleanup) != 0) {
		syslog(LOG_ERR, "libsldap: unable to create the thread "
		"key needed for sharing ldap connections");
		MTperConn = 0;
	}
}
