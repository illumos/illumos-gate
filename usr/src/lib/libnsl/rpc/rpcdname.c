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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rpcdname.c
 * Gets the default domain name
 */
#include "mt.h"
#include "rpc_mt.h"
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <syslog.h>

extern int getdomainname();
extern char *strdup();
static char *default_domain = 0;

static char *
get_default_domain(void)
{
	char temp[256];
	extern mutex_t dname_lock;

/* VARIABLES PROTECTED BY dname_lock: default_domain */

	(void) mutex_lock(&dname_lock);
	if (default_domain) {
		(void) mutex_unlock(&dname_lock);
		return (default_domain);
	}
	if (getdomainname(temp, (size_t)sizeof (temp)) < 0) {
		(void) mutex_unlock(&dname_lock);
		return (0);
	}
	if ((int)strlen(temp) > 0) {
		default_domain = strdup(temp);
		if (default_domain == NULL) {
			syslog(LOG_ERR, "get_default_domain : strdup failed.");
			(void) mutex_unlock(&dname_lock);
			return (0);
		}
	}
	(void) mutex_unlock(&dname_lock);
	return (default_domain);
}

/*
 * This is a wrapper for the system call getdomainname which returns a
 * ypclnt.h error code in the failure case.  It also checks to see that
 * the domain name is non-null, knowing that the null string is going to
 * get rejected elsewhere in the yp client package.
 */
int
__rpc_get_default_domain(char **domain)
{
	if ((*domain = get_default_domain()) != 0)
		return (0);
	return (-1);
}
