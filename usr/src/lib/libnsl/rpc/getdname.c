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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * Gets and sets the domain name of the system
 */

#include <sys/systeminfo.h>

int
getdomainname(char *name, int namelen)
{
	int sysinfostatus;

	sysinfostatus = sysinfo(SI_SRPC_DOMAIN, name, namelen);

	return ((sysinfostatus < 0) ? -1 : 0);
}

int
setdomainname(char *domain, int len)
{
	int sysinfostatus;

	sysinfostatus = sysinfo(SI_SET_SRPC_DOMAIN,
	    domain, len + 1); /* add null */
	return ((sysinfostatus < 0) ? -1 : 0);
}
