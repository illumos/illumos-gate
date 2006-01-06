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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Gets and sets the domain name of the system
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/time.h>
#include <syslog.h>

#ifndef SI_SRPC_DOMAIN
#define	use_file
#endif

#ifdef use_file
char DOMAIN[] = "/etc/domain";
#endif

int setdomainname();

#ifdef use_file
static char *domainname;
#endif

extern mutex_t	dname_lock;

int
getdomainname(name, namelen)
	char *name;
	int namelen;
{
#ifdef use_file
	FILE *domain_fd;
	char *line;

	(void) mutex_lock(&dname_lock);
	if (domainname) {
		(void) strncpy(name, domainname, namelen);
		(void) mutex_unlock(&dname_lock);
		return (0);
	}

	domainname = calloc(1, 256);
	if (domainname == NULL) {
		syslog(LOG_ERR, "getdomainname : out of memory.");
		(void) mutex_unlock(&dname_lock);
		return (-1);
	}

	if ((domain_fd = fopen(DOMAIN, "r")) == NULL) {

		(void) mutex_unlock(&dname_lock);
		return (-1);
	}
	if (fscanf(domain_fd, "%s", domainname) == NULL) {
		(void) fclose(domain_fd);
		(void) mutex_unlock(&dname_lock);
		return (-1);
	}
	(void) fclose(domain_fd);
	(void) strncpy(name, domainname, namelen);
	(void) mutex_unlock(&dname_lock);
	return (0);
#else
	int sysinfostatus;

	sysinfostatus = sysinfo(SI_SRPC_DOMAIN, name, namelen);

	return ((sysinfostatus < 0) ? -1 : 0);
#endif
}

int
setdomainname(domain, len)
	char *domain;
	int len;
{
#ifdef use_file

	FILE *domain_fd;

	(void) mutex_lock(&dname_lock);
	if (domainname)
		free(domainname);

	if ((domain_fd = fopen(DOMAIN, "w")) == NULL) {
		(void) mutex_unlock(&dname_lock);
		return (-1);
	}
	if (fputs(domain, domain_fd) == NULL) {
		(void) mutex_unlock(&dname_lock);
		return (-1);
	}
	(void) fclose(domain_fd);
	domainname = calloc(1, 256);
	if (domainname == NULL) {
		syslog(LOG_ERR, "setdomainname : out of memory.");
		(void) mutex_unlock(&dname_lock);
		return (-1);
	}
	(void) strncpy(domainname, domain, len);
	(void) mutex_unlock(&dname_lock);
	return (0);
#else
	int sysinfostatus;

	sysinfostatus = sysinfo(SI_SET_SRPC_DOMAIN,
				domain, len + 1); /* add null */
	return ((sysinfostatus < 0) ? -1 : 0);
#endif
}
