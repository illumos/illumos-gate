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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libmail.h"
#include <sys/types.h>
#include <ctype.h>
#ifdef SVR4
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#endif

#define	NMLN 512
#ifdef SVR4
#if SYS_NMLN > NMLN
#undef NMLN
#define	NMLN SYS_NMLN
#endif
#endif

static char *look4domain(char *, char *, int);
static char *readdomain(char *, int);

/*
 *  NAME
 *	maildomain() - retrieve the domain name
 *
 *  SYNOPSIS
 *	char *maildomain()
 *
 *  DESCRIPTION
 *	Retrieve the domain name from xgetenv("DOMAIN").
 *	If that is not set, look in /etc/resolv.conf, /etc/inet/named.boot
 *	and /etc/named.boot for "^domain[ ]+<domain>".
 *	If that is not set, use sysinfo(SI_SRPC_DOMAIN) from
 *	-lnsl. Otherwise, return an empty string.
 */

/* read a file for the domain */
static char *look4domain(char *file, char *buf, int size)
{
	char *ret = 0;
	FILE *fp = fopen(file, "r");

	if (!fp)
		return (0);

	while (fgets(buf, size, fp))
		if (strncmp(buf, "domain", 6) == 0)
	if (isspace(buf[6])) {
		char *x = skipspace(buf + 6);
		if (isgraph(*x)) {
			trimnl(x);
			strmove(buf, x);
			ret = buf;
			break;
		}
	}

	(void) fclose(fp);
	return (ret);
}

/* read the domain from the xenvironment or one of the files */
static char *readdomain(char *buf, int size)
{
	char *ret;

	if ((ret = xgetenv("DOMAIN")) != 0) {
		(void) strncpy(buf, ret, size);
		return (buf);
	}

	if (((ret = look4domain("/etc/resolv.conf", buf, size)) != 0) ||
	    ((ret = look4domain("/etc/inet/named.boot", buf, size)) != 0) ||
	    ((ret = look4domain("/etc/named.boot", buf, size)) != 0))
		return (ret);

#ifdef SVR4
	if (sysinfo(SI_SRPC_DOMAIN, buf, size) >= 0)
		return (buf);
#endif

	return (0);
}

char *
maildomain(void)
{
	static char *domain = 0;
	static char dombuf[NMLN+1] = ".";

	/* if we've already been here, return the info */
	if (domain != 0)
		return (domain);

	domain = readdomain(dombuf+1, NMLN);

	/* Make certain that the domain begins with a single dot */
	/* and does not have one at the end. */
	if (domain) {
		size_t len;
		domain = dombuf;
		while (*domain && *domain == '.')
			domain++;
		domain--;
		len = strlen(domain);
		while ((len > 0) && (domain[len-1] == '.'))
			domain[--len] = '\0';
	}
	/* no domain information */
	else
		domain = "";

	return (domain);
}
