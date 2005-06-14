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
 * Copyright 1994 - 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef lint
static char id[] = "%W% (Sun) %G%";
#endif /* not lint */

#include "sendmail.h"

extern int getdomainname();

void
init_md_sun()
{
	struct stat sbuf;

	/* Check for large file descriptor */
	if (fstat(fileno(stdin), &sbuf) < 0)
	{
		if (errno == EOVERFLOW)
		{
			perror("stdin");
			exit(EX_NOINPUT);
		}
	}
}


#ifdef SUN_INIT_DOMAIN
/* this is mainly for backward compatibility in Sun environment */
char *
sun_init_domain()
{
	/*
	 * Get the domain name from the kernel.
	 * If it does not start with a leading dot, then remove
	 * the first component.  Since leading dots are funny Unix
	 * files, we treat a leading "+" the same as a leading dot.
	 * Finally, force there to be at least one dot in the domain name
	 * (i.e. top-level domains are not allowed, like "com", must be
	 * something like "sun.com").
	 */
	char buf[MAXNAME];
	char *period, *autodomain;

	if (getdomainname(buf, sizeof buf) < 0)
		return NULL;

	if (strlen(buf) == 0)
		return NULL;

	if (tTd(0, 20))
		printf("domainname = %s\n", buf);

	if (buf[0] == '+')
		buf[0] = '.';
	period = strchr(buf, '.');
	if (period == NULL)
		autodomain = buf;
	else
		autodomain = period+1;
	if (strchr(autodomain, '.') == NULL)
		return newstr(buf);
	else
		return newstr(autodomain);
}
#endif /* SUN_INIT_DOMAIN */
