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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/isa_defs.h>
#include <sys/utsname.h>
#include <strings.h>

static const char _mdb_version[] = "mdb 1.1";

const char *
mdb_conf_version(void)
{
	return (_mdb_version);
}

const char *
mdb_conf_platform(void)
{
	static char platbuf[MAXNAMELEN];

	if (sysinfo(SI_PLATFORM, platbuf, MAXNAMELEN) != -1)
		return (platbuf);

	return ("unknown");
}

const char *
mdb_conf_isa(void)
{
#if defined(__sparc)
#if defined(__sparcv9)
	return ("sparcv9");
#else	/* __sparcv9 */
	return ("sparc");
#endif	/* __sparcv9 */
#elif defined(__amd64)
	return ("amd64");
#elif defined(__i386)
	return ("i386");
#else
#error	"unknown ISA"
#endif
}

void
mdb_conf_uname(struct utsname *utsp)
{
	bzero(utsp, sizeof (struct utsname));
	(void) uname(utsp);
}
