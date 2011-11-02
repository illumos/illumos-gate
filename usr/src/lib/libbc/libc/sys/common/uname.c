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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<errno.h>
#include	<string.h>
#include	<sys/utsname.h>
#include	<sys/syscall.h>

/*
 * utsname structure has a different format in SVr4/SunOS 5.0.
 * The data needs to be mapped before returning to the user.
 */

/*
 * The following values and structure are from the SVR4 utsname.h.
 */
#define		NEW_SYS_NMLN	257
#define		SYS_NMLN	9
#define		SYS_NDLN	65

struct n_utsname {
	char sysname[NEW_SYS_NMLN];
	char nodename[NEW_SYS_NMLN];
	char release[NEW_SYS_NMLN];
	char version[NEW_SYS_NMLN];
	char machine[NEW_SYS_NMLN];
};

int
uname(struct utsname *uts)
{
	return (bc_uname(uts));
}

int
bc_uname(struct utsname *uts)
{
	struct n_utsname n_uts;
	int    ret;

	if ((ret = _syscall(SYS_uname, &n_uts)) != -1) {
		memcpy(uts->sysname, n_uts.sysname, SYS_NMLN);
		if (strlen(n_uts.sysname) > SYS_NMLN)
			uts->sysname[SYS_NMLN-1] = '\0';

		memcpy(uts->nodename, n_uts.nodename, SYS_NMLN);
		memcpy(uts->nodeext, n_uts.nodename + SYS_NMLN,
		    SYS_NDLN - SYS_NMLN);
		if (strlen(n_uts.nodename + SYS_NMLN) > SYS_NDLN - SYS_NMLN)
			uts->nodeext[SYS_NDLN - SYS_NMLN - 1] = '\0';

		memcpy(uts->release, n_uts.release, SYS_NMLN);
		if (strlen(n_uts.release) > SYS_NMLN)
			uts->release[SYS_NMLN-1] = '\0';
		memcpy(uts->version, n_uts.version, SYS_NMLN);
		if (strlen(n_uts.version) > SYS_NMLN)
			uts->version[SYS_NMLN-1] = '\0';
		memcpy(uts->machine, n_uts.machine, SYS_NMLN);
		if (strlen(n_uts.machine) > SYS_NMLN)
			uts->machine[SYS_NMLN-1] = '\0';
	}

	return (ret);
}
