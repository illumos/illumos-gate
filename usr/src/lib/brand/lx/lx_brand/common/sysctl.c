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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <alloca.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/lx_syscall.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>

/*
 * sysctl() implementation.  The full set of possible values is incredibly
 * large; we only implement the bare minimum here, namely basic kernel
 * information.
 *
 * For the moment, we also print out debugging messages if the application
 * attempts to write or access any other values, so we can tell if we are not
 * supporting something we should be.
 */

struct lx_sysctl_args {
	int *name;
	int nlen;
	void *oldval;
	size_t *oldlenp;
	void *newval;
	size_t newlen;
};

#define	LX_CTL_KERN		1

#define	LX_KERN_OSTYPE		1
#define	LX_KERN_OSRELEASE	2
#define	LX_KERN_OSREV		3
#define	LX_KERN_VERSION		4

long
lx_sysctl(uintptr_t raw)
{
	struct lx_sysctl_args args;
	int name[2];
	size_t oldlen;
	char *namebuf;

	if (uucopy((void *)raw, &args, sizeof (args)) < 0)
		return (-EFAULT);

	/*
	 * We only allow [ CTL_KERN, KERN_* ] pairs, so reject anything that
	 * doesn't have exactly two values starting with LX_CTL_KERN.
	 */
	if (args.nlen != 2)
		return (-ENOTDIR);

	if (uucopy(args.name, name, sizeof (name)) < 0)
		return (-EFAULT);

	if (name[0] != LX_CTL_KERN) {
		lx_debug("sysctl: read of [%d, %d] unsupported",
		    name[0], name[1]);
		return (-ENOTDIR);
	}

	/* We don't support writing new sysctl values. */
	if ((args.newval != NULL) || (args.newlen != 0)) {
		lx_debug("sysctl: write of [%d, %d] unsupported",
		    name[0], name[1]);
		return (-EPERM);
	}

	/*
	 * It may seem silly, but passing in a NULL oldval pointer and not
	 * writing any new values is a perfectly legal thing to do and should
	 * succeed.
	 */
	if (args.oldval == NULL)
		return (0);

	/*
	 * Likewise, Linux specifies that setting a non-NULL oldval but a
	 * zero *oldlenp should result in an errno of EFAULT.
	 */
	if ((uucopy(args.oldlenp, &oldlen, sizeof (oldlen)) < 0) ||
	    (oldlen == 0))
		return (-EFAULT);

	namebuf = SAFE_ALLOCA(oldlen);
	if (namebuf == NULL)
		return (-ENOMEM);

	switch (name[1]) {
	case LX_KERN_OSTYPE:
		(void) strlcpy(namebuf, LX_UNAME_SYSNAME, oldlen);
		break;
	case LX_KERN_OSRELEASE:
		(void) strlcpy(namebuf, lx_release, oldlen);
		break;
	case LX_KERN_VERSION:
		(void) strlcpy(namebuf, LX_UNAME_VERSION, oldlen);
		break;
	default:
		lx_debug("sysctl: read of [CTL_KERN, %d] unsupported", name[1]);
		return (-ENOTDIR);
	}

	oldlen = strlen(namebuf);

	if ((uucopy(namebuf, args.oldval, oldlen) < 0) ||
	    (uucopy(&oldlen, args.oldlenp, sizeof (oldlen)) < 0))
		return (-EFAULT);

	return (0);
}
