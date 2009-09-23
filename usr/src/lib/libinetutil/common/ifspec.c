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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains a routine used to validate a ifconfig-style interface
 * specification
 */

#include <stdlib.h>
#include <ctype.h>
#include <alloca.h>
#include <errno.h>
#include <string.h>
#include <libinetutil.h>

/*
 * Given a token with a logical unit spec, return the logical unit converted
 * to a uint_t.
 *
 * Returns: 0 for success, nonzero if an error occurred. errno is set if
 * necessary.
 */
static int
getlun(const char *bp, int bpsize, uint_t *lun)
{
	char	*ep = (char *)&bp[bpsize - 1];
	char	*sp = strchr(bp, ':'), *tp;

	/* A logical unit spec looks like: <token>:<unsigned int>\0 */
	if (isdigit(*bp) || !isdigit(*ep) || sp == NULL ||
	    strchr(sp + 1, ':') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	*sp++ = '\0';

	/* Lun must be all digits */
	for (tp = sp; tp < ep && isdigit(*tp); tp++)
		/* Null body */;
	if (tp != ep) {
		errno = EINVAL;
		return (-1);
	}

	*lun = atoi(sp);
	return (0);
}

/*
 * Given a single token ending with a ppa spec, return the ppa spec converted
 * to a uint_t.
 *
 * Returns: 0 for success, nonzero if an error occurred. errno is set if
 * necessary.
 */
static int
getppa(const char *bp, int bpsize, uint_t *ppa)
{
	char	*ep = (char *)&bp[bpsize - 1];
	char	*tp;

	if (!isdigit(*ep)) {
		errno = EINVAL;
		return (-1);
	}

	for (tp = ep; tp >= bp && isdigit(*tp); tp--)
		/* Null body */;

	if (*tp == ':') {
		errno = EINVAL;
		return (-1);
	}

	*ppa = atoi(tp + 1);
	return (0);
}

/*
 * Given an ifconfig-style inet relative-path interface specification
 * (e.g: bge0:2), validate its form and decompose the contents into a
 * dynamically allocated ifspec_t.
 *
 * Returns ifspec_t for success, NULL pointer if spec is malformed.
 */
boolean_t
ifparse_ifspec(const char *ifname, ifspec_t *ifsp)
{
	char	*lp, *tp;
	char	ifnamecp[LIFNAMSIZ];

	/* snag a copy we can modify */
	if (strlcpy(ifnamecp, ifname, LIFNAMSIZ) >= LIFNAMSIZ) {
		errno = EINVAL;
		return (B_FALSE);
	}

	ifsp->ifsp_lunvalid = B_FALSE;

	/*
	 * An interface name must have the format of:
	 * dev[ppa][:lun]
	 *
	 * lun - logical unit number.
	 */

	/* Any logical units? */
	lp = strchr(ifnamecp, ':');
	if (lp != NULL) {
		if (getlun(lp, strlen(lp), &ifsp->ifsp_lun) != 0)
			return (B_FALSE);
		ifsp->ifsp_lunvalid = B_TRUE;
	}

	(void) strlcpy(ifsp->ifsp_devnm, ifnamecp, LIFNAMSIZ);

	/* Find ppa  */
	if (getppa(ifsp->ifsp_devnm, strlen(ifsp->ifsp_devnm),
	    &ifsp->ifsp_ppa) != 0) {
		return (B_FALSE);
	}

	/* strip the ppa off of the device name if present */
	for (tp = &ifsp->ifsp_devnm[strlen(ifsp->ifsp_devnm) - 1];
	    tp >= ifsp->ifsp_devnm && isdigit(*tp); tp--) {
		*tp = '\0';
	}

	return (B_TRUE);
}
