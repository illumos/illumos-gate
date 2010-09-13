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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains public API functions for module-level tasks.  For the
 * semantics of these functions, please see the Enterprise DHCP
 * Architecture Document.
 *
 * WARNING: This file is also compiled into the files0 module; if you make
 *	    changes to this file which are not appropriate for files0, you
 *	    will need to provide files0 with its own implementation.
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libgen.h>
#include <errno.h>
#include <dhcp_svc_public.h>
#include <dhcp_svc_private.h>		/* DSVC_SYNCH_CROSSHOST */

#include "util.h"

/*
 * This symbol and its value tell the private layer that it must provide
 * synchronization guarantees via dsvclockd(1M) before calling our *_dn()
 * and *_dt() methods.  Please see $SRC/lib/libdhcpsvc/private/README.synch
 */
int dsvc_synchtype = DSVC_SYNCH_DSVCD | DSVC_SYNCH_CROSSHOST;

int
status(const char *location)
{
	if (location != NULL) {
		if (access(location, F_OK|R_OK) == -1) {
			if (errno == ENOENT)
				return (DSVC_NO_LOCATION);
			return (syserr_to_dsvcerr(errno));
		}
	}
	return (DSVC_SUCCESS);
}

int
version(int *vp)
{
	*vp = DSVC_PUBLIC_VERSION;
	return (DSVC_SUCCESS);
}

int
mklocation(const char *location)
{
	if (mkdirp(location, 0755) == -1) {
		switch (errno) {
		case ENAMETOOLONG:
		case ENOTDIR:
			return (DSVC_INVAL);

		case EEXIST:
			return (DSVC_EXISTS);

		case EROFS:
		case EPERM:
		case EACCES:
			return (DSVC_ACCESS);

		default:
			return (DSVC_INTERNAL);
		}
	}

	return (DSVC_SUCCESS);
}

int
mkloctoken(const char *location, char *token, size_t tokensize)
{
	assert(tokensize >= MAXPATHLEN);
	if (realpath(location, token) == NULL)
		return (syserr_to_dsvcerr(errno));

	return (DSVC_SUCCESS);
}
