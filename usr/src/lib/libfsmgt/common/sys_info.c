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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include "libfsmgt.h"

/*
 * Public methods
 */

char *sys_get_hostname(int *errp) {

	char	host[MAXHOSTNAMELEN + 1];
	char	*ret_val;

	*errp = 0;
	if (gethostname(host, sizeof (host)) == -1) {
		*errp = errno;
		return (NULL);
	}

	ret_val = strdup(host);
	if (ret_val == NULL) {
		*errp = errno;
		return (NULL);
	}

	/*
	 * Note: The space allocated for the return value must be freed by the
	 * caller using free().
	 */
	return (ret_val);
} /* sys_get_hostname */
