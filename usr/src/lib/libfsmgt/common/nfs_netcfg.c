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

#include <errno.h>
#include <netconfig.h>
#include <stdlib.h>
#include <string.h>
#include "libfsmgt.h"

/*
 * Public methods
 */

void
netcfg_free_networkid_list(char **netlist, int num_elements)
{
	fileutil_free_string_array(netlist, num_elements);
} /* netcfg_free_networkid_list */

char **
netcfg_get_networkid_list(int *num_elements, int *errp)
{
	struct netconfig	*nconf;
	NCONF_HANDLE		*nc;
	char			**return_list = NULL;

	/*
	 * setnetconfig must be called before getnetconfig in order to get the
	 * netconfig handle.
	 */
	if ((nc = setnetconfig()) == (NCONF_HANDLE *)NULL) {
		*errp = errno;
		return (NULL);
	}

	*num_elements = 0;
	while (nconf = getnetconfig(nc)) {
		char	**tmp_list;

		/*
		 * Put the elements in the array.
		 */
		tmp_list = realloc(return_list,
			(size_t)(((*num_elements)+1) * sizeof (char *)));
		if (tmp_list == NULL) {
			*errp = errno;
			netcfg_free_networkid_list(return_list, *num_elements);
			*num_elements = 0;
			(void) endnetconfig(nc);
			return (NULL);
		}

		return_list = tmp_list;

		return_list[(*num_elements)] = strdup(nconf->nc_netid);
		if (return_list[(*num_elements)] == NULL) {
			*errp = ENOMEM;
			netcfg_free_networkid_list(return_list, *num_elements);
			*num_elements = 0;
			(void) endnetconfig(nc);
			return (NULL);
		}

		*num_elements = *num_elements + 1;
	}

	(void) endnetconfig(nc);
	/*
	 * Caller must free the space allocated to return_list by calling
	 * netcfg_free_networkid_list.
	 */
	return (return_list);
} /* netcfg_get_networkid_list */
