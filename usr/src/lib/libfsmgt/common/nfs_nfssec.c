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
#include <sys/types.h>
#include <nfs/nfs_sec.h>
#include <strings.h>
#include "libfsmgt.h"

/*
 * Public methods
 */

/*
 * Method: nfssec_free_secmode_list
 *
 * Description: Frees the space allocated for the security mode list array.
 *
 * Parameters:
 *	- char **seclist - the array to be freed.
 *	- int num_elements - the number of elements in the array.
 *
 * Returns:
 *	- Nothing
 */
void
nfssec_free_secmode_list(char **seclist, int num_elements)
{
	fileutil_free_string_array(seclist, num_elements);
} /* nfssec_free_secmode_list */

/*
 * Method: nfssec_get_default_secmode
 *
 * Description: Retrieves the default security mode for NFS.
 *
 * Parameters:
 *	- int *errp - the error indicator.  This will be set to a non-zero
 *	value upon error.
 *
 * Returns:
 *	- char * - the NFS security mode name.
 *	- NULL if an error occurred.
 *
 * Note: Caller must free the space allocated for the return value.
 */
char *
nfssec_get_default_secmode(int *errp)
{
	seconfig_t	secp, defsecp;
	char		*ret_val;
	int		err = 0;

	*errp = 0;
	err = nfs_getseconfig_default(&secp);
	if (err != 0) {
		*errp = err;
		return (NULL);
	}

	err = nfs_getseconfig_bynumber(secp.sc_nfsnum, &defsecp);
	if (err != 0) {
		*errp = err;
		return (NULL);
	}

	ret_val = strdup(defsecp.sc_name);
	if (ret_val == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	return (ret_val);
} /* nfssec_get_default_secmode */

/*
 * Method: nfssec_get_nfs_secmode_list
 *
 * Description: Retrieves a list of the supported NFS security modes from
 * /etc/nfssec.conf.
 *
 * Parameters:
 *	- int *num_elements - integer pointer used to keep track of the number
 *	of elements in the array.
 *	- int *errp - the error indicator.  This will be set to a non-zero
 *	value upon error.
 *
 * Returns:
 *	- char ** - The array containing the supported security mode names as
 *	elements.
 *	- NULL if an error occurred.
 *
 * Note: The space allocated for the return array must be freed by the caller
 * using nfssec_free_secmode_list.
 */
char **
nfssec_get_nfs_secmode_list(int *num_elements, int *errp)
{
	FILE	*fp;
	char	**seclist = NULL;
	int	err = 0;

	*errp = 0;
	if ((fp = fopen(NFSSEC_CONF, "r")) == NULL) {
		/*
		 * The opening of nfssec.conf failed.
		 */
		*errp = errno;
		return (NULL);
	}

	seclist = fileutil_get_first_column_data(fp, num_elements, &err);
	(void) fclose(fp);
	if (seclist == NULL) {
		*errp = err;
		return (NULL);
	}

	return (seclist);
} /* nfssec_get_nfs_secmode_list */
