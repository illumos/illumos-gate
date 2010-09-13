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


#include <sun_sas.h>

/*
 * Loads the HBA Library.  Must be called before calling any HBA library
 * functions
 *
 * Return values:
 *	HBA_STATUS_OK	    library properly loaded
 *	HBA_STATUS_ERROR    library loaded incorrectly
 */
int	loadCount = 0;
HBA_STATUS Sun_sasLoadLibrary() {
	const char	ROUTINE[] = "Sun_sasLoadLibrary";
	di_node_t	root;
	boolean_t	atLeastOneHBA = B_FALSE;
	boolean_t	atLeastOneFailure = B_FALSE;
	hrtime_t	    start = 0;
	hrtime_t	    end = 0;
	double		    duration = 0;

	/* Make sure that library has not been already loaded */
	if (loadCount++ > 0) {
		log(LOG_DEBUG, ROUTINE, "Library already loaded %d time."
		    " Ignoring.", loadCount);
		return (HBA_STATUS_ERROR);
	}
	hba_count = 0;
	open_handle_index = 1;
	/* Initialize the read-write lock */
	if (mutex_init(&all_hbas_lock, USYNC_THREAD, NULL)) {
	    log(LOG_DEBUG, ROUTINE,
		"Unable to initialize lock in LoadLibrary for reason \"%s\"",
		strerror(errno));
	    return (HBA_STATUS_ERROR);
	}
	/* grab write lock */
	lock(&all_hbas_lock);

	start = gethrtime();
	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
	    log(LOG_DEBUG, ROUTINE,
		"Unable to load device tree for reason \"%s\"",
		strerror(errno));
	    unlock(&all_hbas_lock);
	    return (HBA_STATUS_ERROR);
	}
	end = gethrtime();
	duration = end - start;
	duration /= HR_SECOND;
	log(LOG_DEBUG, ROUTINE, "Loading device tree init took "
	    "%.6f seconds", duration);

	/* At load time, we only gather libdevinfo information */
	if (devtree_get_all_hbas(root) == HBA_STATUS_OK) {
	    atLeastOneHBA = B_TRUE;
	} else {
	    atLeastOneFailure = B_TRUE;
	}

	di_fini(root);

	unlock(&all_hbas_lock);

	/* Now determine what status code to return */
	if (atLeastOneHBA) {
	    /* We've got at least one HBA and possibly some failures */
	    return (HBA_STATUS_OK);
	} else if (atLeastOneFailure) {
	    /* We have no HBAs but have failures */
	    return (HBA_STATUS_ERROR);
	} else {
	    /* We have no HBAs and no failures */
	    return (HBA_STATUS_OK);
	}
}
