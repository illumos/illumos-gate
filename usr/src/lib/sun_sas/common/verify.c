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
#include <signal.h>

/*
 * Verify that a given adapter is present on the system.
 * No checks will be performed on the targets, and it is assumed
 * that an adapter can't change the number of ports it has.
 */
HBA_STATUS
verifyAdapter(struct sun_sas_hba *hba_ptr) {
	const char	    ROUTINE[] = "verifyAdapter";
	char		    *charptr, path[MAXPATHLEN+1];
	di_node_t	    node;
	uint_t		    state;

	/*
	 * valid test for a removed HBA.
	 */
	if (hba_ptr == NULL) {
	    log(LOG_DEBUG, ROUTINE, "Null hba_ptr argument");
	    return (HBA_STATUS_ERROR);
	}
	(void) strlcpy(path, hba_ptr->device_path, sizeof (path));

	charptr = strrchr(path, ':');
	if (charptr) {
	    *charptr = '\0';
	}

	errno = 0;

	node = di_init(path, DINFOCPYALL);
	if (node == DI_NODE_NIL) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to take devinfo snapshot on HBA \"%s\" due to %s",
		    path, strerror(errno));
		return (HBA_STATUS_ERROR);
	} else {
		state = di_state(node);
		if (((state & DI_DRIVER_DETACHED) == DI_DRIVER_DETACHED) ||
		    ((state & DI_BUS_DOWN) == DI_BUS_DOWN) ||
		    ((state & DI_BUS_QUIESCED) == DI_BUS_QUIESCED)) {
			di_fini(node);
			log(LOG_DEBUG, ROUTINE,
			    "devinfo node is not online state: %d", state);
			return (HBA_STATUS_ERROR);
		}
	}

	di_fini(node);

	return (HBA_STATUS_OK);
}
