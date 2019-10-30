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
 * Copyright 2019 Joyent, Inc.
 */

#include    <sun_sas.h>

/*
 * Opens a named adapter.
 * By opening an adapter, an upper level application is ensuring that all access
 * to an HBA_HANDLE between and open and a close is to the same adapter.
 *
 * Sun_sasOpenAdapter just creates a new handle and returns the handle.
 * It does not do a driver open
 */
HBA_HANDLE Sun_sasOpenAdapter(char *name) {
	const char		ROUTINE[] = "Sun_sasOpenAdapter";
	struct sun_sas_hba	*hba_ptr;

	if (name == NULL) {
	    log(LOG_DEBUG, ROUTINE, "NULL adapter name.");
	    return (HANDLE_ERROR);
	}
	lock(&all_hbas_lock);
	for (hba_ptr = global_hba_head; hba_ptr != NULL;
		hba_ptr = hba_ptr->next) {
	    if (strcmp(hba_ptr->handle_name, name) == 0) {
		    break;
	    }
	}
	unlock(&all_hbas_lock);
	if (hba_ptr == NULL) {
	    log(LOG_DEBUG, ROUTINE, "Invalid adapter name \"%s\"", name);
	    return (HANDLE_ERROR);
	}

	return (CreateHandle(hba_ptr->index));
}
