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

#include    <sun_sas.h>

/*
 * Closes an adapter
 *
 * the handle is removed from the open_handles list
 */
void
Sun_sasCloseAdapter(HBA_HANDLE handle)
{
	const char			ROUTINE[] = "Sun_sasCloseAdapter";
	struct open_handle		*open_handle_ptr, *open_handle_prev_ptr;
	int				found = 0;

	if (global_hba_head == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Attempted to close an invalid handle %08lx. "
		    "There are no hba handles loaded in the VSL.",
		    handle);
		return;
	}

	/* Removing handle from open_handles; */
	lock(&open_handles_lock);
	if (global_hba_head->open_handles == NULL) {
		/* check to see if there are any open global_hba_head */
		log(LOG_DEBUG, ROUTINE,
		    "Attempted to close an invalid handle %08lx. "
		    "There are no open handles in the VSL.",
		    handle);
	} else if (global_hba_head->open_handles->next == NULL) {
		/* there is only one handle open */
		if (global_hba_head->open_handles->handle == handle) {
			free(global_hba_head->open_handles);
			global_hba_head->open_handles = NULL;
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "Attempted to close an invalid handle %08lx. "
			    "Unable to find handle to close.", handle);
		}
	} else {	/* there is more than one handle open */
		open_handle_ptr = global_hba_head->open_handles;
		if (open_handle_ptr->handle == handle) {
			global_hba_head->open_handles = open_handle_ptr->next;
			free(open_handle_ptr);
		} else {
			for (open_handle_ptr = open_handle_ptr->next,
			    open_handle_prev_ptr =
			    global_hba_head->open_handles;
			    open_handle_ptr != NULL;
			    open_handle_ptr = open_handle_ptr->next) {
				if (open_handle_ptr->handle == handle) {
					open_handle_prev_ptr->next =
					    open_handle_ptr->next;
					free(open_handle_ptr);
					found = 1;
					break;
				} else {
					open_handle_prev_ptr =
					    open_handle_prev_ptr->next;
				}
			}
			if (found == 0) {
				log(LOG_DEBUG, ROUTINE,
				    "Attempted to close an invalid handle "
				    "%08lx.  Unable to find handle to close.",
				    handle);
			}
		}
	}

	unlock(&open_handles_lock);
}
