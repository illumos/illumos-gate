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
 *
 * iSCSI session interfaces
 */

#include "iscsi.h"		/* main header */
#include <sys/scsi/adapters/iscsi_if.h>		/* ioctl interfaces */
/* protocol structs and defines */
#include <sys/iscsi_protocol.h>
#include "iscsi_targetparam.h"
#include "persistent.h"
#include <sys/scsi/adapters/iscsi_door.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/utsname.h>

static iscsi_targetparams_t iscsi_targets;
static iscsi_targetparam_entry_t *iscsi_targetparam_create();

/*
 * Initializes the target list structure.  Called from iscsi_attach.
 */
void
iscsi_targetparam_init() {
    iscsi_targets.target_list = NULL;
    rw_init(&(iscsi_targets.target_list_lock), NULL,
	    RW_DRIVER, NULL);
}

/*
 * Frees target param list and destroys the list lock.
 */
void
iscsi_targetparam_cleanup() {
	iscsi_targetparam_entry_t *curr_entry, *tmp_entry;

	iscsi_targetparam_lock_list(RW_WRITER);

	curr_entry = iscsi_targets.target_list;
	while (curr_entry) {
		tmp_entry = curr_entry->next;
		kmem_free(curr_entry, sizeof (iscsi_targetparam_entry_t));
		curr_entry = tmp_entry;
	}

	iscsi_targetparam_unlock_list();
	rw_destroy(&iscsi_targets.target_list_lock);
}

/*
 * Creates a target param entry and adds it to the target param
 * entry list.
 *
 */
static iscsi_targetparam_entry_t *
iscsi_targetparam_create(uchar_t *name) {
	iscsi_targetparam_entry_t *target;

	ASSERT(name != NULL);

	target = kmem_alloc(sizeof (iscsi_targetparam_entry_t),
		KM_SLEEP);
	(void) strlcpy((char *)target->target_name, (char *)name,
		sizeof (target->target_name));

	/* assign unique key for the target */
	mutex_enter(&iscsi_oid_mutex);
	target->target_oid = iscsi_oid++;
	mutex_exit(&iscsi_oid_mutex);

	/* Add new target to the target list */
	iscsi_targetparam_lock_list(RW_WRITER);
	if (iscsi_targets.target_list == NULL) {
		iscsi_targets.target_list = target;
		iscsi_targets.target_list->next = NULL;
	} else {
		target->next = iscsi_targets.target_list;
		iscsi_targets.target_list = target;
	}
	iscsi_targetparam_unlock_list();
	return (target);
}

/*
 * Returns a target param entry's oid given the target name.  If the target
 * param entry cannot be found one is created and the new oid is returned.
 *
 */
uint32_t
iscsi_targetparam_get_oid(uchar_t *name) {
	int name_length;
	iscsi_targetparam_entry_t *curr_entry;

	ASSERT(name != NULL);
	name_length = strlen((char *)name);

	iscsi_targetparam_lock_list(RW_READER);
	curr_entry = iscsi_targetparam_get_next_entry(NULL);
	while (curr_entry != NULL) {
		if ((name_length == strlen((char *)curr_entry->target_name)) &&
		(bcmp(curr_entry->target_name,
		(char *)name, name_length) == 0)) {
			iscsi_targetparam_unlock_list();
			return (curr_entry->target_oid);
		}
		curr_entry = iscsi_targetparam_get_next_entry(curr_entry);
	}
	iscsi_targetparam_unlock_list();

	curr_entry = iscsi_targetparam_create(name);
	return (curr_entry->target_oid);
}

/*
 * Returns a target param entry's target name given its oid.  If the oid cannot
 * be found, NULL is returned.
 *
 */
uchar_t *iscsi_targetparam_get_name(uint32_t oid) {
	iscsi_targetparam_entry_t *curr_entry;

	iscsi_targetparam_lock_list(RW_READER);
	curr_entry = iscsi_targetparam_get_next_entry(NULL);
	while (curr_entry != NULL) {
		if (curr_entry->target_oid == oid) {
		iscsi_targetparam_unlock_list();
			return (curr_entry->target_name);
		}
		curr_entry = iscsi_targetparam_get_next_entry(curr_entry);
	}
	iscsi_targetparam_unlock_list();
	return (NULL);
}


/*
 * Removes a target param entry from the target param entry list.  The
 * oid is used to lookup the entry to be removed.
 *
 */
int
iscsi_targetparam_remove_target(uint32_t oid) {
	iscsi_targetparam_entry_t *prev_entry, *curr_entry;

	prev_entry = NULL;

	iscsi_targetparam_lock_list(RW_WRITER);
	curr_entry = iscsi_targetparam_get_next_entry(NULL);
	while (curr_entry != NULL) {
		if (curr_entry->target_oid == oid) {

			if (prev_entry == NULL) {
				iscsi_targets.target_list = curr_entry->next;
			} else if (curr_entry->next == NULL) {
				ASSERT(prev_entry != NULL);
				prev_entry->next = NULL;
			} else {
				ASSERT(prev_entry != NULL);
				ASSERT(curr_entry != NULL);
				prev_entry->next = curr_entry->next;
			}

			kmem_free(curr_entry,
			sizeof (iscsi_targetparam_entry_t));

			iscsi_targetparam_unlock_list();
			return (0);
		}

		prev_entry = curr_entry;
		curr_entry = iscsi_targetparam_get_next_entry(curr_entry);
	}

	iscsi_targetparam_unlock_list();
	return (0);
}

/*
 * Returns the next element in the target param entry list.  If
 * NULL is passed as the reference entry then the first item in
 * the list is returned.  NULL will be returned when the last
 * element in the list is used as the reference entry.
 *
 */
iscsi_targetparam_entry_t *
iscsi_targetparam_get_next_entry(iscsi_targetparam_entry_t *ref_entry) {
    iscsi_targetparam_entry_t *entry;

	if (ref_entry == NULL) {
		entry = iscsi_targets.target_list;
	} else {
		entry = ref_entry->next;
	}
	return (entry);
}

/*
 * Lock target param list.
 *
 */
void
iscsi_targetparam_lock_list(krw_t type) {
	rw_enter(&(iscsi_targets.target_list_lock), type);
}

/*
 * Unlock target param list.
 *
 */
void
iscsi_targetparam_unlock_list() {
	rw_exit(&(iscsi_targets.target_list_lock));
}
