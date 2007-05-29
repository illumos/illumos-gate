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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Mechanism Manager - centralized knowledge of mechanisms.
 *
 * The core of the mechmanager is the "mechlist" data structure. It contains
 * information about all mechanisms available from providers that have been
 * exposed to the application.
 *
 * Each element in the array represents a particular mechanism type. The
 * array is sorted by type, so that searching by mechanism can be done
 * quickly. Each element also contains the mechanism data for each slot.
 *
 * The mechlist is constructed on an as-needed basis, entries are not added
 * until the application triggers an action that requires an entry to be
 * added (or updated).
 *
 */

#include <string.h>
#include <strings.h>
#include "pkcs11Conf.h"
#include "metaGlobal.h"


/* Global data... */

#define	INITIAL_MECHLIST_SIZE	256

typedef struct mechliststruct {
	CK_MECHANISM_TYPE type;
	mechinfo_t *slots;
} mechlist_t;

static pthread_rwlock_t mechlist_lock = PTHREAD_RWLOCK_INITIALIZER;
static mechlist_t *mechlist;
static unsigned long num_mechs;
static unsigned long true_mechlist_size;


/* Prototypes... */
static CK_RV meta_mechManager_update_mech(CK_MECHANISM_TYPE, boolean_t);
static CK_RV meta_mechManager_update_slot(CK_ULONG);
static CK_RV update_slotmech(CK_MECHANISM_TYPE, CK_ULONG, unsigned long);
static CK_RV meta_mechManager_allocmechs(CK_MECHANISM_TYPE *, unsigned long,
	unsigned long *);
static boolean_t find_mech_index(CK_MECHANISM_TYPE, unsigned long *);
static int qsort_mechtypes(const void *, const void *);


/*
 * meta_mechManager_initialize
 *
 * Called from C_Initialize. Allocates and initializes storage needed
 * by the slot manager.
 */
CK_RV
meta_mechManager_initialize()
{
	/* The mechlist can dynamically grow, but let's preallocate space. */
	mechlist = calloc(INITIAL_MECHLIST_SIZE, sizeof (mechlist_t));
	if (mechlist == NULL)
		return (CKR_HOST_MEMORY);

	true_mechlist_size = INITIAL_MECHLIST_SIZE;
	num_mechs = 0;

	return (CKR_OK);
}


/*
 * meta_mechManager_finalize
 *
 * Called from C_Finalize. Deallocates any storage held by the slot manager.
 */
void
meta_mechManager_finalize()
{
	int i;

	/* No need to lock list, we assume all sessions are closed. */
	for (i = 0; i < num_mechs; i++) {
		free(mechlist[i].slots);
	}

	free(mechlist);
	mechlist = NULL;
	num_mechs = 0;
	true_mechlist_size = 0;
}


/*
 * meta_mechManager_get_mechs
 *
 * Get list of all available mechanisms.
 *
 * Follows PKCS#11 semantics, where list may be NULL to only request a
 * count of available mechanisms.
 */
CK_RV
meta_mechManager_get_mechs(CK_MECHANISM_TYPE *list, CK_ULONG *listsize)
{
	CK_RV rv = CKR_OK;
	CK_ULONG num_found = 0;
	CK_ULONG slotnum, num_slots;
	unsigned long i;

	/* get number of slots */
	num_slots = meta_slotManager_get_slotcount();

	/*
	 * Update slot info. Ignore any errors.
	 *
	 * NOTE: Due to the PKCS#11 convention of calling C_GetMechanismList
	 * twice (once to get the count, again to get the actual list), this
	 * is somewhat inefficient... However, I don't see an easy way to fix
	 * that without impacting other cases (eg, when the first call contains
	 * an "optimistic" pre-allocated buffer).
	 */
	for (slotnum = 0; slotnum < num_slots; slotnum++) {
		(void) meta_mechManager_update_slot(slotnum);
	}


	/*
	 * Count the number of mechanisms. We can't just use num_mechs,
	 * because some mechs may not currently be supported on any slot.
	 * Also, it may not be allowed based on the mechanism policy.
	 */

	(void) pthread_rwlock_rdlock(&mechlist_lock);
	for (i = 0; i < num_mechs; i++) {
		CK_ULONG j;
		boolean_t supported;

		if (pkcs11_is_dismech(METASLOT_FRAMEWORK_ID,
		    mechlist[i].type)) {
			/* skip mechs disabled by policy */
			continue;
		}

		supported = FALSE;
		for (j = 0; j < num_slots; j++) {
			if (!mechlist[i].slots[j].initialized)
				continue;

			if (mechlist[i].slots[j].supported) {
				supported = B_TRUE;
				break;
			}
		}

		if (supported) {
			num_found++;

			if (list && *listsize >= num_found) {
				list[num_found - 1] = mechlist[i].type;
			}
		}
	}
	(void) pthread_rwlock_unlock(&mechlist_lock);

	if (num_found > *listsize)
		rv = CKR_BUFFER_TOO_SMALL;

	*listsize = num_found;

	return (rv);
}


/*
 * meta_mechManager_get_slots
 *
 * Get list of all slots supporting the specified mechanism.
 *
 * The "mech_support_info" argument should have allocated enough
 * space to accomodate the list of slots that supports the
 * specified mechanism.  The "num_supporting_slots" field
 * in the "mech_support_info" structure will indicate how
 * many slots are found to support the mechanism.
 *
 * If any error occurred in getting the list, info in
 * mech_support_info argument is not updated.
 *
 */
CK_RV
meta_mechManager_get_slots(mech_support_info_t  *mech_support_info,
    boolean_t force_update, CK_MECHANISM_INFO *mech_info)
{
	CK_RV rv;
	boolean_t found;
	CK_ULONG i, num_slots;
	unsigned long index, num_found = 0;
	CK_MECHANISM_INFO info;

	rv = meta_mechManager_update_mech(mech_support_info->mech,
	    force_update);
	if (rv != CKR_OK) {
		return (rv);
	}

	(void) pthread_rwlock_rdlock(&mechlist_lock);

	found = find_mech_index(mech_support_info->mech, &index);
	if (!found) {
		goto finish;
	}

	num_slots = meta_slotManager_get_slotcount();
	for (i = 0; i < num_slots; i++) {
		if (!mechlist[index].slots[i].initialized ||
		    !mechlist[index].slots[i].supported)
			continue;

		if (mech_info) {
			info = mechlist[index].slots[i].mechanism_info;
			if (!(info.flags & mech_info->flags)) {
				continue;
			}
		}

		num_found++;
		(mech_support_info->supporting_slots)[num_found - 1]
		    = &mechlist[index].slots[i];
	}

finish:
	(void) pthread_rwlock_unlock(&mechlist_lock);

	if (num_found == 0) {
		rv = CKR_MECHANISM_INVALID;
	} else {
		mech_support_info->num_supporting_slots = num_found;
	}

	return (rv);
}


/*
 * meta_mechManager_update_mech
 *
 * Updates a mechanism in the mechlist. If the mechanism is not
 * listed, all providers will be queried. If the mechanism
 * is present, but not initialized for some providers, those providers
 * will be queried. Existing entries will not be updated unless the
 * force_refresh flag is set.
 *
 * The force_refresh flag is used by C_GetMechanismInfo, to force an
 * update. Updates are not forced during the common usage by operations
 * [eg C_EncryptInit] to avoid poor performance.
 */
static CK_RV
meta_mechManager_update_mech(CK_MECHANISM_TYPE mech, boolean_t force_refresh)
{
	CK_RV rv;
	CK_ULONG slot, num_slots;
	unsigned long index = 0;
	boolean_t found;

	/* Ensure list contains the mechanism. */
	rv = meta_mechManager_allocmechs(&mech, 1, &index);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_rwlock_wrlock(&mechlist_lock);
	/*
	 * We didn't retain a lock after the first search, so it's possible
	 * that the mechlist was updated. Search again, but use the last
	 * index as a hint to quickly find the mechanism.
	 */
	found = find_mech_index(mech, &index);
	if (!found) {
		/* Shouldn't happen - entries are not removed from list. */
		rv = CKR_GENERAL_ERROR;
		goto finish;
	}

	num_slots = meta_slotManager_get_slotcount();
	for (slot = 0; slot < num_slots; slot++) {
		if (force_refresh || !mechlist[index].slots[slot].initialized) {
			rv = update_slotmech(mech, slot, index);
			if (rv != CKR_OK) {
				/* Ignore error and continue with next slot. */
				rv = CKR_OK;
			}
		}
	}

finish:
	(void) pthread_rwlock_unlock(&mechlist_lock);

	return (rv);
}


/*
 * meta_mechManager_update_slot
 *
 * Updates a slot in the mechlist. Called by C_GetMechanismList
 * [by way of meta_mechManager_get_mechs()]. Unlike
 * meta_mechManager_get_slots(), the context is always to force a refresh
 * of the mechlist.
 *
 */
static CK_RV
meta_mechManager_update_slot(CK_ULONG slotnum)
{
	unsigned long index = 0;
	CK_MECHANISM_TYPE *slot_mechlist = NULL, *tmp_slot_mechlist = NULL;
	CK_ULONG slot_mechlistsize, mechnum, tmp_mechlistsize;
	CK_RV rv;
	boolean_t found;
	CK_SLOT_ID fw_st_id, true_id;
	int i;

	fw_st_id = meta_slotManager_get_framework_table_id(slotnum);
	true_id = TRUEID(fw_st_id);

	/* First, get the count. */
	rv = FUNCLIST(fw_st_id)->C_GetMechanismList(true_id, NULL,
	    &slot_mechlistsize);
	if (rv != CKR_OK) {
		goto finish;
	}

	tmp_slot_mechlist = malloc(
	    slot_mechlistsize * sizeof (CK_MECHANISM_TYPE));
	if (tmp_slot_mechlist == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}

	/* Next, get the actual list. */
	rv = FUNCLIST(fw_st_id)->C_GetMechanismList(true_id,
	    tmp_slot_mechlist, &slot_mechlistsize);
	if (rv != CKR_OK) {
		goto finish;
	}

	/*
	 * filter the list of mechanisms returned by the underlying slot
	 * to remove any mechanisms that are explicitly disabled
	 * in the configuration file.
	 */
	slot_mechlist = malloc(slot_mechlistsize * sizeof (CK_MECHANISM_TYPE));
	if (slot_mechlist == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}

	tmp_mechlistsize = 0;
	for (i = 0; i < slot_mechlistsize; i++) {
		/* filter out the disabled mechanisms */
		if (pkcs11_is_dismech(fw_st_id, tmp_slot_mechlist[i])) {
			continue;
		}

		slot_mechlist[tmp_mechlistsize] = tmp_slot_mechlist[i];
		tmp_mechlistsize++;
	}
	slot_mechlistsize = tmp_mechlistsize;

	/* Sort the mechanisms by value. */
	qsort(slot_mechlist, slot_mechlistsize, sizeof (CK_MECHANISM_TYPE),
	    qsort_mechtypes);

	/* Ensure list contains the mechanisms. */
	rv = meta_mechManager_allocmechs(slot_mechlist, slot_mechlistsize,
	    &index);
	if (rv != CKR_OK)
		goto finish;

	/* Update the mechanism info. */
	(void) pthread_rwlock_wrlock(&mechlist_lock);
	for (mechnum = 0; mechnum < slot_mechlistsize; mechnum++) {
		found = find_mech_index(slot_mechlist[mechnum], &index);
		if (!found) {
			/* This shouldn't happen. */
			rv = CKR_GENERAL_ERROR;
			goto finish;
		}

		rv = update_slotmech(slot_mechlist[mechnum], slotnum, index);
		if (rv != CKR_OK) {
			/* Ignore error, make best effort to finish update. */
			rv = CKR_OK;
			continue;
		}
	}
	(void) pthread_rwlock_unlock(&mechlist_lock);

finish:
	if (slot_mechlist) {
		free(slot_mechlist);
	}

	if (tmp_slot_mechlist) {
		free(tmp_slot_mechlist);
	}

	return (rv);
}


/*
 * update_slotmech
 *
 * Updates the information for a particular mechanism for a particular slot.
 * (ie, slotlist[foo].slots[bar])
 *
 * It is assumed that the caller to this function (all of which are
 * in this file) holds the write-lock to "mechlist_lock".
 *
 */
static CK_RV
update_slotmech(CK_MECHANISM_TYPE mech, CK_ULONG slotnum,
	unsigned long index)
{
	CK_RV rv = CKR_OK;
	CK_MECHANISM_INFO info;
	CK_SLOT_ID fw_st_id, true_id;

	mechlist[index].slots[slotnum].slotnum = slotnum;
	fw_st_id = meta_slotManager_get_framework_table_id(slotnum);
	true_id = TRUEID(fw_st_id);

	/*
	 * Check if the specified mechanism is in the disabled list
	 * of the specified slot.  If so, we can immediately conclude
	 * that it is not supported by the specified slot.
	 */
	if (pkcs11_is_dismech(fw_st_id, mech)) {
		/*
		 * we mark this as initialized so that we won't try
		 * to do this check later
		 */
		mechlist[index].slots[slotnum].initialized = B_TRUE;
		mechlist[index].slots[slotnum].supported = B_FALSE;
		bzero(&mechlist[index].slots[slotnum].mechanism_info,
		    sizeof (CK_MECHANISM_INFO));
		goto finish;
	}

	rv = FUNCLIST(fw_st_id)->C_GetMechanismInfo(true_id, mech, &info);
	if (rv == CKR_OK) {
		mechlist[index].slots[slotnum].initialized = B_TRUE;
		mechlist[index].slots[slotnum].supported = B_TRUE;
		mechlist[index].slots[slotnum].mechanism_info = info;
	} else {
		/* record that the mechanism isn't supported for the slot */
		mechlist[index].slots[slotnum].initialized = B_TRUE;
		mechlist[index].slots[slotnum].supported = B_FALSE;
		bzero(&mechlist[index].slots[slotnum].mechanism_info,
		    sizeof (CK_MECHANISM_INFO));
	}

finish:
	return (rv);
}


/*
 * meta_mechManager_allocmechs
 *
 * Ensures that all of the specified mechanisms are present in the
 * mechlist. If a mechanism is not present, an uninitialized entry is
 * added for it.
 *
 * The returned index can be used by the caller as a hint to where the
 * first mechanism was located.
 */
static CK_RV
meta_mechManager_allocmechs(CK_MECHANISM_TYPE *new_mechs,
	unsigned long num_new_mechs, unsigned long *index_hint)
{
	CK_RV rv = CKR_OK;
	unsigned long i, index = 0;
	boolean_t found;

	/* The optimistic assumption is that the mech is already present. */
	(void) pthread_rwlock_rdlock(&mechlist_lock);
	for (i = 0; i < num_new_mechs; i++) {
		found = find_mech_index(new_mechs[i], &index);

		if (i == 0)
			*index_hint = index;

		if (!found)
			break;
	}
	(void) pthread_rwlock_unlock(&mechlist_lock);

	if (found) {
		return (CKR_OK);
	}

	/*
	 * We stopped searching when the first unknown mech was found. Now
	 * obtain a write-lock, and continue from where we left off, inserting
	 * unknown mechanisms.
	 */

	(void) pthread_rwlock_wrlock(&mechlist_lock);
	for (; i < num_new_mechs; i++) {
		found = find_mech_index(new_mechs[i], &index);

		if (!found) {
			mechinfo_t *new_mechinfos;

			new_mechinfos = calloc(meta_slotManager_get_slotcount(),
			    sizeof (mechinfo_t));
			if (new_mechinfos == NULL) {
				rv = CKR_HOST_MEMORY;
				goto finish;
			}

			/*
			 * If the current storage for the mechlist is too
			 * small, allocate a new list twice as large.
			 */
			if (num_mechs == true_mechlist_size) {
				mechlist_t *newmechlist;

				newmechlist = realloc(mechlist,
				    2 * true_mechlist_size *
				    sizeof (mechlist_t));

				if (newmechlist == NULL) {
					rv = CKR_HOST_MEMORY;
					free(new_mechinfos);
					goto finish;
				}

				mechlist = newmechlist;
				true_mechlist_size *= 2;
			}

			/* Shift existing entries to make space. */
			(void) memmove(&mechlist[index+1], &mechlist[index],
			    (num_mechs - index) * sizeof (mechlist_t));
			num_mechs++;

			mechlist[index].type = new_mechs[i];
			mechlist[index].slots = new_mechinfos;
		}
	}

finish:
	(void) pthread_rwlock_unlock(&mechlist_lock);

	return (rv);
}


/*
 * find_mech_index
 *
 * Performs a search of mechlist for the specified mechanism, and
 * returns if the mechanism was found or not. The value of the "index"
 * argument will be where the mech is (if found), or where it should
 * be (if not found).
 *
 * The current value of "index" will be used as a starting point, if the
 * caller already knows where the mechanism is likely to be.
 *
 * The caller is assumed to have a lock on the mechlist, preventing it
 * from being changed while searching (also to ensure the returned index
 * will remain valid until the list is unlocked).
 *
 * FUTURE: convert to binary search [from O(N) to a O(log(N))].
 *
 * NOTES:
 * 1) This function assumes that mechMap is a sorted list.
 */
static boolean_t
find_mech_index(CK_MECHANISM_TYPE mechanism, unsigned long *index)
{
	boolean_t found = B_FALSE;
	unsigned long i;

	for (i = 0; i < num_mechs; i++) {

		if (mechlist[i].type == mechanism) {
			found = B_TRUE;
			break;
		}

		if (mechlist[i].type > mechanism)
			break;
	}

	*index = i;

	return (found);
}

static int
qsort_mechtypes(const void *arg1, const void *arg2)
{
	CK_MECHANISM_TYPE mech1 = *((CK_MECHANISM_TYPE *)arg1);
	CK_MECHANISM_TYPE mech2 = *((CK_MECHANISM_TYPE *)arg2);

	if (mech1 > mech2)
		return (1);
	if (mech1 < mech2)
		return (-1);
	return (0);
}

/*
 * Check if the specified mechanism is supported by the specified slot.
 * The result is returned in the "supports" argument.  If the "slot_info"
 * argument is not NULL, it will be filled with information about
 * the slot.
 */
CK_RV
meta_mechManager_slot_supports_mech(CK_MECHANISM_TYPE mechanism,
    CK_ULONG slotnum, boolean_t *supports, mechinfo_t **slot_info,
    boolean_t force_update, CK_MECHANISM_INFO *mech_info)
{

	boolean_t found;
	CK_RV rv;
	unsigned long index;
	CK_MECHANISM_INFO info;

	*supports = B_FALSE;

	rv = meta_mechManager_update_mech(mechanism, force_update);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_rwlock_rdlock(&mechlist_lock);

	found = find_mech_index(mechanism, &index);
	if (!found) {
		goto finish;
	}

	if ((mechlist[index].slots[slotnum].initialized) &&
	    (mechlist[index].slots[slotnum].supported)) {
		if (mech_info) {
			info = mechlist[index].slots[slotnum].mechanism_info;
			if (!(info.flags & mech_info->flags)) {
				goto finish;
			}
		}
		*supports = B_TRUE;
		if (slot_info) {
			*slot_info = &(mechlist[index].slots[slotnum]);
		}
	}

finish:
	(void) pthread_rwlock_unlock(&mechlist_lock);

	return (rv);
}
