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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * hci1394_tlabel.h
 *   These routines track the tlabel usage for a 1394 adapter.
 */

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/ieee1394.h>
#include <sys/1394/adapters/hci1394.h>


/*
 * hci1394_tlabel_init()
 *    Initialize the tlabel structures.  These structures will be protected
 *    by a mutex at the iblock_cookie passed in.  Bad tlabels will be usable
 *    when > reclaim_time_nS has gone by.  init() returns a handle to be used
 *    for the rest of the tlabel functions.
 */
void
hci1394_tlabel_init(hci1394_drvinfo_t *drvinfo, hrtime_t reclaim_time_nS,
    hci1394_tlabel_handle_t *tlabel_handle)
{
	hci1394_tlabel_t *tstruct;


	ASSERT(tlabel_handle != NULL);

	/* alloc space for tlabel data */
	tstruct = kmem_alloc(sizeof (hci1394_tlabel_t), KM_SLEEP);

	/* setup handle which is returned from this function */
	*tlabel_handle = tstruct;

	/*
	 * Initialize tlabel structure. We start with max node set to the
	 * maxiumum node we could have so that we make sure the arrays are
	 * initialized correctly in hci1394_tlabel_reset().
	 */
	tstruct->tb_drvinfo = drvinfo;
	tstruct->tb_reclaim_time = reclaim_time_nS;
	tstruct->tb_max_node = TLABEL_RANGE - 1;
	tstruct->tb_bcast_sent = B_FALSE;

	mutex_init(&tstruct->tb_mutex, NULL, MUTEX_DRIVER,
	    drvinfo->di_iblock_cookie);

	/*
	 * The mutex must be initialized before tlabel_reset()
	 * is called.  This is because tlabel_reset is also
	 * used in normal tlabel processing (i.e. not just during
	 * initialization)
	 */
	hci1394_tlabel_reset(tstruct);
}


/*
 * hci1394_tlabel_fini()
 *    Frees up the space allocated in init().  Notice that a pointer to the
 *    handle is used for the parameter.  fini() will set your handle to NULL
 *    before returning.
 */
void
hci1394_tlabel_fini(hci1394_tlabel_handle_t *tlabel_handle)
{
	hci1394_tlabel_t *tstruct;


	ASSERT(tlabel_handle != NULL);

	tstruct = (hci1394_tlabel_t *)*tlabel_handle;

	mutex_destroy(&tstruct->tb_mutex);
	kmem_free(tstruct, sizeof (hci1394_tlabel_t));

	/* set handle to null.  This helps catch bugs. */
	*tlabel_handle = NULL;
}


/*
 * hci1394_tlabel_alloc()
 *    alloc a tlabel based on the node id. If alloc fails, we are out of
 *    tlabels for that node. See comments before set_reclaim_time() on when
 *    bad tlabel's are free to be used again.
 */
int
hci1394_tlabel_alloc(hci1394_tlabel_handle_t tlabel_handle, uint_t destination,
    hci1394_tlabel_info_t *tlabel_info)
{
	uint_t node_number;
	uint_t index;
	uint64_t bad;
	uint64_t free;
	hrtime_t time;
	uint8_t last;


	ASSERT(tlabel_handle != NULL);
	ASSERT(tlabel_info != NULL);

	/* copy destination into tlabel_info */
	tlabel_info->tbi_destination = destination;

	/* figure out what node we are going to */
	node_number = IEEE1394_NODE_NUM(destination);

	mutex_enter(&tlabel_handle->tb_mutex);

	/*
	 * Keep track of if we have sent out a broadcast request and what the
	 * maximum # node we have sent to for reset processing optimization
	 */
	if (node_number == IEEE1394_BROADCAST_NODEID) {
		tlabel_handle->tb_bcast_sent = B_TRUE;
	} else if (node_number > tlabel_handle->tb_max_node) {
		tlabel_handle->tb_max_node = node_number;
	}

	/* setup copies so we don't take up so much space :-) */
	bad = tlabel_handle->tb_bad[node_number];
	free = tlabel_handle->tb_free[node_number];
	time = tlabel_handle->tb_bad_timestamp[node_number];
	last = tlabel_handle->tb_last[node_number];

	/*
	 * If there are any bad tlabels, see if the last bad tlabel recorded for
	 * this nodeid is now good to use. If so, add all bad tlabels for that
	 * node id back into the free list
	 *
	 * NOTE: This assumes that bad tlabels are infrequent.
	 */
	if (bad != 0) {
		if (gethrtime() > time) {

			/* add the bad tlabels back into the free list */
			free |= bad;

			/* clear the bad list */
			bad = 0;
		}
	}

	/*
	 * Find a free tlabel.  This will break out of the loop once it finds a
	 * tlabel.  There are a total of TLABEL_RANGE tlabels.  The alloc
	 * rotates the check so that we don't always use the same tlabel. It
	 * stores the last tlabel used in last.
	 */
	for (index = 0; index < TLABEL_RANGE; index++) {

		/* if the next tlabel to check is free */
		if ((free & ((uint64_t)1 << last)) != 0) {
			/* we are using this tlabel */
			tlabel_info->tbi_tlabel = last;

			/* take it out of the free list */
			free = free & ~((uint64_t)1 << last);

			/*
			 * increment the last count so we start checking on the
			 * next tlabel next alloc().  Note the rollover at
			 * TLABEL_RANGE since we only have TLABEL_RANGE tlabels.
			 */
			(last)++;
			if (last >= TLABEL_RANGE) {
				last = 0;
			}

			/* Copy the copies back */
			tlabel_handle->tb_bad[node_number] = bad;
			tlabel_handle->tb_free[node_number] = free;
			tlabel_handle->tb_bad_timestamp[node_number] = time;
			tlabel_handle->tb_last[node_number] = last;

			/* unlock the tlabel structure */
			mutex_exit(&tlabel_handle->tb_mutex);
			return (DDI_SUCCESS);
		}

		/*
		 * This tlabel is not free, lets go to the next one. Note the
		 * rollover at TLABEL_RANGE since we only have TLABEL_RANGE
		 * tlabels.
		 */
		(last)++;
		if (last >= TLABEL_RANGE) {
			last = 0;
		}
	}

	/* Copy the copies back */
	tlabel_handle->tb_bad[node_number] = bad;
	tlabel_handle->tb_free[node_number] = free;
	tlabel_handle->tb_bad_timestamp[node_number] = time;
	tlabel_handle->tb_last[node_number] = last;

	mutex_exit(&tlabel_handle->tb_mutex);

	return (DDI_FAILURE);
}


/*
 * hci1394_tlabel_free()
 *    free the previously alloc()'d tlabel.  Once a tlabel has been free'd, it
 *    can be used again when alloc() is called.
 */
void
hci1394_tlabel_free(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info)
{
	uint_t node_number;
	uint_t tlabel;


	ASSERT(tlabel_handle != NULL);
	ASSERT(tlabel_info != NULL);
	ASSERT(tlabel_info->tbi_tlabel <= TLABEL_MASK);

	/* figure out what node and tlabel we are using */
	node_number = IEEE1394_NODE_NUM(tlabel_info->tbi_destination);
	tlabel = tlabel_info->tbi_tlabel;

	mutex_enter(&tlabel_handle->tb_mutex);

	/*
	 * Put the tlabel back in the free list and NULL out the (void *) in the
	 * lookup structure.  You wouldn't expect to have to null out the lookup
	 * structure, but we know first hand that bad HW will send invalid
	 * tlabels which could really mess things up if you didn't :-)
	 */
	tlabel_handle->tb_lookup[node_number][tlabel] = NULL;
	tlabel_handle->tb_free[node_number] |= ((uint64_t)1 << tlabel);

	mutex_exit(&tlabel_handle->tb_mutex);
}


/*
 * hci1394_tlabel_register()
 *    Register an opaque command with an alloc()'d tlabel. Each nodeID has it's
 *    own tlabel list.
 */
void
hci1394_tlabel_register(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info, void *cmd)
{
	uint_t node_number;
	uint_t tlabel;


	ASSERT(tlabel_handle != NULL);
	ASSERT(tlabel_info != NULL);
	ASSERT(tlabel_info->tbi_tlabel <= TLABEL_MASK);

	/* figure out what node and tlabel we are using */
	node_number = IEEE1394_NODE_NUM(tlabel_info->tbi_destination);
	tlabel = tlabel_info->tbi_tlabel;

	mutex_enter(&tlabel_handle->tb_mutex);

	/* enter the (void *) into the lookup table */
	tlabel_handle->tb_lookup[node_number][tlabel] = cmd;

	mutex_exit(&tlabel_handle->tb_mutex);
}


/*
 * hci1394_tlabel_lookup()
 *    returns (in cmd) the opaque command which was registered with the
 *    specified tlabel from alloc(). If a tlabel was not registered, cmd ='s
 *    NULL.
 */
void
hci1394_tlabel_lookup(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info, void **cmd)
{
	uint_t node_number;
	uint_t tlabel;


	ASSERT(tlabel_handle != NULL);
	ASSERT(tlabel_info != NULL);
	ASSERT(cmd != NULL);
	ASSERT(tlabel_info->tbi_tlabel <= TLABEL_MASK);

	/* figure out what node and tlabel we are using */
	node_number = IEEE1394_NODE_NUM(tlabel_info->tbi_destination);
	tlabel = tlabel_info->tbi_tlabel;

	mutex_enter(&tlabel_handle->tb_mutex);

	/*
	 * fetch the (void *) from the lookup table.  The case where the pointer
	 * equals NULL will be handled by the layer above.
	 */
	*cmd = tlabel_handle->tb_lookup[node_number][tlabel];

	mutex_exit(&tlabel_handle->tb_mutex);
}


/*
 * hci1394_tlabel_bad()
 *    Register the specified tlabel as bad.  tlabel_lookup() will no longer
 *    return a registered opaque command and this tlabel will not be returned
 *    from alloc() until > reclaim_time has passed. See set_reclaim_time() for
 *    more info.
 */
void
hci1394_tlabel_bad(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info)
{
	uint_t node_number;
	uint_t tlabel;


	ASSERT(tlabel_handle != NULL);
	ASSERT(tlabel_info != NULL);

	/* figure out what node and tlabel we are using */
	node_number = IEEE1394_NODE_NUM(tlabel_info->tbi_destination);
	tlabel = tlabel_info->tbi_tlabel & TLABEL_MASK;

	mutex_enter(&tlabel_handle->tb_mutex);

	/*
	 * Put the tlabel in the bad list and NULL out the (void *) in the
	 * lookup structure.  We may see this tlabel shortly if the device is
	 * late in responding. We want to make sure to drop the message if we
	 * do. Set the bad timestamp to the current time plus the reclaim time.
	 * This is the "new" time when all of the bad tlabels for this node will
	 * be free'd.
	 */
	tlabel_handle->tb_bad_timestamp[node_number] = gethrtime() +
	    tlabel_handle->tb_reclaim_time;
	tlabel_handle->tb_bad[node_number] |= ((uint64_t)1 << tlabel);
	tlabel_handle->tb_lookup[node_number][tlabel] = NULL;

	mutex_exit(&tlabel_handle->tb_mutex);
}


/*
 * hci1394_tlabel_reset()
 *    resets the tlabel tracking structures to an initial state where no
 *    tlabels are outstanding and all tlabels are registered as good.  This
 *    routine should be called every bus reset.
 */
void
hci1394_tlabel_reset(hci1394_tlabel_handle_t tlabel_handle)
{
	int index;
	int index2;


	ASSERT(tlabel_handle != NULL);

	mutex_enter(&tlabel_handle->tb_mutex);

	/* Bus reset optimization. handle broadcast writes separately */
	if (tlabel_handle->tb_bcast_sent == B_TRUE) {
		tlabel_handle->tb_free[IEEE1394_BROADCAST_NODEID] =
		    (uint64_t)0xFFFFFFFFFFFFFFFF;
		tlabel_handle->tb_bad[IEEE1394_BROADCAST_NODEID] =
		    (uint64_t)0;
		tlabel_handle->tb_bad_timestamp[IEEE1394_BROADCAST_NODEID] =
		    (hrtime_t)0;
		tlabel_handle->tb_last[IEEE1394_BROADCAST_NODEID] = 0;
		for (index2 = 0; index2 < TLABEL_RANGE; index2++) {
			tlabel_handle->tb_lookup[IEEE1394_BROADCAST_NODEID
			    ][index2] = NULL;
		}
	}

	/*
	 * Mark all tlabels as free.  No bad tlabels.  Start the first tlabel
	 * alloc at 0.  Cleanout the lookup table.  An optimization to only do
	 * this up to the max node we have seen on the bus has been added.
	 */
	for (index = 0; index <= tlabel_handle->tb_max_node; index++) {
		tlabel_handle->tb_free[index] = (uint64_t)0xFFFFFFFFFFFFFFFF;
		tlabel_handle->tb_bad[index] = (uint64_t)0;
		tlabel_handle->tb_bad_timestamp[index] = (hrtime_t)0;
		tlabel_handle->tb_last[index] = 0;
		for (index2 = 0; index2 < TLABEL_RANGE; index2++) {
			tlabel_handle->tb_lookup[index][index2] = NULL;
		}
	}

	tlabel_handle->tb_max_node = 0;
	tlabel_handle->tb_bcast_sent = B_FALSE;

	mutex_exit(&tlabel_handle->tb_mutex);
}


/*
 * hci1394_tlabel_set_reclaim_time()
 *    This function should be called if a change to the reclaim_time is
 *    required after the initial call to init().  It is not necessary to call
 *    this function if the reclaim time never changes.
 *
 *    Currently, bad tlabels are reclaimed in tlabel_alloc().
 *    It looks like the following for a given node:
 *
 *    if bad tlabels exist
 *	    if ((current time + reclaim time) >= last bad tlabel time)
 *		    free all bad tlabels.
 */
void
hci1394_tlabel_set_reclaim_time(hci1394_tlabel_handle_t tlabel_handle,
    hrtime_t reclaim_time_nS)
{
	ASSERT(tlabel_handle != NULL);

	/*
	 * We do not need to lock the tlabel structure in this because we are
	 * doing a single write to reclaim_time. If this changes in the future,
	 * we may need to add calls to lock() and unlock().
	 */
	tlabel_handle->tb_reclaim_time = reclaim_time_nS;
}
