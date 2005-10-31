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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dnode.h>

uint64_t
dmu_object_alloc(objset_t *os, dmu_object_type_t ot, int blocksize,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx)
{
	objset_impl_t *osi = os->os;
	uint64_t object;
	uint64_t L2_dnode_count = DNODES_PER_BLOCK <<
	    (osi->os_meta_dnode->dn_indblkshift - SPA_BLKPTRSHIFT);
	dnode_t *dn;
	int restarted = B_FALSE;

	mutex_enter(&osi->os_obj_lock);
	for (;;) {
		object = osi->os_obj_next;
		/*
		 * Each time we polish off an L2 bp worth of dnodes
		 * (2^13 objects), move to another L2 bp that's still
		 * reasonably sparse (at most 1/4 full).  Look from the
		 * beginning once, but after that keep looking from here.
		 * If we can't find one, just keep going from here.
		 */
		if (P2PHASE(object, L2_dnode_count) == 0) {
			uint64_t offset = restarted ? object << DNODE_SHIFT : 0;
			int error = dnode_next_offset(osi->os_meta_dnode,
			    B_TRUE, &offset, 2, DNODES_PER_BLOCK >> 2);
			restarted = B_TRUE;
			if (error == 0)
				object = offset >> DNODE_SHIFT;
		}
		osi->os_obj_next = ++object;

		dn = dnode_hold_impl(os->os, object, DNODE_MUST_BE_FREE, FTAG);
		if (dn)
			break;

		if (dmu_object_next(os, &object, B_TRUE) == 0)
			osi->os_obj_next = object - 1;
	}

	dnode_allocate(dn, ot, blocksize, 0, bonustype, bonuslen, tx);
	dnode_rele(dn, FTAG);

	mutex_exit(&osi->os_obj_lock);

	dmu_tx_add_new_object(tx, os, object);
	return (object);
}

int
dmu_object_claim(objset_t *os, uint64_t object, dmu_object_type_t ot,
    int blocksize, dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx)
{
	dnode_t *dn;

	if ((object & DMU_PRIVATE_OBJECT) && !dmu_tx_private_ok(tx))
		return (EBADF);

	dn = dnode_hold_impl(os->os, object, DNODE_MUST_BE_FREE, FTAG);
	if (dn == NULL)
		return (EEXIST);
	dnode_allocate(dn, ot, blocksize, 0, bonustype, bonuslen, tx);
	dnode_rele(dn, FTAG);

	dmu_tx_add_new_object(tx, os, object);
	return (0);
}

int
dmu_object_reclaim(objset_t *os, uint64_t object, dmu_object_type_t ot,
    int blocksize, dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx)
{
	dnode_t *dn;

	if ((object & DMU_PRIVATE_OBJECT) && !dmu_tx_private_ok(tx))
		return (EBADF);

	dn = dnode_hold_impl(os->os, object, DNODE_MUST_BE_ALLOCATED, FTAG);
	if (dn == NULL)
		return (EBADF);
	dnode_reallocate(dn, ot, blocksize, bonustype, bonuslen, tx);
	dnode_rele(dn, FTAG);

	return (0);
}

int
dmu_object_free(objset_t *os, uint64_t object, dmu_tx_t *tx)
{
	dnode_t *dn;

	ASSERT(!(object & DMU_PRIVATE_OBJECT) || dmu_tx_private_ok(tx));

	dn = dnode_hold_impl(os->os, object, DNODE_MUST_BE_ALLOCATED, FTAG);
	if (dn == NULL)
		return (ENOENT);

	ASSERT(dn->dn_type != DMU_OT_NONE);
	dnode_free(dn, tx);
	dnode_rele(dn, FTAG);

	return (0);
}

int
dmu_object_next(objset_t *os, uint64_t *objectp, boolean_t hole)
{
	uint64_t offset = (*objectp + 1) << DNODE_SHIFT;
	int error;

	error = dnode_next_offset(os->os->os_meta_dnode,
	    hole, &offset, 0, DNODES_PER_BLOCK);

	*objectp = offset >> DNODE_SHIFT;

	return (error);
}
