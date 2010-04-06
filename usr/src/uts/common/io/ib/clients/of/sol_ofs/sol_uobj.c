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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * User Objects.
 *
 * User objects are used to manage and protect resources that
 * have been created for a user context.  Each user object
 * maintains a reference count and a read/write mutex to
 * provide the appropriate access to the object depending
 * on the operation at hand.
 *
 * For example when initializing or creating a PD user object,
 * the active context would hold a write lock, but to simply
 * reference the PD object as in a CQ create operation, a
 * read lock is only required.
 *
 * Each user object also maintains a "live" flag.  If this flag
 * is not set, then lookups on this user object will fail
 * even if it still resides in the associated user object
 * management table.  This specifically handles the case
 * where a get operation blocks and does not acquire the lock
 * until after the object has been destroyed (but not yet
 * released).  Destroy operations set the "live" flag to 0
 * prior to dropping their write lock on the user object.
 * This allows the reader to realize when it receives the
 * lock that the object has been destroyed so it can then
 * release it's reference to the user object, and allow it to
 * be freed (the storage will not be freed until the last reference
 * is released).
 */
#include	<sys/debug.h>
#include	<sys/kmem.h>
#include	<sys/sunddi.h>
#include	<sys/ib/clients/of/sol_ofs/sol_ofs_common.h>

extern char	*sol_ofs_dbg_str;
static sol_ofs_uobj_t *ofs_uobj_find(sol_ofs_uobj_table_t *,
    uint_t, int);

/*
 * Function:
 *	sol_ofs_uobj_tbl_init
 * Input:
 *	uo_tbl	- A pointer to the user object resource management table
 *		  to initialize.
 * Output:
 *	None
 * Returns:
 *	None
 * Description:
 * 	Initializes the specified user object resource managment table.
 */
void
sol_ofs_uobj_tbl_init(sol_ofs_uobj_table_t *uo_tbl, size_t uobj_sz)
{
	ASSERT(uo_tbl != NULL);

	rw_init(&uo_tbl->uobj_tbl_lock, NULL, RW_DRIVER, NULL);
	uo_tbl->uobj_tbl_used_blks = 0;
	uo_tbl->uobj_tbl_num_blks = 0;
	uo_tbl->uobj_tbl_uo_cnt = 0;
	uo_tbl->uobj_tbl_uo_sz = uobj_sz;
	uo_tbl->uobj_tbl_uo_root = NULL;
}

/*
 * Function:
 *	sol_ofs_uobj_tbl_fini
 * Input:
 *	uo_tbl	- A pointer to the user object resource management table
 *		  to be released.
 * Output:
 *	None
 * Returns:
 *	None
 * Description:
 * 	Releases any resources held by the specified user object resource
 *	managment table.  The table is no longer valid upon return. NOTE:
 *	the table should be empty when this routine is called, so this
 *	really is more of just a sanity check.
 */
void
sol_ofs_uobj_tbl_fini(sol_ofs_uobj_table_t *uo_tbl)
{
	int			i, j;
	uint32_t	size;
	sol_ofs_uobj_blk_t	*blk;

	ASSERT(uo_tbl != NULL);

	rw_enter(&uo_tbl->uobj_tbl_lock, RW_WRITER);

	if (uo_tbl->uobj_tbl_uo_cnt > 0) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ TBL FINI: object count not zero (cnt=%d)",
		    uo_tbl->uobj_tbl_uo_cnt);
	}

	/*
	 * Go through the roots looking for blocks to free.  Warn if any
	 * our found (there shouldn't be any).
	 */
	for (i = 0; i < uo_tbl->uobj_tbl_used_blks; i++) {
		blk = uo_tbl->uobj_tbl_uo_root[i];
		if (!blk) {
			continue;
		}
		for (j = 0; j < SOL_OFS_UO_BLKSZ; j++) {
			if (blk->ofs_uoblk_blks[j])   {
				/*
				 * This is an error, we may want to free
				 * ultimately sol_ofs_uobj_free
				 * (blk->ofs_uoblk_blks[j]);
				 */
				SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
				    "UOBJ TBL FINI: blk %p, slot %d non null",
				    blk, j);
			}
		}
		kmem_free(blk, sizeof (*blk));
	}

	if (uo_tbl->uobj_tbl_uo_root) {

		size = uo_tbl->uobj_tbl_num_blks *
		    sizeof (sol_ofs_uobj_blk_t *);
		kmem_free(uo_tbl->uobj_tbl_uo_root, size);
	}

	rw_exit(&uo_tbl->uobj_tbl_lock);
	rw_destroy(&uo_tbl->uobj_tbl_lock);
}

/*
 * Function:
 *	uverbs_uob_init
 * Input:
 * 	uobj        - Pointer to the user object to initialize.
 *	user_handle - A user space handle to associates with the object.
 *	              Generally used to identify object in asynchronous
 *	              notifications.
 *	uob_type   - The type of user object.
 * Ouput:
 *	uobj       - Initialized user object.
 * Returns:
 * 	None
 * Description:
 *	Initialize a new user object.  The object will have one reference
 *	placed on it.
 */
void
sol_ofs_uobj_init(sol_ofs_uobj_t *uobj,
    uint64_t user_handle, sol_ofs_uobj_type_t  uobj_type)
{
	uobj->uo_user_handle = user_handle;
	uobj->uo_refcnt = 1;
	uobj->uo_type = uobj_type;
	uobj->uo_id = -1;
	uobj->uo_live = 0;
	rw_init(&uobj->uo_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&uobj->uo_reflock, NULL, MUTEX_DRIVER, NULL);
}

/*
 * Function:
 *	ofs_uobj_fini
 * Input:
 * 	uobj        - Pointer to the user object to be cleaned up.
 * Ouput:
 *	None
 * Returns:
 * 	None
 * Description:
 *	Performs user object cleanup prior to releasing memory.
 */
static void
ofs_uobj_fini(sol_ofs_uobj_t *uobj)
{
	rw_destroy(&uobj->uo_lock);
	mutex_destroy(&uobj->uo_reflock);
}

/*
 * Function:
 *	sol_ofs_uobj_ref
 * Input:
 * 	uobj        - Pointer to the user object
 * Ouput:
 *	None
 * Returns:
 * 	None
 * Description:
 *	Place a reference on the specified user object.
 */
void
sol_ofs_uobj_ref(sol_ofs_uobj_t *uobj)
{
	mutex_enter(&uobj->uo_reflock);
	uobj->uo_refcnt++;
	ASSERT(uobj->uo_refcnt != 0);
	mutex_exit(&uobj->uo_reflock);
}

/*
 * Function:
 *	sol_ofs_uobj_deref
 * Input:
 * 	uobj        - Pointer to the user object
 *	free_func   - Pointer to release function, called if the
 *                    last reference is removed for the user object.
 * Ouput:
 *	None
 * Returns:
 * 	None
 * Description:
 *	Remove a reference to a user object.  If a free function
 *	was specified and the last reference is released, then the
 *	free function is invoked to release the user object.
 */
void
sol_ofs_uobj_deref(sol_ofs_uobj_t *uobj,
    void (*free_func)(sol_ofs_uobj_t *uobj))
{
	SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str, "UOBJ_DEREF: uobj = %p, "
	    "refcnt=%d", uobj, uobj->uo_refcnt);

	mutex_enter(&uobj->uo_reflock);

	ASSERT(uobj->uo_refcnt != 0);
	uobj->uo_refcnt--;
	if (uobj->uo_refcnt == 0) {
		mutex_exit(&uobj->uo_reflock);
		if (free_func)
			free_func(uobj);
	} else {
		mutex_exit(&uobj->uo_reflock);
	}
}

/*
 * Function:
 *	sol_ofs_uobj_add
 * Input:
 *	uo_tbl	- A pointer to the user object resource management table
 *		  to which the object should be added.
 *	uobj    - A pointer ot the user object to be added; a reference
 *	          should exist on this object prior to addition, and the
 *		  object should be removed prior to all references being
 *		  removed.
 * Output:
 *	uobj	- The user object "uo_id" is updated and should be
 *		  used in subsequent lookup operations.
 * Returns:
 *	DDI_SUCCESS on success, else error code.
 * Description:
 * 	Add a user object to the specified user object resource management
 *	table.
 *
 */
int
sol_ofs_uobj_add(sol_ofs_uobj_table_t *uo_tbl, sol_ofs_uobj_t *uobj)
{
	int		i, j, empty = -1;
	sol_ofs_uobj_blk_t	*blk;

	rw_enter(&uo_tbl->uobj_tbl_lock, RW_WRITER);

	/*
	 * Try to find an empty slot for the new user object.
	 */
	for (i = 0; i < uo_tbl->uobj_tbl_used_blks; i++) {
		blk = uo_tbl->uobj_tbl_uo_root[i];
		if (blk != NULL && blk->ofs_uo_blk_avail > 0) {
			SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str,
			    "UOBJ ADD: table:%p, available blks:%d",
			    uo_tbl, blk->ofs_uo_blk_avail);
			for (j = 0; j < SOL_OFS_UO_BLKSZ; j++) {
				if (blk->ofs_uoblk_blks[j] == NULL) {
					blk->ofs_uoblk_blks[j] = uobj;
					uobj->uo_id = j + (i *
					    SOL_OFS_UO_BLKSZ);
					uobj->uo_uobj_sz =
					    uo_tbl->uobj_tbl_uo_sz;
					blk->ofs_uo_blk_avail--;
					uo_tbl->uobj_tbl_uo_cnt++;
					goto obj_added;
				}
			}
		} else if (blk == NULL && empty < 0) {
			/*
			 * Remember the first empty blk we came across.
			 */
			empty = i;
		}
	}

	/*
	 * No entries were available, we must allocate a new block.  If we did
	 * not find a empty block available, then we must allocate/reallocate
	 * the root array (copying any existing blk pointers to it).
	 */
	if (empty < 0) {
		if (uo_tbl->uobj_tbl_used_blks == uo_tbl->uobj_tbl_num_blks) {
			sol_ofs_uobj_blk_t	**p;
			uint_t		newsz;

			newsz = uo_tbl->uobj_tbl_num_blks + SOL_OFS_UO_BLKSZ;
			SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str,
			    "UOBJ ADD: Increasing uobj table size to %d",
			    newsz);

			p = kmem_zalloc(newsz * sizeof (*p), KM_NOSLEEP);
			if (!p) {
				SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
				    "UOBJ ADD: Mem alloc fail\n");
				rw_exit(&uo_tbl->uobj_tbl_lock);
				return (1);
			}

			if (uo_tbl->uobj_tbl_uo_root) {
				uint_t	oldsz;

				oldsz = (uint_t)uo_tbl->uobj_tbl_num_blks *
				    (int)(sizeof (*p));
				bcopy(uo_tbl->uobj_tbl_uo_root, p, oldsz);
				kmem_free(uo_tbl->uobj_tbl_uo_root, oldsz);
			}
			uo_tbl->uobj_tbl_uo_root = p;
			uo_tbl->uobj_tbl_num_blks = newsz;
		}
		empty = uo_tbl->uobj_tbl_used_blks;
		uo_tbl->uobj_tbl_used_blks++;
	}

	/*
	 * There are enough free block pointers in the root, allocate
	 * a new block.
	 */
	blk = kmem_zalloc(sizeof (*blk), KM_NOSLEEP);
	if (!blk) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ ADD: Mem alloc fail\n");
		rw_exit(&uo_tbl->uobj_tbl_lock);
		return (1);
	}
	ASSERT(uo_tbl->uobj_tbl_uo_root[empty] == NULL);
	uo_tbl->uobj_tbl_uo_root[empty] = blk;
	blk->ofs_uo_blk_avail = SOL_OFS_UO_BLKSZ - 1;

	/*
	 * Use the first slot in this new block to add the new user object.
	 */
	uobj->uo_id = empty * SOL_OFS_UO_BLKSZ;
	blk->ofs_uoblk_blks[0] = uobj;
	uobj->uo_uobj_sz = uo_tbl->uobj_tbl_uo_sz;
	uo_tbl->uobj_tbl_uo_cnt++;

obj_added:
	rw_exit(&uo_tbl->uobj_tbl_lock);
	return (0);
}

/*
 * Function:
 *	sol_ofs_uobj_remove
 * Input:
 *	uo_tbl	- A pointer to the user object resource management table
 *		  from which the object should be removed.
 *	uobj    - A pointer ot the user object to be removed.
 * Output:
 *	None
 * Returns:
 *	A pointer to the user object that was removed on success, otherwise
 *	NULL.
 * Description:
 * 	Remove a user object from the specified user resource management
 *	table.
 *
 *	The uobj uo_lock must be held as a writer before calling this.
 */
sol_ofs_uobj_t *
sol_ofs_uobj_remove(sol_ofs_uobj_table_t *uo_tbl, sol_ofs_uobj_t *uobj)
{
	uint_t			i, j;
	sol_ofs_uobj_blk_t	*blk;
	sol_ofs_uobj_t		*p;

	ASSERT(uo_tbl != NULL);
	ASSERT(uobj != NULL);

	p = NULL;
	rw_enter(&uo_tbl->uobj_tbl_lock, RW_WRITER);

	if (!uobj->uo_live) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ REMOVE: object 0x%P, already removed", (void *)uobj);
		goto remove_done;
	}

	if ((uo_tbl->uobj_tbl_uo_cnt == 0) || !(uo_tbl->uobj_tbl_uo_root)) {
		/*
		 * The table is empty, just return not found
		 * Don't panic, userland app could have double free'd
		 * let them deal with it.
		 */
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ REMOVE: table 0x%P empty", (void *)uo_tbl);
		goto remove_done;
	}

	i = uobj->uo_id / SOL_OFS_UO_BLKSZ;
	j = uobj->uo_id % SOL_OFS_UO_BLKSZ;

	if (i >= uo_tbl->uobj_tbl_used_blks) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ REMOVE: object id %d exceeds table size",
		    uobj->uo_id);
		goto remove_done;
	}

	ASSERT(i < uo_tbl->uobj_tbl_num_blks);

	blk = uo_tbl->uobj_tbl_uo_root[i];
	if (blk == NULL) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ REMOVE: object id %d points to invalid root",
		    uobj->uo_id);
		goto remove_done;
	}

	if (blk->ofs_uoblk_blks[j] == NULL) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ REMOVE: object id %d points to invalid block",
		    uobj->uo_id);
		goto remove_done;
	}

	/*
	 * Mark as dead
	 */
	uobj->uo_live = 0;

	p = blk->ofs_uoblk_blks[j];
	blk->ofs_uoblk_blks[j] = NULL;
	blk->ofs_uo_blk_avail++;
	if (blk->ofs_uo_blk_avail == SOL_OFS_UO_BLKSZ) {
		kmem_free(blk, sizeof (*blk));
		uo_tbl->uobj_tbl_uo_root[i] = NULL;
	}
	uo_tbl->uobj_tbl_uo_cnt--;

remove_done:
	rw_exit(&uo_tbl->uobj_tbl_lock);
	return (p);
}

/*
 * Function:
 *	ofs_uobj_find
 * Input:
 *	uo_tbl	- A pointer to the user object resource management table
 *		  to be used for the lookup.
 *	uo_id	- The user object ID to lookup.  This ID was set when
 *		  the object was added to the resource management table.
 *	add_ref	- A non zero value indicates that the user objects reference
 *		  count should be updated to reflect and additional
 *		  reference before it is returned.
 * Output:
 *	None
 * Returns:
 *	A pointer to the user object associated with the uo_id if found,
 *	otherwise NULL.
 * Description:
 * 	Lookup and return a user object from the specified user resource
 *	management table.
 */
static sol_ofs_uobj_t *
ofs_uobj_find(sol_ofs_uobj_table_t *uo_tbl, uint32_t uo_id, int add_ref)
{
	uint32_t		i, j;
	sol_ofs_uobj_blk_t	*blk;
	sol_ofs_uobj_t		*uobj;

	ASSERT(uo_tbl != NULL);
	uobj = NULL;

	rw_enter(&uo_tbl->uobj_tbl_lock, RW_READER);

	if ((uo_tbl->uobj_tbl_uo_cnt == 0) || !(uo_tbl->uobj_tbl_uo_root)) {
		/*
		 * The table is empty, just return not found
		 * Don't panic, userland app could have double free'd
		 * let them deal with it.
		 */
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ FIND: id %d in tbl 0x%P - tbl empty", uo_id,
		    (void *)uo_tbl);
		goto find_done;
	}

	i = uo_id / SOL_OFS_UO_BLKSZ;
	j = uo_id % SOL_OFS_UO_BLKSZ;

	if (i >= uo_tbl->uobj_tbl_used_blks) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ FIND: Index not valid, %d", uo_id);
		goto find_done;
	}

	/*
	 * Get the user object, and if valid perform a get (ref++).
	 * The caller issuing the find, must release the reference
	 * when done.
	 */
	blk = uo_tbl->uobj_tbl_uo_root[i];
	if (blk != NULL) {
		ASSERT(i < uo_tbl->uobj_tbl_num_blks);

		uobj = blk->ofs_uoblk_blks[j];

		if (uobj == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
			    "UOBJ FIND: Index %d not found, blk = %p",
			    uo_id, blk->ofs_uoblk_blks[j]);
		} else if (add_ref) {
			sol_ofs_uobj_ref(uobj);
		}
	} else {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "UOBJ FIND: Uobject not found, %d", uo_id);
		goto find_done;
	}

find_done:
	rw_exit(&uo_tbl->uobj_tbl_lock);
	return (uobj);
}

/*
 * Function:
 *	sol_ofs_uobj_get_read
 * Input:
 *	tbl         - Pointer to the user object managment table to
 *	              be used in the lookup.
 *	uo_id       - The ID to object mapping, assigned to the user
 *	              object at addition to the table.
 * Ouput:
 *	None
 * Returns:
 * 	A pointer to the user object associated with uo_id or NULL
 *      if the entry does not exist.
 * Description:
 *	Lookup a user object and place a reference on it.  Acquires
 *	the object with a READ lock.  The reference and lock should
 *	be released using the sol_ofs_uobj_put() call.
 */
sol_ofs_uobj_t *
sol_ofs_uobj_get_read(sol_ofs_uobj_table_t *tbl, uint32_t uo_id)
{
	sol_ofs_uobj_t *uobj;

	uobj = ofs_uobj_find(tbl, uo_id, 1);
	if (!uobj)
		return (NULL);

	rw_enter(&uobj->uo_lock, RW_READER);

	/*
	 * If object was destroyed before we got the lock, just release
	 * our reference and indicate we didn't find the object.
	 */
	if (!uobj->uo_live) {
		sol_ofs_uobj_put(uobj);
		return (NULL);
	}
	return (uobj);
}

/*
 * Function:
 *	sol_ofs_uobj_get_write
 * Input:
 *	tbl         - Pointer to the user object managment table to
 *	              be used in the lookup.
 *	uo_id       - The ID to object mapping, assigned to the user
 *	              object at addition to the table.
 * Ouput:
 *	None
 * Returns:
 * 	A pointer to the user object associated with uo_id or NULL
 *      if the entry does not exist.
 * Description:
 *	Lookup a user object and place a reference on it.  Acquires
 *	the object with a WRITE lock.  The reference and lock should
 *	be released using the sol_ofs_uobj_put() call.
 */
sol_ofs_uobj_t *
sol_ofs_uobj_get_write(sol_ofs_uobj_table_t *tbl, uint32_t uo_id)
{
	sol_ofs_uobj_t *uobj;


	uobj = ofs_uobj_find(tbl, uo_id, 1);
	if (!uobj)
		return (NULL);

	rw_enter(&uobj->uo_lock, RW_WRITER);

	/*
	 * If object was destroyed before we got the lock, just release
	 * our reference and indicate we didn't find the object.
	 */
	if (!uobj->uo_live) {
		sol_ofs_uobj_put(uobj);
		return (NULL);
	}
	return (uobj);
}

/*
 * Function:
 *	sol_ofs_uobj_free
 * Input:
 *	uobj	-  A pointer to the Solaris User Verbs kernel agent user
 *	           object to be freed.
 * Output:
 *	None.
 * Returns:
 *	None.
 * Description:
 * 	Called when the user object is no longer referenced, it will release
 *	any user object resources and free the container object memory.
 *	NOTE: Currently there is a stipulation that the user object be the
 *	first element of any user object specialization.
 */
void
sol_ofs_uobj_free(sol_ofs_uobj_t *uobj)
{
	size_t	sz;

	ASSERT(uobj);

	/*
	 * Cleanup common user object and then free memory using
	 * length based on associated object type.
	 */
	ofs_uobj_fini(uobj);

	sz = uobj->uo_uobj_sz;
	if (sz)
		kmem_free(uobj, sz);
}

/*
 * Function:
 *	sol_ofs_uobj_put
 * Input:
 * 	uobj        - Pointer to the user object
 * Ouput:
 *	None
 * Returns:
 * 	None
 * Description:
 *	Remove a lock associated with a user object, and decrement
 *	the reference held. On the last deference the user object
 *	will be freed.
 */
void
sol_ofs_uobj_put(sol_ofs_uobj_t *uobj)
{
	rw_exit(&uobj->uo_lock);
	sol_ofs_uobj_deref(uobj, sol_ofs_uobj_free);
}
