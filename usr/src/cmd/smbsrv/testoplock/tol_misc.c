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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * A few excerpts from smb_kutil.c
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/stddef.h>
#include <smbsrv/smb_kproto.h>


/*
 * smb_llist_constructor
 *
 * This function initializes a locked list.
 */
void
smb_llist_constructor(
    smb_llist_t	*ll,
    size_t	size,
    size_t	offset)
{
	rw_init(&ll->ll_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&ll->ll_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&ll->ll_list, size, offset);
	list_create(&ll->ll_deleteq, sizeof (smb_dtor_t),
	    offsetof(smb_dtor_t, dt_lnd));
	ll->ll_count = 0;
	ll->ll_wrop = 0;
	ll->ll_deleteq_count = 0;
	ll->ll_flushing = B_FALSE;
}

/*
 * Flush the delete queue and destroy a locked list.
 */
void
smb_llist_destructor(
    smb_llist_t	*ll)
{
	/* smb_llist_flush(ll); */

	ASSERT(ll->ll_count == 0);
	ASSERT(ll->ll_deleteq_count == 0);

	rw_destroy(&ll->ll_lock);
	list_destroy(&ll->ll_list);
	list_destroy(&ll->ll_deleteq);
	mutex_destroy(&ll->ll_mutex);
}

void
smb_llist_enter(smb_llist_t *ll, krw_t mode)
{
	rw_enter(&ll->ll_lock, mode);
}

/*
 * Exit the list lock and process the delete queue.
 */
void
smb_llist_exit(smb_llist_t *ll)
{
	rw_exit(&ll->ll_lock);
	/* smb_llist_flush(ll); */
}

/*
 * smb_llist_upgrade
 *
 * This function tries to upgrade the lock of the locked list. It assumes the
 * locked has already been entered in RW_READER mode. It first tries using the
 * Solaris function rw_tryupgrade(). If that call fails the lock is released
 * and reentered in RW_WRITER mode. In that last case a window is opened during
 * which the contents of the list may have changed. The return code indicates
 * whether or not the list was modified when the lock was exited.
 */
int smb_llist_upgrade(
    smb_llist_t *ll)
{
	uint64_t	wrop;

	if (rw_tryupgrade(&ll->ll_lock) != 0) {
		return (0);
	}
	wrop = ll->ll_wrop;
	rw_exit(&ll->ll_lock);
	rw_enter(&ll->ll_lock, RW_WRITER);
	return (wrop != ll->ll_wrop);
}

/*
 * smb_llist_insert_head
 *
 * This function inserts the object passed a the beginning of the list. This
 * function assumes the lock of the list has already been entered.
 */
void
smb_llist_insert_head(
    smb_llist_t	*ll,
    void	*obj)
{
	list_insert_head(&ll->ll_list, obj);
	++ll->ll_wrop;
	++ll->ll_count;
}

/*
 * smb_llist_insert_tail
 *
 * This function appends to the object passed to the list. This function assumes
 * the lock of the list has already been entered.
 *
 */
void
smb_llist_insert_tail(
    smb_llist_t	*ll,
    void	*obj)
{
	list_insert_tail(&ll->ll_list, obj);
	++ll->ll_wrop;
	++ll->ll_count;
}

/*
 * smb_llist_remove
 *
 * This function removes the object passed from the list. This function assumes
 * the lock of the list has already been entered.
 */
void
smb_llist_remove(
    smb_llist_t	*ll,
    void	*obj)
{
	list_remove(&ll->ll_list, obj);
	++ll->ll_wrop;
	--ll->ll_count;
}

/*
 * smb_llist_get_count
 *
 * This function returns the number of elements in the specified list.
 */
uint32_t
smb_llist_get_count(
    smb_llist_t *ll)
{
	return (ll->ll_count);
}
