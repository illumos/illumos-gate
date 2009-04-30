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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_ring_buffer_util.c
 *
 * PURPOSE: Ring buffer management
 * Description: Support and management functions for ring buffers
 *
 * $Id: dapl_ring_buffer_util.c,v 1.9 2003/07/08 14:23:35 sjs2 Exp $
 */

#include "dapl_ring_buffer_util.h"

/*
 * dapls_rbuf_alloc
 *
 * Given a DAPL_RING_BUFFER, initialize it and provide memory for
 * the ringbuf itself. A passed in size will be adjusted to the next
 * largest power of two number to simplify management.
 *
 * Input:
 *	rbuf		pointer to DAPL_RING_BUFFER
 *	size		number of elements to allocate & manage
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_rbuf_alloc(
	INOUT	DAPL_RING_BUFFER	*rbuf,
	IN	DAT_COUNT		 size)
{
	unsigned int			rsize;	/* real size */

	/*
	 * The circular buffer must be allocated one too large.
	 * This eliminates any need for a distinct counter, as that
	 * having the two pointers equal always means "empty" -- never "full"
	 */
	size++;

	/* Put size on a power of 2 boundary */
	rsize = 1;
	while ((DAT_COUNT)rsize < size) {
		rsize <<= 1;
	}

	rbuf->base = (void *) dapl_os_alloc(rsize * sizeof (void *));
	if (rbuf->base != NULL) {
		rbuf->lim = rsize - 1;
		rbuf->head = 0;
		rbuf->tail = 0;
		dapl_os_lock_init(&rbuf->lock);
	} else {
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}

	return (DAT_SUCCESS);
}


/*
 * dapls_rbuf_realloc
 *
 * Resizes an empty DAPL_RING_BUFFER. This function is not thread safe;
 * adding or removing elements from a ring buffer while resizing
 * will have indeterminate results.
 *
 * Input:
 *	rbuf		pointer to DAPL_RING_BUFFER
 *	size		number of elements to allocate & manage
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_STATE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_rbuf_realloc(
	INOUT	DAPL_RING_BUFFER	*rbuf,
	IN	DAT_COUNT		 size)
{
	int			rsize;		/* real size */
	DAT_RETURN		dat_status;

	dat_status = DAT_SUCCESS;

	/* if the ring buffer is not empty */
	if (rbuf->head != rbuf->tail) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE, 0);
		goto bail;
	}

	/* Put size on a power of 2 boundary */
	rsize = 1;
	while (rsize < size) {
		rsize <<= 1;
	}

	rbuf->base = (void *)dapl_os_realloc(rbuf->base,
	    rsize * sizeof (void *));
	if (NULL == rbuf->base) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	rbuf->lim = rsize - 1;

bail:
	return (dat_status);
}


/*
 * dapls_rbuf_destroy
 *
 * Release the buffer and reset pointers to a DAPL_RING_BUFFER
 *
 * Input:
 *	rbuf		pointer to DAPL_RING_BUFFER
 *
 * Output:
 *	none
 *
 * Returns:
 *	none
 *
 */
void
dapls_rbuf_destroy(
	IN  DAPL_RING_BUFFER		*rbuf)
{
	if ((NULL == rbuf) ||
	    (NULL == rbuf->base)) {
		return;
	}

	dapl_os_lock_destroy(&rbuf->lock);
	dapl_os_free(rbuf->base, (rbuf->lim + 1) * sizeof (void *));
	rbuf->base = NULL;
	rbuf->lim = 0;
}

/*
 * dapls_rbuf_add
 *
 * Add an entry to the ring buffer
 *
 * Input:
 *	rbuf		pointer to DAPL_RING_BUFFER
 *	entry		entry to add
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES         (queue full)
 *
 */
DAT_RETURN
dapls_rbuf_add(
	IN  DAPL_RING_BUFFER		*rbuf,
	IN  void			*entry)
{
	DAPL_ATOMIC		pos;

	dapl_os_lock(&rbuf->lock);
	pos = rbuf->head;
	if (((pos + 1) & rbuf->lim) != rbuf->tail) {
		rbuf->base[pos] = entry;
		rbuf->head = (pos + 1) & rbuf->lim;
		dapl_os_unlock(&rbuf->lock);
		return (DAT_SUCCESS);
	}

	dapl_os_unlock(&rbuf->lock);
	return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES, DAT_RESOURCE_MEMORY));
}


/*
 * dapls_rbuf_remove
 *
 * Remove an entry from the ring buffer
 *
 * Input:
 *	rbuf		pointer to DAPL_RING_BUFFER
 *
 * Output:
 *	entry		entry removed from the ring buffer
 *
 * Returns:
 *	a pointer to a buffer entry
 */
void *
dapls_rbuf_remove(
	IN  DAPL_RING_BUFFER	*rbuf)
{
	DAPL_ATOMIC		pos;

	dapl_os_lock(&rbuf->lock);
	if (rbuf->head != rbuf->tail) {
		pos = rbuf->tail;
		rbuf->tail = (pos + 1) & rbuf->lim;
		dapl_os_unlock(&rbuf->lock);
		return (rbuf->base[pos]);
	}

	dapl_os_unlock(&rbuf->lock);
	return (NULL);
}


/*
 * dapli_rbuf_count
 *
 * Return the number of entries in use in the ring buffer
 *
 * Input:
 *	rbuf		pointer to DAPL_RING_BUFFER
 *
 * Output:
 *	none
 *
 * Returns:
 *	count of entries
 *
 */
DAT_COUNT
dapls_rbuf_count(
	IN DAPL_RING_BUFFER *rbuf)
{
	int head;
	int tail;

	dapl_os_lock(&rbuf->lock);
	head = rbuf->head;
	tail = rbuf->tail;
	dapl_os_unlock(&rbuf->lock);
	if (head == tail)
		return (0);
	if (head > tail)
		return (head - tail);
	/* add 1 to lim as it is a mask, number of entries - 1 */
	return ((rbuf->lim + 1 - tail + head));
}
