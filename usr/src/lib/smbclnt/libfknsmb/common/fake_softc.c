
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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/sunddi.h>

#define	MIN_N_ITEMS	8

typedef struct i_ddi_soft_state {
	void		**array;	/* the array of pointers */
	kmutex_t	lock;		/* serialize access to this struct */
	size_t		size;		/* how many bytes per state struct */
	size_t		n_items;	/* how many structs herein */
	void		*next;		/* unused */
} i_ddi_soft_state;


void *
ddi_get_soft_state(void *state, int item)
{
	i_ddi_soft_state	*ss = (i_ddi_soft_state *)state;
	void *ret = NULL;

	ASSERT((ss != NULL) && (item >= 0));

	mutex_enter(&ss->lock);

	if (item < ss->n_items && ss->array != NULL)
		ret = ss->array[item];

	mutex_exit(&ss->lock);

	return (ret);
}


int
ddi_soft_state_init(void **state_p, size_t size, size_t n_items)
{
	i_ddi_soft_state	*ss;

	if (state_p == NULL || size == 0)
		return (EINVAL);

	ss = kmem_zalloc(sizeof (*ss), KM_SLEEP);
	mutex_init(&ss->lock, NULL, MUTEX_DRIVER, NULL);
	ss->size = size;

	if (n_items < MIN_N_ITEMS)
		ss->n_items = MIN_N_ITEMS;
	else {
		ss->n_items = n_items;
	}

	ASSERT(ss->n_items >= n_items);

	ss->array = kmem_zalloc(ss->n_items * sizeof (void *), KM_SLEEP);

	*state_p = ss;
	return (0);
}

/*
 * Allocate a state structure of size 'size' to be associated
 * with item 'item'.
 *
 * In this implementation, the array is extended to
 * allow the requested offset, if needed.
 */
int
ddi_soft_state_zalloc(void *state, int item)
{
	i_ddi_soft_state	*ss = (i_ddi_soft_state *)state;
	void			**array;
	void			*new_element;

	if ((state == NULL) || (item < 0))
		return (DDI_FAILURE);

	mutex_enter(&ss->lock);
	if (ss->size == 0) {
		mutex_exit(&ss->lock);
		cmn_err(CE_WARN, "ddi_soft_state_zalloc: bad handle: %s",
		    "fake");
		return (DDI_FAILURE);
	}

	array = ss->array;	/* NULL if ss->n_items == 0 */
	ASSERT(ss->n_items != 0 && array != NULL);

	/*
	 * refuse to tread on an existing element
	 */
	if (item < ss->n_items && array[item] != NULL) {
		mutex_exit(&ss->lock);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate a new element to plug in
	 */
	new_element = kmem_zalloc(ss->size, KM_SLEEP);

	/*
	 * Check if the array is big enough, if not, grow it.
	 */
	if (item >= ss->n_items) {
		void			**new_array;
		size_t			new_n_items;

		/*
		 * Allocate a new array of the right length, copy
		 * all the old pointers to the new array, then
		 * if it exists at all, put the old array on the
		 * dirty list.
		 *
		 * Note that we can't kmem_free() the old array.
		 *
		 * Why -- well the 'get' operation is 'mutex-free', so we
		 * can't easily catch a suspended thread that is just about
		 * to dereference the array we just grew out of.  So we
		 * cons up a header and put it on a list of 'dirty'
		 * pointer arrays.  (Dirty in the sense that there may
		 * be suspended threads somewhere that are in the middle
		 * of referencing them).  Fortunately, we -can- garbage
		 * collect it all at ddi_soft_state_fini time.
		 */
		new_n_items = ss->n_items;
		while (new_n_items < (1 + item))
			new_n_items <<= 1;	/* double array size .. */

		ASSERT(new_n_items >= (1 + item));	/* sanity check! */

		new_array = kmem_zalloc(new_n_items * sizeof (void *),
		    KM_SLEEP);
		/*
		 * Copy the pointers into the new array
		 */
		bcopy(array, new_array, ss->n_items * sizeof (void *));

		/*
		 * Free the old array now.  Note that
		 * ddi_get_soft_state takes the mutex.
		 */
		kmem_free(ss->array, ss->n_items * sizeof (void *));

		ss->array = (array = new_array);
		ss->n_items = new_n_items;
	}

	ASSERT(array != NULL && item < ss->n_items && array[item] == NULL);

	array[item] = new_element;

	mutex_exit(&ss->lock);
	return (DDI_SUCCESS);
}

void
ddi_soft_state_free(void *state, int item)
{
	i_ddi_soft_state	*ss = (i_ddi_soft_state *)state;
	void			**array;
	void			*element;
	static char		msg[] = "ddi_soft_state_free:";

	if (ss == NULL) {
		cmn_err(CE_WARN, "%s null handle: %s",
		    msg, "fake");
		return;
	}

	element = NULL;

	mutex_enter(&ss->lock);

	if ((array = ss->array) == NULL || ss->size == 0) {
		cmn_err(CE_WARN, "%s bad handle: %s",
		    msg, "fake");
	} else if (item < 0 || item >= ss->n_items) {
		cmn_err(CE_WARN, "%s item %d not in range [0..%lu]: %s",
		    msg, item, (ulong_t)ss->n_items - 1, "fake");
	} else if (array[item] != NULL) {
		element = array[item];
		array[item] = NULL;
	}

	mutex_exit(&ss->lock);

	if (element)
		kmem_free(element, ss->size);
}

/*
 * Free the entire set of pointers, and any
 * soft state structures contained therein.
 *
 * Note that we don't grab the ss->lock mutex, even though
 * we're inspecting the various fields of the data structure.
 *
 * There is an implicit assumption that this routine will
 * never run concurrently with any of the above on this
 * particular state structure i.e. by the time the driver
 * calls this routine, there should be no other threads
 * running in the driver.
 */
void
ddi_soft_state_fini(void **state_p)
{
	i_ddi_soft_state	*ss;
	int			item;
	static char		msg[] = "ddi_soft_state_fini:";

	if (state_p == NULL ||
	    (ss = (i_ddi_soft_state *)(*state_p)) == NULL) {
		cmn_err(CE_WARN, "%s null handle: %s",
		    msg, "fake");
		return;
	}

	if (ss->size == 0) {
		cmn_err(CE_WARN, "%s bad handle: %s",
		    msg, "fake");
		return;
	}

	if (ss->n_items > 0) {
		for (item = 0; item < ss->n_items; item++)
			ddi_soft_state_free(ss, item);
		kmem_free(ss->array, ss->n_items * sizeof (void *));
	}

	mutex_destroy(&ss->lock);
	kmem_free(ss, sizeof (*ss));

	*state_p = NULL;
}
