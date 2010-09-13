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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * MODULE: dat_dr.c
 *
 * PURPOSE: dynamic registry implementation
 *
 * $Id: dat_dr.c,v 1.12 2003/08/20 14:28:40 hobie16 Exp $
 */


#include "dat_dr.h"

#include "dat_dictionary.h"


/*
 *
 * Global Variables
 *
 */

static DAT_OS_LOCK 		g_dr_lock;
static DAT_DICTIONARY 		*g_dr_dictionary = NULL;


/*
 *
 * External Functions
 *
 */


/*
 * Function: dat_dr_init
 */

DAT_RETURN
dat_dr_init(void)
{
	DAT_RETURN 	status;

	status = dat_os_lock_init(&g_dr_lock);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	status = dat_dictionary_create(&g_dr_dictionary);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	return (DAT_SUCCESS);
}


/*
 * Function: dat_dr_fini
 */

DAT_RETURN
dat_dr_fini(void)
{
	DAT_RETURN 			status;

	status = dat_os_lock_destroy(&g_dr_lock);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	status = dat_dictionary_destroy(g_dr_dictionary);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	return (DAT_SUCCESS);
}


/*
 * Function: dat_dr_insert
 */

extern DAT_RETURN
dat_dr_insert(
    IN  const DAT_PROVIDER_INFO *info,
    IN  DAT_DR_ENTRY 		*entry)
{
	DAT_RETURN 		status;
	DAT_DICTIONARY_ENTRY 	dict_entry;
	DAT_DR_ENTRY		*data;

	data = dat_os_alloc(sizeof (DAT_DR_ENTRY));
	if (NULL == data) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	*data = *entry;

	dict_entry = NULL;
	status = dat_dictionary_entry_create(&dict_entry);
	if (DAT_SUCCESS != status) {
		goto bail;
	}

	dat_os_lock(&g_dr_lock);

	status = dat_dictionary_insert(g_dr_dictionary,
		dict_entry,
		info,
		(DAT_DICTIONARY_DATA *) data);

	dat_os_unlock(&g_dr_lock);

bail:
	if (DAT_SUCCESS != status) {
		if (NULL != data) {
			dat_os_free(data, sizeof (DAT_DR_ENTRY));
		}


		if (NULL != dict_entry) {
			(void) dat_dictionary_entry_destroy(dict_entry);
		}
	}

	return (status);
}


/*
 * Function: dat_dr_remove
 */

extern DAT_RETURN
dat_dr_remove(
    IN  const DAT_PROVIDER_INFO *info)
{
	DAT_DR_ENTRY 		*data;
	DAT_DICTIONARY_ENTRY 	dict_entry;
	DAT_RETURN 		status;

	dat_os_lock(&g_dr_lock);

	status = dat_dictionary_search(g_dr_dictionary,
	    info,
	    (DAT_DICTIONARY_DATA *) &data);

	if (DAT_SUCCESS != status) {
		/* return status from dat_dictionary_search() */
		goto bail;
	}

	if (0 != data->ref_count) {
		status = DAT_ERROR(DAT_PROVIDER_IN_USE, 0);
		goto bail;
	}

	dict_entry = NULL;
	status = dat_dictionary_remove(g_dr_dictionary,
	    &dict_entry,
	    info,
	    (DAT_DICTIONARY_DATA *) &data);

	if (DAT_SUCCESS != status) {
		/* return status from dat_dictionary_remove() */
		goto bail;
	}

	dat_os_free(data, sizeof (DAT_DR_ENTRY));

bail:
	dat_os_unlock(&g_dr_lock);

	if (NULL != dict_entry) {
		(void) dat_dictionary_entry_destroy(dict_entry);
	}

	return (status);
}


/*
 * Function: dat_dr_provider_open
 */

extern DAT_RETURN
dat_dr_provider_open(
    IN  const DAT_PROVIDER_INFO *info,
    OUT DAT_IA_OPEN_FUNC	*p_ia_open_func)
{
	DAT_RETURN 		status;
	DAT_DR_ENTRY 		*data;

	dat_os_lock(&g_dr_lock);

	status = dat_dictionary_search(g_dr_dictionary,
				info,
				(DAT_DICTIONARY_DATA *) &data);

	dat_os_unlock(&g_dr_lock);

	if (DAT_SUCCESS == status) {
		data->ref_count++;
		*p_ia_open_func = data->ia_open_func;
	}

	return (status);
}


/*
 * Function: dat_dr_provider_close
 */

extern DAT_RETURN
dat_dr_provider_close(
    IN  const DAT_PROVIDER_INFO *info)
{
	DAT_RETURN 		status;
	DAT_DR_ENTRY 		*data;

	dat_os_lock(&g_dr_lock);

	status = dat_dictionary_search(g_dr_dictionary,
	    info,
	    (DAT_DICTIONARY_DATA *) &data);

	dat_os_unlock(&g_dr_lock);

	if (DAT_SUCCESS == status) {
		data->ref_count--;
	}

	return (status);
}


/*
 * Function: dat_dr_size
 */

DAT_RETURN
dat_dr_size(
    OUT	DAT_COUNT		*size)
{
	return (dat_dictionary_size(g_dr_dictionary, size));
}


/*
 * Function: dat_dr_list
 */

DAT_RETURN
dat_dr_list(
    IN  DAT_COUNT		max_to_return,
    OUT DAT_COUNT		*entries_returned,
    OUT DAT_PROVIDER_INFO	* (dat_provider_list[]))
{
	DAT_DR_ENTRY		**array;
	DAT_COUNT 		array_size;
	DAT_COUNT 		i;
	DAT_RETURN 		status;

	array = NULL;
	status = DAT_SUCCESS;

	/*
	 * The dictionary size may increase between the call to
	 * dat_dictionary_size() and dat_dictionary_enumerate().
	 * Therefore we loop until a successful enumeration is made.
	 */
	*entries_returned = 0;
	for (;;) {
		status = dat_dictionary_size(g_dr_dictionary, &array_size);
		if (status != DAT_SUCCESS) {
			goto bail;
		}

		if (array_size == 0) {
			status = DAT_SUCCESS;
			goto bail;
		}

		array = dat_os_alloc(array_size * sizeof (DAT_DR_ENTRY *));
		if (array == NULL) {
			status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
			    DAT_RESOURCE_MEMORY);
			goto bail;
		}

		dat_os_lock(&g_dr_lock);

		status = dat_dictionary_enumerate(g_dr_dictionary,
		    (DAT_DICTIONARY_DATA *) array,
		    array_size);

		dat_os_unlock(&g_dr_lock);

		if (DAT_SUCCESS == status) {
			break;
		} else {
			dat_os_free(array,
			    array_size * sizeof (DAT_DR_ENTRY *));
			array = NULL;
			continue;
		}
	}

	for (i = 0; (i < max_to_return) && (i < array_size); i++) {
		if (NULL == dat_provider_list[i]) {
			status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG3);
			goto bail;
		}

		*dat_provider_list[i] = array[i]->info;
	}

	*entries_returned = i;

bail:
	if (NULL != array) {
		dat_os_free(array, array_size * sizeof (DAT_DR_ENTRY *));
	}

	return (status);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
