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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * MODULE: dat_sr.c
 *
 * PURPOSE: static registry implementation
 *
 * $Id: dat_sr.c,v 1.12 2003/08/20 14:28:40 hobie16 Exp $
 */


#include "dat_sr.h"

#include "dat_dictionary.h"
#include "udat_sr_parser.h"


/*
 *
 * Global Variables
 *
 */

static DAT_OS_LOCK 		g_sr_lock;
static DAT_DICTIONARY 		*g_sr_dictionary = NULL;


/*
 *
 * External Functions
 *
 */


/*
 * Function: dat_sr_init
 */

DAT_RETURN
dat_sr_init(void)
{
	DAT_RETURN 			status;

	status = dat_os_lock_init(&g_sr_lock);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	status = dat_dictionary_create(&g_sr_dictionary);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	/*
	 * Since DAT allows providers to be loaded by either the static
	 * registry or explicitly through OS dependent methods, do not
	 * return an error if no providers are loaded via the static registry.
	 */

	(void) dat_sr_load();

	return (DAT_SUCCESS);
}


/*
 * Function: dat_sr_fini
 */

extern DAT_RETURN
dat_sr_fini(void)
{
	DAT_RETURN 			status;

	status = dat_os_lock_destroy(&g_sr_lock);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	status = dat_dictionary_destroy(g_sr_dictionary);
	if (DAT_SUCCESS != status) {
		return (status);
	}

	return (DAT_SUCCESS);
}


/*
 * Function: dat_sr_insert
 */

extern DAT_RETURN
dat_sr_insert(
    IN  const DAT_PROVIDER_INFO *info,
    IN  DAT_SR_ENTRY 		*entry)
{
	DAT_RETURN 		status;
	DAT_SR_ENTRY 		*data;
	DAT_OS_SIZE 		lib_path_size;
	DAT_OS_SIZE 		lib_path_len;
	DAT_OS_SIZE 		ia_params_size;
	DAT_OS_SIZE 		ia_params_len;
	DAT_DICTIONARY_ENTRY 	dict_entry;

	if (NULL == (data = dat_os_alloc(sizeof (DAT_SR_ENTRY)))) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	lib_path_len = strlen(entry->lib_path);
	lib_path_size = (lib_path_len + 1) * sizeof (char);

	if (NULL == (data->lib_path = dat_os_alloc(lib_path_size))) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dat_os_strncpy(data->lib_path, entry->lib_path, lib_path_len);
	data->lib_path[lib_path_len] = '\0';

	ia_params_len = strlen(entry->ia_params);
	ia_params_size = (ia_params_len + 1) * sizeof (char);

	if (NULL == (data->ia_params = dat_os_alloc(ia_params_size))) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dat_os_strncpy(data->ia_params, entry->ia_params, ia_params_len);
	data->ia_params[ia_params_len] = '\0';

	data->info = entry->info;
	data->lib_handle = entry->lib_handle;
	data->ref_count = entry->ref_count;

	dict_entry = NULL;
	status = dat_dictionary_entry_create(&dict_entry);
	if (DAT_SUCCESS != status) {
		goto bail;
	}

	dat_os_lock(&g_sr_lock);

	status = dat_dictionary_insert(g_sr_dictionary,
				dict_entry,
				info,
				(DAT_DICTIONARY_DATA *)data);
	dat_os_unlock(&g_sr_lock);

bail:
	if (DAT_SUCCESS != status) {
		if (NULL != data) {
			if (NULL != data->lib_path) {
				dat_os_free(data->lib_path, lib_path_size);
			}

			if (NULL != data->ia_params) {
				dat_os_free(data->ia_params, ia_params_size);
			}

			dat_os_free(data, sizeof (DAT_SR_ENTRY));
		}

		if (NULL != dict_entry) {
			(void) dat_dictionary_entry_destroy(dict_entry);
		}
	}

	return (status);
}


/*
 * Function: dat_sr_size
 */

extern DAT_RETURN
dat_sr_size(
    OUT DAT_COUNT		*size)
{
	return (dat_dictionary_size(g_sr_dictionary, size));
}


/*
 * Function: dat_sr_list
 */

extern DAT_RETURN
dat_sr_list(
    IN  DAT_COUNT		max_to_return,
    OUT DAT_COUNT		*entries_returned,
    OUT DAT_PROVIDER_INFO	* (dat_provider_list[]))
{
	DAT_SR_ENTRY		**array;
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
		status = dat_dictionary_size(g_sr_dictionary, &array_size);
		if (DAT_SUCCESS != status) {
			goto bail;
		}

		if (array_size == 0) {
			status = DAT_SUCCESS;
			goto bail;
		}

		array = dat_os_alloc(array_size * sizeof (DAT_SR_ENTRY *));
		if (array == NULL) {
			status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
			    DAT_RESOURCE_MEMORY);
			goto bail;
		}

		dat_os_lock(&g_sr_lock);

		status = dat_dictionary_enumerate(g_sr_dictionary,
				(DAT_DICTIONARY_DATA *) array,
				array_size);

		dat_os_unlock(&g_sr_lock);

		if (DAT_SUCCESS == status) {
			break;
		} else {
			dat_os_free(array,
			    array_size * sizeof (DAT_SR_ENTRY *));
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
		dat_os_free(array, array_size * sizeof (DAT_SR_ENTRY *));
	}

	return (status);
}



/*
 * Function: dat_sr_provider_open
 */

extern DAT_RETURN
dat_sr_provider_open(
    IN  const DAT_PROVIDER_INFO *info)
{
	DAT_RETURN 		status;
	DAT_SR_ENTRY 		*data;

	dat_os_lock(&g_sr_lock);

	status = dat_dictionary_search(g_sr_dictionary,
			info,
			(DAT_DICTIONARY_DATA *) &data);

	if (DAT_SUCCESS == status) {
		if (0 == data->ref_count) {
			status = dat_os_library_load(data->lib_path,
			    &data->lib_handle);
			if (status == DAT_SUCCESS) {
				data->ref_count++;
			} else {
				dat_os_dbg_print(DAT_OS_DBG_TYPE_SR,
				    "DAT Registry: static registry unable to "
				    "load library %s\n", data->lib_path);
				goto bail;
			}
			data->init_func = (DAT_PROVIDER_INIT_FUNC)
			    dat_os_library_sym(data->lib_handle,
				DAT_PROVIDER_INIT_FUNC_STR);
			data->fini_func = (DAT_PROVIDER_FINI_FUNC)
			    dat_os_library_sym(data->lib_handle,
				DAT_PROVIDER_FINI_FUNC_STR);

			if (NULL != data->init_func) {
				(*data->init_func)(&data->info,
				    data->ia_params);
			}
		} else {
			data->ref_count++;
		}
	}

bail:
	dat_os_unlock(&g_sr_lock);

	return (status);
}


/*
 * Function: dat_sr_provider_close
 */

extern DAT_RETURN
dat_sr_provider_close(
    IN  const DAT_PROVIDER_INFO *info)
{
	DAT_RETURN 		status;
	DAT_SR_ENTRY 		*data;

	dat_os_lock(&g_sr_lock);

	status = dat_dictionary_search(g_sr_dictionary,
			info,
			(DAT_DICTIONARY_DATA *)&data);

	if (DAT_SUCCESS == status) {
		if (1 == data->ref_count) {
			if (NULL != data->fini_func) {
				(*data->fini_func)(&data->info);
			}

			status = dat_os_library_unload(data->lib_handle);
			if (status == DAT_SUCCESS) {
				data->ref_count--;
			}
		} else {
			data->ref_count--;
		}
	}

	dat_os_unlock(&g_sr_lock);

	return (status);
}
