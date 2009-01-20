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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *
 * MODULE: udat.c
 *
 * PURPOSE: DAT Provider and Consumer registry functions.
 *
 * $Id: udat.c,v 1.13 2003/08/20 14:28:40 hobie16 Exp $
 */

#include <dat/udat.h>
#include <dat/dat_registry.h> /* Provider API function prototypes */

#include "dat_dr.h"
#include "dat_init.h"
#include "dat_osd.h"
#ifndef	DAT_NO_STATIC_REGISTRY
#include "dat_sr.h"
#endif


#define	UDAT_IS_BAD_POINTER(p) (NULL == (p))

/*
 *
 * Internal Function Declarations
 *
 */

DAT_BOOLEAN
udat_check_state(void);


/*
 *
 * External Function Definitions
 *
 */


/*
 *
 * Provider API
 *
 */


/*
 * Function: dat_registry_add_provider
 */

DAT_RETURN
dat_registry_add_provider(
	IN DAT_PROVIDER			*provider,
	IN const DAT_PROVIDER_INFO	*provider_info)
{
	DAT_DR_ENTRY 		entry;

	dat_os_dbg_print(DAT_OS_DBG_TYPE_PROVIDER_API,
	    "DAT Registry: dat_registry_add_provider() called\n");

	if (UDAT_IS_BAD_POINTER(provider)) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1));
	}

	if (UDAT_IS_BAD_POINTER(provider_info)) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2));
	}

	if (DAT_FALSE == udat_check_state()) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	entry.ref_count = 0;
	entry.ia_open_func = provider->ia_open_func;
	entry.info = *provider_info;

	return (dat_dr_insert(provider_info, &entry));
}


/*
 * Function: dat_registry_remove_provider
 */

DAT_RETURN
dat_registry_remove_provider(
	IN DAT_PROVIDER 		*provider,
	IN  const DAT_PROVIDER_INFO	*provider_info)
{
	dat_os_dbg_print(DAT_OS_DBG_TYPE_PROVIDER_API,
	    "DAT Registry: dat_registry_remove_provider() called\n");

	if (UDAT_IS_BAD_POINTER(provider)) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1));
	}

	if (DAT_FALSE == udat_check_state()) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	return (dat_dr_remove(provider_info));
}


/*
 *
 * Consumer API
 *
 */

/*
 * Function: dat_ia_open
 */

DAT_RETURN
dat_ia_openv(
	IN	const DAT_NAME_PTR	name,
	IN	DAT_COUNT		async_event_qlen,
	INOUT	DAT_EVD_HANDLE		*async_event_handle,
	OUT	DAT_IA_HANDLE		*ia_handle,
	IN	DAT_UINT32		dapl_major,
	IN	DAT_UINT32		dapl_minor,
	IN	DAT_BOOLEAN		thread_safety)
{
	DAT_IA_OPEN_FUNC		ia_open_func;
	DAT_PROVIDER_INFO 		info;
	DAT_RETURN 			status;
	DAT_OS_SIZE 			len;
#define	RO_AWARE_PREFIX	"RO_AWARE_"
	boolean_t			ro_aware_client;
	const char			*_name = name;

	dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
	    "DAT Registry: dat_ia_open() called\n");

	if (UDAT_IS_BAD_POINTER(_name)) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1));
	}

	len = dat_os_strlen(_name);

	if (DAT_NAME_MAX_LENGTH <= len) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1));
	}

	if (UDAT_IS_BAD_POINTER(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}

	if (DAT_FALSE == udat_check_state()) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	/* Find out if this is an RO aware client and if so, strip the prefix */
	ro_aware_client =
	    (strncmp(RO_AWARE_PREFIX, _name, sizeof (RO_AWARE_PREFIX) - 1) ==
	    0);

	/* strip off the prefix from the provider's name if present */
	if (ro_aware_client) {
		_name = _name + sizeof (RO_AWARE_PREFIX) - 1;
		len -= sizeof (RO_AWARE_PREFIX) - 1;
	}

	(void) dat_os_strncpy(info.ia_name, _name, len);
	info.ia_name[len] = '\0';

	info.dapl_version_major = dapl_major;
	info.dapl_version_minor = dapl_minor;
	info.is_thread_safe = thread_safety;

	/*
	 * Since DAT allows providers to be loaded by either the static
	 * registry or explicitly through OS dependent methods, do not
	 * return an error if no providers are loaded via the static registry.
	 * Don't even bother calling the static registry if DAT is compiled
	 * with no static registry support.
	 */

#ifndef DAT_NO_STATIC_REGISTRY
	(void) dat_sr_provider_open(&info);
#endif

	status = dat_dr_provider_open(&info, &ia_open_func);
	if (status != DAT_SUCCESS) {
		dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
		    "DAT Registry: dat_ia_open() provider information "
		    "for IA name %s not found in dynamic registry\n",
		    _name);
		return (status);
	}

	return (*ia_open_func)((const DAT_NAME_PTR) _name,
	    async_event_qlen,
	    async_event_handle,
	    ia_handle,
	    ro_aware_client);
}


/*
 * Function: dat_ia_close
 */

DAT_RETURN
dat_ia_close(
	IN DAT_IA_HANDLE	ia_handle,
	IN DAT_CLOSE_FLAGS	ia_flags)
{
	DAT_PROVIDER	*provider;
	DAT_PROVIDER_ATTR   provider_attr = {0};
	DAT_RETURN 		status;
	const char 		*ia_name;

	dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
	    "DAT Registry: dat_ia_close() called\n");

	if (UDAT_IS_BAD_POINTER(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}

	if (DAT_FALSE == udat_check_state()) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	provider = DAT_HANDLE_TO_PROVIDER(ia_handle);
	ia_name = provider->device_name;

	if (DAT_SUCCESS != (status = dat_ia_query(ia_handle,
	    NULL,
	    0,
	    NULL,
	    DAT_PROVIDER_FIELD_ALL,
	    &provider_attr))) {
		dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
		    "DAT Registry: query function for %s provider failed\n",
		    ia_name);
	} else if (DAT_SUCCESS != (status =
	    (*provider->ia_close_func)(ia_handle, ia_flags))) {
		dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
		    "DAT Registry: close function for %s provider failed\n",
		    ia_name);
	} else {
		DAT_PROVIDER_INFO info;
		DAT_OS_SIZE len;

		len = dat_os_strlen(ia_name);

		dat_os_assert(len <= DAT_NAME_MAX_LENGTH);

		(void) dat_os_strncpy(info.ia_name, ia_name, len);
		info.ia_name[len] = '\0';

		info.dapl_version_major = provider_attr.dapl_version_major;
		info.dapl_version_minor = provider_attr.dapl_version_minor;
		info.is_thread_safe = provider_attr.is_thread_safe;

		status = dat_dr_provider_close(&info);
		if (DAT_SUCCESS != status) {
			dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
			    "DAT Registry: dynamic registry unable to close "
			    "provider for IA name %s\n",
			    ia_name);
		}

#ifndef DAT_NO_STATIC_REGISTRY
		status = dat_sr_provider_close(&info);
		if (DAT_SUCCESS != status) {
			dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
			    "DAT Registry: static registry unable to close "
			    "provider for IA name %s\n",
			    ia_name);
		}
#endif
	}

	return (status);
}


/*
 * Function: dat_registry_list_providers
 */

DAT_RETURN
dat_registry_list_providers(
	IN  DAT_COUNT   		max_to_return,
	    OUT DAT_COUNT   		*entries_returned,
	    OUT	DAT_PROVIDER_INFO 	*(dat_provider_list[]))
{
	DAT_RETURN	dat_status;

	dat_status = DAT_SUCCESS;
	dat_os_dbg_print(DAT_OS_DBG_TYPE_CONSUMER_API,
	    "DAT Registry: dat_registry_list_providers() called\n");

	if (DAT_FALSE == udat_check_state()) {
			return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	if ((UDAT_IS_BAD_POINTER(entries_returned))) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2));
	}

	if (0 != max_to_return && (UDAT_IS_BAD_POINTER(dat_provider_list))) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3));
	}

	if (0 == max_to_return) {
		/*
		 * the user is allowed to call with max_to_return set to zero.
		 * in which case we simply return (in *entries_returned) the
		 * number of providers currently installed.  We must also
		 * (per spec) return an error
		 */
#ifndef DAT_NO_STATIC_REGISTRY
		(void) dat_sr_size(entries_returned);
#else
		(void) dat_dr_size(entries_returned);
#endif
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1));
	} else {
#ifndef DAT_NO_STATIC_REGISTRY
		dat_status = dat_sr_list(max_to_return,
		    entries_returned,
		    dat_provider_list);
#else
		dat_status = dat_dr_list(max_to_return,
		    entries_returned,
		    dat_provider_list);
#endif
	}
	return (dat_status);
}


/*
 *
 * Internal Function Definitions
 *
 */


/*
 * Function: udat_check_state
 */

/*
 * This function returns TRUE if the DAT registry is in a state capable
 * of handling DAT API calls and false otherwise.
 */

DAT_BOOLEAN
udat_check_state(void)
{
	DAT_MODULE_STATE 		state;
	DAT_BOOLEAN 		status;

	state = dat_module_get_state();

	if (DAT_MODULE_STATE_UNINITIALIZED == state) {
		dat_init();
		status = DAT_TRUE;
	} else if (DAT_MODULE_STATE_DEINITIALIZED == state) {
		status = DAT_FALSE;
	} else {
		status = DAT_TRUE;
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
