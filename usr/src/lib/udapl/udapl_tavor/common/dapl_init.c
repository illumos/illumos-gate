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
 * MODULE: dapl_init.c
 *
 * PURPOSE: Interface Adapter management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 2
 *
 * $Id: dapl_init.c,v 1.42 2003/06/30 15:38:20 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_hca_util.h"
#include "dapl_init.h"
#include "dapl_provider.h"
#include "dapl_mr_util.h"
#include "dapl_osd.h"			/* needed for g_daplDebugLevel */
#include "dapl_adapter_util.h"
#include "dapl_name_service.h"
#include "dapl_vendor.h"

static void dapl_init(void);
static void dapl_fini(void);

#pragma init(dapl_init)
#pragma fini(dapl_fini)

/*
 * dapl_init
 *
 * initialize this provider
 * includes initialization of all global variables
 * as well as registering all supported IAs with the dat registry
 *
 * This function needs to be called once when the provider is loaded.
 *
 * Input:
 *	none
 *
 * Output:
 *	none
 *
 * Return Values:
 */
static void
dapl_init(void)
{
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, "DAPL: Started (dapl_init)\n");

#if defined(DAPL_DBG)
	/* set up debug type */
	g_dapl_dbg_type = dapl_os_get_env_val("DAPL_DBG_TYPE",
	    DAPL_DBG_TYPE_ERR | DAPL_DBG_TYPE_WARN);
	/* set up debug level */
	g_dapl_dbg_dest = dapl_os_get_env_val("DAPL_DBG_DEST",
	    DAPL_DBG_DEST_STDOUT);
#endif /* DAPL_DBG */

	/* See if the user is on a loopback setup */
	g_dapl_loopback_connection = dapl_os_get_env_bool("DAPL_LOOPBACK");
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, "DAPL: %s Setting Loopback\n",
	    g_dapl_loopback_connection ? "" : "NOT");

	dapls_ib_state_init();

	/* initialize the provider list */
	dat_status = dapl_provider_list_create();
	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapl_provider_list_create failed %d\n", dat_status);
		goto bail;
	}

	/* Set up name services */
	dat_status = dapls_ns_init();

	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "dapls_ns_init failed %d\n",
		    dat_status);
		goto bail;
	}

	return;

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_ERR, "ERROR: dapl_init failed\n");
	dapl_fini();
}

/*
 * dapl_fini
 *
 * finalize this provider
 * includes freeing of all global variables
 * as well as deregistering all supported IAs from the dat registry
 *
 * This function needs to be called once when the provider is loaded.
 *
 * Input:
 *	none
 *
 * Output:
 *	none
 *
 * Return Values:
 */
static void
dapl_fini(void)
{
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, "DAPL: Stopped (dapl_fini)\n");

	/*
	 * Free up hca related resources
	 */
	dapls_ib_state_fini();

	dat_status = dapl_provider_list_destroy();
	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapl_provider_list_destroy failed %d\n", dat_status);
	}
}

/*
 *
 * This function is called by the registry to initialize a provider
 *
 * The instance data string is expected to have the following form:
 *
 * <hca name> <port number>
 *
 */
/* ARGSUSED */
void
dat_provider_init(
    IN const DAT_PROVIDER_INFO 	*provider_info,
    IN const char 		*instance_data)
{
	DAT_PROVIDER		*provider;
	DAPL_HCA		*hca_ptr;
	DAT_RETURN		dat_status;

	provider = NULL;
	hca_ptr = NULL;

	dat_status = dapl_provider_list_insert(provider_info->ia_name,
	    &provider);
	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dat_provider_list_insert failed: %x\n", dat_status);
		goto bail;
	}

	hca_ptr = dapl_hca_alloc((char *)provider_info->ia_name, 0);
	if (NULL == hca_ptr) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	provider->extension = hca_ptr;

	/* register providers with dat_registry */
	dat_status = dat_registry_add_provider(provider, provider_info);
	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dat_registry_add_provider failed: %x\n", dat_status);
		goto bail;
	}

bail:
	if (DAT_SUCCESS != dat_status) {
		if (NULL != provider) {
			(void) dapl_provider_list_remove(
			    provider_info->ia_name);
		}

		if (NULL != hca_ptr) {
			dapl_hca_free(hca_ptr);
		}
	}
}


/*
 *
 * This function is called by the registry to de-initialize a provider
 *
 */
void
dat_provider_fini(
    IN const DAT_PROVIDER_INFO 	*provider_info)
{
	DAT_PROVIDER	*provider;
	DAT_RETURN	dat_status;

	dat_status = dapl_provider_list_search(provider_info->ia_name,
	    &provider);
	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dat_registry_add_provider failed: %x\n", dat_status);
		return;
	}

	dat_status = dat_registry_remove_provider(provider, provider_info);
	if (DAT_SUCCESS != dat_status) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dat_registry_add_provider failed: %x\n", dat_status);
	}

	(void) dapl_provider_list_remove(provider_info->ia_name);
}



/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
