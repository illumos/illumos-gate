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
 * MODULE: dat_init.c
 *
 * PURPOSE: DAT registry implementation for uDAPL
 * Description: init and fini functions for DAT module.
 *
 * $Id: dat_init.c,v 1.12 2003/07/09 11:26:06 hobie16 Exp $
 */

#include "dat_init.h"

#include "dat_dr.h"
#include "dat_osd.h"

#ifndef DAT_NO_STATIC_REGISTRY
#include "dat_sr.h"
#endif


/*
 *
 * Global Variables
 *
 */

/*
 * Ideally, the following two rules could be enforced:
 *
 * - The DAT Registry's initialization function is executed before that
 *   of any DAT Providers and hence all calls into the registry occur
 *   after the registry module is initialized.
 *
 * - The DAT Registry's deinitialization function is executed after that
 *   of any DAT Providers and hence all calls into the registry occur
 *   before the registry module is deinitialized.
 *
 * However, on many platforms few guarantees are provided regarding the
 * order in which modules initialization and deinitialization functions
 * are invoked.
 *
 * To understand why these rules are difficult to enforce using only
 * features common to all platforms, consider the Linux platform. The order
 * in which Linux shared libraries are loaded into a process's address space
 * is undefined. When a DAT consumer explicitly links to DAT provider
 * libraries, the order in which library initialization and deinitialization
 * functions are invoked becomes important. For example if the DAPL provider
 * calls dat_registry_add_provider() before the registry has been initialized,
 * an error will occur.
 *
 * We assume that modules are loaded with a single thread. Given
 * this assumption, we can use a simple state variable to determine
 * the state of the DAT registry.
 */

static DAT_MODULE_STATE 	g_module_state = DAT_MODULE_STATE_UNINITIALIZED;


/*
 * Function: dat_module_get_state
 */

DAT_MODULE_STATE
dat_module_get_state(void)
{
	return (g_module_state);
}


/*
 *  Function: dat_init
 */

void
dat_init(void)
{
	if (DAT_MODULE_STATE_UNINITIALIZED == g_module_state) {
	/*
	 * update the module state flag immediately in case there
	 * is a recursive call to dat_init().
	 */
		g_module_state = DAT_MODULE_STATE_INITIALIZING;

		dat_os_dbg_init();

		dat_os_dbg_print(DAT_OS_DBG_TYPE_GENERIC,
		    "DAT Registry: Started (dat_init)\n");

#ifndef DAT_NO_STATIC_REGISTRY
		(void) dat_sr_init();
#endif
		(void) dat_dr_init();

		g_module_state = DAT_MODULE_STATE_INITIALIZED;
	}
}


/*
 * Function: dat_fini
 */

void
dat_fini(void)
{
	if (DAT_MODULE_STATE_INITIALIZED == g_module_state) {
		g_module_state = DAT_MODULE_STATE_DEINITIALIZING;

		(void) dat_dr_fini();
#ifndef DAT_NO_STATIC_REGISTRY
		(void) dat_sr_fini();
#endif
		dat_os_dbg_print(DAT_OS_DBG_TYPE_GENERIC,
		    "DAT Registry: Stopped (dat_fini)\n");

		g_module_state = DAT_MODULE_STATE_DEINITIALIZED;
	}
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
