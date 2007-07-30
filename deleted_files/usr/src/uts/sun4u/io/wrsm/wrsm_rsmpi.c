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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides RSMPI initialization/release functions
 * that are called by the RSMPI rsmops module.
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>

#include <sys/cmn_err.h>

/* Driver specific headers */
#include <sys/wrsm_rsmpi.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_barrier.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_transport.h>


#ifdef DEBUG
#define	WRSM_RSM_DEBUG	0x0001
static uint32_t wrsm_rsm_debug = 0;
#define	DPRINTF(a, b) { if (wrsm_rsm_debug & a) wrsmdprintf b; }
#else
#define	DPRINTF(a, b) { }
#endif

/* For pagesizes, nth bit being set means pagesizes of 2^n are supported */
#define	WRSM_ATTR_PAGESIZE_8K	0x8
#define	WRSM_ATTR_PAGESIZE_4M	0x1000
#define	WRSM_ATTR_PAGESIZES	(WRSM_ATTR_PAGESIZE_8K)

static int wrsmrsm_getv(rsm_controller_handle_t cp,
    rsmpi_scat_gath_t *sg_io);
static int wrsmrsm_putv(rsm_controller_handle_t cp,
    rsmpi_scat_gath_t *sg_io);

static rsm_ops_t wrsm_rsm_ops = {
	RSM_VERSION,		/* version 2.0 */
	wrsmrsm_seg_create,	/* seg create - export side */
	wrsmrsm_seg_destroy,	/* seg destroy - export side */
	wrsmrsm_bind,		/* rsm bind - export side */
	wrsmrsm_unbind,		/* rsm unbind - export side */
	wrsmrsm_rebind,		/* rsm rebind - export side */
	wrsmrsm_publish,	/* rsm publish - export side */
	wrsmrsm_unpublish,	/* rsm unpublish - export side */
	wrsmrsm_republish,	/* rsm republish - export side */
	wrsmrsm_connect,	/* rsm connect - import side */
	wrsmrsm_disconnect,	/* rsm disconnect - import side */
	wrsmrsm_get8,		/* get8 - import side read  */
	wrsmrsm_get16,		/* get16 - import side read */
	wrsmrsm_get32,		/* get32 - import side read  */
	wrsmrsm_get64,		/* get64 - import side read */
	wrsmrsm_get,		/* get - import side read */
	wrsmrsm_put8,		/* put8 - import write */
	wrsmrsm_put16,		/* put16 - import write */
	wrsmrsm_put32,		/* put32 - import write */
	wrsmrsm_put64,		/* put64 - import write */
	wrsmrsm_put,		/* put - import write */
	wrsmrsm_map,		/* map - import side */
	wrsmrsm_unmap,		/* unmap - import side */
	wrsm_open_barrier_region, /* open barrier region - import */
	wrsm_open_barrier_regions, /* open barrier regionS - import */
	wrsm_open_barrier_node,	/* open barrier node - import */
	wrsm_open_barrier_ctrl,	/* open barrier ctrl - import */
	wrsm_open_barrier_region_thr, /* open barrier region thread - import */
	wrsm_open_barrier_regions_thr, /* open barrier regionS thread import */
	wrsm_open_barrier_node_thr, /* open barrier node thread - import */
	wrsm_open_barrier_ctrl_thr, /* open barrier ctrl thread - import */
	wrsm_close_barrier,	/* close barrier - import */
	wrsm_reopen_barrier,	/* reopen barrier - import */
	wrsm_order_barrier,	/* order barrier - import */
	wrsm_thread_init,	/* thread init - import */
	wrsm_thread_fini,	/* thread fini - import */
	wrsm_get_barrier_mode,	/* get barrier mode - import */
	wrsm_set_barrier_mode,	/* set barrier mode - import */
	wrsm_sendq_create,	/* sendq create - sending side intr */
	wrsm_sendq_config,	/* sendq config - sending side intr */
	wrsm_sendq_destroy,	/* sendq destroy - sending side intr */
	wrsm_send,		/* send - sending side intr */
	wrsmrsm_register_handler,   /* register handler  - rcv side intr */
	wrsmrsm_unregister_handler, /* unregister handler - rcv side intr */
	wrsmrsm_getv,		/* getv */
	wrsmrsm_putv,		/* putv */
	wrsm_get_peers,		/* get node hardware addresses */
	NULL			/* rsm extension */
};

static rsm_controller_attr_t attr = {
	"Wildcat",		/* attr_name */
	0,			/* set at run time for each controller */
	0x40,			/* attr_direct_access_sizes */
	0x4F,			/* attr_atomic_sizes */
	0x2F,			/* attr_error_sizes */
	RSM_ERR_ZEROES,		/* attr_error_behavior */
	B_TRUE,			/* attr_mmu_protections */
	WRSM_ATTR_PAGESIZES,	/* attr_page_sizes */
	0,			/* set at run time for each controller */
	0,			/* set at run time for each controller */
	0x200000,		/* attr_max_export_segments - 2 Meg */
	0x2000000000,		/* attr_max_import_map_size -128 GB */
	0x36800000000,		/* attr_tot_import_map_size - 3.7 TB */
	0x1B400000,		/* attr_max_import_segments - 457 M */
	B_FALSE,		/* attr_io_space_exportable */
	B_FALSE,		/* attr_imported_space_ioable */
	B_TRUE,			/* attr_intr_sender_ident */
	WRSM_TL_MSG_SIZE - sizeof (uint64_t), /* attr_intr_data_size_max */
	8,			/* attr_intr_data_align */
	B_FALSE,		/* attr_intr_piggyback */
	B_FALSE			/* attr_resource_callbacks */
};


/*
 * returns the rsm_controller_handle_t and the wrsm_rsm_ops in controller
 */
/* ARGSUSED */
int
wrsmrsm_get_controller_handler(const char *name, uint_t number,
    rsm_controller_object_t *controller, uint_t version)
{
	DPRINTF(WRSM_RSM_DEBUG, (CE_CONT, "in wrsm_get_controller_handler"
	    " controller number %d, driver name %s", number, name));

	if (version != wrsm_rsm_ops.rsm_version) {
		DPRINTF(WRSM_RSM_DEBUG, (CE_CONT, "wrsm_get_controller_handler:"
		    " bad version %d != %d", version,
		    wrsm_rsm_ops.rsm_version));
		return (RSMERR_UNSUPPORTED_VERSION);
	}
	if (controller == NULL) {
		DPRINTF(WRSM_RSM_DEBUG, (CE_CONT, "wrsm_get_controller_handler:"
		    " controller is null"));
		return (RSMERR_BAD_CTLR_HNDL);
	}
	controller->handle =
	    (rsm_controller_handle_t)wrsm_nc_ctlr_to_network((uint32_t)number);
	if (controller->handle != NULL) {
		DPRINTF(WRSM_RSM_DEBUG, (CE_CONT, "wrsm_get_controller_handler:"
		    " found controller, setting ops"));
		controller->ops = &wrsm_rsm_ops;
		return (RSM_SUCCESS);
	} else {
		DPRINTF(WRSM_RSM_DEBUG, (CE_CONT, "wrsm_get_controller_handler:"
		    " no controler number %d, driver name %s", number, name));
		return (RSMERR_CTLR_NOT_PRESENT);
	}
}
/*
 * This functions doesn't currently do anything really important - yet
 * a controller must exist before this call.
 */
/* ARGSUSED */
int
wrsmrsm_release_controller_handler(const char *name, uint_t number,
    rsm_controller_object_t *controller)
{

	DPRINTF(WRSM_RSM_DEBUG, (CE_CONT,
	    "in wrsm_release_controller_handler"));
	/* we should not be trying to release a nonexistant controller */
	if (controller->handle == NULL) {
		return (RSMERR_BAD_CTLR_HNDL);
	}

	ASSERT(strcmp(name, "wrsm") == 0);
	controller->ops = NULL;
	controller->handle = NULL;
	return (RSM_SUCCESS);
}

/*
 * record the addr (cnodeid for this controller) in the
 */
void
wrsm_rsm_setup_controller_attr(wrsm_network_t *network)
{
	/* set fixed attribute values */
	network->attr = attr;
	/* set config specific values */
	DPRINTF(WRSM_RSM_DEBUG, (CE_CONT,
	    "in wrsm_rsm_setup_controller_addr - cnodeid is %ld",
	    (rsm_addr_t)network->cnodeid));
	network->attr.attr_controller_addr = (rsm_addr_t)network->cnodeid;
}

/* ARGSUSED */
static int
wrsmrsm_getv(rsm_controller_handle_t cp, rsmpi_scat_gath_t *sg_io)
{
	return (RSMERR_UNSUPPORTED_OPERATION);
}

/* ARGSUSED */
static int
wrsmrsm_putv(rsm_controller_handle_t cp, rsmpi_scat_gath_t *sg_io)
{
	return (RSMERR_UNSUPPORTED_OPERATION);
}
