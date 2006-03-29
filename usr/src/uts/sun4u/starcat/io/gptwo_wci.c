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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WCI Functions to the Safari Configurator
 *
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/autoconf.h>
#include <sys/ksynch.h>
#include <sys/promif.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/gp2cfg.h>
#include <sys/gptwo_wci.h>

#ifdef DEBUG
int gptwo_wci_debug = 0;

static void debug(char *, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

#define	GPTWO_DEBUG0(level, flag, s) if (gptwo_wci_debug >= level) \
    cmn_err(flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1) if (gptwo_wci_debug >= level) \
    debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2) if (gptwo_wci_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3) \
    if (gptwo_wci_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#else
#define	GPTWO_DEBUG0(level, flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1)
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2)
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3)
#endif

void gptwocfg_devi_attach_to_parent(dev_info_t *);

/*
 * Module linkage information for the kernel.
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"gptwo->wci configurator %I%",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

#ifndef	lint
char _depends_on[] = "misc/gptwocfg misc/fcgp2 misc/fcodem misc/busra";
#endif

int
_init(void)
{
	int err = 0;

	/* register devices with the configurator */
	gptwocfg_register_ops(SAFPTYPE_WCI, gptwo_configure_wci,
				gptwo_unconfigure_wci);

	if ((err = mod_install(&modlinkage)) != 0) {
		GPTWO_DEBUG1(1, CE_WARN, "gptwo_wci (WCI Functions) "
		"failed to load, error=%d\n", err);
		gptwocfg_unregister_ops(SAFPTYPE_WCI);
	} else {
		GPTWO_DEBUG0(1, CE_WARN, "gptwo_wci (WCI Functions) "
		"has been loaded.\n");
	}
	return (err);
}

int
_fini(void)
{
	gptwocfg_unregister_ops(SAFPTYPE_WCI);
	return (mod_remove(&modlinkage));
}

int
_info(modinfop)
struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
set_name_prop(dev_info_t *dip, void *arg, uint_t flags)
{
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "name", "wci") != DDI_SUCCESS) {
		return (DDI_WALK_ERROR);
	}

	return (DDI_WALK_TERMINATE);
}

/*ARGSUSED*/
static void
get_new_child(dev_info_t *rdip, void *arg, uint_t flags)
{
	dev_info_t **dipp = (dev_info_t **)arg;

	ASSERT(dipp && (*dipp == NULL));

	*dipp = rdip;
}

gptwo_new_nodes_t *
gptwo_configure_wci(dev_info_t *ap, spcd_t *pcd, uint_t id)
{
	fco_handle_t fco_handle;
	int error, circ;
	dev_info_t *new_child;
	char unit_address[64];
	gptwo_new_nodes_t *new_nodes;
	devi_branch_t b = {0};

	GPTWO_DEBUG2(1, CE_CONT, "gptwo_configure_wci: id=%x pcd=%lx\n",
	    id, pcd);

	new_nodes = gptwocfg_allocate_node_list(1);

	if (pcd->spcd_prsv != SPCD_RSV_PASS) {

		cmn_err(CE_WARN, "gptwo_configure_wci: saf id=0x%x "
		    "Can not be probed\n", id);

		gptwocfg_free_node_list(new_nodes);
		return (NULL);
	}

	new_child = NULL;

	b.arg = &new_child;
	b.type = DEVI_BRANCH_SID;
	b.create.sid_branch_create = set_name_prop;
	b.devi_branch_callback = get_new_child;

	/*
	 * Prevent any changes to new_child
	 * until we have bound it to the correct driver.
	 */
	ndi_devi_enter(ap, &circ);

	if (e_ddi_branch_create(ap, &b, NULL, 0) != NDI_SUCCESS) {
		ASSERT(new_child == NULL);

		GPTWO_DEBUG0(1, CE_CONT,
		    "gptwo_configure_wci: failed "
		    "to alloc child node\n");

		if (new_nodes->gptwo_nodes[0] == NULL) {
			GPTWO_DEBUG0(1, CE_CONT, "gptwo_configure_wci: "
			    "No nodes configured - "
			    "removing new_nodes\n");
			gptwocfg_free_node_list(new_nodes);
			new_nodes = NULL;
		}

		ndi_devi_exit(ap, circ);

		return (new_nodes);
	}

	/*
	 * The platform DR interfaces created the dip in
	 * bound state. Bring devinfo node down to linked
	 * state and hold it there until compatible
	 * properties are created.
	 */
	e_ddi_branch_rele(new_child);
	(void) i_ndi_unconfig_node(new_child, DS_LINKED, 0);
	ASSERT(i_ddi_node_state(new_child) == DS_LINKED);
	e_ddi_branch_hold(new_child);

	mutex_enter(&DEVI(new_child)->devi_lock);
	DEVI(new_child)->devi_flags |= DEVI_NO_BIND;
	mutex_exit(&DEVI(new_child)->devi_lock);

	/*
	 * Drop the busy-hold on parent before calling
	 * fcode_interpreter to prevent potential deadlocks
	 */
	ndi_devi_exit(ap, circ);

	(void) snprintf(unit_address, sizeof (unit_address), "%x", id);

	fco_handle = gp2_fc_ops_alloc_handle(ap, new_child, NULL, NULL,
	    unit_address, NULL);

	GPTWO_DEBUG0(1, CE_CONT,
	    "gptwocfg: Calling Fcode Interpeter...\n");

	error = fcode_interpreter(ap, &gp2_fc_ops, fco_handle);

	GPTWO_DEBUG1(1, CE_CONT,
	    "gptwo_configure_wci: fcode_interpreter "
	    " returned %x\n", error);

	if (error) {
		cmn_err(CE_WARN, "gptwo_wci: Unable to probe wci leaf "
		    "%s\n", unit_address);

		gp2_fc_ops_free_handle(fco_handle);

		(void) e_ddi_branch_destroy(new_child, NULL, 0);
	} else {
		gptwocfg_save_handle(new_child, fco_handle);

		/*
		 * Compatible properties (if any) have been created,
		 * so bind driver.
		 */
		ndi_devi_enter(ap, &circ);
		ASSERT(i_ddi_node_state(new_child) <= DS_LINKED);

		mutex_enter(&DEVI(new_child)->devi_lock);
		DEVI(new_child)->devi_flags &= ~DEVI_NO_BIND;
		mutex_exit(&DEVI(new_child)->devi_lock);

		ndi_devi_exit(ap, circ);

		if (ndi_devi_bind_driver(new_child, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "gptwo_wci: Unable to bind"
			    " new wci child at dip=0x%p\n", new_child);
		}
	}

	if (new_nodes->gptwo_nodes[0] == NULL) {
		GPTWO_DEBUG0(1, CE_CONT, "gptwo_configure_wci: "
		    "No nodes configured - removing new_nodes\n");
		gptwocfg_free_node_list(new_nodes);
		new_nodes = NULL;
	}

	GPTWO_DEBUG1(1, CE_CONT, "gptwo_configure_wci: "
	    "Returning new_nodes=%p\n", new_nodes);

	return (new_nodes);
}

dev_info_t *
gptwo_unconfigure_wci(dev_info_t *dip)
{
	fco_handle_t fco_handle;

	fco_handle = gptwocfg_get_handle(dip);

	if (fco_handle != NULL) {
		/*
		 * If there is a handle, there may be resources
		 * that need to be freed from when the
		 * devices's fcode ran.
		 */
		GPTWO_DEBUG1(1, CE_CONT, "fco_handle=%lx\n", fco_handle);
		gp2_fc_ops_free_handle(fco_handle);
	}
	return (NULL);
}

#ifdef DEBUG
static void
debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
}
#endif
