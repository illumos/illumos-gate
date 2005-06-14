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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Configuration layer of the WildCat RSM driver
 *
 * This file handles user interaction for the wrsm driver, including
 *	- receiving and parsing a configuration,
 *	- initiating controller configuration and reconfiguration,
 *	- keeping track of which wci devices and ncslices are owned by which
 *	controllers,
 *	- private test interfaces
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/policy.h>

/* Driver specific headers */
#include <sys/wrsm.h>
#include <sys/wrsm_common.h>
#include <sys/wrsm_lc.h>
#include <sys/wrsm_cf.h>
#include <sys/wrsm_cf_impl.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_plat.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_session.h>

#include <sys/rsm/rsmpi.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wrsm_barrier.h>

#ifdef DEBUG
#include <sys/promif.h>
#define	CF_DEBUG 0x0001
#define	CF_WARN 0x0002

static uint_t wrsm_cf_debug = CF_WARN;
#define	DPRINTF(a, b)		{ if (wrsm_cf_debug & a) wrsmdprintf b; }
#define	DPRINT_BITMASK(m, b)	dprint_bitmask(m, b)
#else
#define	DPRINTF(a, b)		{ }
#define	DPRINT_BITMASK(m, b)
#endif


#ifdef DEBUG
static void
dprint_bitmask(char *msg, ncslice_bitmask_t bits)
{
	int i;

	DPRINTF(CF_DEBUG, (CE_NOTE, "%s = {", msg));
	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		if (WRSM_IN_SET(bits, i)) {
			DPRINTF(CF_DEBUG, (CE_CONT, "  %d", i));
		}
	}
	DPRINTF(CF_DEBUG, (CE_CONT, "}"));
}
#endif /* DEBUG */

/*
 * Represents the state of the "admin" instance of the wrsm
 * driver.  There should be only one such instance.
 */
typedef struct {
	int controller_devs;
	kmutex_t state_lock;	/* protects access to this state structure */
	kmutex_t wl_lock;	/* protects changes to wci_list */
	kmutex_t cl_lock;	/* protects changes to controller_list */
	kcondvar_t cv;		/* for waiting on the SC */
	kmutex_t cv_lock;	/* Used together with the above condvar */
	wrsm_wci_dev_t *wci_list;
	wrsm_controller_dev_t *controller_list;
	kmutex_t ncslices_lock;
	ncslice_bitmask_t ncslices_allocated;
	uint32_t ncslice_owner[WRSM_MAX_NCSLICES];
} cf_state_t;

static cf_state_t *cf_state = NULL;

static wrsm_controller_dev_t *find_controller(uint_t controller_id);
static wrsm_wci_dev_t *find_wci(safari_port_t port);
static wci_ids_t *create_wci_ids(safari_port_t *wcis, int nwcis,
    uint32_t controller_id, int *nfound);
static int verify_config(wrsm_controller_t *config,
    ncslice_bitmask_t *new_ncslices);
static int verify_newconfig(wrsm_controller_t *old, wrsm_controller_t *new);

static void cf_claim_slice(uint32_t controller_id, wrsm_ncslice_t slice);
static void cf_release_slice(uint32_t controller_id, wrsm_ncslice_t slice);
static int cf_claim_slices(uint32_t controller_id, ncslice_bitmask_t
    req_slices);
static void cf_release_slices(uint32_t controller_id, ncslice_bitmask_t
    rel_slices);
static void cf_release_all_slices(uint32_t controller_id);
static int wrsm_cf_ncslicelist_to_bitmask(wrsm_node_ncslice_array_t slice_array,
    ncslice_t *small_ncslicep, ncslice_bitmask_t *large_slice_bitmask);

static int wrsm_cf_replacecfg(intptr_t arg, int flag);
static int wrsm_cf_checkcfg(intptr_t arg, int flag);
static int wrsm_cf_installcfg(intptr_t arg, int flag);
static int wrsm_cf_initialcfg(intptr_t arg, int flag);
static int wrsm_cf_enablecfg(intptr_t arg, int flag);
static int wrsm_cf_removecfg(intptr_t arg, int flag);
static int wrsm_cf_startcfg(intptr_t arg, int flag);
static int wrsm_cf_stopcfg(intptr_t arg, int flag);
static int wrsm_cf_getcfg(intptr_t arg, int flag);

static int wrsm_cf_ping(int cont_id, intptr_t arg, int flag);
static int wrsm_cf_mbox(int cont_id, intptr_t arg, int flag);
static int wrsm_cf_sess(int cont_id, intptr_t arg, int flag);
static int wrsm_cf_memory_loopback(int cont_id, intptr_t arg, int flag);


static boolean_t wrsm_large_pages_supported = B_FALSE;
static boolean_t wrsm_forwarding_supported = B_FALSE;

/*
 * Called from the driver _init() routine to initialize
 * data private to the config layer.
 */
void
wrsm_cf_init(void)
{
	int i;

	cf_state = kmem_zalloc(sizeof (cf_state_t), KM_SLEEP);
	mutex_init(&cf_state->wl_lock, NULL, MUTEX_DRIVER, NULL);
	cf_state->wci_list = NULL;
	mutex_init(&cf_state->cl_lock, NULL, MUTEX_DRIVER, NULL);
	cf_state->controller_list = NULL;
	mutex_init(&cf_state->ncslices_lock, NULL, MUTEX_DRIVER, NULL);
	WRSMSET_ZERO(cf_state->ncslices_allocated);
	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		cf_state->ncslice_owner[i] = WRSM_BAD_RSM_ID;
	}
	mutex_init(&cf_state->cv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cf_state->cv, NULL, CV_DRIVER, NULL);
}

/*
 * Called from the driver _fini() routine to clean up
 * cf specific things.
 */
void
wrsm_cf_fini(void)
{
	cv_destroy(&cf_state->cv);

	mutex_destroy(&cf_state->ncslices_lock);
	mutex_destroy(&cf_state->wl_lock);
	mutex_destroy(&cf_state->cl_lock);
	mutex_destroy(&cf_state->cv_lock);

	kmem_free(cf_state, sizeof (cf_state_t));
}



/*
 * Called from wrsm_ioctl() when called on a driver instance which
 * has a type of wrsm_admin.  All of the calls from the RSM proxy
 * to install, update and query the configuration data come through
 * here.
 */
/*ARGSUSED*/
int
wrsm_cf_admin_ioctl(struct wrsm_soft_state *softsp, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p)
{
	int retval = EACCES;

	if (cmd != WRSM_CONTROLLERS && cmd != WRSM_GETCFG &&
	    (retval = secpolicy_sys_config(cred_p, B_FALSE)) != 0)
		return (retval);

	switch (cmd) {
	case WRSM_CONTROLLERS:
		*rval_p = cf_state->controller_devs;
		return (0);
	case WRSM_REPLACECFG:
		retval = wrsm_cf_replacecfg(arg, flag);
		break;
	case WRSM_CHECKCFG:
		retval = wrsm_cf_checkcfg(arg, flag);
		break;
	case WRSM_INSTALLCFG:
		retval = wrsm_cf_installcfg(arg, flag);
		break;
	case WRSM_ENABLECFG:
		retval = wrsm_cf_enablecfg(arg, flag);
		break;
	case WRSM_INITIALCFG:
		retval = wrsm_cf_initialcfg(arg, flag);
		break;
	case WRSM_REMOVECFG:
		retval = wrsm_cf_removecfg(arg, flag);
		break;
	case WRSM_STARTCFG:
		retval = wrsm_cf_startcfg(arg, flag);
		break;
	case WRSM_STOPCFG:
		retval = wrsm_cf_stopcfg(arg, flag);
		break;
	case WRSM_GETCFG:
		retval = wrsm_cf_getcfg(arg, flag);
		break;
	default:
		return (EINVAL);
	}

	return (retval);
}

/* For a give wci port, finds the controller it should belong to */
static uint32_t
find_wci_controller(safari_port_t port)
{
	wrsm_controller_dev_t *cont;

	mutex_enter(&cf_state->cl_lock);
	for (cont = cf_state->controller_list; cont; cont = cont->next) {
		if (cont->controller) {
			wrsm_controller_t *config = cont->controller;
			int i;

			if (config->routing == NULL ||
			    config->routing->wcis == NULL) {
				mutex_exit(&cf_state->cl_lock);
				return (WRSM_BAD_RSM_ID);
			}

			for (i = 0; i < config->routing->nwcis; i++) {
				if (config->routing->wcis[i]->port == port) {
					mutex_exit(&cf_state->cl_lock);
					return (cont->controller_id);
				}
			}
		}
	}
	mutex_exit(&cf_state->cl_lock);
	return (WRSM_BAD_RSM_ID);
}

/*
 * Called from _attach() when a new physical WCI is added.
 * The LC handle and port id are saved so that when configuration
 * data comes in which specifies WCIs by port id, it can be
 * translated to the LC handle before being handed to the NC
 */
int
wrsm_cf_newwci(lcwci_handle_t lcwci, safari_port_t port)
{
	wrsm_wci_dev_t *wci;
	wrsm_controller_dev_t *cont = NULL;
	boolean_t newwci = B_FALSE;

	/*
	 * If we already have an wci_dev_t for this wci, that means
	 * that it had previously been attached, assigned to a controller
	 * removed by DR, and now is being added again.
	 */
	wci = find_wci(port);

	if (wci == NULL) {
		/* This is a new WCI, so create an entry for it. */
		newwci = B_TRUE;
		wci = (wrsm_wci_dev_t *)kmem_alloc(sizeof (wrsm_wci_dev_t),
		    KM_SLEEP);
	}
	wci->id.port = port;
	wci->id.lcwci = lcwci;
	wci->controller_id = find_wci_controller(port);
	wci->attached = B_TRUE;

	if (newwci) {
		/* If new wci, add to wci list */
		mutex_enter(&cf_state->wl_lock);
		wci->next = cf_state->wci_list;
		cf_state->wci_list = wci;
		mutex_exit(&cf_state->wl_lock);
	}

	/* See if this WCI belongs to an existing controller */
	cont = find_controller(wci->controller_id);
	if (cont) {
		/* Don't call wrsm_nc_newwci if controller isn't enabled */
		if (cont->state == cf_enabled) {
			return (wrsm_nc_newwci(wci->controller_id, port,
			    lcwci, cont->controller));
		} else {
			/*
			 * Tried to DR in a WCI which belongs to a
			 * controller which is in the middle of being
			 * reconfigured.
			 */
			DPRINTF(CF_WARN, (CE_WARN, "controller busy"));
			return (EBUSY);
		}
	}
	return (WRSM_SUCCESS);
}

/*
 * Remove an entry from the list of attached WCIs
 */
int
wrsm_cf_remove_wci(lcwci_handle_t lcwci)
{
	wrsm_wci_dev_t *wci, *to_remove;
	wrsm_controller_dev_t *cont = NULL;

	DPRINTF(CF_DEBUG, (CE_CONT, "cf_remove_wci"));

	mutex_enter(&cf_state->wl_lock);
	wci = cf_state->wci_list;
	while (wci && wci->id.lcwci != lcwci) {
		wci = wci->next;
	}
	mutex_exit(&cf_state->wl_lock);

	if (wci == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "remove_wci didn't find %p",
		    (void *)lcwci));
		return (WRSM_SUCCESS);
	}

	/*
	 * If this WCI belongs to a controller, then check with
	 * nr to see if it's safe to let it be removed.  If it is
	 * removed, we leave it on the wci_list so that when it
	 * comes back, cf_newwci() can plug it back into the same
	 * controller.
	 */
	if ((cont = find_controller(wci->controller_id))) {
		ASSERT(cont);
		if (cont->state == cf_enabled) {
			int ier = wrsm_nc_removewci(wci->controller_id,
			    wci->id.port);

			if (!ier)
			    wci->attached = B_FALSE;

			return (ier);
		}
		else
			return (EBUSY);
	}

	/*
	 * If the WCI does not belong to a controller, then
	 * delete it from the list.
	 */
	mutex_enter(&cf_state->wl_lock);
	wci = cf_state->wci_list;
	if (wci->id.lcwci == lcwci) {
		to_remove = wci;
		cf_state->wci_list = wci->next;
	} else {
		while (wci && wci->next && wci->next->id.lcwci != lcwci)
			wci = wci->next;
		if (!wci || !wci->next) {
			mutex_exit(&cf_state->wl_lock);
			return (EINVAL);
		}
		to_remove = wci->next;
		wci->next = to_remove->next;
	}
	mutex_exit(&cf_state->wl_lock);
	kmem_free(to_remove, sizeof (wrsm_wci_dev_t));

	return (WRSM_SUCCESS);
}

/*
 * Given the Safari port id of an attached wci, return
 * the corresponding lcwci_handle_t.
 */
lcwci_handle_t
wrsm_cf_lookup_wci(safari_port_t port)
{
	wrsm_wci_dev_t *wci;

	wci = find_wci(port);
	if (wci)
		return (wci->id.lcwci);
	else
		return (NULL);
}

/*
 * This function is registered as a callback from the wrsm mailbox
 * module and is called when it is notfied that the SC has come back
 * up.  This implies that the SC had previously crashed so any
 * outstanding mailbox requests need to be re-sent.
 */
void
wrsm_cf_sc_failed()
{
	wrsm_wci_dev_t *cfwci;

	mutex_enter(&cf_state->wl_lock);
	cfwci = cf_state->wci_list;
	while (cfwci) {
		wrsm_lc_sc_crash(cfwci->id.lcwci);
		cfwci = cfwci->next;
	}
	mutex_exit(&cf_state->wl_lock);
}

/*
 * Reserve a wci for use by the specified controller
 */
int
wrsm_cf_claim_wci(uint32_t controller_id, safari_port_t wci_id)
{
	wrsm_wci_dev_t *wci;

	wci = find_wci(wci_id);
	if (wci) {
		if (wci->controller_id == WRSM_BAD_RSM_ID ||
		    wci->controller_id == controller_id) {
			wci->controller_id = controller_id;
			return (WRSM_SUCCESS);
		} else {
			DPRINTF(CF_WARN, (CE_WARN, "claim_wci: "
			    "wci %d is unavailable", wci_id));
			return (EACCES);
		}
	}

	return (WRSM_SUCCESS);
}

void
wrsm_cf_release_wci(safari_port_t wci_id)
{
	wrsm_wci_dev_t *wci;

	wci = find_wci(wci_id);
	if (wci)
		wci->controller_id = WRSM_BAD_RSM_ID;
}

uint32_t
wrsm_cf_wci_owner(safari_port_t wci_id)
{
	wrsm_wci_dev_t *wci;

	wci = find_wci(wci_id);
	if (wci)
		return (wci->controller_id);
	else
		return (WRSM_BAD_RSM_ID);
}

/*
 * Return true if the local cnode is configured to be used as a
 * starcat central switch.
 */
boolean_t
wrsm_cf_cnode_is_switch(wrsm_controller_t *config)
{
	int i;
	wrsm_routing_data_t *routing;

	if (config == NULL || config->routing == NULL)
		return (B_FALSE);

	routing = config->routing;
	for (i = 0; i < routing->npolicy; ++i) {
		wrsm_routing_policy_t *policy;
		policy = routing->policy[i];
		if (policy->forwarding_allowed) {
			DPRINTF(CF_DEBUG, (CE_CONT, "cf_cnode_is_switch: "
			    "forwarding is allowed"));
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * This function is called from _attach() when a new instance of the
 * driver is created represeting an RSM controller.  The def_info
 * pointer is stashed away allong with the controller id (instance
 * number) so that we can later translate from controller ids coming
 * in via ioctl to the appropriate dev_info to pass to the NC
 */
int
wrsm_cf_new_controller(int cont_id, dev_info_t *devi)
{
	wrsm_controller_dev_t *cont;

	cont = (wrsm_controller_dev_t *)kmem_alloc(
		sizeof (wrsm_controller_dev_t), KM_SLEEP);
	cont->controller_id = cont_id;
	cont->devi = devi;
	cont->controller = NULL;
	cont->state = cf_invalid;
	cont->in_ioctl = B_FALSE;
	mutex_init(&cont->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&cf_state->cl_lock);
	cont->next = cf_state->controller_list;
	cf_state->controller_list = cont;
	++cf_state->controller_devs;
	mutex_exit(&cf_state->cl_lock);
	DPRINTF(CF_DEBUG, (CE_CONT, "wrsm_cf_new_controller:"
	    "new controller id %d", cont->controller_id));

	return (WRSM_SUCCESS);
}

/*
 * Delete an entry from the list of valid controllers.  This is called
 * from the driver _detach() when the instance type is
 * wrsm_rsm_controller.  In this context a "controller" is just a
 * driver instance and it's associated wrsm_controller_dev_t struct.
 * If the controller has configuration data associated with it (ie it
 * has been the subject of an INITIALCFG ioctl) then this will cause
 * the detach to fail.
 */
int
wrsm_cf_remove_controller(int cont_id)
{
	wrsm_controller_dev_t *cont = NULL;
	wrsm_controller_dev_t *to_remove = NULL;

	DPRINTF(CF_DEBUG, (CE_CONT, "remove_controller %d", cont_id));

	if ((cont = find_controller(cont_id)) == NULL)
		return (EINVAL);

	/*
	 * Do not allow the driver to be unloaded if there are
	 * any active controllers.
	 */
	if (cont->controller && cont->state != cf_invalid) {
		DPRINTF(CF_WARN, (CE_WARN, "remove_controller: "
		    "%d is still active", cont_id));
		return (EBUSY);
	}

	mutex_enter(&cf_state->cl_lock);
	cont = cf_state->controller_list;
	if (cont->controller_id == cont_id) {
		to_remove = cont;
		cf_state->controller_list = cont->next;
	} else {
		while (cont && cont->next &&
		    cont->next->controller_id != cont_id)
			cont = cont->next;
		if (!cont || !cont->next) {
			mutex_exit(&cf_state->cl_lock);
			return (EINVAL);
		}
		to_remove = cont->next;
		cont->next = to_remove->next;
	}
	--cf_state->controller_devs;
	mutex_exit(&cf_state->cl_lock);
	mutex_destroy(&to_remove->lock);
	kmem_free(to_remove, sizeof (wrsm_controller_dev_t));
	return (WRSM_SUCCESS);
}


/*ARGSUSED*/
static int
wrsm_cf_replacecfg(intptr_t arg, int flag)
{
	int retval = 0;
	int i;
	wrsm_admin_arg_config_t replace_arg;
	wrsm_controller_dev_t *cont;
	void *controller_data = NULL;
	wrsm_controller_t *new = NULL;
	wrsm_routing_data_t *routing;
	wci_ids_t *attached_wcis = NULL;
	safari_port_t *port_list = NULL;
	boolean_t *new_wci = NULL;
	int num_attached;
	int num_claimed_wcis = 0;
	boolean_t slices_allocated = B_FALSE;
	ncslice_bitmask_t new_ncslices = {0};
	ncslice_bitmask_t added_ncslices = {0};

	DPRINTF(CF_DEBUG, (CE_CONT, "wrsm_cf_replacecfg"));
	if (ddi_copyin((void *)arg, (void *)&replace_arg,
	    sizeof (wrsm_admin_arg_config_t), flag) != 0) {
		retval = EFAULT;
		goto finish;
	}

	if (replace_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "replacecfg: user/kernel version mismatch");
		return (EINVAL);
	}

	if (!(cont = find_controller(replace_arg.controller_id))) {
		retval = EINVAL;
		goto finish;
	}

	if (cont->controller == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_replacecfg: controller %d "
		    "does not exist", replace_arg.controller_id));
		retval = ENOENT;
		goto finish;
	}

	if (cont->state != cf_enabled) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_replacecfg: controller in "
		    "wrong state %d", cont->state));
		retval = EINVAL;
		goto finish;
	}

	controller_data = kmem_alloc(replace_arg.controller_data_size,
	    KM_SLEEP);

	if (ddi_copyin(replace_arg.controller, controller_data,
	    replace_arg.controller_data_size, flag) != 0) {
		retval = EFAULT;
		goto finish;
	}

	if ((new = wrsm_cf_unpack(controller_data)) == NULL) {
		retval = EINVAL;
		goto finish;
	}

	routing = new->routing;

	/*
	 * Scan through the wci list in the wrsm_routing_data
	 * structure and pull out the port numbers, then pass the list
	 * of port numbers to create_wci_ids which builds the list of
	 * wci_ids_t that the NC expects.  This also has the side
	 * effect of marking the wcis as belonging to this controller.
	 */
	port_list = kmem_alloc(sizeof (safari_port_t) *
	    routing->nwcis, KM_SLEEP);
	new_wci = kmem_zalloc(sizeof (boolean_t) * routing->nwcis,
	    KM_SLEEP);
	for (i = 0; i < routing->nwcis; ++i) {
		port_list[i] = routing->wcis[i]->port;
		/* Check wci ownership/availability */
		if (wrsm_cf_wci_owner(port_list[i]) !=
		    replace_arg.controller_id) {
			new_wci[i] = B_TRUE;
			if (wrsm_cf_claim_wci(replace_arg.controller_id,
			    port_list[i]) != 0) {
				retval = EINVAL;
				goto finish;
			}
		}
		++num_claimed_wcis;
	}

	attached_wcis = create_wci_ids(port_list, routing->nwcis,
	    replace_arg.controller_id, &num_attached);

	/* LINTED: E_NOP_IF_STMT */
	if (!attached_wcis) {
		DPRINTF(CF_DEBUG, (CE_CONT, "no attached_wcis"));
	}

	if ((retval = verify_config(new, &new_ncslices)) != 0) {
		cmn_err(CE_NOTE, "cf_replacecfg: illegal new config");
		goto finish;
	}

	if ((retval = verify_newconfig(cont->controller, new)) != 0) {
		cmn_err(CE_NOTE, "cf_replacecfg: illegal config change");
		retval = EINVAL;
		goto finish;
	}


	/*
	 * Find all the slices in the new config not in the old one
	 * and attempt to allocate them.
	 */
	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		if (WRSM_IN_SET(new_ncslices, i) &&
		    !WRSM_IN_SET(cont->ncslices, i))
			WRSMSET_ADD(added_ncslices, i);
	}

	DPRINT_BITMASK("cf_replacecfg: new config added slices",
	    added_ncslices);

	if ((retval = cf_claim_slices(cont->controller_id, added_ncslices))
	    != 0) {
		cmn_err(CE_NOTE, "cf_replacecfg: failed to get needed "
		    "ncslices");
		retval = EINVAL;
		goto finish;
	}
	slices_allocated = B_TRUE;


#ifdef DEBUG
	{
		int j;
		DPRINTF(CF_DEBUG, (CE_CONT, "number of attached wcis %d",
		    num_attached));
		for (j = 0; j < num_attached; ++j)
			DPRINTF(CF_DEBUG, (CE_CONT, "attached[%d] "
			    "lcwci = %p port = %d", j,
			    (void *)attached_wcis[i].lcwci,
			    attached_wcis[i].port));
	}
#endif

	retval = wrsm_nc_replaceconfig(replace_arg.controller_id, new,
	    cont->devi, num_attached, attached_wcis);

finish:
	if (retval == 0) {
		cont->state = cf_replaced;
		cont->pending = new;
		WRSMSET_COPY(new_ncslices, cont->pending_ncslices);
		cont->pending_nbytes = replace_arg.controller_data_size;
	} else {
		if (port_list) {
			for (i = 0; i < num_claimed_wcis; ++i) {
				if (new_wci[i]) {
					wrsm_cf_release_wci(port_list[i]);
				}
			}
		}

		if (slices_allocated) {
			cf_release_slices(cont->controller_id, added_ncslices);
		}

		/* If unpack failed, free controller_data */
		if (controller_data) {
			kmem_free(controller_data,
			    replace_arg.controller_data_size);
		}
	}
	if (port_list) {
		kmem_free(port_list, sizeof (safari_port_t) * routing->nwcis);
		kmem_free(new_wci, sizeof (boolean_t) * routing->nwcis);
	}
	if (attached_wcis) {
		kmem_free(attached_wcis, sizeof (wci_ids_t) *
		    routing->nwcis);
	}

	return (retval);
}

/* ARGSUSED */
static void
cf_release_slice(uint32_t controller_id, wrsm_ncslice_t ncslice)
{
	ASSERT(mutex_owned(&cf_state->ncslices_lock));
	ASSERT(cf_state->ncslice_owner[ncslice] == controller_id);
	ASSERT(WRSM_IN_SET(cf_state->ncslices_allocated, ncslice));
	cf_state->ncslice_owner[ncslice] = WRSM_BAD_RSM_ID;
	WRSMSET_DEL(cf_state->ncslices_allocated, ncslice);
}

static void
cf_release_slices(uint32_t controller_id, ncslice_bitmask_t rel_slices)
{
	int i, retval;
	ncslice_bitmask_t granted;

	mutex_enter(&cf_state->ncslices_lock);
	DPRINT_BITMASK("cf_release_slices: ncslices before removal",
	    cf_state->ncslices_allocated);

	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		if (WRSM_IN_SET(rel_slices, i)) {
			cf_release_slice(controller_id, i);
		}
	}

	/*
	 * Notify wrsmplat of the new list of allocated ncslices
	 */
	if ((retval = wrsmplat_alloc_slices(cf_state->ncslices_allocated,
	    &granted))) {
		/*
		 * a failure should never happen, as we're releasing
		 * slices we already owned; ignore failure.
		 */
		cmn_err(CE_NOTE, "cf_claim_slices: wrsmplat_alloc "
		    "failed %d", retval);
	}

	DPRINT_BITMASK("cf_release_slices: ncslices after removal",
	    cf_state->ncslices_allocated);

	mutex_exit(&cf_state->ncslices_lock);
}

static void
cf_release_all_slices(uint32_t controller_id)
{
	int i, retval;
	ncslice_bitmask_t granted;

	mutex_enter(&cf_state->ncslices_lock);
	DPRINT_BITMASK("cf_release_all_slices: ncslices before removal",
	    cf_state->ncslices_allocated);

	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		if (cf_state->ncslice_owner[i] == controller_id) {
			cf_release_slice(controller_id, i);
		}
	}

	/*
	 * Notify wrsmplat of the new list of allocated ncslices
	 */
	if ((retval = wrsmplat_alloc_slices(cf_state->ncslices_allocated,
	    &granted))) {
		/*
		 * a failure should never happen, as we're releasing
		 * slices we already owned; ignore failure.
		 */
		cmn_err(CE_NOTE, "cf_claim_slices: wrsmplat_alloc "
		    "failed %d", retval);
	}

	DPRINT_BITMASK("cf_release_all_slices: ncslices after removal",
	    cf_state->ncslices_allocated);

	mutex_exit(&cf_state->ncslices_lock);
}

static void
cf_claim_slice(uint32_t controller_id, wrsm_ncslice_t ncslice)
{
#ifdef DEBUG
	ASSERT(mutex_owned(&cf_state->ncslices_lock));
	if (WRSM_IN_SET(cf_state->ncslices_allocated, ncslice)) {
		ASSERT(cf_state->ncslice_owner[ncslice] == controller_id);
	} else {
		ASSERT(cf_state->ncslice_owner[ncslice] == WRSM_BAD_RSM_ID);
	}
#endif /* DEBUG */
	cf_state->ncslice_owner[ncslice] = controller_id;
	WRSMSET_ADD(cf_state->ncslices_allocated, ncslice);
}

static int
cf_claim_slices(uint32_t controller_id, ncslice_bitmask_t req_slices)
{
	int retval = 0;
	ncslice_bitmask_t granted;
	ncslice_bitmask_t union_slices;
	ncslice_bitmask_t new_slices;
	int i;

	mutex_enter(&cf_state->ncslices_lock);
	DPRINT_BITMASK("cf_claim_slices: ncslices allocated",
	    cf_state->ncslices_allocated);
	DPRINT_BITMASK("cf_claim_slices: ncslices requested", req_slices);

	/*
	 * Find out if any of the requsted slices are already taken
	 * by another controller.  This will be the case if any of
	 * the slices in req_slices is allocated and the owner is
	 * someone else.
	 */
	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		if (WRSM_IN_SET(req_slices, i) &&
		    WRSM_IN_SET(cf_state->ncslices_allocated, i) &&
		    cf_state->ncslice_owner[i] != controller_id) {
			DPRINTF(CF_DEBUG, (CE_NOTE, "cf_claim_slices: "
			    "contid %d ncslice %d already taken by cont %d",
			    controller_id, i, cf_state->ncslice_owner[i]));
			mutex_exit(&cf_state->ncslices_lock);
			return (EACCES);
		}
	}

	/* Get the union of the old and new ncslices */
	WRSMSET_COPY(req_slices, union_slices);
	WRSMSET_OR(union_slices, cf_state->ncslices_allocated);

	/* Determine what new slices are needed */
	WRSMSET_COPY(union_slices, new_slices);
	WRSMSET_DIFF(new_slices, cf_state->ncslices_allocated);

	/* If there are new slices that are needed, allocate from SC */
	if (!WRSMSET_ISNULL(new_slices)) {
		DPRINT_BITMASK("cf_claim_slices: new slices",
		    new_slices);

		/* wrsmplat needs to see list of ALL slices desired */
		if ((retval = wrsmplat_alloc_slices(union_slices, &granted))) {
			cmn_err(CE_NOTE, "cf_claim_slices: wrsmplat_alloc "
			    "failed %d", retval);
			mutex_exit(&cf_state->ncslices_lock);
			return (retval);
		}

		/*
		 * If we didn't get everything we requested, back out new
		 * ncslices, then fail.
		 */
		if (!WRSMSET_ISEQUAL(union_slices, granted)) {
			if ((retval = wrsmplat_alloc_slices(
			    cf_state->ncslices_allocated, &granted))) {
				/* ignore failure; this shouldn't happen */
				cmn_err(CE_NOTE,
				    "cf_claim_slices: wrsmplat_alloc "
				    "failed %d", retval);
			}
			mutex_exit(&cf_state->ncslices_lock);
			return (EACCES);
		}

		/*
		 * All requested slices were allocated, so update the
		 * ownership list.
		 */
		for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
			if (WRSM_IN_SET(req_slices, i)) {
				cf_claim_slice(controller_id, i);
			}
		}
	}

	mutex_exit(&cf_state->ncslices_lock);
	return (WRSM_SUCCESS);
}

/*ARGSUSED*/
static int
wrsm_cf_checkcfg(intptr_t arg, int flag)
{
	wrsm_controller_dev_t *cont;
	int retval = 0;
	boolean_t up;

	if (!(cont = find_controller(arg)))
		return (EINVAL);

	if (cont->controller == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_checkcfg: controller "
		    "not present %d", (int)arg));
		return (EINVAL);
	}

	up = wrsm_nc_is_installed_up(arg);
	if (!up)
		retval = EBUSY;
	return (retval);
}


/*ARGSUSED*/
static int
wrsm_cf_installcfg(intptr_t arg, int flag)
{
	wrsm_admin_arg_wci_t install_arg;
	wrsm_controller_dev_t *cont;
	wci_ids_t *attached_wcis = NULL;
	safari_port_t *wcis = NULL;
	int retval = 0;
	int num_attached;
	ncslice_bitmask_t old_slices = {0};
	int i;

	if (ddi_copyin((void *)arg, (void *)&install_arg,
	    sizeof (wrsm_admin_arg_wci_t), flag) != 0)
		return (EFAULT);

	if (install_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "installcfg: user/kernel version mismatch");
		return (EINVAL);
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "wrsm_cf_installcfg controller %d",
	    install_arg.controller_id));

	if (!(cont = find_controller(install_arg.controller_id)))
		return (EINVAL);
	if (cont->controller == NULL || cont->pending == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_installcfg: "
		    "controller not present state=%d", cont->state));
		return (EINVAL);
	}

	mutex_enter(&cont->lock);
	if (cont->in_ioctl) {
		mutex_exit(&cont->lock);
		return (EBUSY);
	}
	cont->in_ioctl = B_TRUE;
	mutex_exit(&cont->lock);

	if (cont->state != cf_replaced) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_installcfg: "
		    "controller in wrong state %d", cont->state));
		cont->in_ioctl = B_FALSE;
		return (EINVAL);
	}

	wcis = kmem_alloc(sizeof (safari_port_t) * install_arg.nwcis,
	    KM_SLEEP);
	if (ddi_copyin((void *)install_arg.wci_ids, (void *)wcis,
	    sizeof (safari_port_t) * install_arg.nwcis, flag) != 0) {
		retval = EFAULT;
		goto finish;
	}

	attached_wcis = create_wci_ids(wcis, install_arg.nwcis,
	    install_arg.controller_id, &num_attached);
	kmem_free(wcis, sizeof (safari_port_t) * install_arg.nwcis);

	/* LINTED: E_NOP_IF_STMT */
	if (!attached_wcis) {
		DPRINTF(CF_DEBUG, (CE_CONT, "no attached_wcis"));
	}

	retval = wrsm_nc_cleanconfig(install_arg.controller_id,
	    num_attached, attached_wcis);
	if (retval != 0)
		goto finish;

	/*
	 * At this point, the NC guarantees that no accesses will be made
	 * to the old ncslices, so it's safe to release them.
	 */

#ifdef DEBUG
	{
		int j;
		DPRINTF(CF_DEBUG, (CE_CONT, "number of attached wcis %d",
		    num_attached));
		for (j = 0; j < num_attached; ++j)
			DPRINTF(CF_DEBUG, (CE_CONT, "attached[%d] "
			    "lcwci = %p port = %d", j,
			    (void *)attached_wcis[j].lcwci,
			    attached_wcis[j].port));
	}
#endif

	retval = wrsm_nc_installconfig(install_arg.controller_id);
	if (retval != 0)
		goto finish;

	WRSMSET_ZERO(old_slices);
	for (i = 0; i < WRSM_MAX_NCSLICES; ++i) {
		if (WRSM_IN_SET(cont->ncslices, i) &&
		    !WRSM_IN_SET(cont->pending_ncslices, i)) {
			WRSMSET_ADD(old_slices, i);
		}
	}
	DPRINT_BITMASK("cf_installcfg: releasing old slices", old_slices);
	cf_release_slices(cont->controller_id, old_slices);

finish:
	if (retval == 0) {
		wrsm_routing_data_t *old_route, *new_route;
		int i, j, old_port;

		/*
		 * Release WCIs from the old config not in the new.
		 * This relies on both the old and new lists of wcis
		 * to be sorted in ascending order by port number.
		 */
		old_route = cont->controller->routing;
		new_route = cont->pending->routing;
		j = 0;
		for (i = 0; i < old_route->nwcis; ++i) {
			old_port = old_route->wcis[i]->port;
			while (j < new_route->nwcis &&
			    new_route->wcis[j]->port < old_port)
				++j;
			if (j >= new_route->nwcis ||
			    new_route->wcis[j]->port > old_port) {
				wrsm_cf_release_wci(old_port);
			}
		}

		cont->state = cf_installed;
		cont->controller = cont->pending;
		WRSMSET_COPY(cont->pending_ncslices, cont->ncslices);
		cont->nbytes = cont->pending_nbytes;
	}

	cont->in_ioctl = B_FALSE;
	if (attached_wcis) {
		kmem_free(attached_wcis, sizeof (wci_ids_t) *
		    install_arg.nwcis);
	}
	return (retval);
}

static int
wrsm_cf_enablecfg(intptr_t arg, int flag)
{
	wrsm_admin_arg_wci_t enable_arg;
	wrsm_controller_dev_t *cont;
	int retval = 0;
	safari_port_t *wcis = NULL;
	wci_ids_t *attached_wcis = NULL;
	int num_attached;

	if (ddi_copyin((void *)arg, (void *)&enable_arg,
	    sizeof (wrsm_admin_arg_wci_t), flag) != 0)
		return (EFAULT);

	if (enable_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "enablecfg: user/kernel version mismatch");
		return (EINVAL);
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "wrsm_cf_enablecfg controller %d",
	    enable_arg.controller_id));

	if (!(cont = find_controller(enable_arg.controller_id)))
		return (EINVAL);

	if (cont->controller == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_enablecfg: "
		    "controller not present %d", enable_arg.controller_id));
		return (EINVAL);
	}

	mutex_enter(&cont->lock);
	if (cont->in_ioctl) {
		mutex_exit(&cont->lock);
		return (EBUSY);
	}
	cont->in_ioctl = B_TRUE;
	mutex_exit(&cont->lock);

	if (cont->state != cf_installed) {
		DPRINTF(CF_WARN, (CE_WARN, "cf_enablecfg: "
		    "controller int wrong state %d", cont->state));
		retval = EINVAL;
		goto err_return;
	}

	wcis = kmem_alloc(sizeof (safari_port_t) * enable_arg.nwcis,
	    KM_SLEEP);
	if (ddi_copyin((void *)enable_arg.wci_ids, (void *)wcis,
	    sizeof (safari_port_t) * enable_arg.nwcis, flag) != 0) {
		retval = EFAULT;
		goto err_return;
	}

	attached_wcis = create_wci_ids(wcis, enable_arg.nwcis,
	    enable_arg.controller_id, &num_attached);
	/* LINTED: E_NOP_IF_STMT */
	if (!attached_wcis) {
		DPRINTF(CF_DEBUG, (CE_CONT, "no attached_wcis"));
	}

	retval = wrsm_nc_enableconfig(enable_arg.controller_id,
	    num_attached, attached_wcis);
	if (attached_wcis) {
		kmem_free(attached_wcis, sizeof (wci_ids_t) *
		    enable_arg.nwcis);
		attached_wcis = NULL;
	}
	if (retval == 0)
		cont->state = cf_enabled;
	cont->in_ioctl = B_FALSE;

	return (retval);

err_return:
	if (wcis)
		kmem_free(wcis, sizeof (safari_port_t) *
		    enable_arg.nwcis);
	cont->in_ioctl = B_FALSE;
	if (attached_wcis) {
		kmem_free(attached_wcis, sizeof (wci_ids_t) *
		    enable_arg.nwcis);
	}

	return (retval);
}

/*
 * Called as a result of an WRSM_INITIALCFG ioctl() call to the wrsm
 * admin psuedo driver.  The arg is a pointer to a wrsm_admin_arg_config_t
 * structure which contains the address and size of a wrsm_controller_t.
 * If successfull, this function brings the controller data in from user
 * space and passes it to wsrm_nc_initialcfg().
 */
static int
wrsm_cf_initialcfg(intptr_t arg, int flag)
{
	int retval = 0;
	int i;
	wrsm_admin_arg_config_t init_arg;
	void *controller_data = NULL;
	wrsm_controller_dev_t *cont;	/* used to walk controller_list */
	wci_ids_t *attached_wcis = NULL;
	wrsm_routing_data_t *routing;
	safari_port_t *port_list = NULL;
	int num_attached;
	boolean_t slices_allocated = B_FALSE;

	DPRINTF(CF_DEBUG, (CE_CONT, "wrsm_cf_initialcfg"));

	if (ddi_copyin((void *)arg, (void *)&init_arg,
	    sizeof (wrsm_admin_arg_config_t), flag) != 0) {
		DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: 1st ddi_copyin "
		    "failed"));
		retval = EFAULT;
		goto err_return;
	}

	if (init_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "initialcfg: user/kernel version mismatch");
		return (EINVAL);
	}

	if (!(cont = find_controller(init_arg.controller_id))) {
		retval = EINVAL;
		DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: find_controller "
		    "failed"));
		goto err_return;
	}

	/*
	 * If there is already a cached wrsm_conroller_t pointer then
	 * we already have a config for this controller so it can't
	 * be "initial".
	 */
	if (cont->controller != NULL) {
		cmn_err(CE_NOTE, "wrsm_cf_initial: "
		    "controller already configured");
		retval = EEXIST;
		cont = NULL;
		goto err_return;
	}

	mutex_enter(&cont->lock);
	if (cont->in_ioctl) {
		mutex_exit(&cont->lock);
		return (EBUSY);
	}
	cont->in_ioctl = B_TRUE;
	mutex_exit(&cont->lock);

	/* Bring the controller data in from user space */
	controller_data = kmem_alloc(init_arg.controller_data_size, KM_SLEEP);
	bzero(controller_data, init_arg.controller_data_size);

	if (ddi_copyin(init_arg.controller, controller_data,
	    init_arg.controller_data_size, flag) != 0) {
		retval = EFAULT;
		DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: 2nd ddi_copyin "
		    "failed"));
		goto err_return;
	}

	cont->nbytes = init_arg.controller_data_size;
	if ((cont->controller = wrsm_cf_unpack(controller_data)) == NULL) {
		retval = EINVAL;
		DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: cf_unpack failed"));
		goto err_return;
	}

	routing = cont->controller->routing;

	/*
	 * Scan through the wci list in the wrsm_routing_data
	 * structure and pull out the port numbers, then pass the list
	 * of port numbers to create_wci_ids which builds the list of
	 * wci_ids_t that the NC expects.  This also has the side
	 * effect of marking the wcis as belonging to this controller.
	 */
	port_list = kmem_alloc(sizeof (safari_port_t) *
	    routing->nwcis, KM_SLEEP);
	for (i = 0; i < routing->nwcis; ++i) {
		port_list[i] = routing->wcis[i]->port;
		if (wrsm_cf_claim_wci(init_arg.controller_id,
		    port_list[i]) != 0) {
			retval = EINVAL;
			DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: cf_claim_wci "
			    "failed"));
			goto err_return;
		}
	}

	attached_wcis = create_wci_ids(port_list, routing->nwcis,
	    init_arg.controller_id, &num_attached);

	if (!attached_wcis) {
		DPRINTF(CF_DEBUG, (CE_CONT, "no attached_wcis"));
		retval = EACCES;
		goto err_return;
	}

	if ((retval = verify_config(cont->controller, &cont->ncslices)) != 0) {
		DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: verify_config "
		    "failed"));
		goto err_return;
	}

	retval = cf_claim_slices(cont->controller_id, cont->ncslices);
	if (retval != 0) {
		cmn_err(CE_NOTE, "cf_initial: failed to get needed ncslices");
		goto err_return;
	}
	slices_allocated = B_TRUE;

#ifdef DEBUG
	{
		int j;
		DPRINTF(CF_DEBUG, (CE_CONT, "number of attached wcis %d",
		    num_attached));
		for (j = 0; j < num_attached; ++j)
			DPRINTF(CF_DEBUG, (CE_CONT, "attached[%d] "
			    "lcwci = %p port = %d", j,
			    (void *)attached_wcis[j].lcwci,
			    attached_wcis[j].port));
	}
#endif

	if ((retval = wrsm_nc_initialconfig(cont->controller_id,
	    cont->controller, cont->devi, num_attached, attached_wcis)) != 0) {
		DPRINTF(CF_DEBUG, (CE_WARN, "initialcfg: nc_intiailconfig "
		    "failed"));
		goto err_return;
	}

	cont->state = cf_installed;
	if (attached_wcis)
		kmem_free(attached_wcis, sizeof (wci_ids_t) * routing->nwcis);
	if (port_list)
		kmem_free(port_list, sizeof (safari_port_t) * routing->nwcis);
	cont->in_ioctl = B_FALSE;

	return (WRSM_SUCCESS);

err_return:

	if (slices_allocated) {
		cf_release_all_slices(cont->controller_id);
	}

	if (port_list)
		for (i = 0; i < routing->nwcis; ++i) {
			/*
			 * Only release WCIs that we have succesfully claimed
			 */
			if (wrsm_cf_wci_owner(port_list[i]) ==
			    init_arg.controller_id)
				wrsm_cf_release_wci(port_list[i]);
		}

	if (attached_wcis) {
		kmem_free(attached_wcis, sizeof (wci_ids_t) * routing->nwcis);
	}
	if (port_list) {
		kmem_free(port_list, sizeof (safari_port_t) * routing->nwcis);
	}

	if (cont && cont->controller) {
		DPRINTF(CF_DEBUG, (CE_WARN, "wrsm_cf_initialcfg failed"));
		wrsm_cf_free(cont->controller);
	}
	if (controller_data)
		kmem_free(controller_data, init_arg.controller_data_size);

	if (cont) {
		cont->controller = NULL;
		WRSMSET_ZERO(cont->ncslices);
		cont->nbytes = 0;
		cont->in_ioctl = B_FALSE;
	}

	return (retval);
}

/*
 * Calledback from the NC to the CF in response to
 * wrsm_nc_initialconfig().  This should be called as soon as
 * the NC has enabled the config.
 */
void
wrsm_cf_is_enabled(uint32_t controller_id)
{
	wrsm_controller_dev_t *cont;

	if (!(cont = find_controller(controller_id))) {
		cmn_err(CE_WARN, "cf_is_enabled: bad controller id %d",
		    controller_id);
		return;
	}
	cont->state = cf_enabled;
}

/*ARGSUSED*/
static int
wrsm_cf_removecfg(intptr_t arg, int flag)
{
	uint_t controller_id = (uint_t)arg;
	wrsm_controller_dev_t *cont;
	wrsm_routing_data_t *routing;
	int retval;
	int i;

	if (!(cont = find_controller(controller_id)))
		return (EINVAL);
	if (!cont->controller)
		return (ENOENT);

	mutex_enter(&cont->lock);
	if (cont->in_ioctl) {
		mutex_exit(&cont->lock);
		return (EBUSY);
	}
	cont->in_ioctl = B_TRUE;
	mutex_exit(&cont->lock);

	if ((retval = wrsm_nc_removeconfig(controller_id)) != 0) {
		cont->in_ioctl = B_FALSE;
		return (retval);
	}

	/* remove ncslice request from inuse */
	cf_release_all_slices(cont->controller_id);

	routing = cont->controller->routing;
	for (i = 0; i < routing->nwcis; ++i)
		wrsm_cf_release_wci(routing->wcis[i]->port);

	wrsm_cf_free(cont->controller);
	kmem_free(cont->controller, cont->nbytes);
	cont->controller = NULL;
	WRSMSET_ZERO(cont->ncslices);
	cont->nbytes = 0;
	cont->state = cf_invalid;
	cont->in_ioctl = B_FALSE;

	return (WRSM_SUCCESS);
}

/*ARGSUSED*/
static int
wrsm_cf_startcfg(intptr_t arg, int flag)
{
	uint_t controller_id = (uint_t)arg;
	wrsm_controller_dev_t *cont;
	int retval;

	if (!(cont = find_controller(controller_id)))
		return (EINVAL);
	if (!cont->controller)
		return (ENOENT);

	mutex_enter(&cont->lock);
	if (cont->in_ioctl) {
		mutex_exit(&cont->lock);
		return (EBUSY);
	}
	cont->in_ioctl = B_TRUE;
	mutex_exit(&cont->lock);

	retval = wrsm_nc_startconfig(controller_id);
	cont->in_ioctl = B_FALSE;
	return (retval);
}


/*ARGSUSED*/
static int
wrsm_cf_stopcfg(intptr_t arg, int flag)
{
	uint_t controller_id = (uint_t)arg;
	wrsm_controller_dev_t *cont;
	int retval;

	if (!(cont = find_controller(controller_id)))
		return (EINVAL);
	if (!cont->controller)
		return (ENOENT);

	mutex_enter(&cont->lock);
	if (cont->in_ioctl) {
		mutex_exit(&cont->lock);
		return (EBUSY);
	}
	cont->in_ioctl = B_TRUE;
	mutex_exit(&cont->lock);

	retval = wrsm_nc_stopconfig(controller_id);
	cont->in_ioctl = B_FALSE;
	return (retval);
}


static int
wrsm_cf_getcfg(intptr_t arg, int flag)
{
	wrsm_admin_arg_config_t get_arg;
	wrsm_controller_dev_t *cont;

	if (ddi_copyin((void *)arg, (char *)&get_arg,
	    sizeof (wrsm_admin_arg_config_t), flag) != 0)
		return (EFAULT);

	if (get_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "getcfg: user/kernel version mismatch");
		return (EINVAL);
	}

	/*
	 * Search for a controller with a matching id in the cache
	 */
	DPRINTF(CF_DEBUG, (CE_CONT, "getcfg: get controller id %d",
	    get_arg.controller_id));

	if (!(cont = find_controller(get_arg.controller_id)))
		return (EINVAL);

	if (!cont->controller)
		return (ENOENT);

	DPRINTF(CF_DEBUG, (CE_CONT, "getcfg: found ctlr size=%ld avail=%ld",
	    cont->nbytes, get_arg.controller_data_size));

	/*
	 * If the size of the user mode data block provided is not big
	 * enough to hold the controller data, fill in the required
	 * size, and return.  Typically this function should be called
	 * once with size of 0 and then a second time with an
	 * appropriate size buffer.
	 */
	if (get_arg.controller_data_size < cont->nbytes) {
		get_arg.controller_data_size = cont->nbytes;
		get_arg.controller = 0;
		if (ddi_copyout(&get_arg, (void *)arg,
		    sizeof (wrsm_admin_arg_config_t), 0)  != 0)
			return (EFAULT);
		else
			return (WRSM_SUCCESS);
	}

	if (ddi_copyout(cont->controller, get_arg.controller,
	    cont->nbytes, 0) != 0) {
		return (EFAULT);
	}

	return (WRSM_SUCCESS);
}

/*
 * Search for the specified controller id in the list created
 * by wrsm_cf_new_controller().
 */
static wrsm_controller_dev_t *
find_controller(uint_t controller_id)
{
	wrsm_controller_dev_t *cont;	/* used to walk controller_list */

	if (controller_id == WRSM_BAD_RSM_ID)
	    return (NULL);

	cont = cf_state->controller_list;
	while (cont) {
		if (cont->controller_id == controller_id)
			break;
		cont = cont->next;
	}

	return (cont);
}

/*
 * Search for the specified wci port id in the list created
 * by wrsm_cf_newwci().
 */
static wrsm_wci_dev_t *
find_wci(safari_port_t port)
{
	wrsm_wci_dev_t *wci;

	mutex_enter(&cf_state->wl_lock);
	wci = cf_state->wci_list;
	while (wci) {
		if (wci->id.port == port)
			break;
		wci = wci->next;
	}
	mutex_exit(&cf_state->wl_lock);

	return (wci);
}

/*
 * A wrsm_controller_t contains a list of pointers to wrsm_wci_data_t.
 * Before calling any of the nc_ functions, this list should be
 * translated to an array of wci_ids_t.  This is done by looking
 * up the safari id of the WCIs in the list created by wrsm_cf_newwci()
 */
static wci_ids_t *
create_wci_ids(safari_port_t *wcis, int nwcis, uint32_t controller_id,
    int *nfoundp)
{
	wci_ids_t *ret;
	wrsm_wci_dev_t *wcidev = NULL;
	int i;
	int nfound = 0;

	ret = (wci_ids_t *)kmem_alloc(sizeof (wci_ids_t) * nwcis, KM_SLEEP);
	for (i = 0; i < nwcis; ++i) {
		safari_port_t port = wcis[i];
		wcidev = find_wci(port);
		if (wcidev == NULL) {
			DPRINTF(CF_DEBUG, (CE_CONT, "wrsm_cf: unknown wci "
			    "number %d", port));
			continue;
		}
		if (wcidev->controller_id != controller_id) {
			DPRINTF(CF_DEBUG, (CE_WARN, "wci %d does not "
			    "belong to controller %d", wcidev->id.port,
			    controller_id));
			continue;
		}

		if (wcidev->attached == B_FALSE)
			continue;

		ret[nfound] = wcidev->id;
		++nfound;
	}

	if (nfoundp)
		*nfoundp = nfound;
	return (ret);

error_ret:
	kmem_free(ret, sizeof (wci_ids_t) * nwcis);
	if (nfoundp)
		*nfoundp = 0;
	return (NULL);
}


static int
verify_config(wrsm_controller_t *config, ncslice_bitmask_t *new_ncslices)
{
	ncslice_bitmask_t network_ncslices, member_ncslices, intersect,
	    imported_ncslices, imported_small_ncslices;
	wrsm_ncslice_t member_small_ncslice;
	int i, j;
	int err;
	wrsm_net_member_t *member;

	if (config->cnodeid < 0 || config->cnodeid >= WRSM_MAX_CNODES) {
		cmn_err(CE_NOTE, "verify: illegal local cnodeid %d",
		    config->cnodeid);
		return (EINVAL);
	}

	/*
	 * Verify that the local wnode is mentioned in the reachable
	 * list and that it points to the local cnode
	 */
	for (i = 0; i < config->routing->nwcis; ++i) {
		wrsm_wci_data_t *wci = config->routing->wcis[i];
		if (!wci->wnode_reachable[wci->local_wnode] ||
		    wci->reachable[wci->local_wnode] != config->cnodeid) {
			cmn_err(CE_NOTE, "verify: wci %d loopback wnode not "
			    "reachable", wci->port);
			return (EINVAL);
		}
	}

	WRSMSET_ZERO(network_ncslices);

	for (i = 0; i < config->nmembers; ++i) {
		ncslice_bitmask_t intersect;

		member = config->members[i];
		err = wrsm_cf_ncslicelist_to_bitmask(member->exported_ncslices,
		    &member_small_ncslice, &member_ncslices);
		if (err) {
			return (err);
		}
		WRSMSET_ADD(member_ncslices, member_small_ncslice);

		/* Check that all ncslices exported to this node are unique */
		WRSMSET_COPY(member_ncslices, intersect);
		WRSMSET_AND(intersect, network_ncslices);

		if (!WRSMSET_ISNULL(intersect)) {
			/*
			 * If the intersection is not empty, then some
			 * of the slices are not unique, so scan
			 * through the list to find which ones for a
			 * better error message and return an error.
			 */
			cmn_err(CE_NOTE, "verify: ncslices not unique");
			for (j = 0; j < WRSM_MAX_NCSLICES; ++j)
				if (WRSM_IN_SET(intersect, j))
					cmn_err(CE_NOTE, "conflict %d", j);
			return (EINVAL);
		}
		WRSMSET_OR(network_ncslices, member_ncslices);


		/*
		 * Check that comm_ncslice is one of the slices
		 * exported by the remote node.
		 */
		if (!WRSM_IN_SET(member_ncslices, member->comm_ncslice)) {
			cmn_err(CE_NOTE,
			    "verify: comm_slice 0x%x not in exported set",
			    member->comm_ncslice);
			return (EINVAL);
		}

		/* Check that the remote cnodeid is valid */
		if (member->cnodeid < 0 ||
		    member->cnodeid >= WRSM_MAX_CNODES) {
			cmn_err(CE_NOTE, "verify: illegal local cnodeid %d",
			    member->cnodeid);
			return (EINVAL);
		}

		/* Check that in and out driver comm offsets are unique */

		for (j = 0; j < config->nmembers; ++j) {
			wrsm_net_member_t *cmpmember = config->members[j];

			if (member == cmpmember)
				continue;

			if (member->local_offset == cmpmember->local_offset) {
				cmn_err(CE_NOTE, "verify: conflicting "
				    "local_offsets, cnode %d and cnode %d\n",
				    member->cnodeid, cmpmember->cnodeid);
				return (EINVAL);
			}
		}
	}

	/*
	 * Collect the ncslices being imported by remote nodes (exported by
	 * this node).  Note that each node's imported ncslices do _not_
	 * need to be different from those of other nodes; however there
	 * must be an agreement on which are large and small ncslices.
	 */
	WRSMSET_ZERO(imported_ncslices);
	WRSMSET_ZERO(imported_small_ncslices);
	for (i = 0; i < config->nmembers; ++i) {
		member = config->members[i];

		err = wrsm_cf_ncslicelist_to_bitmask(member->imported_ncslices,
		    &member_small_ncslice, &member_ncslices);
		if (err) {
			return (err);
		}
		WRSMSET_ADD(imported_small_ncslices, member_small_ncslice);
		WRSMSET_OR(imported_ncslices, member_ncslices);
	}

	/*
	 * Check that no small slices are also used as large slices.
	 */
	WRSMSET_COPY(imported_small_ncslices, intersect);
	WRSMSET_AND(intersect, imported_ncslices);

	if (!WRSMSET_ISNULL(intersect)) {
		/*
		 * If the intersection is not empty, then some
		 * of the slices are being used both for large and
		 * small pages.
		 */
		cmn_err(CE_NOTE, "verify: "
		    "imported ncslices used for both large and small pages");
		for (j = 0; j < WRSM_MAX_NCSLICES; ++j)
			if (WRSM_IN_SET(intersect, j))
				cmn_err(CE_NOTE,
				    "conflict %d", j);
		return (EINVAL);
	}

	WRSMSET_OR(imported_ncslices, imported_small_ncslices);

	/*
	 * Collect the ncslices used to allow this node to forward traffic
	 * from other nodes.
	 */
	WRSMSET_ZERO(intersect);
	for (i = 0; i < config->nmembers; ++i) {
		wrsm_routing_policy_t *policy;

		policy = config->routing->policy[i];
		if (policy->forwarding_allowed) {
			if (!wrsm_forwarding_supported) {
				return (ENOTSUP);
			}

			WRSMSET_COPY(policy->forwarding_ncslices, intersect);
			WRSMSET_AND(intersect, imported_ncslices);
			if (!WRSMSET_ISNULL(intersect)) {
				/*
				 * If the intersection is not empty, then
				 * some of the ncslices used for forwarding
				 * are also exported by this node.  This
				 * isn't supported.
				 */
				cmn_err(CE_NOTE, "verify: "
				    "forwarding ncslices clash with import"
				    "ncslices");
				for (j = 0; j < WRSM_MAX_NCSLICES; ++j)
					if (WRSM_IN_SET(intersect, j))
						cmn_err(CE_NOTE,
						    "conflict %d", j);
				return (EINVAL);
			}
		}
		WRSMSET_OR(network_ncslices, policy->forwarding_ncslices);
	}

	WRSMSET_OR(network_ncslices, member_ncslices);

	DPRINT_BITMASK("cf_verify_config: new config slices",
	    network_ncslices);

	WRSMSET_COPY(network_ncslices, *new_ncslices);
	return (WRSM_SUCCESS);
}

static int
verify_newconfig(wrsm_controller_t *old, wrsm_controller_t *new)
{
	if (!new->routing) {
		cmn_err(CE_NOTE, "verify: routing information required");
		return (EINVAL);
	}

	/*
	 * The cnode of the local node never changes while it is
	 * participating in an RSM network.
	 */
	if (old->cnodeid != new->cnodeid) {
		cmn_err(CE_NOTE, "verify: changing cnodeid");
		return (EINVAL);
	}

	/*
	 * Three related constraints:
	 *
	 * 1) A new configuration must not assign an ncslice to a new
	 * cnode if it was used by a different cnode in the old
	 * configuration.  This is overridden by the stronger constraint #3.
	 *
	 * 2) The ncslice and offset used for driver communication must
	 * not change on a cnode that is containd in both the old and
	 * new configuration.  This is checked in wrsm_nc.c
	 *
	 * 3) No ncslices already exported by a node in the old
	 * configuration can be removed in the new configuration.
	 * This is checked in wrsm_nc.c
	 */

	return (WRSM_SUCCESS);
}

/*
 * Called from wrsm_ioctl() when invoked on a driver instance which
 * has a type of wrsm_rsm_controller.
 */
/* ARGSUSED */
int
wrsm_cf_ctlr_ioctl(int cont_id, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p)
{
	int retval;

	switch (cmd) {
	case WRSM_CTLR_PING:
		retval = wrsm_cf_ping(cont_id, arg, flag);
		break;
	case WRSM_CTLR_MBOX:
		retval = wrsm_cf_mbox(cont_id, arg, flag);
		break;
	case WRSM_CTLR_SESS:
		retval = wrsm_cf_sess(cont_id, arg, flag);
		break;
	case WRSM_CTLR_MEM_LOOPBACK:
		retval = wrsm_cf_memory_loopback(cont_id, arg, flag);
		break;
	default:
		DPRINTF(CF_WARN, (CE_WARN, "unrecognized ioctl cmd %d\n",
		    cmd));
		retval = EINVAL;
	}
	return (retval);
}

static int
wrsm_cf_ping(int cont_id, intptr_t arg, int flag)
{
	wrsm_ping_arg_t ping_arg;
	wrsm_network_t *target_network;
	wrsm_raw_message_t raw_req;
	wrsm_raw_message_t raw_rsp;
	wrsm_message_t *msg = (wrsm_message_t *)&raw_req;
	wrsm_message_t *resp = (wrsm_message_t *)&raw_rsp;
	timespec_t time1, time2;
	int i, rc;

	if (ddi_copyin((void *)arg, (char *)&ping_arg,
	    sizeof (wrsm_ping_arg_t), flag) != 0)
		return (EFAULT);

	if (ping_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "ping: user/kernel version mismatch");
		return (EINVAL);
	}

	if (find_controller(cont_id) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "ping: invalid controller "
		    "id  %d", cont_id));
		return (EINVAL);
	}

	if ((target_network = wrsm_nc_ctlr_to_network(cont_id)) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "ping: no network struct "
		    "for controller %d", cont_id));
		return (EINVAL);
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "ping: sending %d pings to node %d",
	    ping_arg.count, ping_arg.target));

	msg->header.message_type = WRSM_MSG_PING;
	for (i = 0; i < WRSM_MESSAGE_BODY_SIZE; i++) {
		msg->body[i] = i;
	}

	gethrestime(&time1);

	for (i = 0; i < ping_arg.count; ++i) {
		rc = wrsm_tl_rpc(target_network, ping_arg.target, msg, resp);
		if (rc != 0) {
			DPRINTF(CF_WARN, (CE_WARN, "ping: wrsm_tl_rpc"
			    " failed rc=%x i=%d", rc, i));
			return (rc);
		}
	}

	gethrestime(&time2);
	ping_arg.time = (time2.tv_sec * 1000000000 + time2.tv_nsec) -
	    (time1.tv_sec * 1000000000 + time1.tv_nsec);

	if (ddi_copyout(&ping_arg, (void *)arg, sizeof (wrsm_ping_arg_t),
	    0) != 0) {
		return (EFAULT);
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "ping: %d responses received",
	    ping_arg.count));

	return (WRSM_SUCCESS);
}

static int
wrsm_cf_mbox(int cont_id, intptr_t arg, int flag)
{
	wrsm_link_arg_t link_arg;
	wrsm_controller_dev_t *cont = NULL;
	wrsm_controller_t *config;
	wrsm_wci_data_t *wci = NULL;
	int i;

	if (ddi_copyin((void *)arg, (char *)&link_arg,
	    sizeof (wrsm_link_arg_t), flag) != 0)
		return (EFAULT);

	if (link_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "mbox: user/kernel version mismatch");
		return (EINVAL);
	}

	if ((cont = find_controller(cont_id)) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "mbox: invalid controller "
		    "id  %d", cont_id));
		return (EINVAL);
	}

	if ((config = cont->controller) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "mbox: controller %d not "
		    "configured", cont_id));
		return (EINVAL);
	}

	for (i = 0; i < config->routing->nwcis; ++i)
		if (config->routing->wcis[i]->port == link_arg.wci_id) {
			wci = config->routing->wcis[i];
			break;
		}

	if (wci == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "mbox: unknown wci id %d",
		    link_arg.wci_id));
		return (EINVAL);
	}

	switch (link_arg.cmd) {
	case WRSM_CTLR_UPLINK:
		wrsmplat_uplink(link_arg.wci_id, link_arg.link_num,
		    wci->local_gnid, config->fmnodeid, (uint64_t)
		    config->version_stamp, cont_id, B_FALSE);
		break;
	case WRSM_CTLR_DOWNLINK:
		wrsmplat_downlink(link_arg.wci_id, link_arg.link_num, B_FALSE);
		break;
	case WRSM_CTLR_SET_LED:
		wrsmplat_set_led(link_arg.wci_id, link_arg.link_num,
		    link_arg.led_state);
		break;
	case WRSM_CTLR_ALLOC_SLICES:
		break;
	case WRSM_CTLR_SET_SEPROM:
		break;
	default:
		break;
	}
	return (WRSM_SUCCESS);
}






/*
 * memory loopback test: read/write patterns into exported/imported
 * loopback memory
 */


#ifdef DEBUG
#define	DPRINT_DATA(a)	dprint_pattern_data(a)

void
dprint_pattern_data(unsigned char *d)
{
	DPRINTF(CF_DEBUG, (CE_CONT, "0x "
	    "%2x%2x%2x%2x%2x%2x%2x%2x %2x%2x%2x%2x%2x%2x%2x%2x "
	    "%2x%2x%2x%2x%2x%2x%2x%2x %2x%2x%2x%2x%2x%2x%2x%2x "
	    "%2x%2x%2x%2x%2x%2x%2x%2x %2x%2x%2x%2x%2x%2x%2x%2x "
	    "%2x%2x%2x%2x%2x%2x%2x%2x %2x%2x%2x%2x%2x%2x%2x%2x",
	    d[0x0], d[0x1], d[0x2], d[0x3],
	    d[0x4], d[0x5], d[0x6], d[0x7],
	    d[0x8], d[0x9], d[0xa], d[0xb],
	    d[0xc], d[0xd], d[0xe], d[0xf],

	    d[0x10], d[0x11], d[0x12], d[0x13],
	    d[0x14], d[0x15], d[0x16], d[0x17],
	    d[0x18], d[0x19], d[0x1a], d[0x1b],
	    d[0x1c], d[0x1d], d[0x1e], d[0x1f],

	    d[0x20], d[0x21], d[0x22], d[0x23],
	    d[0x24], d[0x25], d[0x26], d[0x27],
	    d[0x28], d[0x29], d[0x2a], d[0x2b],
	    d[0x2c], d[0x2d], d[0x2e], d[0x2f],

	    d[0x30], d[0x31], d[0x32], d[0x33],
	    d[0x34], d[0x35], d[0x36], d[0x37],
	    d[0x38], d[0x39], d[0x3a], d[0x3b],
	    d[0x3c], d[0x3d], d[0x3e], d[0x3f]));
}

#else
#define	DPRINT_DATA(a)
#endif

#define	MEMLOOP_BSIZE	(MMU_PAGESIZE * 8)
typedef int (*lpbk_ptest_t)(caddr_t memptr, size_t len, uint64_t *error_offset,
    unsigned char *expected_data, unsigned char *actual_data);

uint64_t sso_pat[6*8] = {
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	    0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	    0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	    0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	    0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0,
};

/*
 * Write the entire memory region pointed to by memptr.  Apply each of the
 * 4 64 byte patterns in sso_pat to 4 consecutive cachelines.  Keep doing
 * this until the entire region is written.
 */
int
memloop_sso(caddr_t memptr, size_t len, uint64_t *error_offset,
    unsigned char *expected_data, unsigned char *actual_data)
{
	wrsm_raw_message_t raw_msg;
	char *send_data;
	char *receive_data = (char *)&raw_msg;
	uint_t pat = 0;
	uint_t i, j;

	DPRINTF(CF_DEBUG, (CE_CONT, "memloop_sso"));

	for (i = 0; i < (len / 64); i++) {

		send_data = (char *)&(sso_pat[pat]);
		DPRINT_DATA((unsigned char *)send_data);
		wrsm_blkwrite(send_data, memptr, 1);
		wrsm_blkread(memptr, receive_data, 1);
		for (j = 0; j < 64; j++) {
			if (send_data[j] != receive_data[j]) {
				*error_offset = (i * 64) + j;
				bcopy(send_data, expected_data, 64);
				bcopy(receive_data, actual_data, 64);
				return (EIO);
			}
		}
		memptr += 64;
		pat = (pat + 8) % (8 * 6);
	}

	return (WRSM_SUCCESS);
}


unsigned char march_pat[2*64] = {
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/*
 * Write the entire memory region pointed to by memptr, alternately writing
 * 2 cachelines of all 0s followed by 2 cachelines of all 1s.  March one
 * bit along which has the opposite setting from the rest of the bits in
 * each set of 4 cachelines.  (Thus, in the first 4 cachelines, bit 0 is
 * flipped.  In the next 4 cachelines, bit 1 is flipped, and so on.)
 */
int
memloop_slowmarch(caddr_t memptr, size_t len, uint64_t *error_offset,
    unsigned char *expected_data, unsigned char *actual_data)
{
	wrsm_raw_message_t raw_req;
	wrsm_raw_message_t raw_rsp;
	char *send_data = (char *)&raw_req;
	char *receive_data = (char *)&raw_rsp;
	uint_t i, j;
	uint_t pat = 0;
	unsigned char marcher = 1;
	int march_index = 63;
	boolean_t marcher_is_one = B_TRUE;
	boolean_t first_cacheline = B_TRUE;

	DPRINTF(CF_DEBUG, (CE_CONT, "memloop_slowmarch"));

	for (i = 0; i < (len / 64); i++) {
		bcopy((void *)&(march_pat[pat]), (void *)send_data, 64);
		if (marcher_is_one) {
			send_data[march_index] =
			    send_data[march_index] | marcher;
		} else {
			/* set marcher bit to 0 */
			send_data[march_index] =
			    send_data[march_index] & ~marcher;
		}
		DPRINT_DATA((unsigned char *)send_data);

		wrsm_blkwrite(send_data, memptr, 1);
		wrsm_blkread(memptr, receive_data, 1);
		for (j = 0; j < 64; j++) {
			if (send_data[j] != receive_data[j]) {
				*error_offset = (i * 64) + j;
				bcopy(send_data, expected_data, 64);
				bcopy(receive_data, actual_data, 64);
				return (EIO);
			}
		}
		memptr += 64;

		/*
		 * march a bit across the 64 byte cacheline.
		 */

		if (first_cacheline) {
			/*
			 * each 64 byte pattern is repeated
			 */
			first_cacheline = B_FALSE;
		} else {
			first_cacheline = B_TRUE;
			if (marcher_is_one) {
				/*
				 * second half of round:  bits are all 1
				 * except marcher, which is 0.
				 */
				marcher_is_one = B_FALSE;
				pat = 64;
			} else {
				/*
				 * start new round:  bits are all 0 except
				 * marcher, which is 1.
				 */
				marcher_is_one = B_TRUE;
				pat = 0;
				if (marcher & 0x80) {
					/*
					 * wrap marcher back to start of
					 * 64 byte cacheline.
					 */
					marcher = 1;
					march_index--;
					if (march_index == -1) {
						march_index = 63;
					}
				} else {
					marcher = marcher << 1;
				}
			}
		}
	}

	return (WRSM_SUCCESS);
}


/*
 * Write the entire memory region pointed to by memptr, alternately writing
 * a cacheline of all 0s and all 1s.  March one bit along at each 128 bit
 * offset in the cacheline which has the opposite setting from the rest of
 * the bits in each pair of cachelines.  (Thus, in the first 2 cachelines,
 * bits 0, 128, 256 and 384 are flipped.  In the next 2 cachelines, bits 1,
 * 129, 257, 385 are flipped, and so on.)
 */
int
memloop_fastmarch(caddr_t memptr, size_t len, uint64_t *error_offset,
    unsigned char *expected_data, unsigned char *actual_data)
{
	wrsm_raw_message_t raw_req;
	wrsm_raw_message_t raw_rsp;
	char *send_data = (char *)&raw_req;
	char *receive_data = (char *)&raw_rsp;
	uint_t i, j;
	uint_t pat = 0;
	unsigned char marcher = 1;
	uint_t march_index = 63;
	uint_t index;
	boolean_t turn_bit_off = B_FALSE;

	DPRINTF(CF_DEBUG, (CE_CONT, "memloop_fastmarch"));

	for (i = 0; i < (len / 64); i++) {
		bcopy((void *)&(march_pat[pat]), (void *)send_data, 64);
		for (j = 0; j < 4; j++) {
			index = march_index - (16 * j);
			if (turn_bit_off) {
				send_data[index] = send_data[index] & ~marcher;
			} else {
				send_data[index] = send_data[index] | marcher;
			}
		}
		DPRINT_DATA((unsigned char *)send_data);

		wrsm_blkwrite(send_data, memptr, 1);
		wrsm_blkread(memptr, receive_data, 1);
		for (j = 0; j < 64; j++) {
			if (send_data[j] != receive_data[j]) {
				*error_offset = (i * 64) + j;
				bcopy(send_data, expected_data, 64);
				bcopy(receive_data, actual_data, 64);
				return (EIO);
			}
		}
		memptr += 64;

		/*
		 * march alternating bit along
		 */

		if (turn_bit_off) {
			/* finished both passes; increment marcher bit */
			if (marcher & 0x80) {
				marcher = 1;
				march_index--;
				if (march_index == 47) {
					march_index = 63;
				}
			} else {
				marcher = marcher << 1;
			}
			turn_bit_off = B_FALSE;
			pat = 0;
		} else {
			turn_bit_off = B_TRUE;
			pat = 64;
		}
	}

	return (WRSM_SUCCESS);
}


uint64_t xtalk_pat[4*8] = {
	0x5555555555555555, 0x5555555555555555, 0x5555555555555555,
	    0x5555555555555555, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
	    0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
};

/*
 * Write the entire memory region pointed to by memptr.  Apply the 64 byte
 * pattern in xtalk_pat to each cacheline.  Keep doing this until the
 * entire region is written.
 */
int
memloop_xtalk(caddr_t memptr, size_t len, uint64_t *error_offset,
    unsigned char *expected_data, unsigned char *actual_data)
{
	wrsm_raw_message_t raw_buf;
	char *send_data = (char *)&(xtalk_pat[0]);
	char *receive_data = (char *)&raw_buf;
	uint_t i, j;

	DPRINTF(CF_DEBUG, (CE_CONT, "memloop_xtalk"));

	for (i = 0; i < (len / 64); i++) {

		DPRINT_DATA((unsigned char *)send_data);
		wrsm_blkwrite(send_data, memptr, 1);
		wrsm_blkread(memptr, receive_data, 1);
		for (j = 0; j < 64; j++) {
			if (send_data[j] != receive_data[j]) {
				*error_offset = (i * 64) + j;
				bcopy(send_data, expected_data, 64);
				bcopy(receive_data, actual_data, 64);
				return (EIO);
			}
		}
		memptr += 64;
	}

	return (WRSM_SUCCESS);
}


lpbk_ptest_t lpk_pattern_test[WRSM_MAX_PATTERN] = {
	memloop_sso,
	memloop_slowmarch,
	memloop_fastmarch,
	memloop_xtalk
};


/*
 * Loopback memory test.
 *
 * Create a memory segment, import it (loopback connection), then
 * write and read a pattern to requested various offsets in the
 * segment.  Clean up (remove segment), and return whether the
 * writes/reads succeeded.
 *
 * This test is intended for use by SunVTS.
 */
static int
wrsm_cf_memory_loopback(int cont_id, intptr_t arg, int flag)
{
	wrsm_memloopback_arg_t loop_arg;
	wrsm_network_t *network;
	rsm_access_entry_t access_list[1];
	rsm_memseg_export_handle_t exportseg;
	rsm_memseg_import_handle_t importseg;
	rsm_memory_local_t memory;
	void *buf;
	caddr_t aligned_buf;
	off_t bufsize;
	rsm_memseg_id_t segid;
	int err = 0;
	dev_info_t *dip;
	uint_t dev_register;
	off_t dev_offset;
	caddr_t map_kaddr;
	size_t map_len;
	caddr_t memptr;
	uint64_t error_offset;
	int i;
	rsm_barrier_t barrier;

	DPRINTF(CF_DEBUG, (CE_CONT, "in memory_loopback\n"));

	if (ddi_copyin((void *)arg, (char *)&loop_arg,
	    sizeof (wrsm_memloopback_arg_t), flag) != 0) {
		DPRINTF(CF_WARN, (CE_WARN, "illegal arg address"));
		return (EFAULT);
	}
	loop_arg.error_pattern = 0;

	if (find_controller(cont_id) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "memory_loopback: invalid "
		    "controller id  %d", cont_id));
		return (EINVAL);
	}

	if ((network = wrsm_nc_ctlr_to_network(cont_id)) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "memory_loopback: no network "
		    "struct for controller %d", cont_id));
		return (ENXIO);
	}


	/*
	 * We now use our own allocation routines rather than
	 * kmem_{z}alloc() because we require the underlying memory
	 * pages to be static in memory (i.e. non-relocatable).
	 */
	bufsize = MEMLOOP_BSIZE + MMU_PAGESIZE;
	buf = wrsm_alloc(bufsize, VM_NOSLEEP);


	if (buf == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "memory_loopback: no memory"));
		return (ENOMEM);
	}
	aligned_buf = (caddr_t)((uint64_t)
	    ((caddr_t)buf + MMU_PAGEOFFSET) & (uint64_t)MMU_PAGEMASK);


	/*
	 * create segment
	 */
	memory.ms_type = RSM_MEM_VADDR;
	memory.ms_as = &kas;
	memory.ms_length = MEMLOOP_BSIZE;
	memory.ms_vaddr = aligned_buf;

	if ((err = wrsmrsm_seg_create(network, &exportseg, MEMLOOP_BSIZE,
	    0, &memory, RSM_RESOURCE_DONTWAIT, 0)) != RSM_SUCCESS) {
		DPRINTF(CF_WARN, (CE_WARN, "memory_loopback: seg_create"
		    "failed %d", err));
		wrsm_free(buf, bufsize);
		/* distinguish from write/read error in pattern subtest */
		if (err == RSMERR_NOT_MEM)
			err = EHOSTUNREACH;
		else
			err = EINVAL;
		return (err);
	}


	/*
	 * publish segment
	 */
	access_list[0].ae_addr = RSM_ACCESS_PUBLIC;
	access_list[0].ae_permission = RSM_PERM_RDWR;

	segid = RSM_USER_APP_ID_BASE;
	while (segid <= RSM_USER_APP_ID_END) {
		if ((err = wrsmrsm_publish(exportseg, access_list,
		    1, segid, RSM_RESOURCE_DONTWAIT, 0))
		    != RSM_SUCCESS) {
			if (err == RSMERR_SEGID_IN_USE) {
				/* segment id is already in use */
				segid++;
			} else {
				err = EINVAL;
				goto export_cleanup;
			}
		} else {
			/* successful publish */
			break;
		}
	}
	if (segid > RSM_USER_APP_ID_END) {
		err = EAGAIN;
		DPRINTF(CF_WARN, (CE_WARN, "memory_loopback: no segid "
		    "available"));
		goto export_cleanup;
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "memory_loopback: created and "
	    "published a segment with size of 0x%x and segid 0x%x\n",
	    MEMLOOP_BSIZE, segid));


	/*
	 * connect to segment
	 */
	if ((err = wrsmrsm_connect(network, network->cnodeid, segid,
	    &importseg)) != RSM_SUCCESS) {
		/*
		 * distinguish from write/read error in pattern subtest
		 */
		DPRINTF(CF_WARN, (CE_WARN, "cf_memory_loopback: "
		    "wrsmrsm_connect failed err=%d cnodeid %d segid %d",
		    err, network->cnodeid, segid));

		if (err == RSMERR_RSM_ADDR_UNREACHABLE)
			err = EHOSTUNREACH;
		else if (err == RSMERR_CONN_ABORTED)
			err = ENETRESET;
		else
			err = EINVAL;
		goto export_cleanup;
	}

	/*
	 * map in segment
	 */
	err = wrsmrsm_map(importseg, 0, MEMLOOP_BSIZE, &map_len, &dip,
	    &dev_register, &dev_offset, NULL, 0);
	if (err) {
		(void) wrsmrsm_disconnect(importseg);
		err = EINVAL;
		goto export_cleanup;
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "memory_loopback: map returned "
	    "dip 0x%p, rnumber %d offset 0x%lx len 0x%lx\n",
	    (void *)dip, dev_register, dev_offset, map_len));

	err = ddi_map_regs(dip, dev_register, &map_kaddr, dev_offset, map_len);
	if (err != DDI_SUCCESS) {
		(void) wrsmrsm_unmap(importseg);
		(void) wrsmrsm_disconnect(importseg);
		/*
		 * distinguish from write/read error in pattern subtest
		 */
		DPRINTF(CF_WARN, (CE_WARN, "cf_memory_loopback: ddi_map_regs "
		    "failed err = %d rnumber %d offset 0x%lx len 0x%lx",
		    err, dev_register, dev_offset, map_len));

		err = EHOSTUNREACH;
		goto export_cleanup;
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "memory_loopback: ddi_map_regs returned "
	    "map_kaddr 0x%p", (void *)map_kaddr));


	/*
	 * write/read through the WCI
	 */
	memptr = map_kaddr;

	loop_arg.paddr = va_to_pa((void *)aligned_buf);
	for (i = 0; i < WRSM_MAX_PATTERN; i++) {
		if (loop_arg.patterns & (1 << i)) {
			/*
			 * make sure there are no accidentally correct
			 * patterns in the buffer
			 */
			bzero((void *)buf, bufsize);
			if ((err = wrsm_open_barrier_region(importseg,
			    &barrier)) != RSM_SUCCESS) {
				err = EINVAL;
				goto import_cleanup;
			}
			if ((err = (lpk_pattern_test[i])(memptr, MEMLOOP_BSIZE,
			    &error_offset, loop_arg.expected_data,
			    loop_arg.actual_data)) != 0) {
				loop_arg.error_pattern = (1 << i);
				loop_arg.paddr =
				    va_to_pa((void *)(aligned_buf +
				    error_offset));
				err = EIO;
				goto import_cleanup;
			}
			if ((err = wrsm_close_barrier(&barrier))
			    != RSM_SUCCESS) {
				/*
				 * distinguish from write/read error in
				 * pattern subtest
				 */
				if (err == RSMERR_BARRIER_FAILURE)
					err = ENETRESET;
				else
					err = EINVAL;
				goto import_cleanup;
			}
		}
	}

	/*
	 * finished successfully
	 */

import_cleanup:
	ddi_unmap_regs(dip, dev_register, &map_kaddr, dev_offset,
	    map_len);
	(void) wrsmrsm_unmap(importseg);
	(void) wrsmrsm_disconnect(importseg);

export_cleanup:
	(void) wrsmrsm_unpublish(exportseg);
	(void) wrsmrsm_seg_destroy(exportseg);
	wrsm_free(buf, bufsize);

	if (ddi_copyout(&loop_arg, (void *)arg, sizeof (wrsm_memloopback_arg_t),
	    0) != 0) {
		return (EFAULT);
	}

	return (err);
}



static int
wrsm_cf_sess(int cont_id, intptr_t arg, int flag)
{
	wrsm_network_t *network;
	wrsm_sess_arg_t sess_arg;
	int retval = 0;

	if (ddi_copyin((void *)arg, (char *)&sess_arg,
	    sizeof (wrsm_sess_arg_t), flag) != 0) {
		return (EFAULT);
	}

	if (sess_arg.ioctl_version != WRSM_CF_IOCTL_VERSION) {
		cmn_err(CE_WARN, "sess ioctl: user/kernel version mismatch");
		return (EINVAL);
	}

	if (find_controller(cont_id) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "sess ioctl: invalid controller "
		    "id  %d", cont_id));
		return (EINVAL);
	}

	if ((network = wrsm_nc_ctlr_to_network(cont_id)) == NULL) {
		DPRINTF(CF_WARN, (CE_WARN, "sess ioctl: no network struct "
		    "for controller %d", cont_id));
		return (EINVAL);
	}

	DPRINTF(CF_DEBUG, (CE_CONT, "sess cmd %d: %u",
	    sess_arg.cmd, sess_arg.cnodeid));
	switch (sess_arg.cmd) {
	case WRSM_CTLR_SESS_START:
		if (wrsm_sess_establish(network, sess_arg.cnodeid) == 0) {
			retval = EAGAIN;
		}
		break;
	case WRSM_CTLR_SESS_END:
		wrsm_sess_teardown(network, sess_arg.cnodeid);
		break;
	case WRSM_CTLR_SESS_ENABLE:
		wrsm_sess_enable(network, sess_arg.cnodeid);
		break;
	case WRSM_CTLR_SESS_DISABLE:
		retval = wrsm_sess_disable(network, sess_arg.cnodeid);
		break;
	case WRSM_CTLR_SESS_GET:
		wrsm_sess_get_cnodes(network, &sess_arg.cnode_bitmask);
		break;
	default:
		retval = ENOTSUP;
	}
	if (ddi_copyout(&sess_arg, (void *)arg, sizeof (wrsm_sess_arg_t),
	    0) != 0) {
		return (EFAULT);
	}
	return (retval);
}


/*
 * verify that the ncslice array has valid values, then convert into
 * a bitmask.  Return 0 if valid.
 */
static int
wrsm_cf_ncslicelist_to_bitmask(wrsm_node_ncslice_array_t slice_array,
    ncslice_t *small_ncslicep,
    ncslice_bitmask_t *large_slice_bitmask)
{
	int i;

	*small_ncslicep = slice_array.id[0];
	if (*small_ncslicep == 0 || *small_ncslicep >= WRSM_MAX_NCSLICES) {
		return (EINVAL);
	}

	/*
	 * Verify the large page ncslices are valid.  The ncslice for entry
	 * 1 must end with b'001', the ncslice for entry 2 must end with
	 * b'010', entry 3 with b'011' and so on.  An ncslice value of 0
	 * indicates that the entry is invalid.
	 */
	WRSMSET_ZERO(*large_slice_bitmask);
	for (i = 1; i < WRSM_NODE_NCSLICES; i++) {
		if (slice_array.id[i] == 0) {
			continue;
		}
		if (slice_array.id[i] >= WRSM_MAX_NCSLICES) {
			return (EINVAL);
		}
		if (!wrsm_large_pages_supported) {
			cmn_err(CE_NOTE,
			    "verify: large page ncslices not supported");
			return (ENOTSUP);
		}
		if ((slice_array.id[i] & 0x7) != i) {
			cmn_err(CE_NOTE, "verify: invalid large page ncslice");
			return (EINVAL);
		}
		if (slice_array.id[i] == *small_ncslicep) {
			cmn_err(CE_NOTE,
			    "verify: large page ncslice not unique");
			return (EINVAL);
		}

		WRSMSET_ADD(*large_slice_bitmask, slice_array.id[i]);
	}
	DPRINT_BITMASK("wrsm_cf_ncslicelist_to_bitmask large slices",
	    *large_slice_bitmask);

	return (0);
}
