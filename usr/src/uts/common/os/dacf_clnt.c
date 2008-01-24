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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DACF (Device Autoconfiguration Framework) client code.
 *
 * DACF has two clients. the first is dacf modules which implement
 * configuration operations; the second is the set of hooks in the kernel
 * which do rule matching and invoke configuration operations.
 *
 * This file implements the second part, the kernel hooks.
 *
 * Currently implemented are post-attach and pre-detach handlers, and the hook
 * for ddi_create_minor_common() which sets up post-attach and pre-detach
 * reservations.
 *
 * This code depends on the core dacf code (in dacf.c) but the converse should
 * never be true.
 *
 * This file also implements '__kernel', the kernel-supplied dacf module.
 * For now, this is pretty much empty, except under DEBUG, in which case it
 * contains some debugging code.
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/autoconf.h>
#include <sys/modhash.h>
#include <sys/dacf_impl.h>
#include <sys/systm.h>
#include <sys/debug.h>

/*
 * dacfc_match_create_minor()
 * 	Check to see if this minor node creation sequence matches a dacf
 * 	(device autoconfiguration framework) rule.  If so make a reservation
 * 	for the operation to be invoked at post-attach and/or pre-detach time.
 */
void
dacfc_match_create_minor(char *name, char *node_type, dev_info_t *dip,
    struct ddi_minor_data *dmdp, int flag)
{
	dacf_rule_t *r;
	char *dev_path, *dev_pathp, *drv_mname = NULL;
	dacf_rsrvlist_t *pa_rsrv, *pd_rsrv;

	/*
	 * Check the dacf rule for non-clone devices or for network devices.
	 */
	if ((flag & CLONE_DEV) && (strcmp(node_type, DDI_NT_NET) != 0)) {
		return;
	}

	/*
	 * Because dacf currently only implements post-attach and pre-detach
	 * processing, we only care about minor nodes created during attach.
	 * However, there is no restriction on drivers about when to create
	 * minor nodes.
	 */
	if (!DEVI_IS_ATTACHING(dmdp->dip)) {
		return;
	}

	dev_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	dev_pathp = ddi_pathname(dip, dev_path);
	pa_rsrv = kmem_alloc(sizeof (dacf_rsrvlist_t), KM_SLEEP);
	pd_rsrv = kmem_alloc(sizeof (dacf_rsrvlist_t), KM_SLEEP);

	if (name) {
		const char *drv_name = ddi_driver_name(dip);
		if (drv_name == NULL)
			drv_name = "???";
		drv_mname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) snprintf(drv_mname, MAXPATHLEN, "%s:%s", drv_name, name);
	}

	mutex_enter(&dacf_lock);

	/*
	 * Ensure that we don't wind up in a 'matching loop' against a devinfo
	 * node, which could cause deadlock.  This could happen as follows:
	 *
	 * 	We match (just below)
	 * 	We invoke a task (later, at the end of devi_attach)
	 *	   this means we have taken the per-devinfo lock
	 * 	The task invoke winds up causing the same driver (that has
	 *	   just finished attaching) to create another minor node.
	 * 	We try to re-acquire the per-devinfo list lock again in the
	 *	   process of making another reservation
	 */
	mutex_enter(&(DEVI(dip)->devi_lock));
	if (DEVI_IS_INVOKING_DACF(dip)) {
		mutex_exit(&(DEVI(dip)->devi_lock));
		cmn_err(CE_WARN,
		    "!dacf detected deadlock, aborting matching procedure\n");
		mutex_exit(&dacf_lock);
		kmem_free(pa_rsrv, sizeof (dacf_rsrvlist_t));
		kmem_free(pd_rsrv, sizeof (dacf_rsrvlist_t));
		kmem_free(dev_path, MAXPATHLEN);
		if (drv_mname) {
			kmem_free(drv_mname, MAXPATHLEN);
		}
		return;
	}
	mutex_exit(&(DEVI(dip)->devi_lock));

	/*
	 * Do rule matching.  It's possible to construct two rules that would
	 * match against the same minor node, so we match from most to least
	 * specific:
	 * 	device path
	 * 	minor node name (concatenation of drv_name:name
	 * 	node type
	 *
	 * Future additions to the set of device-specifiers should be
	 * sensitive to this ordering.
	 */

	/*
	 * post-attach matching
	 */
	r = NULL;
	if (dev_pathp) {
		r = dacf_match(DACF_OPID_POSTATTACH, DACF_DS_DEV_PATH,
		    dev_pathp);
	}
	if (!r && drv_mname) {
		r = dacf_match(DACF_OPID_POSTATTACH, DACF_DS_DRV_MNAME,
		    drv_mname);
	}
	if (!r && node_type) {
		r = dacf_match(DACF_OPID_POSTATTACH, DACF_DS_MIN_NT, node_type);
	}
	if (r) {
		dacf_rsrv_make(pa_rsrv, r, dmdp, &(DEVI(dip)->devi_dacf_tasks));

		if (dacfdebug & DACF_DBG_MSGS)
			printf("dacf: made 'post-attach' reservation for "
			    "%s, %s, %s\n", name, node_type, dev_pathp);
	} else {
		kmem_free(pa_rsrv, sizeof (dacf_rsrvlist_t));
	}

	/*
	 * pre-detach matching
	 */
	r = NULL;
	if (dev_pathp) {
		r = dacf_match(DACF_OPID_PREDETACH, DACF_DS_DEV_PATH,
		    dev_pathp);
	}
	if (!r && drv_mname) {
		r = dacf_match(DACF_OPID_PREDETACH, DACF_DS_DRV_MNAME,
		    drv_mname);
	}
	if (!r && node_type) {
		r = dacf_match(DACF_OPID_PREDETACH, DACF_DS_MIN_NT, node_type);
	}
	if (r) {
		dacf_rsrv_make(pd_rsrv, r, dmdp, &(DEVI(dip)->devi_dacf_tasks));

		if (dacfdebug & DACF_DBG_MSGS) {
			printf("dacf: made 'pre-detach' reservation for "
			    "%s, %s, %s\n", name, node_type, dev_pathp);
		}
	} else {
		kmem_free(pd_rsrv, sizeof (dacf_rsrvlist_t));
	}

	mutex_exit(&dacf_lock);
	kmem_free(dev_path, MAXPATHLEN);
	if (drv_mname) {
		kmem_free(drv_mname, MAXPATHLEN);
	}
}

/*
 * dacfc_postattach()
 * 	autoconfiguration for post-attach events.
 *
 * 	strategy: try to configure.  If some of the configuration operations
 * 	fail, emit a warning.
 */
int
dacfc_postattach(dev_info_t *devi)
{
	int err = DACF_SUCCESS;
	char *path, *pathp;
	dacf_rsrvlist_t **opsp, *op;
	ASSERT(MUTEX_HELD(&dacf_lock));

	/*
	 * Instruct dacf_process_rsrvs() to invoke each POSTATTACH op.
	 */
	opsp = &DEVI(devi)->devi_dacf_tasks;
	dacf_process_rsrvs(opsp, DACF_OPID_POSTATTACH, DACF_PROC_INVOKE);

	/*
	 * Check to see that all POSTATTACH's succeeded.
	 */
	for (op = *opsp; op != NULL; op = op->rsrv_next) {
		if (op->rsrv_rule->r_opid != DACF_OPID_POSTATTACH)
			continue;
		if (op->rsrv_result == DACF_SUCCESS)
			continue;
		if (dacfdebug & DACF_DBG_DEVI) {
			cmn_err(CE_WARN, "op failed, err = %d\n",
			    op->rsrv_result);
		}
		err = DACF_FAILURE;
		break;
	}

	/*
	 * If one or more postattach's failed, give up.
	 */
	if ((err == DACF_FAILURE) && (dacfdebug & DACF_DBG_DEVI)) {
		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if ((pathp = ddi_pathname(devi, path)) == NULL)
			pathp = "<unknown>";
		cmn_err(CE_WARN, "%s attached, but failed to auto-configure",
		    pathp);
		kmem_free(path, MAXPATHLEN);
	}

	return (err);
}

/*
 * dacfc_predetach()
 * 	auto-unconfiguration for pre-detach events.
 *
 * 	strategy: call the pre-detach operation for all matching reservations.
 * 	If any of these fail, make (one) attempt to reconfigure things back
 * 	into a sane state.  if that fails, our state is uncertain.
 */
int
dacfc_predetach(dev_info_t *devi)
{
	int err = DDI_SUCCESS;
	char *path, *pathp;
	dacf_rsrvlist_t **opsp, *op;
	ASSERT(MUTEX_HELD(&dacf_lock));

	/*
	 * Instruct dacf_process_rsrvs() to invoke each PREDETACH op.
	 */
	opsp = &DEVI(devi)->devi_dacf_tasks;
	dacf_process_rsrvs(opsp, DACF_OPID_PREDETACH, DACF_PROC_INVOKE);

	/*
	 * Check to see that all PREDETACH's succeeded.
	 */
	for (op = *opsp; op != NULL; op = op->rsrv_next) {
		if (op->rsrv_rule->r_opid != DACF_OPID_PREDETACH)
			continue;
		if (op->rsrv_result == 0)
			continue;
		err = DDI_FAILURE;
		break;
	}

	/*
	 * If one or more predetach's failed, make one attempt to fix things
	 * by re-running all of the POST-ATTACH operations.  If any of those
	 * fail, give up.
	 */
	if (err == DDI_FAILURE) {
		int pa_err;

		if (dacfdebug & DACF_DBG_DEVI) {
			path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			if ((pathp = ddi_pathname(devi, path)) == NULL)
				pathp = "<unknown>";
			cmn_err(CE_WARN, "%s failed to auto-unconfigure, "
			    "attempting to reconfigure...", pathp);
			kmem_free(path, MAXPATHLEN);
		}

		pa_err = dacfc_postattach(devi);

		if (dacfdebug & DACF_DBG_DEVI) {
			path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			if ((pathp = ddi_pathname(devi, path)) == NULL)
				pathp = "<unknown>";

			if (pa_err == DDI_FAILURE) {
				cmn_err(CE_WARN, "%s failed to "
				    "auto-unconfigure, and could not be "
				    "re-autoconfigured.", pathp);
			} else {
				cmn_err(CE_WARN, "%s failed to "
				    "auto-unconfigure, but was successfully "
				    "re-autoconfigured.", pathp);
			}
			kmem_free(path, MAXPATHLEN);
		}
	}

	return (err);
}

/*
 * kmod_dacfsw:
 * 	This is the declaration for the kernel-supplied '__kernel' dacf module.
 * 	DACF supplies a framework based around loadable modules.  However, it
 * 	may be convenient (in the future) to have a module provided by the
 * 	kernel.  This is useful in cases when a module can't be loaded (early in
 * 	boot), or for code that would never get unloaded anyway.
 */
#ifdef DEBUG
/*ARGSUSED*/
static int
kmod_test_postattach(dacf_infohdl_t info_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	const char *verbose = dacf_get_arg(arg_hdl, "verbose");
	if (verbose && (strcmp(verbose, "true") == 0)) {
		cmn_err(CE_WARN, "got kmod_test_postattach\n");
	}
	return (0);
}
#endif

static dacf_op_t kmod_op_test[] = {
#ifdef DEBUG
	{ DACF_OPID_POSTATTACH, kmod_test_postattach },
#endif
	{ DACF_OPID_END,	NULL },
};

static dacf_opset_t kmod_opsets[] = {
#ifdef DEBUG
	{ "kmod_test",		kmod_op_test },
#endif
	{ NULL,			NULL },
};

struct dacfsw kmod_dacfsw = {
	DACF_MODREV_1, kmod_opsets
};
