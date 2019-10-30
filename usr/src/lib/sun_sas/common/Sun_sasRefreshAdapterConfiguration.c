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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include    <sun_sas.h>

/*
 * Discover an HBA node with  matching path.
 * The di_node_t argument should be the root of the device tree.
 * This routine assumes the locks have been taken
 */
static int
find_matching_hba(di_node_t node, void *arg)
{
	int *propData, rval;
	walkarg_t *wa = (walkarg_t *)arg;
	char	*devpath, fulldevpath[MAXPATHLEN];

	/* Skip stub(instance -1) nodes */
	if (IS_STUB_NODE(node)) {
		return (DI_WALK_CONTINUE);
	}

	rval = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "sm-hba-supported", &propData);
	if (rval < 0) {
		return (DI_WALK_CONTINUE);
	} else {
		if ((devpath = di_devfs_path(node)) == NULL) {
			/* still continue to see if there is matching one. */
			return (DI_WALK_CONTINUE);
		}
		(void) snprintf(fulldevpath, MAXPATHLEN, "%s%s", DEVICES_DIR,
		    devpath);

		if ((strstr(fulldevpath, wa->devpath)) != NULL) {
			*wa->flag = B_TRUE;
			/* Found a node. No need to walk any more. */
			di_devfs_path_free(devpath);
			return (DI_WALK_TERMINATE);
		}
		di_devfs_path_free(devpath);
	}

	return (DI_WALK_CONTINUE);
}

/*
 * Refreshes information about an HBA
 *
 * Note: This routine holds the locks in write mode
 *       during most of the processing, and as such, will cause
 *	 all other threads to block on entry into the library
 *	 until the refresh is complete.  An optimization would be
 *       to put fine-grain locking in for the open_handle structures.
 */
void
Sun_sasRefreshAdapterConfiguration()
{
	const char		    ROUTINE[] =
	    "Sun_sasRefreshAdapterConfiguration";
	struct sun_sas_hba	    *hba_ptr;
	di_node_t		    root;
	hrtime_t		    start;
	hrtime_t		    end;
	double			    duration;
	walkarg_t		    wa;

	/*
	 * We're going to be tweaking a lot of global lists, so write
	 * lock them.
	 */
	lock(&all_hbas_lock);
	lock(&open_handles_lock);

	start = gethrtime();
	/* Grab device tree */
	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to load device tree for reason \"%s\"",
		    strerror(errno));
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return;
	}

	end = gethrtime();
	duration = end - start;
	duration /= HR_SECOND;
	log(LOG_DEBUG, ROUTINE, "Device tree init took "
	    "%.6f seconds", duration);

	for (hba_ptr = global_hba_head; hba_ptr != NULL;
	    hba_ptr = hba_ptr->next) {
		wa.devpath = hba_ptr->device_path;
		wa.flag = (boolean_t *)calloc(1, sizeof (boolean_t));
		*wa.flag = B_FALSE;

		if (di_walk_node(root, DI_WALK_SIBFIRST, &wa,
		    find_matching_hba) != 0) {
			log(LOG_DEBUG, ROUTINE, "di_walk_node failed.");
			unlock(&open_handles_lock);
			unlock(&all_hbas_lock);
			S_FREE(wa.flag);
			di_fini(root);
			return;
		}

		if (*wa.flag == B_FALSE) {
			/*
			 * Keep the HBA as it is including open handles
			 * per the SM-HBA standards. Just mark it as invalid.
			 */
			log(LOG_DEBUG, ROUTINE, "No matching HBA found. %s",
			    hba_ptr->device_path);
			hba_ptr->invalid = B_TRUE;
		}
		S_FREE(wa.flag);
	}

	/*
	 * Now we marked missing HBA(s). Redisoover hbas to refresh
	 * or add any new adapter to the hba list.
	 * Simply call devtree_get_all_hbas().
	 */
	if (devtree_get_all_hbas(root) != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "devtree_get_all_hbas failed.");
	}
	di_fini(root);

	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);
}
