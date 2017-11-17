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

/*
 * s1394_hotplug.c
 *    1394 Services Layer Hotplug Routines
 *    This file contains routines that walk the old and topology
 *    trees, at bus reset time, creating devinfo's for new nodes and offlining
 *    nodes that are removed.
 */

#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/types.h>

#include <sys/tnf_probe.h>

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>

static void s1394_send_remove_event(s1394_hal_t *hal, dev_info_t *dip,
    t1394_localinfo_t *localinfo);
static void s1394_send_insert_event(s1394_hal_t *hal, dev_info_t *dip,
    t1394_localinfo_t *localinfo);
static dev_info_t *s1394_create_devinfo(s1394_hal_t *hal, s1394_node_t *node,
    uint32_t *unit_dir, int nunit);
static void s1394_update_unit_dir_location(s1394_hal_t *hal, dev_info_t *tdip,
    uint_t offset);

/*
 * s1394_send_remove_event()
 *    Invokes any "remove event" callback registered for dip. Passes
 *    t1394_localinfo_t as impl_data for the callback.
 */
static void
s1394_send_remove_event(s1394_hal_t *hal, dev_info_t *dip,
    t1394_localinfo_t *localinfo)
{
	char name[128];
	ddi_eventcookie_t cookie;

	(void) sprintf(name, "%s%d", ddi_driver_name(dip),
	    ddi_get_instance(dip));

	TNF_PROBE_1_DEBUG(s1394_send_remove_event_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_string, device,
	    name);

	if (ndi_event_retrieve_cookie(hal->hal_ndi_event_hdl, dip,
	    DDI_DEVI_REMOVE_EVENT, &cookie, NDI_EVENT_NOPASS)
	    == NDI_SUCCESS) {
		(void) ndi_event_run_callbacks(hal->hal_ndi_event_hdl, dip,
		    cookie, localinfo);
	}
	TNF_PROBE_0_DEBUG(s1394_send_remove_event_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");
}

/*
 * s1394_send_insert_event()
 *    Invokes any "insert event" callback registered for dip. Passes
 *    t1394_localinfo_t as impl_data for the callback.
 */
static void
s1394_send_insert_event(s1394_hal_t *hal, dev_info_t *dip,
    t1394_localinfo_t *localinfo)
{
	char name[128];
	ddi_eventcookie_t cookie;

	(void) sprintf(name, "%s%d", ddi_driver_name(dip),
	    ddi_get_instance(dip));

	TNF_PROBE_1_DEBUG(s1394_send_insert_event_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_string, device,
	    name);

	if (ndi_event_retrieve_cookie(hal->hal_ndi_event_hdl, dip,
	    DDI_DEVI_INSERT_EVENT, &cookie, NDI_EVENT_NOPASS) ==
	    NDI_SUCCESS)
		(void) ndi_event_run_callbacks(hal->hal_ndi_event_hdl, dip,
		    cookie, localinfo);

	TNF_PROBE_0_DEBUG(s1394_send_insert_event_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");
}

/*
 * s1394_create_devinfo()
 *    This routine creates a devinfo corresponding to the unit_dir passed in.
 *    It adds "hp-node", "reg", "compatible" properties to the devinfo
 *    (formats for "reg" and "compatible" properties are specified by 1275
 *    binding for IEEE1394). If unable to create the devinfo and/or add the
 *    the properties, returns NULL, otherwise, returns the devinfo created.
 *
 *    NOTE: All ndi_* routines are interrupt callable (and thus won't sleep).
 *    So, we don't drop topology_mutex across ndi calls.
 */
static dev_info_t *
s1394_create_devinfo(s1394_hal_t *hal, s1394_node_t *node, uint32_t *unit_dir,
    int nunit)
{
	dev_info_t *hal_dip;
	uint32_t *root_dir;
	dev_info_t *target_dip;

	int root_dir_len;
	int result, i, j, spec_id, sw_version;
	int mod_ven, mod_hw, mod_spec, mod_sw;
	int node_ven, node_hw, node_spec, node_sw;

	/*LINTED type is unused*/
	uint32_t type __unused, key, value;
	uint32_t unit_spec_id, unit_sw_version;
	uint32_t node_spec_id, node_sw_version;
	uint32_t node_vendor_id, node_hw_version;
	uint32_t module_spec_id, module_sw_version;
	uint32_t module_vendor_id, module_hw_version;

	char *fmt = "firewire%06x,%06x";

	char *buf[5], data[5][24];
	uint32_t reg[6];

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	TNF_PROBE_2_DEBUG(s1394_create_devinfo_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_uint, guid_hi,
	    node->node_guid_hi, tnf_uint, guid_lo, node->node_guid_lo);

	hal_dip = hal->halinfo.dip;

	/* Allocate and init a new device node instance. */
	result = ndi_devi_alloc(hal_dip, "unit", (pnode_t)DEVI_SID_NODEID,
	    &target_dip);

	if (result != NDI_SUCCESS) {
		cmn_err(CE_NOTE, "!Unable to create devinfo"
		    " (node's GUID %08x%08x)", node->node_guid_hi,
		    node->node_guid_lo);
		TNF_PROBE_2(s1394_create_devinfo_fail_alloc,
		    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_uint, guid_hi,
		    node->node_guid_hi, tnf_uint, guid_lo, node->node_guid_lo);
		TNF_PROBE_0_DEBUG(s1394_create_devinfo_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (NULL);
	}

	/* Add "hp-node" property */
	result = ndi_prop_update_int(DDI_DEV_T_NONE, target_dip, "hp-node", 0);
	if (result != NDI_SUCCESS) {
		cmn_err(CE_NOTE, "!Unable to add \"hp-node\" property"
		    " (node's GUID %08x%08x)", node->node_guid_hi,
		    node->node_guid_lo);
#if defined(DEBUG)
		cmn_err(CE_CONT, "!Error code %d", result);
#endif
		TNF_PROBE_3(s1394_create_devinfo_hp_node,
		    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_uint, guid_hi,
		    node->node_guid_hi, tnf_uint, guid_lo, node->node_guid_lo,
		    tnf_int, error, result);
		ndi_prop_remove_all(target_dip);
		(void) ndi_devi_free(target_dip);
		TNF_PROBE_0_DEBUG(s1394_create_devinfo_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (NULL);
	}

	spec_id = sw_version = mod_ven = mod_hw = mod_spec = mod_sw =
	    node_ven = node_hw = node_spec = node_sw = 0;
	unit_sw_version = node_sw_version = node_hw_version =
	    module_sw_version = module_hw_version = 0;


	root_dir = CFGROM_ROOT_DIR(node->cfgrom);
	root_dir_len = CFGROM_DIR_LEN(root_dir);

	for (i = 0; i < root_dir_len; i++) {

		CFGROM_TYPE_KEY_VALUE(root_dir[i + 1], type, key, value);
		switch (key) {

		case IEEE1212_MODULE_VENDOR_ID:
			module_vendor_id = value;
			mod_ven++;
			break;
		case IEEE1212_MODULE_HW_VERSION:
			module_hw_version = value;
			mod_hw++;
			break;
		case IEEE1212_MODULE_SPEC_ID:
			module_spec_id = value;
			mod_spec++;
			break;
		case IEEE1212_MODULE_SW_VERSION:
			module_sw_version = value;
			mod_sw++;
			break;
		case IEEE1212_NODE_VENDOR_ID:
			node_vendor_id = value;
			node_ven++;
			break;
		case IEEE1212_NODE_UNIQUE_ID: {
				uint32_t *node_unique_leaf =
				    &root_dir[i + 1] + value;
				node_vendor_id = (node_unique_leaf[1] >> 8);
				node_ven++;
			}
			break;
		case IEEE1212_NODE_HW_VERSION:
			node_hw_version = value;
			node_hw++;
			break;
		case IEEE1212_NODE_SPEC_ID:
			node_spec_id = value;
			node_spec++;
			break;
		case IEEE1212_NODE_SW_VERSION:
			node_sw_version = value;
			node_sw++;
			break;
		}

		if (mod_ven && mod_hw && mod_spec && mod_sw && node_ven &&
		    node_hw && node_spec && node_sw) {
			break;
		}
	}

	/*
	 * Search for unit spec and version
	 */
	for (i = 0; i < CFGROM_DIR_LEN(unit_dir); i++) {

		CFGROM_TYPE_KEY_VALUE(unit_dir[i + 1], type, key, value);
		if (key == IEEE1212_UNIT_SPEC_ID) {

			unit_spec_id = value;
			spec_id++;
		} else if (key == IEEE1212_UNIT_SW_VERSION) {

			unit_sw_version = value;
			sw_version++;
		}
		if (spec_id && sw_version)
			break;
	}

	/*
	 * Refer to IEEE1212 (pages 90-92) for information regarding various
	 * id's. Module_Vendor_Id is required. Node_Vendor_Id is optional and
	 * if not implemented, its assumed value is Module_Vendor_Id.
	 * Module_Spec_Id is optional and if not implemented, its assumed value
	 * is Module_Vendor_Id. Node_Spec_Id is optional, and if not
	 * implemented, its assumed value is Node_Vendor_Id. Unit_Spec_Id is
	 * optional, and if not implemented, its assumed value is
	 * Node_Vendor_Id.
	 */
	if (node_ven == 0) {
		node_vendor_id = module_vendor_id;
		node_ven++;
	}

	if (node_spec == 0) {
		node_spec_id = node_vendor_id;
		node_spec++;
	}

	if (mod_spec == 0) {
		module_spec_id = module_vendor_id;
		mod_spec++;
	}

	if (spec_id == 0) {
		unit_spec_id = node_vendor_id;
		spec_id++;
	}

	i = 0;
	if (sw_version != 0) {
		buf[i] = data[i];
		(void) sprintf(data[i++], fmt, unit_spec_id, unit_sw_version);
	}
	if (node_sw != 0) {
		buf[i] = data[i];
		(void) sprintf(data[i++], fmt, node_spec_id, node_sw_version);
	}
	if (node_hw != 0) {
		buf[i] = data[i];
		(void) sprintf(data[i++], fmt, node_vendor_id, node_hw_version);
	}
	if (mod_sw != 0) {
		buf[i] = data[i];
		(void) sprintf(data[i++], fmt, module_spec_id,
		    module_sw_version);
	}
	if (mod_hw != 0) {
		buf[i] = data[i];
		(void) sprintf(data[i++], fmt, module_vendor_id,
		    module_hw_version);
	}

	result = ndi_prop_update_string_array(DDI_DEV_T_NONE, target_dip,
	    "compatible", (char **)&buf, i);
	if (result != NDI_SUCCESS) {
		cmn_err(CE_NOTE, "!Unable to add \"compatible\" property"
		    " (node's GUID %08x%08x)", node->node_guid_hi,
		    node->node_guid_lo);
#if defined(DEBUG)
		cmn_err(CE_CONT, "!Error code %d; nelements %d", result, i);
		for (j = 0; j < i; j++) {
			cmn_err(CE_CONT, "!buf[%d]: %s", j, buf[j]);
		}
#endif
		ndi_prop_remove_all(target_dip);
		(void) ndi_devi_free(target_dip);
		TNF_PROBE_4(s1394_create_devinfo_fail_compat,
		    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_uint, guid_hi,
		    node->node_guid_hi, tnf_uint, guid_lo, node->node_guid_lo,
		    tnf_int, error, result, tnf_int, nelements, i);
		TNF_PROBE_0_DEBUG(s1394_create_devinfo_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (NULL);
	}

	for (j = 0; j < i; j++) {
		TNF_PROBE_2_DEBUG(s1394_create_devinfo_props,
		    S1394_TNF_SL_HOTPLUG_STACK, "",
		    tnf_int, compat_index, j,
		    tnf_string, compat_prop, buf[j]);
	}

	/* GUID,ADDR */
	reg[0] = node->node_guid_hi;
	reg[1] = node->node_guid_lo;
	s1394_cfgrom_parse_unit_dir(unit_dir, &reg[2], &reg[3], &reg[4],
	    &reg[5]);

	reg[3] = nunit;

	result = ndi_prop_update_int_array(DDI_DEV_T_NONE, target_dip, "reg",
	    (int *)reg, 6);
	if (result != NDI_SUCCESS) {
		cmn_err(CE_NOTE, "!Unable to add \"reg\" property");
#if defined(DEBUG)
		cmn_err(CE_CONT, "!Error code %d", result);
		for (j = 0; j < 6; j++) {
			cmn_err(CE_CONT, "!reg[%d]: 0x%08x", j, reg[j]);
		}
#endif
		ndi_prop_remove_all(target_dip);
		(void) ndi_devi_free(target_dip);
		TNF_PROBE_3(s1394_create_devinfo_fail_reg,
		    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_uint, guid_hi,
		    node->node_guid_hi, tnf_uint, guid_lo, node->node_guid_lo,
		    tnf_int, error, result);
		TNF_PROBE_0_DEBUG(s1394_create_devinfo_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (NULL);
	}

	TNF_PROBE_1_DEBUG(s1394_create_devinfo_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "",
	    tnf_opaque, target_dip, target_dip);

	return (target_dip);
}

/*
 * s1394_devi_find()
 *    Searches all children of pdip for a match of name@caddr. Builds the
 *    name and address of each child node by looking up the reg property on
 *    the node and compares the built name@addr with the name@addr passed in.
 *    Returns the child dip if a match is found, otherwise, returns NULL.
 *    NOTE:
 *    This routine is decidedly non-ddi. We had to use this one since
 *    ndi_devi_find() can find only nodes that have valid addr field
 *    set and that won't happen unless the node goes through INITCHILD
 *    (at which time nx1394.c calls ddi_set_name_addr()). If, in future,
 *    the ndi_devi_find() provides a way of looking up nodes using criteria
 *    other than addr, we can get rid of this routine.
 */
/*ARGSUSED*/
dev_info_t *
s1394_devi_find(dev_info_t *pdip, char *name, char *caddr)
{
	int i, reglen;
	char addr[32];
	uint32_t *regptr;
	dev_info_t *cdip = NULL;

	ASSERT((name != NULL) && (caddr != NULL));

	TNF_PROBE_1_DEBUG(s1394_devi_find_enter, S1394_TNF_SL_HOTPLUG_STACK,
	    "", tnf_string, addr, caddr);

	/*
	 * for each child of this parent, find name and addr and match with
	 * name and caddr passed in.
	 */
	for (cdip = (dev_info_t *)DEVI(pdip)->devi_child; cdip != NULL;
	    cdip = (dev_info_t *)DEVI(cdip)->devi_sibling) {

		i = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "reg", (int **)&regptr,
		    (uint_t *)&reglen);

		if (i != DDI_PROP_SUCCESS)
			continue;

		/*
		 * Construct addr from the reg property (addr is of the format
		 * GGGGGGGGGGGGGGGG[,AAAAAAAAAAAA], where GGGGGGGGGGGGGGGG is
		 * the address and AAAAAAAAAAAA is the optional unit address)
		 */
		if (regptr[2] != NULL || regptr[3] != NULL) {
			(void) sprintf(addr, "%08x%08x,%04x%08x", regptr[0],
			    regptr[1], regptr[2], regptr[3]);
		} else {
			(void) sprintf(addr, "%08x%08x", regptr[0], regptr[1]);
		}
		ddi_prop_free(regptr);

		if (strcmp(caddr, addr) == 0) {
			ASSERT(strcmp(ddi_node_name(cdip), name) == 0);
			break;
		}
	}

	if (cdip == NULL) {
		TNF_PROBE_1(s1394_devi_find_no_match,
		    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string, addr, caddr);
	}

	TNF_PROBE_0_DEBUG(s1394_devi_find_exit, S1394_TNF_SL_HOTPLUG_STACK, "");

	return (cdip);
}

/*
 * s1394_update_devinfo_tree()
 *    Parses the config rom for the passed in node and creates/updates devinfo's
 *    for each unit directory found. If the devinfo corresponding to a unit
 *    already exists, any insert event callbacks registered for that devinfo
 *    are called (topology tree is unlocked and relocked around these
 *    callbacks). Returns DDI_SUCCESS if everything went fine and DDI_FAILURE
 *    if unable to reacquire the lock after callbacks (relock fails because of
 *    an intervening bus reset or if the services layer kills the bus reset
 *    thread). The node is marked as parsed before returning.
 */
int
s1394_update_devinfo_tree(s1394_hal_t *hal, s1394_node_t *node)
{
	dev_info_t *tdip;
	int j, units, d, lockfail = 0;
	s1394_target_t *target, *t;
	uint32_t hi, lo, size_hi, size_lo, type, key, value;
	uint32_t *ptr, *root_dir, dir_len;
	t1394_localinfo_t linfo;

	uint32_t *unit_dir_ptrs[32];
	dev_info_t *devinfo_ptrs[32];
	uint32_t new_devinfo = 0;	/* to keep track of new allocations */

	char caddr[32];

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	ASSERT(CFGROM_PARSED(node) == B_FALSE);
	ASSERT(node->cfgrom != NULL);

	TNF_PROBE_2_DEBUG(s1394_update_devinfo_tree_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_int, node_num,
	    node->node_num, tnf_opaque, cfgrom, node->cfgrom);

	/* scan through config rom looking for unit dirs */
	root_dir = CFGROM_ROOT_DIR(node->cfgrom);

	if (node->cfgrom_valid_size < CFGROM_DIR_LEN(root_dir))
		dir_len = node->cfgrom_valid_size;
	else
		dir_len = CFGROM_DIR_LEN(root_dir);

	CFGROM_TYPE_KEY_VALUE(root_dir[0], type, key, value);
	if (s1394_valid_dir(hal, node, key, root_dir) == B_FALSE) {
		cmn_err(CE_NOTE,
		    "!Bad root directory in config rom (node's GUID %08x%08x)",
		    node->node_guid_hi, node->node_guid_lo);

		TNF_PROBE_1_DEBUG(s1394_update_devinfo_tree_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_string, msg,
		    "bad directory");

		SET_CFGROM_PARSED(node);
		CLEAR_CFGROM_GEN_CHANGED(node);	/* if set */
		CLEAR_CFGROM_NEW_ALLOC(node);

		return (DDI_SUCCESS);
	}

	for (units = 0, j = 1; j <= dir_len; j++) {
		CFGROM_TYPE_KEY_VALUE(root_dir[j], type, key, value);
		if (key == IEEE1212_UNIT_DIRECTORY && type ==
		    IEEE1212_DIRECTORY_TYPE) {
			ptr = &root_dir[j] + value;
			if (s1394_valid_dir(hal, node, key, ptr) == B_TRUE) {
				unit_dir_ptrs[units++] = ptr;
			} else {
				cmn_err(CE_NOTE, "!Bad unit directory in config"
				    " rom (node's GUID %08x%08x)",
				    node->node_guid_hi, node->node_guid_lo);
				TNF_PROBE_2(s1394_update_devinfo_tree_bad_dir,
				    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_uint,
				    guid_hi, node->node_guid_hi, tnf_uint,
				    guid_lo, node->node_guid_lo);
			}
		}
	}

	for (d = 0, j = 0; j < units; j++) {

		s1394_cfgrom_parse_unit_dir(unit_dir_ptrs[j],
		    &hi, &lo, &size_hi, &size_lo);

		lo = j;

		if (hi || lo) {
			(void) sprintf(caddr, "%08x%08x,%04x%08x",
			    node->node_guid_hi, node->node_guid_lo, hi, lo);
		} else {
			(void) sprintf(caddr, "%08x%08x",
			    node->node_guid_hi, node->node_guid_lo);
		}

		tdip = s1394_devi_find(hal->halinfo.dip, "unit", caddr);
		if (tdip != NULL) {

			rw_enter(&hal->target_list_rwlock, RW_WRITER);
			target = s1394_target_from_dip_locked(hal, tdip);
			if (target != NULL) {
				target->target_sibling = NULL;
				target->on_node = node;
				target->target_state &= ~S1394_TARG_GONE;
				target->unit_dir = unit_dir_ptrs[j] - root_dir;

				if ((t = node->target_list) != NULL) {
					ASSERT(t != target);
					while (t->target_sibling != NULL) {
						t = t->target_sibling;
						ASSERT(t != target);
					}
					t->target_sibling = target;
				} else {
					node->target_list = target;
				}

				target->target_list = node->target_list;
			}
			rw_exit(&hal->target_list_rwlock);

			s1394_update_unit_dir_location(hal, tdip,
			    unit_dir_ptrs[j] - root_dir);

		} else {
			/* create devinfo for unit@caddr */
			tdip = s1394_create_devinfo(hal, node,
			    unit_dir_ptrs[j], j);
			if (tdip != NULL) {
				new_devinfo |= (1 << d);
				s1394_update_unit_dir_location(hal, tdip,
				    unit_dir_ptrs[j] - root_dir);
			}
		}
		if (tdip != NULL)
			devinfo_ptrs[d++] = tdip;
	}

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	/* Online all valid units */
	for (j = 0; j < d; j++) {
		if ((new_devinfo & (1 << j)) == 0) {
			linfo.bus_generation = hal->generation_count;
			linfo.local_nodeID = hal->node_id;
		}
		/* don't need to drop topology_tree_mutex across ndi calls */
		(void) ndi_devi_online_async(devinfo_ptrs[j], 0);
		if ((new_devinfo & (1 << j)) == 0) {
			/*
			 * send an insert event if this an existing devinfo.
			 * drop and reacquire topology_tree_mutex across
			 * the event calls
			 */
			s1394_unlock_tree(hal);
			s1394_send_insert_event(hal, devinfo_ptrs[j], &linfo);
			if (s1394_lock_tree(hal) != DDI_SUCCESS) {
				TNF_PROBE_4(s1394_update_devinfo_tree_lock_fail,
				    S1394_TNF_SL_HOTPLUG_ERROR, "",
				    tnf_int, node_num, node->node_num,
				    tnf_opaque, cfgrom, node->cfgrom,
				    tnf_int, unit, j,
				    tnf_opaque, devinfo, devinfo_ptrs[j]);
				lockfail = 1;
				break;
			}
		}
	}

	if (lockfail) {
		TNF_PROBE_0_DEBUG(s1394_update_devinfo_tree_exit,
		    S1394_TNF_SL_HOTPLUG_ERROR, "");
		return (DDI_FAILURE);
	}

	SET_CFGROM_PARSED(node);
	CLEAR_CFGROM_GEN_CHANGED(node);	/* if set */
	CLEAR_CFGROM_NEW_ALLOC(node);

	TNF_PROBE_0_DEBUG(s1394_update_devinfo_tree_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");

	return (DDI_SUCCESS);
}

/*
 * s1394_offline_node()
 *    Offlines a node. This involves marking all targets attached to the
 *    node as gone, invoking any remove event callbacks and calling
 *    ndi_devi_offline to mark the devinfo as OFFLINE (for each unit
 *    directory on the node). The tree is unlocked and relocked around
 *    the callbacks. If unable to relock the tree, DDI_FAILURE, else
 *    returns DDI_SUCCESS.
 */
int
s1394_offline_node(s1394_hal_t *hal, s1394_node_t *node)
{
	s1394_target_t *t;
	dev_info_t *tdip;
	int j, d, units;
	uint32_t *unit_dir_ptrs[32];
	dev_info_t *devinfo_ptrs[32];
	t1394_localinfo_t linfo;
	uint_t node_num;
	uint32_t *ptr, *root_dir, dir_len;
	uint32_t hi, lo, size_hi, size_lo, type, key, value;
	char caddr[32];

	node_num = node->node_num;

	TNF_PROBE_1_DEBUG(s1394_offline_node_enter, S1394_TNF_SL_HOTPLUG_STACK,
	    "", tnf_uint, node_num, node_num);

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	d = 0;
	rw_enter(&hal->target_list_rwlock, RW_WRITER);
	t = node->target_list;
	while (t != NULL) {
		TNF_PROBE_2(s1394_process_old_tree_mark,
		    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_int, node_num, node_num,
		    tnf_opaque, target, t);
		t->target_state |= S1394_TARG_GONE;
		t->on_node = NULL;
		t = t->target_sibling;
	}
	rw_exit(&hal->target_list_rwlock);

	/* scan through config rom looking for unit dirs */
	root_dir = CFGROM_ROOT_DIR(node->cfgrom);

	if (node->cfgrom_valid_size < CFGROM_DIR_LEN(root_dir))
		dir_len = node->cfgrom_valid_size;
	else
		dir_len = CFGROM_DIR_LEN(root_dir);

	CFGROM_TYPE_KEY_VALUE(root_dir[0], type, key, value);

	for (units = 0, j = 1; j <= dir_len; j++) {
		CFGROM_TYPE_KEY_VALUE(root_dir[j], type, key, value);
		if (key == IEEE1212_UNIT_DIRECTORY && type ==
		    IEEE1212_DIRECTORY_TYPE) {
			ptr = &root_dir[j] + value;
			if (s1394_valid_dir(hal, node, key, ptr) == B_TRUE) {
				unit_dir_ptrs[units++] = ptr;
			}
		}
	}

	for (d = 0, j = 0; j < units; j++) {

		s1394_cfgrom_parse_unit_dir(unit_dir_ptrs[j],
		    &hi, &lo, &size_hi, &size_lo);

		lo = j;

		if (hi || lo) {
			(void) sprintf(caddr, "%08x%08x,%04x%08x",
			    node->node_guid_hi, node->node_guid_lo, hi, lo);
		} else {
			(void) sprintf(caddr, "%08x%08x",
			    node->node_guid_hi, node->node_guid_lo);
		}

		if ((tdip = s1394_devi_find(hal->halinfo.dip, "unit", caddr)) !=
		    NULL)
			devinfo_ptrs[d++] = tdip;
	}

	node->old_node = NULL;

	linfo.bus_generation = hal->generation_count;
	linfo.local_nodeID = hal->node_id;

	for (j = 0; j < d; j++) {
		s1394_unlock_tree(hal);

		TNF_PROBE_2(s1394_offline_node,
		    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_int, node_num, node_num,
		    tnf_opaque, devinfo, devinfo_ptrs[j]);

		s1394_send_remove_event(hal, devinfo_ptrs[j], &linfo);
		(void) ndi_devi_offline(devinfo_ptrs[j], NDI_DEVI_REMOVE);
		if (s1394_lock_tree(hal) != DDI_SUCCESS) {
			TNF_PROBE_2(s1394_offline_node,
			    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string, msg,
			    "unlock to relock tree", tnf_uint, node_num,
			    node_num);
			TNF_PROBE_0_DEBUG(s1394_offline_node_exit,
			    S1394_TNF_SL_HOTPLUG_STACK, "");
			return (DDI_FAILURE);
		}
	}

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	TNF_PROBE_0_DEBUG(s1394_offline_node_exit, S1394_TNF_SL_HOTPLUG_STACK,
	    "");
	return (DDI_SUCCESS);
}

/*
 * s1394_process_topology_tree()
 *    Walks the topology tree, processing each node. If node that has
 *    already been parsed, updates the generation property on all devinfos
 *    for the node. Also, if the node exists in both old & new trees, ASSERTS
 *    that both point to the same config rom. If the node has valid config
 *    rom but hasn't been parsed yet, calls s1394_update_devinfo_tree()
 *    to parse and create devinfos for the node. Kicks off further config
 *    rom reading if only the bus info block for the node is read.
 *    Returns DDI_SUCCESS if everything went fine, else returns DDI_FAILURE
 *    (for eg. unable to reacquire the tree lock etc). wait_for_cbs argument
 *    tells the caller if some completions can be expected. wait_gen tells
 *    the generation the commands were issued at.
 */
int
s1394_process_topology_tree(s1394_hal_t *hal, int *wait_for_cbs,
    uint_t *wait_gen)
{
	int i;
	uint_t hal_node_num, number_of_nodes;
	s1394_node_t *node, *onode;
	s1394_status_t status;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	TNF_PROBE_0_DEBUG(s1394_process_topology_tree_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "");

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		TNF_PROBE_0(s1394_process_topology_tree_lock_failed,
		    S1394_TNF_SL_HOTPLUG_ERROR, "");
		TNF_PROBE_0_DEBUG(s1394_process_topology_tree_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (DDI_FAILURE);
	}

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	hal->cfgroms_being_read = 0;
	number_of_nodes = hal->number_of_nodes;
	s1394_unlock_tree(hal);

	for (i = 0; i < number_of_nodes; i++) {

		if (i == hal_node_num)
			continue;
		if (s1394_lock_tree(hal) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		node = &hal->topology_tree[i];

		TNF_PROBE_4_DEBUG(s1394_process_topology_tree,
		    S1394_TNF_SL_HOTPLUG_STACK, "",
		    tnf_int, node_num, i,
		    tnf_int, parsed, CFGROM_PARSED(node),
		    tnf_int, matched, NODE_MATCHED(node),
		    tnf_int, visited, NODE_VISITED(node));

		if (LINK_ACTIVE(node) == B_FALSE) {
			s1394_unlock_tree(hal);
			continue;
		}
		if (node->cfgrom == NULL) {
			s1394_unlock_tree(hal);
			continue;
		}

		onode = node->old_node;

		if (onode != NULL && onode->cfgrom != NULL && node->cfgrom !=
		    NULL) {
			/*
			 * onode->cfgrom != node->cfgrom should have been
			 * handled by s1394_match_GUID()!!!
			 */
			if (onode->cfgrom != node->cfgrom)
				TNF_PROBE_5(s1394_process_topology_tree_err,
				    S1394_TNF_SL_HOTPLUG_ERROR, "",
				    tnf_int, node_num, i, tnf_int, gen_changed,
				    CFGROM_GEN_CHANGED(node), tnf_int, parsed,
				    CFGROM_PARSED(node), tnf_opaque, old_cfgrom,
				    onode->cfgrom, tnf_opaque, new_cfgrom,
				    node->cfgrom);
			ASSERT(onode->cfgrom == node->cfgrom);
		}

		if (CFGROM_PARSED(node) == B_FALSE && CFGROM_ALL_READ(node) ==
		    B_TRUE) {
			ASSERT((node->cfgrom_size <
			    IEEE1394_CONFIG_ROM_QUAD_SZ) ||
			    NODE_MATCHED(node) == B_TRUE);
			rw_enter(&hal->target_list_rwlock, RW_READER);
			ASSERT(node->target_list == NULL);
			rw_exit(&hal->target_list_rwlock);
			if (s1394_update_devinfo_tree(hal, node) ==
			    DDI_FAILURE) {
				ASSERT(MUTEX_NOT_HELD(
				    &hal->topology_tree_mutex));
				TNF_PROBE_1(s1394_process_topology_tree,
				    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string,
				    msg, "failure from update devinfo");
				TNF_PROBE_0_DEBUG(
				    s1394_process_topology_tree_exit,
				    S1394_TNF_SL_HOTPLUG_STACK, "");
				return (DDI_FAILURE);
			}
		} else if (CFGROM_PARSED(node) == B_FALSE && CFGROM_BIB_READ(
		    node) == B_TRUE) {
			if (s1394_read_rest_of_cfgrom(hal, node, &status) !=
			    DDI_SUCCESS) {
				TNF_PROBE_1(s1394_process_topology_tree,
				    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string,
				    msg, "failure reading rest of cfgrom");
				if ((status & S1394_LOCK_FAILED) == 0) {
					ASSERT(MUTEX_HELD(&hal->
					    topology_tree_mutex));
					*wait_for_cbs = 0;
					s1394_unlock_tree(hal);
				}
				TNF_PROBE_0_DEBUG(
				    s1394_process_topology_tree_exit,
				    S1394_TNF_SL_HOTPLUG_STACK, "");
				return (DDI_FAILURE);
			} else {
				*wait_for_cbs = 1;
				*wait_gen = hal->br_cfgrom_read_gen;
			}
		}

		s1394_unlock_tree(hal);
	}

	/*
	 * flag the tree as processed; if a single bus reset happens after
	 * this, we will use tree matching.
	 */
	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		TNF_PROBE_1(s1394_process_topology_tree,
		    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string,
		    msg, "relock failed while marking tree processed");
		TNF_PROBE_0_DEBUG(s1394_process_topology_tree_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (DDI_FAILURE);
	}
	hal->topology_tree_processed = B_TRUE;
	s1394_unlock_tree(hal);

	TNF_PROBE_1_DEBUG(s1394_process_topology_tree_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_int, hal_instance,
	    ddi_get_instance(hal->halinfo.dip));

	return (DDI_SUCCESS);
}

/*
 * s1394_process_old_tree()
 *    Walks through the old tree and offlines nodes that are removed. Nodes
 *    with an active link in the old tree but link powered off in the current
 *    generation are also offlined, as well as nodes with invalid config
 *    rom in current generation.
 *    The topology tree is locked/unlocked while walking through all the nodes;
 *    if the locking fails at any stage, stops further walking and returns
 *    DDI_FAILURE. Returns DDI_SUCCESS if everything went fine.
 */
int
s1394_process_old_tree(s1394_hal_t *hal)
{
	int i;
	uint_t hal_node_num_old, old_number_of_nodes;
	s1394_node_t *onode;

	TNF_PROBE_0_DEBUG(s1394_process_old_tree_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "");

	/*
	 * NODE_MATCHED(onode) == 0 indicates this node doesn't exist
	 * any more.
	 */
	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		TNF_PROBE_0(s1394_process_old_tree_lock_failed,
		    S1394_TNF_SL_HOTPLUG_ERROR, "");
		TNF_PROBE_0_DEBUG(s1394_process_old_tree_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (DDI_FAILURE);
	}
	hal_node_num_old = IEEE1394_NODE_NUM(hal->old_node_id);
	old_number_of_nodes = hal->old_number_of_nodes;
	s1394_unlock_tree(hal);

	for (i = 0; i < old_number_of_nodes; i++) {

		if (i == hal_node_num_old)
			continue;
		if (s1394_lock_tree(hal) != DDI_SUCCESS) {
			TNF_PROBE_2(s1394_process_old_tree,
			    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string, msg,
			    "lock failed while processing node", tnf_uint,
			    node_num, i);
			TNF_PROBE_0_DEBUG(s1394_process_old_tree_exit,
			    S1394_TNF_SL_HOTPLUG_STACK, "");
			return (DDI_FAILURE);
		}

		onode = &hal->old_tree[i];

		if (onode->cfgrom == NULL) {
			CLEAR_CFGROM_STATE(onode);
			s1394_unlock_tree(hal);
			continue;
		}

		TNF_PROBE_1_DEBUG(s1394_process_old_tree,
		    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_opaque,
		    cfgrom, onode->cfgrom);

		TNF_PROBE_5_DEBUG(s1394_process_old_tree,
		    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_int,
		    node_num, i, tnf_int, parsed, CFGROM_PARSED(onode), tnf_int,
		    matched, NODE_MATCHED(onode), tnf_int, visited,
		    NODE_VISITED(onode), tnf_int, generation_changed,
		    CFGROM_GEN_CHANGED(onode));

		/*
		 * onode->cur_node == NULL iff we couldn't read cfgrom in the
		 * current generation in non-tree matching case (and thus
		 * match_GUIDs couldn't set cur_node).
		 */
		if (NODE_MATCHED(onode) == B_FALSE || (onode->cur_node ==
		    NULL || ((CFGROM_VALID(onode) == B_TRUE &&
		    CFGROM_VALID(onode->cur_node) == B_FALSE) ||
		    (LINK_ACTIVE(onode) == B_TRUE && LINK_ACTIVE(onode->
		    cur_node) == B_FALSE)))) {

			if (onode->cur_node != NULL && CFGROM_VALID(onode) ==
			    B_TRUE &&
			    CFGROM_VALID(onode->cur_node) == B_FALSE) {
				TNF_PROBE_1_DEBUG(
				    s1394_process_old_tree_invalid_cfgrom,
				    S1394_TNF_SL_HOTPLUG_STACK, "",
				    tnf_int, node_num, i);
			}
			if (onode->cur_node != NULL && LINK_ACTIVE(onode) ==
			    B_TRUE && LINK_ACTIVE(onode->cur_node) == B_FALSE) {
				TNF_PROBE_1_DEBUG(
				    s1394_process_old_tree_link_off,
				    S1394_TNF_SL_HOTPLUG_STACK,
				    "", tnf_int, node_num, i);
			}
			if (s1394_offline_node(hal, onode) != DDI_SUCCESS) {
				TNF_PROBE_2(s1394_process_old_tree,
				    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string,
				    msg, "failure from offline node", tnf_uint,
				    node_num, i);
				TNF_PROBE_0_DEBUG(s1394_process_old_tree_exit,
				    S1394_TNF_SL_HOTPLUG_STACK, "");
				return (DDI_FAILURE);
			}
			s1394_free_cfgrom(hal, onode, S1394_FREE_CFGROM_OLD);
		}

		s1394_unlock_tree(hal);
	}

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	TNF_PROBE_0_DEBUG(s1394_process_old_tree_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");

	return (DDI_SUCCESS);
}

/*
 * s1394_update_unit_dir_location()
 *    Updates the unit-dir-offset property on the devinfo.
 *    NOTE: ndi_prop_update_int() is interrupt callable (and thus won't block);
 *    so, the caller doesn't drop topology_tree_mutex when calling this routine.
 */
/*ARGSUSED*/
static void
s1394_update_unit_dir_location(s1394_hal_t *hal, dev_info_t *tdip,
    uint_t offset)
{
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	ASSERT(tdip != NULL);

	TNF_PROBE_1_DEBUG(s1394_update_unit_dir_location_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "", tnf_uint, offset, offset);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, tdip, "unit-dir-offset",
	    offset);
	TNF_PROBE_0_DEBUG(s1394_update_unit_dir_location_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");
}

/*
 * s1394_add_target_to_node()
 *    adds target to the list of targets hanging off the node. Figures out
 *    the node by searching the topology tree for the GUID corresponding
 *    to the target. Points on_node field of target structure at the node.
 */
void
s1394_add_target_to_node(s1394_target_t *target)
{
	s1394_target_t *t;
	s1394_hal_t *hal;
	uint32_t guid_hi;
	uint32_t guid_lo;
	int i;
	char name[MAXNAMELEN];
	char *ptr;

	TNF_PROBE_0_DEBUG(s1394_add_target_to_node_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "");

	hal = target->on_hal;
	ASSERT(hal != NULL);

	/* Topology tree must be locked when it gets here! */
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	/* target_list_rwlock should be held in write mode */
	ASSERT(rw_read_locked(&target->on_hal->target_list_rwlock) == 0);

	if ((ptr = ddi_get_name_addr(target->target_dip)) == NULL) {
		TNF_PROBE_0_DEBUG(s1394_add_target_to_node_exit_no_name,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return;
	}

	(void) sprintf(name, ptr);
	/* Drop the ,<ADDR> part, if present */
	if ((ptr = strchr(name, ',')) != NULL)
		*ptr = '\0';

	ptr = name;
	guid_hi = s1394_stoi(ptr, 8, 16);
	guid_lo = s1394_stoi(ptr + 8, 8, 16);

	/* Search the HAL's node list for this GUID */
	for (i = 0; i < hal->number_of_nodes; i++) {
		if (CFGROM_VALID(&hal->topology_tree[i]) == B_TRUE) {
			ASSERT(hal->topology_tree[i].cfgrom != NULL);

			if ((hal->topology_tree[i].node_guid_hi == guid_hi) &&
			    (hal->topology_tree[i].node_guid_lo == guid_lo)) {
				target->on_node = &hal->topology_tree[i];
				if ((t = hal->topology_tree[i].target_list) !=
				    NULL) {
					ASSERT(t != target);
					while (t->target_sibling != NULL) {
						t = t->target_sibling;
						ASSERT(t != target);
					}
					t->target_sibling = target;
				} else {
					hal->topology_tree[i].target_list =
					    target;
				}

				/*
				 * update target_list in all targets on the
				 * node
				 */
				t = hal->topology_tree[i].target_list;
				while (t != NULL) {
					t->target_list =
					    hal->topology_tree[i].target_list;
					t = t->target_sibling;
				}
				break;
			}
		}
	}

	TNF_PROBE_0_DEBUG(s1394_add_target_to_node_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");
}

/*
 * s1394_remove_target_from_node()
 *    Removes target from the corresponding node's target_list.
 */
void
s1394_remove_target_from_node(s1394_target_t *target)
{
	s1394_target_t *t, *t1;
	s1394_hal_t *hal;

	TNF_PROBE_0_DEBUG(s1394_remove_target_from_node_enter,
	    S1394_TNF_SL_HOTPLUG_STACK, "");

	hal = target->on_hal;
	ASSERT(hal != NULL);

	/* Topology tree must be locked when it gets here! */
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	/* target_list_rwlock should be held in write mode */
	ASSERT(rw_read_locked(&target->on_hal->target_list_rwlock) == 0);

	if (target->on_node == NULL) {
		TNF_PROBE_1_DEBUG(s1394_remove_target_from_node_NULL,
		    S1394_TNF_SL_HOTPLUG_STACK, "",
		    tnf_uint, target_state, target->target_state);
	}

	t = target->target_list;
	t1 = NULL;
	while (t != NULL) {
		if (t == target) {
			if (t1 == NULL) {
				target->target_list = t->target_sibling;
			} else {
				t1->target_sibling = t->target_sibling;
			}
			break;
		}
		t1 = t;
		t = t->target_sibling;
	}
	/* Update the target_list pointer in all the targets */
	if (target->on_node != NULL)
		target->on_node->target_list = target->target_list;

	t = t1 = target->target_list;
	while (t != NULL) {
		t->target_list = t1;
		t = t->target_sibling;
	}

	target->on_node = NULL;
	target->target_sibling = NULL;

	TNF_PROBE_0_DEBUG(s1394_remove_target_from_node_exit,
	    S1394_TNF_SL_HOTPLUG_STACK, "");
}
