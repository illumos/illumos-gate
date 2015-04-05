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

#include <libdlvlan.h>
#include <libdlvnic.h>
#include <libvrrpadm.h>

/*
 * VLAN Administration Library.
 *
 * This library is used by administration tools such as dladm(1M) to
 * configure VLANs.
 */

/*
 * Returns the current attributes of the specified VLAN.
 */
dladm_status_t
dladm_vlan_info(dladm_handle_t handle, datalink_id_t vlanid,
    dladm_vlan_attr_t *dvap, uint32_t flags)
{
	dladm_status_t status;
	dladm_vnic_attr_t attr, *vnic = &attr;

	if ((status = dladm_vnic_info(handle, vlanid, vnic, flags)) !=
	    DLADM_STATUS_OK)
		return (status);

	dvap->dv_vid = vnic->va_vid;
	dvap->dv_linkid = vnic->va_link_id;
	dvap->dv_force = vnic->va_force;
	return (status);
}

/*
 * Create a VLAN on given link.
 */
dladm_status_t
dladm_vlan_create(dladm_handle_t handle, const char *vlan, datalink_id_t linkid,
    uint16_t vid, dladm_arg_list_t *proplist, uint32_t flags,
    datalink_id_t *vlan_id_out)
{
	return (dladm_vnic_create(handle, vlan, linkid,
	    VNIC_MAC_ADDR_TYPE_PRIMARY, NULL, 0, NULL, 0, vid, VRRP_VRID_NONE,
	    AF_UNSPEC, vlan_id_out, proplist, NULL, flags | DLADM_OPT_VLAN));
}

/*
 * Delete a given VLAN.
 */
dladm_status_t
dladm_vlan_delete(dladm_handle_t handle, datalink_id_t vlanid, uint32_t flags)
{
	return (dladm_vnic_delete(handle, vlanid, flags | DLADM_OPT_VLAN));
}

dladm_status_t
dladm_vlan_up(dladm_handle_t handle, datalink_id_t linkid)
{
	return (dladm_vnic_up(handle, linkid, DLADM_OPT_VLAN));
}
