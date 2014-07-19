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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <libintl.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <sys/dld.h>
#include <libdladm_impl.h>
#include <libvrrpadm.h>
#include <libdllink.h>
#include <libdlbridge.h>
#include <libdlvnic.h>

/*
 * VNIC administration library.
 */

/*
 * Default random MAC address prefix (locally administered).
 */
static char dladm_vnic_def_prefix[] = {0x02, 0x08, 0x20};

static dladm_status_t	dladm_vnic_persist_conf(dladm_handle_t,
			    const char *name, dladm_vnic_attr_t *,
			    datalink_class_t);
static const char	*dladm_vnic_macaddr2str(const uchar_t *, char *);
static dladm_status_t	dladm_vnic_str2macaddr(const char *, uchar_t *);

/*
 * Convert a diagnostic returned by the kernel into a dladm_status_t.
 */
static dladm_status_t
dladm_vnic_diag2status(vnic_ioc_diag_t ioc_diag)
{
	switch (ioc_diag) {
	case VNIC_IOC_DIAG_NONE:
		return (DLADM_STATUS_OK);
	case VNIC_IOC_DIAG_MACADDRLEN_INVALID:
		return (DLADM_STATUS_INVALIDMACADDRLEN);
	case VNIC_IOC_DIAG_MACADDR_NIC:
		return (DLADM_STATUS_INVALIDMACADDRNIC);
	case VNIC_IOC_DIAG_MACADDR_INUSE:
		return (DLADM_STATUS_INVALIDMACADDRINUSE);
	case VNIC_IOC_DIAG_MACFACTORYSLOTINVALID:
		return (DLADM_STATUS_MACFACTORYSLOTINVALID);
	case VNIC_IOC_DIAG_MACFACTORYSLOTUSED:
		return (DLADM_STATUS_MACFACTORYSLOTUSED);
	case VNIC_IOC_DIAG_MACFACTORYSLOTALLUSED:
		return (DLADM_STATUS_MACFACTORYSLOTALLUSED);
	case VNIC_IOC_DIAG_MACFACTORYNOTSUP:
		return (DLADM_STATUS_MACFACTORYNOTSUP);
	case VNIC_IOC_DIAG_MACPREFIX_INVALID:
		return (DLADM_STATUS_INVALIDMACPREFIX);
	case VNIC_IOC_DIAG_MACPREFIXLEN_INVALID:
		return (DLADM_STATUS_INVALIDMACPREFIXLEN);
	case VNIC_IOC_DIAG_MACMARGIN_INVALID:
		return (DLADM_STATUS_INVALID_MACMARGIN);
	case VNIC_IOC_DIAG_NO_HWRINGS:
		return (DLADM_STATUS_NO_HWRINGS);
	case VNIC_IOC_DIAG_MACADDR_INVALID:
		return (DLADM_STATUS_INVALIDMACADDR);
	case VNIC_IOC_DIAG_MACMTU_INVALID:
		return (DLADM_STATUS_INVALID_MTU);
	default:
		return (DLADM_STATUS_FAILED);
	}
}

/*
 * Send a create command to the VNIC driver.
 */
dladm_status_t
i_dladm_vnic_create_sys(dladm_handle_t handle, dladm_vnic_attr_t *attr)
{
	int rc;
	vnic_ioc_create_t ioc;
	dladm_status_t status = DLADM_STATUS_OK;

	bzero(&ioc, sizeof (ioc));
	ioc.vc_vnic_id = attr->va_vnic_id;
	ioc.vc_link_id = attr->va_link_id;
	ioc.vc_mac_addr_type = attr->va_mac_addr_type;
	ioc.vc_mac_len = attr->va_mac_len;
	ioc.vc_mac_slot = attr->va_mac_slot;
	ioc.vc_mac_prefix_len = attr->va_mac_prefix_len;
	ioc.vc_vid = attr->va_vid;
	ioc.vc_vrid = attr->va_vrid;
	ioc.vc_af = attr->va_af;
	ioc.vc_flags = attr->va_force ? VNIC_IOC_CREATE_FORCE : 0;

	if (attr->va_mac_len > 0 || ioc.vc_mac_prefix_len > 0)
		bcopy(attr->va_mac_addr, ioc.vc_mac_addr, MAXMACADDRLEN);
	bcopy(&attr->va_resource_props, &ioc.vc_resource_props,
	    sizeof (mac_resource_props_t));
	if (attr->va_link_id == DATALINK_INVALID_LINKID)
		ioc.vc_flags |= VNIC_IOC_CREATE_ANCHOR;

	rc = ioctl(dladm_dld_fd(handle), VNIC_IOC_CREATE, &ioc);
	if (rc < 0)
		status = dladm_errno2status(errno);

	if (status != DLADM_STATUS_OK) {
		if (ioc.vc_diag != VNIC_IOC_DIAG_NONE)
			status = dladm_vnic_diag2status(ioc.vc_diag);
	}
	if (status != DLADM_STATUS_OK)
		return (status);

	attr->va_mac_addr_type = ioc.vc_mac_addr_type;
	switch (ioc.vc_mac_addr_type) {
	case VNIC_MAC_ADDR_TYPE_FACTORY:
		attr->va_mac_slot = ioc.vc_mac_slot;
		break;
	case VNIC_MAC_ADDR_TYPE_RANDOM:
		bcopy(ioc.vc_mac_addr, attr->va_mac_addr, MAXMACADDRLEN);
		attr->va_mac_len = ioc.vc_mac_len;
		break;
	}
	return (status);
}

/*
 * Get the configuration information of the given VNIC.
 */
static dladm_status_t
i_dladm_vnic_info_active(dladm_handle_t handle, datalink_id_t linkid,
    dladm_vnic_attr_t *attrp)
{
	vnic_ioc_info_t ioc;
	vnic_info_t *vnic;
	int rc;
	dladm_status_t status = DLADM_STATUS_OK;

	bzero(&ioc, sizeof (ioc));
	vnic = &ioc.vi_info;
	vnic->vn_vnic_id = linkid;

	rc = ioctl(dladm_dld_fd(handle), VNIC_IOC_INFO, &ioc);
	if (rc != 0) {
		status = dladm_errno2status(errno);
		goto bail;
	}

	attrp->va_vnic_id = vnic->vn_vnic_id;
	attrp->va_link_id = vnic->vn_link_id;
	attrp->va_mac_addr_type = vnic->vn_mac_addr_type;
	bcopy(vnic->vn_mac_addr, attrp->va_mac_addr, MAXMACADDRLEN);
	attrp->va_mac_len = vnic->vn_mac_len;
	attrp->va_mac_slot = vnic->vn_mac_slot;
	attrp->va_mac_prefix_len = vnic->vn_mac_prefix_len;
	attrp->va_vid = vnic->vn_vid;
	attrp->va_vrid = vnic->vn_vrid;
	attrp->va_af = vnic->vn_af;
	attrp->va_force = vnic->vn_force;

bail:
	return (status);
}

static dladm_status_t
i_dladm_vnic_info_persist(dladm_handle_t handle, datalink_id_t linkid,
    dladm_vnic_attr_t *attrp)
{
	dladm_conf_t conf;
	dladm_status_t status;
	char macstr[ETHERADDRL * 3];
	char linkover[MAXLINKNAMELEN];
	uint64_t u64;
	datalink_class_t class;

	attrp->va_vnic_id = linkid;
	if ((status = dladm_getsnap_conf(handle, linkid, &conf)) !=
	    DLADM_STATUS_OK)
		return (status);

	status = dladm_get_conf_field(handle, conf, FLINKOVER, linkover,
	    sizeof (linkover));
	if (status != DLADM_STATUS_OK) {
		/*
		 * This isn't an error, etherstubs don't have a FLINKOVER
		 * property.
		 */
		attrp->va_link_id = DATALINK_INVALID_LINKID;
	} else {
		if ((status = dladm_name2info(handle, linkover,
		    &attrp->va_link_id, NULL, NULL, NULL)) != DLADM_STATUS_OK)
			goto done;
	}

	if ((status = dladm_datalink_id2info(handle, linkid, NULL, &class,
	    NULL, NULL, 0)) != DLADM_STATUS_OK)
		goto done;

	if (class == DATALINK_CLASS_VLAN) {
		if (attrp->va_link_id == DATALINK_INVALID_LINKID) {
			status = DLADM_STATUS_BADARG;
			goto done;
		}
		attrp->va_mac_addr_type = VNIC_MAC_ADDR_TYPE_PRIMARY;
		attrp->va_mac_len = 0;
	} else {
		status = dladm_get_conf_field(handle, conf, FMADDRTYPE, &u64,
		    sizeof (u64));
		if (status != DLADM_STATUS_OK)
			goto done;

		attrp->va_mac_addr_type = (vnic_mac_addr_type_t)u64;

		if ((status = dladm_get_conf_field(handle, conf, FVRID,
		    &u64, sizeof (u64))) != DLADM_STATUS_OK) {
			attrp->va_vrid = VRRP_VRID_NONE;
		} else {
			attrp->va_vrid = (vrid_t)u64;
		}

		if ((status = dladm_get_conf_field(handle, conf, FVRAF,
		    &u64, sizeof (u64))) != DLADM_STATUS_OK) {
			attrp->va_af = AF_UNSPEC;
		} else {
			attrp->va_af = (int)u64;
		}

		status = dladm_get_conf_field(handle, conf, FMADDRLEN, &u64,
		    sizeof (u64));
		attrp->va_mac_len = ((status == DLADM_STATUS_OK) ?
		    (uint_t)u64 : ETHERADDRL);

		status = dladm_get_conf_field(handle, conf, FMADDRSLOT, &u64,
		    sizeof (u64));
		attrp->va_mac_slot = ((status == DLADM_STATUS_OK) ?
		    (int)u64 : -1);

		status = dladm_get_conf_field(handle, conf, FMADDRPREFIXLEN,
		    &u64, sizeof (u64));
		attrp->va_mac_prefix_len = ((status == DLADM_STATUS_OK) ?
		    (uint_t)u64 : sizeof (dladm_vnic_def_prefix));

		status = dladm_get_conf_field(handle, conf, FMACADDR, macstr,
		    sizeof (macstr));
		if (status != DLADM_STATUS_OK)
			goto done;

		status = dladm_vnic_str2macaddr(macstr, attrp->va_mac_addr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = dladm_get_conf_field(handle, conf, FVLANID, &u64,
	    sizeof (u64));
	attrp->va_vid = ((status == DLADM_STATUS_OK) ?  (uint16_t)u64 : 0);

	status = DLADM_STATUS_OK;
done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

dladm_status_t
dladm_vnic_info(dladm_handle_t handle, datalink_id_t linkid,
    dladm_vnic_attr_t *attrp, uint32_t flags)
{
	if (flags == DLADM_OPT_ACTIVE)
		return (i_dladm_vnic_info_active(handle, linkid, attrp));
	else if (flags == DLADM_OPT_PERSIST)
		return (i_dladm_vnic_info_persist(handle, linkid, attrp));
	else
		return (DLADM_STATUS_BADARG);
}

/*
 * Remove a VNIC from the kernel.
 */
dladm_status_t
i_dladm_vnic_delete_sys(dladm_handle_t handle, datalink_id_t linkid)
{
	vnic_ioc_delete_t ioc;
	dladm_status_t status = DLADM_STATUS_OK;
	int rc;

	ioc.vd_vnic_id = linkid;

	rc = ioctl(dladm_dld_fd(handle), VNIC_IOC_DELETE, &ioc);
	if (rc < 0)
		status = dladm_errno2status(errno);

	return (status);
}

/*
 * Convert between MAC address types and their string representations.
 */

typedef struct dladm_vnic_addr_type_s {
	const char		*va_str;
	vnic_mac_addr_type_t	va_type;
} dladm_vnic_addr_type_t;

static dladm_vnic_addr_type_t addr_types[] = {
	{"fixed", VNIC_MAC_ADDR_TYPE_FIXED},
	{"random", VNIC_MAC_ADDR_TYPE_RANDOM},
	{"factory", VNIC_MAC_ADDR_TYPE_FACTORY},
	{"auto", VNIC_MAC_ADDR_TYPE_AUTO},
	{"fixed", VNIC_MAC_ADDR_TYPE_PRIMARY},
	{"vrrp", VNIC_MAC_ADDR_TYPE_VRID}
};

#define	NADDR_TYPES (sizeof (addr_types) / sizeof (dladm_vnic_addr_type_t))

static const char *
dladm_vnic_macaddrtype2str(vnic_mac_addr_type_t type)
{
	int i;

	for (i = 0; i < NADDR_TYPES; i++) {
		if (type == addr_types[i].va_type)
			return (addr_types[i].va_str);
	}
	return (NULL);
}

dladm_status_t
dladm_vnic_str2macaddrtype(const char *str, vnic_mac_addr_type_t *val)
{
	int i;
	dladm_vnic_addr_type_t *type;

	for (i = 0; i < NADDR_TYPES; i++) {
		type = &addr_types[i];
		if (strncmp(str, type->va_str, strlen(type->va_str)) == 0) {
			*val = type->va_type;
			return (DLADM_STATUS_OK);
		}
	}
	return (DLADM_STATUS_BADARG);
}

/*
 * Based on the VRRP specification, the virtual router MAC address associated
 * with a virtual router is an IEEE 802 MAC address in the following format:
 *
 * IPv4 case: 00-00-5E-00-01-{VRID} (in hex in internet standard bit-order)
 *
 * IPv6 case: 00-00-5E-00-02-{VRID} (in hex in internet standard bit-order)
 */
static dladm_status_t
i_dladm_vnic_vrrp_mac(vrid_t vrid, int af, uint8_t *mac, uint_t maclen)
{
	if (maclen < ETHERADDRL || vrid < VRRP_VRID_MIN ||
	    vrid > VRRP_VRID_MAX || (af != AF_INET && af != AF_INET6)) {
		return (DLADM_STATUS_BADARG);
	}

	mac[0] = mac[1] = mac[3] = 0x0;
	mac[2] = 0x5e;
	mac[4] = (af == AF_INET) ? 0x01 : 0x02;
	mac[5] = vrid;
	return (DLADM_STATUS_OK);
}

/*
 * Create a new VNIC / VLAN. Update the configuration file and bring it up.
 * The "vrid" and "af" arguments are only required if the mac_addr_type is
 * VNIC_MAC_ADDR_TYPE_VRID. In that case, the MAC address will be caculated
 * based on the above algorithm.
 */
dladm_status_t
dladm_vnic_create(dladm_handle_t handle, const char *vnic, datalink_id_t linkid,
    vnic_mac_addr_type_t mac_addr_type, uchar_t *mac_addr, uint_t mac_len,
    int *mac_slot, uint_t mac_prefix_len, uint16_t vid, vrid_t vrid,
    int af, datalink_id_t *vnic_id_out, dladm_arg_list_t *proplist,
    uint32_t flags)
{
	dladm_vnic_attr_t attr;
	datalink_id_t vnic_id;
	datalink_class_t class;
	uint32_t media = DL_ETHER;
	char name[MAXLINKNAMELEN];
	uchar_t tmp_addr[MAXMACADDRLEN];
	dladm_status_t status;
	boolean_t is_vlan;
	boolean_t is_etherstub;
	int i;
	boolean_t vnic_created = B_FALSE;
	boolean_t conf_set = B_FALSE;

	/*
	 * Sanity test arguments.
	 */
	if ((flags & DLADM_OPT_ACTIVE) == 0)
		return (DLADM_STATUS_NOTSUP);

	is_vlan = ((flags & DLADM_OPT_VLAN) != 0);
	if (is_vlan && ((vid < 1 || vid > 4094)))
		return (DLADM_STATUS_VIDINVAL);

	is_etherstub = (linkid == DATALINK_INVALID_LINKID);

	if (!dladm_vnic_macaddrtype2str(mac_addr_type))
		return (DLADM_STATUS_INVALIDMACADDRTYPE);

	if ((flags & DLADM_OPT_ANCHOR) == 0) {
		if ((status = dladm_datalink_id2info(handle, linkid, NULL,
		    &class, &media, NULL, 0)) != DLADM_STATUS_OK)
			return (status);

		if (class == DATALINK_CLASS_VNIC ||
		    class == DATALINK_CLASS_VLAN)
			return (DLADM_STATUS_BADARG);
	} else {
		/* it's an anchor VNIC */
		if (linkid != DATALINK_INVALID_LINKID || vid != 0)
			return (DLADM_STATUS_BADARG);
	}

	/*
	 * Only VRRP VNIC need VRID and address family specified.
	 */
	if (mac_addr_type != VNIC_MAC_ADDR_TYPE_VRID &&
	    (af != AF_UNSPEC || vrid != VRRP_VRID_NONE)) {
		return (DLADM_STATUS_BADARG);
	}

	/*
	 * If a random address might be generated, but no prefix
	 * was specified by the caller, use the default MAC address
	 * prefix.
	 */
	if ((mac_addr_type == VNIC_MAC_ADDR_TYPE_RANDOM ||
	    mac_addr_type == VNIC_MAC_ADDR_TYPE_AUTO) &&
	    mac_prefix_len == 0) {
		mac_prefix_len = sizeof (dladm_vnic_def_prefix);
		mac_addr = tmp_addr;
		bcopy(dladm_vnic_def_prefix, mac_addr, mac_prefix_len);
	}

	/*
	 * If this is a VRRP VNIC, generate its MAC address using the given
	 * VRID and address family.
	 */
	if (mac_addr_type == VNIC_MAC_ADDR_TYPE_VRID) {
		/*
		 * VRRP VNICs must be created over ethernet data-links.
		 */
		if (vrid < VRRP_VRID_MIN || vrid > VRRP_VRID_MAX ||
		    (af != AF_INET && af != AF_INET6) || mac_addr != NULL ||
		    mac_len != 0 || mac_prefix_len != 0 ||
		    (mac_slot != NULL && *mac_slot != -1) || is_etherstub ||
		    media != DL_ETHER) {
			return (DLADM_STATUS_BADARG);
		}
		mac_len = ETHERADDRL;
		mac_addr = tmp_addr;
		status = i_dladm_vnic_vrrp_mac(vrid, af, mac_addr, mac_len);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (mac_len > MAXMACADDRLEN)
		return (DLADM_STATUS_INVALIDMACADDRLEN);

	if (vnic == NULL) {
		flags |= DLADM_OPT_PREFIX;
		(void) strlcpy(name, "vnic", sizeof (name));
	} else {
		(void) strlcpy(name, vnic, sizeof (name));
	}

	class = is_vlan ? DATALINK_CLASS_VLAN :
	    (is_etherstub ? DATALINK_CLASS_ETHERSTUB : DATALINK_CLASS_VNIC);
	if ((status = dladm_create_datalink_id(handle, name, class,
	    media, flags, &vnic_id)) != DLADM_STATUS_OK)
		return (status);

	if ((flags & DLADM_OPT_PREFIX) != 0) {
		(void) snprintf(name + 4, sizeof (name), "%llu", vnic_id);
		flags &= ~DLADM_OPT_PREFIX;
	}

	bzero(&attr, sizeof (attr));

	/* Extract resource_ctl and cpu_list from proplist */
	if (proplist != NULL) {
		status = dladm_link_proplist_extract(handle, proplist,
		    &attr.va_resource_props, 0);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	attr.va_vnic_id = vnic_id;
	attr.va_link_id = linkid;
	attr.va_mac_addr_type = mac_addr_type;
	attr.va_mac_len = mac_len;
	if (mac_slot != NULL)
		attr.va_mac_slot = *mac_slot;
	if (mac_len > 0)
		bcopy(mac_addr, attr.va_mac_addr, mac_len);
	else if (mac_prefix_len > 0)
		bcopy(mac_addr, attr.va_mac_addr, mac_prefix_len);
	attr.va_mac_prefix_len = mac_prefix_len;
	attr.va_vid = vid;
	attr.va_vrid = vrid;
	attr.va_af = af;
	attr.va_force = (flags & DLADM_OPT_FORCE) != 0;

	status = i_dladm_vnic_create_sys(handle, &attr);
	if (status != DLADM_STATUS_OK)
		goto done;
	vnic_created = B_TRUE;

	/* Save vnic configuration and its properties */
	if (!(flags & DLADM_OPT_PERSIST))
		goto done;

	status = dladm_vnic_persist_conf(handle, name, &attr, class);
	if (status != DLADM_STATUS_OK)
		goto done;
	conf_set = B_TRUE;

	if (proplist != NULL) {
		for (i = 0; i < proplist->al_count; i++) {
			dladm_arg_info_t	*aip = &proplist->al_info[i];

			status = dladm_set_linkprop(handle, vnic_id,
			    aip->ai_name, aip->ai_val, aip->ai_count,
			    DLADM_OPT_PERSIST);
			if (status != DLADM_STATUS_OK)
				break;
		}
	}

done:
	if (status != DLADM_STATUS_OK) {
		if (conf_set)
			(void) dladm_remove_conf(handle, vnic_id);
		if (vnic_created)
			(void) i_dladm_vnic_delete_sys(handle, vnic_id);
		(void) dladm_destroy_datalink_id(handle, vnic_id, flags);
	} else {
		if (vnic_id_out != NULL)
			*vnic_id_out = vnic_id;
		if (mac_slot != NULL)
			*mac_slot = attr.va_mac_slot;
	}

	if (is_vlan) {
		dladm_status_t stat2;

		stat2 = dladm_bridge_refresh(handle, linkid);
		if (status == DLADM_STATUS_OK && stat2 != DLADM_STATUS_OK)
			status = stat2;
	}
	return (status);
}

/*
 * Delete a VNIC / VLAN.
 */
dladm_status_t
dladm_vnic_delete(dladm_handle_t handle, datalink_id_t linkid, uint32_t flags)
{
	dladm_status_t status;
	datalink_class_t class;

	if (flags == 0)
		return (DLADM_STATUS_BADARG);

	if ((dladm_datalink_id2info(handle, linkid, NULL, &class, NULL, NULL, 0)
	    != DLADM_STATUS_OK))
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_VLAN) != 0) {
		if (class != DATALINK_CLASS_VLAN)
			return (DLADM_STATUS_BADARG);
	} else {
		if (class != DATALINK_CLASS_VNIC &&
		    class != DATALINK_CLASS_ETHERSTUB)
			return (DLADM_STATUS_BADARG);
	}

	if ((flags & DLADM_OPT_ACTIVE) != 0) {
		status = i_dladm_vnic_delete_sys(handle, linkid);
		if (status == DLADM_STATUS_OK) {
			(void) dladm_set_linkprop(handle, linkid, NULL, NULL, 0,
			    DLADM_OPT_ACTIVE);
			(void) dladm_destroy_datalink_id(handle, linkid,
			    DLADM_OPT_ACTIVE);
		} else if (status != DLADM_STATUS_NOTFOUND ||
		    !(flags & DLADM_OPT_PERSIST)) {
			return (status);
		}
	}
	if ((flags & DLADM_OPT_PERSIST) != 0) {
		(void) dladm_remove_conf(handle, linkid);
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_PERSIST);
	}
	return (dladm_bridge_refresh(handle, linkid));
}

static const char *
dladm_vnic_macaddr2str(const uchar_t *mac, char *buf)
{
	static char unknown_mac[] = {0, 0, 0, 0, 0, 0};

	if (buf == NULL)
		return (NULL);

	if (bcmp(unknown_mac, mac, ETHERADDRL) == 0)
		(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
	else
		return (_link_ntoa(mac, buf, ETHERADDRL, IFT_OTHER));

	return (buf);
}

static dladm_status_t
dladm_vnic_str2macaddr(const char *str, uchar_t *buf)
{
	int len = 0;
	uchar_t *b = _link_aton(str, &len);

	if (b == NULL || len >= MAXMACADDRLEN)
		return (DLADM_STATUS_BADARG);

	bcopy(b, buf, len);
	free(b);
	return (DLADM_STATUS_OK);
}


static dladm_status_t
dladm_vnic_persist_conf(dladm_handle_t handle, const char *name,
    dladm_vnic_attr_t *attrp, datalink_class_t class)
{
	dladm_conf_t conf;
	dladm_status_t status;
	char macstr[ETHERADDRL * 3];
	char linkover[MAXLINKNAMELEN];
	uint64_t u64;

	if ((status = dladm_create_conf(handle, name, attrp->va_vnic_id,
	    class, DL_ETHER, &conf)) != DLADM_STATUS_OK)
		return (status);

	if (attrp->va_link_id != DATALINK_INVALID_LINKID) {
		status = dladm_datalink_id2info(handle, attrp->va_link_id, NULL,
		    NULL, NULL, linkover, sizeof (linkover));
		if (status != DLADM_STATUS_OK)
			goto done;
		status = dladm_set_conf_field(handle, conf, FLINKOVER,
		    DLADM_TYPE_STR, linkover);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	if (class != DATALINK_CLASS_VLAN) {
		u64 = attrp->va_mac_addr_type;
		status = dladm_set_conf_field(handle, conf, FMADDRTYPE,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			goto done;

		u64 = attrp->va_vrid;
		status = dladm_set_conf_field(handle, conf, FVRID,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			goto done;

		u64 = attrp->va_af;
		status = dladm_set_conf_field(handle, conf, FVRAF,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			goto done;

		if (attrp->va_mac_len != ETHERADDRL) {
			u64 = attrp->va_mac_len;
			status = dladm_set_conf_field(handle, conf, FMADDRLEN,
			    DLADM_TYPE_UINT64, &u64);
			if (status != DLADM_STATUS_OK)
				goto done;
		}

		if (attrp->va_mac_slot != -1) {
			u64 = attrp->va_mac_slot;
			status = dladm_set_conf_field(handle, conf,
			    FMADDRSLOT, DLADM_TYPE_UINT64, &u64);
			if (status != DLADM_STATUS_OK)
			goto done;
		}

		if (attrp->va_mac_prefix_len !=
		    sizeof (dladm_vnic_def_prefix)) {
			u64 = attrp->va_mac_prefix_len;
			status = dladm_set_conf_field(handle, conf,
			    FMADDRPREFIXLEN, DLADM_TYPE_UINT64, &u64);
			if (status != DLADM_STATUS_OK)
				goto done;
		}

		(void) dladm_vnic_macaddr2str(attrp->va_mac_addr, macstr);
		status = dladm_set_conf_field(handle, conf, FMACADDR,
		    DLADM_TYPE_STR, macstr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	if (attrp->va_vid != 0) {
		u64 = attrp->va_vid;
		status = dladm_set_conf_field(handle, conf, FVLANID,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	/*
	 * Commit the link configuration.
	 */
	status = dladm_write_conf(handle, conf);

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

typedef struct dladm_vnic_up_arg_s {
	uint32_t	flags;
	dladm_status_t	status;
} dladm_vnic_up_arg_t;

static int
i_dladm_vnic_up(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t *statusp = &(((dladm_vnic_up_arg_t *)arg)->status);
	dladm_vnic_attr_t attr;
	dladm_status_t status;
	dladm_arg_list_t *proplist;

	bzero(&attr, sizeof (attr));

	status = dladm_vnic_info(handle, linkid, &attr, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		goto done;

	/* Get all properties for this vnic */
	status = dladm_link_get_proplist(handle, linkid, &proplist);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (proplist != NULL) {
		status = dladm_link_proplist_extract(handle, proplist,
		    &attr.va_resource_props, DLADM_OPT_BOOT);
	}

	status = i_dladm_vnic_create_sys(handle, &attr);
	if (status == DLADM_STATUS_OK) {
		status = dladm_up_datalink_id(handle, linkid);
		if (status != DLADM_STATUS_OK)
			(void) i_dladm_vnic_delete_sys(handle, linkid);
	}

done:
	*statusp = status;
	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_vnic_up(dladm_handle_t handle, datalink_id_t linkid, uint32_t flags)
{
	dladm_vnic_up_arg_t vnic_arg;
	datalink_class_t class;

	class = ((flags & DLADM_OPT_VLAN) != 0) ? DATALINK_CLASS_VLAN :
	    (DATALINK_CLASS_VNIC | DATALINK_CLASS_ETHERSTUB);

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_vnic_up, handle,
		    &vnic_arg, class, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_vnic_up(handle, linkid, &vnic_arg);
		return (vnic_arg.status);
	}
}
