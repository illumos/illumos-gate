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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <sys/vlan.h>
#include <zone.h>
#include <librcm.h>
#include <libdlpi.h>
#include <libdevinfo.h>
#include <libdlaggr.h>
#include <libdlvlan.h>
#include <libdlvnic.h>
#include <libdlib.h>
#include <libdllink.h>
#include <libdlmgmt.h>
#include <libdladm_impl.h>
#include <libinetutil.h>

/*
 * Return the attributes of the specified datalink from the DLD driver.
 */
static dladm_status_t
i_dladm_info(dladm_handle_t handle, const datalink_id_t linkid,
    dladm_attr_t *dap)
{
	dld_ioc_attr_t	dia;

	dia.dia_linkid = linkid;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_ATTR, &dia) < 0)
		return (dladm_errno2status(errno));

	dap->da_max_sdu = dia.dia_max_sdu;

	return (DLADM_STATUS_OK);
}

static dladm_status_t
dladm_usagelog(dladm_handle_t handle, dladm_logtype_t type,
    dld_ioc_usagelog_t *log_info)
{
	if (type == DLADM_LOGTYPE_FLOW)
		log_info->ul_type = MAC_LOGTYPE_FLOW;
	else
		log_info->ul_type = MAC_LOGTYPE_LINK;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_USAGELOG, log_info) < 0)
		return (DLADM_STATUS_IOERR);

	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_start_usagelog(dladm_handle_t handle, dladm_logtype_t type,
    uint_t interval)
{
	dld_ioc_usagelog_t	log_info;

	log_info.ul_onoff = B_TRUE;
	log_info.ul_interval = interval;

	return (dladm_usagelog(handle, type, &log_info));
}

dladm_status_t
dladm_stop_usagelog(dladm_handle_t handle, dladm_logtype_t type)
{
	dld_ioc_usagelog_t	log_info;

	log_info.ul_onoff = B_FALSE;
	log_info.ul_interval = 0;

	return (dladm_usagelog(handle, type, &log_info));
}

struct i_dladm_walk_arg {
	dladm_walkcb_t *fn;
	void *arg;
};

static int
i_dladm_walk(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	struct i_dladm_walk_arg *walk_arg = arg;
	char link[MAXLINKNAMELEN];

	if (dladm_datalink_id2info(handle, linkid, NULL, NULL, NULL, link,
	    sizeof (link)) == DLADM_STATUS_OK) {
		return (walk_arg->fn(link, walk_arg->arg));
	}

	return (DLADM_WALK_CONTINUE);
}

/*
 * Walk all datalinks.
 */
dladm_status_t
dladm_walk(dladm_walkcb_t *fn, dladm_handle_t handle, void *arg,
    datalink_class_t class, datalink_media_t dmedia, uint32_t flags)
{
	struct i_dladm_walk_arg walk_arg;

	walk_arg.fn = fn;
	walk_arg.arg = arg;
	return (dladm_walk_datalink_id(i_dladm_walk, handle, &walk_arg,
	    class, dmedia, flags));
}

#define	MAXGRPPERLINK	64

int
dladm_walk_hwgrp(dladm_handle_t handle, datalink_id_t linkid, void *arg,
    boolean_t (*fn)(void *, dladm_hwgrp_attr_t *))
{
	int		bufsize, ret;
	int		nhwgrp = MAXGRPPERLINK;
	dld_ioc_hwgrpget_t *iomp = NULL;

	bufsize = sizeof (dld_ioc_hwgrpget_t) +
	    nhwgrp * sizeof (dld_hwgrpinfo_t);

	if ((iomp = (dld_ioc_hwgrpget_t *)calloc(1, bufsize)) == NULL)
		return (-1);

	iomp->dih_size = nhwgrp * sizeof (dld_hwgrpinfo_t);
	iomp->dih_linkid = linkid;

	ret = ioctl(dladm_dld_fd(handle), DLDIOC_GETHWGRP, iomp);
	if (ret == 0) {
		int			i;
		int			j;
		dld_hwgrpinfo_t 	*dhip;
		dladm_hwgrp_attr_t	attr;

		dhip = (dld_hwgrpinfo_t *)(iomp + 1);
		for (i = 0; i < iomp->dih_n_groups; i++) {
			bzero(&attr, sizeof (attr));

			(void) strlcpy(attr.hg_link_name,
			    dhip->dhi_link_name, sizeof (attr.hg_link_name));
			attr.hg_grp_num = dhip->dhi_grp_num;
			attr.hg_grp_type = dhip->dhi_grp_type;
			attr.hg_n_rings = dhip->dhi_n_rings;
			for (j = 0; j < dhip->dhi_n_rings; j++)
				attr.hg_rings[j] = dhip->dhi_rings[j];
			dladm_sort_index_list(attr.hg_rings, attr.hg_n_rings);
			attr.hg_n_clnts = dhip->dhi_n_clnts;
			(void) strlcpy(attr.hg_client_names,
			    dhip->dhi_clnts, sizeof (attr.hg_client_names));

			if (!(*fn)(arg, &attr))
				break;
			dhip++;
		}
	}
	free(iomp);
	return (ret);
}

/*
 * Invoke the specified callback for each MAC address entry defined on
 * the specified device.
 */
int
dladm_walk_macaddr(dladm_handle_t handle, datalink_id_t linkid, void *arg,
    boolean_t (*fn)(void *, dladm_macaddr_attr_t *))
{
	int		bufsize, ret;
	int		nmacaddr = 1024;
	dld_ioc_macaddrget_t *iomp = NULL;

	bufsize = sizeof (dld_ioc_macaddrget_t) +
	    nmacaddr * sizeof (dld_macaddrinfo_t);

	if ((iomp = (dld_ioc_macaddrget_t *)calloc(1, bufsize)) == NULL)
		return (-1);

	iomp->dig_size = nmacaddr * sizeof (dld_macaddrinfo_t);
	iomp->dig_linkid = linkid;

	ret = ioctl(dladm_dld_fd(handle), DLDIOC_MACADDRGET, iomp);
	if (ret == 0) {
		int i;
		dld_macaddrinfo_t *dmip;
		dladm_macaddr_attr_t attr;

		dmip = (dld_macaddrinfo_t *)(iomp + 1);
		for (i = 0; i < iomp->dig_count; i++) {
			bzero(&attr, sizeof (attr));

			attr.ma_slot = dmip->dmi_slot;
			attr.ma_flags = 0;
			if (dmip->dmi_flags & DLDIOCMACADDR_USED)
				attr.ma_flags |= DLADM_MACADDR_USED;
			bcopy(dmip->dmi_addr, attr.ma_addr,
			    dmip->dmi_addrlen);
			attr.ma_addrlen = dmip->dmi_addrlen;
			(void) strlcpy(attr.ma_client_name,
			    dmip->dmi_client_name, MAXNAMELEN);
			attr.ma_client_linkid = dmip->dma_client_linkid;

			if (!(*fn)(arg, &attr))
				break;
			dmip++;
		}
	}
	free(iomp);
	return (ret);
}

/*
 * These routines are used by administration tools such as dladm(1M) to
 * iterate through the list of MAC interfaces
 */

typedef struct dladm_mac_dev {
	char			dm_name[MAXNAMELEN];
	struct dladm_mac_dev    *dm_next;
} dladm_mac_dev_t;

typedef struct macadm_walk {
	dladm_mac_dev_t	 *dmd_dev_list;
} dladm_mac_walk_t;

/*
 * Local callback invoked for each DDI_NT_NET node.
 */
/* ARGSUSED */
static int
i_dladm_mac_walk(di_node_t node, di_minor_t minor, void *arg)
{
	dladm_mac_walk_t	*dmwp = arg;
	dladm_mac_dev_t		*dmdp = dmwp->dmd_dev_list;
	dladm_mac_dev_t		**last_dmdp = &dmwp->dmd_dev_list;
	char			mac[MAXNAMELEN];

	(void) snprintf(mac, MAXNAMELEN, "%s%d",
	    di_driver_name(node), di_instance(node));

	/*
	 * Skip aggregations.
	 */
	if (strcmp("aggr", di_driver_name(node)) == 0)
		return (DI_WALK_CONTINUE);

	/*
	 * Skip softmacs.
	 */
	if (strcmp("softmac", di_driver_name(node)) == 0)
		return (DI_WALK_CONTINUE);

	while (dmdp) {
		/*
		 * Skip duplicates.
		 */
		if (strcmp(dmdp->dm_name, mac) == 0)
			return (DI_WALK_CONTINUE);

		last_dmdp = &dmdp->dm_next;
		dmdp = dmdp->dm_next;
	}

	if ((dmdp = malloc(sizeof (*dmdp))) == NULL)
		return (DI_WALK_CONTINUE);

	(void) strlcpy(dmdp->dm_name, mac, MAXNAMELEN);
	dmdp->dm_next = NULL;
	*last_dmdp = dmdp;

	return (DI_WALK_CONTINUE);
}

/*
 * Invoke the specified callback for each DDI_NT_NET node.
 */
dladm_status_t
dladm_mac_walk(int (*fn)(const char *, void *arg), void *arg)
{
	di_node_t		root;
	dladm_mac_walk_t	dmw;
	dladm_mac_dev_t		*dmdp, *next;
	boolean_t		done = B_FALSE;

	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
		return (dladm_errno2status(errno));

	dmw.dmd_dev_list = NULL;

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, &dmw,
	    i_dladm_mac_walk);

	di_fini(root);

	dmdp = dmw.dmd_dev_list;
	for (dmdp = dmw.dmd_dev_list; dmdp != NULL; dmdp = next) {
		next = dmdp->dm_next;
		if (!done &&
		    ((*fn)(dmdp->dm_name, arg) == DLADM_WALK_TERMINATE)) {
			done = B_TRUE;
		}
		free(dmdp);
	}

	return (DLADM_STATUS_OK);
}

/*
 * Get the current attributes of the specified datalink.
 */
dladm_status_t
dladm_info(dladm_handle_t handle, datalink_id_t linkid, dladm_attr_t *dap)
{
	return (i_dladm_info(handle, linkid, dap));
}

const char *
dladm_linkstate2str(link_state_t state, char *buf)
{
	const char	*s;

	switch (state) {
	case LINK_STATE_UP:
		s = "up";
		break;
	case LINK_STATE_DOWN:
		s = "down";
		break;
	default:
		s = "unknown";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

const char *
dladm_linkduplex2str(link_duplex_t duplex, char *buf)
{
	const char	*s;

	switch (duplex) {
	case LINK_DUPLEX_FULL:
		s = "full";
		break;
	case LINK_DUPLEX_HALF:
		s = "half";
		break;
	default:
		s = "unknown";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

/*
 * Case 1: rename an existing link1 to a link2 that does not exist.
 * Result: <linkid1, link2>
 */
static dladm_status_t
i_dladm_rename_link_c1(dladm_handle_t handle, datalink_id_t linkid1,
    const char *link1, const char *link2, uint32_t flags)
{
	dld_ioc_rename_t	dir;
	dladm_status_t		status = DLADM_STATUS_OK;

	/*
	 * Link is currently available. Check to see whether anything is
	 * holding this link to prevent a rename operation.
	 */
	if (flags & DLADM_OPT_ACTIVE) {
		dir.dir_linkid1 = linkid1;
		dir.dir_linkid2 = DATALINK_INVALID_LINKID;
		(void) strlcpy(dir.dir_link, link2, MAXLINKNAMELEN);

		if (ioctl(dladm_dld_fd(handle), DLDIOC_RENAME, &dir) < 0) {
			status = dladm_errno2status(errno);
			return (status);
		}
	}

	status = dladm_remap_datalink_id(handle, linkid1, link2);
	if (status != DLADM_STATUS_OK && (flags & DLADM_OPT_ACTIVE)) {
		(void) strlcpy(dir.dir_link, link1, MAXLINKNAMELEN);
		(void) ioctl(dladm_dld_fd(handle), DLDIOC_RENAME, &dir);
	}
	return (status);
}

typedef struct link_hold_arg_s {
	datalink_id_t	linkid;
	datalink_id_t	holder;
	uint32_t	flags;
} link_hold_arg_t;

static int
i_dladm_aggr_link_hold(dladm_handle_t handle, datalink_id_t aggrid, void *arg)
{
	link_hold_arg_t		*hold_arg = arg;
	dladm_aggr_grp_attr_t	ginfo;
	dladm_status_t		status;
	int			i;

	status = dladm_aggr_info(handle, aggrid, &ginfo, hold_arg->flags);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	for (i = 0; i < ginfo.lg_nports; i++) {
		if (ginfo.lg_ports[i].lp_linkid == hold_arg->linkid) {
			hold_arg->holder = aggrid;
			return (DLADM_WALK_TERMINATE);
		}
	}
	return (DLADM_WALK_CONTINUE);
}

static int
i_dladm_vlan_link_hold(dladm_handle_t handle, datalink_id_t vlanid, void *arg)
{
	link_hold_arg_t		*hold_arg = arg;
	dladm_vlan_attr_t	vinfo;
	dladm_status_t		status;

	status = dladm_vlan_info(handle, vlanid, &vinfo, hold_arg->flags);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (vinfo.dv_linkid == hold_arg->linkid) {
		hold_arg->holder = vlanid;
		return (DLADM_WALK_TERMINATE);
	}
	return (DLADM_WALK_CONTINUE);
}

/*
 * Case 2: rename an available physical link link1 to a REMOVED physical link
 *     link2.  As a result, link1 directly inherits all datalinks configured
 *     over link2 (linkid2).
 * Result: <linkid2, link2, link1_phymaj, link1_phyinst, link1_devname,
 *     link2_other_attr>
 */
static dladm_status_t
i_dladm_rename_link_c2(dladm_handle_t handle, datalink_id_t linkid1,
    datalink_id_t linkid2)
{
	rcm_handle_t		*rcm_hdl = NULL;
	nvlist_t		*nvl = NULL;
	link_hold_arg_t		arg;
	dld_ioc_rename_t	dir;
	dladm_conf_t		conf1, conf2;
	char			devname[MAXLINKNAMELEN];
	uint64_t		phymaj, phyinst;
	dladm_status_t		status = DLADM_STATUS_OK;

	/*
	 * First check if linkid1 is associated with any persistent
	 * aggregations or VLANs. If yes, return BUSY.
	 */
	arg.linkid = linkid1;
	arg.holder = DATALINK_INVALID_LINKID;
	arg.flags = DLADM_OPT_PERSIST;
	(void) dladm_walk_datalink_id(i_dladm_aggr_link_hold, handle, &arg,
	    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
	if (arg.holder != DATALINK_INVALID_LINKID)
		return (DLADM_STATUS_LINKBUSY);

	arg.flags = DLADM_OPT_PERSIST;
	(void) dladm_walk_datalink_id(i_dladm_vlan_link_hold, handle, &arg,
	    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
	if (arg.holder != DATALINK_INVALID_LINKID)
		return (DLADM_STATUS_LINKBUSY);

	/*
	 * Send DLDIOC_RENAME to request to rename link1's linkid to
	 * be linkid2. This will check whether link1 is used by any
	 * aggregations or VLANs, or is held by any application. If yes,
	 * return failure.
	 */
	dir.dir_linkid1 = linkid1;
	dir.dir_linkid2 = linkid2;
	if (ioctl(dladm_dld_fd(handle), DLDIOC_RENAME, &dir) < 0)
		status = dladm_errno2status(errno);

	if (status != DLADM_STATUS_OK) {
		return (status);
	}

	/*
	 * Now change the phymaj, phyinst and devname associated with linkid1
	 * to be associated with linkid2. Before doing that, the old active
	 * linkprop of linkid1 should be deleted.
	 */
	(void) dladm_set_linkprop(handle, linkid1, NULL, NULL, 0,
	    DLADM_OPT_ACTIVE);

	if (((status = dladm_getsnap_conf(handle, linkid1, &conf1)) !=
	    DLADM_STATUS_OK) ||
	    ((status = dladm_get_conf_field(handle, conf1, FDEVNAME, devname,
	    MAXLINKNAMELEN)) != DLADM_STATUS_OK) ||
	    ((status = dladm_get_conf_field(handle, conf1, FPHYMAJ, &phymaj,
	    sizeof (uint64_t))) != DLADM_STATUS_OK) ||
	    ((status = dladm_get_conf_field(handle, conf1, FPHYINST, &phyinst,
	    sizeof (uint64_t))) != DLADM_STATUS_OK) ||
	    ((status = dladm_open_conf(handle, linkid2, &conf2)) !=
	    DLADM_STATUS_OK)) {
		dir.dir_linkid1 = linkid2;
		dir.dir_linkid2 = linkid1;
		(void) dladm_init_linkprop(handle, linkid1, B_FALSE);
		(void) ioctl(dladm_dld_fd(handle), DLDIOC_RENAME, &dir);
		return (status);
	}

	dladm_destroy_conf(handle, conf1);
	(void) dladm_set_conf_field(handle, conf2, FDEVNAME, DLADM_TYPE_STR,
	    devname);
	(void) dladm_set_conf_field(handle, conf2, FPHYMAJ, DLADM_TYPE_UINT64,
	    &phymaj);
	(void) dladm_set_conf_field(handle, conf2, FPHYINST,
	    DLADM_TYPE_UINT64, &phyinst);
	(void) dladm_write_conf(handle, conf2);
	dladm_destroy_conf(handle, conf2);

	/*
	 * Delete link1 and mark link2 up.
	 */
	(void) dladm_remove_conf(handle, linkid1);
	(void) dladm_destroy_datalink_id(handle, linkid1, DLADM_OPT_ACTIVE |
	    DLADM_OPT_PERSIST);
	(void) dladm_up_datalink_id(handle, linkid2);

	/*
	 * Now generate the RCM_RESOURCE_LINK_NEW sysevent which can be
	 * consumed by the RCM framework to restore all the datalink and
	 * IP configuration.
	 */
	status = DLADM_STATUS_FAILED;
	if ((nvlist_alloc(&nvl, 0, 0) != 0) ||
	    (nvlist_add_uint64(nvl, RCM_NV_LINKID, linkid2) != 0)) {
		goto done;
	}

	if (rcm_alloc_handle(NULL, 0, NULL, &rcm_hdl) != RCM_SUCCESS)
		goto done;

	if (rcm_notify_event(rcm_hdl, RCM_RESOURCE_LINK_NEW, 0, nvl, NULL) ==
	    RCM_SUCCESS) {
		status = DLADM_STATUS_OK;
	}

done:
	if (rcm_hdl != NULL)
		(void) rcm_free_handle(rcm_hdl);
	nvlist_free(nvl);
	return (status);
}

/*
 * case 3: rename a non-existent link to a REMOVED physical link.
 * Set the removed physical link's device name to link1, so that
 * when link1 attaches, it inherits all the link configuration of
 * the removed physical link.
 */
static dladm_status_t
i_dladm_rename_link_c3(dladm_handle_t handle, const char *link1,
    datalink_id_t linkid2)
{
	dladm_conf_t	conf;
	dladm_status_t	status;

	if (!dladm_valid_linkname(link1))
		return (DLADM_STATUS_LINKINVAL);

	status = dladm_open_conf(handle, linkid2, &conf);
	if (status != DLADM_STATUS_OK)
		goto done;

	if ((status = dladm_set_conf_field(handle, conf, FDEVNAME,
	    DLADM_TYPE_STR, link1)) == DLADM_STATUS_OK) {
		status = dladm_write_conf(handle, conf);
	}

	dladm_destroy_conf(handle, conf);

done:
	return (status);
}

dladm_status_t
dladm_rename_link(dladm_handle_t handle, const char *link1, const char *link2)
{
	datalink_id_t		linkid1 = DATALINK_INVALID_LINKID;
	datalink_id_t		linkid2 = DATALINK_INVALID_LINKID;
	uint32_t		flags1, flags2;
	datalink_class_t	class1, class2;
	uint32_t		media1, media2;
	boolean_t		remphy2 = B_FALSE;
	dladm_status_t  	status;

	(void) dladm_name2info(handle, link1, &linkid1, &flags1, &class1,
	    &media1);
	if ((dladm_name2info(handle, link2, &linkid2, &flags2, &class2,
	    &media2) == DLADM_STATUS_OK) && (class2 == DATALINK_CLASS_PHYS) &&
	    (flags2 == DLADM_OPT_PERSIST)) {
		/*
		 * see whether link2 is a removed physical link.
		 */
		remphy2 = B_TRUE;
	}

	if (linkid1 != DATALINK_INVALID_LINKID) {
		if (linkid2 == DATALINK_INVALID_LINKID) {
			/*
			 * case 1: rename an existing link to a link that
			 * does not exist.
			 */
			status = i_dladm_rename_link_c1(handle, linkid1, link1,
			    link2, flags1);
		} else if (remphy2) {
			/*
			 * case 2: rename an available link to a REMOVED
			 * physical link. Return failure if link1 is not
			 * an active physical link.
			 */
			if ((class1 != class2) || (media1 != media2) ||
			    !(flags1 & DLADM_OPT_ACTIVE)) {
				status = DLADM_STATUS_BADARG;
			} else {
				status = i_dladm_rename_link_c2(handle, linkid1,
				    linkid2);
			}
		} else {
			status = DLADM_STATUS_EXIST;
		}
	} else if (remphy2) {
		status = i_dladm_rename_link_c3(handle, link1, linkid2);
	} else {
		status = DLADM_STATUS_NOTFOUND;
	}
	return (status);
}

typedef struct consumer_del_phys_arg_s {
	datalink_id_t	linkid;
} consumer_del_phys_arg_t;

static int
i_dladm_vlan_link_del(dladm_handle_t handle, datalink_id_t vlanid, void *arg)
{
	consumer_del_phys_arg_t	*del_arg = arg;
	dladm_vlan_attr_t	vinfo;
	dladm_status_t		status;

	status = dladm_vlan_info(handle, vlanid, &vinfo, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (vinfo.dv_linkid == del_arg->linkid)
		(void) dladm_vlan_delete(handle, vlanid, DLADM_OPT_PERSIST);
	return (DLADM_WALK_CONTINUE);
}

static int
i_dladm_part_link_del(dladm_handle_t handle, datalink_id_t partid, void *arg)
{
	consumer_del_phys_arg_t	*del_arg = arg;
	dladm_part_attr_t	pinfo;
	dladm_status_t		status;

	status = dladm_part_info(handle, partid, &pinfo, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (pinfo.dia_physlinkid == del_arg->linkid)
		(void) dladm_part_delete(handle, partid, DLADM_OPT_PERSIST);
	return (DLADM_WALK_CONTINUE);
}

static int
i_dladm_aggr_link_del(dladm_handle_t handle, datalink_id_t aggrid, void *arg)
{
	consumer_del_phys_arg_t		*del_arg = arg;
	dladm_aggr_grp_attr_t		ginfo;
	dladm_status_t			status;
	dladm_aggr_port_attr_db_t	port[1];
	int				i;

	status = dladm_aggr_info(handle, aggrid, &ginfo, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	for (i = 0; i < ginfo.lg_nports; i++)
		if (ginfo.lg_ports[i].lp_linkid == del_arg->linkid)
			break;

	if (i != ginfo.lg_nports) {
		if (ginfo.lg_nports == 1 && i == 0) {
			consumer_del_phys_arg_t	aggr_del_arg;

			/*
			 * First delete all the VLANs on this aggregation, then
			 * delete the aggregation itself.
			 */
			aggr_del_arg.linkid = aggrid;
			(void) dladm_walk_datalink_id(i_dladm_vlan_link_del,
			    handle, &aggr_del_arg, DATALINK_CLASS_VLAN,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
			(void) dladm_aggr_delete(handle, aggrid,
			    DLADM_OPT_PERSIST);
		} else {
			port[0].lp_linkid = del_arg->linkid;
			(void) dladm_aggr_remove(handle, aggrid, 1, port,
			    DLADM_OPT_PERSIST);
		}
	}
	return (DLADM_WALK_CONTINUE);
}

typedef struct del_phys_arg_s {
	dladm_status_t	rval;
} del_phys_arg_t;

static int
i_dladm_phys_delete(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	uint32_t		flags;
	datalink_class_t	class;
	uint32_t		media;
	dladm_status_t		status = DLADM_STATUS_OK;
	del_phys_arg_t		*del_phys_arg = arg;
	consumer_del_phys_arg_t	del_arg;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, &class,
	    &media, NULL, 0)) != DLADM_STATUS_OK) {
		goto done;
	}

	/*
	 * see whether this link is a removed physical link.
	 */
	if ((class != DATALINK_CLASS_PHYS) || !(flags & DLADM_OPT_PERSIST) ||
	    (flags & DLADM_OPT_ACTIVE)) {
		status = DLADM_STATUS_BADARG;
		goto done;
	}

	if (media == DL_ETHER) {
		del_arg.linkid = linkid;
		(void) dladm_walk_datalink_id(i_dladm_aggr_link_del, handle,
		    &del_arg, DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		(void) dladm_walk_datalink_id(i_dladm_vlan_link_del, handle,
		    &del_arg, DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
	} else if (media == DL_IB) {
		del_arg.linkid = linkid;
		(void) dladm_walk_datalink_id(i_dladm_part_link_del, handle,
		    &del_arg, DATALINK_CLASS_PART, DL_IB, DLADM_OPT_PERSIST);
	}

	(void) dladm_remove_conf(handle, linkid);
	(void) dladm_destroy_datalink_id(handle, linkid, DLADM_OPT_PERSIST);
done:
	del_phys_arg->rval = status;
	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_phys_delete(dladm_handle_t handle, datalink_id_t linkid)
{
	del_phys_arg_t	arg = {DLADM_STATUS_OK};

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_phys_delete, handle, &arg,
		    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_phys_delete(handle, linkid, &arg);
		return (arg.rval);
	}
}

dladm_status_t
dladm_phys_info(dladm_handle_t handle, datalink_id_t linkid,
    dladm_phys_attr_t *dpap, uint32_t flags)
{
	dladm_status_t	status;

	assert(flags == DLADM_OPT_ACTIVE || flags == DLADM_OPT_PERSIST);

	switch (flags) {
	case DLADM_OPT_PERSIST: {
		dladm_conf_t	conf;

		status = dladm_getsnap_conf(handle, linkid, &conf);
		if (status != DLADM_STATUS_OK)
			return (status);

		status = dladm_get_conf_field(handle, conf, FDEVNAME,
		    dpap->dp_dev, MAXLINKNAMELEN);
		dladm_destroy_conf(handle, conf);
		return (status);
	}
	case DLADM_OPT_ACTIVE: {
		dld_ioc_phys_attr_t	dip;

		dip.dip_linkid = linkid;
		if (ioctl(dladm_dld_fd(handle), DLDIOC_PHYS_ATTR, &dip) < 0) {
			status = dladm_errno2status(errno);
			return (status);
		}
		dpap->dp_novanity = dip.dip_novanity;
		(void) strlcpy(dpap->dp_dev, dip.dip_dev, MAXLINKNAMELEN);
		return (DLADM_STATUS_OK);
	}
	default:
		return (DLADM_STATUS_BADARG);
	}
}

typedef struct i_walk_dev_state_s {
	const char *devname;
	datalink_id_t linkid;
	boolean_t found;
} i_walk_dev_state_t;

int
i_dladm_walk_dev2linkid(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_phys_attr_t dpa;
	dladm_status_t status;
	i_walk_dev_state_t *statep = arg;

	status = dladm_phys_info(handle, linkid, &dpa, DLADM_OPT_PERSIST);
	if ((status == DLADM_STATUS_OK) &&
	    (strcmp(statep->devname, dpa.dp_dev) == 0)) {
		statep->found = B_TRUE;
		statep->linkid = linkid;
		return (DLADM_WALK_TERMINATE);
	}
	return (DLADM_WALK_CONTINUE);
}

/*
 * Get the linkid from the physical device name.
 */
dladm_status_t
dladm_dev2linkid(dladm_handle_t handle, const char *devname,
    datalink_id_t *linkidp)
{
	i_walk_dev_state_t state;

	state.found = B_FALSE;
	state.devname = devname;

	(void) dladm_walk_datalink_id(i_dladm_walk_dev2linkid, handle, &state,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
	if (state.found == B_TRUE) {
		*linkidp = state.linkid;
		return (DLADM_STATUS_OK);
	} else {
		return (dladm_errno2status(ENOENT));
	}
}

static int
parse_devname(const char *devname, char *driver, uint_t *ppa, size_t maxlen)
{
	char	*cp, *tp;
	int	len;

	/*
	 * device name length must not be 0, and it must end with digit.
	 */
	if (((len = strlen(devname)) == 0) || !isdigit(devname[len - 1]))
		return (EINVAL);

	(void) strlcpy(driver, devname, maxlen);
	cp = (char *)&driver[len - 1];

	for (tp = cp; isdigit(*tp); tp--) {
		if (tp <= driver)
			return (EINVAL);
	}

	*ppa = atoi(tp + 1);
	*(tp + 1) = '\0';
	return (0);
}

dladm_status_t
dladm_linkid2legacyname(dladm_handle_t handle, datalink_id_t linkid, char *dev,
    size_t len)
{
	char			devname[MAXLINKNAMELEN];
	uint16_t		vid = VLAN_ID_NONE;
	datalink_class_t	class;
	dladm_status_t		status;

	status = dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		goto done;

	/*
	 * If this is a VLAN, we must first determine the class and linkid of
	 * the link the VLAN has been created over.
	 */
	if (class == DATALINK_CLASS_VLAN) {
		dladm_vlan_attr_t	dva;

		status = dladm_vlan_info(handle, linkid, &dva,
		    DLADM_OPT_ACTIVE);
		if (status != DLADM_STATUS_OK)
			goto done;
		linkid = dva.dv_linkid;
		vid = dva.dv_vid;

		if ((status = dladm_datalink_id2info(handle, linkid, NULL,
		    &class, NULL, NULL, 0)) != DLADM_STATUS_OK) {
			goto done;
		}
	}

	switch (class) {
	case DATALINK_CLASS_AGGR: {
		dladm_aggr_grp_attr_t	dga;

		status = dladm_aggr_info(handle, linkid, &dga,
		    DLADM_OPT_ACTIVE);
		if (status != DLADM_STATUS_OK)
			goto done;

		if (dga.lg_key == 0) {
			/*
			 * If the key was not specified when the aggregation
			 * is created, we cannot guess its /dev node name.
			 */
			status = DLADM_STATUS_BADARG;
			goto done;
		}
		(void) snprintf(devname, MAXLINKNAMELEN, "aggr%d", dga.lg_key);
		break;
	}
	case DATALINK_CLASS_PHYS: {
		dladm_phys_attr_t	dpa;

		status = dladm_phys_info(handle, linkid, &dpa,
		    DLADM_OPT_PERSIST);
		if (status != DLADM_STATUS_OK)
			goto done;

		(void) strlcpy(devname, dpa.dp_dev, MAXLINKNAMELEN);
		break;
	}
	default:
		status = DLADM_STATUS_BADARG;
		goto done;
	}

	if (vid != VLAN_ID_NONE) {
		char		drv[MAXNAMELEN];
		uint_t		ppa;

		if (parse_devname(devname, drv, &ppa, MAXNAMELEN) != 0) {
			status = DLADM_STATUS_BADARG;
			goto done;
		}
		if (snprintf(dev, len, "%s%d", drv, vid * 1000 + ppa) >= len)
			status = DLADM_STATUS_TOOSMALL;
	} else {
		if (strlcpy(dev, devname, len) >= len)
			status = DLADM_STATUS_TOOSMALL;
	}

done:
	return (status);
}

dladm_status_t
dladm_parselink(const char *dev, char *provider, uint_t *ppa)
{
	ifspec_t	ifsp;

	if (dev == NULL || !ifparse_ifspec(dev, &ifsp))
		return (DLADM_STATUS_LINKINVAL);

	if (provider != NULL)
		(void) strlcpy(provider, ifsp.ifsp_devnm, DLPI_LINKNAME_MAX);

	if (ppa != NULL)
		*ppa = ifsp.ifsp_ppa;

	return (DLADM_STATUS_OK);
}
