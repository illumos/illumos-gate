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
#include <libdllink.h>
#include <libdlmgmt.h>
#include <libdladm_impl.h>
#include <libinetutil.h>

/*
 * Return the attributes of the specified datalink from the DLD driver.
 */
static dladm_status_t
i_dladm_info(int fd, const datalink_id_t linkid, dladm_attr_t *dap)
{
	dld_ioc_attr_t	dia;

	dia.dia_linkid = linkid;

	if (i_dladm_ioctl(fd, DLDIOC_ATTR, &dia, sizeof (dia)) < 0)
		return (dladm_errno2status(errno));

	dap->da_max_sdu = dia.dia_max_sdu;

	return (DLADM_STATUS_OK);
}

struct i_dladm_walk_arg {
	dladm_walkcb_t *fn;
	void *arg;
};

static int
i_dladm_walk(datalink_id_t linkid, void *arg)
{
	struct i_dladm_walk_arg *walk_arg = arg;
	char link[MAXLINKNAMELEN];

	if (dladm_datalink_id2info(linkid, NULL, NULL, NULL, link,
	    sizeof (link)) == DLADM_STATUS_OK) {
		return (walk_arg->fn(link, walk_arg->arg));
	}

	return (DLADM_WALK_CONTINUE);
}

/*
 * Walk all datalinks.
 */
dladm_status_t
dladm_walk(dladm_walkcb_t *fn, void *arg, datalink_class_t class,
    datalink_media_t dmedia, uint32_t flags)
{
	struct i_dladm_walk_arg walk_arg;

	walk_arg.fn = fn;
	walk_arg.arg = arg;
	return (dladm_walk_datalink_id(i_dladm_walk, &walk_arg,
	    class, dmedia, flags));
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
dladm_info(datalink_id_t linkid, dladm_attr_t *dap)
{
	int		fd;
	dladm_status_t	status;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	status = i_dladm_info(fd, linkid, dap);

	(void) close(fd);
	return (status);
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
 * Set zoneid of a given link. Note that this function takes a link name
 * argument instead of a linkid, because a data-link (and its linkid) could
 * be created implicitly as the result of this function. For example, a VLAN
 * could be created if a VLAN PPA hack name is assigned to an exclusive
 * non-global zone.
 */
dladm_status_t
dladm_setzid(const char *dlname, char *zone_name)
{
	datalink_id_t	linkid;
	char		*val;
	char		**prop_val;
	char		link[MAXLINKNAMELEN];
	uint_t		ppa;
	char		dev[DLPI_LINKNAME_MAX];
	int		valsize;
	dladm_status_t	status = DLADM_STATUS_OK;
	char		*prop_name = "zone";
	boolean_t	needfree = B_FALSE;
	char		delim = ':';

	/* If the link does not exist, it is a ppa-hacked vlan. */
	status = dladm_name2info(dlname, &linkid, NULL, NULL, NULL);
	switch (status) {
	case DLADM_STATUS_NOTFOUND:
		if (strlen(dlname) > MAXLINKNAMELEN)
			return (DLADM_STATUS_BADVAL);

		if (strlen(zone_name) > ZONENAME_MAX)
			return (DLADM_STATUS_BADVAL);

		status = dladm_parselink(dlname, dev, &ppa);
		if (status != DLADM_STATUS_OK)
			return (status);

		ppa = (uint_t)DLS_PPA2INST(ppa);
		(void) snprintf(link, sizeof (link), "%s%d", dev, ppa);

		status = dladm_name2info(link, &linkid, NULL,  NULL, NULL);
		if (status != DLADM_STATUS_OK)
			return (status);

		/*
		 * Since the link does not exist as yet, we've to pass the
		 * link name too as part of data, so that the kernel can
		 * create the link. Hence, we're packing the zone_name and
		 * the link name into val.
		 */
		valsize = ZONENAME_MAX + MAXLINKNAMELEN + 1;
		val = malloc(valsize);
		if (val == NULL)
			return (DLADM_STATUS_NOMEM);
		needfree = B_TRUE;

		(void) snprintf(val, valsize, "%s%c%s", zone_name,
		    delim, dlname);

		break;
	case DLADM_STATUS_OK:
		/*
		 * The link exists, so only the zone_name is being passed as
		 * val. We could also pass zone_name + linkname like in the
		 * previous case just to maintain consistency, but other calls
		 * like set_linkprop() in dladm.c [which is called when we run
		 * 'dladm set-linkprop -p zone <linkname>' at the command line]
		 * pass in the value entered at the command line [which is zone
		 * name] as val.
		 */
		val = zone_name;
		break;
	default:
		return (DLADM_STATUS_FAILED);
	}

	prop_val = &val;
	status = dladm_set_linkprop(linkid, prop_name, prop_val, 1,
	    DLADM_OPT_ACTIVE);

	if (needfree)
		free(val);
	return (status);
}

/*
 * Case 1: rename an existing link1 to a link2 that does not exist.
 * Result: <linkid1, link2>
 */
static dladm_status_t
i_dladm_rename_link_c1(datalink_id_t linkid1, const char *link1,
    const char *link2, uint32_t flags)
{
	dld_ioc_rename_t	dir;
	dladm_conf_t		conf;
	dladm_status_t		status = DLADM_STATUS_OK;
	int			fd;

	/*
	 * Link is currently available. Check to see whether anything is
	 * holding this link to prevent a rename operation.
	 */
	if (flags & DLADM_OPT_ACTIVE) {
		dir.dir_linkid1 = linkid1;
		dir.dir_linkid2 = DATALINK_INVALID_LINKID;
		(void) strlcpy(dir.dir_link, link2, MAXLINKNAMELEN);
		if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
			return (dladm_errno2status(errno));

		if (i_dladm_ioctl(fd, DLDIOC_RENAME, &dir, sizeof (dir)) < 0) {
			status = dladm_errno2status(errno);
			(void) close(fd);
			return (status);
		}
	}

	status = dladm_remap_datalink_id(linkid1, link2);
	if (status != DLADM_STATUS_OK)
		goto done;

	/*
	 * Flush the current mapping to persistent configuration.
	 */
	if ((flags & DLADM_OPT_PERSIST) &&
	    (((status = dladm_read_conf(linkid1, &conf)) != DLADM_STATUS_OK) ||
	    ((status = dladm_write_conf(conf)) != DLADM_STATUS_OK))) {
		(void) dladm_remap_datalink_id(linkid1, link1);
	}
done:
	if (flags & DLADM_OPT_ACTIVE) {
		if (status != DLADM_STATUS_OK) {
			(void) strlcpy(dir.dir_link, link1, MAXLINKNAMELEN);
			(void) i_dladm_ioctl(fd, DLDIOC_RENAME, &dir,
			    sizeof (dir));
		}
		(void) close(fd);
	}
	return (status);
}

typedef struct link_hold_arg_s {
	datalink_id_t	linkid;
	datalink_id_t	holder;
	uint32_t	flags;
} link_hold_arg_t;

static int
i_dladm_aggr_link_hold(datalink_id_t aggrid, void *arg)
{
	link_hold_arg_t		*hold_arg = arg;
	dladm_aggr_grp_attr_t	ginfo;
	dladm_status_t		status;
	int			i;

	status = dladm_aggr_info(aggrid, &ginfo, hold_arg->flags);
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
i_dladm_vlan_link_hold(datalink_id_t vlanid, void *arg)
{
	link_hold_arg_t		*hold_arg = arg;
	dladm_vlan_attr_t	vinfo;
	dladm_status_t		status;

	status = dladm_vlan_info(vlanid, &vinfo, hold_arg->flags);
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
i_dladm_rename_link_c2(datalink_id_t linkid1, datalink_id_t linkid2)
{
	rcm_handle_t		*rcm_hdl = NULL;
	nvlist_t		*nvl = NULL;
	link_hold_arg_t		arg;
	dld_ioc_rename_t	dir;
	int			fd;
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
	(void) dladm_walk_datalink_id(i_dladm_aggr_link_hold, &arg,
	    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
	if (arg.holder != DATALINK_INVALID_LINKID)
		return (DLADM_STATUS_LINKBUSY);

	arg.flags = DLADM_OPT_PERSIST;
	(void) dladm_walk_datalink_id(i_dladm_vlan_link_hold, &arg,
	    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
	if (arg.holder != DATALINK_INVALID_LINKID)
		return (DLADM_STATUS_LINKBUSY);

	/*
	 * Send DLDIOC_RENAME to request to rename link1's linkid to
	 * be linkid2. This will check whether link1 is used by any
	 * aggregations or VLANs, or is held by any application. If yes,
	 * return failure.
	 */
	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	dir.dir_linkid1 = linkid1;
	dir.dir_linkid2 = linkid2;
	if (i_dladm_ioctl(fd, DLDIOC_RENAME, &dir, sizeof (dir)) < 0)
		status = dladm_errno2status(errno);

	if (status != DLADM_STATUS_OK) {
		(void) close(fd);
		return (status);
	}

	/*
	 * Now change the phymaj, phyinst and devname associated with linkid1
	 * to be associated with linkid2. Before doing that, the old active
	 * linkprop of linkid1 should be deleted.
	 */
	(void) dladm_set_linkprop(linkid1, NULL, NULL, 0, DLADM_OPT_ACTIVE);

	if (((status = dladm_read_conf(linkid1, &conf1)) != DLADM_STATUS_OK) ||
	    ((status = dladm_get_conf_field(conf1, FDEVNAME, devname,
	    MAXLINKNAMELEN)) != DLADM_STATUS_OK) ||
	    ((status = dladm_get_conf_field(conf1, FPHYMAJ, &phymaj,
	    sizeof (uint64_t))) != DLADM_STATUS_OK) ||
	    ((status = dladm_get_conf_field(conf1, FPHYINST, &phyinst,
	    sizeof (uint64_t))) != DLADM_STATUS_OK) ||
	    ((status = dladm_read_conf(linkid2, &conf2)) != DLADM_STATUS_OK)) {
		dir.dir_linkid1 = linkid2;
		dir.dir_linkid2 = linkid1;
		(void) dladm_init_linkprop(linkid1, B_FALSE);
		(void) i_dladm_ioctl(fd, DLDIOC_RENAME, &dir, sizeof (dir));
		(void) close(fd);
		return (status);
	}
	(void) close(fd);

	dladm_destroy_conf(conf1);
	(void) dladm_set_conf_field(conf2, FDEVNAME, DLADM_TYPE_STR, devname);
	(void) dladm_set_conf_field(conf2, FPHYMAJ, DLADM_TYPE_UINT64, &phymaj);
	(void) dladm_set_conf_field(conf2, FPHYINST,
	    DLADM_TYPE_UINT64, &phyinst);
	(void) dladm_write_conf(conf2);
	dladm_destroy_conf(conf2);

	/*
	 * Delete link1 and mark link2 up.
	 */
	(void) dladm_destroy_datalink_id(linkid1, DLADM_OPT_ACTIVE |
	    DLADM_OPT_PERSIST);
	(void) dladm_remove_conf(linkid1);
	(void) dladm_up_datalink_id(linkid2);

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
	if (nvl != NULL)
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
i_dladm_rename_link_c3(const char *link1, datalink_id_t linkid2)
{
	dladm_conf_t	conf;
	dladm_status_t	status;

	if (!dladm_valid_linkname(link1))
		return (DLADM_STATUS_LINKINVAL);

	status = dladm_read_conf(linkid2, &conf);
	if (status != DLADM_STATUS_OK)
		goto done;

	if ((status = dladm_set_conf_field(conf, FDEVNAME, DLADM_TYPE_STR,
	    link1)) == DLADM_STATUS_OK) {
		status = dladm_write_conf(conf);
	}

	dladm_destroy_conf(conf);

done:
	return (status);
}

dladm_status_t
dladm_rename_link(const char *link1, const char *link2)
{
	datalink_id_t		linkid1 = DATALINK_INVALID_LINKID;
	datalink_id_t		linkid2 = DATALINK_INVALID_LINKID;
	uint32_t		flags1, flags2;
	datalink_class_t	class1, class2;
	uint32_t		media1, media2;
	boolean_t		remphy2 = B_FALSE;
	dladm_status_t  	status;

	(void) dladm_name2info(link1, &linkid1, &flags1, &class1, &media1);
	if ((dladm_name2info(link2, &linkid2, &flags2, &class2, &media2) ==
	    DLADM_STATUS_OK) && (class2 == DATALINK_CLASS_PHYS) &&
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
			status = i_dladm_rename_link_c1(linkid1, link1, link2,
			    flags1);
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
				status = i_dladm_rename_link_c2(linkid1,
				    linkid2);
			}
		} else {
			status = DLADM_STATUS_EXIST;
		}
	} else if (remphy2) {
		status = i_dladm_rename_link_c3(link1, linkid2);
	} else {
		status = DLADM_STATUS_NOTFOUND;
	}
	return (status);
}

typedef struct consumer_del_phys_arg_s {
	datalink_id_t	linkid;
} consumer_del_phys_arg_t;

static int
i_dladm_vlan_link_del(datalink_id_t vlanid, void *arg)
{
	consumer_del_phys_arg_t	*del_arg = arg;
	dladm_vlan_attr_t	vinfo;
	dladm_status_t		status;

	status = dladm_vlan_info(vlanid, &vinfo, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (vinfo.dv_linkid == del_arg->linkid)
		(void) dladm_vlan_delete(vlanid, DLADM_OPT_PERSIST);
	return (DLADM_WALK_CONTINUE);
}

static int
i_dladm_aggr_link_del(datalink_id_t aggrid, void *arg)
{
	consumer_del_phys_arg_t		*del_arg = arg;
	dladm_aggr_grp_attr_t		ginfo;
	dladm_status_t			status;
	dladm_aggr_port_attr_db_t	port[1];
	int				i;

	status = dladm_aggr_info(aggrid, &ginfo, DLADM_OPT_PERSIST);
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
			    &aggr_del_arg, DATALINK_CLASS_VLAN,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
			(void) dladm_aggr_delete(aggrid, DLADM_OPT_PERSIST);
		} else {
			port[0].lp_linkid = del_arg->linkid;
			(void) dladm_aggr_remove(aggrid, 1, port,
			    DLADM_OPT_PERSIST);
		}
	}
	return (DLADM_WALK_CONTINUE);
}

typedef struct del_phys_arg_s {
	dladm_status_t	rval;
} del_phys_arg_t;

static int
i_dladm_phys_delete(datalink_id_t linkid, void *arg)
{
	uint32_t		flags;
	datalink_class_t	class;
	uint32_t		media;
	dladm_status_t		status = DLADM_STATUS_OK;
	del_phys_arg_t		*del_phys_arg = arg;
	consumer_del_phys_arg_t	del_arg;

	if ((status = dladm_datalink_id2info(linkid, &flags, &class,
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
		(void) dladm_walk_datalink_id(i_dladm_aggr_link_del, &del_arg,
		    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		(void) dladm_walk_datalink_id(i_dladm_vlan_link_del, &del_arg,
		    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
	}

	(void) dladm_destroy_datalink_id(linkid, DLADM_OPT_PERSIST);
	(void) dladm_remove_conf(linkid);

done:
	del_phys_arg->rval = status;
	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_phys_delete(datalink_id_t linkid)
{
	del_phys_arg_t	arg = {DLADM_STATUS_OK};

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_phys_delete, &arg,
		    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_phys_delete(linkid, &arg);
		return (arg.rval);
	}
}

dladm_status_t
dladm_phys_info(datalink_id_t linkid, dladm_phys_attr_t *dpap, uint32_t flags)
{
	dladm_status_t	status;

	assert(flags == DLADM_OPT_ACTIVE || flags == DLADM_OPT_PERSIST);

	switch (flags) {
	case DLADM_OPT_PERSIST: {
		dladm_conf_t	conf;

		status = dladm_read_conf(linkid, &conf);
		if (status != DLADM_STATUS_OK)
			return (status);

		status = dladm_get_conf_field(conf, FDEVNAME, dpap->dp_dev,
		    MAXLINKNAMELEN);
		dladm_destroy_conf(conf);
		return (status);
	}
	case DLADM_OPT_ACTIVE: {
		dld_ioc_phys_attr_t	dip;
		int			fd;

		if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
			return (dladm_errno2status(errno));

		dip.dip_linkid = linkid;
		if (i_dladm_ioctl(fd, DLDIOC_PHYS_ATTR, &dip, sizeof (dip))
		    < 0) {
			status = dladm_errno2status(errno);
			(void) close(fd);
			return (status);
		}
		(void) close(fd);
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
i_dladm_walk_dev2linkid(datalink_id_t linkid, void *arg)
{
	dladm_phys_attr_t dpa;
	dladm_status_t status;
	i_walk_dev_state_t *statep = arg;

	status = dladm_phys_info(linkid, &dpa, DLADM_OPT_PERSIST);
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
dladm_dev2linkid(const char *devname, datalink_id_t *linkidp)
{
	i_walk_dev_state_t state;

	state.found = B_FALSE;
	state.devname = devname;

	(void) dladm_walk_datalink_id(i_dladm_walk_dev2linkid, &state,
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
dladm_linkid2legacyname(datalink_id_t linkid, char *dev, size_t len)
{
	char			devname[MAXLINKNAMELEN];
	uint16_t		vid = VLAN_ID_NONE;
	datalink_class_t	class;
	dladm_status_t		status;

	status = dladm_datalink_id2info(linkid, NULL, &class, NULL, NULL, 0);
	if (status != DLADM_STATUS_OK)
		goto done;

	/*
	 * If this is a VLAN, we must first determine the class and linkid of
	 * the link the VLAN has been created over.
	 */
	if (class == DATALINK_CLASS_VLAN) {
		dladm_vlan_attr_t	dva;

		status = dladm_vlan_info(linkid, &dva, DLADM_OPT_ACTIVE);
		if (status != DLADM_STATUS_OK)
			goto done;
		linkid = dva.dv_linkid;
		vid = dva.dv_vid;

		if ((status = dladm_datalink_id2info(linkid, NULL, &class, NULL,
		    NULL, 0)) != DLADM_STATUS_OK) {
			goto done;
		}
	}

	switch (class) {
	case DATALINK_CLASS_AGGR: {
		dladm_aggr_grp_attr_t	dga;

		status = dladm_aggr_info(linkid, &dga, DLADM_OPT_ACTIVE);
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

		status = dladm_phys_info(linkid, &dpa, DLADM_OPT_PERSIST);
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
dladm_get_single_mac_stat(datalink_id_t linkid, const char *name, uint8_t type,
    void *val)
{
	char		module[DLPI_LINKNAME_MAX];
	uint_t		instance;
	char 		link[DLPI_LINKNAME_MAX];
	dladm_status_t	status;
	uint32_t	flags, media;
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;
	dladm_phys_attr_t dpap;

	if ((status = dladm_datalink_id2info(linkid, &flags, NULL, &media,
	    link, DLPI_LINKNAME_MAX)) != DLADM_STATUS_OK)
		return (status);

	if (media != DL_ETHER)
		return (DLADM_STATUS_LINKINVAL);

	status = dladm_phys_info(linkid, &dpap, DLADM_OPT_PERSIST);

	if (status != DLADM_STATUS_OK)
		return (status);

	status = dladm_parselink(dpap.dp_dev, module, &instance);

	if (status != DLADM_STATUS_OK)
		return (status);

	if ((kcp = kstat_open()) == NULL)
		return (dladm_errno2status(errno));

	/*
	 * The kstat query could fail if the underlying MAC
	 * driver was already detached.
	 */
	if ((ksp = kstat_lookup(kcp, module, instance, "mac")) == NULL &&
	    (ksp = kstat_lookup(kcp, module, instance, NULL)) == NULL)
		goto bail;

	if (kstat_read(kcp, ksp, NULL) == -1)
		goto bail;

	if (dladm_kstat_value(ksp, name, type, val) < 0)
		goto bail;

	(void) kstat_close(kcp);
	return (DLADM_STATUS_OK);
bail:
	(void) kstat_close(kcp);
	return (dladm_errno2status(errno));

}

int
dladm_kstat_value(kstat_t *ksp, const char *name, uint8_t type, void *buf)
{
	kstat_named_t	*knp;

	if ((knp = kstat_data_lookup(ksp, (char *)name)) == NULL)
		return (-1);

	if (knp->data_type != type)
		return (-1);

	switch (type) {
	case KSTAT_DATA_UINT64:
		*(uint64_t *)buf = knp->value.ui64;
		break;
	case KSTAT_DATA_UINT32:
		*(uint32_t *)buf = knp->value.ui32;
		break;
	default:
		return (-1);
	}

	return (0);
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
