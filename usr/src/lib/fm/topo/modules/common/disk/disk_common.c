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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Functions in this file are shared between the disk and ses enumerators.
 *
 * A topo_list_t of all disks is returned by a successful disk_list_gather()
 * call, and the list is freed by a disk_list_free(). To create a 'disk' topo
 * node below a specific 'bay' parent node either disk_declare_path() or
 * disk_declare_addr() are called. The caller determines which 'disk' is
 * in which 'bay'. A disk's 'label' and 'authority' information come from
 * its parent 'bay' node.
 */

#include <ctype.h>
#include <strings.h>
#include <libdevinfo.h>
#include <devid.h>
#include <sys/libdevid.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/dkio.h>
#include <sys/scsi/scsi_types.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/libdiskstatus.h>
#include <sys/fm/protocol.h>
#include <sys/scsi/generic/inquiry.h>
#include "disk.h"

/* common callback information for di_walk_node() and di_devlink_walk */
typedef struct disk_cbdata {
	topo_mod_t		*dcb_mod;
	topo_list_t		*dcb_list;

	di_devlink_handle_t	dcb_devhdl;
	dev_di_node_t		*dcb_dnode;	/* for di_devlink_walk only */
} disk_cbdata_t;

/*
 * Given a /devices path for a whole disk, appending this extension gives the
 * path to a raw device that can be opened.
 */
#if defined(__i386) || defined(__amd64)
#define	PHYS_EXTN	":q,raw"
#elif defined(__sparc) || defined(__sparcv9)
#define	PHYS_EXTN	":c,raw"
#else
#error	Unknown architecture
#endif

/*
 * Methods for disks. This is used by the disk-transport module to
 * generate ereports based off SCSI disk status.
 */
static int disk_status(topo_mod_t *, tnode_t *, topo_version_t,
	nvlist_t *, nvlist_t **);

static const topo_method_t disk_methods[] = {
	{ TOPO_METH_DISK_STATUS, TOPO_METH_DISK_STATUS_DESC,
	    TOPO_METH_DISK_STATUS_VERSION, TOPO_STABILITY_INTERNAL,
	    disk_status },
	{ NULL }
};

static const topo_pgroup_info_t io_pgroup = {
	TOPO_PGROUP_IO,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t disk_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t storage_pgroup = {
	TOPO_PGROUP_STORAGE,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/*
 * Set the properties of the disk node, from dev_di_node_t data.
 * Properties include:
 *	group: protocol	 properties: resource, asru, label, fru
 *	group: authority properties: product-id, chasis-id, server-id
 *	group: io	 properties: devfs-path, devid
 *	group: storage	 properties:
 *		- logical-disk, disk-model, disk-manufacturer, serial-number
 *		- firmware-revision, capacity-in-bytes
 *
 * NOTE: the io and storage groups won't be present if the dnode passed in is
 * NULL. This happens when a disk is found through ses, but is not enumerated
 * in the devinfo tree.
 */
static int
disk_set_props(topo_mod_t *mod, tnode_t *parent,
    tnode_t *dtn, dev_di_node_t *dnode)
{
	nvlist_t	*asru = NULL;
	char		*label = NULL;
	nvlist_t	*fmri = NULL;
	int		err;

	/* pull the label property down from our parent 'bay' node */
	if (topo_node_label(parent, &label, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "label error %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_node_label_set(dtn, label, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "label_set error %s\n", topo_strerror(err));
		goto error;
	}

	/* get the resource fmri, and use it as the fru */
	if (topo_node_resource(dtn, &fmri, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "resource error: %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_node_fru_set(dtn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "fru_set error: %s\n", topo_strerror(err));
		goto error;
	}

	/* create/set the authority group */
	if ((topo_pgroup_create(dtn, &disk_auth_pgroup, &err) != 0) &&
	    (err != ETOPO_PROP_DEFD)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "create disk_auth error %s\n", topo_strerror(err));
		goto error;
	}

	/* create the storage group */
	if (topo_pgroup_create(dtn, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "create storage error %s\n", topo_strerror(err));
		goto error;
	}

	/* no dnode was found for this disk - skip the io and storage groups */
	if (dnode == NULL) {
		err = 0;
		goto out;
	}

	/* form and set the asru */
	if ((asru = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION,
	    dnode->ddn_dpath, dnode->ddn_devid)) == NULL) {
		err = ETOPO_FMRI_UNKNOWN;
		topo_mod_dprintf(mod, "disk_set_props: "
		    "asru error %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_node_asru_set(dtn, asru, 0, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "asru_set error %s\n", topo_strerror(err));
		goto error;
	}

	/* create/set the devfs-path and devid in the io group */
	if (topo_pgroup_create(dtn, &io_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "create io error %s\n", topo_strerror(err));
		goto error;
	}

	if (topo_prop_set_string(dtn, TOPO_PGROUP_IO, TOPO_IO_DEV_PATH,
	    TOPO_PROP_IMMUTABLE, dnode->ddn_dpath, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set dev error %s\n", topo_strerror(err));
		goto error;
	}

	if (dnode->ddn_devid && topo_prop_set_string(dtn, TOPO_PGROUP_IO,
	    TOPO_IO_DEVID, TOPO_PROP_IMMUTABLE, dnode->ddn_devid, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set devid error %s\n", topo_strerror(err));
		goto error;
	}

	if (dnode->ddn_ppath_count != 0 &&
	    topo_prop_set_string_array(dtn, TOPO_PGROUP_IO, TOPO_IO_PHYS_PATH,
	    TOPO_PROP_IMMUTABLE, (const char **)dnode->ddn_ppath,
	    dnode->ddn_ppath_count, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set phys-path error %s\n", topo_strerror(err));
		goto error;
	}

	/* set the storage group public /dev name */
	if (dnode->ddn_lpath != NULL &&
	    topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_LOGICAL_DISK_NAME, TOPO_PROP_IMMUTABLE,
	    dnode->ddn_lpath, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set disk_name error %s\n", topo_strerror(err));
		goto error;
	}

	/* populate other misc storage group properties */
	if (dnode->ddn_mfg && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MANUFACTURER, TOPO_PROP_IMMUTABLE,
	    dnode->ddn_mfg, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set mfg error %s\n", topo_strerror(err));
		goto error;
	}
	if (dnode->ddn_model && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MODEL, TOPO_PROP_IMMUTABLE,
	    dnode->ddn_model, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set model error %s\n", topo_strerror(err));
		goto error;
	}
	if (dnode->ddn_serial && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_SERIAL_NUM, TOPO_PROP_IMMUTABLE,
	    dnode->ddn_serial, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set serial error %s\n", topo_strerror(err));
		goto error;
	}
	if (dnode->ddn_firm && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE,
	    dnode->ddn_firm, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set firm error %s\n", topo_strerror(err));
		goto error;
	}
	if (dnode->ddn_cap && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_CAPACITY, TOPO_PROP_IMMUTABLE,
	    dnode->ddn_cap, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set cap error %s\n", topo_strerror(err));
		goto error;
	}
	err = 0;

out:
	nvlist_free(fmri);
	if (label)
		topo_mod_strfree(mod, label);
	nvlist_free(asru);
	return (err);

error:	err = topo_mod_seterrno(mod, err);
	goto out;
}

/*
 * Trim leading and trailing whitespace from the string.
 */
static char *
disk_trim_whitespace(topo_mod_t *mod, const char *begin)
{
	const char *end;
	char *buf;
	size_t count;

	if (begin == NULL)
		return (NULL);

	end = begin + strlen(begin);

	while (begin < end && isspace(*begin))
		begin++;
	while (begin < end && isspace(*(end - 1)))
		end--;

	count = end - begin;
	if ((buf = topo_mod_alloc(mod, count + 1)) == NULL)
		return (NULL);

	(void) strlcpy(buf, begin, count + 1);

	return (buf);
}

/*
 * Manufacturing strings can contain characters that are invalid for use in hc
 * authority names.  This trims leading and trailing whitespace, and
 * substitutes any characters known to be bad.
 */
char *
disk_auth_clean(topo_mod_t *mod, const char *str)
{
	char *buf, *p;

	if (str == NULL)
		return (NULL);

	if ((buf = topo_mod_strdup(mod, str)) == NULL)
		return (NULL);

	while ((p = strpbrk(buf, " :=")) != NULL)
		*p = '-';

	return (buf);
}

/* create the disk topo node */
static int
disk_tnode_create(topo_mod_t *mod, tnode_t *parent,
    dev_di_node_t *dnode, const char *name, topo_instance_t i, tnode_t **rval)
{
	int		len;
	nvlist_t	*fmri;
	tnode_t		*dtn;
	char		*part = NULL;
	nvlist_t	*auth;
	char		*mfg, *model, *firm, *serial;

	*rval = NULL;
	if (dnode != NULL) {
		mfg = disk_auth_clean(mod, dnode->ddn_mfg);
		model = disk_auth_clean(mod, dnode->ddn_model);
		firm = disk_auth_clean(mod, dnode->ddn_firm);
		serial = disk_auth_clean(mod, dnode->ddn_serial);
	} else {
		mfg = model = firm = serial = NULL;
	}

	/* form 'part=' of fmri as "<mfg>-<model>" */
	if (mfg != NULL && model != NULL) {
		len = strlen(mfg) + 1 + strlen(model) + 1;
		if ((part = topo_mod_alloc(mod, len)) != NULL)
			(void) snprintf(part, len, "%s-%s",
			    mfg, model);
	}

	auth = topo_mod_auth(mod, parent);
	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i, NULL,
	    auth, part ? part : model, firm, serial);
	nvlist_free(auth);

	topo_mod_strfree(mod, part);
	topo_mod_strfree(mod, mfg);
	topo_mod_strfree(mod, model);
	topo_mod_strfree(mod, firm);
	topo_mod_strfree(mod, serial);

	if (fmri == NULL) {
		topo_mod_dprintf(mod, "disk_tnode_create: "
		    "hcfmri (%s%d/%s%d) error %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	if ((dtn = topo_node_bind(mod, parent, name, i, fmri)) == NULL) {
		if (topo_mod_errno(mod) == EMOD_NODE_BOUND) {
			/*
			 * if disk 0 is already there then we're done
			 */
			nvlist_free(fmri);
			return (0);
		}
		topo_mod_dprintf(mod, "disk_tnode_create: "
		    "bind (%s%d/%s%d) error %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (-1);
	}
	nvlist_free(fmri);

	/* add the properties of the disk */
	if (disk_set_props(mod, parent, dtn, dnode) != 0) {
		topo_mod_dprintf(mod, "disk_tnode_create: "
		    "disk_set_props (%s%d/%s%d) error %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(dtn);
		return (-1);
	}
	*rval = dtn;
	return (0);
}

static int
disk_declare(topo_mod_t *mod, tnode_t *parent, dev_di_node_t *dnode,
    tnode_t **childp)
{
	tnode_t		*dtn = NULL;
	int		rval;

	rval = disk_tnode_create(mod, parent, dnode, DISK, 0, &dtn);
	if (dtn == NULL) {
		if (rval == 0)
			return (0);
		topo_mod_dprintf(mod, "disk_declare: "
		    "disk_tnode_create error %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	/* register disk_methods against the disk topo node */
	if (topo_method_register(mod, dtn, disk_methods) != 0) {
		topo_mod_dprintf(mod, "disk_declare: "
		    "topo_method_register error %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(dtn);
		return (-1);
	}
	if (childp != NULL)
		*childp = dtn;
	return (0);
}

int
disk_declare_path(topo_mod_t *mod, tnode_t *parent, topo_list_t *listp,
    const char *path)
{
	dev_di_node_t		*dnode;
	int i;

	/*
	 * Check for match using physical phci (ddn_ppath). Use
	 * di_devfs_path_match so generic.vs.non-generic names match.
	 */
	for (dnode = topo_list_next(listp); dnode != NULL;
	    dnode = topo_list_next(dnode)) {
		if (dnode->ddn_ppath == NULL)
			continue;

		for (i = 0; i < dnode->ddn_ppath_count; i++) {
			if (di_devfs_path_match(dnode->ddn_ppath[0], path))
				return (disk_declare(mod, parent, dnode, NULL));
		}
	}

	topo_mod_dprintf(mod, "disk_declare_path: "
	    "failed to find disk matching path %s", path);
	return (0);
}

int
disk_declare_addr(topo_mod_t *mod, tnode_t *parent, topo_list_t *listp,
    const char *addr, tnode_t **childp)
{
	dev_di_node_t *dnode;
	int i;

	/* Check for match using addr. */
	for (dnode = topo_list_next(listp); dnode != NULL;
	    dnode = topo_list_next(dnode)) {
		if (dnode->ddn_target_port == NULL)
			continue;

		for (i = 0; i < dnode->ddn_ppath_count; i++) {
			if ((dnode->ddn_target_port[i] != NULL) &&
			    (strncmp(dnode->ddn_target_port[i], addr,
			    strcspn(dnode->ddn_target_port[i], ":"))) == 0) {
				topo_mod_dprintf(mod, "disk_declare_addr: "
				    "found disk matching addr %s", addr);
				return (disk_declare(mod, parent, dnode,
				    childp));
			}
		}
	}

	topo_mod_dprintf(mod, "disk_declare_addr: "
	    "failed to find disk matching addr %s", addr);

	return (1);
}

/*
 * Used to declare a disk that has been discovered through other means (usually
 * ses), that is not enumerated in the devinfo tree.
 */
int
disk_declare_non_enumerated(topo_mod_t *mod, tnode_t *parent, tnode_t **childp)
{
	return (disk_declare(mod, parent, NULL, childp));
}

/* di_devlink callback for dev_di_node_add */
static int
disk_devlink_callback(di_devlink_t dl, void *arg)
{
	disk_cbdata_t	*cbp = (disk_cbdata_t *)arg;
	topo_mod_t	*mod = cbp->dcb_mod;
	dev_di_node_t	*dnode = cbp->dcb_dnode;
	const char	*devpath;
	char		*ctds, *slice;

	devpath = di_devlink_path(dl);
	if ((dnode == NULL) || (devpath == NULL))
		return (DI_WALK_TERMINATE);

	/* trim the slice off the public name */
	if (((ctds = strrchr(devpath, '/')) != NULL) &&
	    ((slice = strchr(ctds, 's')) != NULL))
		*slice = '\0';

	/* Establish the public /dev name (no slice) */
	dnode->ddn_lpath = topo_mod_strdup(mod, ctds ? ctds + 1 : devpath);

	if (ctds && slice)
		*slice = 's';
	return (DI_WALK_TERMINATE);
}

static void
dev_di_node_free(topo_mod_t *mod, dev_di_node_t *dnode)
{
	int i;

	/* free the stuff we point to */
	if (dnode->ddn_devid)
		topo_mod_strfree(mod, dnode->ddn_devid);
	for (i = 0; i < dnode->ddn_ppath_count; i++) {
		/* topo_mod_strfree does NULL checking. */
		topo_mod_strfree(mod, dnode->ddn_ppath[i]);
		topo_mod_strfree(mod, dnode->ddn_target_port[i]);
		topo_mod_strfree(mod, dnode->ddn_attached_port[i]);
		topo_mod_strfree(mod, dnode->ddn_bridge_port[i]);
	}
	topo_mod_free(mod, dnode->ddn_ppath,
	    dnode->ddn_ppath_count * sizeof (char *));
	topo_mod_free(mod, dnode->ddn_target_port,
	    dnode->ddn_ppath_count * sizeof (char *));
	topo_mod_free(mod, dnode->ddn_attached_port,
	    dnode->ddn_ppath_count * sizeof (char *));
	topo_mod_free(mod, dnode->ddn_bridge_port,
	    dnode->ddn_ppath_count * sizeof (char *));
	topo_mod_strfree(mod, dnode->ddn_dpath);
	topo_mod_strfree(mod, dnode->ddn_lpath);

	topo_mod_strfree(mod, dnode->ddn_mfg);
	topo_mod_strfree(mod, dnode->ddn_model);
	topo_mod_strfree(mod, dnode->ddn_serial);
	topo_mod_strfree(mod, dnode->ddn_firm);
	topo_mod_strfree(mod, dnode->ddn_cap);

	/* free self */
	topo_mod_free(mod, dnode, sizeof (dev_di_node_t));
}

static int
dev_di_node_add(di_node_t node, char *devid, disk_cbdata_t *cbp)
{
	topo_mod_t	*mod = cbp->dcb_mod;
	dev_di_node_t	*dnode;
	di_path_t	pnode;
	char		*path;
	int		mlen;
	char		*minorpath;
	char		*extn = ":a";
	char		*s;
	int64_t		*nblocksp;
	uint64_t	nblocks;
	int		*dblksizep;
	uint_t		dblksize;
	char		lentry[MAXPATHLEN];
	int		pathcount;
	int		*inq_dtype, itype;
	int 		i;

	if (devid) {
		/*
		 * Check for list duplicate using devid search.
		 * Note if there is no devid, then we can end up with duplicates
		 * in the list, but this doesn't do any harm.
		 */
		for (dnode = topo_list_next(cbp->dcb_list);
		    dnode != NULL; dnode = topo_list_next(dnode)) {
			if (dnode->ddn_devid &&
			    devid_str_compare(dnode->ddn_devid, devid) == 0) {
				topo_mod_dprintf(mod, "dev_di_node_add: "
				    "already there %s\n", devid);
				return (0);
			}
		}
	}

	if ((dnode = topo_mod_zalloc(mod, sizeof (dev_di_node_t))) == NULL)
		return (-1);

	if (devid) {
		/* Establish the devid. */
		dnode->ddn_devid = topo_mod_strdup(mod, devid);
		if (dnode->ddn_devid == NULL)
			goto error;
	}

	/* Establish the devinfo dpath */
	if ((path = di_devfs_path(node)) == NULL) {
		(void) topo_mod_seterrno(mod, errno);
		goto error;
	}

	dnode->ddn_dpath = topo_mod_strdup(mod, path);
	di_devfs_path_free(path);
	if (dnode->ddn_dpath == NULL)
		goto error;

	/*
	 * Establish the physical ppath and target ports. If the device is
	 * non-mpxio then dpath and ppath are the same, and the target port is a
	 * property of the device node.
	 *
	 * If dpath is a client node under scsi_vhci, then iterate over all
	 * paths and get their physical paths and target port properrties.
	 * di_path_client_next_path call below will
	 * return non-NULL, and ppath is set to the physical path to the first
	 * pathinfo node.
	 *
	 * NOTE: It is possible to get a generic.vs.non-generic path
	 * for di_devfs_path.vs.di_path_devfs_path like:
	 *    xml: /pci@7b,0/pci1022,7458@11/pci1000,3060@2/sd@2,0
	 *  pnode: /pci@7b,0/pci1022,7458@11/pci1000,3060@2/disk@2,0
	 * To resolve this issue disk_declare_path() needs to use the
	 * special di_devfs_path_match() interface.
	 */
	pathcount = 0;
	pnode = NULL;
	while ((pnode = di_path_client_next_path(node, pnode)) != NULL) {
		pathcount++;
	}

	if (pathcount == 0) {
		if ((dnode->ddn_ppath =
		    topo_mod_zalloc(mod, sizeof (char *))) == NULL)
			goto error;

		dnode->ddn_ppath_count = 1;
		if ((dnode->ddn_ppath[0] = topo_mod_strdup(mod,
		    dnode->ddn_dpath)) == NULL)
			goto error;

		if ((dnode->ddn_target_port = topo_mod_zalloc(mod,
		    sizeof (char *))) == NULL)
			goto error;

		if ((dnode->ddn_attached_port = topo_mod_zalloc(mod,
		    sizeof (char *))) == NULL)
			goto error;

		if ((dnode->ddn_bridge_port = topo_mod_zalloc(mod,
		    sizeof (char *))) == NULL)
			goto error;

		/* There should be only one target port for a devinfo node. */
		if ((di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    SCSI_ADDR_PROP_TARGET_PORT, &s)) == 1) {
			if ((dnode->ddn_target_port[0] =
			    topo_mod_strdup(mod,
			    scsi_wwnstr_skip_ua_prefix(s))) ==
			    NULL)
				goto error;
		}

		if ((di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    SCSI_ADDR_PROP_ATTACHED_PORT, &s)) == 1) {
			/* There should be one attached port if any. */
			if ((dnode->ddn_attached_port[0] =
			    topo_mod_strdup(mod,
			    scsi_wwnstr_skip_ua_prefix(s))) ==
			    NULL)
				goto error;
		}

		if ((di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    SCSI_ADDR_PROP_BRIDGE_PORT, &s)) == 1) {
			/* There should be one bridge port if any. */
			if ((dnode->ddn_bridge_port[0] =
			    topo_mod_strdup(mod,
			    scsi_wwnstr_skip_ua_prefix(s))) ==
			    NULL)
				goto error;
		}

	} else {
		/* processing a scsi_vhci device. */
		if ((dnode->ddn_ppath = topo_mod_zalloc(mod,
		    pathcount * sizeof (char *))) == NULL)
			goto error;

		dnode->ddn_ppath_count = pathcount;

		if ((dnode->ddn_target_port = topo_mod_zalloc(mod,
		    pathcount * sizeof (char *))) == NULL)
			goto error;

		if ((dnode->ddn_attached_port = topo_mod_zalloc(mod,
		    pathcount * sizeof (char *))) == NULL)
			goto error;

		if ((dnode->ddn_bridge_port = topo_mod_zalloc(mod,
		    pathcount * sizeof (char *))) == NULL)
			goto error;

		pnode = NULL;
		pathcount = 0;
		while ((pnode = di_path_client_next_path(node,
		    pnode)) != NULL) {
			if ((path = di_path_devfs_path(pnode)) == NULL) {
				(void) topo_mod_seterrno(mod, errno);
				goto error;
			}

			dnode->ddn_ppath[pathcount] =
			    topo_mod_strdup(mod, path);
			di_devfs_path_free(path);
			if (dnode->ddn_ppath[pathcount] == NULL)
				goto error;

			if ((di_path_prop_lookup_strings(pnode,
			    SCSI_ADDR_PROP_TARGET_PORT, &s)) == 1) {
				if ((dnode->ddn_target_port[pathcount] =
				    topo_mod_strdup(mod,
				    scsi_wwnstr_skip_ua_prefix(s))) ==
				    NULL)
					goto error;
			}

			if ((di_path_prop_lookup_strings(pnode,
			    SCSI_ADDR_PROP_ATTACHED_PORT, &s)) == 1) {
				if ((dnode->ddn_attached_port[pathcount] =
				    topo_mod_strdup(mod,
				    scsi_wwnstr_skip_ua_prefix(s))) ==
				    NULL)
					goto error;
			}

			if ((di_path_prop_lookup_strings(pnode,
			    SCSI_ADDR_PROP_BRIDGE_PORT, &s)) == 1) {
				if ((dnode->ddn_bridge_port[pathcount] =
				    topo_mod_strdup(mod,
				    scsi_wwnstr_skip_ua_prefix(s))) ==
				    NULL)
					goto error;
			}

			pathcount++;
		}
	}

	/*
	 * Find the public /dev name for a disk by adding a minor name and using
	 * di_devlink interface for reverse translation (use devinfo path).
	 */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "inquiry-device-type",
	    &inq_dtype) > 0) {
		dnode->ddn_dtype = *inq_dtype;
		itype = (*inq_dtype) & DTYPE_MASK;
		if (itype == DTYPE_DIRECT) {
			mlen = strlen(dnode->ddn_dpath) + strlen(extn) + 1;
			if ((minorpath = topo_mod_alloc(mod, mlen)) == NULL)
				goto error;
			(void) snprintf(minorpath, mlen, "%s%s",
			    dnode->ddn_dpath, extn);
			cbp->dcb_dnode = dnode;
			(void) di_devlink_walk(cbp->dcb_devhdl, "^dsk/",
			    minorpath, DI_PRIMARY_LINK, cbp,
			    disk_devlink_callback);
			topo_mod_free(mod, minorpath, mlen);
			if (dnode->ddn_lpath == NULL) {
				topo_mod_dprintf(mod, "dev_di_node_add: "
				    "failed to determine logical path");
			}
		}
	} else {
		dnode->ddn_dtype = DTYPE_UNKNOWN;
	}

	/* cache various bits of optional information about the device. */
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_VENDOR_ID, &s) > 0) {
		if ((dnode->ddn_mfg = disk_trim_whitespace(mod, s)) == NULL)
			goto error;
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_PRODUCT_ID, &s) > 0) {
		if ((dnode->ddn_model = disk_trim_whitespace(mod, s)) == NULL)
			goto error;
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_REVISION_ID, &s) > 0) {
		if ((dnode->ddn_firm = disk_trim_whitespace(mod, s)) == NULL)
			goto error;
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_SERIAL_NO, &s) > 0) {
		if ((dnode->ddn_serial = disk_trim_whitespace(mod, s)) == NULL)
			goto error;
	}
	if (di_prop_lookup_int64(DDI_DEV_T_ANY, node,
	    "device-nblocks", &nblocksp) > 0) {
		nblocks = (uint64_t)*nblocksp;
		/*
		 * To save kernel memory, the driver may not define
		 * "device-dblksize" when its value is default DEV_BSIZE.
		 */
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "device-dblksize", &dblksizep) > 0)
			dblksize = (uint_t)*dblksizep;
		else
			dblksize = DEV_BSIZE;		/* default value */
		(void) snprintf(lentry, sizeof (lentry),
		    "%" PRIu64, nblocks * dblksize);
		if ((dnode->ddn_cap = topo_mod_strdup(mod, lentry)) == NULL)
			goto error;
	}

	topo_mod_dprintf(mod, "dev_di_node_add: "
	    "adding %s\n", devid ? dnode->ddn_devid : "NULL devid");
	topo_mod_dprintf(mod, "                  "
	    "       %s\n", dnode->ddn_dpath);
	for (i = 0; i < dnode->ddn_ppath_count; i++) {
		topo_mod_dprintf(mod, "                  "
		    "       %s\n", dnode->ddn_ppath[i]);
	}
	topo_list_append(cbp->dcb_list, dnode);
	return (0);

error:
	dev_di_node_free(mod, dnode);
	return (-1);
}

/* di_walk_node callback for disk_list_gather */
static int
dev_walk_di_nodes(di_node_t node, void *arg)
{
	char			*devidstr = NULL;
	char			*s;
	int			*val;

	/*
	 * If it's not a scsi_vhci client and doesn't have a target_port
	 * property and doesn't have a target property then it's not a storage
	 * device and we're not interested.
	 */
	if (di_path_client_next_path(node, NULL) == NULL &&
	    di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    SCSI_ADDR_PROP_TARGET_PORT, &s) <= 0 &&
	    di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    SCSI_ADDR_PROP_TARGET, &val) <= 0) {
		return (DI_WALK_CONTINUE);
	}
	(void) di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    DEVID_PROP_NAME, &devidstr);

	/* create/find the devid scsi topology node */
	(void) dev_di_node_add(node, devidstr, arg);

	return (DI_WALK_CONTINUE);
}

int
dev_list_gather(topo_mod_t *mod, topo_list_t *listp)
{
	di_node_t		devtree;
	di_devlink_handle_t	devhdl;
	disk_cbdata_t		dcb;

	if ((devtree = topo_mod_devinfo(mod)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "disk_list_gather: "
		    "topo_mod_devinfo() failed");
		return (-1);
	}

	if ((devhdl = di_devlink_init(NULL, 0)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "disk_list_gather: "
		    "di_devlink_init() failed");
		return (-1);
	}

	dcb.dcb_mod = mod;
	dcb.dcb_list = listp;
	dcb.dcb_devhdl = devhdl;

	/* walk the devinfo snapshot looking for disk nodes */
	(void) di_walk_node(devtree, DI_WALK_CLDFIRST, &dcb,
	    dev_walk_di_nodes);

	(void) di_devlink_fini(&devhdl);

	return (0);
}

void
dev_list_free(topo_mod_t *mod, topo_list_t *listp)
{
	dev_di_node_t	*dnode;

	while ((dnode = topo_list_next(listp)) != NULL) {
		/* order of delete/free is important */
		topo_list_delete(listp, dnode);
		dev_di_node_free(mod, dnode);
	}
}

/*
 * Query the current disk status. If successful, the disk status is returned
 * as an nvlist consisting of at least the following members:
 *
 *	protocol	string		Supported protocol (currently "scsi")
 *
 *	status		nvlist		Arbitrary protocol-specific information
 *					about the current state of the disk.
 *
 *	faults		nvlist		A list of supported faults. Each
 *					element of this list is a boolean value.
 *					An element's existence indicates that
 *					the drive supports detecting this fault,
 *					and the value indicates the current
 *					state of the fault.
 *
 *	<fault-name>	nvlist		For each fault named in 'faults', a
 *					nvlist describing protocol-specific
 *					attributes of the fault.
 *
 * This method relies on the libdiskstatus library to query this information.
 */
static int
disk_status(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers,
    nvlist_t *in_nvl, nvlist_t **out_nvl)
{
	disk_status_t	*dsp;
	char		*devpath, *fullpath;
	size_t		pathlen;
	nvlist_t	*status;
	int		err;

	*out_nvl = NULL;

	if (vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	/*
	 * If the caller specifies the "path" parameter, then this indicates
	 * that we should use this instead of deriving it from the topo node
	 * itself.
	 */
	if (nvlist_lookup_string(in_nvl, "path", &fullpath) == 0) {
		devpath = NULL;
	} else {
		/*
		 * Get the /devices path and attempt to open the disk status
		 * handle.
		 */
		if (topo_prop_get_string(nodep, TOPO_PGROUP_IO,
		    TOPO_IO_DEV_PATH, &devpath, &err) != 0)
			return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

		/*
		 * Note that sizeof(string) includes the terminating NULL byte
		 */
		pathlen = strlen(devpath) + sizeof ("/devices") +
		    sizeof (PHYS_EXTN) - 1;

		if ((fullpath = topo_mod_alloc(mod, pathlen)) == NULL)
			return (topo_mod_seterrno(mod, EMOD_NOMEM));

		(void) snprintf(fullpath, pathlen, "/devices%s%s", devpath,
		    PHYS_EXTN);

		topo_mod_strfree(mod, devpath);
	}

	if ((dsp = disk_status_open(fullpath, &err)) == NULL) {
		if (devpath)
			topo_mod_free(mod, fullpath, pathlen);
		return (topo_mod_seterrno(mod, err == EDS_NOMEM ?
		    EMOD_NOMEM : EMOD_METHOD_NOTSUP));
	}

	if (devpath)
		topo_mod_free(mod, fullpath, pathlen);

	if ((status = disk_status_get(dsp)) == NULL) {
		err = (disk_status_errno(dsp) == EDS_NOMEM ?
		    EMOD_NOMEM : EMOD_METHOD_NOTSUP);
		disk_status_close(dsp);
		return (topo_mod_seterrno(mod, err));
	}

	*out_nvl = status;
	disk_status_close(dsp);
	return (0);
}
