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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <devid.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/dkio.h>
#include <sys/scsi/scsi_types.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/libdiskstatus.h>
#include <sys/fm/protocol.h>
#include "disk.h"

static int disk_status(topo_mod_t *, tnode_t *, topo_version_t,
	nvlist_t *, nvlist_t **);

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

static int disk_enum(topo_mod_t *, tnode_t *, const char *,
	topo_instance_t, topo_instance_t, void *, void *);

static const topo_modops_t disk_ops =
	{ disk_enum, NULL };

const topo_modinfo_t disk_info =
	{DISK, FM_FMRI_SCHEME_HC, DISK_VERSION, &disk_ops};

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_pgroup_info_t disk_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
};

static const topo_pgroup_info_t storage_pgroup = {
	TOPO_STORAGE_PGROUP,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/*
 * Methods for disks.  This is used by the disk-transport module to
 * generate ereports based off SCSI disk status.
 */
static const topo_method_t disk_methods[] = {
	{ TOPO_METH_DISK_STATUS, TOPO_METH_DISK_STATUS_DESC,
	    TOPO_METH_DISK_STATUS_VERSION, TOPO_STABILITY_INTERNAL,
	    disk_status },
	{ NULL }
};
static di_devlink_handle_t	devlink_hdl = NULL;

/* disk node information */
typedef struct disk_di_node {
	topo_list_t	ddn_list;
	int		ddn_instance;
	char		*ddn_devid;
	di_node_t	ddn_node;
	char		*ddn_lpath;   /* logical path */
	char		*ddn_dpath;   /* device path */
}disk_di_node_t;

typedef struct disk_di_nodes {
	pthread_mutex_t disk_di_nodes_lock;
	topo_list_t disk_di_nodes_list;
}disk_di_nodes_t;

/* list of devices */
static disk_di_nodes_t disk_di_nodes;

/* given a device find it in the global device list */
static disk_di_node_t *
disk_di_node_match_device(char *device)
{
	disk_di_node_t		*dnode;

	(void) pthread_mutex_lock(&disk_di_nodes.disk_di_nodes_lock);
	for (dnode = topo_list_next(&(disk_di_nodes.disk_di_nodes_list));
	    dnode != NULL; dnode = topo_list_next(dnode)) {
		if (dnode->ddn_devid != NULL &&
		    strcmp(device,
		    dnode->ddn_dpath) == 0) {
			(void) pthread_mutex_unlock(
			    &disk_di_nodes.disk_di_nodes_lock);
			return (dnode);
		}
	}
	(void) pthread_mutex_unlock(&disk_di_nodes.disk_di_nodes_lock);
	return (NULL);
}

/* get the disk storage group information */
static void
disk_storage_info(topo_mod_t *mod, disk_di_node_t *dnode,
    char **model, char **manuf, char **serial, char **firm, char **cap)
{
	char		*entry;
	di_node_t	node = dnode->ddn_node;
	int64_t		*nblocksp;
	uint64_t	nblocks;
	int		*dblksizep;
	uint_t		dblksize;
	char		lentry[MAXPATHLEN];

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_VENDOR_ID, &entry) > 0) {
		*manuf = topo_mod_strdup(mod, entry);
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_PRODUCT_ID, &entry) > 0) {
		*model = topo_mod_strdup(mod, entry);
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_REVISION_ID, &entry) > 0) {
		*firm = topo_mod_strdup(mod, entry);
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    INQUIRY_SERIAL_NO, &entry) > 0) {
		*serial = topo_mod_strdup(mod, entry);
	}
	if (di_prop_lookup_int64(DDI_DEV_T_ANY, node,
	    "device-nblocks", &nblocksp) > 0) {
		nblocks = (uint64_t)*nblocksp;
		/*
		 * To save kernel memory, the driver may not
		 * define "device-dblksize" when its value is
		 * the default DEV_BSIZE value.
		 */
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "device-dblksize", &dblksizep) > 0)
			dblksize = (uint_t)*dblksizep;
		else
			dblksize = DEV_BSIZE;		/* default value */
		(void) snprintf(lentry, sizeof (lentry),
		    "%" PRIu64, nblocks * dblksize);
		*cap = topo_mod_strdup(mod, lentry);
	}
}

/* populate the protocol group properties */
static void
disk_set_proto_props(topo_mod_t *mod, tnode_t *dtn, int pinst)
{
	int		err;
	nvlist_t	*asru = NULL;
	char		label[32];
	char		*func = "disk_set_proto_props";
	nvlist_t	*fmri;
	disk_di_node_t	*dnode;

	/* set the asru */
	dnode = topo_node_getspecific(dtn);
	asru = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION,
	    dnode->ddn_dpath, dnode->ddn_devid);
	if (topo_node_asru_set(dtn, asru, 0, &err) != 0) {
		topo_mod_dprintf(mod,
		    "%s: topo_node_asru_set error %d\n",
		    func, err);
		nvlist_free(asru);
		(void) topo_mod_seterrno(mod, err);
		return;
	}
	nvlist_free(asru);

	(void) snprintf(label, sizeof (label), "HD_ID_%d", pinst);
	if (topo_node_label_set(dtn, label, &err) != 0) {
		topo_mod_dprintf(mod, "%s: label error %s\n", func,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return;
	}

	/* get the resource property  */
	if (topo_node_resource(dtn, &fmri, &err) != 0) {
		topo_mod_dprintf(mod,
		    "%s: topo_node_resource error: %s\n", func,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return;
	}

	/* set the child fru to the same as the resource */
	if (topo_node_fru_set(dtn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod,
		    "%s: topo_node_fru_set error: %s\n", func,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		nvlist_free(fmri);
		return;
	}
	nvlist_free(fmri);
}


/*
 * Set the properties of the disk node which include:
 *	group: protocol  properties: resource, asru, label, fru
 *	group: authority properties: product-id, chasis-id, server-id
 *	group: io	 properties: devfs-path
 *	group: storage   properties:
 *		- logical-disk, disk-model, disk-manufacturer, serial-number
 *		- firmware-revision, capacity-in-bytes
 */
static void
disk_set_props(tnode_t *dtn, tnode_t *parent, char *model, char *manuf,
    char *serial, char *firm, char *cap, int *err, topo_mod_t *mod)
{
	char	*device;
	char 	*ptr, *ptr1;
	int	inst = topo_node_instance(parent);
	disk_di_node_t	*dnode;

	dnode = topo_node_getspecific(dtn);

	/* set the protocol group properties */
	disk_set_proto_props(mod, dtn, inst);

	/* create/set the authority group */
	if (topo_pgroup_create(dtn, &disk_auth_pgroup, err) == 0) {
		(void) topo_prop_inherit(dtn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, err);
		(void) topo_prop_inherit(dtn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, err);
		(void) topo_prop_inherit(dtn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, err);
	}

	/* create/set the devfs-path in the io group */
	(void) topo_pgroup_create(dtn, &io_pgroup, err);

	if (topo_prop_get_string(parent, TOPO_BINDING_PGROUP,
	    TOPO_BINDING_OCCUPANT, &device, err) == 0) {
		(void) topo_prop_set_string(dtn, TOPO_PGROUP_IO,
		    TOPO_IO_DEV_PATH, TOPO_PROP_IMMUTABLE, device, err);

		topo_mod_strfree(mod, device);
	}

	/* create the storage group */
	(void) topo_pgroup_create(dtn, &storage_pgroup, err);

	/* set the storage group properties */
	ptr = strrchr(dnode->ddn_lpath, '/');
	ptr1 = strchr(ptr, 's');
	if (ptr1)
		*ptr1 = '\0';
	(void) topo_prop_set_string(dtn, TOPO_STORAGE_PGROUP,
	    TOPO_STORAGE_LOGICAL_DISK_NAME, TOPO_PROP_IMMUTABLE,
	    ptr+1, err);
	if (ptr1)
		*ptr1 = 's';


	/* populate the storage group properties */
	if (model) {
		(void) topo_prop_set_string(dtn, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_MODEL, TOPO_PROP_IMMUTABLE, model, err);
	}
	if (manuf) {
		(void) topo_prop_set_string(dtn, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_MANUFACTURER, TOPO_PROP_IMMUTABLE, manuf,
		    err);
	}
	if (serial) {
		(void) topo_prop_set_string(dtn, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_SERIAL_NUM, TOPO_PROP_IMMUTABLE, serial, err);
	}
	if (firm) {
		(void) topo_prop_set_string(dtn, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE, firm, err);
	}
	if (cap) {
		(void) topo_prop_set_string(dtn, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_CAPACITY, TOPO_PROP_IMMUTABLE, cap, err);
	}
}

/* create the disk topo node */
/*ARGSUSED*/
static tnode_t *
disk_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, char *model, char *manuf,
    char *serial, char *firm, char *cap, void *priv)
{
	int		err, len = 0;
	nvlist_t	*fmri;
	tnode_t		*dtn;
	char 		*mm = NULL;
	char		*s;
	nvlist_t	*auth = topo_mod_auth(mod, parent);

	if ((s = strchr(model, ' ')) != NULL) {
		*s = '-';
	}
	len = strlen(manuf) + strlen(model) + 2;
	if ((mm = topo_mod_alloc(mod, len)) != NULL)
		(void) snprintf(mm, len, "%s-%s", manuf, model);
	else
		mm = model;

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, mm, firm, serial);

	nvlist_free(auth);

	if (mm != model)
		topo_mod_free(mod, mm, len);
	else if (*s != NULL)
		*s = ' ';

	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind: %s.\n",
		    name, topo_mod_errmsg(mod));
		return (NULL);
	}

	if ((dtn = topo_node_bind(mod, parent, name, i, fmri)) == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	topo_node_setspecific(dtn, priv);

	/* add the properties of the disk */
	disk_set_props(dtn, parent, model, manuf, serial, firm, cap,
	    &err, mod);

	return (dtn);
}

/*ARGSUSED*/
static tnode_t *
disk_declare(tnode_t *parent, const char *name, topo_instance_t i,
    void *priv, topo_mod_t *mod)
{
	tnode_t	*dtn;
	int	err;
	char	*func = "disk_declare";
	char	*model = NULL, *manuf = NULL, *serial = NULL;
	char	*cap = NULL, *firm = NULL;
	disk_di_node_t		*dnode  = (disk_di_node_t *)priv;
	nvlist_t		*fmri;

	disk_storage_info(mod, dnode,
	    &model, &manuf, &serial, &firm, &cap);

	/* create the node */
	dtn = disk_tnode_create(mod, parent,
	    name, i, model, manuf, serial, firm, cap, priv);

	topo_mod_strfree(mod, model);
	topo_mod_strfree(mod, manuf);
	topo_mod_strfree(mod, serial);
	topo_mod_strfree(mod, firm);
	topo_mod_strfree(mod, cap);

	if (dtn == NULL) {
		return (NULL);
	}

	/* set the parent fru */
	if (topo_node_resource(parent, &fmri, &err) != 0) {
		topo_mod_dprintf(mod,
		    "%s: topo_node_resource error: %s\n", func,
		    topo_strerror(err));
		topo_node_unbind(dtn);
		return (NULL);
	}
	if (topo_node_fru_set(parent, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod, "%s topo_node_fru error: %s\n",
		    func, topo_strerror(err));
		nvlist_free(fmri);
		topo_node_unbind(dtn);
		return (NULL);
	}

	if (topo_method_register(mod, dtn, disk_methods) != 0) {
		topo_mod_dprintf(mod,
		    "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		topo_node_unbind(dtn);
		return (NULL);
	}

	nvlist_free(fmri);

	return (dtn);
}

/*ARGSUSED*/
static int
disk_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	tnode_t		*diskn;
	char		*device;
	int		err;
	disk_di_node_t	*dnode;

	if (strcmp(name, DISK) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    DISK);
		return (-1);
	}

	if (topo_prop_get_string(rnode, TOPO_BINDING_PGROUP,
	    TOPO_BINDING_OCCUPANT, &device, &err) != 0)
		return (-1);

	if ((dnode = disk_di_node_match_device(device)) == NULL) {
		topo_mod_dprintf(mod,
		    "No occupant found for bay=%d.\n",
		    topo_node_instance(rnode));
		topo_mod_strfree(mod, device);
		return (-1);
	}

	diskn = disk_declare(rnode, name, 0, dnode, mod);
	if (diskn == NULL) {
		topo_mod_dprintf(mod, "Enumeration of %s failed: %s\n",
		    DISK, topo_strerror(topo_mod_errno(mod)));
		topo_mod_strfree(mod, device);
		return (-1); /* mod_errno already set */
	}
	topo_mod_strfree(mod, device);
	return (0);
}

/*
 * Query the current disk status.  If successful, the disk status is returned as
 * an nvlist consisting of at least the following members:
 *
 *	protocol	string		Supported protocol (currently "scsi")
 *
 *	status		nvlist		Arbitrary protocol-specific information
 *					about the current state of the disk.
 *
 *	faults		nvlist		A list of supported faults.  Each
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
	disk_status_t *dsp;
	char *devpath, *fullpath;
	size_t pathlen;
	int err;
	nvlist_t *status;
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

/* di_devlink callback for disk_drvinst2devpath */
static int
disk_drvinst2devpath_devlink_callback(di_devlink_t dl, void *arg)
{
	char	**devpathp = (char **)arg;
	char	*devpath = (char *)di_devlink_path(dl);

	*devpathp = strdup(devpath);
	return (DI_WALK_TERMINATE);
}

static disk_di_node_t *
disk_di_node_add(int *instancep, char *devid, di_node_t node, topo_mod_t *mod)
{
	int		mlen;
	char		*devpath, *minorpath;
	char		*extn = ":a";
	disk_di_node_t		*dnode;

	(void) pthread_mutex_lock(&(disk_di_nodes.disk_di_nodes_lock));
	for (dnode = topo_list_next(&(disk_di_nodes.disk_di_nodes_list));
	    dnode != NULL; dnode = topo_list_next(dnode)) {
		if (strcmp(dnode->ddn_devid, devid) == 0) {
			topo_mod_dprintf(mod,
			    "disk_node_add - already there %s\n", devid);
			(void) pthread_mutex_unlock(
			    &disk_di_nodes.disk_di_nodes_lock);
			return (dnode);	/* return existing node */
		}
	}

	if ((dnode = topo_mod_alloc(mod, sizeof (disk_di_node_t))) == NULL) {
		topo_mod_dprintf(mod,
		    "disk_node_add - topo_mod_alloc failed\n");
		(void) pthread_mutex_unlock(&disk_di_nodes.disk_di_nodes_lock);
		return (NULL);	/* return existing node */
	}

	dnode->ddn_devid = strdup(devid);
	dnode->ddn_instance = *instancep;
	dnode->ddn_node = node;
	dnode->ddn_dpath  = di_devfs_path(node);

	mlen = strlen(dnode->ddn_dpath) + strlen(extn) + 1;
	minorpath = topo_mod_alloc(mod, mlen);
	(void) snprintf(minorpath, mlen, "%s%s", dnode->ddn_dpath,
	    extn);
	/* walk devlink looking for node that maps to /device path */
	devpath = NULL;
	(void) di_devlink_walk(devlink_hdl, "^dsk/",
	    minorpath, DI_PRIMARY_LINK,
	    (void *)&devpath, disk_drvinst2devpath_devlink_callback);
	topo_mod_free(mod, minorpath, mlen);
	dnode->ddn_lpath = devpath;

	topo_list_append(&disk_di_nodes.disk_di_nodes_list, (void *)dnode);
	(void) pthread_mutex_unlock(&disk_di_nodes.disk_di_nodes_lock);

	topo_mod_dprintf(mod,
	    "disk_node_add - adding %s inst: %d\n",
	    dnode->ddn_devid, *instancep);
	*instancep = (*instancep) + 1;
	return (dnode);
}

/*ARGSUSED*/
static int
disk_walk_di_nodes(di_node_t node, void *arg)
{
	ddi_devid_t	devid = NULL;
	char		*devidstr;
	static int	instance_devid = 0;
	topo_mod_t	*mod = (topo_mod_t *)arg;

	/* only interested in nodes that have devids */
	devid = (ddi_devid_t)di_devid(node);
	if (devid == NULL)
		return (DI_WALK_CONTINUE);

	/* ... with a string representation of the devid */
	devidstr = devid_str_encode(devid, NULL);
	if (devidstr == NULL)
		return (DI_WALK_CONTINUE);

	/* create/find the devid scsi topology node */
	(void) disk_di_node_add(&instance_devid, devidstr, node, mod);
	devid_str_free(devidstr);
	return (DI_WALK_CONTINUE);
}

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	di_node_t	devtree;

	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPODISKDEBUG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing %s enumerator\n", DISK);

	if (topo_mod_register(mod, &disk_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "%s registration failed: %s\n",
		    DISK, topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	(void) pthread_mutex_init(&disk_di_nodes.disk_di_nodes_lock, NULL);
	disk_di_nodes.disk_di_nodes_list.l_next = NULL;
	disk_di_nodes.disk_di_nodes_list.l_prev = NULL;

	devtree = di_init("/", DINFOCACHE);
	/* we don't get all the nodes with topo_mod_devinfo */
	if (devtree == NULL) {
		topo_mod_unregister(mod);
		(void) pthread_mutex_destroy(&disk_di_nodes.disk_di_nodes_lock);
		topo_mod_dprintf(mod, "topo_mod_devinfo init failed.");
		return (-1);
	}
	/* walk the tree to get the devids */
	devlink_hdl = di_devlink_init(NULL, 0);
	if (devlink_hdl == DI_NODE_NIL) {
		topo_mod_unregister(mod);
		(void) pthread_mutex_destroy(&disk_di_nodes.disk_di_nodes_lock);
		topo_mod_dprintf(mod, "di_devlink init failed.");
		return (-1);
	}
	(void) di_walk_node(devtree, DI_WALK_CLDFIRST, mod,
	    disk_walk_di_nodes);

	if (devlink_hdl != NULL)
		(void) di_devlink_fini(&devlink_hdl);

	topo_mod_dprintf(mod, "%s enumerator initialized\n", DISK);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	disk_di_node_t	*dnode;

	(void) pthread_mutex_lock(&disk_di_nodes.disk_di_nodes_lock);
	while ((dnode = topo_list_next(&(disk_di_nodes.disk_di_nodes_list)))
	    != NULL) {
		free(dnode->ddn_lpath);
		free(dnode->ddn_dpath);
		free(dnode->ddn_devid);
		topo_list_delete(&(disk_di_nodes.disk_di_nodes_list),
		    (void *)dnode);
		topo_mod_free(mod, dnode, sizeof (disk_di_node_t));
	}
	(void) pthread_mutex_unlock(&disk_di_nodes.disk_di_nodes_lock);
	(void) pthread_mutex_destroy(&disk_di_nodes.disk_di_nodes_lock);
	topo_mod_unregister(mod);
}
