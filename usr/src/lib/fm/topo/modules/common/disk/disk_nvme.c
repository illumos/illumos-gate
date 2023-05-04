/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * This file drives topo node enumeration of NVMe controllers.  A single "nvme"
 * node is enumerated for each NVMe controller.   Child "disk" nodes are then
 * enumerated for each configured NVMe namespace.
 *
 * nvme nodes are expected to be enumerated under either a "bay" node (for U.2
 * devices) or a "slot" node (for M.2 devices) or a "pciexfn" node (for AIC
 * devices).
 *
 * Enumeration of NVMe controllers on PCIe add-in cards is automatically driven
 * by the pcibus topo module.
 *
 * In order to allow for associating a given NVMe controller with a physical
 * location, enumeration of U.2 and M.2 devices should be driven by a
 * platform-specific topo map which statically sets the following two
 * properties on the parent "bay" or "slot" node:
 *
 * propgroup        property        description
 * ---------        --------        ------------
 * binding          driver          "nvme"
 * binding          parent-device   devpath of parent PCIe device
 *
 * for example:
 *
 * <propgroup name="binding" version="1" name-stability="Private"
 *   data-stability="Private">
 *     <propval name="driver" type="string" value="nvme"/>
 *     <propval name="parent-device" type="string"
 *       value="/pci@0,0/pci8086,6f09@3,1"/>
 * </propgroup>
 * <dependents grouping="children">
 *     <range name="nvme" min="0" max="0">
 *         <enum-method name="disk" version="1"/>
 *     </range>
 * </dependents>
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

#include <sys/fm/protocol.h>
#include <fm/topo_hc.h>
#include <fm/topo_mod.h>

#include <sys/dkio.h>
#include <sys/scsi/generic/inquiry.h>

#include <sys/nvme.h>
#include "disk.h"
#include "disk_drivers.h"

typedef struct nvme_enum_info {
	topo_mod_t		*nei_mod;
	di_node_t		nei_dinode;
	nvme_identify_ctrl_t	*nei_idctl;
	nvme_version_t		nei_vers;
	tnode_t			*nei_parent;
	tnode_t			*nei_nvme;
	nvlist_t		*nei_nvme_fmri;
	const char		*nei_nvme_path;
	int			nei_fd;
} nvme_enum_info_t;

typedef struct devlink_arg {
	topo_mod_t		*dla_mod;
	char			*dla_logical_disk;
	uint_t			dla_strsz;
} devlink_arg_t;

static int
devlink_cb(di_devlink_t dl, void *arg)
{
	devlink_arg_t *dlarg = (devlink_arg_t *)arg;
	topo_mod_t *mod = dlarg->dla_mod;
	const char *devpath;
	char *slice, *ctds;

	if ((devpath = di_devlink_path(dl)) == NULL ||
	    (dlarg->dla_logical_disk = topo_mod_strdup(mod, devpath)) ==
	    NULL) {
		return (DI_WALK_TERMINATE);
	}

	/*
	 * We need to keep track of the original string size before we
	 * truncate it with a NUL, so that we can free the right number of
	 * bytes when we're done, otherwise libumem will complain.
	 */
	dlarg->dla_strsz = strlen(dlarg->dla_logical_disk) + 1;

	/* trim the slice off the public name */
	if (((ctds = strrchr(dlarg->dla_logical_disk, '/')) != NULL) &&
	    ((slice = strchr(ctds, 's')) != NULL))
		*slice = '\0';

	return (DI_WALK_TERMINATE);
}

static char *
get_logical_disk(topo_mod_t *mod, const char *devpath, uint_t *bufsz)
{
	di_devlink_handle_t devhdl;
	devlink_arg_t dlarg = { 0 };
	char *minorpath = NULL;

	if (asprintf(&minorpath, "%s:a", devpath) < 0) {
		return (NULL);
	}

	if ((devhdl = di_devlink_init(NULL, 0)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "%s: di_devlink_init failed", __func__);
		free(minorpath);
		return (NULL);
	}

	dlarg.dla_mod = mod;

	(void) di_devlink_walk(devhdl, "^dsk/", minorpath, DI_PRIMARY_LINK,
	    &dlarg, devlink_cb);

	(void) di_devlink_fini(&devhdl);
	free(minorpath);

	*bufsz = dlarg.dla_strsz;
	return (dlarg.dla_logical_disk);
}

static int
make_disk_node(nvme_enum_info_t *nvme_info, di_node_t dinode,
    topo_instance_t inst)
{
	topo_mod_t *mod = nvme_info->nei_mod;
	nvlist_t *auth = NULL, *fmri = NULL;
	tnode_t *disk;
	char *rev = NULL, *model = NULL, *serial = NULL, *path;
	char *logical_disk = NULL, *devid, *manuf, *ctd = NULL;
	char *cap_bytes_str = NULL, full_path[MAXPATHLEN + 1];
	char *pname = topo_node_name(nvme_info->nei_parent);
	topo_instance_t pinst = topo_node_instance(nvme_info->nei_parent);
	const char **ppaths = NULL;
	struct dk_minfo minfo;
	uint64_t cap_bytes;
	uint_t bufsz;
	int fd = -1, err, ret = -1, r;

	if ((path = di_devfs_path(dinode)) == NULL) {
		topo_mod_dprintf(mod, "%s: failed to get dev path", __func__);
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		return (ret);
	}

	topo_mod_dprintf(mod, "%s: found nvme namespace: %s", __func__, path);

	/*
	 * Issue the DKIOCGMEDIAINFO ioctl to get the capacity
	 */
	(void) snprintf(full_path, MAXPATHLEN, "/devices%s%s", path,
	    PHYS_EXTN);
	if ((fd = open(full_path, O_RDWR)) < 0 ||
	    ioctl(fd, DKIOCGMEDIAINFO, &minfo) < 0) {
		topo_mod_dprintf(mod, "failed to get blkdev capacity (%s)",
		    strerror(errno));
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	cap_bytes = minfo.dki_lbsize * minfo.dki_capacity;

	if (asprintf(&cap_bytes_str, "%" PRIu64, cap_bytes) < 0) {
		topo_mod_dprintf(mod, "%s: failed to alloc string", __func__);
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto error;
	}

	/*
	 * Gather the FRU identity information from the devinfo properties
	 */
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, dinode, DEVID_PROP_NAME,
	    &devid) == -1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, dinode, INQUIRY_VENDOR_ID,
	    &manuf) == -1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, dinode, INQUIRY_PRODUCT_ID,
	    &model) == -1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, dinode, INQUIRY_REVISION_ID,
	    &rev) == -1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, dinode, INQUIRY_SERIAL_NO,
	    &serial) == -1) {
		topo_mod_dprintf(mod, "%s: failed to lookup devinfo props on "
		    "%s", __func__, path);
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	model = topo_mod_clean_str(mod, model);
	rev = topo_mod_clean_str(mod, rev);
	serial = topo_mod_clean_str(mod, serial);

	/*
	 * Lookup the /dev/dsk/c#t#d# disk device name from the blkdev path
	 */
	if ((logical_disk = get_logical_disk(mod, path, &bufsz)) == NULL) {
		topo_mod_dprintf(mod, "failed to find logical disk");
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	/*
	 * If we were able to look up the logical disk path for this namespace
	 * then set ctd to be that pathname, minus the "/dev/dsk/" portion.
	 */
	if ((ctd = strrchr(logical_disk, '/')) !=  NULL) {
		ctd = ctd + 1;
	} else {
		topo_mod_dprintf(mod, "malformed logical disk path: %s",
		    logical_disk);
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	/*
	 * Build the FMRI and then bind the disk node to the parent nvme node.
	 */
	auth = topo_mod_auth(mod, nvme_info->nei_nvme);
	fmri = topo_mod_hcfmri(mod, nvme_info->nei_nvme, FM_HC_SCHEME_VERSION,
	    DISK, inst, NULL, auth, model, rev, serial);

	if (fmri == NULL) {
		/* errno set */
		topo_mod_dprintf(mod, "%s: hcfmri failed for %s=%" PRIu64
		    "/%s=0/%s=%" PRIu64, __func__, pname, pinst, NVME, DISK,
		    inst);
		goto error;
	}
	if ((disk = topo_node_bind(mod, nvme_info->nei_nvme, DISK, inst,
	    fmri)) == NULL) {
		/* errno set */
		topo_mod_dprintf(mod, "%s: bind failed for %s=%" PRIu64
		    "/%s=0/%s=%" PRIu64, __func__, pname, pinst, NVME, DISK,
		    inst);
		goto error;
	}

	/* Create authority and system propgroups */
	topo_pgroup_hcset(disk, auth);

	/*
	 * As the "disk" in this case is simply a logical construct
	 * representing an NVMe namespace, we inherit the FRU from the parent
	 * node.
	 */
	if (topo_node_fru_set(disk, NULL, 0, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to set FRU: %s", __func__,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	if ((ppaths = topo_mod_zalloc(mod, sizeof (char *))) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto error;
	}
	ppaths[0] = path;

	/*
	 * Create the "storage" and "io" property groups and then fill them
	 * with the standard set of properties for "disk" nodes.
	 */
	if (topo_pgroup_create(disk, &io_pgroup, &err) != 0 ||
	    topo_pgroup_create(disk, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to create propgroups: %s",
		    __func__, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	r = topo_prop_set_string(disk, TOPO_PGROUP_IO, TOPO_IO_DEV_PATH,
	    TOPO_PROP_IMMUTABLE, path, &err);

	r += topo_prop_set_string_array(disk, TOPO_PGROUP_IO,
	    TOPO_IO_PHYS_PATH, TOPO_PROP_IMMUTABLE, ppaths, 1, &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_IO, TOPO_IO_DEVID,
	    TOPO_PROP_IMMUTABLE, devid, &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MANUFACTURER, TOPO_PROP_IMMUTABLE, manuf, &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_CAPACITY, TOPO_PROP_IMMUTABLE, cap_bytes_str,
	    &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_SERIAL_NUM, TOPO_PROP_IMMUTABLE, serial, &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MODEL, TOPO_PROP_IMMUTABLE, model, &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE, rev, &err);

	r += topo_prop_set_string(disk, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_LOGICAL_DISK_NAME, TOPO_PROP_IMMUTABLE, ctd, &err);

	if (r != 0) {
		topo_mod_dprintf(mod, "%s: failed to create properties: %s",
		    __func__, topo_strerror(err));
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	ret = 0;

error:
	free(cap_bytes_str);
	if (fd > 0)
		(void) close(fd);
	if (ppaths != NULL)
		topo_mod_free(mod, ppaths, sizeof (char *));
	di_devfs_path_free(path);
	nvlist_free(auth);
	nvlist_free(fmri);
	topo_mod_strfree(mod, rev);
	topo_mod_strfree(mod, model);
	topo_mod_strfree(mod, serial);
	topo_mod_free(mod, logical_disk, bufsz);
	return (ret);
}

static const topo_pgroup_info_t nvme_pgroup = {
	TOPO_PGROUP_NVME,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};


static int
make_nvme_node(nvme_enum_info_t *nvme_info)
{
	topo_mod_t *mod = nvme_info->nei_mod;
	nvlist_t *auth = NULL, *fmri = NULL, *fru;
	tnode_t *nvme;
	char raw_rev[NVME_FWVER_SZ + 1], raw_model[NVME_MODEL_SZ + 1];
	char raw_serial[NVME_SERIAL_SZ + 1];
	char *rev = NULL, *model = NULL, *serial = NULL, *vers = NULL;
	char *pname = topo_node_name(nvme_info->nei_parent);
	char *label = NULL;
	topo_instance_t pinst = topo_node_instance(nvme_info->nei_parent);
	int err = 0, ret = -1;
	di_node_t cn;
	uint_t i;

	/*
	 * The raw strings returned by the IDENTIFY CONTROLLER command are
	 * not NUL-terminated, so we fix that up.
	 */
	(void) strncpy(raw_rev, nvme_info->nei_idctl->id_fwrev, NVME_FWVER_SZ);
	raw_rev[NVME_FWVER_SZ] = '\0';
	(void) strncpy(raw_model, nvme_info->nei_idctl->id_model,
	    NVME_MODEL_SZ);
	raw_model[NVME_MODEL_SZ] = '\0';
	(void) strncpy(raw_serial, nvme_info->nei_idctl->id_serial,
	    NVME_SERIAL_SZ);
	raw_serial[NVME_SERIAL_SZ] = '\0';

	/*
	 * Next we pass the strings through a function that sanitizes them of
	 * any characters that can't be used in an FMRI string.
	 */
	rev = topo_mod_clean_str(mod, raw_rev);
	model = topo_mod_clean_str(mod, raw_model);
	serial = topo_mod_clean_str(mod, raw_serial);

	auth = topo_mod_auth(mod, nvme_info->nei_parent);
	fmri = topo_mod_hcfmri(mod, nvme_info->nei_parent, FM_HC_SCHEME_VERSION,
	    NVME, 0, NULL, auth, model, rev, serial);

	if (fmri == NULL) {
		/* errno set */
		topo_mod_dprintf(mod, "%s: hcfmri failed for %s=%" PRIu64
		    "/%s=0", __func__, pname, pinst, NVME);
		goto error;
	}

	/*
	 * If our parent is a pciexfn node, then we need to create a nvme range
	 * underneath it to hold the nvme heirarchy.  For other cases, where
	 * enumeration is being driven by a topo map file, this range will have
	 * already been statically defined in the XML.
	 */
	if (strcmp(pname, PCIEX_FUNCTION) == 0) {
		if (topo_node_range_create(mod, nvme_info->nei_parent, NVME, 0,
		    0) < 0) {
			/* errno set */
			topo_mod_dprintf(mod, "%s: error creating %s range",
			    __func__, NVME);
			goto error;
		}
	}

	/*
	 * Create a new topo node to represent the NVMe controller and bind it
	 * to the parent node.
	 */
	if ((nvme = topo_node_bind(mod, nvme_info->nei_parent, NVME, 0,
	    fmri)) == NULL) {
		/* errno set */
		topo_mod_dprintf(mod, "%s: bind failed for %s=%" PRIu64
		    "/%s=0", __func__, pname, pinst, NVME);
		goto error;
	}
	nvme_info->nei_nvme = nvme;
	nvme_info->nei_nvme_fmri = fmri;

	/*
	 * If our parent node is a "pciexfn" node then this is a NVMe device on
	 * a PCIe AIC, so we inherit our parent's FRU.  Otherwise, we set the
	 * FRU to ourself.
	 */
	if (strcmp(topo_node_name(nvme_info->nei_parent), PCIEX_FUNCTION) == 0)
		fru = NULL;
	else
		fru = fmri;

	if (topo_node_fru_set(nvme, fru, 0, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to set FRU: %s", __func__,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	/*
	 * Clone the label from our parent node.  We can't inherit the property
	 * because the label prop is mutable on bay nodes and only immutable
	 * properties can be inherited.
	 */
	if ((topo_node_label(nvme_info->nei_parent, &label, &err) != 0 &&
	    err != ETOPO_PROP_NOENT) ||
	    topo_node_label_set(nvme, label, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to set label: %s",
		    __func__, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	if (topo_pgroup_create(nvme, &nvme_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to create %s pgroup: %s",
		    __func__, TOPO_PGROUP_NVME, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	if (asprintf(&vers, "%u.%u", nvme_info->nei_vers.v_major,
	    nvme_info->nei_vers.v_minor) < 0) {
		topo_mod_dprintf(mod, "%s: failed to alloc string", __func__);
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto error;
	}
	if (topo_prop_set_string(nvme, TOPO_PGROUP_NVME, TOPO_PROP_NVME_VER,
	    TOPO_PROP_IMMUTABLE, vers, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to set %s/%s property",
		    __func__, TOPO_PGROUP_NVME, TOPO_PROP_NVME_VER);
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	if (topo_pgroup_create(nvme, &io_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to create %s pgroup: %s",
		    __func__, TOPO_PGROUP_IO, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}
	if (topo_prop_set_string(nvme, TOPO_PGROUP_IO, TOPO_IO_DEV_PATH,
	    TOPO_PROP_IMMUTABLE, nvme_info->nei_nvme_path, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to set %s/%s property",
		    __func__, TOPO_PGROUP_IO, TOPO_IO_DEV_PATH);
		(void) topo_mod_seterrno(mod, err);
		goto error;
	}

	/*
	 * Create a child disk node for each namespace.
	 */
	if (topo_node_range_create(mod, nvme, DISK, 0,
	    (nvme_info->nei_idctl->id_nn - 1)) < 0) {
		/* errno set */
		topo_mod_dprintf(mod, "%s: error creating %s range", __func__,
		    DISK);
		goto error;
	}

	for (i = 0, cn = di_child_node(nvme_info->nei_dinode);
	    cn != DI_NODE_NIL;
	    i++, cn = di_sibling_node(cn)) {

		if (make_disk_node(nvme_info, cn, i) != 0) {
			char *path = di_devfs_path(cn);
			/*
			 * We note the failure, but attempt to forge ahead and
			 * enumerate any other namespaces.
			 */
			topo_mod_dprintf(mod, "%s: make_disk_node() failed "
			    "for %s\n", __func__,
			    path ? path : "unknown path");
			di_devfs_path_free(path);
		}
	}
	ret = 0;

error:
	free(vers);
	nvlist_free(auth);
	nvlist_free(fmri);
	topo_mod_strfree(mod, rev);
	topo_mod_strfree(mod, model);
	topo_mod_strfree(mod, serial);
	topo_mod_strfree(mod, label);
	return (ret);
}

struct diwalk_arg {
	topo_mod_t	*diwk_mod;
	tnode_t		*diwk_parent;
};

/*
 * This function gathers identity information from the NVMe controller and
 * stores it in a struct.  This struct is passed to make_nvme_node(), which
 * does the actual topo node creation.
 */
static int
discover_nvme_ctl(di_node_t node, di_minor_t minor, void *arg)
{
	struct diwalk_arg *wkarg = arg;
	topo_mod_t *mod = wkarg->diwk_mod;
	char *path = NULL, *devctl = NULL;
	nvme_ioctl_t nioc = { 0 };
	nvme_identify_ctrl_t *idctl = NULL;
	nvme_enum_info_t nvme_info = { 0 };
	int fd = -1, ret = DI_WALK_TERMINATE;

	if ((path = di_devfs_minor_path(minor)) == NULL) {
		topo_mod_dprintf(mod, "failed to get minor path");
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		return (ret);
	}

	topo_mod_dprintf(mod, "%s=%" PRIu64 ": found nvme controller: %s",
	    topo_node_name(wkarg->diwk_parent),
	    topo_node_instance(wkarg->diwk_parent), path);

	if (asprintf(&devctl, "/devices%s", path) < 0) {
		topo_mod_dprintf(mod, "failed to alloc string");
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto error;
	}

	if ((fd = open(devctl, O_RDWR)) < 0) {
		topo_mod_dprintf(mod, "failed to open %s", devctl);
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}
	if ((idctl = topo_mod_zalloc(mod, NVME_IDENTIFY_BUFSIZE)) == NULL) {
		topo_mod_dprintf(mod, "zalloc failed");
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto error;
	}
	nioc.n_len = NVME_IDENTIFY_BUFSIZE;
	nioc.n_buf = (uintptr_t)idctl;
	nioc.n_arg = NVME_IDENTIFY_CTRL;

	if (ioctl(fd, NVME_IOC_IDENTIFY, &nioc) != 0) {
		topo_mod_dprintf(mod, "NVME_IOC_IDENTIFY ioctl "
		    "failed: %s", strerror(errno));
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	nioc.n_len = sizeof (nvme_version_t);
	nioc.n_buf = (uintptr_t)&nvme_info.nei_vers;
	nioc.n_arg = 0;

	if (ioctl(fd, NVME_IOC_VERSION, &nioc) != 0) {
		topo_mod_dprintf(mod, "NVME_IOC_VERSION ioctl failed: %s",
		    strerror(errno));
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto error;
	}

	nvme_info.nei_mod = mod;
	nvme_info.nei_nvme_path = path;
	nvme_info.nei_dinode = node;
	nvme_info.nei_idctl = idctl;
	nvme_info.nei_parent = wkarg->diwk_parent;
	nvme_info.nei_fd = fd;

	if (make_nvme_node(&nvme_info) != 0) {
		/* errno set */
		goto error;
	}

	ret = DI_WALK_CONTINUE;

error:
	if (fd > 0)
		(void) close(fd);
	di_devfs_path_free(path);
	free(devctl);
	if (idctl != NULL)
		topo_mod_free(mod, idctl, NVME_IDENTIFY_BUFSIZE);
	return (ret);
}

int
disk_nvme_enum_disk(topo_mod_t *mod, tnode_t *pnode)
{
	char *parent = NULL;
	int err;
	di_node_t devtree;
	di_node_t dnode;
	struct diwalk_arg wkarg = { 0 };
	int ret = -1;

	/*
	 * Lookup a property containing the devfs path of the parent PCIe
	 * device of the NVMe device we're attempting to enumerate.  This
	 * property is hard-coded in per-platform topo XML maps that are
	 * delivered with the OS.  This hard-coded path allows topo to map a
	 * given NVMe controller to a physical location (bay or slot) on the
	 * platform, when generating the topo snapshot.
	 */
	if (topo_prop_get_string(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_PARENT_DEV, &parent, &err) != 0) {
		topo_mod_dprintf(mod, "parent node was missing nvme binding "
		    "properties\n");
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}
	if ((devtree = topo_mod_devinfo(mod)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "failed to get devinfo snapshot");
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	/*
	 * Walk the devinfo tree looking NVMe devices. For each NVMe device,
	 * check if the devfs path of the parent matches the one specified in
	 * TOPO_BINDING_PARENT_DEV.
	 */
	wkarg.diwk_mod = mod;
	wkarg.diwk_parent = pnode;
	dnode = di_drv_first_node(NVME_DRV, devtree);
	while (dnode != DI_NODE_NIL) {
		char *path;

		if ((path = di_devfs_path(di_parent_node(dnode))) == NULL) {
			topo_mod_dprintf(mod, "failed to get dev path");
			(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
			goto out;
		}
		if (strcmp(parent, path) == 0) {
			if (di_walk_minor(dnode, DDI_NT_NVME_NEXUS, 0,
			    &wkarg, discover_nvme_ctl) < 0) {
				di_devfs_path_free(path);
				goto out;
			}
		}
		di_devfs_path_free(path);
		dnode = di_drv_next_node(dnode);
	}
	ret = 0;

out:
	topo_mod_strfree(mod, parent);
	return (ret);
}
