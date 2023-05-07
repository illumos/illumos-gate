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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This file drives topo node enumeration of NVMe controllers.  A single "nvme"
 * node is enumerated for each NVMe controller.   Child "disk" nodes are then
 * enumerated for each active or attached NVMe namespace.
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
#include <stdbool.h>

#include <sys/fm/protocol.h>
#include <fm/topo_hc.h>
#include <fm/topo_mod.h>
#include <topo_ufm.h>

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

static bool
disk_nvme_make_ns_serial(topo_mod_t *mod, const nvme_identify_nsid_t *id,
    uint32_t nsid, char *buf, size_t buflen)
{
	uint8_t zero_guid[16] = { 0 };
	int ret;

	if (bcmp(zero_guid, id->id_nguid, sizeof (id->id_nguid)) != 0) {
		ret = snprintf(buf, buflen, "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X"
		    "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",
		    id->id_nguid[0], id->id_nguid[1], id->id_nguid[2],
		    id->id_nguid[3], id->id_nguid[4], id->id_nguid[5],
		    id->id_nguid[6], id->id_nguid[7], id->id_nguid[8],
		    id->id_nguid[9], id->id_nguid[10], id->id_nguid[11],
		    id->id_nguid[12], id->id_nguid[13], id->id_nguid[14],
		    id->id_nguid[15]);
	} else if (bcmp(zero_guid, id->id_eui64, sizeof (id->id_eui64)) != 0) {
		ret = snprintf(buf, buflen,
		    "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",
		    id->id_eui64[0], id->id_eui64[1], id->id_eui64[2],
		    id->id_eui64[3], id->id_eui64[4], id->id_eui64[5],
		    id->id_eui64[6], id->id_eui64[7]);
	} else {
		ret = snprintf(buf, buflen, "%u", nsid);
	}

	if ((size_t)ret >= buflen) {
		topo_mod_dprintf(mod, "overflowed serial number for nsid %u: "
		    "needed %zu bytes, got %d", nsid, buflen, ret);
		return (false);
	}

	return (true);
}

/*
 * Create the common I/O property group properties that are shared between
 * controllers and namespaces. We assume the property group was already created.
 */
static bool
disk_nvme_common_io(topo_mod_t *mod, tnode_t *tn, di_node_t di)
{
	int err;
	int inst = di_instance(di);
	const char *drv = di_driver_name(di);
	char *path;
	const char *ppaths[1];

	if (inst != -1 && topo_prop_set_uint32(tn, TOPO_PGROUP_IO,
	    TOPO_IO_INSTANCE, TOPO_PROP_IMMUTABLE, (uint32_t)inst, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s:%s on %s[%" PRIu64 "]: "
		    "%s", TOPO_PGROUP_IO, TOPO_IO_INSTANCE, topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
		return (false);
	}

	if (drv != NULL && topo_prop_set_string(tn, TOPO_PGROUP_IO,
	    TOPO_IO_DRIVER, TOPO_PROP_IMMUTABLE, drv, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s:%s on %s[%" PRIu64 "]: "
		    "%s", TOPO_PGROUP_IO, TOPO_IO_DRIVER, topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
		return (false);
	}

	if (drv != NULL) {
		nvlist_t *fmri = topo_mod_modfmri(mod, FM_MOD_SCHEME_VERSION,
		    drv);
		if (mod != NULL && topo_prop_set_fmri(tn, TOPO_PGROUP_IO,
		    TOPO_IO_MODULE, TOPO_PROP_IMMUTABLE, fmri, &err) != 0) {
			topo_mod_dprintf(mod, "failed to set %s:%s on %s[%"
			    PRIu64 "]: %s", TOPO_PGROUP_IO, TOPO_IO_MODULE,
			    topo_node_name(tn), topo_node_instance(tn),
			    topo_strerror(err));
			nvlist_free(fmri);
			return (false);
		}
		nvlist_free(fmri);
	}

	path = di_devfs_path(di);
	ppaths[0] = path;
	if (path != NULL && topo_prop_set_string(tn, TOPO_PGROUP_IO,
	    TOPO_IO_DEV_PATH, TOPO_PROP_IMMUTABLE, path, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s:%s on %s[%" PRIu64 "]: "
		    "%s", TOPO_PGROUP_IO, TOPO_IO_DRIVER, topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
		di_devfs_path_free(path);
		return (false);
	}

	if (path != NULL && topo_prop_set_string_array(tn, TOPO_PGROUP_IO,
	    TOPO_IO_PHYS_PATH, TOPO_PROP_IMMUTABLE, ppaths, 1, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s:%s on %s[%" PRIu64 "]: "
		    "%s", TOPO_PGROUP_IO, TOPO_IO_PHYS_PATH, topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
		di_devfs_path_free(path);
		return (false);
	}
	di_devfs_path_free(path);

	return (true);
}

/*
 * Add the various storage and I/O property group items that are appropriate
 * given that we have a devinfo node. The storage property group has already
 * been created, but the I/O property group has not.
 */
static void
disk_nvme_make_ns_di_props(topo_mod_t *mod, tnode_t *tn, di_node_t di)
{
	int err;
	char *devid, *mfg, *model, *rev, *serial, *log, *path;
	uint_t buflen;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, di, DEVID_PROP_NAME,
	    &devid) != 1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, di, INQUIRY_VENDOR_ID,
	    &mfg) != 1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, di, INQUIRY_PRODUCT_ID,
	    &model) != 1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, di, INQUIRY_REVISION_ID,
	    &rev) != 1 ||
	    di_prop_lookup_strings(DDI_DEV_T_ANY, di, INQUIRY_SERIAL_NO,
	    &serial) != 1) {
		topo_mod_dprintf(mod, "failed to get devinfo props for %s[%"
		    PRIu64 "]", topo_node_name(tn), topo_node_instance(tn));
		return;
	}

	/*
	 * Set the basic storage manufacturer information. Yes, this is
	 * information really about the NVMe controller and not the namespace.
	 * That's how the storage property group basically works here.
	 */
	if (topo_prop_set_string(tn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MANUFACTURER, TOPO_PROP_IMMUTABLE, mfg, &err) != 0 ||
	    topo_prop_set_string(tn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_SERIAL_NUM, TOPO_PROP_IMMUTABLE, serial, &err) != 0 ||
	    topo_prop_set_string(tn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE, rev, &err) != 0 ||
	    topo_prop_set_string(tn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MODEL, TOPO_PROP_IMMUTABLE, model, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set storage properties on "
		    "%s[%" PRIu64 "]: %s", topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
		return;
	}

	if (topo_pgroup_create(tn, &io_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create I/O property "
		    "group on %s[%" PRIu64 "]: %s",  topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
	}

	if (!disk_nvme_common_io(mod, tn, di)) {
		return;
	}

	/*
	 * The last property that we'd like to attempt to create for a namespace
	 * is a mapping back to its corresponding logical disk entry in /dev.
	 * The logical disk will be everything past the trailing /, i.e. a
	 * cXtXdX value.
	 */
	path = di_devfs_path(di);
	if (path == NULL) {
		return;
	}
	log = get_logical_disk(mod, path, &buflen);
	di_devfs_path_free(path);
	if (log == NULL) {
		return;
	}
	path = strrchr(log, '/');
	if (path != NULL && path[1] != '\0' &&
	    topo_prop_set_string(tn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_LOGICAL_DISK_NAME, TOPO_PROP_IMMUTABLE, path + 1,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s:%s on %s[%"
		    PRIu64 "]: %s", TOPO_PGROUP_STORAGE,
		    TOPO_STORAGE_LOGICAL_DISK_NAME, topo_node_name(tn),
		    topo_node_instance(tn), topo_strerror(err));
	}
	topo_mod_free(mod, log, buflen);
}

static void
disk_nvme_make_ns(nvme_enum_info_t *nei, uint32_t nsid)
{
	topo_mod_t *mod = nei->nei_mod;
	nvlist_t *auth = NULL, *fmri = NULL;
	const topo_instance_t inst = nsid - 1;
	nvme_ns_info_t info;
	nvme_ioctl_t ioc;
	char serial[64], capstr[64];
	uint64_t cap, blksz;
	tnode_t *tn;
	uint8_t lba;
	int err;

	bzero(&ioc, sizeof (ioc));
	bzero(&info, sizeof (info));
	ioc.n_len = sizeof (nvme_ns_info_t);
	ioc.n_buf = (uintptr_t)&info;
	ioc.n_arg = nsid;

	if (ioctl(nei->nei_fd, NVME_IOC_NS_INFO, &ioc) != 0) {
		topo_mod_dprintf(mod, "failed to get namespace info for ns %u: "
		    "%s", nsid, strerror(errno));
		return;
	}

	if ((info.nni_state & NVME_NS_STATE_IGNORED) != 0) {
		return;
	}

	if ((info.nni_state &
	    (NVME_NS_STATE_ACTIVE | NVME_NS_STATE_ATTACHED)) == 0) {
		topo_mod_dprintf(mod, "skipping nsid %u because it is not "
		    "active or attached (state: 0x%x)", nsid, info.nni_state);
		return;
	}

	auth = topo_mod_auth(mod, nei->nei_nvme);
	if (auth == NULL) {
		topo_mod_dprintf(mod, "failed to get auth for nsid %u from "
		    "parent %s[%" PRIu64 "]: %s", nsid,
		    topo_node_name(nei->nei_nvme),
		    topo_node_instance(nei->nei_nvme), topo_mod_errmsg(mod));
		goto done;
	}

	/*
	 * We want to construct the FMRI for the namespace. The namespace is a
	 * little awkward in terms of things like the model, revision, and
	 * serial. While blkdev sets up standard inquiry properties to map these
	 * to the parent device which makes sense in the context of trying to
	 * use this as a normal block device, it's not really appropriate here.
	 * The namespace is not the NVMe controller. We construct the namespace
	 * serial number from the preferential ordering of information that
	 * we're given of the NGUID, EUI64, and then fall back to the namespace
	 * number.
	 */
	if (!disk_nvme_make_ns_serial(mod, &info.nni_id, nsid, serial,
	    sizeof (serial))) {
		goto done;
	}
	fmri = topo_mod_hcfmri(mod, nei->nei_nvme, FM_HC_SCHEME_VERSION,
	    DISK, inst, NULL, auth, NULL, NULL, serial);
	if (fmri == NULL) {
		topo_mod_dprintf(mod, "failed to make fmri for %s[%" PRIu64
		    "] on nsid %u: %s", DISK, inst, nsid, topo_mod_errmsg(mod));
		goto done;
	}

	tn = topo_node_bind(mod, nei->nei_nvme, DISK, inst, fmri);
	if (tn == NULL) {
		topo_mod_dprintf(mod, "failed to bind fmri for %s[%" PRIu64
		    "] on nsid %u: %s", DISK, inst, nsid, topo_mod_errmsg(mod));
		goto done;
	}

	/*
	 * Always inherit our parent's FRU. The namespace is just a part of the
	 * device in reality.
	 */
	if (topo_node_fru_set(tn, NULL, 0, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set FRU for %s[%" PRIu64
		    "] on nsid %u: %s", DISK, inst, nsid, topo_strerror(err));
		goto done;

	}

	/*
	 * Our namespace may or may not be attached. From the namespace we will
	 * always get the capacity and block information. The rest of it will
	 * end up being filled in if we find a devinfo node.
	 */
	if (topo_pgroup_create(tn, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create storage property "
		    "group on %s[%" PRIu64 "]: %s", DISK, inst,
		    topo_strerror(err));
	}

	lba = info.nni_id.id_flbas.lba_format;
	blksz = 1ULL << info.nni_id.id_lbaf[lba].lbaf_lbads;
	if (blksz != 0 && topo_prop_set_uint64(tn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_LOG_BLOCK_SIZE, TOPO_PROP_IMMUTABLE, blksz, &err) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s:%s on %s[%"
		    PRIu64 "]: %s", TOPO_PGROUP_STORAGE,
		    TOPO_STORAGE_LOG_BLOCK_SIZE, DISK, inst,
		    topo_strerror(err));
		goto done;
	}

	cap = blksz * info.nni_id.id_nsize;
	if (snprintf(capstr, sizeof (capstr), "%" PRIu64, cap) >=
	    sizeof (capstr)) {
		topo_mod_dprintf(mod, "overflowed capacity calculation on "
		    "nsid %u", nsid);
		goto done;
	}

	/*
	 * Finally attempt to find a child node that has a matching name and go
	 * from there. Sorry, this does result in node creation being O(n^2),
	 * but at least n is usually small today.
	 */
	for (di_node_t di = di_child_node(nei->nei_dinode); di != DI_NODE_NIL;
	    di = di_sibling_node(di)) {
		const char *addr = di_bus_addr(di);
		if (addr != NULL && strcmp(addr, info.nni_addr) == 0) {
			disk_nvme_make_ns_di_props(mod, tn, di);
		}
	}

done:
	nvlist_free(auth);
	nvlist_free(fmri);
}

/*
 * Attempt to make a ufm node, but swallow the error so we can try to get as
 * much of the disk information as possible.
 */
static void
disk_nvme_make_ufm(topo_mod_t *mod, nvme_enum_info_t *nei)
{
	topo_ufm_devinfo_t tud;
	char *path = di_devfs_path(nei->nei_dinode);
	if (path == NULL) {
		return;
	}

	tud.tud_method = TOPO_UFM_M_DEVINFO;
	tud.tud_path = path;
	if (topo_mod_load(mod, TOPO_MOD_UFM, TOPO_VERSION) == NULL) {
		topo_mod_dprintf(mod, "disk enum could not load ufm module");
		di_devfs_path_free(path);
		return;
	}

	(void) topo_mod_enumerate(mod, nei->nei_nvme, TOPO_MOD_UFM, UFM, 0, 0,
	    &tud);
	di_devfs_path_free(path);
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
	 * underneath it to hold the nvme hierarchy.  For other cases, where
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

	/*
	 * Ensure that we have a UFM property set based on our devinfo path.
	 * This is a little repetitive if our parent actually did so as well,
	 * but given that the majority of such nodes are under bays and slots
	 * right now, it's a worthwhile tradeoff.
	 */
	disk_nvme_make_ufm(mod, nvme_info);

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

	if (!disk_nvme_common_io(mod, nvme, nvme_info->nei_dinode)) {
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

	/*
	 * Iterate over each namespace to see if it's a candidate for inclusion.
	 * Namespaces start at index 1 and not every namespace will be included.
	 * We map things such that a disk instance is always namespace - 1 to
	 * fit into the above mapping.
	 */
	for (uint32_t i = 1; i <= nvme_info->nei_idctl->id_nn; i++) {
		disk_nvme_make_ns(nvme_info, i);
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
