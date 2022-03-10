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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * fwflash(8) backend for UFMs.
 */

#include <libdevinfo.h>
#include <strings.h>
#include <libintl.h>
#include <pcidb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libnvpair.h>
#include <sys/ddi_ufm.h>
#include <sys/sysmacros.h>
#include <fwflash/fwflash.h>

/*
 * We pick a fixed size unit to work on.
 */
#define	UFM_READ_BUFLEN	(16 * 1024 * 1024)

/*
 * These are indexes into the addresses array that we use.
 */
#define	UFM_ADDR_PATH	0
#define	UFM_ADDR_SUB	1
#define	UFM_ADDR_CAP	2

typedef struct ufmfw_ident_arg {
	uint_t uia_nfound;
	int uia_index;
	int uia_err;
} ufmfw_ident_arg_t;

/*
 * fwflash requires we declare our driver name as data with this name.
 */
const char drivername[] = "ufm";
const int plugin_version = FWPLUGIN_VERSION_2;

/*
 * External data from fwflash.
 */
extern di_node_t rootnode;
extern struct fw_plugin *self;

/*
 * Global, shared data.
 */
static int ufmfw_ufm_fd = -1;
static pcidb_hdl_t *ufmfw_pcidb;
static boolean_t ufmfw_ready = B_FALSE;

/*
 * Read image zero and slot zero that we find.
 */
int
fw_readfw(struct devicelist *flashdev, const char *filename)
{
	nvlist_t **images, **slots;
	uint_t nimages, nslots, caps;
	uint64_t imgsize, offset;
	void *buf;
	int fd;
	nvlist_t *nvl = flashdev->ident->encap_ident;

	caps = (uintptr_t)flashdev->addresses[UFM_ADDR_CAP];
	if ((caps & DDI_UFM_CAP_READIMG) == 0) {
		logmsg(MSG_ERROR, "%s: device %s does not support reading "
		    "images\n", flashdev->drvname, flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	if (nvlist_lookup_nvlist_array(nvl, DDI_UFM_NV_IMAGES, &images,
	    &nimages) != 0) {
		logmsg(MSG_ERROR, gettext("%s: %s missing UFM image data\n"),
		    flashdev->drvname, flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	if (nimages == 0) {
		logmsg(MSG_ERROR, gettext("%s: %s has no UFM images\n"),
		    flashdev->drvname, flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	if (nvlist_lookup_nvlist_array(images[0], DDI_UFM_NV_IMAGE_SLOTS,
	    &slots, &nslots) != 0) {
		logmsg(MSG_ERROR, gettext("%s: image zero of %s has no "
		    "slots\n"), flashdev->drvname, flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	if (nvlist_lookup_uint64(slots[0], DDI_UFM_NV_SLOT_IMGSIZE,
	    &imgsize) != 0) {
		logmsg(MSG_ERROR, gettext("%s: device %s doesn't have an image "
		    "size\n"), flashdev->drvname, flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	logmsg(MSG_INFO, gettext("%s: Need to read %" PRIu64 " bytes\n"),
	    flashdev->drvname, imgsize);

	if ((buf = malloc(UFM_READ_BUFLEN)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: Failed to allocate data "
		    "buffer\n"), flashdev->drvname);
		return (FWFLASH_FAILURE);
	}

	if ((fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644)) < 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to open file %s: %s\n"),
		    flashdev->drvname, filename, strerror(errno));
		free(buf);
		return (FWFLASH_FAILURE);
	}

	offset = 0;
	while (imgsize > 0) {
		ufm_ioc_readimg_t rimg;
		uint64_t toread = MIN(imgsize, UFM_READ_BUFLEN);
		size_t woff;

		bzero(&rimg, sizeof (rimg));
		rimg.ufri_version = DDI_UFM_CURRENT_VERSION;
		rimg.ufri_imageno = 0;
		rimg.ufri_slotno = 0;
		rimg.ufri_offset = offset;
		rimg.ufri_len = toread;
		rimg.ufri_buf = buf;
		(void) strlcpy(rimg.ufri_devpath,
		    flashdev->addresses[UFM_ADDR_PATH],
		    sizeof (rimg.ufri_devpath));
		logmsg(MSG_INFO, gettext("%s: want to read %" PRIu64 " bytes "
		    "at offset %" PRIu64 "\n"), flashdev->drvname,
		    rimg.ufri_len, rimg.ufri_offset);

		if (ioctl(ufmfw_ufm_fd, UFM_IOC_READIMG, &rimg) != 0) {
			logmsg(MSG_ERROR, gettext("%s: failed to read image: "
			    "%s\n"), flashdev->drvname, strerror(errno));
			free(buf);
			(void) close(fd);
			return (FWFLASH_FAILURE);
		}

		logmsg(MSG_INFO, gettext("%s: read %" PRIu64 " bytes at offset "
		    "%" PRIu64 "\n"), flashdev->drvname, rimg.ufri_nread,
		    offset);
		offset += rimg.ufri_nread;
		imgsize -= rimg.ufri_nread;

		woff = 0;
		while (rimg.ufri_nread > 0) {
			size_t towrite = MIN(rimg.ufri_nread, UFM_READ_BUFLEN);
			ssize_t ret = write(fd, buf + woff, towrite);
			if (ret == -1) {
				logmsg(MSG_ERROR, gettext("%s: failed to write "
				    "to %s: %s\n"), flashdev->drvname, filename,
				    strerror(errno));
				free(buf);
				(void) close(fd);
				return (FWFLASH_FAILURE);
			}

			rimg.ufri_nread -= ret;
			woff += ret;
		}
	}

	free(buf);
	if (close(fd) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to finish writing to %s: "
		    "%s\n"), flashdev->drvname, filename, strerror(errno));
		return (FWFLASH_FAILURE);
	}
	logmsg(MSG_INFO, gettext("%s: successfully wrote image to %s\n"),
	    flashdev->drvname, filename);
	return (FWFLASH_SUCCESS);
}


int
fw_writefw(struct devicelist *flashdev)
{
	return (FWFLASH_SUCCESS);
}

static void
ufmfw_flashdev_free(struct devicelist *flashdev)
{
	if (flashdev == NULL)
		return;
	if (flashdev->ident != NULL) {
		free(flashdev->ident->vid);
		free(flashdev->ident->pid);
		nvlist_free(flashdev->ident->encap_ident);
	}
	free(flashdev->ident);
	free(flashdev->drvname);
	free(flashdev->classname);
	free(flashdev->access_devname);
	di_devfs_path_free(flashdev->addresses[UFM_ADDR_PATH]);
	free(flashdev->addresses[UFM_ADDR_SUB]);
	free(flashdev);
}

/*
 * Check if a node is a PCI device. This is so we can deal with VPD information.
 * Hopefully we'll have a generalized devinfo or fmtopo VPD section which we can
 * then use for this instead.
 */
static boolean_t
ufmfw_node_pci(di_node_t node)
{
	while (node != DI_NODE_NIL) {
		char *strs;
		int ret = di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    "device_type", &strs);

		if (ret > 0) {
			if (strcmp(strs, "pci") == 0 ||
			    strcmp(strs, "pciex") == 0) {
				return (B_TRUE);
			}
		}

		node = di_parent_node(node);
	}
	return (B_FALSE);
}

/*
 * Cons up VPD information based on the PCI ID. Hopefully in time we'll use the
 * actual PCI VPD information and more generally allow a device to specify its
 * vpd automatically.
 */
static boolean_t
ufmfw_fill_vpd(struct devicelist *flashdev, di_node_t node)
{
	int *vid, *did, *svid, *sdid;
	pcidb_vendor_t *vend = NULL;
	pcidb_device_t *dev = NULL;
	pcidb_subvd_t *subdv = NULL;
	char *vstr, *dstr;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "vendor-id", &vid) != 1) {
		logmsg(MSG_ERROR, gettext("%s: %s missing 'vendor-id' "
		    "property\n"), flashdev->drvname, flashdev->access_devname);
		return (B_FALSE);
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "device-id", &did) != 1) {
		logmsg(MSG_ERROR, gettext("%s: %s missing 'device-id' "
		    "property\n"), flashdev->drvname, flashdev->access_devname);
		return (B_FALSE);
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "subsystem-vendor-id",
	    &svid) != 1 || di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "subsystem-device-id", &sdid) != 1) {
		svid = NULL;
		sdid = NULL;
	}

	vend = pcidb_lookup_vendor(ufmfw_pcidb, vid[0]);
	if (vend != NULL) {
		dev = pcidb_lookup_device_by_vendor(vend, did[0]);
	}

	if (dev != NULL && svid != NULL && sdid != NULL) {
		subdv = pcidb_lookup_subvd_by_device(dev, svid[0], sdid[0]);
	}

	if (vend != NULL) {
		vstr = strdup(pcidb_vendor_name(vend));
	} else {
		(void) asprintf(&vstr, "pci:%x", vid[0]);
	}

	if (vstr == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to allocate vid "
		    "string\n"), flashdev->drvname);
		return (B_FALSE);
	}
	flashdev->ident->vid = vstr;

	if (dev != NULL) {
		dstr = strdup(pcidb_device_name(dev));
	} else {
		(void) asprintf(&dstr, "pci:%x", did[0]);
	}

	if (dstr == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to allocate pid "
		    "string\n"), flashdev->drvname);
		return (B_FALSE);
	}
	flashdev->ident->pid = dstr;

	if (subdv != NULL) {
		/*
		 * Because this is optional, don't fail if we fail to duplicate
		 * this.
		 */
		flashdev->addresses[UFM_ADDR_SUB] =
		    strdup(pcidb_subvd_name(subdv));
		if (flashdev->addresses[UFM_ADDR_SUB] == NULL) {
			logmsg(MSG_WARN, gettext("%s: failed to allocate vpd "
			    "subsystem name\n"), flashdev->drvname);
		}
	}

	return (B_TRUE);
}

static int
ufmfw_di_walk_cb(di_node_t node, void *arg)
{
	int ret;
	boolean_t found = B_FALSE;
	di_prop_t prop = DI_PROP_NIL;
	ufmfw_ident_arg_t *uia = arg;
	struct devicelist *flashdev = NULL;
	ufm_ioc_getcaps_t caps;
	ufm_ioc_bufsz_t bufsz;
	ufm_ioc_report_t rep;
	char *devfs, *packnvl;
	nvlist_t *nvl = NULL;

	while ((prop = di_prop_next(node, prop)) != DI_PROP_NIL) {
		const char *pname = di_prop_name(prop);
		if (strcmp(pname, "ddi-ufm-capable") == 0) {
			found = B_TRUE;
			break;
		}
	}

	if (!found) {
		return (DI_WALK_CONTINUE);
	}

	if (!ufmfw_node_pci(node)) {
		return (DI_WALK_CONTINUE);
	}

	if ((devfs = di_devfs_path(node)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to get device node "
		    "path\n"), drivername);
		goto err;
	}

	bzero(&caps, sizeof (caps));
	caps.ufmg_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(caps.ufmg_devpath, devfs, sizeof (caps.ufmg_devpath));
	if (ioctl(ufmfw_ufm_fd, UFM_IOC_GETCAPS, &caps) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to get UFM caps for "
		    "UFM compatible device %s: %s\n"), drivername, devfs,
		    strerror(errno));
		di_devfs_path_free(devfs);
		return (DI_WALK_CONTINUE);
	}

	/*
	 * If nothing is supported just leave it be.
	 */
	if (caps.ufmg_caps == 0) {
		di_devfs_path_free(devfs);
		return (DI_WALK_CONTINUE);
	}

	bzero(&bufsz, sizeof (bufsz));
	bufsz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(bufsz.ufbz_devpath, devfs, sizeof (bufsz.ufbz_devpath));
	if (ioctl(ufmfw_ufm_fd, UFM_IOC_REPORTSZ, &bufsz) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to get UFM report size "
		    "for device %s: %s\n"), drivername, devfs,
		    strerror(errno));
		di_devfs_path_free(devfs);
		return (DI_WALK_CONTINUE);
	}

	if ((packnvl = malloc(bufsz.ufbz_size)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to allocate %zu bytes "
		    "for report buffer\n"), drivername, bufsz.ufbz_size);
		di_devfs_path_free(devfs);
		goto err;
	}
	bzero(&rep, sizeof (rep));
	rep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	rep.ufmr_bufsz = bufsz.ufbz_size;
	rep.ufmr_buf = packnvl;
	(void) strlcpy(rep.ufmr_devpath, devfs, sizeof (rep.ufmr_devpath));
	if (ioctl(ufmfw_ufm_fd, UFM_IOC_REPORT, &rep) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to get UFM report "
		    "for device %s: %s\n"), drivername, devfs,
		    strerror(errno));
		free(packnvl);
		di_devfs_path_free(devfs);
		return (DI_WALK_CONTINUE);
	}

	if ((ret = nvlist_unpack(packnvl, rep.ufmr_bufsz, &nvl, 0)) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to unpack UFM report "
		    "for device %s: %s\n"), drivername, devfs, strerror(ret));
		free(packnvl);
		di_devfs_path_free(devfs);
		return (DI_WALK_CONTINUE);

	}
	free(packnvl);

	if ((flashdev = calloc(1, sizeof (*flashdev))) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to allocate new "
		    "device entry for node %s\n"), drivername, devfs);
		di_devfs_path_free(devfs);
		goto err;
	}

	flashdev->addresses[UFM_ADDR_PATH] = devfs;

	if (asprintf(&flashdev->access_devname, "/devices%s",
	    flashdev->addresses[UFM_ADDR_PATH]) == -1) {
		logmsg(MSG_ERROR, gettext("%s: failed to construct device "
		    "path\n"), drivername);
		goto err;
	}
	if ((flashdev->drvname = strdup(drivername)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to construct driver "
		    "name\n"), drivername);
		goto err;
	}
	if ((flashdev->classname = strdup(drivername)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to allocate vpd "
		    "data\n"), drivername);
		goto err;
	}

	if ((flashdev->ident = calloc(1, sizeof (struct vpr))) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to construct class "
		    "name\n"), drivername);
		goto err;
	}
	if (!ufmfw_fill_vpd(flashdev, node)) {
		goto err;
	}

	flashdev->ident->encap_ident = nvl;

	flashdev->index = uia->uia_index;
	uia->uia_index++;
	flashdev->addresses[UFM_ADDR_CAP] = (void *)(uintptr_t)caps.ufmg_caps;
	flashdev->plugin = self;
	uia->uia_nfound++;

	TAILQ_INSERT_TAIL(fw_devices, flashdev, nextdev);

	return (DI_WALK_CONTINUE);

err:
	nvlist_free(nvl);
	uia->uia_err = FWFLASH_FAILURE;
	ufmfw_flashdev_free(flashdev);
	return (DI_WALK_TERMINATE);
}

int
fw_identify(int start)
{
	ufmfw_ident_arg_t uia;

	if (!ufmfw_ready) {
		return (FWFLASH_FAILURE);
	}

	uia.uia_nfound = 0;
	uia.uia_index = start;
	uia.uia_err = FWFLASH_SUCCESS;
	(void) di_walk_node(rootnode, DI_WALK_CLDFIRST, &uia,
	    ufmfw_di_walk_cb);
	if (uia.uia_nfound == 0) {
		return (FWFLASH_FAILURE);
	}

	return (uia.uia_err);
}

int
fw_devinfo(struct devicelist *flashdev)
{
	nvlist_t *nvl, **images;
	uint_t nimages, img, caps;

	(void) printf(gettext("Device[%d] %s\n"), flashdev->index,
	    flashdev->access_devname);
	(void) printf(gettext("Class [%s]\n"), flashdev->classname);
	(void) printf(gettext("\tVendor: %s\n\tDevice: %s\n"),
	    flashdev->ident->vid, flashdev->ident->pid);
	if (flashdev->addresses[UFM_ADDR_SUB] != NULL) {
		(void) printf(gettext("\tSubsystem: %s\n"),
		    flashdev->addresses[UFM_ADDR_SUB]);
	}

	caps = (uintptr_t)flashdev->addresses[UFM_ADDR_CAP];
	if (caps != 0) {
		boolean_t first = B_TRUE;
		(void) printf(gettext("\tCapabilities: "));
		if (caps & DDI_UFM_CAP_REPORT) {
			(void) printf(gettext("Report"));
			first = B_FALSE;
		}

		if (caps & DDI_UFM_CAP_READIMG) {
			(void) printf(gettext("%sRead Image"),
			    first ? "" : ", ");
		}
		(void) printf("\n");
	}

	nvl = flashdev->ident->encap_ident;
	if (nvlist_lookup_nvlist_array(nvl, DDI_UFM_NV_IMAGES, &images,
	    &nimages) != 0) {
		goto done;
	}

	for (img = 0; img < nimages; img++) {
		nvlist_t **slots;
		uint_t nslots, s;
		char *desc;

		if (nvlist_lookup_nvlist_array(images[img],
		    DDI_UFM_NV_IMAGE_SLOTS, &slots, &nslots) != 0) {
			goto done;
		}

		if (nvlist_lookup_string(images[img], DDI_UFM_NV_IMAGE_DESC,
		    &desc) != 0) {
			desc = NULL;
		}

		if (desc != NULL) {
			(void) printf(gettext("\tImage %d: %s\n"), img, desc);
		} else {
			(void) printf(gettext("\tImage %d:\n"), img);
		}

		for (s = 0; s < nslots; s++) {
			uint32_t attr;
			char *version;

			if (nvlist_lookup_uint32(slots[s], DDI_UFM_NV_SLOT_ATTR,
			    &attr) != 0) {
				attr = 0;
			}

			if (nvlist_lookup_string(slots[s],
			    DDI_UFM_NV_SLOT_VERSION, &version) != 0) {
				version = "<unknown>";
			}

			printf(gettext("\t    Slot %d (%c|%c|%c): %s\n"), s,
			    attr & DDI_UFM_ATTR_READABLE ? 'r' : '-',
			    attr & DDI_UFM_ATTR_WRITEABLE ? 'w' : '-',
			    attr & DDI_UFM_ATTR_ACTIVE ? 'a' : '-',
			    attr & DDI_UFM_ATTR_EMPTY ? "<empty>" : version);

		}
	}

done:
	(void) printf("\n\n");
	return (FWFLASH_SUCCESS);
}

void
fw_cleanup(struct devicelist *flashdev)
{
	ufmfw_flashdev_free(flashdev);
}

#pragma init(ufmfw_init)
static void
ufmfw_init(void)
{
	ufmfw_ufm_fd = open("/dev/ufm", O_RDONLY);
	if (ufmfw_ufm_fd < 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to open /dev/ufm: %s\n"),
		    drivername, strerror(errno));
		return;
	}

	ufmfw_pcidb = pcidb_open(PCIDB_VERSION);
	if (ufmfw_pcidb == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to open libpcidb: %s\n"),
		    drivername, strerror(errno));
		return;
	}
	ufmfw_ready = B_TRUE;
}

#pragma fini(ufmfw_fini)
static void
ufmfw_fini(void)
{
	pcidb_close(ufmfw_pcidb);
	if (ufmfw_ufm_fd >= 0) {
		(void) close(ufmfw_ufm_fd);
	}
	ufmfw_ready = B_FALSE;
}
