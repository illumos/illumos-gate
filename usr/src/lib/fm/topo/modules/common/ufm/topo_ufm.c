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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This implements logic to enumerate UFM nodes based on different data sources
 * in the system. Being in a module allows it to be used by several other
 * modules in the system and means that we can encapsulate all of the messy
 * logic here.
 *
 * Our module is not designed to operate from a topo map right now. Instead, it
 * is expected that callers are going to pass the enumeration argument in.
 */

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <string.h>
#include <sys/ddi_ufm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "topo_ufm.h"

/*
 * Attempt to create the specific UFM image that is listed in the nvl.
 */
static int
topo_ufm_devinfo_image(topo_mod_t *mod, tnode_t *pn, topo_instance_t inst,
    nvlist_t *nvl)
{
	int ret;
	char *desc;
	tnode_t *img_tn;
	nvlist_t **slots;
	uint_t nslots;

	ret = nvlist_lookup_string(nvl, DDI_UFM_NV_IMAGE_DESC, &desc);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to look up %s: %s",
		    DDI_UFM_NV_IMAGE_DESC, strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	ret = nvlist_lookup_nvlist_array(nvl, DDI_UFM_NV_IMAGE_SLOTS, &slots,
	    &nslots);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to look up %s: %s",
		    DDI_UFM_NV_IMAGE_SLOTS, strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	if (nslots == 0) {
		topo_mod_dprintf(mod, "refusing to create UFM image with zero "
		    "slots");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	img_tn = topo_mod_create_ufm(mod, pn, inst, desc, NULL);
	if (img_tn == NULL) {
		topo_mod_dprintf(mod, "failed to create ufm image %" PRIu64
		    "on %s[%" PRIu64 "]: %s", inst, topo_node_name(pn),
		    topo_node_instance(pn), topo_mod_errmsg(mod));
		return (-1);
	}

	if (topo_node_range_create(mod, img_tn, SLOT, 0, nslots - 1) != 0) {
		topo_mod_dprintf(mod, "failed to create node range %s[0, %u]: "
		    "%s", SLOT, nslots - 1, topo_mod_errmsg(mod));
		topo_node_unbind(img_tn);
		return (-1);
	}

	/*
	 * Go through and create the slots. Once we've reached this part, it's
	 * hard to clean up the UFM image node as it will have ranges and
	 * potentially children (because we've been looping). We'll have to hope
	 * that the enumeration error is sufficient for someone taking a
	 * snapshot.
	 *
	 * A slot must have an attributes property. If that is not there, we
	 * can't do much more than that. It must have a version, but only if the
	 * empty attribute is not set! There may be misc. extra data, which
	 * we'll include but don't care if we can get it or not.
	 */
	for (uint_t i = 0; i < nslots; i++) {
		topo_ufm_slot_info_t slot = { 0 };
		uint32_t attr, rw;
		char *vers;

		slot.usi_slotid = i;
		ret = nvlist_lookup_uint32(slots[i], DDI_UFM_NV_SLOT_ATTR,
		    &attr);
		if (ret != 0) {
			topo_mod_dprintf(mod, "failed to get required %s "
			    "property from slot %u: %s", DDI_UFM_NV_SLOT_ATTR,
			    i, strerror(errno));
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}

		slot.usi_version = vers;
		rw = attr & (DDI_UFM_ATTR_READABLE | DDI_UFM_ATTR_WRITEABLE);
		switch (rw) {
		case DDI_UFM_ATTR_READABLE | DDI_UFM_ATTR_WRITEABLE:
			slot.usi_mode = TOPO_UFM_SLOT_MODE_RW;
			break;
		case DDI_UFM_ATTR_READABLE:
			slot.usi_mode = TOPO_UFM_SLOT_MODE_RO;
			break;
		case DDI_UFM_ATTR_WRITEABLE:
			slot.usi_mode = TOPO_UFM_SLOT_MODE_WO;
			break;
		default:
			slot.usi_mode = TOPO_UFM_SLOT_MODE_NONE;
			break;
		}

		slot.usi_active = (attr & DDI_UFM_ATTR_ACTIVE) != 0;

		vers = NULL;
		if ((attr & DDI_UFM_ATTR_EMPTY) == 0 &&
		    (ret = nvlist_lookup_string(slots[i],
		    DDI_UFM_NV_SLOT_VERSION, &vers)) != 0) {
			topo_mod_dprintf(mod, "failed to get required %s "
			    "property from non-empty slot %u: %s",
			    DDI_UFM_NV_SLOT_VERSION, i, strerror(errno));
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}
		slot.usi_version = vers;

		/*
		 * If there are additional attributes that exist, then leverage
		 * those. However, we'll ignore failures of this because it's
		 * optional.
		 */
		slot.usi_extra = NULL;
		(void) nvlist_lookup_nvlist(slots[i], DDI_UFM_NV_SLOT_MISC,
		    &slot.usi_extra);

		if (topo_mod_create_ufm_slot(mod, img_tn, &slot) == NULL) {
			topo_mod_dprintf(mod, "failed to create ufm slot %u on "
			    "image %" PRIu64 ": %s", i, inst,
			    topo_mod_errmsg(mod));
			return (-1);
		}
	}

	return (0);
}

/*
 * Utlilizing the devinfo tree create information about the given ufm. We use
 * [min, max] as a way to figure out which UFMs to create and treat this as a
 * way to slice up parts of the range. We will only actually create nodes based
 * on how many are present.
 */
static int
topo_ufm_devinfo(topo_mod_t *mod, tnode_t *pn, topo_instance_t min,
    topo_instance_t max, topo_ufm_devinfo_t *tud)
{
	int fd = -1;
	int ret;
	ufm_ioc_getcaps_t caps = { 0 };
	ufm_ioc_bufsz_t bufsz = { 0 };
	ufm_ioc_report_t report = { 0 };
	nvlist_t *nvl = NULL, **img_nvl;
	uint_t nimg;

	if (tud->tud_path == NULL) {
		topo_mod_dprintf(mod, "missing required devfs path");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	/*
	 * We check the path size here now so we can guarantee that all of the
	 * rest of the string copying will fit inside our buffers and therefore
	 * we ignore the strlcpy() result.
	 */
	if (strlen(tud->tud_path) >= MAXPATHLEN) {
		topo_mod_dprintf(mod, "given devfs path exceeds MAXPATHLEN "
		    "buffers, cannot continue");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	fd = open(DDI_UFM_DEV, O_RDONLY);
	if (fd < 0) {
		topo_mod_dprintf(mod, "failed to open %s: %s", DDI_UFM_DEV,
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	caps.ufmg_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(caps.ufmg_devpath, tud->tud_path,
	    sizeof (caps.ufmg_devpath));

	/*
	 * We swallow ioctl errors on purpose. The device driver may not support
	 * UFMs at all. Similarly, if it doesn't actually support reporting UFM
	 * information, then we're done here.
	 */
	if (ioctl(fd, UFM_IOC_GETCAPS, &caps) != 0) {
		topo_mod_dprintf(mod, "failed to get UFM capabilities for "
		    "%s: %s", tud->tud_path, strerror(errno));
		ret = 0;
		goto out;
	}

	if ((caps.ufmg_caps & DDI_UFM_CAP_REPORT) == 0) {
		topo_mod_dprintf(mod, "path %s does not support UFM reporting",
		    tud->tud_path);
		ret = 0;
		goto out;
	}

	bufsz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(bufsz.ufbz_devpath, tud->tud_path,
	    sizeof (bufsz.ufbz_devpath));
	if (ioctl(fd, UFM_IOC_REPORTSZ, &bufsz) != 0) {
		topo_mod_dprintf(mod, "failed to get UFM buffer size for "
		    "%s: %s", tud->tud_path, strerror(errno));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	report.ufmr_version = DDI_UFM_CURRENT_VERSION;
	report.ufmr_bufsz = bufsz.ufbz_size;
	report.ufmr_buf = topo_mod_alloc(mod, bufsz.ufbz_size);
	if (report.ufmr_buf == NULL) {
		ret = topo_mod_seterrno(mod, EMOD_NOMEM);
		goto out;
	}
	(void) strlcpy(report.ufmr_devpath, tud->tud_path,
	    sizeof (report.ufmr_devpath));
	if (ioctl(fd, UFM_IOC_REPORT, &report) != 0) {
		topo_mod_dprintf(mod, "failed to retrieve UFM report for "
		    "%s: %s", tud->tud_path, strerror(errno));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	ret = nvlist_unpack(report.ufmr_buf, report.ufmr_bufsz, &nvl, 0);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to unpack report nvlist from "
		    "%s: %s", tud->tud_path, strerror(ret));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	/*
	 * First see if the report actually gave us images. If there are no
	 * images, then there is nothing to do.
	 */
	ret = nvlist_lookup_nvlist_array(nvl, DDI_UFM_NV_IMAGES, &img_nvl,
	    &nimg);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to retrieve key %s from "
		    "report: %s", DDI_UFM_NV_IMAGES, strerror(ret));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	if (nimg == 0) {
		ret = 0;
		goto out;
	}

	max = MIN(max, nimg - 1);
	if (topo_node_range_create(mod, pn, UFM, min, max) != 0) {
		topo_mod_dprintf(mod, "failed to create node range %s[%" PRIu64
		    ", %" PRIu64 "]: %s", UFM, min, max, topo_mod_errmsg(mod));
		ret = -1;
		goto out;
	}

	for (topo_instance_t i = min; i <= max; i++) {
		ret = topo_ufm_devinfo_image(mod, pn, i, img_nvl[i]);
		if (ret != 0) {
			goto out;
		}
	}

out:
	nvlist_free(nvl);
	if (report.ufmr_buf != NULL) {
		topo_mod_free(mod, report.ufmr_buf, bufsz.ufbz_size);
	}

	if (fd >= 0) {
		(void) close(fd);
	}
	return (ret);
}

static int
topo_ufm_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	topo_ufm_method_t *mp;

	topo_mod_dprintf(mod, "asked to enum %s [%" PRIu64 ", %" PRIu64 "] on "
	    "%s%" PRIu64 "\n", name, min, max, topo_node_name(pnode),
	    topo_node_instance(pnode));

	if (strcmp(name, UFM) != 0) {
		topo_mod_dprintf(mod, "cannot enumerate %s: unknown type",
		    name);
		return (-1);
	}

	if (data == NULL) {
		topo_mod_dprintf(mod, "cannot enumerate %s: missing required "
		    "data", name);
		return (-1);
	}

	mp = data;
	switch (*mp) {
	case TOPO_UFM_M_DEVINFO:
		return (topo_ufm_devinfo(mod, pnode, min, max, data));
	default:
		topo_mod_dprintf(mod, "encountered unknown UFM enum method: "
		    "0x%x, bailing", *mp);
		return (-1);
	}

}

static const topo_modops_t topo_ufm_ops = {
	topo_ufm_enum, NULL
};

static topo_modinfo_t topo_ufm_mod = {
	"UFM Enumerator", FM_FMRI_SCHEME_HC, TOPO_MOD_UFM_VERS, &topo_ufm_ops
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOUFMDEBUG") != NULL) {
		topo_mod_setdebug(mod);
	}

	return (topo_mod_register(mod, &topo_ufm_mod, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
