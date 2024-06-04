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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This file implements the logic behind the NVMe controller information
 * interface.
 *
 * The idea behind controller information is to gather all of the information
 * related to controller information in one structure that can then be
 * interrogated. This data should have its own lifetime and represents a point
 * in time snapshot. This then allows this information to be saved and restored
 * across systems.
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/sysmacros.h>

#include "libnvme_impl.h"

bool
nvme_info_error(nvme_ctrl_info_t *ci, nvme_info_err_t err, int32_t sys,
    const char *fmt, ...)
{
	int ret;
	va_list ap;

	ci->nci_err = err;
	ci->nci_syserr = sys;
	va_start(ap, fmt);
	ret = vsnprintf(ci->nci_errmsg, sizeof (ci->nci_errmsg), fmt, ap);
	va_end(ap);
	if (ret >= sizeof (ci->nci_errmsg)) {
		ci->nci_errlen = sizeof (ci->nci_errmsg) - 1;
	} else if (ret <= 0) {
		ci->nci_errlen = 0;
		ci->nci_errmsg[0] = '\0';
	} else {
		ci->nci_errlen = (size_t)ret;
	}

	return (false);
}

bool
nvme_info_success(nvme_ctrl_info_t *ci)
{
	ci->nci_err = NVME_INFO_ERR_OK;
	ci->nci_syserr = 0;
	ci->nci_errmsg[0] = '\0';
	ci->nci_errlen = 0;

	return (true);
}

nvme_info_err_t
nvme_ctrl_info_err(nvme_ctrl_info_t *ci)
{
	return (ci->nci_err);
}

int32_t
nvme_ctrl_info_syserr(nvme_ctrl_info_t *ci)
{
	return (ci->nci_syserr);
}

const char *
nvme_ctrl_info_errmsg(nvme_ctrl_info_t *ci)
{
	return (ci->nci_errmsg);
}

size_t
nvme_ctrl_info_errlen(nvme_ctrl_info_t *ci)
{
	return (ci->nci_errlen);
}

/*
 * These errors are shared with the nvme_ns_info_t structures. While they both
 * allow for us to pass in their respective information objects, that's mostly
 * for future API changes. The namespace information variant of this just calls
 * this function with the control information set to NULL.
 */
const char *
nvme_ctrl_info_errtostr(nvme_ctrl_info_t *ci, nvme_info_err_t err)
{
	switch (err) {
	case NVME_INFO_ERR_OK:
		return ("NVME_INFO_ERR_OK");
	case NVME_INFO_ERR_TRANSPORT:
		return ("NVME_INFO_ERR_TRANSPORT");
	case NVME_INFO_ERR_VERSION:
		return ("NVME_INFO_ERR_VERSION");
	case NVME_INFO_ERR_MISSING_CAP:
		return ("NVME_INFO_ERR_MISSING_CAP");
	case NVME_INFO_ERR_BAD_LBA_FMT:
		return ("NVME_INFO_ERR_BAD_LBA_FMT");
	case NVME_INFO_ERR_PERSIST_NVL:
		return ("NVME_INFO_ERR_PERSIST_NVL");
	case NVME_INFO_ERR_BAD_FMT:
		return ("NVME_INFO_ERR_BAD_FMT");
	case NVME_INFO_ERR_BAD_FMT_DATA:
		return ("NVME_INFO_ERR_BAD_FMT_DATA");
	case NVME_INFO_ERR_NS_INACTIVE:
		return ("NVME_INFO_ERR_NS_INACTIVE");
	case NVME_INFO_ERR_NS_NO_BLKDEV:
		return ("NVME_INFO_ERR_NS_NO_BLKDEV");
	default:
		return ("unknown error");
	}
}

void
nvme_ctrl_info_free(nvme_ctrl_info_t *ci)
{
	free(ci);
}

/*
 * The caller is required to ensure that out is at least max_src + 1 bytes long.
 */
static void
nvme_ctrl_info_init_ident_str(const char *src, size_t max_src,
    char *out)
{
	while (max_src > 0 && src[max_src - 1] == ' ') {
		max_src--;
	}

	if (max_src == 0) {
		*out = '\0';
		return;
	}

	(void) memcpy(out, src, max_src);
	out[max_src] = '\0';
}

static void
nvme_ctrl_info_init_ident(nvme_ctrl_info_t *ci)
{
	nvme_ctrl_info_init_ident_str(ci->nci_info.id_serial,
	    sizeof (ci->nci_info.id_serial), ci->nci_serial);
	nvme_ctrl_info_init_ident_str(ci->nci_info.id_model,
	    sizeof (ci->nci_info.id_model), ci->nci_model);
	nvme_ctrl_info_init_ident_str(ci->nci_info.id_fwrev,
	    sizeof (ci->nci_info.id_fwrev), ci->nci_fwrev);
}

bool
nvme_ctrl_info_restore(nvme_t *nvme, nvlist_t *nvl, nvme_ctrl_info_t **outp)
{
	int ret;
	uint32_t vers;
	nvme_ctrl_info_t *ci;
	char *path;
	uchar_t *ctrl, *ns;
	uint_t ctrl_len, ns_len;

	if (nvl == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvlist_t input pointer: %p", nvl));
	}

	if (outp == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvme_ctrl_info_t output pointer: %p", outp));
	}
	*outp = NULL;

	ci = calloc(1, sizeof (nvme_ctrl_info_t));
	if (ci == NULL) {
		int e = errno;
		return (nvme_error(nvme, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ctrl_info: %s",
		    strerror(e)));
	}

	if ((ret = nvlist_lookup_uint32(nvl, NVME_NVL_CI_VERS, &vers)) != 0) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, ret, "failed "
		    "to get version key: %s", strerror(ret));
		goto err;
	}

	if (vers != NVME_NVL_CI_VERS_0) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, 0,
		    "found unsupported version key: 0x%x", vers);
		goto err;
	}

	ret = nvlist_lookup_pairs(nvl, 0,
	    NVME_NVL_CI_MAJOR, DATA_TYPE_UINT16, &ci->nci_vers.v_major,
	    NVME_NVL_CI_MINOR, DATA_TYPE_UINT16, &ci->nci_vers.v_minor,
	    NVME_NVL_CI_INST, DATA_TYPE_INT32, &ci->nci_inst,
	    NVME_NVL_CI_DEV_PATH, DATA_TYPE_STRING, &path,
	    NVME_NVL_CI_ID_CTRL, DATA_TYPE_BYTE_ARRAY, &ctrl, &ctrl_len,
	    NVME_NVL_CI_ID_NS, DATA_TYPE_BYTE_ARRAY, &ns, &ns_len,
	    NVME_NVL_CI_TPORT, DATA_TYPE_UINT32, &ci->nci_tport, NULL);
	if (ret != 0) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, ret,
		    "failed to retrieve required keys: %s", strerror(ret));
		goto err;
	}

	if (ci->nci_inst < 0) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, 0,
		    "instance data is negative");
		goto err;
	}

	if (ctrl_len != sizeof (ci->nci_info)) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, 0, "identify "
		    "controller information is the wrong length, expected "
		    "0x%zx bytes, found 0x%x", sizeof (ci->nci_info), ctrl_len);
		goto err;
	}

	if (ns_len != sizeof (ci->nci_ns)) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, 0, "identify "
		    "namespace information is the wrong length, expected "
		    "0x%zx bytes, found 0x%x", sizeof (ci->nci_info), ctrl_len);
		goto err;
	}

	(void) memcpy(&ci->nci_info, ctrl, ctrl_len);
	(void) memcpy(&ci->nci_ns, ns, ns_len);

	if (strlcpy(ci->nci_dev_path, path, sizeof (ci->nci_dev_path)) >=
	    sizeof (ci->nci_dev_path)) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, 0, "device "
		    "path would have overflowed");
		goto err;
	}

	if (ci->nci_tport != NVME_CTRL_TRANSPORT_PCI) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, 0, "found "
		    "unknown transport type: 0x%x", ci->nci_tport);
		goto err;
	}

	ret = nvlist_lookup_pairs(nvl, 0,
	    NVME_NVL_CI_PCI_VID, DATA_TYPE_UINT16, &ci->nci_vid,
	    NVME_NVL_CI_PCI_DID, DATA_TYPE_UINT16, &ci->nci_did,
	    NVME_NVL_CI_PCI_SUBVID, DATA_TYPE_UINT16, &ci->nci_subvid,
	    NVME_NVL_CI_PCI_SUBSYS, DATA_TYPE_UINT16, &ci->nci_subsys,
	    NVME_NVL_CI_PCI_REV, DATA_TYPE_UINT8, &ci->nci_rev,
	    NVME_NVL_CI_PCI_MPSMIN, DATA_TYPE_UINT32, &ci->nci_mps_min,
	    NVME_NVL_CI_PCI_MPSMAX, DATA_TYPE_UINT32, &ci->nci_mps_max,
	    NVME_NVL_CI_PCI_NINTRS, DATA_TYPE_UINT32, &ci->nci_nintrs, NULL);
	if (ret != 0) {
		(void) nvme_error(nvme, NVME_ERR_BAD_RESTORE, ret,
		    "failed to retrieve required PCI-specific keys: %s",
		    strerror(ret));
		goto err;
	}

	nvme_ctrl_info_init_ident(ci);
	*outp = ci;
	return (true);

err:
	nvme_ctrl_info_free(ci);
	return (false);
}

bool
nvme_ctrl_info_persist(nvme_ctrl_info_t *ci, nvlist_t **nvlp)
{
	int ret;
	nvlist_t *nvl;

	if ((ret = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL,
		    ret, "failed to create initial nvlist_t *: %s",
		    strerror(ret)));
	}

	if ((ret = nvlist_add_uint32(nvl, NVME_NVL_CI_VERS,
	    NVME_NVL_CI_VERS_0)) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist %s to nvlist: %s", NVME_NVL_CI_VERS,
		    strerror(ret)));
	}

	if ((ret = nvlist_add_int32(nvl, NVME_NVL_CI_INST, ci->nci_inst)) !=
	    0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist %s to nvlist: %s", NVME_NVL_CI_INST,
		    strerror(ret)));
	}

	if ((ret = nvlist_add_uint16(nvl, NVME_NVL_CI_MAJOR,
	    ci->nci_vers.v_major)) != 0 ||
	    (ret = nvlist_add_uint16(nvl, NVME_NVL_CI_MINOR,
	    ci->nci_vers.v_minor)) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist version data to nvlist: %s",
		    strerror(ret)));
	}

	if ((ret = nvlist_add_string(nvl, NVME_NVL_CI_DEV_PATH,
	    ci->nci_dev_path)) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist %s to nvlist: %s", NVME_NVL_CI_DEV_PATH,
		    strerror(ret)));
	}

	if ((ret = nvlist_add_byte_array(nvl, NVME_NVL_CI_ID_CTRL,
	    (void *)&ci->nci_info, sizeof (ci->nci_info))) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist %s to nvlist: %s", NVME_NVL_CI_ID_CTRL,
		    strerror(ret)));
	}

	if ((ret = nvlist_add_byte_array(nvl, NVME_NVL_CI_ID_NS,
	    (void *)&ci->nci_ns, sizeof (ci->nci_ns))) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist %s to nvlist: %s", NVME_NVL_CI_ID_NS,
		    strerror(ret)));
	}

	if ((ret = nvlist_add_uint32(nvl, NVME_NVL_CI_TPORT, ci->nci_tport)) !=
	    0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist %s to nvlist: %s", NVME_NVL_CI_TPORT,
		    strerror(ret)));
	}

	if ((ret = nvlist_add_uint16(nvl, NVME_NVL_CI_PCI_VID,
	    ci->nci_vid)) != 0 ||
	    (ret = nvlist_add_uint16(nvl, NVME_NVL_CI_PCI_DID,
	    ci->nci_did)) != 0 ||
	    (ret = nvlist_add_uint16(nvl, NVME_NVL_CI_PCI_SUBVID,
	    ci->nci_subvid)) != 0 ||
	    (ret = nvlist_add_uint16(nvl, NVME_NVL_CI_PCI_SUBSYS,
	    ci->nci_subsys)) != 0 ||
	    (ret = nvlist_add_uint8(nvl, NVME_NVL_CI_PCI_REV,
	    ci->nci_rev)) != 0 ||
	    (ret = nvlist_add_uint32(nvl, NVME_NVL_CI_PCI_MPSMIN,
	    ci->nci_mps_min)) != 0 ||
	    (ret = nvlist_add_uint32(nvl, NVME_NVL_CI_PCI_MPSMAX,
	    ci->nci_mps_max)) != 0 ||
	    (ret = nvlist_add_uint32(nvl, NVME_NVL_CI_PCI_NINTRS,
	    ci->nci_nintrs)) != 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_PERSIST_NVL, ret,
		    "failed to persist PCI data to nvlist: %s", strerror(ret)));
	}

	*nvlp = nvl;
	return (true);
}

static bool
nvme_ctrl_get_udi(nvme_ctrl_t *ctrl, di_node_t di, const char *prop,
    uint32_t *outp, uint32_t max)
{
	int *vals, nvals;

	nvals = di_prop_lookup_ints(DDI_DEV_T_ANY, di, prop, &vals);
	if (nvals < 0) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_LIBDEVINFO, e, "failed "
		    "to get property %s while constructing controller "
		    "information: %s", prop, strerror(e)));
	} else if (nvals != 1) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_DEVI_PROP, 0,
		    "found unexpected number of property values for %s while "
		    "constructing controller information, expected 1, found %d",
		    prop, nvals));
	}

	if (vals[0] < 0 || vals[0] > max) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_DEVI_PROP, 0,
		    "property %s has value 0x%x outside the allowed range "
		    "[0x0, 0x%x]", prop, vals[0], max));
	}

	*outp = (uint32_t)vals[0];
	return (true);
}

bool
nvme_ctrl_info_snap(nvme_ctrl_t *ctrl, nvme_ctrl_info_t **outp)
{
	nvme_ctrl_info_t *ci;
	uint32_t val;
	nvme_ioctl_ctrl_info_t info;

	if (outp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ctrl_info_t output pointer: %p",
		    outp));
	}
	*outp = NULL;

	ci = calloc(1, sizeof (nvme_ctrl_info_t));
	if (ci == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ctrl_info: %s",
		    strerror(e)));
	}

	if (!nvme_ctrl_get_udi(ctrl, ctrl->nc_devi, "vendor-id", &val,
	    UINT16_MAX)) {
		goto err;
	}
	ci->nci_vid = (uint16_t)val;

	if (!nvme_ctrl_get_udi(ctrl, ctrl->nc_devi, "device-id", &val,
	    UINT16_MAX)) {
		goto err;
	}
	ci->nci_did = (uint16_t)val;

	/*
	 * The system will not create a subsystem-vendor-id or a subsystem-id if
	 * the subsytem vendor is zero. This should not be a fatal error.
	 * However, if a subsytem-vendor-id is present then we should expect a
	 * subsystem-id.
	 */
	if (nvme_ctrl_get_udi(ctrl, ctrl->nc_devi, "subsystem-vendor-id", &val,
	    UINT16_MAX)) {
		ci->nci_subvid = (uint16_t)val;

		if (!nvme_ctrl_get_udi(ctrl, ctrl->nc_devi, "subsystem-id",
		    &val, UINT16_MAX)) {
			goto err;
		}
	} else {
		ci->nci_subvid = 0;
		ci->nci_subsys = 0;
	}

	if (!nvme_ctrl_get_udi(ctrl, ctrl->nc_devi, "revision-id", &val,
	    UINT8_MAX)) {
		goto err;
	}
	ci->nci_rev = (uint8_t)val;

	/*
	 * As we only support PCI based NVMe devices right now, we simply always
	 * identify everything as PCI based. In the future, this would be
	 * something we'd want to get from either an ioctl or a devinfo
	 * property.
	 */
	ci->nci_tport = NVME_CTRL_TRANSPORT_PCI;

	if (!nvme_ioc_ctrl_info(ctrl, &info)) {
		goto err;
	}

	ci->nci_vers = info.nci_vers;
	ci->nci_info = info.nci_ctrl_id;
	ci->nci_ns = info.nci_common_ns;
	ci->nci_mps_min = info.nci_caps.cap_mpsmin;
	ci->nci_mps_max = info.nci_caps.cap_mpsmax;
	ci->nci_nintrs = info.nci_nintrs;

	nvme_ctrl_info_init_ident(ci);
	*outp = ci;
	return (nvme_ctrl_success(ctrl));

err:
	nvme_ctrl_info_free(ci);
	return (false);
}

uint16_t
nvme_ctrl_info_vendor(nvme_ctrl_info_t *ci)
{
	return (ci->nci_info.id_vid);
}

const char *
nvme_ctrl_info_model(nvme_ctrl_info_t *ci)
{
	return (ci->nci_model);
}

const char *
nvme_ctrl_info_serial(nvme_ctrl_info_t *ci)
{
	return (ci->nci_serial);
}

uint32_t
nvme_ctrl_info_fwgran(nvme_ctrl_info_t *ci)
{
	nvme_valid_ctrl_data_t data;

	data.vcd_vers = &ci->nci_vers;
	data.vcd_id = &ci->nci_info;
	return (nvme_fw_load_granularity(&data));
}

const char *
nvme_ctrl_info_fwrev(nvme_ctrl_info_t *ci)
{
	return (ci->nci_fwrev);
}

const nvme_identify_ctrl_t *
nvme_ctrl_info_identify(nvme_ctrl_info_t *ci)
{
	return (&ci->nci_info);
}

const nvme_version_t *
nvme_ctrl_info_version(nvme_ctrl_info_t *ci)
{
	return (&ci->nci_vers);
}

nvme_ctrl_transport_t
nvme_ctrl_info_transport(nvme_ctrl_info_t *ci)
{
	return (ci->nci_tport);
}

nvme_ctrl_type_t
nvme_ctrl_info_type(nvme_ctrl_info_t *ci)
{
	if (nvme_vers_ctrl_info_atleast(ci, &nvme_vers_1v4)) {
		switch (ci->nci_info.id_cntrltype) {
		case NVME_CNTRLTYPE_IO:
			return (NVME_CTRL_TYPE_IO);
		case NVME_CNTRLTYPE_DISC:
			return (NVME_CTRL_TYPE_DISCOVERY);
		case NVME_CNTRLTYPE_ADMIN:
			return (NVME_CTRL_TYPE_ADMIN);
		default:
			return (NVME_CTRL_TYPE_UNKNOWN);
		}
	} else {
		return (NVME_CTRL_TYPE_IO);
	}
}

static bool
nvme_ctrl_info_pci_tport(nvme_ctrl_info_t *ci)
{
	if (ci->nci_tport != NVME_CTRL_TRANSPORT_PCI) {
		return (nvme_info_error(ci, NVME_INFO_ERR_TRANSPORT, 0,
		    "cannot get PCI data from device with type %s (0x%x)",
		    nvme_tporttostr(ci->nci_tport), ci->nci_tport));
	}

	return (true);
}

bool
nvme_ctrl_info_pci_vid(nvme_ctrl_info_t *ci, uint16_t *u16p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u16p = ci->nci_vid;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_did(nvme_ctrl_info_t *ci, uint16_t *u16p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u16p = ci->nci_did;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_subvid(nvme_ctrl_info_t *ci, uint16_t *u16p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u16p = ci->nci_subvid;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_subsys(nvme_ctrl_info_t *ci, uint16_t *u16p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u16p = ci->nci_subsys;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_rev(nvme_ctrl_info_t *ci, uint8_t *u8p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u8p = ci->nci_rev;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_mps_min(nvme_ctrl_info_t *ci, uint32_t *u32p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u32p = ci->nci_mps_min;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_mps_max(nvme_ctrl_info_t *ci, uint32_t *u32p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u32p = ci->nci_mps_max;
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_pci_nintrs(nvme_ctrl_info_t *ci, uint32_t *u32p)
{
	if (!nvme_ctrl_info_pci_tport(ci))
		return (false);

	*u32p = ci->nci_nintrs;
	return (nvme_info_success(ci));
}

static bool
nvme_ctrl_info_nsmgmt(nvme_ctrl_info_t *ci)
{
	if (!nvme_vers_ctrl_info_atleast(ci, &nvme_vers_1v2)) {
		return (nvme_info_error(ci, NVME_INFO_ERR_VERSION, 0,
		    "cannot provide information, device must be at least "
		    "version 1.2, but is %u.%u", ci->nci_vers.v_major,
		    ci->nci_vers.v_minor));
	}

	if (ci->nci_info.id_oacs.oa_nsmgmt == 0) {
		return (nvme_info_error(ci, NVME_INFO_ERR_MISSING_CAP, 0,
		    "cannot provide information, device does not support "
		    "namespace management"));

	}

	return (true);
}

bool
nvme_ctrl_info_cap(nvme_ctrl_info_t *ci, nvme_uint128_t *u128p)
{
	if (!nvme_ctrl_info_nsmgmt(ci)) {
		return (false);
	}

	(void) memcpy(u128p, &ci->nci_info.ap_tnvmcap, sizeof (nvme_uint128_t));
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_unalloc_cap(nvme_ctrl_info_t *ci, nvme_uint128_t *u128p)
{
	if (!nvme_ctrl_info_nsmgmt(ci)) {
		return (false);
	}

	(void) memcpy(u128p, &ci->nci_info.ap_unvmcap, sizeof (nvme_uint128_t));
	return (nvme_info_success(ci));
}

bool
nvme_ctrl_info_common_ns(nvme_ctrl_info_t *ci, const nvme_identify_nsid_t **idp)
{
	if (!nvme_ctrl_info_nsmgmt(ci)) {
		return (false);
	}

	*idp = &ci->nci_ns;
	return (nvme_info_success(ci));
}

uint32_t
nvme_ctrl_info_nformats(nvme_ctrl_info_t *ci)
{
	return (MIN(ci->nci_ns.id_nlbaf + 1, NVME_MAX_LBAF));
}

uint32_t
nvme_ctrl_info_nns(nvme_ctrl_info_t *ci)
{
	return (ci->nci_info.id_nn);
}

bool
nvme_ctrl_info_format(nvme_ctrl_info_t *ci, uint32_t idx,
    const nvme_nvm_lba_fmt_t **outp)
{
	const uint32_t max = nvme_ctrl_info_nformats(ci);
	if (idx >= max) {
		return (nvme_info_error(ci, NVME_INFO_ERR_BAD_FMT, 0,
		    "requested index %u is invalid: valid range is [0, %u]",
		    idx, max - 1));
	}

	if (!ci->nci_lbaf_valid[idx]) {
		uint8_t lbads = ci->nci_ns.id_lbaf[idx].lbaf_lbads;

		if (lbads == 0) {
			return (nvme_info_error(ci, NVME_INFO_ERR_BAD_FMT, 0,
			    "format %u is not actually valid due to 0 LBA "
			    "data size even though it is considered a valid "
			    "LBA format by NLBAF", lbads));
		}

		if (lbads < 9) {
			return (nvme_info_error(ci, NVME_INFO_ERR_BAD_FMT_DATA,
			    0, "NVMe devices are not allowed to have a LBA "
			    "data size of less than 512 bytes, found raw "
			    "shift value of %u for format %u", lbads, idx));
		}

		if (lbads >= 64) {
			return (nvme_info_error(ci, NVME_INFO_ERR_BAD_FMT_DATA,
			    0, "LBA format %u has LBA data size greater "
			    "than 64 (%u), cannot be represented as a byte "
			    "size", idx, lbads));
		}

		ci->nci_lbaf[idx].nnlf_id = idx;
		ci->nci_lbaf[idx].nnlf_ms = ci->nci_ns.id_lbaf[idx].lbaf_ms;
		ci->nci_lbaf[idx].nnlf_lbasz = 1ULL << lbads;
		ci->nci_lbaf[idx].nnlf_rel = ci->nci_ns.id_lbaf[idx].lbaf_rp;
		ci->nci_lbaf_valid[idx] = true;
	}

	*outp = &ci->nci_lbaf[idx];
	return (nvme_info_success(ci));
}

uint32_t
nvme_nvm_lba_fmt_id(const nvme_nvm_lba_fmt_t *lbaf)
{
	return (lbaf->nnlf_id);
}

uint32_t
nvme_nvm_lba_fmt_meta_size(const nvme_nvm_lba_fmt_t *lbaf)
{
	return (lbaf->nnlf_ms);
}

uint64_t
nvme_nvm_lba_fmt_data_size(const nvme_nvm_lba_fmt_t *lbaf)
{
	return (lbaf->nnlf_lbasz);
}

uint32_t
nvme_nvm_lba_fmt_rel_perf(const nvme_nvm_lba_fmt_t *lbaf)
{
	return (lbaf->nnlf_rel);
}
