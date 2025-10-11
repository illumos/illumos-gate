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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * I2C Controller related functions.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "libi2c_impl.h"

void
i2c_ctrl_discover_fini(i2c_ctrl_iter_t *iter)
{
	if (iter == NULL)
		return;

	di_fini(iter->ci_root);
	free(iter);
}

i2c_iter_t
i2c_ctrl_discover_step(i2c_ctrl_iter_t *iter, const i2c_ctrl_disc_t **discp)
{
	*discp = NULL;

	if (iter->ci_done) {
		return (I2C_ITER_DONE);
	}

	for (;;) {
		if (iter->ci_cur == DI_NODE_NIL) {
			iter->ci_cur = di_drv_first_node(I2C_NEX_DRV,
			    iter->ci_root);
		} else {
			iter->ci_cur = di_drv_next_node(iter->ci_cur);
		}

		if (iter->ci_cur == DI_NODE_NIL) {
			iter->ci_done = true;
			return (I2C_ITER_DONE);
		}

		if (!i2c_node_is_type(iter->ci_cur, I2C_NODE_T_CTRL)) {
			continue;
		}

		iter->ci_disc.icd_devi = iter->ci_cur;
		iter->ci_disc.icd_minor = i2c_node_minor(iter->ci_cur);
		if (iter->ci_disc.icd_minor == DI_MINOR_NIL) {
			continue;
		}

		*discp = &iter->ci_disc;
		return (I2C_ITER_VALID);
	}

	return (I2C_ITER_DONE);
}

bool
i2c_ctrl_discover_init(i2c_hdl_t *hdl, i2c_ctrl_iter_t **iterp)
{
	i2c_ctrl_iter_t *iter;

	if (iterp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_ctrl_iter_t output pointer: %p", iterp));
	}

	iter = calloc(1, sizeof (i2c_ctrl_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_ctrl_iter_t"));
	}

	iter->ci_hdl = hdl;
	iter->ci_root = di_init("/", DINFOCPYALL);
	if (iter->ci_root == NULL) {
		int e = errno;
		i2c_ctrl_discover_fini(iter);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "initialize devinfo snapshot: %s", strerrordesc_np(e)));
	}
	iter->ci_done = false;
	iter->ci_cur = DI_NODE_NIL;

	*iterp = iter;
	return (i2c_success(hdl));
}

bool
i2c_ctrl_discover(i2c_hdl_t *hdl, i2c_ctrl_disc_f func, void *arg)
{
	i2c_ctrl_iter_t *iter;
	const i2c_ctrl_disc_t *disc;
	i2c_iter_t ret;

	if (func == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_ctrl_disc_f function pointer: %p", func));
	}

	if (!i2c_ctrl_discover_init(hdl, &iter)) {
		return (false);
	}

	while ((ret = i2c_ctrl_discover_step(iter, &disc)) == I2C_ITER_VALID) {
		if (!func(hdl, disc, arg))
			break;
	}

	i2c_ctrl_discover_fini(iter);
	if (ret == I2C_ITER_ERROR) {
		return (false);
	}

	return (i2c_success(hdl));
}

di_node_t
i2c_ctrl_disc_devi(const i2c_ctrl_disc_t *discp)
{
	return (discp->icd_devi);
}

di_minor_t
i2c_ctrl_disc_minor(const i2c_ctrl_disc_t *discp)
{
	return (discp->icd_minor);
}

void
i2c_ctrl_fini(i2c_ctrl_t *ctrl)
{
	if (ctrl == NULL) {
		return;
	}

	if (ctrl->ctrl_fd >= 0) {
		(void) close(ctrl->ctrl_fd);
	}

	di_devfs_path_free(ctrl->ctrl_minor);
	di_devfs_path_free(ctrl->ctrl_path);
	free(ctrl->ctrl_name);
	free(ctrl);
}

bool
i2c_ctrl_init(i2c_hdl_t *hdl, di_node_t di, i2c_ctrl_t **ctrlp)
{
	di_minor_t minor;
	i2c_ctrl_t *ctrl;
	ui2c_ctrl_nprops_t nprops;

	if (di == DI_NODE_NIL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid di_node_t: %p", di));
	}

	if (ctrlp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_ctrl_t output pointer: %p", ctrlp));
	}

	if (!i2c_node_is_type(di, I2C_NODE_T_CTRL)) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s isn't "
		    "an i2c controller", di_node_name(di), di_bus_addr(di)));
	}

	/*
	 * See if we can find a minor node that corresponds to a controller
	 * nexus.
	 */
	minor = i2c_node_minor(di);
	if (minor == DI_MINOR_NIL) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s is "
		    "not an i2c controller: failed to find controller minor",
		    di_node_name(di), di_bus_addr(di)));
	}

	ctrl = calloc(1, sizeof (i2c_ctrl_t));
	if (ctrl == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_ctrl_t"));
	}

	ctrl->ctrl_fd = -1;
	ctrl->ctrl_hdl = hdl;
	ctrl->ctrl_inst = di_instance(di);
	ctrl->ctrl_name = strdup(di_bus_addr(di));
	if (ctrl->ctrl_name == NULL) {
		int e = errno;
		i2c_ctrl_fini(ctrl);
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to duplicate "
		    "controller bus address"));
	}

	ctrl->ctrl_path = di_devfs_path(di);
	if (ctrl->ctrl_path == NULL) {
		int e = errno;
		i2c_ctrl_fini(ctrl);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "obtain controller's devfs path: %s", strerrordesc_np(e)));
	}

	ctrl->ctrl_minor = di_devfs_minor_path(minor);
	if (ctrl->ctrl_minor == NULL) {
		int e = errno;
		i2c_ctrl_fini(ctrl);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "obtain controller's minor path: %s", strerrordesc_np(e)));
	}

	ctrl->ctrl_fd = openat(hdl->ih_devfd, ctrl->ctrl_minor + 1, O_RDWR);
	if (ctrl->ctrl_fd < 0) {
		int e = errno;
		(void) i2c_error(hdl, I2C_ERR_OPEN_DEV, e, "failed to open "
		    "device path '/devices%s: %s", ctrl->ctrl_minor,
		    strerrordesc_np(e));
		i2c_ctrl_fini(ctrl);
		return (false);
	}

	if (ioctl(ctrl->ctrl_fd, UI2C_IOCTL_CTRL_NPROPS, &nprops) != 0) {
		int e = errno;
		i2c_ctrl_fini(ctrl);
		return (i2c_ioctl_syserror(hdl, e, "controller nprops "
		    "request"));
	}
	ctrl->ctrl_nstd = nprops.ucp_nstd;
	ctrl->ctrl_npriv = nprops.ucp_npriv;

	*ctrlp = ctrl;
	return (i2c_success(hdl));
}

bool
i2c_ctrl_init_by_path(i2c_hdl_t *hdl, const char *name, i2c_ctrl_t **ctrlp)
{
	i2c_node_type_t type;
	di_node_t dn, root;

	if (name == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c controller name: %p", name));
	}

	if (ctrlp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_ctrl_t output pointer: %p", ctrlp));
	}

	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "initialize devinfo snapshot: %s", strerrordesc_np(e)));
	}

	if (!i2c_path_parse(hdl, name, root, &dn, &type,
	    I2C_ERR_BAD_CONTROLLER)) {
		di_fini(root);
		return (false);
	}

	if (type != I2C_NODE_T_CTRL) {
		di_fini(root);
		return (i2c_error(hdl, I2C_ERR_BAD_CONTROLLER, 0, "parsed I2C "
		    "path %s did not end at a controller", name));
	}

	bool ret = i2c_ctrl_init(hdl, dn, ctrlp);
	di_fini(root);
	return (ret);
}

const char *
i2c_ctrl_name(i2c_ctrl_t *ctrl)
{
	return (ctrl->ctrl_name);
}

int32_t
i2c_ctrl_instance(i2c_ctrl_t *ctrl)
{
	return (ctrl->ctrl_inst);
}

const char *
i2c_ctrl_path(i2c_ctrl_t *ctrl)
{
	return (ctrl->ctrl_path);
}

uint32_t
i2c_ctrl_nprops(i2c_ctrl_t *ctrl)
{
	/*
	 * Currently we only have standard properties. If we have
	 * controller-specific properties in the future then those should be
	 * added to this.
	 */
	return (ctrl->ctrl_nstd);
}

const char *
i2c_prop_info_name(i2c_prop_info_t *info)
{
	return (info->pinfo_info.upi_name);
}

i2c_prop_t
i2c_prop_info_id(i2c_prop_info_t *info)
{
	return (info->pinfo_info.upi_prop);
}

i2c_prop_type_t
i2c_prop_info_type(i2c_prop_info_t *info)
{
	return (info->pinfo_info.upi_type);
}

bool
i2c_prop_info_sup(i2c_prop_info_t *info)
{
	return (info->pinfo_sup);
}

i2c_prop_perm_t
i2c_prop_info_perm(i2c_prop_info_t *info)
{
	return (info->pinfo_info.upi_perm);
}

bool
i2c_prop_info_def_u32(i2c_prop_info_t *info, uint32_t *defp)
{
	i2c_hdl_t *hdl = info->pinfo_hdl;

	if (defp == NULL) {

	}

	if (!info->pinfo_sup) {
		return (i2c_error(hdl, I2C_ERR_PROP_UNSUP, 0, "default value "
		    "is unavailable because property %s is not supported by "
		    "the controller", info->pinfo_info.upi_name));
	}

	switch (info->pinfo_info.upi_type) {
	case I2C_PROP_TYPE_U32:
	case I2C_PROP_TYPE_BIT32:
		if (info->pinfo_info.upi_def_len != sizeof (uint32_t)) {
			return (i2c_error(hdl, I2C_ERR_PROP_TYPE_MISMATCH, 0,
			    "property %s does not have a default value",
			    info->pinfo_info.upi_name));
		}
		(void) memcpy(defp, info->pinfo_info.upi_def,
		    sizeof (uint32_t));
		break;
	default:
		return (i2c_error(hdl, I2C_ERR_PROP_TYPE_MISMATCH, 0,
		    "property %s default value does not have a 32-bit "
		    "integer type (found type 0x%x)", info->pinfo_info.upi_name,
		    info->pinfo_info.upi_type));
		break;
	}

	return (i2c_success(hdl));
}

const i2c_prop_range_t *
i2c_prop_info_pos(i2c_prop_info_t *info)
{
	if (!info->pinfo_sup || info->pinfo_info.upi_pos_len <
	    sizeof (i2c_prop_range_t)) {
		return (NULL);
	}

	return ((i2c_prop_range_t *)info->pinfo_info.upi_pos);
}

void
i2c_prop_info_free(i2c_prop_info_t *info)
{
	free(info);
}

bool
i2c_prop_info(i2c_ctrl_t *ctrl, i2c_prop_t prop, i2c_prop_info_t **infop)
{
	i2c_hdl_t *hdl = ctrl->ctrl_hdl;
	i2c_prop_info_t *info;

	if (infop == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_prop_info_t output pointer: %p", infop));
	}

	info = calloc(1, sizeof (i2c_prop_info_t));
	if (info == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_prop_info_t"));
	}

	info->pinfo_info.upi_prop = prop;
	if (ioctl(ctrl->ctrl_fd, UI2C_IOCTL_CTRL_PROP_INFO,
	    &info->pinfo_info) != 0) {
		int e = errno;
		return (i2c_ioctl_syserror(hdl, e, "property info request"));
	}

	i2c_error_t *err = &info->pinfo_info.upi_error;
	if (err->i2c_error != I2C_CORE_E_OK &&
	    err->i2c_error != I2C_PROP_E_UNSUP) {
		free(info);
		return (i2c_ioctl_error(hdl, err, "property info request"));
	}

	info->pinfo_hdl = hdl;
	info->pinfo_sup = err->i2c_error == I2C_CORE_E_OK;
	*infop = info;
	return (i2c_success(hdl));
}

/*
 * Find the property that maps to name the max power way. Basically iterate over
 * all known properties and see if the name matches.
 */
bool
i2c_prop_info_by_name(i2c_ctrl_t *ctrl, const char *name,
    i2c_prop_info_t **infop)
{
	i2c_hdl_t *hdl = ctrl->ctrl_hdl;
	i2c_prop_info_t *info;

	if (name == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid property name pointer: %p", name));
	}

	if (infop == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_prop_info_t output pointer: %p", infop));
	}

	for (uint32_t i = 0; i < ctrl->ctrl_nstd; i++) {
		if (!i2c_prop_info(ctrl, i, &info)) {
			return (false);
		}

		if (strcmp(name, i2c_prop_info_name(info)) == 0) {
			*infop = info;
			return (i2c_success(hdl));
		}

		i2c_prop_info_free(info);
	}

	return (i2c_error(hdl, I2C_ERR_BAD_PROP, 0, "unkonwn property: %s",
	    name));
}

bool
i2c_prop_get(i2c_ctrl_t *ctrl, i2c_prop_t id, void *buf, size_t *lenp)
{
	i2c_hdl_t *hdl = ctrl->ctrl_hdl;
	ui2c_prop_t prop;

	if (buf == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid property data buffer pointer: %p", buf));
	}

	if (lenp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid property size pointer: %p", buf));
	}

	(void) memset(&prop, 0, sizeof (ui2c_prop_t));
	prop.up_prop = id;

	if (ioctl(ctrl->ctrl_fd, UI2C_IOCTL_CTRL_PROP_GET, &prop) != 0) {
		int e = errno;
		return (i2c_ioctl_syserror(hdl, e, "property get request"));
	}

	if (prop.up_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &prop.up_error,
		    "property get request"));
	}

	size_t orig = *lenp;
	*lenp = prop.up_size;
	if (orig < prop.up_size) {
		return (i2c_error(hdl, I2C_ERR_PROP_BUF_TOO_SMALL, 0,
		    "property requires %u bytes to hold data, but only passed "
		    "a buffer of %zu bytes", prop.up_size, orig));
	}

	(void) memcpy(buf, prop.up_value, prop.up_size);
	return (i2c_success(hdl));
}

bool
i2c_prop_set(i2c_ctrl_t *ctrl, i2c_prop_t id, const void *buf, size_t len)
{
	i2c_hdl_t *hdl = ctrl->ctrl_hdl;
	ui2c_prop_t prop;

	if (buf == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid property data buffer pointer: %p", buf));
	}

	if (len == 0) {
		return (i2c_error(hdl, I2C_ERR_PROP_BUF_TOO_SMALL, 0,
		    "property buffer length must be more than 0"));
	}

	if (len > I2C_PROP_SIZE_MAX) {
		return (i2c_error(hdl, I2C_ERR_PROP_BUF_TOO_BIG, 0,
		    "property buffer length must be less than or equal to %u",
		    I2C_PROP_SIZE_MAX));
	}

	(void) memset(&prop, 0, sizeof (ui2c_prop_t));
	prop.up_prop = id;
	prop.up_size = len;
	(void) memcpy(&prop.up_value, buf, len);

	if (ioctl(ctrl->ctrl_fd, UI2C_IOCTL_CTRL_PROP_SET, &prop) != 0) {
		int e = errno;
		return (i2c_ioctl_syserror(hdl, e, "property set request"));
	}

	if (prop.up_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &prop.up_error,
		    "property set request"));
	}

	return (i2c_success(hdl));
}
