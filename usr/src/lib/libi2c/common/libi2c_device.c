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
 * Device addition, removal, and discovery
 */

#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <fcntl.h>

#include "libi2c_impl.h"

void
i2c_device_add_req_fini(i2c_dev_add_req_t *req)
{
	nvlist_free(req->add_nvl);
	free(req);
}

bool
i2c_device_add_req_init(i2c_port_t *port, i2c_dev_add_req_t **reqp)
{
	i2c_hdl_t *hdl = port->port_hdl;
	i2c_dev_add_req_t *req;

	if (reqp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_dev_add_req_t output pointer: %p", reqp));
	}

	req = calloc(1, sizeof (i2c_dev_add_req_t));
	if (req == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_dev_add_req_t"));
	}
	req->add_port = port;
	req->add_need = I2C_DEV_ADD_REQ_FIELD_NAME | I2C_DEV_ADD_REQ_FIELD_ADDR;

	int ret = nvlist_alloc(&req->add_nvl, NV_UNIQUE_NAME, 0);
	if (!i2c_nvlist_error(hdl, ret, "create a nvlist")) {
		free(req);
		return (false);
	}

	*reqp = req;
	return (i2c_success(hdl));
}

bool
i2c_device_add_req_set_addr(i2c_dev_add_req_t *req, const i2c_addr_t *addr)
{
	int ret;
	i2c_hdl_t *hdl = req->add_port->port_hdl;

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	if (!i2c_addr_validate(hdl, addr)) {
		return (false);
	}

	ret = nvlist_add_uint16(req->add_nvl, UI2C_IOCTL_NVL_TYPE,
	    addr->ia_type);
	if (!i2c_nvlist_error(hdl, ret, "insert address type")) {
		return (false);
	}

	ret = nvlist_add_uint16(req->add_nvl, UI2C_IOCTL_NVL_ADDR,
	    addr->ia_addr);
	if (!i2c_nvlist_error(hdl, ret, "insert address type")) {
		return (false);
	}

	req->add_need &= ~I2C_DEV_ADD_REQ_FIELD_ADDR;
	return (i2c_success(hdl));
}

bool
i2c_device_add_req_set_name(i2c_dev_add_req_t *req, const char *name)
{
	i2c_hdl_t *hdl = req->add_port->port_hdl;

	if (!i2c_name_validate(hdl, name, "name")) {
		return (false);
	}

	int ret = nvlist_add_string(req->add_nvl, UI2C_IOCTL_NVL_NAME, name);
	if (!i2c_nvlist_error(hdl, ret, "insert name string")) {
		return (false);
	}

	req->add_need &= ~I2C_DEV_ADD_REQ_FIELD_NAME;
	return (i2c_success(hdl));
}

bool
i2c_device_add_req_set_compatible(i2c_dev_add_req_t *req, char *const *compat,
    size_t ncompat)
{
	i2c_hdl_t *hdl = req->add_port->port_hdl;

	/*
	 * Treat this as a request to clear the optional compatible information.
	 */
	if (compat == NULL && ncompat == 0) {
		int ret = nvlist_remove(req->add_nvl, UI2C_IOCTL_NVL_COMPAT,
		    DATA_TYPE_STRING_ARRAY);
		if (ret == 0 || ret == ENOENT) {
			return (i2c_success(hdl));
		}
		return (i2c_error(hdl, I2C_ERR_INTERNAL, ret, "unexpected "
		    "internal error while trying to clear compatible[]"));
	}

	if (compat == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid compatible pointer: %p", compat));
	} else if (ncompat == 0) {
		return (i2c_error(hdl, I2C_ERR_COMPAT_LEN_RANGE, 0, "number "
		    "of compatible entries cannot be zero when given a "
		    "non-NULL pointer (%p)", compat));
	} else if (ncompat > UI2C_IOCTL_NVL_NCOMPAT_MAX) {
		return (i2c_error(hdl, I2C_ERR_COMPAT_LEN_RANGE, 0, "device "
		    "compatible array is too long (%zu), valid range is [1, "
		    "%u]", ncompat, UI2C_IOCTL_NVL_NCOMPAT_MAX));
	}

	for (size_t i = 0; i < ncompat; i++) {
		char desc[64];

		(void) snprintf(desc, sizeof (desc), "compatible[%u]", i);
		if (!i2c_name_validate(hdl, compat[i], desc)) {
			return (false);
		}
	}

	int ret = nvlist_add_string_array(req->add_nvl, UI2C_IOCTL_NVL_COMPAT,
	    compat, ncompat);
	if (!i2c_nvlist_error(hdl, ret, "insert compatible string[]")) {
		return (false);
	}
	return (i2c_success(hdl));
}

bool
i2c_device_add_req_exec(i2c_dev_add_req_t *req)
{
	i2c_hdl_t *hdl = req->add_port->port_hdl;
	size_t pack_size;
	char *pack_buf = NULL;
	int nvl_ret;
	bool ret = false;
	ui2c_dev_add_t dev;

	if (req->add_need != 0) {
		char buf[128];
		bool comma = false;

		buf[0] = '\0';
		if ((req->add_need & I2C_DEV_ADD_REQ_FIELD_ADDR) != 0) {
			(void) strlcat(buf, "device address", sizeof (buf));
			comma = true;
		}

		if ((req->add_need & I2C_DEV_ADD_REQ_FIELD_NAME) != 0) {
			if (comma) {
				(void) strlcat(buf, ",", sizeof (buf));
			}
			(void) strlcat(buf, "name", sizeof (buf));
			comma = true;
		}

		return (i2c_error(hdl, I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS, 0,
		    "cannot execute add device request due to missing fields: "
		    "%s", buf));
	}

	nvl_ret = nvlist_size(req->add_nvl, &pack_size, NV_ENCODE_NATIVE);
	if (!i2c_nvlist_error(hdl, nvl_ret, "determine packed nvlist size")) {
		goto out;
	}

	pack_buf = malloc(pack_size);
	if (pack_buf == NULL) {
		ret = i2c_error(hdl, I2C_ERR_NO_MEM, errno, "failed to "
		    "allocate %zu bytes for packed request nvlist", pack_size);
		goto out;
	}

	nvl_ret = nvlist_pack(req->add_nvl, &pack_buf, &pack_size,
	    NV_ENCODE_NATIVE, 0);
	if (!i2c_nvlist_error(hdl, nvl_ret, "pack request nvlist")) {
		goto out;
	}

	(void) memset(&dev, 0, sizeof (ui2c_dev_add_t));
	dev.uda_nvl = (uintptr_t)pack_buf;
	dev.uda_nvl_len = pack_size;

	if (ioctl(req->add_port->port_fd, UI2C_IOCTL_DEVICE_ADD, &dev) != 0) {
		int e = errno;
		ret = i2c_ioctl_syserror(hdl, e, "add device request");
		goto out;
	}

	if (dev.uda_error.i2c_error != I2C_CORE_E_OK) {
		ret = i2c_ioctl_error(hdl, &dev.uda_error,
		    "add device request");
		goto out;
	}

	ret = i2c_success(hdl);
out:
	free(pack_buf);
	return (ret);
}

bool
i2c_device_rem(i2c_port_t *port, const i2c_addr_t *addr)
{
	ui2c_dev_rem_t rem;
	i2c_hdl_t *hdl = port->port_hdl;

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	if (!i2c_addr_validate(hdl, addr)) {
		return (false);
	}

	(void) memset(&rem, 0, sizeof (ui2c_dev_rem_t));
	rem.udr_addr = *addr;

	if (ioctl(port->port_fd, UI2C_IOCTL_DEVICE_REMOVE, &rem) != 0) {
		int e = errno;
		return (i2c_ioctl_syserror(hdl, e, "remove device request"));
	}

	if (rem.udr_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &rem.udr_error,
		    "remove device request"));
	}

	return (i2c_success(hdl));
}

void
i2c_device_discover_fini(i2c_dev_iter_t *iter)
{
	if (iter == NULL)
		return;

	i2c_port_discover_fini(iter->di_iter);
	free(iter);
}

/*
 * Fill information about the device's under this single port per the notes in
 * i2c_device_discover_step().
 */
static bool
i2c_device_discover_port(i2c_hdl_t *hdl, dev_port_info_t *dpi)
{
	for (di_minor_t m = di_minor_next(dpi->dpi_port, DI_MINOR_NIL);
	    m != DI_MINOR_NIL; m = di_minor_next(dpi->dpi_port, m)) {
		i2c_addr_t addr;

		if (strcmp(di_minor_nodetype(m), DDI_NT_I2C_DEV) != 0)
			continue;

		if (!i2c_kernel_address_parse(hdl, di_minor_name(m), &addr)) {
			return (false);
		}

		if (addr.ia_type == I2C_ADDR_7BIT) {
			dpi->dpi_7b[addr.ia_addr].dmi_minor = m;
		} else {
			dpi->dpi_10b[addr.ia_addr].dmi_minor = m;
		}
	}

	/*
	 * Now go through all of our children and try to map them to something
	 * we know.
	 */
	for (di_node_t di = di_child_node(dpi->dpi_port); di != DI_NODE_NIL;
	    di = di_sibling_node(di)) {
		i2c_addr_t addr;

		if (i2c_node_type(di) != I2C_NODE_T_DEV) {
			continue;
		}

		/*
		 * For the purposes of iteration we order devices by the first
		 * address that they have in their regs[] array. We assume that
		 * this will be the primary one. We will skip cases where we
		 * have a minor but not a devinfo in this list.
		 */
		if (!i2c_reg_to_addr(hdl, di, &addr, 0)) {
			return (false);
		}

		if (addr.ia_type == I2C_ADDR_7BIT) {
			dpi->dpi_7b[addr.ia_addr].dmi_node = di;
		} else {
			dpi->dpi_10b[addr.ia_addr].dmi_node = di;
		}
	}

	return (true);
}

static bool
i2c_device_discover_one(i2c_dev_iter_t *iter, dev_map_info_t *map)
{
	iter->di_disc.idd_map = map;
	iter->di_disc.idd_port = &iter->di_info;
	if (!i2c_node_to_path(iter->di_hdl, map->dmi_node,
	    iter->di_disc.idd_path, sizeof (iter->di_disc.idd_path))) {
		return (false);
	}

	return (true);
}

/*
 * Device discovery starts by walking the last of I2C ports. After that we
 * proceed to try to walk all of the immediate children. The port has a list of
 * all of the minors that are I2C devices. So we first gather that up and marry
 * it up to the actual dev_info nodes in the snapshot. The minor node will be
 * created while we're creating the child node and we should only see one if we
 * see the other. By walking the minor node list, this gives us a way to ignore
 * dev info nodes that end up under the port that aren't actually in-band
 * devices (e.g. a non-in-band mux).
 */
i2c_iter_t
i2c_device_discover_step(i2c_dev_iter_t *iter, const i2c_dev_disc_t **discp)
{
	for (;;) {
		/*
		 * First check if we're already done or if we're taking a lap
		 * because we've processed all ports.
		 */
		if (iter->di_done) {
			return (I2C_ITER_DONE);
		}

		if (iter->di_curport == NULL) {
			i2c_iter_t iret = i2c_port_discover_step(iter->di_iter,
			    &iter->di_curport);
			if (iret == I2C_ITER_DONE) {
				iter->di_done = true;
				return (I2C_ITER_DONE);
			} else if (iret != I2C_ITER_VALID) {
				return (iret);
			}

			memset(&iter->di_info, 0, sizeof (dev_port_info_t));
			iter->di_info.dpi_port =
			    i2c_port_disc_devi(iter->di_curport);
		}

		/*
		 * See if we have minor info for this port yet. If not, we go
		 * and build it.
		 */
		dev_port_info_t *pi = &iter->di_info;
		if (!pi->dpi_scanned) {
			pi->dpi_scanned = true;
			if (!i2c_device_discover_port(iter->di_hdl, pi)) {
				return (I2C_ITER_ERROR);
			}
		}

		/*
		 * Is this port done, if so move onto the next.
		 */
		if (pi->dpi_7bit_done && pi->dpi_10bit_done) {
			iter->di_curport = NULL;
			continue;
		}

		if (!pi->dpi_7bit_done) {
			while (pi->dpi_curidx < ARRAY_SIZE(pi->dpi_7b)) {
				dev_map_info_t *map =
				    &pi->dpi_7b[pi->dpi_curidx];
				pi->dpi_curidx++;
				if (map->dmi_minor == DI_MINOR_NIL ||
				    map->dmi_node == DI_NODE_NIL) {
					continue;
				}

				if (i2c_device_discover_one(iter, map)) {
					*discp = &iter->di_disc;
					return (I2C_ITER_VALID);
				} else {
					return (I2C_ITER_ERROR);
				}
			}
			pi->dpi_7bit_done = true;
			pi->dpi_curidx = 0;
		}


		if (!pi->dpi_10bit_done) {
			while (pi->dpi_curidx < ARRAY_SIZE(pi->dpi_10b)) {
				dev_map_info_t *map =
				    &pi->dpi_10b[pi->dpi_curidx];
				pi->dpi_curidx++;
				if (map->dmi_minor == DI_MINOR_NIL ||
				    map->dmi_node == DI_NODE_NIL) {
					continue;
				}

				if (i2c_device_discover_one(iter, map)) {
					*discp = &iter->di_disc;
					return (I2C_ITER_VALID);
				} else {
					return (I2C_ITER_ERROR);
				}
			}
			pi->dpi_10bit_done = true;
			pi->dpi_curidx = 0;
		}
	}

	return (I2C_ITER_ERROR);
}

bool
i2c_device_discover_init(i2c_hdl_t *hdl, i2c_dev_iter_t **iterp)
{
	i2c_dev_iter_t *iter;

	if (iterp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_dev_iter_t output pointer: %p", iterp));
	}

	iter = calloc(1, sizeof (i2c_dev_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_dev_iter_t"));
	}

	iter->di_hdl = hdl;
	iter->di_done = false;
	if (!i2c_port_discover_init(hdl, &iter->di_iter)) {
		free(iter);
		return (false);
	}

	*iterp = iter;
	return (i2c_success(hdl));
}

bool
i2c_device_discover(i2c_hdl_t *hdl, i2c_dev_disc_f func, void *arg)
{
	i2c_dev_iter_t *iter;
	const i2c_dev_disc_t *disc;
	i2c_iter_t ret;

	if (func == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_dev_disc_f function pointer: %p", func));
	}

	if (!i2c_device_discover_init(hdl, &iter)) {
		return (false);
	}

	while ((ret = i2c_device_discover_step(iter, &disc)) ==
	    I2C_ITER_VALID) {
		if (!func(hdl, disc, arg))
			break;
	}

	i2c_device_discover_fini(iter);
	if (ret == I2C_ITER_ERROR) {
		return (false);
	}

	return (i2c_success(hdl));
}

const char *
i2c_device_disc_name(const i2c_dev_disc_t *disc)
{
	return (di_node_name(disc->idd_map->dmi_node));
}

di_node_t
i2c_device_disc_devi(const i2c_dev_disc_t *disc)
{
	return (disc->idd_map->dmi_node);
}

di_minor_t
i2c_device_disc_devctl(const i2c_dev_disc_t *disc)
{
	return (disc->idd_map->dmi_minor);
}

const char *
i2c_device_disc_path(const i2c_dev_disc_t *disc)
{
	return (disc->idd_path);
}

void
i2c_device_info_free(i2c_dev_info_t *info)
{
	free(info->dinfo_name);
	free(info->dinfo_driver);
	free(info->dinfo_addrs);
	di_devfs_path_free(info->dinfo_minor);
	free(info);
}

const char *
i2c_device_info_path(const i2c_dev_info_t *info)
{
	return (info->dinfo_path);
}

const char *
i2c_device_info_name(const i2c_dev_info_t *info)
{
	return (info->dinfo_name);
}

const char *
i2c_device_info_driver(const i2c_dev_info_t *info)
{
	return (info->dinfo_driver);
}

int
i2c_device_info_instance(const i2c_dev_info_t *info)
{
	return (info->dinfo_inst);
}

uint32_t
i2c_device_info_naddrs(const i2c_dev_info_t *info)
{
	return (info->dinfo_naddrs);
}

const i2c_addr_t *
i2c_device_info_addr_primary(const i2c_dev_info_t *info)
{
	return (&info->dinfo_info.udi_primary);
}

const i2c_addr_t *
i2c_device_info_addr(const i2c_dev_info_t *info, uint32_t n)
{
	if (n >= info->dinfo_naddrs) {
		return (NULL);
	}

	return (&info->dinfo_addrs[n]);
}

i2c_addr_source_t
i2c_device_info_addr_source(const i2c_dev_info_t *info, uint32_t n)
{
	if (n >= info->dinfo_naddrs) {
		return (0);
	}

	return (info->dinfo_info.udi_7b[info->dinfo_addrs[n].ia_addr]);
}

bool
i2c_device_info_snap(i2c_hdl_t *hdl, di_node_t dn, i2c_dev_info_t **infop)
{
	di_minor_t minor;
	i2c_dev_info_t *info;

	if (dn == DI_NODE_NIL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid di_node_t: %p", dn));
	}

	if (infop == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_dev_info_t output pointer: %p", infop));
	}

	if (!i2c_node_is_type(dn, I2C_NODE_T_DEV)) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s is "
		    "not an i2c device", di_node_name(dn), di_bus_addr(dn)));
	}

	minor = i2c_node_minor(dn);
	if (minor == DI_MINOR_NIL) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s is "
		    "not an i2c device: failed to find device minor",
		    di_node_name(dn), di_bus_addr(dn)));
	}

	info = calloc(1, sizeof (i2c_dev_info_t));
	info->dinfo_name = strdup(di_node_name(dn));
	if (info->dinfo_name == NULL) {
		int e = errno;
		i2c_device_info_free(info);
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to duplicate "
		    "device node name"));
	}

	if (!i2c_node_to_path(hdl, dn, info->dinfo_path,
	    sizeof (info->dinfo_path))) {
		i2c_device_info_free(info);
		return (false);
	}

	if (di_driver_name(dn) != NULL) {
		info->dinfo_driver = strdup(di_driver_name(dn));
		if (info->dinfo_driver == NULL) {
			int e = errno;
			i2c_device_info_free(info);
			return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to "
			    "duplicate device driver name"));
		}
	} else {
		info->dinfo_driver = NULL;
	}
	info->dinfo_inst = di_instance(dn);
	info->dinfo_minor = di_devfs_minor_path(minor);
	if (info->dinfo_minor == NULL) {
		int e = errno;
		i2c_device_info_free(info);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "obtain devices's devfs path: %s", strerrordesc_np(e)));
	}

	int fd = openat(hdl->ih_devfd, info->dinfo_minor + 1, O_RDONLY);
	if (fd < 0) {
		int e = errno;
		(void) i2c_error(hdl, I2C_ERR_OPEN_DEV, e, "failed to open "
		    "device path /devices%s: %s", info->dinfo_minor,
		    strerrordesc_np(e));
		i2c_device_info_free(info);
		return (false);
	}

	if (ioctl(fd, UI2C_IOCTL_DEV_INFO, &info->dinfo_info) != 0) {
		int e = errno;
		i2c_device_info_free(info);
		return (i2c_ioctl_syserror(hdl, e, "device information "
		    "request"));
	}

	(void) close(fd);
	if (info->dinfo_info.udi_error.i2c_error != I2C_CORE_E_OK) {
		i2c_device_info_free(info);
		return (i2c_ioctl_error(hdl, &info->dinfo_info.udi_error,
		    "device information request"));
	}

	for (uint32_t i = 0; i < ARRAY_SIZE(info->dinfo_info.udi_7b); i++) {
		if (info->dinfo_info.udi_7b[i] != 0) {
			info->dinfo_naddrs++;
		}
	}

	VERIFY3U(info->dinfo_naddrs, >, 0);
	info->dinfo_addrs = calloc(info->dinfo_naddrs, sizeof (i2c_addr_t));
	if (info->dinfo_addrs == NULL) {
		int e = errno;
		(void) i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for %u I2C addresses", info->dinfo_naddrs);
		i2c_device_info_free(info);
		return (false);
	}

	for (uint32_t i = 0, idx = 0; i < ARRAY_SIZE(info->dinfo_info.udi_7b);
	    i++) {
		if (info->dinfo_info.udi_7b[i] != 0) {
			info->dinfo_addrs[idx].ia_type = I2C_ADDR_7BIT;
			info->dinfo_addrs[idx].ia_addr = i;
			idx++;
		}
	}

	*infop = info;
	return (i2c_success(hdl));
}

/*
 * Get information about a device specified by path. In addition, return its
 * port. If nodev_ok is set to true, then our caller is fine with returning
 * success, but without the device information. This would happen if the path
 * ended at a port.
 */
bool
i2c_port_dev_init_by_path(i2c_hdl_t *hdl, const char *path, bool nodev_ok,
    i2c_port_t **portp, i2c_dev_info_t **infop)
{
	i2c_node_type_t type;
	di_node_t dn, root, port_dn, dev_dn;
	if (path == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c path: %p", path));
	}

	if (portp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_port_t output pointer: %p", infop));
	}
	*portp = NULL;

	if (infop == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_dev_info_t output pointer: %p", infop));
	}
	*infop = NULL;

	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "initialize devinfo snapshot: %s", strerrordesc_np(e)));
	}

	if (!i2c_path_parse(hdl, path, root, &dn, &type, I2C_ERR_BAD_DEVICE)) {
		di_fini(root);
		return (false);
	}

	switch (type) {
	case I2C_NODE_T_DEV:
		dev_dn = dn;
		port_dn = di_parent_node(dev_dn);
		break;
	case I2C_NODE_T_PORT:
		if (!nodev_ok) {
			return (i2c_error(hdl, I2C_ERR_BAD_DEVICE, 0, "parsed "
			    "I2C path %s did not end at a device", path));
		}
		dev_dn = DI_NODE_NIL;
		port_dn = dn;
		break;
	default:
		di_fini(root);
		return (i2c_error(hdl, I2C_ERR_BAD_DEVICE, 0, "parsed I2C "
		    "path %s did not end at a device (or port)", path));
	}

	if (!i2c_port_init(hdl, port_dn, portp)) {
		di_fini(root);
		return (false);
	}

	if (dev_dn != DI_NODE_NIL) {
		if (!i2c_device_info_snap(hdl, dev_dn, infop)) {
			di_fini(root);
			i2c_port_fini(*portp);
			return (false);
		}
	}

	return (true);
}
