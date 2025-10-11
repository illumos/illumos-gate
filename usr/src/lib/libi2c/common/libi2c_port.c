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
 * I2C port discovery and initialization.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "libi2c_impl.h"

void
i2c_port_discover_fini(i2c_port_iter_t *iter)
{
	if (iter == NULL) {
		return;
	}

	free(iter->pi_ports);
	di_fini(iter->pi_root);
	free(iter);
}

i2c_iter_t
i2c_port_discover_step(i2c_port_iter_t *iter, const i2c_port_disc_t **discp)
{
	for (;;) {
		if (iter->pi_curport == iter->pi_nports) {
			return (I2C_ITER_DONE);
		}

		iter->pi_disc.pd_devi = iter->pi_ports[iter->pi_curport];
		iter->pi_curport++;

		if (!i2c_node_to_path(iter->pi_hdl, iter->pi_disc.pd_devi,
		    iter->pi_disc.pd_path, sizeof (iter->pi_disc.pd_path))) {
			continue;
		}

		*discp = &iter->pi_disc;
		return (I2C_ITER_VALID);
	}
}

/*
 * We have two nodes that are not the same. They are at the same point in the
 * tree though. We expect all devices at a given layer in the tree to have the
 * same type. We start with the node name and if they're the same fall back to
 * the bus address which must be unique at this point.
 */
static int
i2c_port_sort_node(di_node_t l, di_node_t r)
{
	const char *nl = di_node_name(l);
	const char *nr = di_node_name(r);
	int ret;

	if ((ret = strcmp(nl, nr)) == 0) {
		nl = di_bus_addr(l);
		nr = di_bus_addr(r);
		ret = strcmp(nl, nr);
	}

	return (ret);
}

typedef struct {
	di_node_t ni_ctrl;
	di_node_t ni_parent;
	uint32_t ni_height;
} node_info_t;

static void
i2c_port_sort_info(di_node_t dn, node_info_t *info)
{
	(void) memset(info, 0, sizeof (node_info_t));

	info->ni_parent = di_parent_node(dn);
	for (;;) {
		i2c_node_type_t type = i2c_node_type(dn);

		if (type == I2C_NODE_T_CTRL) {
			info->ni_ctrl = dn;
			return;
		}

		info->ni_height++;
		dn = di_parent_node(dn);
		if (dn == DI_NODE_NIL) {
			return;
		}
	}
}

static int
i2c_port_sort(const void *left, const void *right)
{
	di_node_t l = *(di_node_t *)left;
	di_node_t r = *(di_node_t *)right;
	node_info_t li, ri;

	if (l == r) {
		return (0);
	}

	/*
	 * We have two nodes that are different points in the tree. We basically
	 * want to ask:
	 *
	 *  - What controller do they point to?
	 *  - What are the relative heights in the tree?
	 *
	 * If they belong to different controllers, we sort based on the
	 * controller's name. If they belong to the same controller, then we use
	 * the height in the tree. If they have the same height, we then see if
	 * they have the same parent. If they don't, we sort on the parent (like
	 * the controller). If they do, we use their name directly.
	 */
	i2c_port_sort_info(l, &li);
	i2c_port_sort_info(r, &ri);

	if (li.ni_ctrl != ri.ni_ctrl) {
		return (i2c_port_sort_node(li.ni_ctrl, ri.ni_ctrl));
	}

	if (li.ni_height != ri.ni_height) {
		return (li.ni_height < ri.ni_height ? -1 : 1);
	}

	if (li.ni_parent != ri.ni_parent) {
		return (i2c_port_sort_node(li.ni_parent, ri.ni_parent));
	}

	return (i2c_port_sort_node(l, r));
}
bool
i2c_port_discover_init(i2c_hdl_t *hdl, i2c_port_iter_t **iterp)
{
	i2c_port_iter_t *iter;

	if (iterp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_port_iter_t output pointer: %p", iterp));
	}

	iter = calloc(1, sizeof (i2c_port_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_port_iter_t"));
	}

	iter->pi_root = di_init("/", DINFOCPYALL);
	if (iter->pi_root == NULL) {
		int e = errno;
		i2c_port_discover_fini(iter);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "initialize devinfo snapshot: %s", strerrordesc_np(e)));
	}
	iter->pi_done = false;

	/*
	 * We want port discovery to have a reasonably stable and meaningful
	 * order. This is going to be built on top of for devices. We want to
	 * treat this in a bit of a depth-search sense. We don't want to do the
	 * children of one controller's port, then switch to a different
	 * controller, and then come back to say a mux. To facilitate this, note
	 * all the ports first, sort them, and then come back to it.
	 */
	for (di_node_t dn = di_drv_first_node(I2C_NEX_DRV, iter->pi_root);
	    dn != NULL; dn = di_drv_next_node(dn)) {
		if (!i2c_node_is_type(dn, I2C_NODE_T_PORT)) {
			continue;
		}

		if (iter->pi_nalloc == iter->pi_nports) {
			di_node_t *new;
			uint32_t toalloc = iter->pi_nalloc + 16;

			new = recallocarray(iter->pi_ports, iter->pi_nports,
			    toalloc, sizeof (di_node_t));
			if (new == NULL) {
				int e = errno;
				i2c_port_discover_fini(iter);
				return (i2c_error(hdl, I2C_ERR_NO_MEM, e,
				    "failed to allocate memory for a %u "
				    "element di_node_t array",
				    toalloc));
			}
			iter->pi_ports = new;
			iter->pi_nalloc = toalloc;
		}

		iter->pi_ports[iter->pi_nports] = dn;
		iter->pi_nports++;
	}

	qsort(iter->pi_ports, iter->pi_nports, sizeof (di_node_t),
	    i2c_port_sort);

	*iterp = iter;
	return (i2c_success(hdl));
}

bool
i2c_port_discover(i2c_hdl_t *hdl, i2c_port_disc_f func, void *arg)
{
	i2c_port_iter_t *iter;
	const i2c_port_disc_t *disc;
	i2c_iter_t ret;

	if (func == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_port_disc_f function pointer: %p", func));
	}

	if (!i2c_port_discover_init(hdl, &iter)) {
		return (false);
	}

	while ((ret = i2c_port_discover_step(iter, &disc)) == I2C_ITER_VALID) {
		if (!func(hdl, disc, arg))
			break;
	}

	i2c_port_discover_fini(iter);
	if (ret == I2C_ITER_ERROR) {
		return (false);
	}

	return (i2c_success(hdl));
}

di_node_t
i2c_port_disc_devi(const i2c_port_disc_t *disc)
{
	return (disc->pd_devi);
}

const char *
i2c_port_disc_path(const i2c_port_disc_t *disc)
{
	return (disc->pd_path);
}

void
i2c_port_fini(i2c_port_t *port)
{
	if (port == NULL) {
		return;
	}

	if (port->port_fd >= 0) {
		(void) close(port->port_fd);
	}

	di_devfs_path_free(port->port_minor);
	free(port->port_name);
	free(port);
}

bool
i2c_port_init(i2c_hdl_t *hdl, di_node_t di, i2c_port_t **portp)
{
	di_minor_t minor;
	di_node_t parent;
	i2c_node_type_t ptype;

	if (di == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid di_node_t: %p", di));
	}

	if (portp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_port_t output pointer: %p", portp));
	}

	/*
	 * We've verified that we were given an i2cnex instance, make sure this
	 * corresponds to a port.
	 */
	if (!i2c_node_is_type(di, I2C_NODE_T_PORT)) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s is "
		    "not an i2c port", di_node_name(di), di_bus_addr(di)));
	}

	minor = i2c_node_minor(di);
	if (minor == DI_MINOR_NIL) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s is "
		    "not an i2c port: failed to find port minor",
		    di_node_name(di), di_bus_addr(di)));
	}

	i2c_port_t *port = calloc(1, sizeof (i2c_port_t));
	if (port == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_port_t"));
	}

	port->port_fd = -1;
	port->port_hdl = hdl;
	port->port_inst = di_instance(di);
	port->port_name = strdup(di_bus_addr(di));
	if (port->port_name == NULL) {
		int e = errno;
		i2c_port_fini(port);
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to duplicate "
		    "port bus address"));
	}

	parent = di_parent_node(di);
	ptype = i2c_node_type(parent);
	if (ptype == I2C_NODE_T_CTRL) {
		port->port_type = I2C_PORT_TYPE_CTRL;
	} else if (ptype == I2C_NODE_T_MUX) {
		port->port_type = I2C_PORT_TYPE_MUX;
	} else {
		i2c_port_fini(port);
		return (i2c_error(hdl, I2C_ERR_BAD_DEVI, 0, "devi %s@%s is not "
		    "an i2c port: found wrong parent", di_node_name(di),
		    di_bus_addr(di)));
	}

	if (!i2c_node_to_path(hdl, di, port->port_path,
	    sizeof (port->port_path))) {
		i2c_port_fini(port);
		return (false);
	}

	port->port_minor = di_devfs_minor_path(minor);
	if (port->port_minor == NULL) {
		int e = errno;
		i2c_port_fini(port);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "obtain ports's devfs path: %s", strerrordesc_np(e)));
	}

	port->port_fd = openat(hdl->ih_devfd, port->port_minor + 1, O_RDWR);
	if (port->port_fd < 0) {
		int e = errno;
		(void) i2c_error(hdl, I2C_ERR_OPEN_DEV, e, "failed to open "
		    "device path /devices%s: %s", port->port_minor,
		    strerrordesc_np(e));
		i2c_port_fini(port);
		return (false);
	}

	if (ioctl(port->port_fd, UI2C_IOCTL_PORT_INFO, &port->port_info) != 0) {
		int e = errno;
		i2c_port_fini(port);
		return (i2c_ioctl_syserror(hdl, e, "port information request"));
	}

	if (port->port_info.upo_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &port->port_info.upo_error,
		    "port information request"));
	}

	*portp = port;
	return (i2c_success(hdl));
}

/*
 * Initialize a port based on the passed in name. This name may be a top-level
 * port for the controller or it may be a port on a mux. We end up walking the
 * path, tokenizing and parsing it to try to find something here.
 */
bool
i2c_port_init_by_path(i2c_hdl_t *hdl, const char *path, i2c_port_t **portp)
{
	i2c_node_type_t type;
	di_node_t dn, root;

	if (path == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c port path: %p", path));
	}

	if (portp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_port_t output pointer: %p", portp));
	}

	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "initialize devinfo snapshot: %s", strerrordesc_np(e)));
	}

	if (!i2c_path_parse(hdl, path, root, &dn, &type, I2C_ERR_BAD_PORT)) {
		di_fini(root);
		return (false);
	}

	if (type != I2C_NODE_T_PORT) {
		di_fini(root);
		return (i2c_error(hdl, I2C_ERR_BAD_PORT, 0, "parsed I2C path "
		    "%s did not end at a port", path));
	}

	bool ret = i2c_port_init(hdl, dn, portp);
	di_fini(root);
	return (ret);
}

const char *
i2c_port_name(i2c_port_t *port)
{
	return (port->port_name);
}

const char *
i2c_port_path(i2c_port_t *port)
{
	return (port->port_path);
}

uint32_t
i2c_port_portno(i2c_port_t *port)
{
	return (port->port_info.upo_portno);
}

i2c_port_type_t
i2c_port_type(i2c_port_t *port)
{
	return (port->port_type);
}

void
i2c_port_map_free(i2c_port_map_t *map)
{
	free(map);
}

bool
i2c_port_map_snap(i2c_port_t *port, i2c_port_map_t **mapp)
{
	i2c_port_map_t *map;
	i2c_hdl_t *hdl = port->port_hdl;

	if (mapp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_port_map_t output pointer: %p", mapp));
	}

	map = calloc(1, sizeof (i2c_port_map_t));
	if (map == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_port_map_t"));
	}
	map->pm_hdl = hdl;

	if (ioctl(port->port_fd, UI2C_IOCTL_PORT_INFO, &map->pm_info) != 0) {
		int e = errno;
		i2c_port_fini(port);
		return (i2c_ioctl_syserror(hdl, e, "port maprmation request"));
	}

	if (map->pm_info.upo_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &map->pm_info.upo_error,
		    "port information request"));
	}

	*mapp = map;
	return (i2c_success(hdl));
}

void
i2c_port_map_ndevs(const i2c_port_map_t *map, uint32_t *local, uint32_t *ds)
{
	if (local != NULL) {
		*local = map->pm_info.upo_ndevs;
	}

	if (ds != NULL) {
		*ds = map->pm_info.upo_ndevs_ds;
	}
}

bool
i2c_port_map_addr_info(const i2c_port_map_t *map, const i2c_addr_t *addr,
    uint32_t *devsp, bool *dsp, major_t *majorp)
{
	if (!i2c_addr_validate(map->pm_hdl, addr)) {
		return (false);
	}

	if (addr->ia_type != I2C_ADDR_7BIT) {
		(void) i2c_error(map->pm_hdl, I2C_ERR_UNSUP_ADDR_TYPE, 0,
		    "port map information is not available for this address "
		    "type");
		return (false);
	}

	const ui2c_port_addr_info_t *info = &map->pm_info.upo_7b[addr->ia_addr];

	if (devsp != NULL) {
		*devsp = info->pai_ndevs;
	}

	if (dsp != NULL) {
		*dsp = info->pai_downstream;
	}

	if (majorp != NULL) {
		*majorp = info->pai_major;
	}


	return (i2c_success(map->pm_hdl));
}
