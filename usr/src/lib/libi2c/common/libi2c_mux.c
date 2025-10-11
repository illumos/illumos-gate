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
 * Mux discovery support
 */

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "libi2c_impl.h"

void
i2c_mux_discover_fini(i2c_mux_iter_t *iter)
{
	if (iter == NULL)
		return;
	di_fini(iter->mi_root);
	free(iter);
}

i2c_iter_t
i2c_mux_discover_step(i2c_mux_iter_t *iter, const i2c_mux_disc_t **discp)
{
	i2c_hdl_t *hdl = iter->mi_hdl;
	*discp = NULL;

	if (iter->mi_done) {
		return (I2C_ITER_DONE);
	}

	for (;;) {
		if (iter->mi_cur == DI_NODE_NIL) {
			iter->mi_cur = di_drv_first_node(I2C_NEX_DRV,
			    iter->mi_root);
		} else {
			iter->mi_cur = di_drv_next_node(iter->mi_cur);
		}

		if (iter->mi_cur == DI_NODE_NIL) {
			iter->mi_done = true;
			return (I2C_ITER_DONE);
		}

		if (!i2c_node_is_type(iter->mi_cur, I2C_NODE_T_MUX)) {
			continue;
		}

		di_minor_t m = i2c_node_minor(iter->mi_cur);
		if (m == DI_MINOR_NIL) {
			continue;
		}

		iter->mi_disc.md_devi = iter->mi_cur;
		iter->mi_disc.md_minor = m;
		if (!i2c_node_to_path(hdl, iter->mi_cur, iter->mi_disc.md_path,
		    sizeof (iter->mi_disc.md_path))) {
			return (I2C_ITER_ERROR);
		}

		char *mpath = di_devfs_minor_path(m);
		if (mpath == NULL) {
			int e = errno;
			di_devfs_path_free(mpath);
			(void) i2c_error(hdl, I2C_ERR_LIBDEVINFO, e,
			    "failed to get minor path for %s@%s:%s",
			    di_node_name(iter->mi_cur),
			    di_bus_addr(iter->mi_cur), di_minor_name(m));
			return (I2C_ITER_ERROR);
		}

		int fd = openat(hdl->ih_devfd, mpath + 1, O_RDONLY);
		if (fd < 0) {
			int e = errno;
			di_devfs_path_free(mpath);
			(void) i2c_error(hdl, I2C_ERR_OPEN_DEV, e, "failed to "
			    "open device path '/devices%s: %s", mpath,
			    strerrordesc_np(e));
			return (I2C_ITER_ERROR);
		}
		di_devfs_path_free(mpath);

		if (ioctl(fd, UI2C_IOCTL_MUX_INFO, &iter->mi_disc.md_info) !=
		    0) {
			int e = errno;
			(void) close(fd);
			(void) i2c_ioctl_syserror(hdl, e, "mux information "
			    "request");
			return (I2C_ITER_ERROR);
		}
		(void) close(fd);
		if (iter->mi_disc.md_info.umi_error.i2c_error !=
		    I2C_CORE_E_OK) {
			(void) i2c_ioctl_error(hdl,
			    &iter->mi_disc.md_info.umi_error, "mux information "
			    "request");
			return (I2C_ITER_ERROR);
		}

		*discp = &iter->mi_disc;
		return (I2C_ITER_VALID);
	}
}

bool
i2c_mux_discover_init(i2c_hdl_t *hdl, i2c_mux_iter_t **iterp)
{
	i2c_mux_iter_t *iter;

	if (iterp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_mux_iter_t output pointer: %p", iterp));
	}

	iter = calloc(1, sizeof (i2c_mux_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_mux_iter_t"));
	}

	iter->mi_hdl = hdl;
	iter->mi_root = di_init("/", DINFOCPYALL);
	if (iter->mi_root == NULL) {
		int e = errno;
		i2c_mux_discover_fini(iter);
		return (i2c_error(hdl, I2C_ERR_LIBDEVINFO, e, "failed to "
		    "initialize devinfo snapshot: %s", strerrordesc_np(e)));
	}
	iter->mi_done = false;
	iter->mi_cur = DI_NODE_NIL;

	*iterp = iter;
	return (i2c_success(hdl));
}

bool
i2c_mux_discover(i2c_hdl_t *hdl, i2c_mux_disc_f func, void *arg)
{
	i2c_mux_iter_t *iter;
	const i2c_mux_disc_t *disc;
	i2c_iter_t ret;

	if (func == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_mux_disc_f function pointer: %p", func));
	}

	if (!i2c_mux_discover_init(hdl, &iter)) {
		return (false);
	}

	while ((ret = i2c_mux_discover_step(iter, &disc)) == I2C_ITER_VALID) {
		if (!func(hdl, disc, arg))
			break;
	}

	i2c_mux_discover_fini(iter);
	if (ret == I2C_ITER_ERROR) {
		return (false);
	}

	return (i2c_success(hdl));
}

di_node_t
i2c_mux_disc_devi(const i2c_mux_disc_t *disc)
{
	return (disc->md_devi);
}

di_minor_t
i2c_mux_disc_devctl(const i2c_mux_disc_t *disc)
{
	return (disc->md_minor);
}

const char *
i2c_mux_disc_name(const i2c_mux_disc_t *disc)
{
	return (di_bus_addr(disc->md_devi));
}

const char *
i2c_mux_disc_path(const i2c_mux_disc_t *disc)
{
	return (disc->md_path);
}

uint32_t
i2c_mux_disc_nports(const i2c_mux_disc_t *disc)
{
	return (disc->md_info.umi_nports);
}
