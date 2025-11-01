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
 * Misc. utility functions for our ioctl tests.
 */

#include <libdevinfo.h>
#include <err.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysmacros.h>

#include <sys/i2c/ioctl.h>

#include "i2c_ioctl_util.h"

static int i2c_test_devfd = -1;
const char *i2c_sim_dipath = "/pseudo/i2csim@0";

/*
 * Different forms of invalid I2C addresses.
 */
const bad_addr_t bad_addrs[] = {
	{ I2C_ADDR_7BIT, 0x00, I2C_CORE_E_ADDR_RSVD },
	{ I2C_ADDR_7BIT, 0x7f, I2C_CORE_E_ADDR_RSVD },
	{ I2C_ADDR_7BIT, 0x80, I2C_CORE_E_BAD_ADDR },
	{ I2C_ADDR_7BIT, 0x7777, I2C_CORE_E_BAD_ADDR },
	{ I2C_ADDR_7BIT, INT16_MAX, I2C_CORE_E_BAD_ADDR },
	{ I2C_ADDR_7BIT, UINT16_MAX, I2C_CORE_E_BAD_ADDR },
	{ I2C_ADDR_10BIT, 0x42, I2C_CORE_E_UNSUP_ADDR_TYPE },
	{ I2C_ADDR_10BIT, 0x3ff, I2C_CORE_E_UNSUP_ADDR_TYPE },
	{ I2C_ADDR_10BIT, 0x7ff, I2C_CORE_E_BAD_ADDR },
	{ I2C_ADDR_10BIT, 0x7777, I2C_CORE_E_BAD_ADDR },
	{ 0x7777, 0x42, I2C_CORE_E_BAD_ADDR_TYPE },
	{ 0x2, 0x23, I2C_CORE_E_BAD_ADDR_TYPE },
	{ INT16_MAX, UINT16_MAX, I2C_CORE_E_BAD_ADDR_TYPE },
};

const size_t nbad_addrs = ARRAY_SIZE(bad_addrs);

static di_node_t
i2c_ioctl_test_init_devi(void)
{
	di_node_t root;

	if (i2c_test_devfd == -1) {
		i2c_test_devfd = open("/devices", O_RDONLY | O_DIRECTORY);
		if (i2c_test_devfd < 0) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed "
			    "to open /devices");
		}
	}

	/*
	 * We do not cache this as a global as some tests want to be able to
	 * find devices after they've created and made changes to the set of
	 * devices present. This makes some tests more expensive, but others
	 * correct!
	 */
	root = di_init(i2c_sim_dipath, DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
		    "initialize devinfo library");
	}

	return (root);
}

static i2c_dev_t
i2c_node_type(di_node_t dn)
{
	const char *drv = di_driver_name(dn);
	char *strs;
	int nstrs;

	nstrs = di_prop_lookup_strings(DDI_DEV_T_ANY, dn, "device_type",
	    &strs);
	if (nstrs == 1 && strcmp(strs, "i2c") == 0) {
		return (I2C_D_DEVICE);
	}

	if (drv == NULL || strcmp(drv, "i2cnex") != 0) {
		return (I2C_D_OTHER);
	}

	nstrs = di_prop_lookup_strings(DDI_DEV_T_ANY, dn, I2C_NEXUS_TYPE_PROP,
	    &strs);
	if (nstrs != 1) {
		return (I2C_D_OTHER);
	}

	if (strcmp(strs, I2C_NEXUS_TYPE_PORT) == 0) {
		return (I2C_D_PORT);
	} else if (strcmp(strs, I2C_NEXUS_TYPE_CTRL) == 0) {
		return (I2C_D_CTRL);
	} else if (strcmp(strs, I2C_NEXUS_TYPE_MUX) == 0) {
		return (I2C_D_MUX);
	}

	return (I2C_D_OTHER);
}

static di_node_t
i2c_ioctl_test_find_by_addr(di_node_t dev, i2c_dev_t type, const char *targ)
{
	for (di_node_t dn = di_child_node(dev); dn != NULL;
	    dn = di_sibling_node(dn)) {
		if (i2c_node_type(dn) != type)
			continue;

		const char *addr = di_bus_addr(dn);
		if (addr != NULL && strcmp(addr, targ) == 0) {
			return (dn);
		}
	}
	return (DI_NODE_NIL);
}

/*
 * muxes use the address of their driver instance. This is variable, so we can't
 * rely on it; however, a device will only have a single mux so we take the
 * first one we find.
 */
static di_node_t
i2c_ioctl_test_find_mux(di_node_t dev)
{
	for (di_node_t dn = di_child_node(dev); dn != NULL;
	    dn = di_sibling_node(dn)) {
		if (i2c_node_type(dn) == I2C_D_MUX) {
			return (dn);
		}
	}
	return (DI_NODE_NIL);
}

static di_node_t
i2c_ioctl_test_find_device(di_node_t dev, const char *addrstr)
{
	uint16_t addr;
	const char *err;

	addr = (uint16_t)strtonumx(addrstr, 0, 0x7f, &err, 0);
	if (err != NULL) {
		errx(EXIT_FAILURE, "failed to parse %s as a 7-bit address: "
		    "value is %s", addrstr, err);
	}

	for (di_node_t dn = di_child_node(dev); dn != NULL;
	    dn = di_sibling_node(dn)) {
		if (i2c_node_type(dn) != I2C_D_DEVICE)
			continue;

		int *reg;
		int nreg = di_prop_lookup_ints(DDI_DEV_T_ANY, dn, "reg", &reg);
		if (nreg == 0 || (nreg % 2) != 0)
			continue;

		if (reg[0] == I2C_ADDR_7BIT && reg[1] == addr) {
			return (dn);
		}
	}
	return (DI_NODE_NIL);
}

static di_minor_t
i2c_ioctl_test_device_minor(di_node_t dn)
{
	int nreg, *reg;
	char name[32];

	nreg = di_prop_lookup_ints(DDI_DEV_T_ANY, dn, "reg", &reg);
	if (nreg == 0 || (nreg % 2) != 0) {
		return (DI_MINOR_NIL);
	}

	(void) snprintf(name, sizeof (name), "%x,%x", reg[0], reg[1]);
	dn = di_parent_node(dn);
	if (i2c_node_type(dn) != I2C_D_PORT) {
		return (DI_MINOR_NIL);
	}

	for (di_minor_t m = di_minor_next(dn, DI_MINOR_NIL); m != DI_MINOR_NIL;
	    m = di_minor_next(dn, m)) {
		if (strcmp(di_minor_nodetype(m), DDI_NT_I2C_DEV) == 0 &&
		    strcmp(di_minor_name(m), name) == 0) {
			return (m);
		}
	}

	return (DI_MINOR_NIL);

	return (DI_MINOR_NIL);
}

static di_minor_t
i2c_ioctl_test_minor(di_node_t dn, i2c_dev_t type)
{
	const char *nt;

	switch (type) {
	case I2C_D_CTRL:
		nt = DDI_NT_I2C_CTRL;
		break;
	case I2C_D_PORT:
		nt = DDI_NT_I2C_PORT;
		break;
	case I2C_D_MUX:
		nt = DDI_NT_I2C_MUX;
		break;
	case I2C_D_DEVICE:
		return (i2c_ioctl_test_device_minor(dn));
	default:
		return (DI_MINOR_NIL);
	}

	for (di_minor_t m = di_minor_next(dn, DI_MINOR_NIL); m != DI_MINOR_NIL;
	    m = di_minor_next(dn, m)) {
		if (strcmp(di_minor_nodetype(m), nt) == 0) {
			return (m);
		}
	}

	return (DI_MINOR_NIL);
}

/*
 * This is a variant of our i2c path that explicitly includes the mux nodes with
 * a string "mux" to make it easier for us to open and refer to it as a device
 * node. As userland doesn't directly interact with these normally, these aren't
 * in the path.
 */
int
i2c_ioctl_test_get_fd(i2c_dev_t dev, const char *path, int flags)
{
	char *dup = strdup(path), *lasts;
	if (dup == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory to duplicate path "
		    "%s", path);
	}

	i2c_dev_t type = I2C_D_OTHER;
	di_node_t root = i2c_ioctl_test_init_devi();
	di_node_t devi = root;
	for (const char *ent = strtok_r(dup, "/", &lasts); ent != NULL;
	    ent = strtok_r(NULL, "/", &lasts)) {
		switch (type) {
		case I2C_D_OTHER:
			/*
			 * We're at the root of the i2csim0 tree. There should
			 * be an i2cnex child whose address matches our
			 * controller name.
			 */
			devi = i2c_ioctl_test_find_by_addr(devi, I2C_D_CTRL,
			    ent);
			if (devi == NULL) {
				errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
				    "failed to find controller %s as part of "
				    "path %s", ent, path);
			}
			type = I2C_D_CTRL;
			break;
		case I2C_D_CTRL:
		case I2C_D_MUX:
			devi = i2c_ioctl_test_find_by_addr(devi, I2C_D_PORT,
			    ent);
			if (devi == NULL) {
				errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
				    "failed to find port %s as part of "
				    "path %s", ent, path);
			}
			type = I2C_D_PORT;
			break;
		case I2C_D_PORT:
			devi = i2c_ioctl_test_find_device(devi, ent);
			if (devi == NULL) {
				errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
				    "failed to find device %s as part of "
				    "path %s", ent, path);
			}
			type = I2C_D_DEVICE;
			break;
		case I2C_D_DEVICE:
			if (strcmp(ent, "mux") != 0) {
				errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
				    "device cannot have something other than "
				    "mux under them, found %s", ent);
			}

			devi = i2c_ioctl_test_find_mux(devi);
			if (devi == NULL) {
				errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: "
				    "failed to find mux as part of path %s",
				    path);
			}
			type = I2C_D_MUX;
			break;
		}
	}

	if (type != dev) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: path %s ended at "
		    "type 0x%x, but expected 0x%x", path, type, dev);
	}
	free(dup);

	di_minor_t minor = i2c_ioctl_test_minor(devi, type);
	if (minor == DI_MINOR_NIL) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to find "
		    "minor corresponding to path %s", path);
	}

	char *minor_path = di_devfs_minor_path(minor);
	if (minor_path == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to get minor "
		    "path for %s", path);
	}

	int fd = openat(i2c_test_devfd, minor_path + 1, flags);
	if (fd < 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to open "
		    "/devices%s", minor_path);
	}
	di_devfs_path_free(minor_path);
	di_fini(root);
	return (fd);
}
