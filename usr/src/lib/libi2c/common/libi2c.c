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
 * libi2c, a magical place that deals with everyone's favorite device class to
 * hate.
 */

#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/ilstr.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/obpdefs.h>

#include "libi2c_impl.h"

void
i2c_fini(i2c_hdl_t *hdl)
{
	freelocale(hdl->ih_c_loc);
	(void) close(hdl->ih_devfd);
	free(hdl);
}

i2c_hdl_t *
i2c_init(void)
{
	i2c_hdl_t *hdl;

	hdl = calloc(1, sizeof (i2c_hdl_t));
	if (hdl == NULL) {
		return (NULL);
	}

	hdl->ih_devfd = open("/devices", O_RDONLY | O_DIRECTORY);
	if (hdl->ih_devfd < 0) {
		free(hdl);
		return (NULL);
	}

	hdl->ih_c_loc = newlocale(LC_ALL_MASK, "C", NULL);
	return (hdl);
}

/*
 * Provide a simple answer as to whether or not an address is a reserved
 * address. This function is a bit awkward as invalid addresses are technically
 * not reserved.
 */
bool
i2c_addr_reserved(const i2c_addr_t *addr)
{
	switch (addr->ia_type) {
	case I2C_ADDR_7BIT:
		if (addr->ia_addr >= (1 << 7)) {
			return (false);
		}
		break;
	case I2C_ADDR_10BIT:
		if (addr->ia_addr >= (1 << 10)) {
			return (false);
		}
		break;
	default:
		return (false);
	}

	/*
	 * Because we've already done a size check up above we know illegal
	 * 7-bit addresses that are reserved 10-bit addresses will have already
	 * been checked.
	 */
	switch (addr->ia_addr) {
	case I2C_RSVD_ADDR_GEN_CALL:
	case I2C_RSVD_ADDR_C_BUS:
	case I2C_RSVD_ADDR_DIFF_BUS:
	case I2C_RSVD_ADDR_FUTURE:
	case I2C_RSVD_ADDR_HS_0:
	case I2C_RSVD_ADDR_HS_1:
	case I2C_RSVD_ADDR_HS_2:
	case I2C_RSVD_ADDR_HS_3:
	case I2C_RSVD_ADDR_10B_0:
	case I2C_RSVD_ADDR_10B_1:
	case I2C_RSVD_ADDR_10B_2:
	case I2C_RSVD_ADDR_10B_3:
	case I2C_RSVD_ADDR_DID_0:
	case I2C_RSVD_ADDR_DID_1:
	case I2C_RSVD_ADDR_DID_2:
	case I2C_RSVD_ADDR_DID_3:
		return (true);
	default:
		return (false);
	}
}

bool
i2c_addr_validate(i2c_hdl_t *hdl, const i2c_addr_t *addr)
{
	uint16_t max;

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	switch (addr->ia_type) {
	case I2C_ADDR_7BIT:
		max = 1 << 7;
		break;
	case I2C_ADDR_10BIT:
		max = 1 << 10;
		break;
	default:
		return (i2c_error(hdl, I2C_ERR_BAD_ADDR_TYPE, 0, "invalid "
		    "address type family 0x%x", addr->ia_type));
	}

	if (addr->ia_addr >= max) {
		return (i2c_error(hdl, I2C_ERR_BAD_ADDR, 0, "address 0x%x is "
		    "outside the valid range for the address type: [0x00, "
		    "0x%02x]", addr->ia_addr, max - 1));
	}

	return (true);
}

/*
 * The set of valid characters for the 'name' and 'compatible' properties comes
 * from IEEE 1275 (which was carried forward into device tree). A name must be
 * at most 31 characters. It is allowed to contain lower case, upper case,
 * numbers, and ",.+-_". We require the first character to be a letter. We check
 * all of this against our copy of the C locale to ensure that a program in a
 * different locale doesn't get a different answer.
 */
CTASSERT(I2C_NAME_MAX == OBP_MAXDRVNAME);
bool
i2c_name_validate(i2c_hdl_t *hdl, const char *name, const char *desc)
{
	size_t len;

	if (name == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid %s pointer: %p", desc, name));
	}

	len = strnlen(name, I2C_NAME_MAX);
	if (len >= I2C_NAME_MAX) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEV_NAME, 0, "%s exceeds "
		    "%u character length limit, including NUL", desc,
		    I2C_NAME_MAX));
	} else if (len == 0) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEV_NAME, 0, "%s cannot "
		    "have zero length", desc));
	}

	if (isalpha_l(name[0], hdl->ih_c_loc) == 0) {
		return (i2c_error(hdl, I2C_ERR_BAD_DEV_NAME, 0, "%s must "
		    "have an ASCII upper or lowercase first letter: found 0x%x",
		    desc, name[0]));
	}

	for (size_t i = 1; i < len; i++) {
		if (isalpha_l(name[i], hdl->ih_c_loc) ||
		    isdigit_l(name[i], hdl->ih_c_loc)) {
			continue;
		}

		if (name[i] == ',' || name[i] == '.' || name[i] == '+' ||
		    name[i] == '-' || name[i] == '_') {
			continue;
		}

		return (i2c_error(hdl, I2C_ERR_BAD_DEV_NAME, 0, "%s character "
		    "%zu is not from the valid set: found 0x%x", desc, i,
		    name[i]));
	}

	return (true);
}

i2c_node_type_t
i2c_node_type(di_node_t dn)
{
	const char *drv = di_driver_name(dn);
	char *strs;
	int nstrs;

	nstrs = di_prop_lookup_strings(DDI_DEV_T_ANY, dn, "device_type",
	    &strs);
	if (nstrs == 1 && strcmp(strs, "i2c") == 0) {
		return (I2C_NODE_T_DEV);
	}

	if (drv == NULL || strcmp(drv, I2C_NEX_DRV) != 0) {
		return (I2C_NODE_T_OTHER);
	}

	nstrs = di_prop_lookup_strings(DDI_DEV_T_ANY, dn, I2C_NEXUS_TYPE_PROP,
	    &strs);
	if (nstrs != 1) {
		return (I2C_NODE_T_OTHER);
	}

	if (strcmp(strs, I2C_NEXUS_TYPE_PORT) == 0) {
		return (I2C_NODE_T_PORT);
	} else if (strcmp(strs, I2C_NEXUS_TYPE_CTRL) == 0) {
		return (I2C_NODE_T_CTRL);
	} else if (strcmp(strs, I2C_NEXUS_TYPE_MUX) == 0) {
		return (I2C_NODE_T_MUX);
	}

	return (I2C_NODE_T_OTHER);
}

/*
 * Given a device node, find the corresponding minor node in its parent port.
 * This node will be named after the kernel form of the device, which is going
 * to be the type,addr aka reg[0],reg[1].
 */
static di_minor_t
i2c_node_minor_device(di_node_t dn)
{
	int nreg, *reg;
	char name[32];

	nreg = di_prop_lookup_ints(DDI_DEV_T_ANY, dn, "reg", &reg);
	if (nreg == 0 || (nreg % 2) != 0) {
		return (DI_MINOR_NIL);
	}

	(void) snprintf(name, sizeof (name), "%x,%x", reg[0], reg[1]);
	dn = di_parent_node(dn);
	if (i2c_node_type(dn) != I2C_NODE_T_PORT) {
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
}

di_minor_t
i2c_node_minor(di_node_t dn)
{
	const char *nt;
	i2c_node_type_t type = i2c_node_type(dn);

	switch (type) {
	case I2C_NODE_T_CTRL:
		nt = DDI_NT_I2C_CTRL;
		break;
	case I2C_NODE_T_PORT:
		nt = DDI_NT_I2C_PORT;
		break;
	case I2C_NODE_T_MUX:
		nt = DDI_NT_I2C_MUX;
		break;
	/*
	 * Device's don't have their control minor under them. The parent port
	 * has it, so when we need that, change this around to go search the
	 * parent for it.
	 */
	case I2C_NODE_T_DEV:
		return (i2c_node_minor_device(dn));
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

bool
i2c_node_is_type(di_node_t dn, i2c_node_type_t type)
{
	return (i2c_node_type(dn) == type);
}


/*
 * This constructs the named i2c path that can be used to get to the node dn
 * through a series of '/' delineated pieces. The canonical name to use varies
 * based on the node type and stop once we hit a controller:
 *
 *  - controllers: controller name in the di_node_t address
 *  - ports: port name in the di_node_t address
 *  - devices: primary i2c address
 */
bool
i2c_node_to_path(i2c_hdl_t *hdl, di_node_t dn, char *buf, size_t buflen)
{
	ilstr_t ils;
	bool first = true;
	i2c_addr_t addr;
	char addrstr[32];

	ilstr_init_prealloc(&ils, buf, buflen);

	for (;;) {
		i2c_node_type_t type = i2c_node_type(dn);

		switch (type) {
		case I2C_NODE_T_CTRL:
		case I2C_NODE_T_PORT:
			if (!first) {
				ilstr_prepend_str(&ils, "/");
			}
			ilstr_prepend_str(&ils, di_bus_addr(dn));
			first = false;
			break;
		case I2C_NODE_T_MUX:
			/*
			 * The i2cnex that represents a mux today is not used in
			 * the logical path that we use with humans.
			 */
			break;
		case I2C_NODE_T_DEV:
			if (!first) {
				ilstr_prepend_str(&ils, "/");
			}

			/*
			 * While it is tempting to use the bus address here, we
			 * cannot actually assume that a device address is
			 * valid. A device will only be addressed on the bus if
			 * a driver is attached to it.
			 *
			 * Therefore a device is identified with the primary
			 * address that it has, e.g. regs[0]. We use the
			 * somewhat more user firendly form of the address where
			 * 10-bit addresses have the leading '1,' to indicate
			 * the class, but 7-bit do not. As in practice that's
			 * what we'll be dealing with 99% of the time.
			 */
			if (!i2c_reg_to_addr(hdl, dn, &addr, 0)) {
				return (false);
			}

			VERIFY(i2c_addr_to_string(hdl, &addr, addrstr,
			    sizeof (addrstr)));
			ilstr_prepend_str(&ils, addrstr);
			first = false;
			break;
		default:
			return (i2c_error(hdl, I2C_ERR_INTERNAL, 0,
			    "encountered unknown node type constructing path: "
			    "0x%x", type));
		}

		/*
		 * If we've hit a controller we're done. However, look out in
		 * case we haven't and make sure we have a parent before
		 * continuing.
		 */
		if (type == I2C_NODE_T_CTRL)
			break;

		dn = di_parent_node(dn);
		if (dn == DI_NODE_NIL)
			break;
	}

	if (ilstr_errno(&ils) != ILSTR_ERROR_OK) {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "failed to "
		    "construct string for node %s: %s", di_node_name(dn),
		    ilstr_errstr(&ils)));
	}

	return (true);
}

/*
 * Parse the kernel's I2C device address style, <type>,<address>. The only
 * thing assumed about str is that it is null terminated. The kernel integers
 * for type and address are always in hex regardless of whether or not they
 * have a leading 0x.
 */
bool
i2c_kernel_address_parse(i2c_hdl_t *hdl, const char *str, i2c_addr_t *addr)
{
	char *eptr;
	unsigned long ul;

	errno = 0;
	ul = strtoul(str, &eptr, 16);
	if (errno != 0 || *eptr != ',') {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "kernel string %s "
		    "did not have a valid leading type", str));
	}

	if (ul == I2C_ADDR_7BIT) {
		addr->ia_type = I2C_ADDR_7BIT;
	} else if (ul == I2C_ADDR_10BIT) {
		addr->ia_type = I2C_ADDR_10BIT;
	} else {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "kernel string %s "
		    "did not have a valid type, found 0x%lx", str, ul));
	}

	errno = 0;
	ul = strtoul(eptr + 1, &eptr, 16);
	if (errno != 0 || *eptr != '\0') {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "kernel string %s "
		    "did not have a valid address", str));
	}

	if ((addr->ia_type == I2C_ADDR_7BIT && ul >= 1 << 7) ||
	    (addr->ia_type == I2C_ADDR_10BIT && ul >= 1 << 10)) {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "kernel string %s "
		    "address 0x%lx is too large for type", str, ul));
	}

	addr->ia_addr = (uint16_t)ul;
	return (true);
}

/*
 * Parse a user address as compared to a kernel address. The main difference
 * here is that the user address does not use a prefix for the 7-bit addresses
 * and the 10-bit addresses use the "10b," prefix.
 */
bool
i2c_addr_parse(i2c_hdl_t *hdl, const char *buf, i2c_addr_t *addr)
{
	char *eptr;
	unsigned long ul;
	const char *comma;
	uint16_t max;

	if (buf == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid address string pointer: %p", buf));
	}

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	comma = strchr(buf, ',');
	if (comma != NULL) {
		size_t len = (uintptr_t)comma - (uintptr_t)buf;
		if (len != 3 || strncmp("10b", buf, len) != 0) {
			return (i2c_error(hdl, I2C_ERR_BAD_ADDR_TYPE, 0,
			    "found invalid address type on %s", buf));
		}
		addr->ia_type = I2C_ADDR_10BIT;
		buf = comma + 1;
		max = 1 << 10;
	} else {
		addr->ia_type = I2C_ADDR_7BIT;
		max = 1 << 7;
	}

	errno = 0;
	ul = strtoul(buf, &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		return (i2c_error(hdl, I2C_ERR_BAD_ADDR, 0, "address %s could "
		    "not be parsed", buf));
	}

	if (ul >= max) {
		return (i2c_error(hdl, I2C_ERR_BAD_ADDR, 0, "address 0x%lx is "
		    "outside the valid range for the address type: [0x00, "
		    "0x%02x]", ul, max - 1));
	}

	addr->ia_addr = (uint16_t)ul;
	return (true);
}

bool
i2c_addr_to_string(i2c_hdl_t *hdl, const i2c_addr_t *addr, char *buf,
    size_t len)
{
	size_t ret;

	if (buf == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid address string pointer: %p", buf));
	}

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	if (!i2c_addr_validate(hdl, addr)) {
		return (false);
	}

	if (addr->ia_type == I2C_ADDR_10BIT) {
		ret = snprintf(buf, len, "10b,0x%03x", addr->ia_addr);
	} else {
		ret = snprintf(buf, len, "0x%02x", addr->ia_addr);
	}
	if (ret >= len) {
		return (i2c_error(hdl, I2C_ERR_BUF_TOO_SMALL, 0, "output "
		    "buffer is too small: need %zu bytes, have %zu", ret,
		    len));
	}

	return (true);
}

/*
 * Convert the specified index for a device into an address.
 */
bool
i2c_reg_to_addr(i2c_hdl_t *hdl, di_node_t dn, i2c_addr_t *addr, uint32_t n)
{
	int nreg, *reg;
	uint32_t type_idx = n * 2;
	uint32_t addr_idx = n * 2 + 1;

	nreg = di_prop_lookup_ints(DDI_DEV_T_ANY, dn, "reg", &reg);
	if (nreg == 0 || (nreg % 2) != 0) {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "device %s@%s "
		    "does not have a valid i2c reg[] property",
		    di_node_name(dn), di_bus_addr(dn)));
	}

	if (addr_idx >= nreg) {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "device %s@%s "
		    "does not have a valid i2c reg[] property",
		    di_node_name(dn), di_bus_addr(dn)));
	}

	if (reg[type_idx] == I2C_ADDR_7BIT) {
		addr->ia_type = I2C_ADDR_7BIT;
	} else if (reg[type_idx] == I2C_ADDR_10BIT) {
		addr->ia_type = I2C_ADDR_10BIT;
	} else {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "device %s@%s "
		    "does not have a valid i2c address type, found 0x%x",
		    di_node_name(dn), di_bus_addr(dn), reg[type_idx]));
	}

	if ((addr->ia_type == I2C_ADDR_7BIT && reg[addr_idx] >= 1 << 7) ||
	    (addr->ia_type == I2C_ADDR_10BIT && reg[addr_idx] >= 1 << 10)) {
		return (i2c_error(hdl, I2C_ERR_INTERNAL, 0, "device %s@%s "
		    "address 0x%x is too large for type", di_node_name(dn),
		    di_bus_addr(dn), reg[addr_idx]));
	}

	addr->ia_addr = (uint16_t)reg[1];

	return (true);
}

bool
i2c_addr_equal(const i2c_addr_t *a, const i2c_addr_t *b)
{
	return (a->ia_type == b->ia_type && a->ia_addr == b->ia_addr);
}

di_node_t
i2c_path_find_ctrl(di_node_t root, const char *name)
{
	for (di_node_t di = di_drv_first_node(I2C_NEX_DRV, root); di != NULL;
	    di = di_drv_next_node(di)) {
		if (!i2c_node_is_type(di, I2C_NODE_T_CTRL)) {
			continue;
		}

		if (strcmp(name, di_bus_addr(di)) == 0) {
			return (di);
		}
	}

	return (DI_NODE_NIL);
}

di_node_t
i2c_path_find_mux(di_node_t dev)
{
	for (di_node_t dn = di_child_node(dev); dn != NULL;
	    dn = di_sibling_node(dn)) {
		if (i2c_node_type(dn) == I2C_NODE_T_MUX) {
			return (dn);
		}
	}

	return (DI_NODE_NIL);
}

di_node_t
i2c_path_find_port(di_node_t parent, const char *name)
{
	for (di_node_t dn = di_child_node(parent); dn != NULL;
	    dn = di_sibling_node(dn)) {
		if (!i2c_node_is_type(dn, I2C_NODE_T_PORT)) {
			continue;
		}

		if (strcmp(di_bus_addr(dn), name) == 0) {
			return (dn);
		}
	}

	return (DI_NODE_NIL);
}

/*
 * When parsing a device, there are three different options that we accept:
 *
 *  - The device's name@address
 *  - The device's address
 *  - The device's driver and instance (e.g. spd511x2)
 *
 * The address is always reg[0] because the aactual node address may not exist
 * at this time. Similarly, we cannot assume that a driver is bound and attached
 * to the node.
 */
di_node_t
i2c_path_find_device(i2c_hdl_t *hdl, di_node_t port, const char *name)
{
	for (di_node_t dn = di_child_node(port); dn != NULL;
	    dn = di_sibling_node(dn)) {
		i2c_addr_t daddr;
		char daddrstr[32];

		if (i2c_node_type(dn) != I2C_NODE_T_DEV) {
			continue;
		}

		if (!i2c_reg_to_addr(hdl, dn, &daddr, 0)) {
			continue;
		}

		if (!i2c_addr_to_string(hdl, &daddr, daddrstr,
		    sizeof (daddrstr))) {
			continue;
		}

		/*
		 * Always check if we match on the converted address.
		 */
		if (strcmp(name, daddrstr) == 0) {
			return (dn);
		}

		/*
		 * We didn't match on that, is there a driver?
		 */
		if (di_driver_name(dn) != NULL && di_instance(dn) != -1) {
			char buf[128];

			(void) snprintf(buf, sizeof (buf), "%s%d",
			    di_driver_name(dn), di_instance(dn));
			if (strcmp(name, buf) == 0) {
				return (dn);
			}
		}

		/*
		 * Finally check if we match name@addr. Only do this if we have
		 * an actual @ in the user bit.
		 */
		const char *at = strchr(name, '@');
		if (at != NULL) {
			char buf[128];

			(void) snprintf(buf, sizeof (buf), "%s@%s",
			    di_node_name(dn), daddrstr);
			if (strcmp(name, buf) == 0) {
				return (dn);
			}
		}
	}

	return (DI_NODE_NIL);
}

bool
i2c_path_parse(i2c_hdl_t *hdl, const char *path, di_node_t root, di_node_t *dnp,
    i2c_node_type_t *typep, i2c_err_t err)
{
	di_node_t cur_devi;
	char *dup, *state;
	i2c_node_type_t cur;
	bool ret = false;

	if (path == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid I2C path pointer: %p", path));
	}

	dup = strdup(path);
	if (dup == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to duplicate "
		    "I2C path"));
	}

	cur = I2C_NODE_T_OTHER;
	cur_devi = NULL;
	for (const char *ent = strtok_r(dup, "/", &state); ent != NULL;
	    ent = strtok_r(NULL, "/", &state)) {
		switch (cur) {
		case I2C_NODE_T_OTHER:
			/*
			 * This is our top-level state. We need to find a
			 * controller that matches this name.
			 */
			cur_devi = i2c_path_find_ctrl(root, ent);
			if (cur_devi == DI_NODE_NIL) {
				(void) i2c_error(hdl, err, 0,
				    "failed to find controller %s as part of "
				    "parsing I2C path %s", ent, path);
				goto err;
			}
			cur = I2C_NODE_T_CTRL;
			break;
		case I2C_NODE_T_DEV:
			/*
			 * Today we expect a device to only ever have a single
			 * node under it which is a mux. We walk all the
			 * children and look for this. This is because muxes
			 * aren't named. It's possible someone has created more
			 * than one node, so that's why we don't just go
			 * directly. After we do this, we explicitly fall
			 * through to the controller handling logic, as it has
			 * to do the same class.
			 */
			cur_devi = i2c_path_find_mux(cur_devi);
			if (cur_devi == DI_NODE_NIL) {
				(void) i2c_error(hdl, err, 0,
				    "failed to find mux %s as part of "
				    "parsing I2C path %s", ent, path);
				goto err;
			}
			/* FALLTHROUGH */
		case I2C_NODE_T_CTRL:
			cur_devi = i2c_path_find_port(cur_devi, ent);
			if (cur_devi == DI_NODE_NIL) {
				(void) i2c_error(hdl, err, 0,
				    "failed to find port %s as part of "
				    "parsing I2C path %s", ent, path);
				goto err;
			}
			cur = I2C_NODE_T_PORT;
			break;
		case I2C_NODE_T_PORT:
			cur_devi = i2c_path_find_device(hdl, cur_devi, ent);
			if (cur_devi == DI_NODE_NIL) {
				(void) i2c_error(hdl, err, 0,
				    "failed to find device %s as part of "
				    "parsing I2C path %s", ent, path);
				goto err;
			}
			cur = I2C_NODE_T_DEV;
			break;
		default:
			abort();
		}
	}

	*dnp = cur_devi;
	*typep = cur;
	ret = true;

err:
	free(dup);
	return (ret);
}
