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
 * Go through our various discovery APIs and make sure that we can find all of
 * the different devices that we expect. This test is designed to operate
 * against the full device complement. Specifically we go through and perform
 * discovery to get the devi, open devices by their devi and then come back and
 * use a path open and verify that we get the same sorts of things.
 */

#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "libi2c_test_util.h"

typedef struct {
	bool cc_fail;
	i2c_ctrl_t *cc_i2c;
	i2c_ctrl_t *cc_smbus;
} ctrl_cb_t;

static bool
disc_ctrl_cb(i2c_hdl_t *hdl, const i2c_ctrl_disc_t *disc, void *arg)
{
	ctrl_cb_t *cb = arg;
	di_node_t di = i2c_ctrl_disc_devi(disc);
	const char *name = di_bus_addr(di);

	if (strcmp(name, "i2csim0") == 0) {
		if (cb->cc_i2c != NULL) {
			warnx("TEST FAILED: discovered i2csim0 a second time!");
			cb->cc_fail = true;
		}

		if (!i2c_ctrl_init(hdl, di, &cb->cc_i2c)) {
			libi2c_test_warn(hdl, "TEST FAILED: failed to "
			    "initialize i2c_ctrl_t for i2csim0");
			cb->cc_fail = true;
		}
	}

	if (strcmp(name, "smbussim1") == 0) {
		if (cb->cc_smbus != NULL) {
			warnx("TEST FAILED: discovered smbussim1 a second "
			    "time!");
			cb->cc_fail = true;
		}

		if (!i2c_ctrl_init(hdl, di, &cb->cc_smbus)) {
			libi2c_test_warn(hdl, "TEST FAILED: failed to "
			    "initialize i2c_ctrl_t for smbussim1");
			cb->cc_fail = true;
		}
	}

	return (true);
}

static bool
disc_ctrl_path(i2c_hdl_t *hdl, i2c_ctrl_t *ctrl, const char *path)
{
	i2c_ctrl_t *alt;
	bool ret = true;

	if (!i2c_ctrl_init_by_path(hdl, path, &alt)) {
		libi2c_test_warn(hdl, "TEST FAILED: failed to initialize "
		    "controller by path %s", path);
		return (false);
	}

	if (strcmp(i2c_ctrl_name(ctrl), i2c_ctrl_name(alt)) != 0) {
		warnx("TEST FAILED: name mismatch on %s: %s vs. %s", path,
		    i2c_ctrl_name(ctrl), i2c_ctrl_name(alt));
		ret = false;
	}

	if (strcmp(i2c_ctrl_path(ctrl), i2c_ctrl_path(alt)) != 0) {
		warnx("TEST FAILED: path mismatch on %s: %s vs. %s", path,
		    i2c_ctrl_path(ctrl), i2c_ctrl_path(alt));
		ret = false;
	}

	if (i2c_ctrl_instance(ctrl) != i2c_ctrl_instance(alt)) {
		warnx("TEST FAILED: instance mismatch on %s: %d vs. %d", path,
		    i2c_ctrl_instance(ctrl), i2c_ctrl_instance(alt));
		ret = false;
	}

	if (i2c_ctrl_nprops(ctrl) != i2c_ctrl_nprops(alt)) {
		warnx("TEST FAILED: nprops mismatch on %s: %u vs. %u", path,
		    i2c_ctrl_nprops(ctrl), i2c_ctrl_nprops(alt));
		ret = false;
	}

	if (ret) {
		(void) printf("TEST PASSED: Controller %s has the same "
		    "properties when discovered by devi and path\n", path);
	}
	i2c_ctrl_fini(alt);
	return (ret);
}

/*
 * Start by finding and opening the controller for i2csim0 and smbussim1 by
 * their devi based upon controller discovery. Once we have, that come back and
 * use the path based and compare the results.
 */
static bool
disc_ctrls(i2c_hdl_t *hdl)
{
	bool ret = true;
	ctrl_cb_t ctrl_cb;

	(void) memset(&ctrl_cb, 0, sizeof (ctrl_cb));
	if (!i2c_ctrl_discover(hdl, disc_ctrl_cb, &ctrl_cb)) {
		libi2c_test_warn(hdl, "TEST FAILED: failed to discover "
		    "controllers");
	}

	if (ctrl_cb.cc_fail) {
		ret = false;
	}

	if (ctrl_cb.cc_i2c != NULL) {
		if (!disc_ctrl_path(hdl, ctrl_cb.cc_i2c, "i2csim0"))
			ret = false;
		i2c_ctrl_fini(ctrl_cb.cc_i2c);
	} else {
		warnx("TEST FAILED: failed to discover i2csim0 controller");
		ret = false;
	}

	if (ctrl_cb.cc_smbus != NULL) {
		if (!disc_ctrl_path(hdl, ctrl_cb.cc_smbus, "smbussim1"))
			ret = false;
		i2c_ctrl_fini(ctrl_cb.cc_smbus);
	} else {
		warnx("TEST FAILED: failed to discover smbussim1 controller");
		ret = false;
	}

	const char *bad_ctrls[] = { "i2csim0/0", "smbussim1/1", "", "foobar",
	    "i2csim0/0/0x20", "0x7777" };
	for (size_t i = 0; i < ARRAY_SIZE(bad_ctrls); i++) {
		i2c_ctrl_t *ctrl;

		if (i2c_ctrl_init_by_path(hdl, bad_ctrls[i], &ctrl)) {
			warnx("TEST FAILED: expected path %s to not result "
			    "in a controller, but we found one!", bad_ctrls[i]);
			ret = false;
			i2c_ctrl_fini(ctrl);
		} else if (i2c_err(hdl) != I2C_ERR_BAD_CONTROLLER) {
			i2c_err_t e = i2c_err(hdl);
			warnx("TEST FAILED: bad controller %s resulted in "
			    "error %s (0x%x), but expected "
			    "I2C_ERR_BAD_CONTROLLER (0x%x)", bad_ctrls[i],
			    i2c_errtostr(hdl, e), e, I2C_ERR_BAD_CONTROLLER);
			ret = false;
		} else {
			(void) printf("TEST PASSED: successfully failed to "
			    "open bad controller '%s'\n", bad_ctrls[i]);
		}
	}

	return (ret);
}

/*
 * Round trip from the devi to a port and get its path and make sure it matches
 * the discovery path.
 */
static bool
disc_port_cb(i2c_hdl_t *hdl, const i2c_port_disc_t *disc, void *arg)
{
	bool *retp = arg;
	i2c_port_t *port;
	const char *dpath = i2c_port_disc_path(disc);

	if (strstr(dpath, "i2csim") == NULL && strstr(dpath, "smbussim") ==
	    NULL) {
		return (true);
	}

	if (!i2c_port_init(hdl, i2c_port_disc_devi(disc), &port)) {
		libi2c_test_warn(hdl, "failed to open port by devi %s", dpath);
		*retp = false;
		return (true);
	}

	const char *alt_path = i2c_port_path(port);
	if (strcmp(alt_path, dpath) == 0) {
		(void) printf("TEST PASSED: port %s has same discovery and "
		    "i2c_port_t path\n", dpath);
	} else {
		warnx("TEST FAILED: port %s has different discovery path %s "
		    "and i2c_port_t path %s", dpath, dpath, alt_path);
		*retp = false;
	}

	i2c_port_fini(port);
	return (true);
}

static bool
disc_port_path(i2c_hdl_t *hdl, const char *path, uint32_t portno,
    i2c_port_type_t type)
{
	bool ret = true;
	i2c_port_t *port;

	if (i2c_port_init_by_path(hdl, path, &port)) {
		if (i2c_port_portno(port) != portno) {
			warnx("TEST FAILED: port %s has port number 0x%x, "
			    "expected 0x%x", path, i2c_port_portno(port),
			    portno);
			ret = false;
		}

		if (i2c_port_type(port) != type) {
			warnx("TEST FAILED: port %s has type 0x%x, expected "
			    "0x%x", path, i2c_port_type(port), type);
			ret = false;
		}

		if (ret) {
			(void) printf("TEST PASSED: port %s has expected "
			    "properties\n", path);
		}
		i2c_port_fini(port);
	} else {
		libi2c_test_warn(hdl, "TEST FAILED: failed to open port %s",
		    path);
		ret = false;
	}

	return (ret);
}

static bool
disc_ports(i2c_hdl_t *hdl)
{
	bool ret = true;

	if (!i2c_port_discover(hdl, disc_port_cb, &ret)) {
		libi2c_test_warn(hdl, "TEST FAILED: failed to walk I2C ports");
		ret = false;
	}

	if (!disc_port_path(hdl, "i2csim0/0", 0, I2C_PORT_TYPE_CTRL)) {
		ret = false;
	}

	if (!disc_port_path(hdl, "smbussim1/1", 1, I2C_PORT_TYPE_CTRL)) {
		ret = false;
	}

	if (!disc_port_path(hdl, "i2csim0/0/0x70/4", 4, I2C_PORT_TYPE_MUX)) {
		ret = false;
	}

	if (!disc_port_path(hdl, "i2csim0/0/0x70/0/0x71/3", 3,
	    I2C_PORT_TYPE_MUX)) {
		ret = false;
	}

	const char *bad_ports[] = { "i2csim0", "i2csim0/0/0x20",
	    "this-does-not-exist", "/", "", "smbussim1/2",
	    "i2csim0/0/0x70/23" };
	for (size_t i = 0; i < ARRAY_SIZE(bad_ports); i++) {
		i2c_port_t *port;

		if (i2c_port_init_by_path(hdl, bad_ports[i], &port)) {
			warnx("TEST FAILED: expected path %s to not result "
			    "in a port, but we found one!", bad_ports[i]);
			ret = false;
			i2c_port_fini(port);
		} else if (i2c_err(hdl) != I2C_ERR_BAD_PORT) {
			i2c_err_t e = i2c_err(hdl);
			warnx("TEST FAILED: bad port %s resulted in error "
			    "%s (0x%x), but expected I2C_ERR_BAD_PORT (0x%x)",
			    bad_ports[i], i2c_errtostr(hdl, e), e,
			    I2C_ERR_BAD_PORT);
			ret = false;
		} else {
			(void) printf("TEST PASSED: successfully failed to "
			    "open bad port '%s'\n", bad_ports[i]);
		}
	}

	return (ret);
}

/*
 * Perform basic verification of the i2csim0 muxes which are named after the
 * driver.
 */
static bool
disc_mux_cb(i2c_hdl_t *hdl, const i2c_mux_disc_t *disc, void *arg)
{
	int *retp = arg;
	const char *path = i2c_mux_disc_path(disc);
	bool valid = true;

	if (strstr(path, "i2csim0/0/0x70") == NULL)
		return (true);

	if (i2c_mux_disc_nports(disc) != 8) {
		warnx("TEST FAILED: mux %s has %u ports, not the expected 8",
		    path, i2c_mux_disc_nports(disc));
		valid = false;
	}

	const char *driver = "pca954x";
	const char *name = i2c_mux_disc_name(disc);
	if (strncmp(driver, name, strlen(driver)) != 0) {
		warnx("TEST FAILED: mux %s has name %s that doesn't start "
		    "with %s", path, i2c_mux_disc_name(disc), driver);
		valid = false;
	}

	if (valid) {
		(void) printf("TEST PASSED: i2csim mux %s has expected "
		    "discovery information\n", path);
	} else {
		*retp = EXIT_FAILURE;
	}

	return (true);
}

typedef struct disc_dev {
	const char *dd_path;
	const char *dd_name;
	const char *dd_driver;
	uint8_t dd_pri;
} disc_dev_t;

/*
 * This is a subset of the devices that we expect to exist that we're going to
 * validate against.
 */
static const disc_dev_t disc_devtab[] = {
	{ "i2csim0/0/0x10", "at24c32", "at24c", 0x10 },
	{ "i2csim0/0/0x70", "pca9548", "pca954x", 0x70 },
	{ "i2csim0/0/0x70/0/0x71", "pca9548", "pca954x", 0x71 },
	{ "i2csim0/0/0x70/2/0x71", "ts5111", "ts511x", 0x71 },
	{ "i2csim0/0/0x70/2/0x72", "ts5111", "ts511x", 0x72 },
	{ "i2csim0/0/0x70/3/0x71", "ts5111", "ts511x", 0x71 },
	{ "i2csim0/0/0x70/3/0x72", "ts5111", "ts511x", 0x72 },
	{ "i2csim0/0/0x70/0/0x71/7/0x72", "at24c32", "at24c", 0x72 },
};

typedef struct {
	bool dc_err;
	bool dc_found[ARRAY_SIZE(disc_devtab)];
} disc_cb_t;

static bool
disc_devs_cb(i2c_hdl_t *hdl, const i2c_dev_disc_t *disc, void *arg)
{
	const disc_dev_t *dd = NULL;
	const char *path = i2c_device_disc_path(disc);
	disc_cb_t *cb = arg;
	size_t idx;

	for (size_t i = 0; i < ARRAY_SIZE(disc_devtab); i++) {
		if (strcmp(disc_devtab[i].dd_path, path) == 0) {
			dd = &disc_devtab[i];
			idx = i;
			break;
		}
	}

	if (dd == NULL) {
		return (true);
	}

	if (cb->dc_found[idx]) {
		warnx("TEST FAILED: discovered device %s twice", dd->dd_path);
		cb->dc_err = true;
		return (true);
	}

	cb->dc_found[idx] = true;
	bool valid = true;
	i2c_dev_info_t *info;

	if (!i2c_device_info_snap(hdl, i2c_device_disc_devi(disc), &info)) {
		libi2c_test_warn(hdl, "TEST FAILED: failed to get device info "
		    "for %s", dd->dd_path);
		cb->dc_err = true;
		return (true);
	}

	if (strcmp(i2c_device_info_path(info), dd->dd_path) != 0) {
		warnx("TEST FAILED: device %s has path %s, expected %s",
		    dd->dd_path, i2c_device_info_path(info), dd->dd_path);
		cb->dc_err = true;
		valid = false;
	}

	if (strcmp(i2c_device_info_name(info), dd->dd_name) != 0) {
		warnx("TEST FAILED: device %s has name %s, expected %s",
		    dd->dd_path, i2c_device_info_name(info), dd->dd_name);
		cb->dc_err = true;
		valid = false;
	}

	if (strcmp(i2c_device_info_driver(info), dd->dd_driver) != 0) {
		warnx("TEST FAILED: device %s has driver %s, expected %s",
		    dd->dd_path, i2c_device_info_driver(info), dd->dd_driver);
		cb->dc_err = true;
		valid = false;
	}

	if (i2c_device_info_addr_source(info, 0) != I2C_ADDR_SOURCE_REG) {
		warnx("TEST FAILED: device %s has address source 0x%x, "
		    "expected 0x%x", dd->dd_path,
		    i2c_device_info_addr_source(info, 0), I2C_ADDR_SOURCE_REG);
		cb->dc_err = true;
		cb->dc_err = true;
		valid = false;
	}

	const i2c_addr_t *addr = i2c_device_info_addr_primary(info);
	if (addr->ia_type != I2C_ADDR_7BIT || addr->ia_addr != dd->dd_pri) {
		warnx("TEST FAILED: device %s has address 0x%x,0x%x, "
		    "expected 0x%x,0x%x", dd->dd_path, addr->ia_type,
		    addr->ia_addr, I2C_ADDR_7BIT, dd->dd_pri);
		cb->dc_err = true;
		valid = false;
	}

	if (valid) {
		(void) printf("TEST PASSED: device %s information matches "
		    "table\n", dd->dd_path);
	}
	i2c_device_info_free(info);
	return (true);
}

static bool
disc_devs(i2c_hdl_t *hdl)
{
	bool ret = true;

	disc_cb_t cb;
	(void) memset(&cb, 0, sizeof (cb));

	if (!i2c_device_discover(hdl, disc_devs_cb, &cb)) {
		libi2c_test_warn(hdl, "TEST FAILED: failed to iterate devices");
		ret = false;
	}

	if (cb.dc_err) {
		ret = false;
	}

	for (size_t i = 0; i < ARRAY_SIZE(cb.dc_found); i++) {
		if (!cb.dc_found[i]) {
			warnx("TEST FAILED: device discovery did not find "
			    "%s", disc_devtab[i].dd_path);
			ret = false;
		}
	}

	const char *bad_devs[] = { "i2csim0", "", "i2csim0/0", "i2csim0/0/",
	    "i2csim0/0/0x702", "i2csim0/0/foobar", "i2csim0/0/0x70/0" };
	for (size_t i = 0; i < ARRAY_SIZE(bad_devs); i++) {
		i2c_port_t *port;
		i2c_dev_info_t *info;

		if (i2c_port_dev_init_by_path(hdl, bad_devs[i], false, &port,
		    &info)) {
			warnx("TEST FAILED: opened bad device path %s",
			    bad_devs[i]);
			i2c_port_fini(port);
			i2c_device_info_free(info);
			ret = false;
		} else if (i2c_err(hdl) != I2C_ERR_BAD_DEVICE) {
			warnx("TEST FAILED: bad device %s resulted in error "
			    "%s (0x%x), but expected I2C_ERR_BAD_DEVICE (0x%x)",
			    bad_devs[i], i2c_errtostr(hdl, i2c_err(hdl)),
			    i2c_err(hdl), I2C_ERR_BAD_DEVICE);
			ret = false;
		} else {
			(void) printf("TEST PASSED: failed to open bad device "
			    "%s\n", bad_devs[i]);
		}
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	i2c_hdl_t *hdl = i2c_init();
	if (hdl == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create "
		    "libi2c handle");
	}

	if (!disc_ctrls(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!disc_ports(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!i2c_mux_discover(hdl, disc_mux_cb, &ret)) {
		libi2c_test_warn(hdl, "TEST FAILURE: failed to iterate "
		    "muxes");
		ret = EXIT_FAILURE;
	}

	if (!disc_devs(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	i2c_fini(hdl);
	return (ret);
}
