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
 * Verify that we fail when we're missing a field in a given request. This works
 * from the empty device profile and targets smbussim1 where there will be no
 * devices.
 */

#include <stdlib.h>
#include <err.h>

#include "libi2c_test_util.h"

static bool
test_add(i2c_hdl_t *hdl, i2c_dev_add_req_t *req, const char *desc)
{
	if (i2c_device_add_req_exec(req)) {
		warnx("TEST FAILED: incomplete device add (%s) accidentally "
		    "succeeded", desc);
		return (false);
	} else if (i2c_err(hdl) != I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS) {
		warnx("TEST FAILED: incomplete device add (%s) failed with "
		    "%s (0x%x), expected I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS "
		    "(0x%x)", desc, i2c_errtostr(hdl, i2c_err(hdl)),
		    i2c_err(hdl), I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS);
		return (false);
	} else {
		(void) printf("TEST PASSED: incomplete device add (%s) failed "
		    "with I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS\n", desc);
		return (true);
	}
}

/*
 * Test that we error with missing fields. The compatible field is optional so
 * this is basically just checking combinations of name and addr.
 */
static bool
missing_adds(i2c_hdl_t *hdl, i2c_port_t *port)
{
	bool ret = true;
	i2c_dev_add_req_t *add;

	if (!i2c_device_add_req_init(port, &add)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize device add requiest");
	}

	if (!test_add(hdl, add, "all")) {
		ret = false;
	}

	const i2c_addr_t addr = { I2C_ADDR_7BIT, 0x23 };
	if (!i2c_device_add_req_set_addr(add, &addr)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to set "
		    "device add address");
	}

	if (!test_add(hdl, add, "name")) {
		ret = false;
	}
	i2c_device_add_req_fini(add);

	if (!i2c_device_add_req_init(port, &add)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize device add requiest");
	}

	if (!i2c_device_add_req_set_name(add, "foobar")) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to set "
		    "device add address");
	}

	if (!test_add(hdl, add, "addr")) {
		ret = false;
	}

	i2c_device_add_req_fini(add);

	return (ret);
}

static bool
test_i2c_io(i2c_hdl_t *hdl, i2c_io_req_t *req, const char *desc)
{
	if (i2c_io_req_exec(req)) {
		warnx("TEST FAILED: incomplete I2C I/O (%s) accidentally "
		    "succeeded", desc);
		return (false);
	} else if (i2c_err(hdl) != I2C_ERR_IO_REQ_MISSING_FIELDS) {
		warnx("TEST FAILED: incomplete I2C I/O (%s) failed with "
		    "%s (0x%x), expected I2C_ERR_IO_REQ_MISSING_FIELDS (0x%x)",
		    desc, i2c_errtostr(hdl, i2c_err(hdl)), i2c_err(hdl),
		    I2C_ERR_IO_REQ_MISSING_FIELDS);
		return (false);
	} else {
		(void) printf("TEST PASSED: incomplete I2C I/O (%s) failed "
		    "with I2C_ERR_IO_REQ_MISSING_FIELDS\n", desc);
		return (true);
	}
}

static bool
missing_i2c_io(i2c_hdl_t *hdl, i2c_port_t *port)
{
	bool ret = true;
	i2c_io_req_t *req;

	if (!i2c_io_req_init(port, &req)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize I2C I/O request");
	}

	if (!test_i2c_io(hdl, req, "all")) {
		ret = false;
	}

	uint8_t rbuf[4] = { 0 };
	uint8_t wbuf[4] = { 0 };
	if (!i2c_io_req_set_transmit_data(req, wbuf, sizeof (wbuf))) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "set I2C transmit buffer");
	}

	if (!i2c_io_req_set_receive_buf(req, rbuf, sizeof (rbuf))) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "set I2C receive buffer");
	}

	if (!test_i2c_io(hdl, req, "addr")) {
		ret = false;
	}
	i2c_io_req_fini(req);
	return (ret);
}

static bool
test_smbus_io(i2c_hdl_t *hdl, smbus_io_req_t *req, const char *desc)
{
	if (smbus_io_req_exec(req)) {
		warnx("TEST FAILED: incomplete SMBus I/O (%s) accidentally "
		    "succeeded", desc);
		return (false);
	} else if (i2c_err(hdl) != I2C_ERR_IO_REQ_MISSING_FIELDS) {
		warnx("TEST FAILED: incomplete SMBus I/O (%s) failed with "
		    "%s (0x%x), expected I2C_ERR_IO_REQ_MISSING_FIELDS (0x%x)",
		    desc, i2c_errtostr(hdl, i2c_err(hdl)), i2c_err(hdl),
		    I2C_ERR_IO_REQ_MISSING_FIELDS);
		return (false);
	} else {
		(void) printf("TEST PASSED: incomplete SMBus I/O (%s) failed "
		    "with I2C_ERR_IO_REQ_MISSING_FIELDS\n", desc);
		return (true);
	}
}

/*
 * We only test a handful of the various SMBus operations here and hope that if
 * it works for them it works for most.
 */
static bool
missing_smbus_io(i2c_hdl_t *hdl, i2c_port_t *port)
{
	bool ret = true;
	smbus_io_req_t *req;

	if (!smbus_io_req_init(port, &req)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize SMBus I/O request");
	}

	if (!test_smbus_io(hdl, req, "all")) {
		ret = false;
	}
	smbus_io_req_fini(req);

	if (!smbus_io_req_init(port, &req)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize SMBus I/O request");
	}

	const i2c_addr_t addr = { I2C_ADDR_7BIT, 0x42 };
	if (!smbus_io_req_set_addr(req, &addr)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "set SMBus request address");
	}

	if (!test_smbus_io(hdl, req, "command")) {
		ret = false;
	}
	smbus_io_req_fini(req);

	if (!smbus_io_req_init(port, &req)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize SMBus I/O request");
	}

	if (!smbus_io_req_set_write_u16(req, 0x23, 0x7777)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "set write u16 command");
	}

	if (!test_smbus_io(hdl, req, "addr: u16")) {
		ret = false;
	}
	smbus_io_req_fini(req);

	if (!smbus_io_req_init(port, &req)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize SMBus I/O request");
	}

	uint8_t buf[4];
	if (!smbus_io_req_set_read_block_i2c(req, 0x23, buf, sizeof (buf))) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "set read I2C block command");
	}

	if (!test_smbus_io(hdl, req, "addr: read block i2c")) {
		ret = false;
	}
	smbus_io_req_fini(req);


	return (ret);
}

int
main(void)
{
	i2c_port_t *port;
	int ret = EXIT_SUCCESS;
	i2c_hdl_t *hdl = i2c_init();
	if (hdl == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create "
		    "libi2c handle");
	}

	if (!i2c_port_init_by_path(hdl, "smbussim1/0", &port)) {
		libi2c_test_fatal(hdl, "INTERNAL TEST FAILURE: failed to "
		    "initialize port smbussim1/0");
	}

	if (!missing_adds(hdl, port)) {
		ret = EXIT_FAILURE;
	}

	if (!missing_i2c_io(hdl, port)) {
		ret = EXIT_FAILURE;
	}

	if (!missing_smbus_io(hdl, port)) {
		ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	i2c_port_fini(port);
	i2c_fini(hdl);
	return (ret);
}
