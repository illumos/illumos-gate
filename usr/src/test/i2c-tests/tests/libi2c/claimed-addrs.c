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
 * Validate that our fake at24c08 which claims additional addresses properly
 * reports that it does. This requires that the driver be attached, which we
 * force by opening up the corresponding eeprom file in /dev/eeprom.
 */

#include <stdlib.h>
#include <err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/debug.h>
#include <unistd.h>

#include "libi2c_test_util.h"

int
main(void)
{
	int ret = EXIT_SUCCESS;
	i2c_hdl_t *hdl = i2c_init();
	if (hdl == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create "
		    "libi2c handle");
	}

	/*
	 * Get an initial snapshot of the device information so we can get the
	 * driver and instance to open up the device.
	 */
	i2c_port_t *port;
	i2c_dev_info_t *info;

	if (!i2c_port_dev_init_by_path(hdl, "i2csim0/0/0x20", false, &port,
	    &info)) {
		libi2c_test_fatal(hdl, "TEST FAILED: failed to initialize "
		    "i2csim0/0/0x20");
	}

	char path[PATH_MAX];
	(void) snprintf(path, sizeof (path), "/dev/eeprom/%s/%d/eeprom",
	    i2c_device_info_driver(info), i2c_device_info_instance(info));
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open EEPROM %s",
		    path);
	}

	i2c_device_info_free(info);
	i2c_port_fini(port);

	/*
	 * Take a fresh snapshot of the device information now that we have the
	 * device open we're guaranteed the driver is attached and has claimed
	 * all of its addresses.
	 */
	if (!i2c_port_dev_init_by_path(hdl, "i2csim0/0/0x20", false, &port,
	    &info)) {
		libi2c_test_fatal(hdl, "TEST FAILED: failed to snapshot "
		    "i2csim0/0/0x20");
	}

	if (i2c_device_info_naddrs(info) != 4) {
		warnx("TEST FAILED: expected 4 addresses, but found %u",
		    i2c_device_info_naddrs(info));
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: successfully found 4 at24c08 "
		    "addresses\n");
	}

	if (i2c_device_info_addr_source(info, 0) != I2C_ADDR_SOURCE_REG) {
		warnx("TEST FAILED: at24c08 address 0 has wrong source 0x%x, "
		    "expected reg (0x%x)", i2c_device_info_addr_source(info, 0),
		    I2C_ADDR_SOURCE_REG);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: at24c08 address 0 correctly noted "
		    "as from reg[]\n");
	}

	for (uint32_t i = 1; i < i2c_device_info_naddrs(info); i++) {
		if (i2c_device_info_addr_source(info, i) !=
		    I2C_ADDR_SOURCE_CLAIMED) {
			warnx("TEST FAILED: at24c08 address %u has wrong "
			    "source 0x%x, expected claimed (0x%x)", i,
			    i2c_device_info_addr_source(info, i),
			    I2C_ADDR_SOURCE_CLAIMED);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: at24c08 address %u "
			    "correctly noted as claimed\n");
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	VERIFY0(close(fd));
	i2c_device_info_free(info);
	i2c_port_fini(port);
	i2c_fini(hdl);
	return (ret);
}
