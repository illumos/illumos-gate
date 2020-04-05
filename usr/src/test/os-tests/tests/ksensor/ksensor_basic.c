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
 * Copyright 2020 Oxide Computer Company
 */

/*
 * Basic ksensor functionality test
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include <sys/sensors.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static const char *ksensor_path = "/dev/sensors/test/test.temp.0.1";

int
main(void)
{
	sensor_ioctl_kind_t kind;
	sensor_ioctl_temperature_t temp;
	int ret = 0;

	int fd = open(ksensor_path, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open %s",
		    ksensor_path);
	}

	arc4random_buf(&kind, sizeof (kind));
	arc4random_buf(&temp, sizeof (temp));

	if (ioctl(fd, SENSOR_IOCTL_TYPE, &kind) != 0) {
		warn("TEST FAILED: failed to get sensor type");
		ret = EXIT_FAILURE;
	}

	if (kind.sik_kind != SENSOR_KIND_TEMPERATURE) {
		warnx("TEST FAILED: expected temperature sensor, found kind %d",
		    kind);
		ret = EXIT_FAILURE;
	}

	if (ioctl(fd, SENSOR_IOCTL_TEMPERATURE, &temp) != 0) {
		warn("TEST FAILED: failed to get sensor temperature");
		ret = EXIT_FAILURE;
	}

	/*
	 * These values come from the dummy temperature sensor in ksensor_test.
	 */
	if (temp.sit_unit != SENSOR_UNIT_CELSIUS) {
		warnx("TEST FAILED: expected temp unit %" PRIu32 ", but found "
		    "%" PRIu32, SENSOR_UNIT_CELSIUS, temp.sit_unit);
		ret = EXIT_FAILURE;
	}

	if (temp.sit_gran != 4) {
		warnx("TEST FAILED: expected temp gran %" PRId32 ", but found "
		    "%" PRId32, 4, temp.sit_gran);
		ret = EXIT_FAILURE;
	}

	if (temp.sit_prec != -2) {
		warnx("TEST FAILED: expected temp prec %" PRId32 ", but found "
		    "%" PRId32, -2, temp.sit_prec);
		ret = EXIT_FAILURE;
	}

	if (temp.sit_temp != 23) {
		warnx("TEST FAILED: expected temp %" PRId64 ", but found "
		    "%" PRId64, 23, temp.sit_temp);
		ret = EXIT_FAILURE;
	}

	return (ret);
}
