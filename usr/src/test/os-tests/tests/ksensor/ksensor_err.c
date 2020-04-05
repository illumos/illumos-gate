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
 * Describe the purpose of this file.
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
#include <sys/sysmacros.h>

static const char *error_sensor = "/dev/sensors/test/test.eio.0";
static int error_exit;

static void
error_kind(int fd, int exp)
{
	sensor_ioctl_kind_t kind, alt_kind;

	arc4random_buf(&alt_kind, sizeof (alt_kind));
	(void) memcpy(&kind, &alt_kind, sizeof (alt_kind));

	if (ioctl(fd, SENSOR_IOCTL_TYPE, &kind) == 0) {
		warnx("TEST FAILED: SENSIOR_IOCTL_TYPE succeeded on EIO "
		    "sensor");
		error_exit = EXIT_FAILURE;
	}

	if (errno != exp) {
		warnx("TEST FAILED: SENSIOR_IOCTL_TYPE got errno %d, "
		    "expected %d", errno, exp);
		error_exit = EXIT_FAILURE;
	}

	if (memcmp(&kind, &alt_kind, sizeof (alt_kind)) != 0) {
		warnx("TEST FAILED: SENSIOR_IOCTL_TYPE modified data on error");
		error_exit = EXIT_FAILURE;
	}
}

static void
error_temp(int fd, int exp)
{
	sensor_ioctl_temperature_t temp, alt_temp;

	arc4random_buf(&alt_temp, sizeof (alt_temp));
	(void) memcpy(&temp, &alt_temp, sizeof (alt_temp));

	if (ioctl(fd, SENSOR_IOCTL_TEMPERATURE, &temp) == 0) {
		warnx("TEST FAILED: SENSIOR_IOCTL_TEMPERATURE suceeded on "
		    "EIO sensor");
		error_exit = EXIT_FAILURE;
	}

	if (errno != exp) {
		warnx("TEST FAILED: SENSIOR_IOCTL_TEMPERATURE got errno %d, "
		    "expected %d", errno, EIO);
		error_exit = EXIT_FAILURE;
	}

	if (memcmp(&temp, &alt_temp, sizeof (alt_temp)) != 0) {
		warnx("TEST FAILED: SENSIOR_IOCTL_TEMPERATURE modified "
		    "data on error");
		error_exit = EXIT_FAILURE;
	}
}

int
main(void)
{
	int i;
	int flags[] = { O_RDWR, O_WRONLY, O_RDONLY | O_NDELAY,
		O_RDONLY | O_NONBLOCK };
	int fd = open(error_sensor, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open %s",
		    error_sensor);
	}

	error_kind(fd, EIO);
	error_temp(fd, EIO);
	(void) close(fd);

	/*
	 * Check for illegal open combinations.
	 */
	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		fd = open(error_sensor, flags[i]);
		if (fd >= 0) {
			printf("i is %d\n", i);
			warnx("TEST FAILED: opened a sensor with flags 0x%x, "
			    "but expected failure", flags[i]);
			error_exit = EXIT_FAILURE;
		}
	}

	return (error_exit);
}
