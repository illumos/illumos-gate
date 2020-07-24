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

	if (ioctl(fd, SENSOR_IOCTL_KIND, &kind) == 0) {
		warnx("TEST FAILED: SENSOR_IOCTL_KIND succeeded on EIO "
		    "sensor");
		error_exit = EXIT_FAILURE;
	}

	if (errno != exp) {
		warnx("TEST FAILED: SENSOR_IOCTL_KIND got errno %d, "
		    "expected %d", errno, exp);
		error_exit = EXIT_FAILURE;
	}

	if (memcmp(&kind, &alt_kind, sizeof (alt_kind)) != 0) {
		warnx("TEST FAILED: SENSOR_IOCTL_KIND modified data on error");
		error_exit = EXIT_FAILURE;
	}
}

static void
error_temp(int fd, int exp)
{
	sensor_ioctl_scalar_t scalar, alt_scalar;

	arc4random_buf(&alt_scalar, sizeof (alt_scalar));
	(void) memcpy(&scalar, &alt_scalar, sizeof (alt_scalar));

	if (ioctl(fd, SENSOR_IOCTL_SCALAR, &scalar) == 0) {
		warnx("TEST FAILED: SENSIOR_IOCTL_SCALAR suceeded on "
		    "EIO sensor");
		error_exit = EXIT_FAILURE;
	}

	if (errno != exp) {
		warnx("TEST FAILED: SENSIOR_IOCTL_SCALAR got errno %d, "
		    "expected %d", errno, EIO);
		error_exit = EXIT_FAILURE;
	}

	if (memcmp(&scalar, &alt_scalar, sizeof (alt_scalar)) != 0) {
		warnx("TEST FAILED: SENSIOR_IOCTL_SCALAR modified "
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
