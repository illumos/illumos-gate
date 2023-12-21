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
 * Basic program that reads random sensors, mostly ignoring errors. This is in
 * support of the stress test program.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/sensors.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <limits.h>
#include <strings.h>

/*
 * Wait for a random amount in 1500 ms, but make sure to wait at least 10ms.
 */
static uint32_t timeout = 1500;
static uint32_t skew = 10;

int
main(int argc, const char *argv[])
{
	int nsensors = 0, ninst = 0;
	uint32_t ms;

	if (argc != 3) {
		errx(EXIT_FAILURE, "missing required args: ninstance, "
		    "nsensors");
	}

	nsensors = atoi(argv[1]);
	ninst = atoi(argv[2]);
	if (nsensors <= 0 || ninst <= 0) {
		errx(EXIT_FAILURE, "got bad values for some of nesnsors (%u), "
		    "ninst (%u)", nsensors, ninst);
	}

	for (;;) {
		int fd;
		char buf[PATH_MAX];
		uint32_t sens, inst;
		struct timespec ts;
		sensor_ioctl_scalar_t scalar;

		/* 0s based */
		sens = arc4random_uniform(nsensors);
		/* 1s based */
		inst = arc4random_uniform(ninst) + 1;
		(void) snprintf(buf, sizeof (buf),
		    "/dev/sensors/test/test.temp.%u.%u", sens, inst);

		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			warn("failed to open %s", buf);
			goto wait;
		}

		bzero(&scalar, sizeof (scalar));
		if (ioctl(fd, SENSOR_IOCTL_SCALAR, &scalar) != 0) {
			warn("failed to get sensor temperature on %s", buf);
		}

		if (scalar.sis_unit != SENSOR_UNIT_CELSIUS) {
			warnx("data from sensor %s looks off, expected sensor "
			    "to indicate Celsius, but instead %u", buf,
			    scalar.sis_unit);
		}

		(void) close(fd);
wait:
		ms = arc4random_uniform(timeout) + skew;
		ts.tv_sec = ms / 1000;
		ts.tv_nsec = (ms % 1000) * (NANOSEC / MILLISEC);
		(void) nanosleep(&ts, NULL);
	}
	return (0);
}
