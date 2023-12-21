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
#include <sys/sysmacros.h>

typedef struct sensor_test {
	const char *st_path;
	uint64_t st_kind;
	uint32_t st_unit;
	int32_t st_gran;
	uint32_t st_prec;
	int64_t st_val;
} sensor_test_t;

/*
 * These values come from the dummy sensors in the ksensor_test driver.
 */
static sensor_test_t ksensor_basic_tests[] = {
	{ "/dev/sensors/test/test.temp.0.1", SENSOR_KIND_TEMPERATURE,
	    SENSOR_UNIT_CELSIUS, 4, -2, 23 },
	{ "/dev/sensors/test/test.volt.0.1", SENSOR_KIND_VOLTAGE,
	    SENSOR_UNIT_VOLTS, 1000, 0, 3300 },
	{ "/dev/sensors/test/test.current.0.1", SENSOR_KIND_CURRENT,
	    SENSOR_UNIT_AMPS, 10, 0, 5 },
};

static boolean_t
ksensor_basic(sensor_test_t *st)
{
	sensor_ioctl_kind_t kind;
	sensor_ioctl_scalar_t scalar;
	int fd;

	fd = open(st->st_path, O_RDONLY);
	if (fd < 0) {
		warn("TEST FAILED: failed to open %s", st->st_path);
		return (B_FALSE);
	}

	arc4random_buf(&kind, sizeof (kind));
	arc4random_buf(&scalar, sizeof (scalar));

	if (ioctl(fd, SENSOR_IOCTL_KIND, &kind) != 0) {
		warn("TEST FAILED: %s: failed to get sensor kind", st->st_path);
		goto err;
	}

	if (kind.sik_kind != st->st_kind) {
		warnx("TEST FAILED: %s: expected kind %" PRIu64 ", found kind %"
		    PRIu64, st->st_path, st->st_kind, kind.sik_kind);
		goto err;
	}

	if (ioctl(fd, SENSOR_IOCTL_SCALAR, &scalar) != 0) {
		warn("TEST FAILED: %s: failed to read sensor", st->st_path);
		goto err;
	}

	if (scalar.sis_unit != st->st_unit) {
		warnx("TEST FAILED: %s: expected unit %" PRIu32 ", but found "
		    "%" PRIu32, st->st_path, st->st_unit, scalar.sis_unit);
		goto err;
	}

	if (scalar.sis_gran != st->st_gran) {
		warnx("TEST FAILED: %s: expected gran %" PRId32 ", but found "
		    "%" PRId32, st->st_path, st->st_gran, scalar.sis_gran);
		goto err;
	}

	if (scalar.sis_prec != st->st_prec) {
		warnx("TEST FAILED: %s: expected prec %" PRIu32 ", but found "
		    "%" PRIu32, st->st_path, st->st_prec, scalar.sis_prec);
		goto err;
	}

	if (scalar.sis_value != st->st_val) {
		warnx("TEST FAILED: %s: expected value %" PRId64 ", but found "
		    "%" PRId64, st->st_path, st->st_val, scalar.sis_value);
		goto err;
	}

	return (B_TRUE);
err:
	(void) close(fd);
	return (B_FALSE);
}

int
main(void)
{
	size_t i;
	int ret = EXIT_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(ksensor_basic_tests); i++) {
		if (!ksensor_basic(&ksensor_basic_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}
