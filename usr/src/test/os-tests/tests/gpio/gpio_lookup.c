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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This test verifies that we can look up names across the gpio_sim controllers
 * and that all three return the same results for a given pin.
 */

#include <err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/gpio/kgpio.h>

static int gpio_lookup_ret = EXIT_SUCCESS;
static const char *gpio_paths[] = {
	"/devices/pseudo/kgpio@0:gpio_sim0",
	"/devices/pseudo/kgpio@0:gpio_sim1",
	"/devices/pseudo/kgpio@0:gpio_sim2"
};

static const char *gpio_names[] = {
	"3v3",
	"periodic-500ms",
	"open-drain"
};

static void
gpio_lookup(int fd, const char *name, uint32_t *idp)
{
	kgpio_ioc_name2id_t kin;

	(void) memset(&kin, 0, sizeof (kin));
	if (strlcpy(kin.kin_name, name, sizeof (kin.kin_name)) >=
	    sizeof (kin.kin_name)) {
		errx(EXIT_FAILURE, "would have exceeded kin_name with %s",
		    name);
	}

	if (ioctl(fd, KGPIO_IOC_GPIO_NAME2ID, &kin) != 0) {
		warn("TEST FAILED: failed to translate %s", name);
		gpio_lookup_ret = EXIT_FAILURE;
	} else {
		*idp = kin.kin_id;
	}
}

/*
 * Generate a few different error cases that we know to expect:
 *
 *  o Invalid name due to no '\0'
 *  o Invalid name of length 0
 *  o An unkonwn name
 */
static void
gpio_lookup_errs(int fd)
{
	kgpio_ioc_name2id_t kin;

	(void) memset(&kin, 0, sizeof (kin));
	if (ioctl(fd, KGPIO_IOC_GPIO_NAME2ID, &kin) == 0) {
		warnx("TEST FAILED: zero length lookup passed, expected "
		    "EINVAL");
		gpio_lookup_ret = EXIT_FAILURE;
	} else if (errno != EINVAL) {
		warn("TEST FAILED: zero length lookup had wrong errno, "
		    "expected EINVAL, found");
		gpio_lookup_ret = EXIT_FAILURE;
	}

	(void) memset(kin.kin_name, 'a', sizeof (kin.kin_name));
	if (ioctl(fd, KGPIO_IOC_GPIO_NAME2ID, &kin) == 0) {
		warnx("TEST FAILED: no '\\0' lookup passed, expected "
		    "EINVAL");
		gpio_lookup_ret = EXIT_FAILURE;
	} else if (errno != EINVAL) {
		warn("TEST FAILED: no '\\0' lookup had wrong errno, "
		    "expected EINVAL, found");
		gpio_lookup_ret = EXIT_FAILURE;
	}

	(void) strlcpy(kin.kin_name, "three rings for elven kings",
	    sizeof (kin.kin_name));
	if (ioctl(fd, KGPIO_IOC_GPIO_NAME2ID, &kin) == 0) {
		warnx("TEST FAILED: found rings for elven kings, expected "
		    "ENOENT");
		gpio_lookup_ret = EXIT_FAILURE;
	} else if (errno != ENOENT) {
		warn("TEST FAILED: rings for elven kings had wrong errno, "
		    "expected ENOENT, found");
		gpio_lookup_ret = EXIT_FAILURE;
	}
}

int
main(void)
{
	int fds[ARRAY_SIZE(gpio_paths)];
	uint32_t found_ids[ARRAY_SIZE(gpio_paths)];

	for (size_t i = 0; i < ARRAY_SIZE(gpio_paths); i++) {
		fds[i] = open(gpio_paths[i], O_RDONLY);
		if (fds[i] < 0) {
			err(EXIT_FAILURE, "failed to open controller %s",
			    gpio_paths[i]);
		}
	}

	/*
	 * We expect all of these to be successful.
	 */
	for (size_t name = 0; name < ARRAY_SIZE(gpio_names); name++) {
		uint32_t id0;

		for (size_t ctrl = 0; ctrl < ARRAY_SIZE(gpio_paths); ctrl++) {
			gpio_lookup(fds[ctrl], gpio_names[name],
			    &found_ids[ctrl]);
		}

		id0 = found_ids[0];
		for (size_t ctrl = 0; ctrl < ARRAY_SIZE(gpio_paths); ctrl++) {
			if (found_ids[ctrl] != id0) {
				warnx("ID Mismatch for %s: got %u on "
				    "%s and %u on %s", gpio_names[name],
				    id0, gpio_paths[0], found_ids[ctrl],
				    gpio_paths[ctrl]);
				gpio_lookup_ret = EXIT_FAILURE;
			}
		}

	}

	gpio_lookup_errs(fds[0]);

	return (gpio_lookup_ret);
}
