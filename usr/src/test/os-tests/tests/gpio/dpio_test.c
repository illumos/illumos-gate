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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * Perform basic validation around DPIO creation cases and that the resulting
 * character devices properly honor the constraints put in them.
 *
 * The test starts by creating 4 DPIOs on GPIOs 0-3:
 *
 *  o GPIO 0: no read/write
 *  o GPIO 1: read-only
 *  o GPIO 2: read-write
 *  o GPIO 3: read-write, kernel
 *
 * We then iterate on GPIOs 4/5 for other tests that should fail to create
 * DPIOs.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/sysmacros.h>
#include <time.h>

#include <sys/gpio/kgpio.h>
#include <sys/gpio/dpio.h>

#define	SIM_NPINS	6

/*
 * For now we hardcode the path to our controller rather than discovering it
 * through libdevinfo or libxpio to simplify the test implementation (and not
 * have deps on libxpio for functionality below libxpio).
 */
static const char *dpio_ctrl_path = "/devices/pseudo/kgpio@0:gpio_sim2";
static int dpio_exit = EXIT_SUCCESS;

typedef struct {
	const char *dce_desc;
	uint32_t dce_gpio;
	const char *dce_name;
	kgpio_dpio_flags_t dce_flags;
	int dce_errno;
} dpio_create_err_t;

const dpio_create_err_t dpio_create_errs[] = {
	{ "GPIO already a DPIO", 0, "WeIrDnAmE12345", 0, EBUSY },
	{ "Name already used", 5, "dpioTESTnone", 0, EEXIST },
	{ "bad pin", UINT32_MAX, "thispindoesnotexist23", 0, ENOENT },
	{ "Name already used", 5, "dpioTESTnone", 0, EEXIST },
	{ "bad flags", 5, "amaZINGflags12345", ~KGPIO_DPIO_F_WRITE, EINVAL },
	{ "bad name 1", 5, "12345!@#$%^", 0, EINVAL },
	{ "bad name 2", 5, "this-is-a-___test!", 0, EINVAL },
};

/*
 * Reuse the error struct, ignoring the error to create our defaults.
 */
static const dpio_create_err_t dpio_default_dpios[] = {
	{ NULL, 0, "dpioTESTnone", 0, 0 },
	{ NULL, 1, "dpioTESTro", KGPIO_DPIO_F_READ, 0 },
	{ NULL, 2, "dpioTESTrw", KGPIO_DPIO_F_READ | KGPIO_DPIO_F_WRITE, 0 },
	{ NULL, 3, "dpioTESTrwK", KGPIO_DPIO_F_READ | KGPIO_DPIO_F_WRITE |
	    KGPIO_DPIO_F_KERNEL, 0 }
};

static void
dpio_fail(const char *fmt, ...)
{
	va_list ap;
	dpio_exit = EXIT_FAILURE;
	(void) printf("TEST FAILED: ");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	(void) putchar('\n');
}

static void
dpio_pass(const char *fmt, ...)
{
	va_list ap;

	(void) printf("TEST PASSED: ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	(void) putchar('\n');
}

static void
dpio_bad_create(int ctrl_fd, const dpio_create_err_t *test)
{
	kgpio_dpio_create_t create;

	(void) memset(&create, 0, sizeof (create));
	create.kdc_id = test->dce_gpio;
	create.kdc_flags = test->dce_flags;
	(void) strlcpy(create.kdc_name, test->dce_name,
	    sizeof (create.kdc_name));

	if (ioctl(ctrl_fd, KGPIO_IOC_DPIO_CREATE, &create) == 0) {
		dpio_fail("DPIO create: %s: succeeded when we expected failure",
		    test->dce_desc);
	} else if (errno != test->dce_errno) {
		dpio_fail("DPIO create failed: %s: but got wrong errno. "
		    "Expected %d, found %d", test->dce_desc, test->dce_errno,
		    errno);
	} else {
		dpio_pass("DPIO create failed: %s", test->dce_desc);
	}
}

static bool
dpio_default_create(int ctrl_fd, uint32_t gpio, const char *name,
    kgpio_dpio_flags_t flags)
{
	kgpio_dpio_create_t create;

	(void) memset(&create, 0, sizeof (create));
	create.kdc_id = gpio;
	create.kdc_flags = flags;
	(void) strlcpy(create.kdc_name, name, sizeof (create.kdc_name));

	if (ioctl(ctrl_fd, KGPIO_IOC_DPIO_CREATE, &create) != 0) {
		warn("failed to create bootstrap DPIO");
		return (false);
	}

	return (true);
}

/*
 * As part of exiting, make sure that there are no DPIOs remaining on our
 * controller. This should not be used for general tests as it ignores a number
 * of errors.
 */
static void
dpio_cleanup(int ctrl_fd)
{
	for (uint32_t i = 0; i < SIM_NPINS; i++) {
		kgpio_dpio_destroy_t destroy;

		(void) memset(&destroy, 0, sizeof (destroy));
		destroy.kdd_id = i;
		if (ioctl(ctrl_fd, KGPIO_IOC_DPIO_DESTROY, &destroy) != 0) {
			if (errno != ENOENT) {
				dpio_fail("failed to cleanup DPIO on pin %u",
				    i);
			}
		}
	}
}

/*
 * Verify the various set of features around writing to a DPIO work:
 *
 *  o Getting the current output
 *  o Advancing write timestamps
 *  o Actually performing the write
 *
 * If any of these fail, we short-circuit and don't perform the rest.
 */
static void
dpio_test_cbops_write(int fd, const char *path)
{
	dpio_curout_t curout;
	dpio_timing_t pre, post;
	uint32_t val;
	ssize_t ret;

	(void) memset(&curout, 0, sizeof (curout));
	if (ioctl(fd, DPIO_IOC_CUROUT, &curout) != 0) {
		dpio_fail("failed to get DPIO_IOC_CUROUT on %s: %s", path,
		    strerror(errno));
		return;
	}
	dpio_pass("DPIO_IOC_CUROUT successful on %s", path);

	(void) memset(&pre, 0, sizeof (pre));
	(void) memset(&post, 0, sizeof (post));
	if (ioctl(fd, DPIO_IOC_TIMING, &pre) != 0) {
		dpio_fail("failed to get DPIO_IOC_TIMING on %s: %s", path,
		    strerror(errno));
		return;
	}
	dpio_pass("DPIO_IOC_TIMING successful on %s", path);

	val = curout.dps_curout;
	ret = write(fd, &val, sizeof (val));
	if (ret == -1) {
		dpio_fail("write failed on %s: %s", path, strerror(ret));
		return;
	} else if (ret != 4) {
		dpio_fail("write to %s returned wrong number of bytes: %ld, "
		    "expected 4 bytes", path, ret);
		return;
	}
	dpio_pass("write successful on %s", path);

	if (ioctl(fd, DPIO_IOC_TIMING, &post) != 0) {
		dpio_fail("failed to get post-write DPIO_IOC_TIMING on %s: %s",
		    path, strerror(errno));
		return;
	}

	if (post.dpt_last_write > pre.dpt_last_write) {
		dpio_pass("write time advanced on %s", path);
	} else {
		dpio_fail("write time on %s did not advance, pre: 0x%lx, "
		    "post: 0x%lx", pre.dpt_last_write, post.dpt_last_write);
	}
}

static void
dpio_test_cbops(const char *name, bool can_open, bool can_read, bool can_write)
{
	uint32_t val;
	char path[PATH_MAX];
	dpio_curout_t curout;
	int fd;
	ssize_t ret;

	(void) snprintf(path, sizeof (path), "/dev/dpio/%s", name);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		if (!can_open) {
			dpio_pass("failed to open %s", path);
		} else {
			dpio_fail("failed to open %s, but expected to: %s",
			    path, strerror(errno));
		}
		return;
	} else {
		if (!can_open) {
			dpio_fail("TEST FAILED: accidentally was able to open "
			    "%s", path);
			return;
		} else {
			dpio_pass("successfully opened %s", path);
		}
	}

	errno = 0;
	ret = read(fd, &val, sizeof (val));
	if (ret != 4) {
		if (!can_read && errno == ENOTSUP) {
			dpio_pass("successfully failed to read %s", path);
		} else if (!can_read) {
			dpio_fail("failed to read %s: %s, but expected ENOTSUP",
			    path, strerror(errno));
		} else {
			dpio_fail("failed to read %s: %s", path,
			    strerror(errno));
		}
	} else {
		if (!can_read) {
			dpio_fail("successfully read %s, but expected failure",
			    path);
		} else {
			dpio_pass("successfully read %s", path);
		}
	}

	if (can_write) {
		dpio_test_cbops_write(fd, path);
		(void) close(fd);
		return;
	}

	/*
	 * Test the can't write path case here. This means we expect that
	 * getting the current output will fail and that a write will fail. We
	 * won't bother checking the timing information in this case either.
	 * That is being done in the write check.
	 */

	(void) memset(&curout, 0, sizeof (curout));
	if (ioctl(fd, DPIO_IOC_CUROUT, &curout) == 0) {
		dpio_fail("DPIO_IOC_CUROUT worked on %s, but expected failure",
		    path);
	} else if (errno != ENOTSUP) {
		dpio_fail("got unexpected errno from DPIO_IOC_CUROUT ioctl on "
		    "%s: %s, expected ENOTSUP", path, strerror(errno));
	} else {
		dpio_pass("DPIO_IOC_CUROUT failed on %s", path);
	}

	val = 0;
	if (write(fd, &val, sizeof (val)) == 0) {
		dpio_fail("wrote to %s, but expected failure", path);
	} else if (errno != ENOTSUP) {
		dpio_fail("got unexpected errno writing to %s: %s, expected "
		    "ENOTSUP", path, strerror(errno));
	} else {
		dpio_pass("successfully failed to write %s", path);
	}

	(void) close(fd);
}

/*
 * The /dev entries for a DPIO are created somewhat asynchronously from the
 * minor node which is created synchronously in the ioctl. Poll in 10ms chunks
 * for one of these to show up.
 */
static void
dpio_dev_poll(void)
{
	struct timespec ts;
	size_t max;

	ts.tv_sec = 0;
	ts.tv_nsec = MSEC2NSEC(10);
	max = SEC2NSEC(1) / ts.tv_nsec;

	for (size_t i = 0; i < ARRAY_SIZE(dpio_default_dpios); i++) {
		char buf[PATH_MAX];
		bool found = false;

		(void) snprintf(buf, sizeof (buf), "/dev/dpio/%s",
		    dpio_default_dpios[i].dce_name);

		for (size_t i = 0; i < max; i++) {
			struct stat st;

			if (stat(buf, &st) == 0) {
				found = true;
				break;
			}

			(void) nanosleep(&ts, NULL);
		}

		if (!found) {
			dpio_fail("timed out waiting for %s", buf);
		}
	}
}

/*
 * Verify that basic FEXCL behavior works.
 */
static void
dpio_test_excl(void)
{
	int exclfd, nonexcl;
	char path[PATH_MAX];

	(void) snprintf(path, sizeof (path), "/dev/dpio/%s",
	    dpio_default_dpios[0].dce_name);

	nonexcl = open(path, O_RDWR);
	if (nonexcl < 0) {
		dpio_fail("couldn't open base non-excl fd: %s",
		    strerror(errno));
		return;
	}

	exclfd = open(path, O_RDWR | O_EXCL);
	if (exclfd >= 0) {
		dpio_fail("open O_EXCL worked, but dev was already open with "
		    "fd %d", nonexcl);
	} else if (errno != EBUSY) {
		dpio_fail("open O_EXCL if already open failed with unexpected "
		    "errno: %s, expected EBUSY", strerror(errno));
	} else {
		dpio_pass("open O_EXCL fails if already open");
	}
	(void) close(nonexcl);

	exclfd = open(path, O_RDWR | O_EXCL);
	if (exclfd < 0) {
		dpio_fail("couldn't open bae excl fd: %s", strerror(errno));
		return;
	} else {
		dpio_pass("base O_EXCL open");
	}

	nonexcl = open(path, O_RDWR);
	if (nonexcl >= 0) {
		dpio_fail("O_EXCL didn't block subsequent open of fd %d",
		    exclfd);
	} else if (errno != EBUSY) {
		dpio_fail("O_EXCL blocked other open, but with unexpected "
		    "errno: %s, expected EBUSY", strerror(errno));
	} else {
		dpio_pass("O_EXCL blocks subsequent open");
	}

	(void) close(exclfd);
}

/*
 * Verify we can't destroy a DPIO if it's currently open.
 */
static void
dpio_destroy_ebusy(int ctrl_fd)
{
	int fd;
	char path[PATH_MAX];
	kgpio_dpio_destroy_t destroy;

	(void) snprintf(path, sizeof (path), "/dev/dpio/%s",
	    dpio_default_dpios[0].dce_name);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		dpio_fail("failed to open %s for destruction tests: %s", path,
		    strerror(errno));
		return;
	}

	(void) memset(&destroy, 0, sizeof (destroy));
	destroy.kdd_id = dpio_default_dpios[0].dce_gpio;

	if (ioctl(ctrl_fd, KGPIO_IOC_DPIO_DESTROY, &destroy) == 0) {
		dpio_fail("DPIO was destroyed despite open fd!!");
	} else if (errno != EBUSY) {
		dpio_fail("failed to destroy DPIO with open fd, but got wrong "
		    "errno: found %s, expected EBUSY", strerror(errno));
	} else {
		dpio_pass("failed to destroy DPIO with open fd");
	}

	(void) close(fd);
}

int
main(void)
{
	int ctrl_fd;

	ctrl_fd = open(dpio_ctrl_path, O_RDWR);
	if (ctrl_fd < 0) {
		err(EXIT_FAILURE, "failed to open controller %s",
		    dpio_ctrl_path);
	}

	/*
	 * We use somewhat gross names with the hope that we'll avoid anything
	 * actually created.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(dpio_default_dpios); i++) {
		const dpio_create_err_t *t = &dpio_default_dpios[i];
		if (!dpio_default_create(ctrl_fd, t->dce_gpio, t->dce_name,
		    t->dce_flags)) {
			dpio_fail("failed to create initial DPIOs");
			goto cleanup;
		} else {
			dpio_pass("created bootstrap DPIO %u", i);
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(dpio_create_errs); i++) {
		dpio_bad_create(ctrl_fd, &dpio_create_errs[i]);
	}

	/*
	 * Make sure we get our links and then go through and test the various
	 * cbops work or don't work based on the actual values that we set.
	 */
	dpio_dev_poll();

	dpio_test_cbops("dpioTESTnone", true, false, false);
	dpio_test_cbops("dpioTESTro", true, true, false);
	dpio_test_cbops("dpioTESTrw", true, true, true);
	dpio_test_cbops("dpioTESTrwK", false, false, false);

	/*
	 * Verify a few particular behaviours around fds. In particular we want
	 * to make sure O_EXCL / FEXCL is honored properly in the device. We
	 * also want to make sure that you can't destroy something if the fd is
	 * open.
	 */
	dpio_test_excl();
	dpio_destroy_ebusy(ctrl_fd);

cleanup:
	dpio_cleanup(ctrl_fd);

	(void) close(ctrl_fd);
	if (dpio_exit == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}
	return (dpio_exit);
}
