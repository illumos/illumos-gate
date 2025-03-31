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
 * Verify we can set and obtain various mutex attributes in the structure. This
 * is also a regression test for illumos#17334 where we did not get the type
 * correctly. This does not validate that a mutex can be successfully created
 * with these attributes.
 */

#include <stdlib.h>
#include <err.h>
#include <pthread.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

typedef int (*attr_set_f)(pthread_mutexattr_t *, int);
typedef int (*attr_get_f)(const pthread_mutexattr_t *, int *);

static const int check_types[] = { PTHREAD_MUTEX_NORMAL,
    PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_DEFAULT };
static const int check_shared[] = { PTHREAD_PROCESS_SHARED,
    PTHREAD_PROCESS_PRIVATE };
static const int check_prioceil[] = { 0, 1, 2 };
static const int check_protocol[] = { PTHREAD_PRIO_NONE, PTHREAD_PRIO_INHERIT,
    PTHREAD_PRIO_PROTECT };
static const int check_robust[] = { PTHREAD_MUTEX_STALLED, PTHREAD_MUTEX_ROBUST,
    PTHREAD_MUTEX_STALL_NP, PTHREAD_MUTEX_ROBUST_NP };

static bool
check_field(const char *desc, pthread_mutexattr_t *attr, attr_get_f get_f,
    attr_set_f set_f, int def, const int *vals, size_t nvals, int err_code)
{
	bool ret = true;
	int r, v;

	if ((r = get_f(attr, NULL)) != EINVAL) {
		warnx("TEST FAILED: expected getting %s attribute with invalid "
		    "attr structure to return EINVAL, found %s", desc,
		    strerrorname_np(r));
		ret = false;
	} else {
		(void) printf("TEST PASSED: getting attribute %s with invalid "
		    "attributes returned EINVAL\n");
	}

	if ((r = get_f(attr, &v)) != 0) {
		warnc(r, "TEST FAILED: failed to get default value for mutex "
		    "%s", desc);
		ret = false;
	} else if (v != def) {
		warnx("TEST FAILED: mutex %s has wrong default value: expected "
		    "0x%x, found 0x%x", desc, def, v);
		ret = false;
	} else {
		(void) printf("TEST PASSED: mutex %s default value is the "
		    "expected value\n", desc);
	}

	for (size_t i = 0; i < nvals; i++) {
		if ((r = set_f(attr, vals[i])) != 0) {
			warnc(r, "TEST FAILED: failed to set mutex %s "
			    "attribute to 0x%x", desc, vals[i]);
			ret = false;
			continue;
		}

		if ((r = get_f(attr, &v)) != 0) {
			warnc(r, "TEST FAILED: failed to get value for mutex "
			    "%s", desc);
			ret = false;
		} else if (v != vals[i]) {
			warnx("TEST FAILED: mutex %s has wrong value: expected "
			    "0x%x, found 0x%x", desc, vals[i], v);
			ret = false;
		} else {
			(void) printf("TEST PASSED: mutex %s value matches "
			    "what we just set (0x%x)\n", desc, vals[i]);
		}
	}

	if ((r = set_f(attr, INT32_MAX)) != err_code) {
		warnx("TEST FAILED: expected setting mutex %s to INT32_MAX to "
		    "fail with %s, got %s (0x%x)", desc,
		    strerrorname_np(err_code), strerrorname_np(r), r);
		ret = false;
	} else {
		(void) printf("TEST PASSED: Setting mutex %s to invalid value "
		    "(INT32_MAX) correctly failed with %s\n", desc,
		    strerrorname_np(err_code));
	}

	if ((r = set_f(attr, INT32_MIN)) != err_code) {
		warnx("TEST FAILED: expected setting mutex %s to INT32_MIN to "
		    "fail with %s, got %s (0x%x)", desc,
		    strerrorname_np(err_code), strerrorname_np(r), r);
		ret = false;
	} else {
		(void) printf("TEST PASSED: Setting mutex %s to invalid value "
		    "(INT32_MIN) correctly failed with %s\n", desc,
		    strerrorname_np(err_code));
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS, r;
	pthread_mutexattr_t attr;

	if ((r = pthread_mutexattr_init(&attr)) != 0) {
		errc(EXIT_FAILURE, r, "TEST FAILED: failed to initialize "
		    "mutex attributes");
	}

	if (!check_field("type", &attr, pthread_mutexattr_gettype,
	    pthread_mutexattr_settype, PTHREAD_MUTEX_DEFAULT, check_types,
	    ARRAY_SIZE(check_types), EINVAL)) {
		ret = EXIT_FAILURE;
	}

	if (!check_field("shared", &attr, pthread_mutexattr_getpshared,
	    pthread_mutexattr_setpshared, PTHREAD_PROCESS_PRIVATE, check_shared,
	    ARRAY_SIZE(check_shared), EINVAL)) {
		ret = EXIT_FAILURE;
	}

	if (!check_field("priority ceiling", &attr,
	    pthread_mutexattr_getprioceiling, pthread_mutexattr_setprioceiling,
	    0, check_prioceil, ARRAY_SIZE(check_prioceil), EINVAL)) {
		ret = EXIT_FAILURE;
	}

	if (!check_field("protocol", &attr, pthread_mutexattr_getprotocol,
	    pthread_mutexattr_setprotocol, PTHREAD_PRIO_NONE, check_protocol,
	    ARRAY_SIZE(check_protocol), ENOTSUP)) {
		ret = EXIT_FAILURE;
	}

	if (!check_field("robust", &attr, pthread_mutexattr_getrobust,
	    pthread_mutexattr_setrobust, PTHREAD_MUTEX_STALLED, check_robust,
	    ARRAY_SIZE(check_robust), EINVAL)) {
		ret = EXIT_FAILURE;
	}

	if ((r = pthread_mutexattr_destroy(&attr)) != 0) {
		warnc(r, "TEST FAILED: failed to destroy mutex attributes");
		ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
