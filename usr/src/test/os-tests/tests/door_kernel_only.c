/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Tests for the DOOR_KERNEL_ONLY door attribute. A door created with the
 * attribute reports it through door_info(3C) and the kernel refuses
 * door_call(3C) on it from any process with EACCES, before the server
 * procedure runs. A door created without the attribute can be called from
 * a user process, and ucred_iskernel(3C) reports that such a caller is not
 * the kernel.
 */

#include <sys/ccompile.h>
#include <door.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucred.h>
#include <unistd.h>

static uint_t ncalls;
static bool server_kernel;

static void
server(void *cookie __unused, char *argp __unused, size_t asz __unused,
    door_desc_t *dp __unused, uint_t ndesc __unused)
{
	ucred_t *uc = NULL;

	ncalls++;
	if (door_ucred(&uc) != 0)
		err(EXIT_FAILURE, "door_ucred");
	server_kernel = ucred_iskernel(uc);
	ucred_free(uc);
	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * Invoke the door and check the outcome against the expected errno, where
 * 0 means the call is expected to succeed.
 */
static bool
call(int did, const char *desc, int experr)
{
	door_arg_t da = { 0 };

	errno = 0;
	if (door_call(did, &da) == 0) {
		if (experr == 0)
			return (true);
		warnx("%s: door_call unexpectedly succeeded", desc);
		return (false);
	}
	if (experr == 0) {
		warn("%s: door_call failed", desc);
		return (false);
	}
	if (errno != experr) {
		warn("%s: door_call failed with the wrong error", desc);
		return (false);
	}
	return (true);
}

static bool
check_attr(int did, const char *desc, bool expect)
{
	door_info_t di;

	if (door_info(did, &di) != 0)
		err(EXIT_FAILURE, "%s: door_info", desc);
	if (((di.di_attributes & DOOR_KERNEL_ONLY) != 0) != expect) {
		warnx("%s: door_info %s DOOR_KERNEL_ONLY", desc,
		    expect ? "does not report" : "reports");
		return (false);
	}
	return (true);
}

int
main(void)
{
	uint_t fails = 0;
	int plain, konly;
	ucred_t *uc;

	if ((uc = ucred_get(getpid())) == NULL)
		err(EXIT_FAILURE, "ucred_get");
	if (ucred_iskernel(uc)) {
		warnx("ucred_iskernel reports this process as the kernel");
		fails++;
	}
	ucred_free(uc);

	if ((plain = door_create(server, NULL, 0)) == -1)
		err(EXIT_FAILURE, "door_create(plain)");
	if ((konly = door_create(server, NULL, DOOR_KERNEL_ONLY)) == -1)
		err(EXIT_FAILURE, "door_create(DOOR_KERNEL_ONLY)");

	if (!check_attr(plain, "plain door", false))
		fails++;
	if (!check_attr(konly, "kernel-only door", true))
		fails++;

	if (!call(plain, "plain door", 0))
		fails++;
	if (ncalls != 1) {
		warnx("plain door: server procedure ran %u times, expected 1",
		    ncalls);
		fails++;
	}
	if (server_kernel) {
		warnx("plain door: ucred_iskernel reported a kernel caller");
		fails++;
	}

	if (!call(konly, "kernel-only door", EACCES))
		fails++;
	if (ncalls != 1) {
		warnx("kernel-only door: server procedure ran for a refused "
		    "call");
		fails++;
	}

	(void) door_revoke(konly);
	(void) door_revoke(plain);

	if (fails != 0) {
		(void) printf("TEST FAILED: %u check(s) failed\n", fails);
		return (EXIT_FAILURE);
	}
	(void) printf("TEST PASSED\n");
	return (EXIT_SUCCESS);
}
