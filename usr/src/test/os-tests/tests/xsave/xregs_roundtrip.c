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
 * Verify that we can read the xregs of a thread and write them back intact.
 * This uses libproc as a wrapper. We then start the thread running again and
 * attempt to write to /proc ourselves to expect an EBUSY because the thread is
 * not stopped.
 */

#include <libproc.h>
#include <thread.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "xsave_util.h"

int
main(void)
{
	int ret, fd;
	ssize_t sret;
	struct ps_prochandle *P;
	struct ps_lwphandle *L;
	thread_t targ;
	prxregset_t *prx, *prx_alt;
	size_t prx_len, prx_alt_len;
	struct iovec iov[2];
	long cmd = PCSXREG;

	P = Pgrab(getpid(), PGRAB_RDONLY, &ret);
	if (P == NULL) {
		errx(EXIT_FAILURE, "failed to grab ourself: %s",
		    Pgrab_error(ret));
	}

	ret = thr_create(NULL, 0, xsu_sleeper_thread, NULL, THR_DETACHED,
	    &targ);
	if (ret != 0) {
		errc(EXIT_FAILURE, ret, "failed to create sleeper thread");
	}

	L = Lgrab(P, targ, &ret);
	if (L == NULL) {
		errx(EXIT_FAILURE, "failed to grab our sleeper thread: %s",
		    Lgrab_error(ret));
	}

	ret = Lstop(L, 0);
	if (ret != 0) {
		err(EXIT_FAILURE, "failed to stop the sleeper thread");
	}

	if (Lgetxregs(L, &prx, &prx_len) != 0) {
		err(EXIT_FAILURE, "failed to get xregs");
	}

	(void) printf("TEST PASSED: successfully got initial xregs\n");

	if (Lsetxregs(L, prx, prx_len) != 0) {
		err(EXIT_FAILURE, "failed to set xregs");
	}

	(void) printf("TEST PASSED: successfully set xregs\n");

	if (Lgetxregs(L, &prx_alt, &prx_alt_len) != 0) {
		err(EXIT_FAILURE, "failed to get xregs after write");
	}

	if (prx_len != prx_alt_len) {
		errx(EXIT_FAILURE, "xreg length changed across a write: "
		    "originally found %zu, now %zu", prx_len, prx_alt_len);
	}

	if (memcmp(prx, prx_alt, prx_len) != 0) {
		const uint8_t *a = (uint8_t *)prx;
		const uint8_t *b = (uint8_t *)prx_alt;
		for (size_t i = 0; i < prx_len; i++) {
			if (a[i] != b[i]) {
				(void) fprintf(stderr, "prx[0x%x] = 0x%02x, "
				    "prx_alt[0x%x] = 0x%02x\n", i, a[i], i,
				    b[i]);
			}
		}
		errx(EXIT_FAILURE, "xregs were not the same!");
	}

	(void) printf("TEST PASSED: round-trip xregs\n");

	if (Lsetrun(L, 0, 0) != 0) {
		err(EXIT_FAILURE, "failed to start sleeper thread");
	}

	/*
	 * We write to /proc directly ourselves as a way to avoid libproc's own
	 * checks for the state of the thread.
	 */
	fd = Lctlfd(L);
	if (fd < 0) {
		errx(EXIT_FAILURE, "failed to get sleeper thread control d");
	}

	iov[0].iov_base = (char *)&cmd;
	iov[0].iov_len = sizeof (long);
	iov[1].iov_base = (char *)prx;
	iov[1].iov_len = prx_len;
	sret = writev(fd, iov, ARRAY_SIZE(iov));
	if (sret != -1) {
		errx(EXIT_FAILURE, "writev returned %zd, but expected -1",
		    sret);
	}

	if (errno != EBUSY) {
		errx(EXIT_FAILURE, "xregs error was not EBUSY, got %d!", errno);
	}

	(void) printf("TEST PASSED: got EBUSY with PCSXREG to running "
	    "thread\n");
	Plwp_freexregs(P, prx, prx_len);
	return (EXIT_SUCCESS);
}
