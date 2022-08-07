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
 * This is designed to act as a basic test of PORT_SOURCE_FILE associations and
 * a regression test for illumos#14898. In particular we want to verify certain
 * behaviors of association and disassociation with respect to the value in the
 * user payload. We will create and tear down the underlying event port each
 * time. The rough cases are:
 *
 *   o associate, trigger, port_get -> first associate event
 *   o associate, associate, trigger, port_get -> second associate event
 *   o associate, trigger, associate, port_get -> second associate event
 *   o associate, disassociate, port_get -> no event
 *   o associate, trigger, disassociate, port_get -> no event
 *   o associate, trigger, disassociate, associate, port_get -> second associate
 *     event
 *   o associate, trigger, disassociate, fstat, associate, port_get -> no event
 */

#include <port.h>
#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <stdbool.h>
#include <sys/sysmacros.h>

static int fa_nfail = 0;
static uintptr_t fa_user = 1;
static char *fa_path;

/*
 * This is a series of actions that we want to be able to take on our port. We
 * keep going until we do encounter a FA_DONE, at which point we do a
 * port_get() to compare things.
 */
typedef enum {
	FA_DONE,
	FA_ASSOC,
	FA_DEASSOC,
	FA_FSTAT,
	FA_TRIGGER
} fa_act_t;

#define	FA_MAX_EVENTS	6

typedef struct {
	bool fa_getevent;
	const char *fa_msg;
	fa_act_t fa_acts[FA_MAX_EVENTS];
} fa_test_t;

fa_test_t fa_tests[] = {
	{ false, "port_get -> no event",
	    { FA_TRIGGER, FA_DONE } },
	{ false, "associate, port_get -> no event",
	    { FA_ASSOC, FA_DONE } },
	{ true, "associate, trigger, port_get -> first user",
	    { FA_ASSOC, FA_TRIGGER, FA_DONE } },
	{ true, "associate, associate, trigger, port_get -> second user",
	    { FA_ASSOC, FA_ASSOC, FA_TRIGGER, FA_DONE } },
	{ true, "associate, trigger, associate, port_get -> second user",
	    { FA_ASSOC, FA_TRIGGER, FA_ASSOC, FA_DONE } },
	{ false, "associate, disassociate, port_get -> no event",
	    { FA_ASSOC, FA_DEASSOC, FA_DONE } },
	{ false, "associate, trigger, disassociate, port_get -> no event",
	    { FA_ASSOC, FA_TRIGGER, FA_DEASSOC, FA_DONE } },
	{ true, "associate, trigger, disassociate, associate, port_get -> "
	    "second user", { FA_ASSOC, FA_TRIGGER, FA_DEASSOC, FA_ASSOC,
	    FA_DONE } },
	{ false, "associate, trigger, disassociate, fstat, associate, port_get "
	    "-> no event", { FA_ASSOC, FA_TRIGGER, FA_DEASSOC, FA_FSTAT,
	    FA_ASSOC, FA_DONE } },
};

static void
fa_run_test(int portfd, int filefd, fa_test_t *test)
{
	int ret;
	uint_t nget;
	struct stat st;
	struct file_obj fo;
	port_event_t pe;
	struct timespec to;
	bool pass;

	/*
	 * At the beginning of a test we stat our underlying file so we can make
	 * sure our information is up to date. We purposefully keep it the same
	 * across a run so that way certain tests will automatically trigger an
	 * event on association.
	 */
	if (fstat(filefd, &st) != 0) {
		warn("failed to stat %s", fa_path);
		(void) printf("TEST FAILED: %s\n", test->fa_msg);
		fa_nfail = 1;
		return;
	}

	bzero(&fo, sizeof (fo));

	for (uint_t i = 0; test->fa_acts[i] != FA_DONE; i++) {
		uint32_t data;

		switch (test->fa_acts[i]) {
		case FA_ASSOC:
			bzero(&fo, sizeof (fo));
			fo.fo_atime = st.st_atim;
			fo.fo_mtime = st.st_mtim;
			fo.fo_ctime = st.st_ctim;
			fo.fo_name = fa_path;

			fa_user++;
			if (port_associate(portfd, PORT_SOURCE_FILE,
			    (uintptr_t)&fo, FILE_MODIFIED, (void *)fa_user) <
			    0) {
				warn("failed to associate event");
				fa_nfail = 1;
			}
			break;
		case FA_DEASSOC:
			if (port_dissociate(portfd, PORT_SOURCE_FILE,
			    (uintptr_t)&fo) != 0) {
				warn("failed to dissociate event");
				fa_nfail = 1;
			}
			break;
		case FA_FSTAT:
			if (fstat(filefd, &st) != 0) {
				warn("failed to stat %s", fa_path);
				fa_nfail = 1;
			}
			break;
		case FA_TRIGGER:
			data = arc4random();
			if (write(filefd, &data, sizeof (data)) < 0) {
				warn("failed to write data to %s", fa_path);
			}
			break;
		default:
			abort();
		}
	}

	/*
	 * At this point we attempt to see if there's an event for us. We
	 * explicitly zero the timeout so we don't wait at all.
	 */
	bzero(&to, sizeof (to));
	bzero(&pe, sizeof (pe));
	nget = 1;
	ret = port_getn(portfd, &pe, 1, &nget, &to);
	if (ret < 0) {
		warn("port_getn failed unexpectedly");
		(void) printf("TEST FAILED: %s\n", test->fa_msg);
		fa_nfail = 1;
		return;
	}

	if (!test->fa_getevent) {
		if (nget != 0) {
			warnx("port_getn() returned an event, but we expected "
			    "none");
			(void) printf("portev_events: 0x%x, portev_source: "
			    "0x%x\n", pe.portev_events, pe.portev_source);
			(void) printf("TEST FAILED: %s\n", test->fa_msg);
			fa_nfail = 1;
		} else {
			(void) printf("TEST PASSED: %s\n", test->fa_msg);
		}
		return;
	} else {
		if (nget == 0) {
			warnx("port_getn() returned no events, but we expected "
			    "one");
			(void) printf("TEST FAILED: %s\n", test->fa_msg);
			fa_nfail = 1;
			return;
		}
	}

	pass = true;
	if (pe.portev_source != PORT_SOURCE_FILE) {
		(void) printf("port source mismatch: found 0x%x, expected "
		    "0x%x\n", pe.portev_source, PORT_SOURCE_FILE);
		pass = false;
	}

	if (pe.portev_events != FILE_MODIFIED) {
		(void) printf("port events mismatch: found 0x%x, expected "
		    "0x%x\n", pe.portev_events, FILE_MODIFIED);
		pass = false;
	}

	if ((uintptr_t)pe.portev_user != fa_user) {
		(void) printf("port user mismatch: found 0x%p, expected "
		    "0x%lx\n", pe.portev_user, fa_user);
		pass = false;

	}

	if (pass) {
		(void) printf("TEST PASSED: %s\n", test->fa_msg);
	} else {
		fa_nfail = 1;
		(void) printf("TEST FAILED: %s\n", test->fa_msg);
	}
}

int
main(void)
{
	int fd;


	if (asprintf(&fa_path, "/tmp/file_assoc_test.%d", getpid()) < 0) {
		err(EXIT_FAILURE, "failed to create temp file");
	}

	fd = open(fa_path, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to create %s", fa_path);
	}

	/*
	 * We open and close the underlying port that we're using for each run
	 * to make sure that any associations that were created do not persist.
	 */
	for (uint_t i = 0; i < ARRAY_SIZE(fa_tests); i++) {
		int port = port_create();
		if (port < 0) {
			err(EXIT_FAILURE, "failed to create event port");
		}
		fa_run_test(port, fd, &fa_tests[i]);
		(void) close(port);
	}

	(void) close(fd);
	(void) unlink(fa_path);
	return (fa_nfail);
}
