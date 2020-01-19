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
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Test different O_DIRECTORY open cases.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <door.h>
#include <stropts.h>
#include <sys/socket.h>

static uint_t odir_failures;
static char odir_fpath[PATH_MAX];
static char odir_dpath[PATH_MAX];
static char odir_doorpath[PATH_MAX];
static char odir_enoent[PATH_MAX];
static char odir_udspath[PATH_MAX];
static int odir_did = -1;
static int odir_uds = -1;

static void
odir_test_one(const char *test, const char *path, int flags, int err)
{
	int fd = open(path, flags | O_DIRECTORY | O_RDONLY, 0644);
	if (fd >= 0) {
		(void) close(fd);
		if (err != 0) {
			odir_failures++;
			warnx("TEST FAILED: %s: opened %s, but expected error: "
			    "%d", test, path, err);
		}
	} else {
		if (err == 0) {
			odir_failures++;
			warnx("TEST FAILED: %s: failed to open %s, error: %d",
			    test, path, err);
		} else if (err != errno) {
			odir_failures++;
			warnx("TEST FAILED: %s: wrong error for path %s, "
			    "found %d, expected %d", test, path, errno, err);
		}
	}
}

static void
odir_door_server(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t ndesc)
{
	(void) door_return(NULL, 0, NULL, 0);
}

static boolean_t
odir_setup(void)
{
	int fd;
	struct stat st;
	struct sockaddr_un un;
	pid_t pid = getpid();

	(void) snprintf(odir_fpath, sizeof (odir_fpath),
	    "/tmp/odir.%d.file", pid);
	if ((fd = creat(odir_fpath, 0644)) < 0) {
		warn("failed to create temp file %s", odir_fpath);
		odir_fpath[0] = '\0';
		return (B_FALSE);
	}
	(void) close(fd);

	(void) snprintf(odir_dpath, sizeof (odir_dpath),
	    "/tmp/odir.%d.dir", pid);
	if (mkdir(odir_dpath, 0755) != 0) {
		warn("failed to create temp directory %s", odir_dpath);
		odir_dpath[0] = '\0';
		return (B_FALSE);
	}

	odir_did = door_create(odir_door_server, NULL, 0);
	if (odir_did == -1) {
		warnx("failed to create door");
		return (B_FALSE);
	}
	(void) snprintf(odir_doorpath, sizeof (odir_doorpath),
	    "/tmp/odir.%d.door", pid);
	if ((fd = creat(odir_doorpath, 0644)) < 0) {
		warn("failed to create %s", odir_doorpath);
		odir_doorpath[0] = '\0';
		return (B_FALSE);
	}
	(void) close(fd);
	if (fattach(odir_did, odir_doorpath) != 0) {
		warn("failed to attach door to %s", odir_doorpath);
		(void) unlink(odir_doorpath);
		odir_doorpath[0] = '\0';
		return (B_FALSE);
	}

	(void) snprintf(odir_enoent, sizeof (odir_enoent),
	    "/tmp/odir.%d.enoent", pid);
	if (stat(odir_enoent, &st) == 0) {
		warnx("somehow random file %s exists!", odir_enoent);
	}

	odir_uds = socket(PF_UNIX, SOCK_STREAM, 0);
	if (odir_uds == -1) {
		warn("failed to create UDS");
		return (B_FALSE);
	}
	(void) snprintf(odir_udspath, sizeof (odir_udspath),
	    "/tmp/odir.%d.uds", pid);
	(void) memset(&un, '\0', sizeof (un));
	un.sun_family = AF_UNIX;
	if (strlcpy(un.sun_path, odir_udspath, sizeof (un.sun_path)) >=
	    sizeof (un.sun_path)) {
		warnx("%s overflows AF_UNIX path", odir_udspath);
		odir_udspath[0] = '\0';
		return (B_FALSE);
	}

	if (bind(odir_uds, (struct sockaddr *)&un, SUN_LEN(&un)) != 0) {
		warn("failed to bind %s", odir_udspath);
		odir_udspath[0] = '\0';
		return (B_FALSE);
	}

	if (listen(odir_uds, 1) != 0) {
		warn("failed to listen on %s", odir_udspath);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
odir_verify_enoent(void)
{
	struct stat st;

	if (stat(odir_enoent, &st) == 0) {
		warnx("TEST FAILED: %s was created", odir_enoent);
		odir_failures++;
	} else if (errno != ENOENT) {
		warn("TEST FAILED: stat on %s failed", odir_enoent);
		odir_failures++;
	}
}

static void
odir_cleanup(void)
{
	if (odir_udspath[0] != '\0') {
		if (unlink(odir_udspath) != 0) {
			warn("failed to unlink %s", odir_udspath);
		}
	}

	if (odir_uds != -1) {
		if (close(odir_uds) != 0) {
			warn("failed to close UDS");
		}
	}

	if (odir_doorpath[0] != '\0') {
		if (fdetach(odir_doorpath) != 0) {
			warn("failed to detach door %s", odir_doorpath);
		}

		if (unlink(odir_doorpath) != 0) {
			warn("failed to unlink %s", odir_doorpath);
		}
	}

	if (odir_did != -1) {
		if (door_revoke(odir_did) != 0) {
			warn("failed to revoke door");
		}
	}

	if (odir_dpath[0] != '\0') {
		if (rmdir(odir_dpath) != 0) {
			warn("failed to clean up %s", odir_dpath);
		}
	}

	if (odir_fpath[0] != '\0') {
		if (unlink(odir_fpath) != 0) {
			warn("failed to clean up %s", odir_fpath);
		}
	}
}

int
main(void)
{
	if (!odir_setup()) {
		odir_cleanup();
		return (EXIT_FAILURE);
	}

	odir_test_one("regular file", odir_fpath, 0, ENOTDIR);
	odir_test_one("directory", odir_dpath, 0, 0);
	odir_test_one("character device", "/dev/null", 0, ENOTDIR);
	odir_test_one("door server", odir_doorpath, 0, ENOTDIR);
	odir_test_one("missing file", odir_enoent, 0, ENOENT);
	odir_test_one("UDS", odir_udspath, 0, ENOTDIR);

	odir_test_one("O_CREAT | O_DIRECTORY on a regular file", odir_fpath,
	    O_CREAT, ENOTDIR);
	odir_test_one("O_CREAT | O_DIRECTORY | O_EXCL on a regular file",
	    odir_fpath, O_CREAT | O_EXCL, EINVAL);

	odir_test_one("O_CREAT | O_DIRECTORY on a directory", odir_dpath,
	    O_CREAT, 0);
	odir_test_one("O_CREAT | O_DIRECTORY | O_EXCL on a directory",
	    odir_dpath, O_CREAT | O_EXCL, EINVAL);

	odir_test_one("O_CREAT | O_DIRECTORY on a missing file", odir_enoent,
	    O_CREAT, ENOENT);
	odir_verify_enoent();
	odir_test_one("O_CREAT | O_DIRECTORY | O_EXCL on a missing file",
	    odir_enoent, O_CREAT | O_EXCL, EINVAL);
	odir_verify_enoent();

	odir_cleanup();
	if (odir_failures > 0) {
		warnx("%u tests failed", odir_failures);
	}

	return (odir_failures > 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}
