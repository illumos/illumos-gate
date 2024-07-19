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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Basic tests for statvfs and fstatvfs. In particular we want to verify the
 * following:
 *
 *  - We can generate basic statvfs(2) errors like ENOENT, ENOTDIR, and EFAULT.
 *  - We can generate basic fstatvfs(2) errors like EBADF and EFAULT.
 *  - statvfs and fstatvfs work on basic file systems like /, ctfs, bootfs,
 *    objfs, procfs, tmpfs, etc. Additional paths will be allowed on the command
 *    line for this.
 *  - fstatvfs works on sockets and devices, but not pipes
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <stdbool.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <port.h>
#include <door.h>

static bool
statvfs_fail(const char *path, int exp, struct statvfs *svp)
{
	struct statvfs st;

	if (svp == NULL) {
		svp = &st;
	}

	if (statvfs(path, svp) == 0) {
		warnx("TEST FAILED: statvfs on %s passed, but expected %s",
		    path, strerrorname_np(exp));
		return (false);
	}

	if (errno != exp) {
		warnx("TEST FAILED: statvfs on %s returned wrong errno: "
		    "expected %s, found %s", path, strerrorname_np(exp),
		    strerrorname_np(errno));
		return (false);
	}

	(void) printf("TEST PASSED: statvfs on %s correctly returned %s\n",
	    path, strerrorname_np(exp));
	return (true);
}

static bool
statvfs_pass(const char *path, const char *fs)
{
	struct statvfs sv;

	if (statvfs(path, &sv) != 0) {
		warnx("TEST FAILED: statvfs on %s failed with %s, but "
		    "expected success", path, strerrorname_np(errno));
		return (false);
	}

	(void) printf("TEST PASSED: statvfs on %s worked\n", path);
	if (fs == NULL) {
		return (true);
	}

	if (strcmp(sv.f_basetype, fs) != 0) {
		warnx("TEST FAILED: statvfs on %s has wrong fs: expected %s, "
		    "found %s", path, fs, sv.f_basetype);
		return (false);
	}

	(void) printf("TEST PASSED: statvfs on %s correctly indicated fs %s\n",
	    path, fs);
	return (true);
}

typedef struct {
	const char *sp_path;
	const char *sp_fs;
	int sp_ret;
} statvfs_pass_t;

static const statvfs_pass_t statvfs_passes[] = {
	{ "/", NULL },
	{ "/usr/lib/libc.so.1", NULL },
	{ "/var/run", "tmpfs" },
	{ "/etc/svc/volatile", "tmpfs" },
	{ "/system/boot", "bootfs" },
	{ "/system/contract", "ctfs" },
	{ "/system/object", "objfs" },
	{ "/dev/fd", "fd" },
	{ "/etc/mnttab", "mntfs" },
	{ "/dev/net", "dev" },
	/* This is a symlink in the GZ to /devices */
	{ "/dev/zero", "devfs" },
	{ "/devices/pseudo", "devfs" },
	{ "/etc/dfs/sharetab", "sharefs" },
	{ "/proc/self/psinfo", "proc" },
	{ "/var/run/name_service_door", "namefs" }
};

typedef struct fstatvfs_test {
	int (*ft_open)(const struct fstatvfs_test *);
	const char *ft_path;
	const char *ft_fs;
	int ft_ret;
} fstatvfs_test_t;

static int
statvfs_open_file(const fstatvfs_test_t *test)
{
	int fd = open(test->ft_path, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open file %s",
		    test->ft_path);
	}

	return (fd);
}

static int
statvfs_open_socket(const fstatvfs_test_t *test)
{
	struct sockaddr_in in;
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create basic "
		    "socket");
	}

	(void) memset(&in, 0, sizeof (in));
	if (bind(fd, (struct sockaddr *)&in, sizeof (in)) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to bind socket");
	}

	return (fd);
}

static int
statvfs_open_uds(const fstatvfs_test_t *test)
{
	int fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create UDS");
	}

	return (fd);
}

static int
statvfs_open_pipe(const fstatvfs_test_t *test)
{
	int fds[2];

	if (pipe(fds) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create pipe");
	}

	VERIFY0(close(fds[1]));
	return (fds[0]);
}

static int
statvfs_open_negfd(const fstatvfs_test_t *test)
{
	return (-1);
}

static int
statvfs_open_bigfd(const fstatvfs_test_t *test)
{
	return (0x7777);
}

static int
statvfs_open_portfs(const fstatvfs_test_t *test)
{
	int fd = port_create();
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create event port");
	}

	return (fd);
}

static void
statvfs_close_door(void *cookie, char *arg, size_t size, door_desc_t *dp,
    uint_t ndesc)
{
	(void) door_return(NULL, 0, NULL, 0);
}

static int
statvfs_open_door(const fstatvfs_test_t *test)
{
	int fd = door_create(statvfs_close_door, NULL, 0);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create door");
	}
	return (fd);
}

static const fstatvfs_test_t fstatvfs_tests[] = {
	{ statvfs_open_socket, "localhost socket", "sockfs", 0 },
	{ statvfs_open_uds, "UDS socket", "sockfs", 0 },
	{ statvfs_open_pipe, "pipe", NULL, ENOSYS },
	{ statvfs_open_file, "/dev/tcp", NULL, ENOSYS },
	{ statvfs_open_negfd, "bad fd (-1)", NULL, EBADF },
	{ statvfs_open_negfd, "bad fd (-1)", NULL, EBADF },
	{ statvfs_open_bigfd, "bad fd (0x7777)", NULL, EBADF },
	{ statvfs_open_portfs, "event port", NULL, ENOSYS },
	{ statvfs_open_door, "door server", NULL, ENOSYS }
};

static bool
fstatvfs_test(const fstatvfs_test_t *test)
{
	struct statvfs sv;
	int ret, fd, e;

	/*
	 * Some tests will specifically use a bad fd value trying to get EBADF.
	 * In those cases don't try to close the fd again.
	 */
	fd = test->ft_open(test);
	ret = fstatvfs(fd, &sv);
	e = errno;
	if (test->ft_ret != EBADF) {
		VERIFY0(close(fd));
	}

	if (ret != 0) {
		if (test->ft_ret == 0) {
			warnx("TEST FAILED: fstatvfs on %s failed with %s, but "
			    "expected success", test->ft_path,
			    strerrorname_np(errno));
			return (false);
		}

		if (e != test->ft_ret) {
			warnx("TEST FAILED: fstatvfs on %s returned wrong "
			    "errno: expected %s, found %s", test->ft_path,
			    strerrorname_np(test->ft_ret), strerrorname_np(e));
			return (false);
		}

		(void) printf("TEST PASSED: fstatvfs on %s correctly failed "
		    "with %s\n", test->ft_path, strerrorname_np(test->ft_ret));
		return (true);
	}

	if (test->ft_ret != 0) {
		warnx("TEST FAILED: fstatvfs on %s passed, but expected %s",
		    test->ft_path, strerrorname_np(test->ft_ret));
		return (false);
	}

	(void) printf("TEST PASSED: fstatvfs on %s worked\n", test->ft_path);
	if (test->ft_fs == NULL) {
		return (true);
	}

	if (strcmp(sv.f_basetype, test->ft_fs) != 0) {
		warnx("TEST FAILED: fstatvfs on %s has wrong fs: expected %s, "
		    "found %s", test->ft_path, test->ft_fs, sv.f_basetype);
		return (false);
	}

	(void) printf("TEST PASSED: fstatvfs on %s correctly indicated fs %s\n",
	    test->ft_path, test->ft_fs);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	void *unmap;
	long page;

	page = sysconf(_SC_PAGESIZE);
	VERIFY3S(page, >=, sizeof (struct statvfs));
	unmap = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (unmap == MAP_FAILED) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to mmap our "
		    "empty page");
	}

	if (!statvfs_fail("/elbe12th!", ENOENT, NULL)) {
		ret = EXIT_FAILURE;
	}

	if (!statvfs_fail("/usr/sbin/dtrace/wait", ENOTDIR, NULL)) {
		ret = EXIT_FAILURE;
	}

	if (!statvfs_fail("/", EFAULT, unmap)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Each passing statvfs test should be a passing fstatvfs test as well.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(statvfs_passes); i++) {
		fstatvfs_test_t ft;

		if (!statvfs_pass(statvfs_passes[i].sp_path,
		    statvfs_passes[i].sp_fs)) {
			ret = EXIT_FAILURE;
		}

		ft.ft_open = statvfs_open_file;
		ft.ft_path = statvfs_passes[i].sp_path;
		ft.ft_fs = statvfs_passes[i].sp_fs;
		ft.ft_ret = 0;

		if (!fstatvfs_test(&ft)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(fstatvfs_tests); i++) {
		if (!fstatvfs_test(&fstatvfs_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}
	return (ret);
}
