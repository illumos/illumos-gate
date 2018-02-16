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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/corectl.h>

#define	ZHYVE_CMD_FILE	"/var/run/bhyve/zhyve.cmd"
#define	ZHYVE_LOG_FILE	"/tmp/zhyve.log"

#define	FILE_PROVISIONING	"/var/svc/provisioning"
#define	FILE_PROVISION_SUCCESS	"/var/svc/provision_success"

extern int bhyve_main(int, char **);
void (*vm_started_cb)(void);
const char *cmdname;

/*
 * Much like basename() but does not alter the path passed to it.
 */
static void
get_cmdname(const char *path)
{
	cmdname = strrchr(path, '/');
	if (cmdname == NULL) {
		cmdname = path;
		return;
	}
	assert(*cmdname == '/');
	cmdname++;
}

/*
 * Do a read of the specified size or return an error.  Returns 0 on success
 * and -1 on error.  Sets errno to EINVAL if EOF is encountered.  For other
 * errors, see read(2).
 */
static int
full_read(int fd, char *buf, size_t len)
{
	ssize_t nread = 0;
	size_t totread = 0;

	while (totread < len) {
		nread = read(fd, buf + totread, len - totread);
		if (nread == 0) {
			errno = EINVAL;
			return (-1);
		}
		if (nread < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return (-1);
		}
		totread += nread;
	}
	assert(totread == len);

	return (0);
}

/*
 * Reads the command line options from the packed nvlist in the file referenced
 * by path.  On success, 0 is returned and the members of *argv reference memory
 * allocated from an nvlist.  On failure, -1 is returned.
 */

static int
parse_options_file(const char *path, uint_t *argcp, char ***argvp)
{
	int fd = -1;
	struct stat stbuf;
	char *buf = NULL;
	nvlist_t *nvl = NULL;
	int ret;

	if ((fd = open(path, O_RDONLY)) < 0 ||
	    fstat(fd, &stbuf) != 0 ||
	    (buf = malloc(stbuf.st_size)) == NULL ||
	    full_read(fd, buf, stbuf.st_size) != 0 ||
	    nvlist_unpack(buf, stbuf.st_size, &nvl, 0) != 0 ||
	    nvlist_lookup_string_array(nvl, "zhyve_args", argvp, argcp) != 0) {
		nvlist_free(nvl);
		ret = -1;
	} else {
		ret = 0;
	}

	free(buf);
	(void) close(fd);

	(void) printf("Configuration from %s:\n", path);
	nvlist_print(stdout, nvl);

	return (ret);
}

static void
mark_provisioned(void)
{
	if (rename(FILE_PROVISIONING, FILE_PROVISION_SUCCESS) != 0) {
		(void) fprintf(stderr, "Cannot rename %s to %s: %s\n",
		    FILE_PROVISIONING, FILE_PROVISION_SUCCESS,
		    strerror(errno));
	}
}

/*
 * Setup to suppress core dumps within the zone.
 */
static void
config_core_dumps()
{
	(void) core_set_options(0x0);
}

int
main(int argc, char **argv)
{
	uint_t zargc;
	char **zargv;
	int fd;
	struct stat stbuf;

	get_cmdname(argv[0]);
	if (strcmp(cmdname, "zhyve") != 0) {
		return (bhyve_main(argc, argv));
	}

	config_core_dumps();

	fd = open("/dev/null", O_WRONLY);
	assert(fd >= 0);
	if (fd != STDIN_FILENO) {
		(void) dup2(fd, STDIN_FILENO);
		(void) close(fd);
	}
	fd = open(ZHYVE_LOG_FILE, O_WRONLY|O_CREAT|O_APPEND, 0644);
	assert(fd >= 0);
	(void) dup2(fd, STDOUT_FILENO);
	setvbuf(stdout, NULL, _IONBF, 0);
	(void) dup2(fd, STDERR_FILENO);
	setvbuf(stderr, NULL, _IONBF, 0);
	if (fd != STDOUT_FILENO && fd != STDERR_FILENO) {
		(void) close(fd);
	}

	if (parse_options_file(ZHYVE_CMD_FILE, &zargc, &zargv) != 0) {
		(void) fprintf(stderr, "%s: failed to parse %s: %s\n",
		    cmdname, ZHYVE_CMD_FILE, strerror(errno));
		return (1);
	}

	if (lstat(FILE_PROVISIONING, &stbuf) == 0) {
		vm_started_cb = mark_provisioned;
	}

	return (bhyve_main(zargc, zargv));
}
