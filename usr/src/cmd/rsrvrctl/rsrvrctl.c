/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2021 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include <sys/vmm_dev.h>

static void
usage(const char *pname)
{
	fprintf(stderr,
	    "Usage: %s [-a add] [-r remove] [-q]\n"
	    "\t-a <SZ> add SZ MiB to the reservoir\n"
	    "\t-r <SZ> remove SZ MiB from the reservoir\n"
	    "\t-q query reservoir state\n", pname);
}

static bool
parse_size(const char *arg, size_t *resp)
{
	size_t res;

	errno = 0;
	res = strtoul(arg, NULL, 0);
	if (errno != 0) {
		return (false);
	}

	*resp = (res * 1024 * 1024);
	return (true);
}

static void
do_add(int fd, size_t sz)
{
	int res;

	res = ioctl(fd, VMM_RESV_ADD, sz);
	if (res != 0) {
		perror("Could not add to reservoir");
		exit(EXIT_FAILURE);
	}
}

static void
do_remove(int fd, size_t sz)
{
	int res;

	res = ioctl(fd, VMM_RESV_REMOVE, sz);
	if (res != 0) {
		perror("Could not remove from reservoir");
		exit(EXIT_FAILURE);
	}
}

static void
do_query(int fd)
{
	struct vmm_resv_query data;
	int res;

	res = ioctl(fd, VMM_RESV_QUERY, &data);
	if (res != 0) {
		perror("Could not query reservoir info");
		return;
	}

	printf("Free KiB:\t%llu\n"
	    "Allocated KiB:\t%llu\n"
	    "Transient Allocated KiB:\t%llu\n"
	    "Size limit KiB:\t%llu\n",
	    data.vrq_free_sz / 1024,
	    data.vrq_alloc_sz / 1024,
	    data.vrq_alloc_transient_sz / 1024,
	    data.vrq_limit / 1024);
}

int
main(int argc, char *argv[])
{
	char c;
	const char *opt_a = NULL, *opt_r = NULL;
	bool opt_q = false;
	int fd;

	const char *pname = argv[0];

	while ((c = getopt(argc, argv, "a:r:qh")) != -1) {
		switch (c) {
		case 'a':
			opt_a = optarg;
			break;
		case 'r':
			opt_r = optarg;
			break;
		case 'q':
			opt_q = true;
			break;
		case 'h':
			usage(pname);
			return (EXIT_SUCCESS);
		default:
			usage(pname);
			return (EXIT_FAILURE);
		}
	}
	if (optind < argc ||
	    (opt_a == NULL && opt_r == NULL && !opt_q) ||
	    (opt_a != NULL && opt_r != NULL)) {
		usage(pname);
		return (EXIT_FAILURE);
	}

	fd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (fd < 0) {
		perror("Could not open vmmctl");
		usage(pname);
		return (EXIT_FAILURE);
	}

	if (opt_a != NULL) {
		size_t sz;

		if (!parse_size(opt_a, &sz)) {
			perror("Invalid size");
			usage(pname);
			return (EXIT_FAILURE);
		}

		do_add(fd, sz);
	}
	if (opt_r != NULL) {
		size_t sz;

		if (!parse_size(opt_r, &sz)) {
			perror("Invalid size");
			usage(pname);
			return (EXIT_FAILURE);
		}
		do_remove(fd, sz);
	}
	if (opt_q) {
		do_query(fd);
	}

	(void) close(fd);
	return (0);
}
