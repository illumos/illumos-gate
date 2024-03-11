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
 * Copyright 2023 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>

#include <sys/vmm_dev.h>

const char *prog_name;

static void
usage(int exitcode)
{
	assert(prog_name != NULL);
	fprintf(stderr,
	    "Usage: %s [-a add] [-r remove] [-q]\n"
	    "\t-a <SZ> add SZ MiB to the reservoir\n"
	    "\t-r <SZ> remove SZ MiB from the reservoir\n"
	    "\t-s <SZ> set reservoir to SZ MiB, if possible\n"
	    "\t-c <SZ> use SZ MiB chunks when performing resize ops\n"
	    "\t-q query reservoir state\n", prog_name);
	exit(exitcode);
}

/*
 * Parse an input size of MiB to bytes.
 */
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

static size_t
query_size(int fd)
{
	struct vmm_resv_query data;

	int res = ioctl(fd, VMM_RESV_QUERY, &data);
	if (res != 0) {
		err(EXIT_FAILURE, "Could not query reservoir sizing");
	}

	return (data.vrq_free_sz + data.vrq_alloc_sz);
}

static void
do_add(int fd, size_t sz, size_t chunk)
{
	const size_t cur = query_size(fd);
	struct vmm_resv_target target = {
		.vrt_target_sz = cur + sz,
		.vrt_chunk_sz = MIN(chunk, sz),
	};

	if (ioctl(fd, VMM_RESV_SET_TARGET, &target) != 0) {
		err(EXIT_FAILURE, "Could not add %zu bytes to reservoir", sz);
	}
}

static void
do_remove(int fd, size_t sz, size_t chunk)
{
	const size_t cur = query_size(fd);
	if (cur == 0) {
		/* Reservoir is already empty */
		return;
	}

	const size_t clamped_sz = MIN(sz, cur);
	struct vmm_resv_target target = {
		.vrt_target_sz = cur - clamped_sz,
		.vrt_chunk_sz = MIN(chunk, sz),
	};

	if (ioctl(fd, VMM_RESV_SET_TARGET, &target) != 0) {
		err(EXIT_FAILURE, "Could not remove %zu bytes from reservoir",
		    clamped_sz);
	}
}


bool caught_siginfo = false;

static void
siginfo_handler(int sig, siginfo_t *sip, void *ucp)
{
	caught_siginfo = true;
}

static void
do_set_target(int fd, size_t sz, size_t chunk)
{
	struct vmm_resv_target target = {
		.vrt_target_sz = sz,
		.vrt_chunk_sz = chunk,
	};

	struct sigaction sa = {
		.sa_sigaction = siginfo_handler,
		.sa_flags = SA_SIGINFO,
	};
	if (sigaction(SIGINFO, &sa, NULL) != 0) {
		err(EXIT_FAILURE, "Could not configure SIGINFO handler");
	}

	do {
		if (ioctl(fd, VMM_RESV_SET_TARGET, &target) != 0) {
			if (errno != EINTR) {
				err(EXIT_FAILURE,
				    "Could not set reservoir size to %zu bytes",
				    sz);
			}

			if (caught_siginfo) {
				caught_siginfo = false;
				(void) printf("Reservoir size: %zu MiB\n",
				    target.vrt_result_sz / (1024 * 1024));
			}
		}
	} while (target.vrt_result_sz != sz);
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

	printf("Free MiB:\t%zu\n"
	    "Allocated MiB:\t%zu\n"
	    "Transient Allocated MiB:\t%zu\n"
	    "Size limit MiB:\t%zu\n",
	    data.vrq_free_sz / (1024 * 1024),
	    data.vrq_alloc_sz / (1024 * 1024),
	    data.vrq_alloc_transient_sz / (1024 * 1024),
	    data.vrq_limit / (1024 * 1024));
}

int
main(int argc, char *argv[])
{
	int c;
	const char *opt_a = NULL, *opt_r = NULL, *opt_s = NULL;
	bool opt_q = false;
	int fd;

	prog_name = argv[0];

	uint_t resize_opts = 0;
	size_t chunk_sz = 0;
	while ((c = getopt(argc, argv, "a:r:s:c:qh")) != -1) {
		switch (c) {
		case 'a':
			if (opt_a == NULL) {
				resize_opts++;
				opt_a = optarg;
			}
			break;
		case 'r':
			if (opt_r == NULL) {
				resize_opts++;
				opt_r = optarg;
			}
			break;
		case 's':
			if (opt_s == NULL) {
				resize_opts++;
				opt_s = optarg;
			}
			break;
		case 'c':
			if (!parse_size(optarg, &chunk_sz)) {
				warn("Invalid chunk size %s", optarg);
				usage(EXIT_FAILURE);
			}
			break;
		case 'q':
			opt_q = true;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	if (optind < argc ||
	    (resize_opts == 0 && !opt_q) || (resize_opts > 1)) {
		usage(EXIT_FAILURE);
	}

	fd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (fd < 0) {
		perror("Could not open vmmctl");
		usage(EXIT_FAILURE);
	}

	if (opt_a != NULL) {
		size_t sz;

		if (!parse_size(opt_a, &sz)) {
			warn("Invalid size %s", opt_a);
			usage(EXIT_FAILURE);
		}

		do_add(fd, sz, chunk_sz);
	} else if (opt_r != NULL) {
		size_t sz;

		if (!parse_size(opt_r, &sz)) {
			warn("Invalid size %s", opt_r);
			usage(EXIT_FAILURE);
		}
		do_remove(fd, sz, chunk_sz);
	} else if (opt_s != NULL) {
		size_t sz;

		if (!parse_size(opt_s, &sz)) {
			warn("Invalid size %s", opt_s);
			usage(EXIT_FAILURE);
		}
		do_set_target(fd, sz, chunk_sz);
	} else if (opt_q) {
		do_query(fd);
	}

	(void) close(fd);
	return (0);
}
