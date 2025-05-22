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
 * Copyright 2018, Joyent, Inc.
 * Copyright 2022 MNX Cloud, Inc.
 */

/*
 * With no option, exit 0 if the current hardware is bhyve-compatible, non-zero
 * otherwise. A '-v' option can be used to print the incompatibility reason
 * provided by the kernel.
 *
 * The -c option can be used to print the number of virtual CPUs supported by
 * bhyve build.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/vmm.h>

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>

static void
usage()
{
	fprintf(stderr, "bhhwcompat [-cv]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int fd, c, version;
	char emsg[128];
	boolean_t max_cpu = B_FALSE;
	boolean_t verbose = B_FALSE;

	while ((c = getopt(argc, argv, "cv")) != -1) {
		switch (c) {
		case 'c':
			max_cpu = B_TRUE;
			break;
		case 'v':
			verbose = B_TRUE;
			break;
		default:
			usage();
		}
	}

/*
 * Uggh, recent changes to sys/vmm.h exclude this from userland. Keep in synch.
 * See illumos#14691 for the correct answer to this problem.
 */
#define	VM_MAXCPU 64
	if (max_cpu) {
		(void) printf("%d\n", VM_MAXCPU);
	}

	if ((fd = open(VMM_CTL_DEV, O_RDONLY | O_EXCL)) < 0) {
		if (verbose)
			fprintf(stderr, "missing %s\n", VMM_CTL_DEV);
		exit(1);
	}

	emsg[0] = '\0';
	version = ioctl(fd, VMM_INTERFACE_VERSION, 0);
	if (version != VMM_CURRENT_INTERFACE_VERSION) {
		if (verbose) {
			fprintf(stderr, "mismatched interface version, "
			    "expecting %d, got %d\n",
			    VMM_CURRENT_INTERFACE_VERSION, version);
		}
		exit(1);
	}
	if (ioctl(fd, VMM_VM_SUPPORTED, emsg) < 0)  {
		if (verbose)
			fprintf(stderr, "%s\n", emsg);
		exit(1);
	}

	(void) close(fd);
	return (0);
}
