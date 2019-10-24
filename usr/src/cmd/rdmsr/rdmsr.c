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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/cpuid_drv.h>

#include <libintl.h>
#include <string.h>
#include <locale.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

static const char dev_cpu_self_cpuid[] = "/dev/" CPUID_SELF_NAME;

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int errflg = 0;
	int fd;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "")) != EOF) {
		switch (c) {
		case '?':
		default:
			errflg++;
			break;
		}
	}

	if (errflg != 0 || optind == argc) {
		fprintf(stderr, gettext("usage: rdmsr [0x<msrnr>...]\n"));
		return (EXIT_FAILURE);
	}

	if ((fd = open(dev_cpu_self_cpuid, O_RDONLY)) == -1) {
		err(EXIT_FAILURE, gettext("failed to open %s"),
		    dev_cpu_self_cpuid);
	}

	while (optind != argc) {
		struct cpuid_rdmsr crm;
		char *p;

		errno = 0;
		crm.cr_msr_nr = strtoull(argv[optind], &p, 0);

		if (errno != 0 || p == argv[optind] || *p != '\0') {
			fprintf(stderr,
			    gettext("rdmsr: invalid argument '%s'\n"),
			    argv[optind]);
			exit(EXIT_FAILURE);
		}

		if (ioctl(fd, CPUID_RDMSR, &crm) != 0) {
			warn(gettext("rdmsr of 0x%lx failed"), crm.cr_msr_nr);
			ret = EXIT_FAILURE;
		} else {
			printf("0x%lx: 0x%lx\n", crm.cr_msr_nr, crm.cr_msr_val);
		}

		optind++;
	}

	return (ret);
}
