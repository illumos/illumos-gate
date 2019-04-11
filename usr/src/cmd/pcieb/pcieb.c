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

/*
 * Private command to manipulate link speeds of PCIe bridges and allow
 * retraining. This is designed to aid debugging.
 */

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pcieb_ioctl.h>

static const char *pcieb_progname;

static void
pcieb_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", pcieb_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-x] [-s speed] pcie-bridge\n"
	    "\n"
	    "\t-s speed		Set link to speed\n",
	    "\t-x		Retrain link\n",
	    pcieb_progname);

}

static uint32_t
pcieb_parse_speed(const char *s)
{
	if (strcasecmp(s, "2.5") == 0 || strcasecmp(s, "gen1") == 0) {
		return (PCIEB_LINK_SPEED_GEN1);
	} else if (strcasecmp(s, "5") == 0 || strcasecmp(s, "gen2") == 0) {
		return (PCIEB_LINK_SPEED_GEN2);
	} else if (strcasecmp(s, "8") == 0 || strcasecmp(s, "gen3") == 0) {
		return (PCIEB_LINK_SPEED_GEN3);
	} else if (strcasecmp(s, "16") == 0 || strcasecmp(s, "gen4") == 0) {
		return (PCIEB_LINK_SPEED_GEN4);
	} else {
		errx(EXIT_FAILURE, "invalid speed: %s", s);
	}
}

int
main(int argc, char *argv[])
{
	int c;
	boolean_t retrain = B_FALSE;
	boolean_t set = B_FALSE;
	boolean_t get = B_TRUE;
	uint32_t speed = PCIEB_LINK_SPEED_UNKNOWN;
	int fd;

	pcieb_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":xs:")) != -1) {
		switch (c) {
		case 's':
			speed = pcieb_parse_speed(optarg);
			set = B_TRUE;
			get = B_FALSE;
			break;
		case 'x':
			retrain = B_TRUE;
			get = B_FALSE;
			break;
		case ':':
			pcieb_usage("option -%c requires an operand\n", optopt);
			return (2);
		case '?':
		default:
			pcieb_usage("unknown option: -%c\n", optopt);
			return (2);

		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		pcieb_usage("missing required PCIe bridge device\n");
		return (2);
	}

	if ((fd = open(argv[0], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[0]);
	}

	if (set) {
		pcieb_ioctl_target_speed_t pits;

		pits.pits_flags = 0;
		pits.pits_speed = speed;

		if (ioctl(fd, PCIEB_IOCTL_SET_TARGET_SPEED, &pits) != 0) {
			err(EXIT_FAILURE, "failed to set target speed");
		}
	}

	if (retrain) {
		if (ioctl(fd, PCIEB_IOCTL_RETRAIN) != 0) {
			err(EXIT_FAILURE, "failed to retrain link");
		}
	}

	if (get) {
		pcieb_ioctl_target_speed_t pits;

		if (ioctl(fd, PCIEB_IOCTL_GET_TARGET_SPEED, &pits) != 0) {
			err(EXIT_FAILURE, "failed to get target speed");
		}

		(void) printf("Bridge target speed: ");
		switch (pits.pits_speed) {
		case PCIEB_LINK_SPEED_GEN1:
			(void) printf("2.5 GT/s (gen1)\n");
			break;
		case PCIEB_LINK_SPEED_GEN2:
			(void) printf("5.0 GT/s (gen2)\n");
			break;
		case PCIEB_LINK_SPEED_GEN3:
			(void) printf("8.0 GT/s (gen3)\n");
			break;
		case PCIEB_LINK_SPEED_GEN4:
			(void) printf("16.0 GT/s (gen4)\n");
			break;
		default:
			(void) printf("Unknown Value: 0x%x\n", pits.pits_speed);
		}

		if ((pits.pits_flags & ~PCIEB_FLAGS_ADMIN_SET) != 0) {
			(void) printf("Unknown flags: 0x%x\n", pits.pits_flags);
		} else if ((pits.pits_flags & PCIEB_FLAGS_ADMIN_SET) != 0) {
			(void) printf("Flags: Admin Set Speed\n");
		}
	}

	(void) close(fd);
	return (0);
}
