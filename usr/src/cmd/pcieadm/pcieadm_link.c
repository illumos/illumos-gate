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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Implement logic related to the state of PCIe links. These operate on a PCIe
 * bridge (e.g. a root port) by way of the private ioctls implemented by the
 * 'pcieb' driver.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <ofmt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include <pcieb_ioctl.h>

#include "pcieadm.h"

/*
 * Go through and initialize the common logic for most of the link related
 * commands that need to use the pcieb ioctls. This includes:
 *
 *  - Verifying it makes sense
 *  - Setting privileges
 *  - Opening the actual devctl file
 *  - Finding the dip
 */
static int
pcieadm_link_pcieb_open(pcieadm_t *pcip, const char *device, bool write)
{
	const char *drv;

	/*
	 * We retain FILE_DAC_READ and FILE_DAC_SEARCH to find and open the
	 * device file and SYS_DEVICES for the ioctls themselves. To open it for
	 * writing (some bridge ioctls, such as retrain, mutate link state) we
	 * also need FILE_DAC_WRITE to override the node's permissions, and
	 * FILE_WRITE because, unlike FILE_READ, it is stripped from our minimal
	 * privilege set.
	 */
	VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_SYS_DEVICES));
	VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_FILE_DAC_READ));
	VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_FILE_DAC_SEARCH));
	if (write) {
		VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_FILE_WRITE));
		VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_FILE_DAC_WRITE));
	}
	pcieadm_init_privs(pcip);

	pcieadm_find_dip(pcip, device);
	drv = di_driver_name(pcip->pia_devi);
	if (drv == NULL || strcmp(drv, "pcieb") != 0) {
		errx(EXIT_FAILURE, "device %s is not a PCIe bridge: found "
		    "driver %s, but expected pcieb", device,
		    drv == NULL ? "<none>" : drv);
	}

	for (di_minor_t m = di_minor_next(pcip->pia_devi, DI_MINOR_NIL);
	    m != NULL; m = di_minor_next(pcip->pia_devi, m)) {
		if (strcmp(di_minor_name(m), "devctl") == 0) {
			char buf[PATH_MAX], *mp;
			int fd;

			mp = di_devfs_minor_path(m);
			if (mp == NULL) {
				err(EXIT_FAILURE, "failed to get devfs path "
				    "for %s devctl minor", device);
			}

			if (snprintf(buf, sizeof (buf), "/devices%s", mp) >=
			    sizeof (buf)) {
				errx(EXIT_FAILURE, "failed to construct devfs "
				    "minor path for %s devctl minor: internal "
				    "path buffer would have overflowed",
				    device);
			}
			di_devfs_path_free(mp);

			if (setppriv(PRIV_SET, PRIV_EFFECTIVE,
			    pcip->pia_priv_eff) != 0) {
				err(EXIT_FAILURE, "failed to raise privileges");
			}

			fd = open(buf, write ? O_RDWR : O_RDONLY);
			if (fd < 0) {
				err(EXIT_FAILURE,
				    "failed to open %s devctl minor %s",
				    device, buf);
			}

			if (setppriv(PRIV_SET, PRIV_EFFECTIVE,
			    pcip->pia_priv_min) != 0) {
				err(EXIT_FAILURE,
				    "failed to reduce privileges");
			}

			return (fd);
		}
	}

	errx(EXIT_FAILURE, "failed to find devctl minor for %s", device);
}

static void
pcieadm_link_limit_usage(FILE *f)
{
	(void) fprintf(f, "\tlink limit\t[-s speed] -d device\n");
}

static void
pcieadm_link_limit_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s link limit [-s speed] -d device\n",
	    pcieadm_progname);
	(void) fprintf(stderr, "Print or set the administrative limit on the "
	    "corresponding PCIe link\n\n"
	    "\t-d device\tthe PCIe bridge to operate on (driver instance,"
	    "\n\t\t\t/devices path, or b/d/f)\n"
	    "\t-s speed\tlimit the device to the specified PCIe gen/speed "
	    "(e.g.\n\t\t\t2.5, 32, gen2, gen3, etc.)\n");
}

typedef struct {
	uint32_t	pls_speed;
	const char	*pls_gts;
	const char	*pls_gen;
	const char	*pls_alt;
} pcieadm_link_speed_t;

static const pcieadm_link_speed_t pcieadm_link_speeds[] = {
	{ PCIEB_LINK_SPEED_GEN1, "2.5",  "gen1", NULL },
	{ PCIEB_LINK_SPEED_GEN2, "5.0",  "gen2", "5" },
	{ PCIEB_LINK_SPEED_GEN3, "8.0",  "gen3", "8" },
	{ PCIEB_LINK_SPEED_GEN4, "16.0", "gen4", "16" },
	{ PCIEB_LINK_SPEED_GEN5, "32.0", "gen5", "32" },
	{ PCIEB_LINK_SPEED_GEN6, "64.0", "gen6", "64" }
};

static uint32_t
pcieadm_parse_pcieb_speed(const char *str)
{
	for (uint_t i = 0; i < ARRAY_SIZE(pcieadm_link_speeds); i++) {
		const pcieadm_link_speed_t *pls = &pcieadm_link_speeds[i];

		if (strcasecmp(str, pls->pls_gts) == 0 ||
		    strcasecmp(str, pls->pls_gen) == 0 ||
		    (pls->pls_alt != NULL &&
		    strcasecmp(str, pls->pls_alt) == 0)) {
			return (pls->pls_speed);
		}
	}

	errx(EXIT_FAILURE, "failed to parse speed: %s", str);
}

static const pcieadm_link_speed_t *
pcieadm_link_speed_lookup(uint32_t speed)
{
	for (uint_t i = 0; i < ARRAY_SIZE(pcieadm_link_speeds); i++) {
		if (pcieadm_link_speeds[i].pls_speed == speed)
			return (&pcieadm_link_speeds[i]);
	}

	return (NULL);
}

static int
pcieadm_link_limit(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	const char *device = NULL, *speed = NULL;
	pcieb_ioctl_target_speed_t pits;

	while ((c = getopt(argc, argv, ":d:s:")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 's':
			speed = optarg;
			break;
		case ':':
			pcieadm_link_limit_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_link_limit_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}

	}

	if (device == NULL) {
		pcieadm_link_limit_help("missing required device argument "
		    "(-d)");
		exit(EXIT_USAGE);
	}

	argc -= optind;
	argv += optind;
	if (argc != 0) {
		errx(EXIT_USAGE, "encountered extraneous arguments starting "
		    "with %s", argv[0]);
	}

	int fd = pcieadm_link_pcieb_open(pcip, device, speed != NULL);
	bzero(&pits, sizeof (pits));

	if (speed != NULL) {
		pits.pits_speed = pcieadm_parse_pcieb_speed(speed);

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) != 0)
			err(EXIT_FAILURE, "failed to raise privileges");

		if (ioctl(fd, PCIEB_IOCTL_SET_TARGET_SPEED, &pits) != 0) {
			err(EXIT_FAILURE, "failed to set %s target speed",
			    device);
		}

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) != 0)
			err(EXIT_FAILURE, "failed to reduce privileges");
	} else {
		const pcieadm_link_speed_t *pls;

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) != 0)
			err(EXIT_FAILURE, "failed to raise privileges");

		if (ioctl(fd, PCIEB_IOCTL_GET_TARGET_SPEED, &pits) != 0) {
			err(EXIT_FAILURE, "failed to get %s target speed",
			    device);
		}

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) != 0)
			err(EXIT_FAILURE, "failed to reduce privileges");

		pls = pcieadm_link_speed_lookup(pits.pits_speed);
		if (pls != NULL) {
			(void) printf("Target speed: %s GT/s (%s)\n",
			    pls->pls_gts, pls->pls_gen);
		} else {
			(void) printf("Target speed: unknown speed value: "
			    "0x%x\n", pits.pits_speed);
		}

		if ((pits.pits_flags & ~PCIEB_FLAGS_ADMIN_SET) != 0) {
			(void) printf("Unknown flags: 0x%x\n", pits.pits_flags);
		} else if ((pits.pits_flags & PCIEB_FLAGS_ADMIN_SET) != 0) {
			(void) printf("Flags: Admin Set Speed\n");
		}
	}

	VERIFY0(close(fd));
	return (ret);
}

static void
pcieadm_link_retrain_usage(FILE *f)
{
	(void) fprintf(f, "\tlink retrain\t-d device\n");
}

static void
pcieadm_link_retrain_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s link retrain -d device\n",
	    pcieadm_progname);
	(void) fprintf(stderr,
	    "Retrain the link on the specified upstream port by requesting\n"
	    "it via the PCIe Link Control register.\n\n"
	    "\t-d device\tthe PCIe bridge to operate on (driver instance,\n"
	    "\t\t\t/devices path, or b/d/f)\n");
}

static int
pcieadm_link_retrain(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	const char *device = NULL;

	while ((c = getopt(argc, argv, ":d:")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case ':':
			pcieadm_link_retrain_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_link_retrain_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	if (device == NULL) {
		pcieadm_link_retrain_help("missing required device argument "
		    "(-d)");
		exit(EXIT_USAGE);
	}

	argc -= optind;
	argv += optind;
	if (argc != 0) {
		errx(EXIT_USAGE, "encountered extraneous arguments starting "
		    "with %s", argv[0]);
	}

	int fd = pcieadm_link_pcieb_open(pcip, device, true);

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) != 0)
		err(EXIT_FAILURE, "failed to raise privileges");

	if (ioctl(fd, PCIEB_IOCTL_RETRAIN) != 0) {
		err(EXIT_FAILURE, "failed to retrain link %s", device);
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) != 0)
		err(EXIT_FAILURE, "failed to reduce privileges");

	VERIFY0(close(fd));
	return (ret);
}

static const pcieadm_cmdtab_t pcieadm_cmds_link[] = {
	{ "limit", pcieadm_link_limit, pcieadm_link_limit_usage },
	{ "retrain", pcieadm_link_retrain, pcieadm_link_retrain_usage },
	{ NULL }
};

int
pcieadm_link(pcieadm_t *pcip, int argc, char *argv[])
{
	return (pcieadm_walk_tab(pcip, pcieadm_cmds_link, argc, argv));
}

void
pcieadm_link_usage(FILE *f)
{
	pcieadm_walk_usage(pcieadm_cmds_link, f);
}
