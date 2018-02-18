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
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Private utility to get and set LED information on NICs. This should really
 * all be integrated into FM. Until we have figured out that plumbing, this
 * allows us to have a little something that we can use to drive work.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>

#include <libdladm.h>
#include <libdllink.h>
#include <sys/mac.h>
#include <sys/dld.h>
#include <sys/dld_ioc.h>

static const char *dlled_progname;
static dladm_handle_t dlled_hdl;
static char dlled_dlerrmsg[DLADM_STRSIZE];

typedef struct dlled_led_map {
	const char *dlm_name;
	mac_led_mode_t dlm_bits;
} dlled_led_map_t;

static dlled_led_map_t dlled_map[] = {
	{ "default",	MAC_LED_DEFAULT },
	{ "off", 	MAC_LED_OFF },
	{ "on", 	MAC_LED_ON },
	{ "ident",	MAC_LED_IDENT }
};

#define	DLLED_MAP_NENTRIES	\
	(sizeof (dlled_map) / sizeof (dlled_led_map_t))

static void
dlled_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", dlled_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-s mode] [link]\n"
	    "\n"
	    "\t-s mode   set LED to mode\n",
	    dlled_progname);
}

static mac_led_mode_t
dlled_parse_mode(const char *orig)
{
	char *mode;
	char *part;
	mac_led_mode_t m = 0;

	mode = strdup(orig);
	if (mode == NULL) {
		fprintf(stderr, "failed to allocate memory to dup led "
		    "mode: %s\n", strerror(errno));
		exit(1);
	}

	part = strtok(mode, ",");
	while (part != NULL) {
		int i;

		for (i = 0; i < DLLED_MAP_NENTRIES; i++) {
			if (strcmp(dlled_map[i].dlm_name, part) == 0) {
				m |= dlled_map[i].dlm_bits;
				break;
			}
		}

		if (i == DLLED_MAP_NENTRIES) {
			fprintf(stderr, "unknown LED mode: %s\n", part);
			exit(1);
		}

		part = strtok(NULL, ",");
	}

	free(mode);
	if (m == 0) {
		fprintf(stderr, "failed to parse %s: no valid modes "
		    "specified\n", orig);
		exit(1);
	}

	return (m);
}

static void
dlled_mode2str(mac_led_mode_t mode, char *buf, size_t len)
{
	int i;
	boolean_t first = B_TRUE;
	mac_led_mode_t orig = mode;

	for (i = 0; i < DLLED_MAP_NENTRIES; i++) {
		if ((mode & dlled_map[i].dlm_bits) != 0) {
			if (first) {
				first = B_FALSE;
			} else {
				(void) strlcat(buf, ",", len);
			}
			(void) strlcat(buf, dlled_map[i].dlm_name, len);
			mode &= ~dlled_map[i].dlm_bits;
		}
	}

	if (mode != 0) {
		(void) snprintf(buf, len, "unknown mode: 0x%x\n", orig);
	}
}


static int
dlled_set(const char *link, mac_led_mode_t mode)
{
	datalink_id_t linkid;
	dladm_status_t status;
	dld_ioc_led_t dil;

	if ((status = dladm_name2info(dlled_hdl, link, &linkid, NULL, NULL,
	    NULL)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to get link "
		    "id for link %s: %s\n", link,
		    dladm_status2str(status, dlled_dlerrmsg));
		return (1);
	}

	bzero(&dil, sizeof (dil));
	dil.dil_linkid = linkid;
	dil.dil_active = mode;

	if (ioctl(dladm_dld_fd(dlled_hdl), DLDIOC_SETLED, &dil) != 0) {
		(void) fprintf(stderr, "failed to set LED on "
		    "device %s: %s\n", link, strerror(errno));
		return (1);
	}

	return (0);
}

static int
dlled_get_led(dladm_handle_t hdl, datalink_id_t linkid, void *arg)
{
	dladm_status_t status;
	char name[MAXLINKNAMELEN];
	char supported[128], active[128];
	dld_ioc_led_t dil;

	if ((status = dladm_datalink_id2info(hdl, linkid, NULL, NULL, NULL,
	    name, sizeof (name))) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to get datalink name for link "
		    "%d: %s", linkid, dladm_status2str(status,
		    dlled_dlerrmsg));
		return (DLADM_WALK_CONTINUE);
	}



	bzero(&dil, sizeof (dil));
	dil.dil_linkid = linkid;

	if (ioctl(dladm_dld_fd(hdl), DLDIOC_GETLED, &dil) != 0) {
		(void) fprintf(stderr, "failed to get LED information for "
		    "device %s: %s\n", name, strerror(errno));
		return (DLADM_WALK_CONTINUE);
	}

	active[0] = '\0';
	supported[0] = '\0';
	dlled_mode2str(dil.dil_active, active, sizeof (active));
	dlled_mode2str(dil.dil_supported, supported, sizeof (supported));

	printf("%-20s %-12s %s\n", name, active, supported);

	return (DLADM_WALK_CONTINUE);
}

int
main(int argc, char *argv[])
{
	int c, ret;
	boolean_t opt_s = B_FALSE;
	mac_led_mode_t set_mode = 0;
	dladm_status_t status;

	dlled_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch (c) {
		case 's':
			opt_s = B_TRUE;
			set_mode = dlled_parse_mode(optarg);
			break;
		case ':':
			dlled_usage("option -%c requires an operand\n", optopt);
			return (2);
		case '?':
		default:
			dlled_usage("unknown option: -%c\n", optopt);
			return (2);
		}
	}

	argc -= optind;
	argv += optind;

	if (opt_s && argc > 1) {
		dlled_usage("-s only operates on a single datalink\n");
		return (2);
	}

	if (opt_s && argc <= 0) {
		dlled_usage("-s requires a datalink\n");
		return (2);
	}

	if ((status = dladm_open(&dlled_hdl)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to open /dev/dld: %s\n",
		    dladm_status2str(status, dlled_dlerrmsg));
		return (1);
	}

	if (opt_s) {
		return (dlled_set(argv[0], set_mode));
	}

	(void) printf("%-20s %-12s %s\n", "LINK", "ACTIVE", "SUPPORTED");

	ret = 0;
	if (argc == 0) {
		(void) dladm_walk_datalink_id(dlled_get_led, dlled_hdl, NULL,
		    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_ACTIVE);
	} else {
		int i, dlret;
		datalink_id_t linkid;

		for (i = 0; i < argc; i++) {
			if ((status = dladm_name2info(dlled_hdl, argv[i],
			    &linkid, NULL, NULL, NULL)) != DLADM_STATUS_OK) {
				(void) fprintf(stderr, "failed to get link "
				    "id for link %s: %s\n", link,
				    dladm_status2str(status, dlled_dlerrmsg));
				return (1);
			}

			dlret = dlled_get_led(dlled_hdl, linkid, NULL);
			if (dlret != DLADM_WALK_CONTINUE) {
				ret = 1;
				break;
			}
		}
	}

	return (ret);
}
