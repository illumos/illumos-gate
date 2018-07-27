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
 * Copyright (c) 2018 Joyent, Inc.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <libgen.h>
#include <libdevinfo.h>

#include <sys/sata/adapters/ahci/ahciem.h>

#define	AHCIEM_IDENT	"ident"
#define	AHCIEM_FAULT	"fault"
#define	AHCIEM_NOACTIVITY	"noactivity"
#define	AHCIEM_DEFAULT	"default"
#define	AHCIEM_UNKNOWN	"unknown"

#define	EXIT_USAGE	2

static const char *ahciem_progname;

typedef struct {
	boolean_t		ahci_set;
	ahci_em_led_state_t	ahci_led;
	int			ahci_argc;
	char			**ahci_argv;
	boolean_t		*ahci_found;
	int			ahci_err;
} ahciem_t;

static void
ahciem_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-s mode] [port]\n"
	    "\n"
	    "\t-s mode\t\tset LED to mode\n",
	    ahciem_progname);
}

static const char *
ahciem_led_to_string(uint_t led)
{
	switch (led) {
	case AHCI_EM_LED_IDENT_ENABLE:
		return (AHCIEM_IDENT);
	case AHCI_EM_LED_FAULT_ENABLE:
		return (AHCIEM_FAULT);
	case AHCI_EM_LED_ACTIVITY_DISABLE:
		return (AHCIEM_NOACTIVITY);
	case (AHCI_EM_LED_IDENT_ENABLE | AHCI_EM_LED_FAULT_ENABLE):
		return (AHCIEM_IDENT "," AHCIEM_FAULT);
	case (AHCI_EM_LED_IDENT_ENABLE | AHCI_EM_LED_ACTIVITY_DISABLE):
		return (AHCIEM_IDENT "," AHCIEM_NOACTIVITY);
	case (AHCI_EM_LED_FAULT_ENABLE | AHCI_EM_LED_ACTIVITY_DISABLE):
		return (AHCIEM_FAULT "," AHCIEM_NOACTIVITY);
	/* BEGIN CSTYLED */
	case (AHCI_EM_LED_IDENT_ENABLE | AHCI_EM_LED_FAULT_ENABLE |
	    AHCI_EM_LED_ACTIVITY_DISABLE):
		return (AHCIEM_IDENT "," AHCIEM_FAULT "," AHCIEM_NOACTIVITY);
	/* END CSTYLED */
	case 0:
		return (AHCIEM_DEFAULT);
	default:
		return (AHCIEM_UNKNOWN);
	}
}

static boolean_t
ahciem_match(ahciem_t *ahci, const char *port)
{
	int i;

	if (ahci->ahci_argc == 0)
		return (B_TRUE);

	for (i = 0; i < ahci->ahci_argc; i++) {
		size_t len = strlen(ahci->ahci_argv[i]);

		/*
		 * Perform a partial match on the base name. This allows us to
		 * match all of a controller by using a string like "ahci0".
		 */
		if (strncmp(ahci->ahci_argv[i], port, len) == 0) {
			ahci->ahci_found[i] = B_TRUE;
			return (B_TRUE);
		}

	}

	return (B_FALSE);
}

static ahci_em_led_state_t
ahciem_parse(const char *arg)
{
	if (strcmp(arg, AHCIEM_IDENT) == 0) {
		return (AHCI_EM_LED_IDENT_ENABLE);
	} else if (strcmp(arg, AHCIEM_FAULT) == 0) {
		return (AHCI_EM_LED_FAULT_ENABLE);
	} else if (strcmp(arg, AHCIEM_NOACTIVITY) == 0) {
		return (AHCI_EM_LED_ACTIVITY_DISABLE);
	} else if (strcmp(arg, AHCIEM_DEFAULT) == 0) {
		return (0);
	}

	errx(EXIT_USAGE, "invalid LED mode with -s: %s", arg);
}

static void
ahciem_set(ahciem_t *ahci, const char *portstr, int fd, int port)
{
	ahci_ioc_em_set_t set;

	bzero(&set, sizeof (set));

	set.aiems_port = port;
	set.aiems_op = AHCI_EM_IOC_SET_OP_SET;
	set.aiems_leds = ahci->ahci_led;

	if (ioctl(fd, AHCI_EM_IOC_SET, &set) != 0) {
		warn("failed to set LEDs on %s", portstr);
		ahci->ahci_err = 1;
	}
}

static int
ahciem_devinfo(di_node_t node, void *arg)
{
	char *driver, *mpath, *fullpath;
	const char *sup;
	int inst, fd;
	uint_t i;
	ahciem_t *ahci = arg;
	di_minor_t m;
	ahci_ioc_em_get_t get;

	if ((driver = di_driver_name(node)) == NULL)
		return (DI_WALK_CONTINUE);
	if (strcmp(driver, "ahci") != 0)
		return (DI_WALK_CONTINUE);
	inst = di_instance(node);

	m = DI_MINOR_NIL;
	while ((m = di_minor_next(node, m)) != DI_MINOR_NIL) {
		char *mname = di_minor_name(m);

		if (mname != NULL && strcmp("devctl", mname) == 0)
			break;
	}

	if (m == DI_MINOR_NIL) {
		warnx("encountered ahci%d without devctl node", inst);
		return (DI_WALK_PRUNECHILD);
	}

	if ((mpath = di_devfs_minor_path(m)) == NULL) {
		warnx("failed to get path for ahci%d devctl minor", inst);
		return (DI_WALK_PRUNECHILD);
	}

	if (asprintf(&fullpath, "/devices/%s", mpath) == -1) {
		warn("failed to construct /devices path from %s", mpath);
		return (DI_WALK_PRUNECHILD);
	}

	if ((fd = open(fullpath, O_RDWR)) < 0) {
		warn("failed to open ahci%d devctl path %s", inst, fullpath);
		goto out;
	}

	bzero(&get, sizeof (get));
	if (ioctl(fd, AHCI_EM_IOC_GET, &get) != 0) {
		warn("failed to get AHCI enclosure information for ahci%d",
		    inst);
		ahci->ahci_err = 1;
		goto out;
	}

	if ((get.aiemg_flags & AHCI_EM_FLAG_CONTROL_ACTIVITY) != 0) {
		sup = ahciem_led_to_string(AHCI_EM_LED_IDENT_ENABLE |
		    AHCI_EM_LED_FAULT_ENABLE | AHCI_EM_LED_ACTIVITY_DISABLE);
	} else {
		sup = ahciem_led_to_string(AHCI_EM_LED_IDENT_ENABLE |
		    AHCI_EM_LED_FAULT_ENABLE);
	}

	for (i = 0; i < AHCI_EM_IOC_MAX_PORTS; i++) {
		char port[64];
		const char *state;

		if (((1 << i) & get.aiemg_nports) == 0)
			continue;

		(void) snprintf(port, sizeof (port), "ahci%d/%u", inst, i);
		if (!ahciem_match(ahci, port))
			continue;

		if (ahci->ahci_set) {
			ahciem_set(ahci, port, fd, i);
			continue;
		}

		state = ahciem_led_to_string(get.aiemg_status[i]);
		(void) printf("%-20s %-12s %s,default\n", port, state, sup);
	}

out:
	free(fullpath);
	return (DI_WALK_PRUNECHILD);
}

int
main(int argc, char *argv[])
{
	int c, i, ret;
	di_node_t root;
	ahciem_t ahci;

	ahciem_progname = basename(argv[0]);

	bzero(&ahci, sizeof (ahciem_t));
	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch (c) {
		case 's':
			ahci.ahci_set = B_TRUE;
			ahci.ahci_led = ahciem_parse(optarg);
			break;
		case ':':
			ahciem_usage("option -%c requires an operand\n",
			    optopt);
			return (EXIT_USAGE);
		case '?':
		default:
			ahciem_usage("unknown option: -%c\n", optopt);
			return (EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;
	ahci.ahci_argc = argc;
	ahci.ahci_argv = argv;
	if (argc > 0) {
		ahci.ahci_found = calloc(argc, sizeof (boolean_t));
		if (ahci.ahci_found == NULL) {
			err(EXIT_FAILURE, "failed to alloc memory for %d "
			    "booleans", argc);
		}
	}

	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		err(EXIT_FAILURE, "failed to open devinfo tree");
	}

	if (!ahci.ahci_set) {
		(void) printf("%-20s %-12s %s\n", "PORT", "ACTIVE",
		    "SUPPORTED");
	}

	if (di_walk_node(root, DI_WALK_CLDFIRST, &ahci,
	    ahciem_devinfo) != 0) {
		err(EXIT_FAILURE, "failed to walk devinfo tree");
	}

	ret = ahci.ahci_err;
	for (i = 0; i < argc; i++) {
		if (ahci.ahci_found[i])
			continue;
		warnx("failed to find ahci enclosure port \"%s\"",
		    ahci.ahci_argv[i]);
		ret = 1;
	}

	return (ret);
}
