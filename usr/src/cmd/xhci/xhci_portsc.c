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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * This is a private utility that combines a number of minor debugging routines
 * for xhci.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libdevinfo.h>
#include <sys/usb/hcd/xhci/xhci_ioctl.h>
#include <sys/usb/hcd/xhci/xhcireg.h>

static char *xp_devpath = NULL;
static int xp_npaths;
static const char *xp_path;
static const char *xp_state = NULL;
static uint32_t xp_port;
static boolean_t xp_verbose = B_FALSE;
static boolean_t xp_clear = B_FALSE;
static boolean_t xp_list = B_FALSE;
extern const char *__progname;

static int
xp_usage(const char *format, ...)
{
	if (format != NULL) {
		va_list alist;

		va_start(alist, format);
		vwarnx(format, alist);
		va_end(alist);
	}

	(void) fprintf(stderr, "usage:  %s [-l] [-v] [-c] [-d path] [-p port] "
	    "[-s state]\n", __progname);
	return (2);
}

static const char *xp_pls_strings[] = {
	"U0",
	"U1",
	"U2",
	"U3 (suspended)",
	"Disabled",
	"RxDetect",
	"Inactive",
	"Polling",
	"Recovery",
	"Hot Reset",
	"Compliance Mode",
	"Test Mode",
	"Reserved",
	"Reserved",
	"Reserved",
	"Resume",
	NULL
};

static void
xp_dump_verbose(uint32_t portsc)
{
	if (portsc & XHCI_PS_CCS)
		(void) printf("\t\t\tCCS\n");
	if (portsc & XHCI_PS_PED)
		(void) printf("\t\t\tPED\n");
	if (portsc & XHCI_PS_OCA)
		(void) printf("\t\t\tOCA\n");
	if (portsc & XHCI_PS_PR)
		(void) printf("\t\t\tPR\n");
	if (portsc & XHCI_PS_PP) {
		(void) printf("\t\t\tPLS: %s (%d)\n",
		    xp_pls_strings[XHCI_PS_PLS_GET(portsc)],
		    XHCI_PS_PLS_GET(portsc));
		(void) printf("\t\t\tPP\n");
	} else {
		(void) printf("\t\t\tPLS: undefined (No PP)\n");
	}

	if (XHCI_PS_SPEED_GET(portsc) != 0) {
		(void) printf("\t\t\tPort Speed: ");
		switch (XHCI_PS_SPEED_GET(portsc)) {
		case 0:
			(void) printf("Undefined ");
			break;
		case XHCI_SPEED_FULL:
			(void) printf("Full ");
			break;
		case XHCI_SPEED_LOW:
			(void) printf("Low ");
			break;
		case XHCI_SPEED_HIGH:
			(void) printf("High ");
			break;
		case XHCI_SPEED_SUPER:
			(void) printf("Super ");
			break;
		default:
			(void) printf("Unknown ");
			break;
		}
		(void) printf("(%d)\n", XHCI_PS_SPEED_GET(portsc));
	}
	if (XHCI_PS_PIC_GET(portsc) != 0)
		(void) printf("\t\t\tPIC: %d\n", XHCI_PS_PIC_GET(portsc));

	if (portsc & XHCI_PS_LWS)
		(void) printf("\t\t\tLWS\n");
	if (portsc & XHCI_PS_CSC)
		(void) printf("\t\t\tCSC\n");
	if (portsc & XHCI_PS_PEC)
		(void) printf("\t\t\tPEC\n");
	if (portsc & XHCI_PS_WRC)
		(void) printf("\t\t\tWRC\n");
	if (portsc & XHCI_PS_OCC)
		(void) printf("\t\t\tOCC\n");
	if (portsc & XHCI_PS_PRC)
		(void) printf("\t\t\tPRC\n");
	if (portsc & XHCI_PS_PLC)
		(void) printf("\t\t\tPLC\n");
	if (portsc & XHCI_PS_CEC)
		(void) printf("\t\t\tCEC\n");
	if (portsc & XHCI_PS_CAS)
		(void) printf("\t\t\tCAS\n");
	if (portsc & XHCI_PS_WCE)
		(void) printf("\t\t\tWCE\n");
	if (portsc & XHCI_PS_WDE)
		(void) printf("\t\t\tWDE\n");
	if (portsc & XHCI_PS_WOE)
		(void) printf("\t\t\tWOE\n");
	if (portsc & XHCI_PS_DR)
		(void) printf("\t\t\tDR\n");
	if (portsc & XHCI_PS_WPR)
		(void) printf("\t\t\tWPR\n");
}

static void
xp_dump(const char *path)
{
	int fd, i;
	xhci_ioctl_portsc_t xhi = { 0 };

	fd = open(path, O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open %s", path);
	}

	if (ioctl(fd, XHCI_IOCTL_PORTSC, &xhi) != 0)
		err(EXIT_FAILURE, "failed to get port status");

	(void) close(fd);

	for (i = 1; i <= xhi.xhi_nports; i++) {
		if (xp_port != 0 && i != xp_port)
			continue;

		(void) printf("port %2d:\t0x%08x\n", i, xhi.xhi_portsc[i]);
		if (xp_verbose == B_TRUE)
			xp_dump_verbose(xhi.xhi_portsc[i]);
	}
}

static void
xp_set_pls(const char *path, uint32_t port, const char *state)
{
	int fd, i;
	xhci_ioctl_setpls_t xis;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open %s", path);
	}

	xis.xis_port = port;
	for (i = 0; xp_pls_strings[i] != NULL; i++) {
		if (strcasecmp(state, xp_pls_strings[i]) == 0)
			break;
	}

	if (xp_pls_strings[i] == NULL) {
		errx(EXIT_FAILURE, "unknown state string: %s\n", state);
	}

	xis.xis_pls = i;
	(void) printf("setting port %d with pls %d\n", port, xis.xis_pls);

	if (ioctl(fd, XHCI_IOCTL_SETPLS, &xis) != 0)
		err(EXIT_FAILURE, "failed to set port status");

	(void) close(fd);
}

static void
xp_clear_change(const char *path, uint32_t port)
{
	int fd;
	xhci_ioctl_clear_t xic;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open %s", path);
	}

	xic.xic_port = port;
	(void) printf("clearing change bits on port %d\n", port);
	if (ioctl(fd, XHCI_IOCTL_CLEAR, &xic) != 0)
		err(EXIT_FAILURE, "failed to set port status");

	(void) close(fd);
}

/* ARGSUSED */
static int
xp_devinfo_cb(di_node_t node, void *arg)
{
	char *drv;
	di_minor_t minor;
	boolean_t *do_print = arg;

	drv = di_driver_name(node);
	if (drv == NULL)
		return (DI_WALK_CONTINUE);
	if (strcmp(drv, "xhci") != 0)
		return (DI_WALK_CONTINUE);

	/*
	 * We have an instance of the xhci driver. We need to find the minor
	 * node for the hubd instance. These are all usually greater than
	 * HUBD_IS_ROOT_HUB. However, to avoid hardcoding that here, we instead
	 * rely on the fact that the minor node for the actual device has a
	 * :hubd as the intance.
	 */
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		char *mname, *path;

		mname = di_minor_name(minor);
		if (mname == NULL)
			continue;
		if (strcmp(mname, "hubd") != 0)
			continue;
		path = di_devfs_minor_path(minor);
		if (*do_print == B_TRUE) {
			(void) printf("/devices%s\n", path);
			di_devfs_path_free(path);
		} else {
			xp_npaths++;
			if (xp_devpath == NULL)
				xp_devpath = path;
			else
				di_devfs_path_free(path);
		}
	}

	return (DI_WALK_PRUNECHILD);
}

/*
 * We need to find all minor nodes of instances of the xhci driver whose name is
 * 'hubd'.
 */
static void
xp_find_devs(boolean_t print)
{
	di_node_t root;

	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		err(EXIT_FAILURE, "failed to initialize devices tree");
	}

	if (di_walk_node(root, DI_WALK_CLDFIRST, &print, xp_devinfo_cb) != 0)
		err(EXIT_FAILURE, "failed to walk devices tree");
}

int
main(int argc, char *argv[])
{
	int c;
	char devpath[PATH_MAX];

	while ((c = getopt(argc, argv, ":d:vlcp:s:")) != -1) {
		switch (c) {
		case 'c':
			xp_clear = B_TRUE;
			break;
		case 'd':
			xp_path = optarg;
			break;
		case 'l':
			xp_list = B_TRUE;
			break;
		case 'v':
			xp_verbose = B_TRUE;
			break;
		case 'p':
			xp_port = atoi(optarg);
			if (xp_port < 1 || xp_port > XHCI_PORTSC_NPORTS)
				return (xp_usage("invalid port for -p: %d\n",
				    optarg));
			break;
		case 's':
			xp_state = optarg;
			break;
		case ':':
			return (xp_usage("-%c requires an operand\n", optopt));
		case '?':
			return (xp_usage("unknown option: -%c\n", optopt));
		default:
			abort();
		}
	}

	if (xp_list == B_TRUE && (xp_path != NULL || xp_clear == B_TRUE ||
	    xp_port > 0 || xp_state != NULL)) {
		return (xp_usage("-l cannot be used with other options\n"));
	}

	if (xp_list == B_TRUE) {
		xp_find_devs(B_TRUE);
		return (0);
	}

	if (xp_path == NULL) {
		xp_find_devs(B_FALSE);
		if (xp_npaths == 0) {
			errx(EXIT_FAILURE, "no xhci devices found");
		} else if (xp_npaths > 1) {
			errx(EXIT_FAILURE, "more than one xhci device found, "
			    "please specify device with -d, use -l to list");
		}
		if (snprintf(devpath, sizeof (devpath), "/devices/%s",
		    xp_devpath) >= sizeof (devpath))
			errx(EXIT_FAILURE, "xhci path found at %s overflows "
			    "internal device path");
		di_devfs_path_free(xp_devpath);
		xp_devpath = NULL;
		xp_path = devpath;
	}

	if (xp_clear == B_TRUE && xp_state != NULL) {
		return (xp_usage("-c and -s can't be used together\n"));
	}

	if (xp_state != NULL) {
		xp_set_pls(xp_path, xp_port, xp_state);
	} else if (xp_clear == B_TRUE) {
		xp_clear_change(xp_path, xp_port);
	} else {
		xp_dump(xp_path);
	}

	return (0);
}
