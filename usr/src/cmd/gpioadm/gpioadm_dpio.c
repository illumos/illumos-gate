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
 * Copyright 2022 Oxide Computer Company
 */

#include <err.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ofmt.h>
#include <libdevinfo.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "gpioadm.h"

static void
gpioadm_dpio_list_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm dpio list [-H] [-o field[,...] [-p]] "
	    "[filter...]\n");
}

static void __PRINTFLIKE(1)
gpioadm_dpio_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm dpio list [-H] [-o "
	    "field[,...] [-p]] [filter...]\n");
	(void) fprintf(stderr, "\nList information about DPIOs\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparsable output (requires -o)\n\n"
	    "The following fields are supported:\n"
	    "\tdpio\t\tthe name of the DPIO\n"
	    "\tcontroller\tthe name of the underlying GPIO controller\n"
	    "\tgpionum\t\tthe number of the underlying GPIO\n"
	    "\tcaps\t\tDPIO capabilities\n"
	    "\tflags\t\tDPIO flags that effect its behavior\n"
	    "Filters restrict output to the named DPIOs. Each filter is "
	    "treated\nlike an OR allowing one to limit output to specific "
	    "controllers. It is\nan error if a DPIO isn't found.\n");
}

typedef enum gpioadm_dpio_list_otype {
	GPIOADM_DPIO_LIST_DPIO,
	GPIOADM_DPIO_LIST_CTRL,
	GPIOADM_DPIO_LIST_GPIONUM,
	GPIOADM_DPIO_LIST_CAPS,
	GPIOADM_DPIO_LIST_FLAGS
} gpioadm_dpio_list_otype_t;

static boolean_t
gpioadm_dpio_list_ofmt_caps(char *buf, uint_t buflen, xpio_dpio_info_t *info)
{
	boolean_t first = B_TRUE;
	dpio_caps_t caps = xpio_dpio_info_caps(info);
	dpio_caps_t bits[3] = { DPIO_C_READ, DPIO_C_WRITE, DPIO_C_POLL };
	const char *strs[3] = { "read", "write", "poll" };
	uintptr_t off = 0;

	for (size_t i = 0; i < ARRAY_SIZE(bits); i++) {
		int len;

		if ((caps & bits[i]) == 0)
			continue;

		len = snprintf(buf + off, buflen - off, "%s%s",
		    first ? "" : ",", strs[i]);
		if (len >= (buflen - off)) {
			return (B_FALSE);
		}
		off += len;
		first = B_FALSE;
	}

	return (B_TRUE);
}

static boolean_t
gpioadm_dpio_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	xpio_dpio_info_t *info = ofarg->ofmt_cbarg;
	dpio_flags_t flags;

	switch (ofarg->ofmt_id) {
	case GPIOADM_DPIO_LIST_DPIO:
		if (strlcpy(buf, xpio_dpio_info_name(info), buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_DPIO_LIST_CTRL:
		if (strlcpy(buf, xpio_dpio_info_ctrl(info), buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_DPIO_LIST_GPIONUM:
		if (snprintf(buf, buflen, "%u", xpio_dpio_info_gpionum(info)) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_DPIO_LIST_CAPS:
		return (gpioadm_dpio_list_ofmt_caps(buf, buflen, info));
	case GPIOADM_DPIO_LIST_FLAGS:
		flags = xpio_dpio_info_flags(info);
		if (flags == 0) {
			if (strlcpy(buf, "-", buflen) >= buflen) {
				return (B_FALSE);
			}
		} else {
			if (strlcpy(buf, "K", buflen) >= buflen) {
				return (B_FALSE);
			}
		}
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const char *gpioadm_dpio_list_fields = "dpio,caps,flags,controller,"
	"gpionum";
static const ofmt_field_t gpioadm_dpio_list_ofmt[] = {
	{ "DPIO", 16, GPIOADM_DPIO_LIST_DPIO, gpioadm_dpio_list_ofmt_cb },
	{ "CAPS", 16, GPIOADM_DPIO_LIST_CAPS, gpioadm_dpio_list_ofmt_cb },
	{ "FLAGS", 8, GPIOADM_DPIO_LIST_FLAGS, gpioadm_dpio_list_ofmt_cb },
	{ "CONTROLLER", 16, GPIOADM_DPIO_LIST_CTRL, gpioadm_dpio_list_ofmt_cb },
	{ "GPIONUM", 8, GPIOADM_DPIO_LIST_GPIONUM, gpioadm_dpio_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

typedef struct {
	ofmt_handle_t gdl_ofmt;
	uint32_t gdl_nprint;
	bool gdl_err;
	int gdl_nfilts;
	char **gdl_filts;
	bool *gdl_used;
} gpioadm_dpio_list_t;

static bool
gpioadm_dpio_list_cb(xpio_t *xpio, xpio_dpio_disc_t *disc, void *arg)
{
	gpioadm_dpio_list_t *gdl = arg;
	/* Strip out the kernel mandated 'dpio:' */
	const char *name = di_minor_name(disc->xdd_minor) + 5;
	xpio_dpio_info_t *info;

	if (gdl->gdl_nfilts > 0) {
		bool found = false;

		for (int i = 0; i < gdl->gdl_nfilts; i++) {
			if (strcmp(name, gdl->gdl_filts[i]) == 0) {
				found = true;
				gdl->gdl_used[i] = true;
				break;
			}
		}

		if (!found) {
			return (true);
		}
	}

	gdl->gdl_nprint++;

	if (!xpio_dpio_info(gpioadm.gpio_xpio, disc->xdd_minor, &info)) {
		gpioadm_warn("failed to get controller info for %s", name);
		gdl->gdl_err = true;
		return (true);
	}

	ofmt_print(gdl->gdl_ofmt, info);
	xpio_dpio_info_free(info);

	return (true);
}

static int
gpioadm_dpio_list(int argc, char *argv[])
{
	int c;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	gpioadm_dpio_list_t gdl;

	(void) memset(&gdl, 0, sizeof (gdl));

	while ((c = getopt(argc, argv, ":Ho:p")) != -1) {
		switch (c) {
		case 'H':
			flags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'p':
			parse = B_TRUE;
			flags |= OFMT_PARSABLE;
			break;
		case ':':
			gpioadm_dpio_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_dpio_list_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (fields == NULL) {
		fields = gpioadm_dpio_list_fields;
	}

	argc -= optind;
	argv += optind;
	if (argc > 0) {
		gdl.gdl_nfilts = argc;
		gdl.gdl_filts = argv;
		gdl.gdl_used = calloc(argc, sizeof (bool));
		if (gdl.gdl_used == NULL) {
			err(EXIT_FAILURE, "failed to allocate filter tracking "
			    "memory");
		}
	}
	oferr = ofmt_open(fields, gpioadm_dpio_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, gpioadm_ofmt_errx, warnx);

	gdl.gdl_nprint = 0;
	gdl.gdl_err = B_FALSE;
	gdl.gdl_ofmt = ofmt;
	xpio_dpio_discover(gpioadm.gpio_xpio, gpioadm_dpio_list_cb, &gdl);

	for (int i = 0; i < gdl.gdl_nfilts; i++) {
		if (!gdl.gdl_used[i]) {
			warnx("filter '%s' did not match any DPIOs",
			    gdl.gdl_filts[i]);
			gdl.gdl_err = true;
		}
	}

	if (gdl.gdl_nprint == 0) {
		/*
		 * We only bother to warn about no DPIOs being found when there
		 * are no filters as otherwise the user would have gotten a
		 * message about unmatched filters just above.
		 */
		if (gdl.gdl_nfilts == 0) {
			warnx("no DPIOs found");
		}
		gdl.gdl_err = true;
	}

	return (gdl.gdl_err ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void
gpioadm_dpio_define_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm dpio define [-r] [-w] [-K] "
	    "controller/gpio name\n");
}

static void __PRINTFLIKE(1)
gpioadm_dpio_define_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm dpio define [-r] [-w] [-K] "
	    "controller/gpio name\n");
	(void) fprintf(stderr, "\nCreate a new DPIO from the specified GPIO\n\n"
	    "\t-r\t\tthe DPIO is allowed to read the GPIO input value\n"
	    "\t-w\t\tthe DPIO is allowed to set the GPIO output value\n"
	    "\t-K\t\tthe DPIO should only be accessible from the kernel\n");
}

static int
gpioadm_dpio_define(int argc, char *argv[])
{
	int c;
	xpio_ctrl_t *ctrl;
	xpio_gpio_info_t *gpio;
	xpio_dpio_features_t feats = 0;

	while ((c = getopt(argc, argv, ":rwK")) != -1) {
		switch (c) {
		case 'r':
			feats |= XPIO_DPIO_F_READ;
			break;
		case 'K':
			feats |= XPIO_DPIO_F_KERNEL;
			break;
		case 'w':
			feats |= XPIO_DPIO_F_WRITE;
			break;
		case ':':
			gpioadm_dpio_define_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_dpio_define_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		errx(EXIT_FAILURE, "missing required gpio specifier and dpio "
		    "name");
	} else if (argc == 1) {
		errx(EXIT_FAILURE, "missing required dpio name");
	} else if (argc > 2) {
		errx(EXIT_FAILURE, "encountered extraneous arguments beginning "
		    "with '%s'", argv[2]);
	}

	gpioadm_ctrl_gpio_init(argv[0], &ctrl, &gpio);
	if (!xpio_dpio_create(ctrl, gpio, argv[1], feats)) {
		gpioadm_fatal("failed to create dpio %s from gpio %s", argv[1],
		    argv[0]);
	}

	return (EXIT_SUCCESS);
}

static void
gpioadm_dpio_undefine_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm dpio undefine controller/gpio\n");
}

static void __PRINTFLIKE(1)
gpioadm_dpio_undefine_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm dpio undefine "
	    "controller/gpio\n");
	(void) fprintf(stderr, "\nRemove a DPIO from the system backed by the "
	    "specified controller and GPIO\n");
}

static int
gpioadm_dpio_undefine(int argc, char *argv[])
{
	int c;
	xpio_ctrl_t *ctrl;
	xpio_gpio_info_t *gpio;

	while ((c = getopt(argc, argv, ":")) != -1) {
		switch (c) {
		case ':':
			gpioadm_dpio_undefine_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_dpio_undefine_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		errx(EXIT_FAILURE, "missing required gpio specifier");
	} else if (argc > 1) {
		errx(EXIT_FAILURE, "encountered extraneous arguments beginning "
		    "with '%s'", argv[1]);
	}

	gpioadm_ctrl_gpio_init(argv[0], &ctrl, &gpio);
	if (!xpio_dpio_destroy(ctrl, gpio)) {
		gpioadm_fatal("failed to release gpio %s from being a DPIO",
		    argv[0]);
	}

	return (EXIT_SUCCESS);
}

static const gpioadm_cmdtab_t gpioadm_cmds_dpio[] = {
	{ "list", gpioadm_dpio_list, gpioadm_dpio_list_usage },
	{ "define", gpioadm_dpio_define, gpioadm_dpio_define_usage },
	{ "undefine", gpioadm_dpio_undefine, gpioadm_dpio_undefine_usage },
	{ NULL, NULL, NULL }
};

int
gpioadm_dpio(int argc, char *argv[])
{
	return (gpioadm_walk_tab(gpioadm_cmds_dpio, argc, argv));
}

void
gpioadm_dpio_usage(FILE *f)
{
	gpioadm_walk_usage(gpioadm_cmds_dpio, f);
}
