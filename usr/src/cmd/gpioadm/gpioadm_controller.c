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

#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ofmt.h>
#include <libdevinfo.h>
#include <strings.h>
#include <sys/debug.h>

#include "gpioadm.h"

static void
gpioadm_controller_list_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm controller list [-H] [-o field[,...] "
	    "[-p]] [filter...]\n");
}

static void __PRINTFLIKE(1)
gpioadm_controller_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm controller list [-H] [-o "
	    "field[,...] [-p]] [filter...]\n");
	(void) fprintf(stderr, "\nList GPIO controllers in the system and "
	    "associated information.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparsable output (requires -o)\n\n"
	    "The following fields are supported:\n"
	    "\tcontroller\tthe name of the controller\n"
	    "\tngpios\t\tthe number of GPIOs the controller has\n"
	    "\tndpios\t\tthe number of DPIOs the controller has\n"
	    "\tpath\t\tthe path to the minor node of the controller\n"
	    "\tprovider\tthe /devices path of the provider\n\n"
	    "Filters restrict output to the named controllers. Each filter is "
	    "treated\nlike an OR allowing one to limit output to specific "
	    "controllers. It is\nan error if a controller isn't found.\n");
}

typedef enum gpioadm_controller_list_otype {
	GPIOADM_CTRL_LIST_CTRLR,
	GPIOADM_CTRL_LIST_NGPIO,
	GPIOADM_CTRL_LIST_NDPIO,
	GPIOADM_CTRL_LIST_PATH,
	GPIOADM_CTRL_LIST_PROVIDER
} gpioadm_controllier_list_otype_t;

typedef struct gpioadm_controller_list_ofmt {
	const char *gclo_minor;
	const char *gclo_devpath;
	char *gclo_path;
	uint32_t gclo_ngpio;
	uint32_t gclo_ndpio;
} gpioadm_controller_list_ofmt_t;

static boolean_t
gpioadm_controller_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	gpioadm_controller_list_ofmt_t *gclo = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case GPIOADM_CTRL_LIST_CTRLR:
		if (strlcpy(buf, gclo->gclo_minor, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_CTRL_LIST_NGPIO:
		if (snprintf(buf, buflen, "%u", gclo->gclo_ngpio) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_CTRL_LIST_NDPIO:
		if (snprintf(buf, buflen, "%u", gclo->gclo_ndpio) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_CTRL_LIST_PROVIDER:
		if (strlcpy(buf, gclo->gclo_devpath, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_CTRL_LIST_PATH:
		/*
		 * Asking for the minor path can fail. So if we have nothing,
		 * just ignore this.
		 */
		if (gclo->gclo_path == NULL)
			break;
		if (strlcpy(buf, gclo->gclo_path, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static const char *gpioadm_controller_list_fields = "controller,ngpios,ndpios,"
	"provider";
static const ofmt_field_t gpioadm_controller_list_ofmt[] = {
	{ "CONTROLLER", 16, GPIOADM_CTRL_LIST_CTRLR,
	    gpioadm_controller_list_ofmt_cb },
	{ "NGPIOS", 8, GPIOADM_CTRL_LIST_NGPIO,
	    gpioadm_controller_list_ofmt_cb },
	{ "NDPIOS", 8, GPIOADM_CTRL_LIST_NDPIO,
	    gpioadm_controller_list_ofmt_cb },
	{ "PROVIDER", 42, GPIOADM_CTRL_LIST_PROVIDER,
	    gpioadm_controller_list_ofmt_cb },
	{ "PATH", 42, GPIOADM_CTRL_LIST_PATH,
	    gpioadm_controller_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

typedef struct {
	ofmt_handle_t gcl_ofmt;
	uint32_t gcl_nprint;
	bool gcl_err;
	int gcl_nfilts;
	char **gcl_filts;
	bool *gcl_used;
} gpioadm_controller_list_t;

static bool
gpioadm_controller_list_cb(xpio_t *xpio, xpio_ctrl_disc_t *disc, void *arg)
{
	xpio_ctrl_t *ctrl;
	xpio_ctrl_info_t *info;
	gpioadm_controller_list_ofmt_t list;
	gpioadm_controller_list_t *gcl = arg;
	const char *mname = di_minor_name(disc->xcd_minor);

	if (gcl->gcl_nfilts > 0) {
		bool match = false;

		for (int i = 0; i < gcl->gcl_nfilts; i++) {
			if (strcmp(mname, gcl->gcl_filts[i]) == 0) {
				gcl->gcl_used[i] = true;
				match = true;
				break;
			}
		}

		if (!match) {
			return (true);
		}
	}

	if (!xpio_ctrl_init(xpio, disc->xcd_minor, &ctrl)) {
		gpioadm_warn("failed to initialize controller %s", mname);
		gcl->gcl_err = B_TRUE;
		return (true);
	}

	if (!xpio_ctrl_info(ctrl, &info)) {
		gpioadm_warn("failed to get controller info for %s", mname);
		xpio_ctrl_fini(ctrl);
		gcl->gcl_err = B_TRUE;
		return (true);
	}

	bzero(&list, sizeof (list));
	list.gclo_minor = mname;
	list.gclo_ngpio = xpio_ctrl_info_ngpios(info);
	list.gclo_ndpio = xpio_ctrl_info_ndpios(info);
	list.gclo_devpath = xpio_ctrl_info_devpath(info);
	list.gclo_path = di_devfs_minor_path(disc->xcd_minor);

	ofmt_print(gcl->gcl_ofmt, &list);
	gcl->gcl_nprint++;

	di_devfs_path_free(list.gclo_path);
	xpio_ctrl_info_free(info);
	xpio_ctrl_fini(ctrl);
	return (true);
}

static int
gpioadm_controller_list(int argc, char *argv[])
{
	int c;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	gpioadm_controller_list_t gcl;

	(void) memset(&gcl, 0, sizeof (gcl));

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
			gpioadm_controller_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_controller_list_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (fields == NULL) {
		fields = gpioadm_controller_list_fields;
	}

	argc -= optind;
	argv += optind;
	if (argc > 0) {
		gcl.gcl_nfilts = argc;
		gcl.gcl_filts = argv;
		gcl.gcl_used = calloc(argc, sizeof (bool));
		if (gcl.gcl_used == NULL) {
			err(EXIT_FAILURE, "failed to allocate filter tracking "
			    "memory");
		}
	}
	oferr = ofmt_open(fields, gpioadm_controller_list_ofmt, flags, 0,
	    &ofmt);
	ofmt_check(oferr, parse, ofmt, gpioadm_ofmt_errx, warnx);

	gcl.gcl_nprint = 0;
	gcl.gcl_err = B_FALSE;
	gcl.gcl_ofmt = ofmt;
	xpio_ctrl_discover(gpioadm.gpio_xpio, gpioadm_controller_list_cb,
	    &gcl);

	for (int i = 0; i < gcl.gcl_nfilts; i++) {
		if (!gcl.gcl_used[i]) {
			warnx("filter '%s' did not match any controllers",
			    gcl.gcl_filts[i]);
			gcl.gcl_err = true;
		}
	}

	if (gcl.gcl_nprint == 0) {
		/*
		 * We only bother to warn about no controllers being found when
		 * there are no filters as otherwise the user would have gotten
		 * a message about unmatched filters just above.
		 */
		if (gcl.gcl_nfilts == 0) {
			warnx("no gpio controllers found");
		}
		gcl.gcl_err = true;
	}

	return (gcl.gcl_err ? EXIT_FAILURE : EXIT_SUCCESS);
}

static const gpioadm_cmdtab_t gpioadm_cmds_ctrl[] = {
	{ "list", gpioadm_controller_list, gpioadm_controller_list_usage },
	{ NULL, NULL, NULL }
};

int
gpioadm_controller(int argc, char *argv[])
{
	return (gpioadm_walk_tab(gpioadm_cmds_ctrl, argc, argv));
}

void
gpioadm_controller_usage(FILE *f)
{
	gpioadm_walk_usage(gpioadm_cmds_ctrl, f);
}
