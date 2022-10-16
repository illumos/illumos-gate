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
gpioadm_gpio_attr_get_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm gpio attr get [-H] [-o field[,...] [-p]] "
	    "controller/gpio [filter...]\n");
}

static void __PRINTFLIKE(1)
gpioadm_gpio_attr_get_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm gpio attr get [-H] "
	    "[-o field[,...] [-p]] controller/gpio\n\t\t\t      [filter...]\n");
	(void) fprintf(stderr, "\nList attributes of a specific GPIO\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparsable output (requires -o)\n\n"
	    "The following fields are supported:\n"
	    "\tattr\t\tthe name of the attribute\n"
	    "\tvalue\t\tthe human-readable value of the attribute\n"
	    "\traw\t\tan untranslated value of the attribute (e.g. "
	    "underlying\n\t\t\tenum)\n"
	    "\tperm\t\tthe permissions of the attribute\n"
	    "\tpossible\tthe possible values the attribute may take\n\n"
	    "Supported filters are the names of attributes. An attribute "
	    "will be printed\nas long as it matches a single filter (they "
	    "function as an OR). If any\nfilter does not match, then a non-"
	    "zero exit status is returned.\n");
}

typedef enum gpioadm_gpio_attr_get_otype {
	GPIOADM_GPIO_ATTR_GET_ATTR,
	GPIOADM_GPIO_ATTR_GET_VALUE,
	GPIOADM_GPIO_ATTR_GET_RAW,
	GPIOADM_GPIO_ATTR_GET_PERM,
	GPIOADM_GPIO_ATTR_GET_POSSIBLE,
} gpioadm_gpio_attr_get_otype_t;

typedef struct gpioadm_gpio_attr_get_ofmt {
	xpio_gpio_info_t *ggag_info;
	xpio_gpio_attr_t *ggag_attr;
} gpioadm_gpio_attr_get_ofmt_t;

static boolean_t
gpioadm_gpio_attr_get_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	const char *str;
	uint32_t u32;
	uint32_t *u32_arr;
	const char **str_arr;
	uint_t count;
	uintptr_t off = 0;

	gpioadm_gpio_attr_get_ofmt_t *ggag = ofarg->ofmt_cbarg;
	xpio_gpio_info_t *info = ggag->ggag_info;
	xpio_gpio_attr_t *attr = ggag->ggag_attr;

	switch (ofarg->ofmt_id) {
	case GPIOADM_GPIO_ATTR_GET_ATTR:
		if (strlcpy(buf, xpio_gpio_attr_name(info, attr), buflen) >=
		    buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_GPIO_ATTR_GET_VALUE:
		switch (xpio_gpio_attr_type(info, attr)) {
		case XPIO_ATTR_TYPE_STRING:
			if (!xpio_gpio_attr_value_string(attr, &str)) {
				return (B_FALSE);
			}

			if (strlcpy(buf, str, buflen) >= buflen) {
				return (B_FALSE);
			}
			break;
		case XPIO_ATTR_TYPE_UINT32:
			if (!xpio_gpio_attr_xlate_to_str(info, attr, buf,
			    buflen)) {
				return (B_FALSE);
			}
			break;
		}
		break;
	case GPIOADM_GPIO_ATTR_GET_RAW:
		switch (xpio_gpio_attr_type(info, attr)) {
		case XPIO_ATTR_TYPE_STRING:
			if (!xpio_gpio_attr_value_string(attr, &str)) {
				return (B_FALSE);
			}

			if (strlcpy(buf, str, buflen) >= buflen) {
				return (B_FALSE);
			}
			break;
		case XPIO_ATTR_TYPE_UINT32:
			if (!xpio_gpio_attr_value_uint32(attr, &u32)) {
				return (B_FALSE);
			}

			if (snprintf(buf, buflen, "0x%x", u32) >= buflen) {
				return (B_FALSE);
			}
			break;
		}
		break;
	case GPIOADM_GPIO_ATTR_GET_PERM:
		switch (xpio_gpio_attr_prot(info, attr)) {
		case XPIO_ATTR_PROT_RO:
			if (strlcpy(buf, "r-", buflen) >= buflen) {
				return (B_FALSE);
			}
			break;
		case XPIO_ATTR_PROT_RW:
			if (strlcpy(buf, "rw", buflen) >= buflen) {
				return (B_FALSE);
			}
			break;
		}
		break;
	case GPIOADM_GPIO_ATTR_GET_POSSIBLE:
		switch (xpio_gpio_attr_type(info, attr)) {
		case XPIO_ATTR_TYPE_STRING:
			xpio_gpio_attr_possible_string(info, attr, &str_arr,
			    &count);
			for (uint_t i = 0; i < count; i++) {
				int len = snprintf(buf + off, buflen - off,
				    "%s%s", i > 0 ? "," : "", str_arr[i]);
				if (len >= (buflen - off)) {
					return (B_FALSE);
				}
				off += len;
			}
			break;
		case XPIO_ATTR_TYPE_UINT32:
			xpio_gpio_attr_possible_uint32(info, attr, &u32_arr,
			    &count);
			for (uint_t i = 0; i < count; i++) {
				char xlate[512];
				if (!xpio_gpio_attr_xlate_uint32_to_str(info,
				    attr, u32_arr[i], xlate, sizeof (xlate))) {
					return (B_FALSE);
				}
				int len = snprintf(buf + off, buflen - off,
				    "%s%s", i > 0 ? "," : "", xlate);
				if (len >= (buflen - off)) {
					return (B_FALSE);
				}
				off += len;
			}
			break;
		}
		break;
	default:
		abort();
	}

	return (B_TRUE);
}

static const char *gpioadm_gpio_attr_get_fields = "attr,perm,value,possible";
static const ofmt_field_t gpioadm_gpio_attr_get_ofmt[] = {
	{ "ATTR", 22, GPIOADM_GPIO_ATTR_GET_ATTR,
	    gpioadm_gpio_attr_get_ofmt_cb },
	{ "PERM", 6, GPIOADM_GPIO_ATTR_GET_PERM,
	    gpioadm_gpio_attr_get_ofmt_cb },
	{ "VALUE", 24, GPIOADM_GPIO_ATTR_GET_VALUE,
	    gpioadm_gpio_attr_get_ofmt_cb },
	{ "RAW", 16, GPIOADM_GPIO_ATTR_GET_RAW,
	    gpioadm_gpio_attr_get_ofmt_cb },
	{ "POSSIBLE", 24, GPIOADM_GPIO_ATTR_GET_POSSIBLE,
	    gpioadm_gpio_attr_get_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static int
gpioadm_gpio_attr_get(int argc, char *argv[])
{
	int c, ret;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL, *target = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	xpio_ctrl_t *ctrl;
	xpio_gpio_info_t *gpio;
	bool *filts = NULL;

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
			gpioadm_gpio_attr_get_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_gpio_attr_get_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (!parse) {
		flags |= OFMT_WRAP;
	}

	if (fields == NULL) {
		fields = gpioadm_gpio_attr_get_fields;
	}

	argc -= optind;
	argv += optind;
	if (argc == 0) {
		errx(EXIT_FAILURE, "missing required controller and gpio");
	}
	target = argv[0];
	argc--;
	argv++;

	if (argc > 0) {
		filts = calloc(argc, sizeof (bool));
		if (filts == NULL) {
			err(EXIT_FAILURE, "failed to allocate memory for "
			    "filter tracking");
		}
	}
	oferr = ofmt_open(fields, gpioadm_gpio_attr_get_ofmt, flags, 0,
	    &ofmt);
	ofmt_check(oferr, parse, ofmt, gpioadm_ofmt_errx, warnx);

	gpioadm_ctrl_gpio_init(target, &ctrl, &gpio);

	for (xpio_gpio_attr_t *attr = xpio_gpio_attr_next(gpio, NULL);
	    attr != NULL; attr = xpio_gpio_attr_next(gpio, attr)) {
		gpioadm_gpio_attr_get_ofmt_t ggag;

		if (argc > 0) {
			const char *aname = xpio_gpio_attr_name(gpio, attr);
			bool match = false;
			for (int i = 0; i < argc; i++) {
				if (strcmp(argv[i], aname) == 0) {
					match = true;
					filts[i] = true;
				}
			}

			if (!match) {
				continue;
			}
		}

		ggag.ggag_info = gpio;
		ggag.ggag_attr = attr;
		ofmt_print(ofmt, &ggag);
	}

	ret = EXIT_SUCCESS;
	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any attributes",
			    argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	free(filts);
	return (ret);
}

static void
gpioadm_gpio_attr_set_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm gpio attr set controller/gpio attr=value "
	    "[attr=value...]\n");
}

static void __PRINTFLIKE(1)
gpioadm_gpio_attr_set_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm gpio attr set controller/gpio "
	    "attr=value [attr=value...]\n");
	(void) fprintf(stderr, "\nSets the attributes of a single GPIO. "
	    "All specified attributes are\napplied at once.\n");
}

static int
gpioadm_gpio_attr_set(int argc, char *argv[])
{
	int c;
	const char *target;
	xpio_ctrl_t *ctrl;
	xpio_gpio_info_t *gpio;
	xpio_gpio_update_t *update;

	while ((c = getopt(argc, argv, ":")) != -1) {
		switch (c) {
		case ':':
			gpioadm_gpio_attr_set_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_gpio_attr_set_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		errx(EXIT_USAGE, "missing required controller/gpio target");
	}

	if (argc == 1) {
		errx(EXIT_USAGE, "missing required attribute settings");
	}

	target = argv[0];
	gpioadm_ctrl_gpio_init(target, &ctrl, &gpio);
	if (!xpio_gpio_update_init(gpioadm.gpio_xpio, gpio, &update)) {
		gpioadm_fatal("failed to initialize update");
	}

	for (int i = 1; i < argc; i++) {
		char *eq = strchr(argv[i], '=');
		const char *name, *value;
		xpio_gpio_attr_t *attr;

		if (eq == NULL) {
			errx(EXIT_FAILURE, "invalid attribute: missing equals "
			    "sign for value: %s", argv[i]);
		}
		name = argv[i];
		value = eq + 1;
		*eq = '\0';

		attr = xpio_gpio_attr_find(gpio, name);
		if (attr == NULL) {
			errx(EXIT_FAILURE, "invalid attribute: no attribute "
			    "named %s exists for GPIO %s", name, target);
		}

		if (!xpio_gpio_attr_from_str(update, attr, value)) {
			gpioadm_update_fatal(update, "failed to set attribute "
			    "%s to %s on GPIO %s", name, value, target);
		}
	}

	if (!xpio_gpio_update(ctrl, update)) {
		if (xpio_err(gpioadm.gpio_xpio) != XPIO_ERR_BAD_UPDATE) {
			gpioadm_fatal("failed to update GPIO %s", target);
		}

		gpioadm_warn("failed to update GPIO %s", target);

		for (xpio_gpio_attr_err_t *err =
		    xpio_gpio_attr_err_next(update, NULL); err != NULL;
		    err = xpio_gpio_attr_err_next(update, err)) {
			xpio_update_err_t uerr = xpio_gpio_attr_err_err(err);

			(void) fprintf(stderr, "\tattribute %s -- %s (0x%x)\n",
			    xpio_gpio_attr_err_name(err),
			    xpio_update_err2str(update, uerr), uerr);
		}
	}

	return (EXIT_SUCCESS);
}

static const gpioadm_cmdtab_t gpioadm_cmds_gpio_attr[] = {
	{ "get", gpioadm_gpio_attr_get, gpioadm_gpio_attr_get_usage },
	{ "set", gpioadm_gpio_attr_set, gpioadm_gpio_attr_set_usage },
	{ NULL, NULL, NULL }
};

static void
gpioadm_gpio_attr_usage(FILE *f)
{
	gpioadm_walk_usage(gpioadm_cmds_gpio_attr, f);
}

static int
gpioadm_gpio_attr(int argc, char *argv[])
{
	return (gpioadm_walk_tab(gpioadm_cmds_gpio_attr, argc, argv));
}

static void
gpioadm_gpio_list_usage(FILE *f)
{
	(void) fprintf(f, "\tgpioadm gpio list [-H] [-o field[,...] [-p]] "
	    "[-1] [filter...]\n");
}

static void __PRINTFLIKE(1)
gpioadm_gpio_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  gpioadm gpio list [-H] [-o "
	    "field[,...] [-p]] [-1] [filter...]\n");
	(void) fprintf(stderr, "\nList GPIOs in the system.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparsable output (requires -o)\n"
	    "\t-1\t\terror if more than one GPIO is listed\n\n"
	    "The following fields are supported:\n"
	    "\tcontroller\tthe name of the controller\n"
	    "\tgpio\t\tthe name of the gpio\n"
	    "\tid\t\tthe GPIO's numeric id\n"
	    "Filters can be used to constrain the GPIOs that are listed. If a "
	    "filter is\npresent, it will be an error if it is unused. Filters "
	    "can specify either an\nentire controller, a specific GPIO on a "
	    "controller, or all GPIOs with a given\nname. The controller and "
	    "GPIO are separated with a '/' character. For example:\n\n"
	    "\tgpio_sim0\t\tThis would match all GPIOs on the controller\n"
	    "\t\t\t\t'gpio_sim0'.\n"
	    "\tzen_gpio0/EGPIO9_3\tThis would match the specific GPIO, "
	    "EGPIO9_3,\n\t\t\t\ton the specified controller, zen_gpio0.\n"
	    "\t*/gpio3\t\t\tThis would match all GPIOs named 'gpio3' on any\n"
	    "\t\t\t\tcontroller.\n");
}

typedef enum gpioadm_gpio_list_otype {
	GPIOADM_GPIO_LIST_CTRL,
	GPIOADM_GPIO_LIST_NAME,
	GPIOADM_GPIO_LIST_ID
} gpioadm_gpio_list_otype_t;

typedef struct gpioadm_gpio_list_ofmt {
	const char *gglo_minor;
	const char *gglo_name;
	uint32_t gglo_id;
	uint32_t gglo_flags;
} gpioadm_gpio_list_ofmt_t;

static boolean_t
gpioadm_gpio_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	gpioadm_gpio_list_ofmt_t *gglo = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case GPIOADM_GPIO_LIST_CTRL:
		if (strlcpy(buf, gglo->gglo_minor, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_GPIO_LIST_NAME:
		if (strlcpy(buf, gglo->gglo_name, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case GPIOADM_GPIO_LIST_ID:
		if (snprintf(buf, buflen, "%u", gglo->gglo_id) >= buflen) {
			return (B_FALSE);
		}
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static const char *gpioadm_gpio_list_fields = "controller,gpio,id";
static const ofmt_field_t gpioadm_gpio_list_ofmt[] = {
	{ "CONTROLLER", 16, GPIOADM_GPIO_LIST_CTRL,
	    gpioadm_gpio_list_ofmt_cb },
	{ "GPIO", 20, GPIOADM_GPIO_LIST_NAME,
	    gpioadm_gpio_list_ofmt_cb },
	{ "ID", 8, GPIOADM_GPIO_LIST_ID,
	    gpioadm_gpio_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

typedef struct {
	bool ggl_err;
	bool ggl_one;
	uint_t ggl_nprint;
	ofmt_handle_t ggl_ofmt;
	int ggl_nfilts;
	char *const *ggl_filts;
	bool *ggl_used;
} gpioadm_gpio_list_t;

static bool
gpioadm_gpio_list_match(const char *ctrl, const char *gpio,
    gpioadm_gpio_list_t *ggl)
{
	if (ggl->ggl_nfilts <= 0) {
		return (true);
	}

	for (int i = 0; i < ggl->ggl_nfilts; i++) {
		const char *filt = ggl->ggl_filts[i];
		const char *slash = strchr(filt, '/');
		bool all_ctrls;
		size_t ctrl_len;

		/*
		 * This is just a controller filter.
		 */
		if (slash == NULL) {
			if (strcmp(ctrl, filt) == 0) {
				ggl->ggl_used[i] = true;
				return (true);
			}
		}

		ctrl_len = (uintptr_t)slash - (uintptr_t)filt;
		if (ctrl_len == 0) {
			return (false);
		}

		all_ctrls = ctrl_len == 1 && filt[0] == '*';
		if (!all_ctrls && (strlen(ctrl) != ctrl_len ||
		    strncmp(ctrl, filt, ctrl_len) != 0)) {
			continue;
		}

		if (strcmp(slash + 1, gpio) == 0) {
			ggl->ggl_used[i] = true;
			return (true);
		}
	}

	return (false);
}

static bool
gpioadm_gpio_list_cb(xpio_t *xpio, xpio_ctrl_disc_t *disc, void *arg)
{
	xpio_ctrl_t *ctrl;
	xpio_ctrl_info_t *info;
	uint32_t ngpios;
	const char *mname = di_minor_name(disc->xcd_minor);
	gpioadm_gpio_list_t *ggl = arg;

	if (!xpio_ctrl_init(xpio, disc->xcd_minor, &ctrl)) {
		gpioadm_warn("failed to initialize controller %s", mname);
		ggl->ggl_err = true;
		return (true);
	}

	if (!xpio_ctrl_info(ctrl, &info)) {
		gpioadm_warn("failed to get controller info for %s", mname);
		xpio_ctrl_fini(ctrl);
		ggl->ggl_err = true;
		return (true);
	}

	ngpios = xpio_ctrl_info_ngpios(info);
	for (uint32_t i = 0; i < ngpios; i++) {
		gpioadm_gpio_list_ofmt_t list;
		xpio_gpio_info_t *gpio_info;
		xpio_gpio_attr_t *attr;

		if (!xpio_gpio_info(ctrl, i, &gpio_info)) {
			ggl->ggl_err = true;
			gpioadm_warn("failed to get gpio info for %s:%u",
			    mname, i);
			continue;
		}

		attr = xpio_gpio_attr_find(gpio_info, KGPIO_ATTR_NAME);
		if (attr == NULL || !xpio_gpio_attr_value_string(attr,
		    &list.gglo_name)) {
			warnx("GPIO %s/%u missing name attribute",
			    mname, i);
			goto skip;
		}
		list.gglo_minor = mname;
		list.gglo_id = i;
		list.gglo_flags = 0;

		if (!gpioadm_gpio_list_match(mname, list.gglo_name, ggl)) {
			goto skip;
		}

		ggl->ggl_nprint++;
		ofmt_print(ggl->ggl_ofmt, &list);

skip:
		xpio_gpio_info_free(gpio_info);
	}

	xpio_ctrl_fini(ctrl);
	return (true);
}

static int
gpioadm_gpio_list(int argc, char *argv[])
{
	int c;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	gpioadm_gpio_list_t ggl;

	(void) memset(&ggl, 0, sizeof (ggl));
	while ((c = getopt(argc, argv, ":Ho:p1")) != -1) {
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
		case '1':
			ggl.ggl_one = true;
			break;
		case ':':
			gpioadm_gpio_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			gpioadm_gpio_list_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (fields == NULL) {
		fields = gpioadm_gpio_list_fields;
	}

	argc -= optind;
	argv += optind;
	if (argc > 0) {
		ggl.ggl_nfilts = argc;
		ggl.ggl_filts = argv;
		ggl.ggl_used = calloc(argc, sizeof (bool));
		if (ggl.ggl_used == NULL) {
			err(EXIT_FAILURE, "failed to allocate memory for "
			    "filter tracking");
		}
	}
	oferr = ofmt_open(fields, gpioadm_gpio_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, gpioadm_ofmt_errx, warnx);

	ggl.ggl_err = false;
	ggl.ggl_ofmt = ofmt;
	xpio_ctrl_discover(gpioadm.gpio_xpio, gpioadm_gpio_list_cb, &ggl);

	for (int i = 0; i < ggl.ggl_nfilts; i++) {
		if (!ggl.ggl_used[i]) {
			warnx("filter '%s' did not match any GPIOs",
			    ggl.ggl_filts[i]);
			ggl.ggl_err = true;
		}
	}

	if (ggl.ggl_one && ggl.ggl_nprint > 1) {
		warnx("-1 specified, but %u GPIOs printed", ggl.ggl_nprint);
		ggl.ggl_err = true;
	}

	if (ggl.ggl_nprint == 0) {
		if (ggl.ggl_nfilts == 0) {
			warnx("no GPIOs found");
		}
		ggl.ggl_err = true;
	}

	return (ggl.ggl_err ? EXIT_FAILURE : EXIT_SUCCESS);
}

static const gpioadm_cmdtab_t gpioadm_cmds_gpio[] = {
	{ "attr", gpioadm_gpio_attr, gpioadm_gpio_attr_usage },
	{ "list", gpioadm_gpio_list, gpioadm_gpio_list_usage },
	{ NULL, NULL, NULL }
};

int
gpioadm_gpio(int argc, char *argv[])
{
	return (gpioadm_walk_tab(gpioadm_cmds_gpio, argc, argv));
}

void
gpioadm_gpio_usage(FILE *f)
{
	gpioadm_walk_usage(gpioadm_cmds_gpio, f);
}
