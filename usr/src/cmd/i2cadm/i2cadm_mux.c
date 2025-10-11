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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * i2cadm mux related operations.
 */

#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <ofmt.h>

#include "i2cadm.h"

static void
i2cadm_mux_list_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm mux list [-H] [-o field,[...] [-p]] "
	    "[filter]\n");
}

static void
i2cadm_mux_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm mux list [-H] "
	    "[-o field[,...] [-p]] [filter...]\n\n");
	(void) fprintf(stderr, "List multiplexors in the system. Each <filter> "
	    "selects a multiplexor based " "on\nits device's name, device "
	    "driver, or the mux's name. When multiple filters are\nspecified, "
	    "they are treated like an OR. It is an error if a filter isn't "
	    "used.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported:\n"
	    "\tdevice\t\tthe name of the device that powers the mux\n"
	    "\tnports\t\tthe number of ports on the mux\n"
	    "\tname\t\tthe name of the mux\n"
	    "\tinstance\tthe instance of the driver for the mux\n"
	    "\tpath\t\tthe I2C path of the mux\n");
}

typedef enum {
	I2CADM_MUX_LIST_DEVICE,
	I2CADM_MUX_LIST_NAME,
	I2CADM_MUX_LIST_NPORTS,
	I2CADM_MUX_LIST_INSTANCE,
	I2CADM_MUX_LIST_PATH
} i2cadm_mux_list_otype_t;

static boolean_t
i2cadm_mux_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	const i2c_mux_disc_t *disc = ofarg->ofmt_cbarg;
	size_t len;
	di_node_t dn;

	switch (ofarg->ofmt_id) {
	case I2CADM_MUX_LIST_DEVICE:
		dn = di_parent_node(i2c_mux_disc_devi(disc));
		len = snprintf(buf, buflen, "%s", di_node_name(dn));
		break;
	case I2CADM_MUX_LIST_NAME:
		len = strlcpy(buf, i2c_mux_disc_name(disc), buflen);
		break;
	case I2CADM_MUX_LIST_NPORTS:
		len = snprintf(buf, buflen, "%u", i2c_mux_disc_nports(disc));
		break;
	case I2CADM_MUX_LIST_INSTANCE:
		/*
		 * Because a mux exists here, we know our parent instance must
		 * be active and attached.
		 */
		dn = di_parent_node(i2c_mux_disc_devi(disc));
		len = snprintf(buf, buflen, "%s%d", di_driver_name(dn),
		    di_instance(dn));
		break;
	case I2CADM_MUX_LIST_PATH:
		len = strlcpy(buf, i2c_mux_disc_path(disc), buflen);
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const char *i2cadm_mux_list_fields = "device,nports,name,instance,path";
static const ofmt_field_t i2cadm_mux_list_ofmt[] = {
	{ "DEVICE", 12, I2CADM_MUX_LIST_DEVICE, i2cadm_mux_list_ofmt_cb },
	{ "NAME", 12, I2CADM_MUX_LIST_NAME, i2cadm_mux_list_ofmt_cb },
	{ "NPORTS", 12, I2CADM_MUX_LIST_NPORTS, i2cadm_mux_list_ofmt_cb },
	{ "INSTANCE", 16, I2CADM_MUX_LIST_INSTANCE, i2cadm_mux_list_ofmt_cb },
	{ "PATH", 40, I2CADM_MUX_LIST_PATH, i2cadm_mux_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static int
i2cadm_mux_list(int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	bool *filts = NULL, print = false;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	const i2c_mux_disc_t *disc;
	i2c_mux_iter_t *iter;
	i2c_iter_t iret;

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
			i2cadm_mux_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_mux_list_help("unknown option: -%c",
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
		fields = i2cadm_mux_list_fields;
	}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		filts = calloc(argc, sizeof (bool));
		if (filts == NULL) {
			err(EXIT_FAILURE, "failed to allocate memory for "
			    "filter tracking");
		}
	}

	oferr = ofmt_open(fields, i2cadm_mux_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);


	if (!i2c_mux_discover_init(i2cadm.i2c_hdl, &iter)) {
		i2cadm_fatal("failed to in initialize mux walk");
	}

	while ((iret = i2c_mux_discover_step(iter, &disc)) ==
	    I2C_ITER_VALID) {
		if (argc > 0) {
			const char *name = i2c_mux_disc_name(disc);
			di_node_t dn = di_parent_node(i2c_mux_disc_devi(disc));
			const char *drv = di_driver_name(dn);
			const char *pname = di_node_name(dn);
			bool match = false;

			for (int i = 0; i < argc; i++) {
				if (strcmp(argv[i], name) == 0 ||
				    strcmp(argv[i], drv) == 0 ||
				    strcmp(argv[i], pname) == 0) {
					match = true;
					filts[i] = true;
				}
			}

			if (!match) {
				continue;
			}
		}

		ofmt_print(ofmt, (void *)disc);
		print = true;
	}

	if (iret == I2C_ITER_ERROR) {
		i2cadm_warn("failed to iterate muxes");
		ret = EXIT_FAILURE;
	}

	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any muxes", argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	if (!print && argc == 0) {
		warnx("no I2C muxes found");
		ret = EXIT_FAILURE;
	}

	free(filts);
	ofmt_close(ofmt);
	return (ret);
}

static i2cadm_cmdtab_t i2cadm_mux_cmds[] = {
	{ "list", i2cadm_mux_list, i2cadm_mux_list_usage },
};

int
i2cadm_mux(int argc, char *argv[])
{
	return (i2cadm_walk_tab(i2cadm_mux_cmds, ARRAY_SIZE(i2cadm_mux_cmds),
	    argc, argv));
}

void
i2cadm_mux_usage(FILE *f)
{
	i2cadm_walk_usage(i2cadm_mux_cmds, ARRAY_SIZE(i2cadm_mux_cmds), f);
}
