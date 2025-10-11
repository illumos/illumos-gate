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
 * i2cadm device related operations.
 */

#include <err.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <ofmt.h>

#include "i2cadm.h"

/*
 * Attempt to apply filters. We accept the following filters that are trying to
 * match devices:
 *
 *  - Matching a specific address
 *  - Matching a portion of a device path
 *  - Matching a specific driver or instance
 *  - Matching a node name
 *
 * These filters are shared between both device list and device addrs.
 */
static bool
i2cadm_device_filt(const i2c_dev_info_t *info, int nfilts, char **filts,
    bool *used)
{
	bool match = false;
	char inst[128] = { '\0' }, addr[64] = { '\0' };
	const char *name, *path, *driver;
	size_t pathlen;

	if (nfilts == 0) {
		return (true);
	}

	name = i2c_device_info_name(info);
	path = i2c_device_info_path(info);
	pathlen = strlen(path);
	driver = i2c_device_info_driver(info);
	if (i2c_device_info_instance(info) != -1 && driver != NULL) {
		(void) snprintf(inst, sizeof (inst), "%s%d", driver,
		    i2c_device_info_instance(info));
	}

	const i2c_addr_t *ia = i2c_device_info_addr_primary(info);
	if (!i2c_addr_to_string(i2cadm.i2c_hdl, ia, addr, sizeof (addr))) {
		addr[0] = '\0';
	}

	/*
	 * Note, we have to go through all the filters to see if they match as
	 * someone could have specified something more than once.
	 */
	for (int i = 0; i < nfilts; i++) {
		if (strcmp(filts[i], name) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (addr[0] != '\0' && strcmp(filts[i], addr) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (driver != NULL && strcmp(filts[i], driver) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (inst[0] != '\0' && strcmp(filts[i], inst) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(path, filts[i]) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		size_t len = strlen(filts[i]);
		if (len < pathlen && strncmp(path, filts[i], len) == 0) {
			used[i] = true;
			match = true;
			continue;
		}
	}

	return (match);
}

static int
i2cadm_device_iter(ofmt_handle_t ofmt, int argc, char *argv[], bool *filts,
    void (*func)(ofmt_handle_t, const i2c_dev_info_t *))
{
	int ret = EXIT_SUCCESS;
	bool print = false;
	const i2c_dev_disc_t *disc;
	i2c_dev_iter_t *iter;
	i2c_iter_t iret;

	if (!i2c_device_discover_init(i2cadm.i2c_hdl, &iter)) {
		i2cadm_fatal("failed to initialize device discovery");
	}

	while ((iret = i2c_device_discover_step(iter, &disc)) ==
	    I2C_ITER_VALID) {
		i2c_dev_info_t *info;

		if (!i2c_device_info_snap(i2cadm.i2c_hdl,
		    i2c_device_disc_devi(disc), &info)) {
			i2cadm_warn("failed to get device information for "
			    "%s", i2c_device_disc_path(disc));
			ret = EXIT_FAILURE;
			continue;
		}

		if (!i2cadm_device_filt(info, argc, argv, filts)) {
			i2c_device_info_free(info);
			continue;
		}

		func(ofmt, info);
		i2c_device_info_free(info);
		print = true;
	}

	if (iret == I2C_ITER_ERROR) {
		i2cadm_warn("failed to discover devices");
		ret = EXIT_FAILURE;
	}

	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any devices",
			    argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	if (!print && argc == 0) {
		warnx("no I2C devices found");
		ret = EXIT_FAILURE;
	}

	free(filts);
	ofmt_close(ofmt);
	i2c_device_discover_fini(iter);

	return (ret);
}

static void
i2cadm_device_addrs_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm device addrs [-H] [-o field,[...] [-p]] "
	    "[filter]\n");
}

static void
i2cadm_device_addrs_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm device addrs [-H] "
	    "[-o field[,...] [-p]] [filters]\n\n");
	(void) fprintf(stderr, "List addresses assigned to devices and their "
	    "source. Each <filter> selects\ndevices based upon its address, "
	    "the device's name, the driver's name, the\ndriver's instance, or "
	    "the I2C path. Multiple filters are treated as an OR. It\n is an "
	    "error if a filter isn't used.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported:\n"
	    "\tpath\t\tthe device path\n"
	    "\ttype\t\tthe address's type\n"
	    "\taddr\t\tthe specific address\n"
	    "\tsource\tindicates where the address came from\n");
}

typedef enum {
	I2CADM_DEVICE_ADDRS_PATH,
	I2CADM_DEVICE_ADDRS_TYPE,
	I2CADM_DEVICE_ADDRS_ADDR,
	I2CADM_DEVICE_ADDRS_SOURCE
} i2cadm_device_addrs_otype_t;

typedef struct i2cadm_device_addrs_ofmt {
	const i2c_dev_info_t *idoa_info;
	const i2c_addr_t *idoa_addr;
	i2c_addr_source_t idoa_source;
} i2cadm_device_addrs_ofmt_t;

static boolean_t
i2cadm_device_addrs_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	const i2cadm_device_addrs_ofmt_t *arg = ofarg->ofmt_cbarg;
	size_t len;

	switch (ofarg->ofmt_id) {
	case I2CADM_DEVICE_ADDRS_PATH:
		len = strlcpy(buf, i2c_device_info_path(arg->idoa_info),
		    buflen);
		break;
	case I2CADM_DEVICE_ADDRS_TYPE:
		if (arg->idoa_addr->ia_type == I2C_ADDR_7BIT) {
			len = strlcpy(buf, "7-bit", buflen);
		} else if (arg->idoa_addr->ia_type == I2C_ADDR_10BIT) {
			len = strlcpy(buf, "10-bit", buflen);
		} else {
			len = snprintf(buf, buflen, "unknown (0x%x)",
			    arg->idoa_addr->ia_type);
		}
		break;
	case I2CADM_DEVICE_ADDRS_ADDR:
		len = snprintf(buf, buflen, "0x%02x", arg->idoa_addr->ia_addr);
		break;
	case I2CADM_DEVICE_ADDRS_SOURCE:
		switch (arg->idoa_source) {
		case I2C_ADDR_SOURCE_REG:
			len = strlcpy(buf, "platform", buflen);
			break;
		case I2C_ADDR_SOURCE_CLAIMED:
			len = strlcpy(buf, "claimed", buflen);
			break;
		case I2C_ADDR_SOURCE_SHARED:
			len = strlcpy(buf, "shared", buflen);
			break;
		default:
			len = snprintf(buf, buflen, "unknown (0x%x)",
			    arg->idoa_source);
		}
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const char *i2cadm_device_addrs_fields = "path,type,addr,source";
static const ofmt_field_t i2cadm_device_addrs_ofmt[] = {
	{ "PATH", 40, I2CADM_DEVICE_ADDRS_PATH, i2cadm_device_addrs_ofmt_cb },
	{ "TYPE", 10, I2CADM_DEVICE_ADDRS_TYPE, i2cadm_device_addrs_ofmt_cb },
	{ "ADDR", 10, I2CADM_DEVICE_ADDRS_ADDR, i2cadm_device_addrs_ofmt_cb },
	{ "SOURCE", 16, I2CADM_DEVICE_ADDRS_SOURCE,
	    i2cadm_device_addrs_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static void
i2cadm_device_addrs_cb(ofmt_handle_t ofmt, const i2c_dev_info_t *info)
{
	for (uint32_t i = 0; i < i2c_device_info_naddrs(info); i++) {
		i2cadm_device_addrs_ofmt_t arg;

		arg.idoa_info = info;
		arg.idoa_addr = i2c_device_info_addr(info, i);
		arg.idoa_source = i2c_device_info_addr_source(info, i);
		ofmt_print(ofmt, &arg);
	}
}

static int
i2cadm_device_addrs(int argc, char *argv[])
{
	int c;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	bool *filts = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;

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
			i2cadm_device_addrs_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_device_addrs_help("unknown option: -%c",
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
		fields = i2cadm_device_addrs_fields;
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

	oferr = ofmt_open(fields, i2cadm_device_addrs_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);

	return (i2cadm_device_iter(ofmt, argc, argv, filts,
	    i2cadm_device_addrs_cb));
}

static void
i2cadm_device_list_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm device list [-H] [-o field,[...] [-p]] "
	    "[filter]\n");
}

static void
i2cadm_device_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm device list [-H] "
	    "[-o field[,...] [-p]] [filter...]\n\n");
	(void) fprintf(stderr, "List I2C devices in the system. Each <filter> "
	    "selects devices based upon its\naddress, the device's name, the "
	    "driver's name, the driver's instance, or the\nI2C path. Multiple "
	    "filters are treated as an OR. It is an error if a filter\nisn't "
	    "used.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported:\n"
	    "\tname\t\tthe name of the device\n"
	    "\taddr\t\tthe primary address of the device\n"
	    "\tinstance\tthe driver instance of the device\n"
	    "\tpath\t\tthe I2C path of the device\n");
}

typedef enum {
	I2CADM_DEVICE_LIST_NAME,
	I2CADM_DEVICE_LIST_ADDR,
	I2CADM_DEVICE_LIST_INSTANCE,
	I2CADM_DEVICE_LIST_PATH
} i2cadm_device_list_otype_t;

static boolean_t
i2cadm_device_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	const i2c_dev_info_t *info = ofarg->ofmt_cbarg;
	size_t len;
	const i2c_addr_t *addr;

	switch (ofarg->ofmt_id) {
	case I2CADM_DEVICE_LIST_NAME:
		len = strlcpy(buf, i2c_device_info_name(info), buflen);
		break;
	case I2CADM_DEVICE_LIST_ADDR:
		addr = i2c_device_info_addr_primary(info);
		if (!i2c_addr_to_string(i2cadm.i2c_hdl, addr, buf, buflen)) {
			return (B_FALSE);
		}

		return (B_TRUE);
	case I2CADM_DEVICE_LIST_INSTANCE:
		if (i2c_device_info_driver(info) != NULL &&
		    i2c_device_info_instance(info) != -1) {
			len = snprintf(buf, buflen, "%s%d",
			    i2c_device_info_driver(info),
			    i2c_device_info_instance(info));
		} else {
			len = strlcpy(buf, "--", buflen);
		}
		break;
	case I2CADM_DEVICE_LIST_PATH:
		len = strlcpy(buf, i2c_device_info_path(info), buflen);
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const char *i2cadm_device_list_fields = "name,addr,instance,path";
static const ofmt_field_t i2cadm_device_list_ofmt[] = {
	{ "NAME", 12, I2CADM_DEVICE_LIST_NAME, i2cadm_device_list_ofmt_cb },
	{ "ADDR", 12, I2CADM_DEVICE_LIST_ADDR, i2cadm_device_list_ofmt_cb },
	{ "INSTANCE", 16, I2CADM_DEVICE_LIST_INSTANCE,
	    i2cadm_device_list_ofmt_cb },
	{ "PATH", 40, I2CADM_DEVICE_LIST_PATH, i2cadm_device_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static void
i2cadm_device_list_cb(ofmt_handle_t ofmt, const i2c_dev_info_t *info)
{
	ofmt_print(ofmt, (void *)info);
}

static int
i2cadm_device_list(int argc, char *argv[])
{
	int c;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	bool *filts = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;

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
			i2cadm_device_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_device_list_help("unknown option: -%c",
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
		fields = i2cadm_device_list_fields;
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

	oferr = ofmt_open(fields, i2cadm_device_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);

	return (i2cadm_device_iter(ofmt, argc, argv, filts,
	    i2cadm_device_list_cb));
}

static void
i2cadm_device_add_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm device add [-c compat] port name addr\n");
}

static void
i2cadm_device_add_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm device add [-c comapt] "
	    "port name addr\n\n");
	(void) fprintf(stderr, "Inform the system of a new I2C device with the "
	    "specified address. The device\nwill be inserted under the given "
	    "bus (or multiplexer port if specified). The\naddress must be "
	    "unique on its multiplexor (if applicable) and bus.\n\n"
	    "\t-c compat\tAdd the driver compatible entry to the device. This "
	    "may\n\t\t\tbe specified multiple times. They will be added to "
	    "the\n\t\t\tdevice in the order specified.\n");
}

static int
i2cadm_device_add(int argc, char *argv[])
{
	int c;
	char **compat = NULL;
	size_t ncompat = 0, nalloc = 0;
	i2c_port_t *port;
	i2c_addr_t addr;
	i2c_dev_add_req_t *req;

	while ((c = getopt(argc, argv, ":c")) != -1) {
		switch (c) {
		case 'c':
			if (ncompat == nalloc) {
				nalloc += 8;
				compat = recallocarray(compat, ncompat, nalloc,
				    sizeof (char *));
				if (compat == NULL) {
					err(EXIT_FAILURE, "failed to allocate "
					    "memory for %zu compatible array "
					    "entries", nalloc);
				}
			}
			compat[ncompat] = optarg;
			ncompat++;
			break;
		case ':':
			i2cadm_device_add_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_device_add_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 3) {
		errx(EXIT_USAGE, "encountered extraneous arguments starting "
		    "with %s", argv[3]);
	} else if (argc == 0) {
		errx(EXIT_FAILURE, "missing required port path, device name, "
		    "and device address");
	} else if (argc == 1) {
		errx(EXIT_FAILURE, "missing required device name and device "
		    "address");
	} else if (argc == 2) {
		errx(EXIT_FAILURE, "missing required device address");
	}

	if (!i2c_port_init_by_path(i2cadm.i2c_hdl, argv[0], &port)) {
		i2cadm_fatal("failed to parse port path %s", argv[0]);
	}

	if (!i2c_addr_parse(i2cadm.i2c_hdl, argv[2], &addr)) {
		i2cadm_fatal("failed to parse address %s", argv[2]);
	}

	if (!i2c_device_add_req_init(port, &req)) {
		i2cadm_fatal("failed to initialize device add request");
	}

	if (!i2c_device_add_req_set_addr(req, &addr)) {
		i2cadm_fatal("failed to set device address");
	}

	if (!i2c_device_add_req_set_name(req, argv[1])) {
		i2cadm_fatal("failed to set device name");
	}

	if (ncompat > 0 && !i2c_device_add_req_set_compatible(req, compat,
	    ncompat)) {
		i2cadm_fatal("failed to set device compatible[]");
	}

	if (!i2c_device_add_req_exec(req)) {
		i2cadm_fatal("failed to add device");
	}

	i2c_device_add_req_fini(req);
	i2c_port_fini(port);
	free(compat);
	return (EXIT_SUCCESS);
}

static void
i2cadm_device_remove_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm device remove <path>\n");
}

static void
i2cadm_device_remove_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm device remove <path>\n\n");
	(void) fprintf(stderr, "Remove the I2C device identified by the "
	    "specified path. If the device is in use,\nthis may "
	    "fail.\n");
}

static int
i2cadm_device_remove(int argc, char *argv[])
{
	int c;
	i2c_port_t *port;
	i2c_dev_info_t *info;

	while ((c = getopt(argc, argv, "")) != -1) {
		switch (c) {
		case ':':
			i2cadm_device_remove_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_device_remove_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 1) {
		errx(EXIT_USAGE, "encountered extraneous arguments starting "
		    "with %s", argv[1]);
	} else if (argc == 0) {
		errx(EXIT_FAILURE, "missing required device path");
	}

	if (!i2c_port_dev_init_by_path(i2cadm.i2c_hdl, argv[0], false, &port,
	    &info)) {
		i2cadm_fatal("failed to parse device path %s", argv[0]);
	}

	if (!i2c_device_rem(port, i2c_device_info_addr_primary(info))) {
		i2cadm_fatal("failed to remove device %s", argv[0]);
	}

	i2c_device_info_free(info);
	i2c_port_fini(port);
	return (EXIT_SUCCESS);
}

static i2cadm_cmdtab_t i2cadm_device_cmds[] = {
	{ "list", i2cadm_device_list, i2cadm_device_list_usage },
	{ "addrs", i2cadm_device_addrs, i2cadm_device_addrs_usage },
	{ "add", i2cadm_device_add, i2cadm_device_add_usage },
	{ "remove", i2cadm_device_remove, i2cadm_device_remove_usage }
};

int
i2cadm_device(int argc, char *argv[])
{
	return (i2cadm_walk_tab(i2cadm_device_cmds,
	    ARRAY_SIZE(i2cadm_device_cmds), argc, argv));
}

void
i2cadm_device_usage(FILE *f)
{
	i2cadm_walk_usage(i2cadm_device_cmds, ARRAY_SIZE(i2cadm_device_cmds),
	    f);
}
