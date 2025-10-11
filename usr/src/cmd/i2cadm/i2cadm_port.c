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
 * i2cadm port related operations.
 */

#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <ofmt.h>
#include <sys/debug.h>

#include "i2cadm.h"

static void
i2cadm_port_map_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm port map [-o field,[...] [-H] [-p]] "
	    "<port>\n");
}

static void
i2cadm_port_map_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm port map [-o field,[...] [-H] "
	    "[-p]] <port>\n");
	(void) fprintf(stderr, "\nPrint port address usage\n\n"
	    "\t-H\t\tomit the column header (requires -o)\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported when "
	    "using -o:\n"
	    "\taddr\t\tthe I2C address\n"
	    "\tcount\t\tthe number of devices using address\n"
	    "\ttype\t\tdescribes how the address is being used\n"
	    "\tmajor\t\tthe major number using a shared address\n"
	    "\tdriver\t\tthe driver name using a shared address\n");
}

typedef enum {
	I2CADM_MAP_TYPE_NONE,
	I2CADM_MAP_TYPE_LOCAL,
	I2CADM_MAP_TYPE_DS,
	I2CADM_MAP_TYPE_SHARED,
	I2CADM_MAP_TYPE_ERROR
} i2cadm_map_type_t;

typedef struct i2cadm_map {
	i2cadm_map_type_t map_type;
	uint32_t map_count;
	major_t map_major;
	char *map_shared;
} i2cadm_map_t;

typedef struct {
	major_t mn_major;
	char *mn_name;
} major_to_name_t;

int
i2cadm_major_to_name_cb(di_node_t node, void *arg)
{
	major_to_name_t *m = arg;
	if (di_driver_major(node) == m->mn_major) {
		const char *name = di_driver_name(node);
		if (name != NULL) {
			m->mn_name = strdup(name);
			if (m->mn_name == NULL) {
				err(EXIT_FAILURE, "failed to allocate memory "
				    "to duplicate driver name for major 0x%x",
				    m->mn_major);
			}
		}
		return (DI_WALK_TERMINATE);
	}
	return (DI_WALK_CONTINUE);
}

/*
 * Major number to name, the kind of max power way. While we could maybe parse
 * /etc/name_to_major, which really should be some set of library routines to be
 * honest, we're instead going to just walk a devinfo snapshot until we we find
 * a node with a matching major. The thing is, the node is present and a driver
 * is attached, otherwise it wouldn't have a shared address.
 */
static char *
i2cadm_major_to_name(major_t m)
{
	major_to_name_t arg = { .mn_major = m };
	di_node_t root = di_init("/", DINFOSUBTREE);
	if (root == DI_NODE_NIL) {
		err(EXIT_FAILURE, "failed to take devinfo snapshot");
	}

	(void) di_walk_node(root, DI_WALK_CLDFIRST, &arg,
	    i2cadm_major_to_name_cb);

	di_fini(root);
	return (arg.mn_name);
}

typedef enum {
	I2CADM_PORT_MAP_ADDR,
	I2CADM_PORT_MAP_COUNT,
	I2CADM_PORT_MAP_TYPE,
	I2CADM_PORT_MAP_MAJOR,
	I2CADM_PORT_MAP_DRIVER
} i2adm_port_map_otype_t;

typedef struct {
	uint16_t ipm_addr;
	const i2cadm_map_t *ipm_map;
} i2cadm_port_map_ofmt_t;

static boolean_t
i2cadm_port_map_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	i2cadm_port_map_ofmt_t *arg = ofarg->ofmt_cbarg;
	size_t len;
	const char *str;

	switch (ofarg->ofmt_id) {
	case I2CADM_PORT_MAP_ADDR:
		len = snprintf(buf, buflen, "%u", arg->ipm_addr);
		break;
	case I2CADM_PORT_MAP_COUNT:
		len = snprintf(buf, buflen, "%u", arg->ipm_map->map_count);
		break;
	case I2CADM_PORT_MAP_TYPE:
		switch (arg->ipm_map->map_type) {
		case I2CADM_MAP_TYPE_NONE:
			str = "none";
			break;
		case I2CADM_MAP_TYPE_LOCAL:
			str = "local";
			break;
		case I2CADM_MAP_TYPE_DS:
			str = "downstream";
			break;
		case I2CADM_MAP_TYPE_SHARED:
			str = "shared";
			break;
		case I2CADM_MAP_TYPE_ERROR:
			str = "error";
			break;
		default:
			abort();
		}
		len = strlcpy(buf, str, buflen);
		break;
	case I2CADM_PORT_MAP_MAJOR:
		if (arg->ipm_map->map_type == I2CADM_MAP_TYPE_SHARED) {
			len = snprintf(buf, buflen, "%u",
			    arg->ipm_map->map_major);
		} else {
			len = strlcpy(buf, "-", buflen);
		}
		break;
	case I2CADM_PORT_MAP_DRIVER:
		if (arg->ipm_map->map_type == I2CADM_MAP_TYPE_SHARED) {
			str = arg->ipm_map->map_shared;
			if (str == NULL)
				str = "unknown";
		} else {
			str = "-";
		}
		len = strlcpy(buf, str, buflen);
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const ofmt_field_t i2cadm_port_map_ofmt[] = {
	{ "ADDR", 8, I2CADM_PORT_MAP_ADDR, i2cadm_port_map_ofmt_cb },
	{ "COUNT", 8, I2CADM_PORT_MAP_COUNT, i2cadm_port_map_ofmt_cb },
	{ "TYPE", 16, I2CADM_PORT_MAP_TYPE, i2cadm_port_map_ofmt_cb },
	{ "MAJOR", 8, I2CADM_PORT_MAP_MAJOR, i2cadm_port_map_ofmt_cb },
	{ "DRIVER", 16, I2CADM_PORT_MAP_DRIVER, i2cadm_port_map_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static const char *key = ""
"\t- = No Device      L = Local Device\n"
"\tS = Shared         v = Downstream\n"
"\t                   E = Error\n";

static bool
i2cadm_port_map_table_cb(void *arg, uint16_t addr)
{
	const i2cadm_map_t *results = arg;
	bool shared = false;

	switch (results[addr].map_type) {
	case I2CADM_MAP_TYPE_NONE:
		(void) printf("%3s", "-");
		break;
	case I2CADM_MAP_TYPE_LOCAL:
		(void) printf("%3s", "L");
		break;
	case I2CADM_MAP_TYPE_DS:
		(void) printf("%2uv", results[addr].map_count);
		break;
	case I2CADM_MAP_TYPE_SHARED:
		shared = true;
		(void) printf("%2uS", results[addr].map_count);
		break;
	case I2CADM_MAP_TYPE_ERROR:
		(void) printf("%3s", "E");
		break;
	}

	return (shared);
}

static void
i2cadm_port_map_table_post(void *arg, uint16_t max_addr)
{
	const i2cadm_map_t *results = arg;
	(void) printf("\nShared Address Owners:\n");

	for (uint16_t i = 0; i < max_addr; i++) {
		if (results[i].map_type != I2CADM_MAP_TYPE_SHARED)
			continue;

		const char *name = results[i].map_shared;
		if (name == NULL)
			name = "unknown";
		if (max_addr > UINT8_MAX) {
			(void) printf("0x%03x: %s (%u)\n", i, name,
			    results[i].map_major);
		} else {
			(void) printf("0x%02x: %s (%u)\n", i, name,
			    results[i].map_major);
		}
	}
}

static int
i2cadm_port_map(int argc, char *argv[])
{
	int c;
	i2c_port_t *port;
	i2c_port_map_t *map;
	uint16_t max_addr = 1 << 7;
	i2cadm_map_t *results;
	boolean_t parse = B_FALSE;
	uint_t flags = 0;
	const char *fields = NULL;
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
			i2cadm_port_map_help("option -%c requires an argument",
			    optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_port_map_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argv += optind;
	argc -= optind;
	if (argc == 0) {
		errx(EXIT_USAGE, "missing required port");
	} else if (argc > 1) {
		errx(EXIT_USAGE, "encountered extraneous arguments starting "
		    "with %s", argv[1]);
	}

	if (!i2c_port_init_by_path(i2cadm.i2c_hdl, argv[0], &port)) {
		i2cadm_fatal("failed to parse port path %s", argv[0]);
	}

	if (!i2c_port_map_snap(port, &map)) {
		i2cadm_fatal("failed to get port map");
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (flags != 0 && fields == NULL) {
		errx(EXIT_USAGE, "-H can only be used with -o");
	}

	if (fields != NULL) {
		if (!parse) {
			flags |= OFMT_WRAP;
		}

		oferr = ofmt_open(fields, i2cadm_port_map_ofmt, flags, 0,
		    &ofmt);
		ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);
	}

	results = calloc(max_addr, sizeof (i2cadm_map_t));
	if (results == NULL) {
		err(EXIT_FAILURE, "failed to allocate port map results "
		    "tracking structure");
	}

	for (uint16_t i = 0; i < max_addr; i++) {
		i2c_addr_t addr = { I2C_ADDR_7BIT, i };
		bool ds;
		uint32_t ndevs;
		major_t major;

		if (!i2c_port_map_addr_info(map, &addr, &ndevs, &ds, &major)) {
			results[i].map_type = I2CADM_MAP_TYPE_ERROR;
			continue;
		}

		if (ndevs == 0) {
			results[i].map_type = I2CADM_MAP_TYPE_NONE;
			continue;
		}

		results[i].map_count = ndevs;
		if (major != DDI_MAJOR_T_NONE) {
			results[i].map_type = I2CADM_MAP_TYPE_SHARED;
			results[i].map_shared = i2cadm_major_to_name(major);
			results[i].map_major = major;
		} else if (ds) {
			results[i].map_type = I2CADM_MAP_TYPE_DS;
		} else {
			VERIFY3U(ndevs, ==, 1);
			results[i].map_type = I2CADM_MAP_TYPE_LOCAL;
		}
	}

	if (fields == NULL) {
		i2cadm_table_t table = {
			.table_port = argv[0],
			.table_key = key,
			.table_msg = "Address map for",
			.table_max = max_addr,
			.table_cb = i2cadm_port_map_table_cb,
			.table_post = i2cadm_port_map_table_post
		};
		i2cadm_print_table(&table, results);
	} else {
		for (uint16_t i = 0; i < max_addr; i++) {
			i2cadm_port_map_ofmt_t arg = {
				.ipm_addr = i,
				.ipm_map = &results[i]
			};
			ofmt_print(ofmt, &arg);
		}
		ofmt_close(ofmt);
	}

	for (uint16_t i = 0; i < max_addr; i++) {
		free(results[i].map_shared);
	}
	free(results);
	i2c_port_map_free(map);
	i2c_port_fini(port);
	return (0);
}

static void
i2cadm_port_list_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm port list [-H] [-o field,[...] [-p]] "
	    "[filter]\n");
}

typedef enum {
	I2CADM_PORT_LIST_PATH,
	I2CADM_PORT_LIST_TYPE,
	I2CADM_PORT_LIST_NAME,
	I2CADM_PORT_LIST_NUM,
	I2CADM_PORT_LIST_NDEVS,
	I2CADM_PORT_LIST_TDEVS
} i2cadm_port_list_otype_tt;

typedef struct i2cadm_port_list_ofmt {
	i2c_port_t *ipl_port;
	i2c_port_map_t *ipl_map;
} i2cadm_port_list_ofmt_t;

static void
i2cadm_port_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm port list [-H] "
	    "[-o field[,...] [-p]] [filter...]\n\n");
	(void) fprintf(stderr, "List I2C ports in the system. Each <filter> "
	    "selects ports based upon its\ntype, name, or the I2C path. "
	    "Multiple filters are treated as an OR. It is an\nerror if a "
	    "filter isn't used.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported:\n"
	    "\tpath\t\tthe I2C path of the port\n"
	    "\ttype\t\tthe type of I2C port: controller or multiplexor\n"
	    "\tname\t\tthe port's name\n"
	    "\tportno\t\tthe system's port number (zero based)\n"
	    "\tndevs\t\tthe number of device's directly attached to this port\n"
	    "\ttdevs\t\tthe total number of devices under this port\n");
}

static boolean_t
i2cadm_port_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	uint32_t local, ds;
	i2cadm_port_list_ofmt_t *arg = ofarg->ofmt_cbarg;
	size_t len;

	switch (ofarg->ofmt_id) {
	case I2CADM_PORT_LIST_PATH:
		len = strlcpy(buf, i2c_port_path(arg->ipl_port), buflen);
		break;
	case I2CADM_PORT_LIST_TYPE:
		switch (i2c_port_type(arg->ipl_port)) {
		case I2C_PORT_TYPE_CTRL:
			len = strlcat(buf, "controller", buflen);
			break;
		case I2C_PORT_TYPE_MUX:
			len = strlcat(buf, "multiplexor", buflen);
			break;
		default:
			len = snprintf(buf, buflen, "unknown: 0x%x",
			    i2c_port_type(arg->ipl_port));
			break;
		}
		break;
	case I2CADM_PORT_LIST_NAME:
		len = strlcpy(buf, i2c_port_name(arg->ipl_port), buflen);
		break;
	case I2CADM_PORT_LIST_NUM:
		len = snprintf(buf, buflen, "%u",
		    i2c_port_portno(arg->ipl_port));
		break;
	case I2CADM_PORT_LIST_NDEVS:
		i2c_port_map_ndevs(arg->ipl_map, &local, NULL);
		len = snprintf(buf, buflen, "%u", local);
		break;
	case I2CADM_PORT_LIST_TDEVS:
		i2c_port_map_ndevs(arg->ipl_map, &local, &ds);
		len = snprintf(buf, buflen, "%u", local + ds);
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const char *i2cadm_port_list_fields = "path,type,portno,ndevs,tdevs";
static const ofmt_field_t i2cadm_port_list_ofmt[] = {
	{ "NAME", 12, I2CADM_PORT_LIST_NAME, i2cadm_port_list_ofmt_cb },
	{ "TYPE", 14, I2CADM_PORT_LIST_TYPE, i2cadm_port_list_ofmt_cb },
	{ "PORTNO", 8, I2CADM_PORT_LIST_NUM, i2cadm_port_list_ofmt_cb },
	{ "NDEVS", 8, I2CADM_PORT_LIST_NDEVS, i2cadm_port_list_ofmt_cb },
	{ "TDEVS", 8, I2CADM_PORT_LIST_TDEVS, i2cadm_port_list_ofmt_cb },
	{ "PATH", 32, I2CADM_PORT_LIST_PATH, i2cadm_port_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

/*
 * We accept the following filters for matching ports:
 *
 *  - Matching on the ports name
 *  - Matching on the port's type
 *  - Matching on a portion of the port's path
 */
static bool
i2cadm_port_list_filt(const i2cadm_port_list_ofmt_t *arg, int nfilts,
    char **filts, bool *used)
{
	bool match = false;
	const char *type, *name, *path;

	if (nfilts == 0) {
		return (true);
	}

	name = i2c_port_name(arg->ipl_port);
	path = i2c_port_path(arg->ipl_port);
	size_t pathlen = strlen(path);
	if (i2c_port_type(arg->ipl_port) == I2C_PORT_TYPE_CTRL) {
		type = "controller";
	} else {
		type = "multiplexor";
	}

	for (int i = 0; i < nfilts; i++) {
		if (strcmp(filts[i], name) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(filts[i], type) == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(filts[i], path) == 0) {
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
i2cadm_port_list(int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	bool *filts = NULL, print = false;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	i2c_port_iter_t *iter;
	i2c_iter_t iret;
	const i2c_port_disc_t *disc;

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
			i2cadm_port_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_port_list_help("unknown option: -%c",
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
		fields = i2cadm_port_list_fields;
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

	oferr = ofmt_open(fields, i2cadm_port_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);


	if (!i2c_port_discover_init(i2cadm.i2c_hdl, &iter)) {
		i2cadm_fatal("failed to in initialize port discovery");
	}

	while ((iret = i2c_port_discover_step(iter, &disc)) == I2C_ITER_VALID) {
		i2cadm_port_list_ofmt_t arg;

		if (!i2c_port_init(i2cadm.i2c_hdl, i2c_port_disc_devi(disc),
		    &arg.ipl_port)) {
			i2cadm_warn("failed to initialize port %s",
			    i2c_port_disc_path(disc));
			continue;
		}

		if (!i2c_port_map_snap(arg.ipl_port, &arg.ipl_map)) {
			i2cadm_warn("failed to get port map for %s",
			    i2c_port_disc_path(disc));
			i2c_port_fini(arg.ipl_port);
			continue;
		}

		if (i2cadm_port_list_filt(&arg, argc, argv, filts)) {
			ofmt_print(ofmt, &arg);
			print = true;
		}

		i2c_port_map_free(arg.ipl_map);
		i2c_port_fini(arg.ipl_port);
	}

	if (iret == I2C_ITER_ERROR) {
		i2cadm_warn("failed to discover ports");
		ret = EXIT_FAILURE;
	}

	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any ports",
			    argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	if (!print && argc == 0) {
		warnx("no I2C ports found");
		ret = EXIT_FAILURE;
	}

	i2c_port_discover_fini(iter);
	return (ret);
}

static i2cadm_cmdtab_t i2cadm_port_cmds[] = {
	{ "list", i2cadm_port_list, i2cadm_port_list_usage },
	{ "map", i2cadm_port_map, i2cadm_port_map_usage },
};

int
i2cadm_port(int argc, char *argv[])
{
	return (i2cadm_walk_tab(i2cadm_port_cmds, ARRAY_SIZE(i2cadm_port_cmds),
	    argc, argv));
}

void
i2cadm_port_usage(FILE *f)
{
	i2cadm_walk_usage(i2cadm_port_cmds, ARRAY_SIZE(i2cadm_port_cmds), f);
}
