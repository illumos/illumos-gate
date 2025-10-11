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
 * i2cadm controller related operations.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <ofmt.h>
#include <sys/ilstr.h>
#include <sys/debug.h>

#include "i2cadm.h"

/*
 * Various property conversion routines. These could also potentially be in
 * libi2c if we find it useful for other consumers.
 */
typedef struct op_map {
	uint32_t om_op;
	const char *om_name;
} op_map_t;

static const op_map_t speed_op_map[] = {
	{ I2C_SPEED_STD, "standard" },
	{ I2C_SPEED_FAST, "fast" },
	{ I2C_SPEED_FPLUS, "fast-plus" },
	{ I2C_SPEED_HIGH, "high" },
	{ I2C_SPEED_ULTRA, "ultra" }
};

static const op_map_t type_op_map[] = {
	{ I2C_CTRL_TYPE_I2C, "i2c" },
	{ I2C_CTRL_TYPE_I3C, "i3c" },
	{ I2C_CTRL_TYPE_SMBUS, "smbus" }
};

static const op_map_t smbus_op_map[] = {
	{ SMBUS_PROP_OP_QUICK_COMMAND, "quick" },
	{ SMBUS_PROP_OP_SEND_BYTE, "send-byte", },
	{ SMBUS_PROP_OP_RECV_BYTE, "recv-byte" },
	{ SMBUS_PROP_OP_WRITE_BYTE, "write-byte" },
	{ SMBUS_PROP_OP_READ_BYTE, "read-byte" },
	{ SMBUS_PROP_OP_WRITE_WORD, "write-word" },
	{ SMBUS_PROP_OP_READ_WORD, "read-word" },
	{ SMBUS_PROP_OP_PROCESS_CALL, "process-call" },
	{ SMBUS_PROP_OP_WRITE_BLOCK, "write-block" },
	{ SMBUS_PROP_OP_READ_BLOCK, "read-block" },
	{ SMBUS_PROP_OP_HOST_NOTIFY, "host-notify" },
	{ SMBUS_PROP_OP_BLOCK_PROCESS_CALL, "block-call" },
	{ SMBUS_PROP_OP_WRITE_U32, "write-u32" },
	{ SMBUS_PROP_OP_READ_U32, "read-u32" },
	{ SMBUS_PROP_OP_WRITE_U64, "write-u64" },
	{ SMBUS_PROP_OP_READ_U64, "read-u64" },
	{ SMBUS_PROP_OP_I2C_WRITE_BLOCK, "write-i2c-block" },
	{ SMBUS_PROP_OP_I2C_READ_BLOCK, "read-i2c-block" }
};

static boolean_t
i2cadm_map_to_str_one(uint32_t val, char *buf, uint_t buflen,
    const op_map_t *map, size_t nents)
{
	if (val == 0) {
		return (strlcpy(buf, "--", buflen) < buflen);
	}

	for (size_t i = 0; i < nents; i++) {
		if (map[i].om_op == val) {
			return (strlcpy(buf, map[i].om_name, buflen) < buflen);
		}
	}

	return (B_FALSE);
}

static boolean_t
i2cadm_map_to_str(uint32_t val, char *buf, uint_t buflen, const op_map_t *map,
    size_t nents)
{
	ilstr_t ilstr;

	if (val == 0) {
		return (strlcpy(buf, "--", buflen) < buflen);
	}

	ilstr_init_prealloc(&ilstr, buf, buflen);

	for (size_t i = 0; i < nents; i++) {
		if ((val & map[i].om_op) == 0)
			continue;

		val &= ~map[i].om_op;
		if (i > 0) {
			ilstr_append_char(&ilstr, ',');
		}
		ilstr_append_str(&ilstr, map[i].om_name);
	}

	if (val != 0) {
		char str[32];
		(void) snprintf(str, sizeof (str), ",0x%x", val);

		if (ilstr_len(&ilstr) > 0) {
			ilstr_append_char(&ilstr, ',');
		}
		ilstr_append_str(&ilstr, str);
	}

	ilstr_errno_t err = ilstr_errno(&ilstr);
	ilstr_fini(&ilstr);
	return (err == ILSTR_ERROR_OK);
}

static boolean_t
i2cadm_value_print(i2c_prop_info_t *info, uint32_t val, char *buf,
    uint_t buflen)
{
	uint_t len;

	switch (i2c_prop_info_id(info)) {
	case I2C_PROP_BUS_SPEED:
		return (i2cadm_map_to_str_one(val, buf, buflen, speed_op_map,
		    ARRAY_SIZE(speed_op_map)));
	case I2C_PROP_TYPE:
		return (i2cadm_map_to_str_one(val, buf, buflen, type_op_map,
		    ARRAY_SIZE(type_op_map)));
	case SMBUS_PROP_SUP_OPS:
		return (i2cadm_map_to_str(val, buf, buflen, smbus_op_map,
		    ARRAY_SIZE(smbus_op_map)));
	default:
		len = snprintf(buf, buflen, "%u", val);
	}

	return (len < buflen);
}

static boolean_t
i2cadm_value_print_pos_u32(const i2c_prop_range_t *range, char *buf,
    uint_t buflen)
{
	ilstr_t ilstr;

	ilstr_init_prealloc(&ilstr, buf, buflen);
	for (uint32_t i = 0; i < range->ipr_count; i++) {
		const i2c_prop_u32_range_t *r;
		char str[64];

		r = &range->ipr_range[i].ipvr_u32;
		if (r->ipur_min == r->ipur_max) {
			(void) snprintf(str, sizeof (str), "u", r->ipur_min);
		} else {
			(void) snprintf(str, sizeof (str), "%u-%u", r->ipur_min,
			    r->ipur_max);
		}
		if (i > 0) {
			ilstr_append_char(&ilstr, ',');
		}
		ilstr_append_str(&ilstr, str);
	}

	ilstr_errno_t err = ilstr_errno(&ilstr);
	ilstr_fini(&ilstr);
	return (err == ILSTR_ERROR_OK);
}

static boolean_t
i2cadm_value_print_pos_bit32(i2c_prop_info_t *info,
    const i2c_prop_range_t *range, char *buf, uint_t buflen)
{
	if (range->ipr_count != 1) {
		return (B_FALSE);
	}

	uint32_t val = range->ipr_range[0].ipvr_bit32;
	switch (i2c_prop_info_id(info)) {
	case I2C_PROP_BUS_SPEED:
		return (i2cadm_map_to_str(val, buf, buflen, speed_op_map,
		    ARRAY_SIZE(speed_op_map)));
	case SMBUS_PROP_SUP_OPS:
		return (i2cadm_map_to_str(val, buf, buflen, smbus_op_map,
		    ARRAY_SIZE(smbus_op_map)));
	default:
		return (snprintf(buf, buflen, "0x%x", val) < buflen);
	}
}

static boolean_t
i2cadm_value_print_pos(i2c_prop_info_t *info, char *buf, uint_t buflen)
{
	uint_t len;
	const i2c_prop_range_t *range = i2c_prop_info_pos(info);

	if (range == NULL) {
		if (i2c_err(i2cadm.i2c_hdl) == I2C_ERR_PROP_UNSUP) {
			return (strlcpy(buf, "--", buflen) < buflen);
		}
		return (B_FALSE);
	}

	if (range->ipr_count == 0) {
		return (strlcpy(buf, "--", buflen) < buflen);
	}

	switch (range->ipr_type) {
	case I2C_PROP_TYPE_U32:
		return (i2cadm_value_print_pos_u32(range, buf, buflen));
	case I2C_PROP_TYPE_BIT32:
		return (i2cadm_value_print_pos_bit32(info, range, buf, buflen));
	default:
		return (B_FALSE);
	}

	return (len <= buflen);
}

static void
i2cadm_controller_prop_get_usage(FILE *f)
{
	(void) fprintf(stderr, "\ti2cadm controller prop get [-Hp] "
	    "[-o field[,...] <controller> [filter]\n");
}

static void
i2cadm_controller_prop_get_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm controller prop get [-H] "
	    "[-o field[,...] [-p]] <controller> [filter...]\n\n");
	(void) fprintf(stderr, "List properties on the specified controller. "
	    "Each <filter> selects a property\nbased on its name. When "
	    "multiple filters are specified, they are treated like\nan OR. It "
	    "is an error if a filter isn't used.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported:\n"
	    "\tproperty\tthe name of the property\n"
	    "\tperm\t\tthe property's permissions\n"
	    "\tvalue\t\tthe property's value\n"
	    "\tdefault\t\tthe property's default value\n"
	    "\tpossible\tthe property's possible values\n"
	    "\ttype\t\tthe property's type\n"
	    "\tctrl\t\tthe name of the controller\n"
	    "\tid\t\tthe system id for the property\n");
}

typedef enum {
	I2CADM_CTRL_PROP_GET_PROP,
	I2CADM_CTRL_PROP_GET_PERM,
	I2CADM_CTRL_PROP_GET_VALUE,
	I2CADM_CTRL_PROP_GET_DEF,
	I2CADM_CTRL_PROP_GET_POS,
	I2CADM_CTRL_PROP_GET_TYPE,
	I2CADM_CTRL_PROP_GET_CTRL,
	I2CADM_CTRL_PROP_GET_ID
} i2cadm_ctrl_prop_get_otype_t;

typedef struct i2cadm_ctrl_prop_get_ofmt {
	const char *icpg_ctrl;
	i2c_prop_info_t *icpg_info;
	bool icpg_valid;
	uint32_t icpg_u32;
} i2cadm_ctrl_prop_get_ofmt_t;

static boolean_t
i2cadm_ctrl_prop_get_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	i2cadm_ctrl_prop_get_ofmt_t *arg = ofarg->ofmt_cbarg;
	size_t len;
	uint32_t def;

	switch (ofarg->ofmt_id) {
	case I2CADM_CTRL_PROP_GET_PROP:
		len = strlcpy(buf, i2c_prop_info_name(arg->icpg_info), buflen);
		break;
	case I2CADM_CTRL_PROP_GET_PERM:
		switch (i2c_prop_info_perm(arg->icpg_info)) {
		case I2C_PROP_PERM_RO:
			len = strlcpy(buf, "r-", buflen);
			break;
		case I2C_PROP_PERM_RW:
			len = strlcpy(buf, "rw", buflen);
			break;
		default:
			return (B_FALSE);
		}
		break;
	case I2CADM_CTRL_PROP_GET_VALUE:
		if (!arg->icpg_valid) {
			len = strlcpy(buf, "--", buflen);
			break;
		}

		return (i2cadm_value_print(arg->icpg_info, arg->icpg_u32, buf,
		    buflen));
	case I2CADM_CTRL_PROP_GET_DEF:
		if (!i2c_prop_info_def_u32(arg->icpg_info, &def)) {
			len = strlcpy(buf, "--", buflen);
			break;
		}

		return (i2cadm_value_print(arg->icpg_info, def, buf, buflen));
	case I2CADM_CTRL_PROP_GET_POS:
		return (i2cadm_value_print_pos(arg->icpg_info, buf, buflen));
	case I2CADM_CTRL_PROP_GET_TYPE:
		switch (i2c_prop_info_type(arg->icpg_info)) {
		case I2C_PROP_TYPE_U32:
			len = strlcpy(buf, "u32", buflen);
			break;
		case I2C_PROP_TYPE_BIT32:
			len = strlcpy(buf, "bit32", buflen);
			break;
		default:
			return (B_FALSE);
		}
		break;
	case I2CADM_CTRL_PROP_GET_CTRL:
		len = strlcpy(buf, arg->icpg_ctrl, buflen);
		break;
	case I2CADM_CTRL_PROP_GET_ID:
		len = snprintf(buf, buflen, "%u",
		    i2c_prop_info_id(arg->icpg_info));
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const char *i2cadm_ctrl_prop_get_fields =
	"property,perm,value,default,possible";
static const ofmt_field_t i2cadm_ctrl_prop_get_ofmt[] = {
	{ "PROPERTY", 20, I2CADM_CTRL_PROP_GET_PROP,
	    i2cadm_ctrl_prop_get_ofmt_cb },
	{ "PERM", 6, I2CADM_CTRL_PROP_GET_PERM, i2cadm_ctrl_prop_get_ofmt_cb },
	{ "VALUE", 16, I2CADM_CTRL_PROP_GET_VALUE,
	    i2cadm_ctrl_prop_get_ofmt_cb },
	{ "DEFAULT", 16, I2CADM_CTRL_PROP_GET_DEF,
	    i2cadm_ctrl_prop_get_ofmt_cb },
	{ "POSSIBLE", 16, I2CADM_CTRL_PROP_GET_POS,
	    i2cadm_ctrl_prop_get_ofmt_cb },
	{ "TYPE", 6, I2CADM_CTRL_PROP_GET_TYPE, i2cadm_ctrl_prop_get_ofmt_cb },
	{ "CONTROLLER", 12, I2CADM_CTRL_PROP_GET_CTRL,
	    i2cadm_ctrl_prop_get_ofmt_cb },
	{ "ID", 8, I2CADM_CTRL_PROP_GET_ID, i2cadm_ctrl_prop_get_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static int
i2cadm_controller_prop_get(int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL, *cname;
	i2c_ctrl_t *ctrl;
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
			i2cadm_controller_prop_get_help("option -%c requires "
			    "an argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_controller_prop_get_help("unknown option: -%c",
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
		fields = i2cadm_ctrl_prop_get_fields;
	}

	argc -= optind;
	argv += optind;
	if (argc == 0) {
		errx(EXIT_FAILURE, "missing required controller");
	}

	cname = argv[0];
	argc--;
	argv++;
	if (!i2c_ctrl_init_by_path(i2cadm.i2c_hdl, cname, &ctrl)) {
		i2cadm_fatal("failed to initialize controller %s", cname);
	}

	if (argc > 0) {
		filts = calloc(argc, sizeof (bool));
		if (filts == NULL) {
			err(EXIT_FAILURE, "failed to allocate memory for "
			    "filter tracking");
		}
	}

	oferr = ofmt_open(fields, i2cadm_ctrl_prop_get_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);

	uint32_t nprops = i2c_ctrl_nprops(ctrl);
	for (uint32_t i = 0; i < nprops; i++) {
		i2c_prop_info_t *info;
		i2cadm_ctrl_prop_get_ofmt_t arg;

		if (!i2c_prop_info(ctrl, i, &info)) {
			i2cadm_warn("failed to get property %u information", i);
			ret = EXIT_FAILURE;
			continue;
		}

		if (argc > 0) {
			const char *name = i2c_prop_info_name(info);
			bool match = false;

			for (int i = 0; i < argc; i++) {
				if (strcmp(argv[i], name) == 0) {
					match = true;
					filts[i] = true;
				}
			}

			if (!match) {
				i2c_prop_info_free(info);
				continue;
			}
		}

		(void) memset(&arg, 0, sizeof (arg));
		arg.icpg_ctrl = cname;
		arg.icpg_info = info;

		if (i2c_prop_info_sup(info)) {
			i2c_prop_type_t type = i2c_prop_info_type(info);
			if (type == I2C_PROP_TYPE_U32 ||
			    type == I2C_PROP_TYPE_BIT32) {
				size_t len = sizeof (uint32_t);
				if (!i2c_prop_get(ctrl, i, &arg.icpg_u32,
				    &len)) {
					i2cadm_warn("failed to get property "
					    "%s (%u)", i2c_prop_info_name(info),
					    i);
					ret = EXIT_FAILURE;
				} else if (len != sizeof (uint32_t)) {
					warnx("property %s (%u) returned "
					    "unexpected property size of %zu, "
					    "but %zu was expected, unable to "
					    "print value",
					    i2c_prop_info_name(info), i, len,
					    sizeof (uint32_t));
					ret = EXIT_FAILURE;
				} else {
					arg.icpg_valid = true;
				}
			} else {
				warnx("property %s (%u) has unknown type 0x%x, "
				    "cannot get or display value",
				    i2c_prop_info_name(info), i, type);
				ret = EXIT_FAILURE;
			}
		}

		ofmt_print(ofmt, &arg);
		free(info);
	}

	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any properties",
			    argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	free(filts);
	ofmt_close(ofmt);
	i2c_ctrl_fini(ctrl);
	return (ret);
}

static void
i2cadm_controller_prop_set_usage(FILE *f)
{
	(void) fprintf(stderr, "\ti2cadm controller prop set <controller> "
	    "<property>=<value>\n");
}

static int
i2cadm_controller_prop_set(int argc, char *argv[])
{
	i2c_ctrl_t *ctrl;
	i2c_prop_info_t *info;
	char *prop, *val;
	size_t buflen = 0;
	void *buf = NULL;

	if (argc == 0) {
		errx(EXIT_FAILURE, "missing required controller and property");
	} else if (argc == 1) {
		errx(EXIT_FAILURE, "missing required property");
	} else if (argc > 2) {
		errx(EXIT_FAILURE, "only one property can be set at a time, "
		    "extraneous arguments start with %s", argv[2]);
	}

	if (!i2c_ctrl_init_by_path(i2cadm.i2c_hdl, argv[0], &ctrl)) {
		i2cadm_fatal("failed to initialize controller %s", argv[0]);
	}

	prop = argv[1];
	val = strchr(prop, '=');
	if (val == NULL) {
		errx(EXIT_FAILURE, "could not parse property name and value "
		    "from %s: missing = separator", argv[1]);
	}
	*val = '\0';
	val++;

	if (!i2c_prop_info_by_name(ctrl, prop, &info)) {
		i2cadm_fatal("failed to get information for property %s", prop);
	}

	if (!i2c_prop_info_sup(info)) {
		errx(EXIT_FAILURE, "controller %s does not support property %s",
		    argv[0], prop);
	}

	if (i2c_prop_info_perm(info) != I2C_PROP_PERM_RW) {
		errx(EXIT_FAILURE, "property %s is read-only on controller %s",
		    prop, argv[0]);
	}

	/*
	 * See if this property is one that we parse via string transformations.
	 */
	switch (i2c_prop_info_id(info)) {
	case I2C_PROP_BUS_SPEED:
		for (size_t i = 0; i < ARRAY_SIZE(speed_op_map); i++) {
			if (strcmp(val, speed_op_map[i].om_name) == 0) {
				buflen = sizeof (uint32_t);
				buf = calloc(1, buflen);
				if (buf == NULL) {
					errx(EXIT_FAILURE, "failed to allocate "
					    "%zu bytes of memory to hold %s "
					    "property value", buflen, prop);
				}

				(void) memcpy(buf, &speed_op_map[i].om_op,
				    sizeof (uint32_t));
			}
		}
		break;
	default:
		break;
	}

	if (buf == NULL) {
		uint32_t u32;
		const char *errstr;

		switch (i2c_prop_info_type(info)) {
		case I2C_PROP_TYPE_U32:
		case I2C_PROP_TYPE_BIT32:
			u32 = (uint32_t)strtonumx(val, 0, UINT32_MAX, &errstr,
			    0);
			if (errstr != NULL) {
				errx(EXIT_FAILURE, "invalid 32-bit %s property "
				    "values: %s is %s", prop, val, errstr);
			}

			buflen = sizeof (uint32_t);
			buf = calloc(1, buflen);
			if (buf == NULL) {
				errx(EXIT_FAILURE, "failed to allocate %zu "
				    "bytes of memory to hold %s property value",
				    buflen, prop);
			}

			(void) memcpy(buf, &u32, sizeof (uint32_t));
			break;
		default:
			errx(EXIT_FAILURE, "unable to parse property %s type "
			    "0x%x", prop, i2c_prop_info_type(info));

		}
	}

	if (!i2c_prop_set(ctrl, i2c_prop_info_id(info), buf, buflen)) {
		i2cadm_fatal("failed to set property %s to %s", prop, val);
	}

	i2c_prop_info_free(info);
	i2c_ctrl_fini(ctrl);
	return (EXIT_SUCCESS);
}

static i2cadm_cmdtab_t i2cadm_ctrl_prop_cmds[] = {
	{ "get", i2cadm_controller_prop_get, i2cadm_controller_prop_get_usage },
	{ "set", i2cadm_controller_prop_set, i2cadm_controller_prop_set_usage }
};

static int
i2cadm_controller_prop(int argc, char *argv[])
{
	return (i2cadm_walk_tab(i2cadm_ctrl_prop_cmds,
	    ARRAY_SIZE(i2cadm_ctrl_prop_cmds), argc, argv));
}

static void
i2cadm_controller_prop_usage(FILE *f)
{
	i2cadm_walk_usage(i2cadm_ctrl_prop_cmds,
	    ARRAY_SIZE(i2cadm_ctrl_prop_cmds), f);
}

static void
i2cadm_controller_list_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm controller list [-H] [-o field,[...] [-p]] "
	    "[filter]\n");
}

static void
i2cadm_controller_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm controller list [-H] "
	    "[-o field[,...] [-p]] [filter...]\n\n");
	(void) fprintf(stderr, "List I2C Controllers. Each <filter> selects a "
	    "set of controllers to show and\ncan be a controller or driver "
	    "name. When multiple filters are specified, they\nare treated like "
	    "an OR. It is an error if a filter isn't used.\n\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported:\n"
	    "\tname\t\tthe controller's name\n"
	    "\ttype\t\tthe controller's type (e.g. i2c, smbus)\n"
	    "\tspeed\t\tthe controller's current speed\n"
	    "\tdriver\t\tthe name of the driver for the controller\n"
	    "\tinstance\tthe driver instance for the controller\n"
	    "\tprovider\tthe /devices path of the provider\n");
}

typedef enum {
	I2CADM_CTRL_LIST_NAME,
	I2CADM_CTRL_LIST_TYPE,
	I2CADM_CTRL_LIST_SPEED,
	I2CADM_CTRL_LIST_NPORTS,
	I2CADM_CTRL_LIST_DRIVER,
	I2CADM_CTRL_LIST_INSTANCE,
	I2CADM_CTRL_LIST_PROVIDER
} i2cadm_ctrl_list_otype_t;

typedef struct i2cadm_ctrl_list_ofmt {
	di_node_t icl_nexus;
	di_node_t icl_drv;
	i2c_ctrl_t *icl_ctrl;
	uint32_t icl_speed;
	uint32_t icl_type;
	uint32_t icl_nports;
} i2cadm_ctrl_list_ofmt_t;

static boolean_t
i2cadm_ctrl_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	i2cadm_ctrl_list_ofmt_t *arg = ofarg->ofmt_cbarg;
	size_t len;

	switch (ofarg->ofmt_id) {
	case I2CADM_CTRL_LIST_NAME:
		len = strlcat(buf, di_bus_addr(arg->icl_nexus), buflen);
		break;
	case I2CADM_CTRL_LIST_TYPE:
		return (i2cadm_map_to_str_one(arg->icl_type, buf, buflen,
		    type_op_map, ARRAY_SIZE(type_op_map)));
	case I2CADM_CTRL_LIST_SPEED:
		return (i2cadm_map_to_str_one(arg->icl_speed, buf, buflen,
		    speed_op_map, ARRAY_SIZE(speed_op_map)));
	case I2CADM_CTRL_LIST_NPORTS:
		len = snprintf(buf, buflen, "%u", arg->icl_nports);
		break;
	case I2CADM_CTRL_LIST_DRIVER:
		len = strlcat(buf, di_driver_name(arg->icl_drv), buflen);
		break;
	case I2CADM_CTRL_LIST_INSTANCE:
		len = snprintf(buf, buflen, "%s%d",
		    di_driver_name(arg->icl_drv), di_instance(arg->icl_drv));
		break;
	case I2CADM_CTRL_LIST_PROVIDER:
		len = strlcat(buf, i2c_ctrl_path(arg->icl_ctrl), buflen);
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const char *i2cadm_ctrl_list_fields = "name,type,speed,nports,provider";
static const ofmt_field_t i2cadm_ctrl_list_ofmt[] = {
	{ "NAME", 12, I2CADM_CTRL_LIST_NAME, i2cadm_ctrl_list_ofmt_cb },
	{ "TYPE", 10, I2CADM_CTRL_LIST_TYPE, i2cadm_ctrl_list_ofmt_cb },
	{ "SPEED", 12, I2CADM_CTRL_LIST_SPEED, i2cadm_ctrl_list_ofmt_cb },
	{ "NPORTS", 8, I2CADM_CTRL_LIST_NPORTS, i2cadm_ctrl_list_ofmt_cb },
	{ "DRIVER", 10, I2CADM_CTRL_LIST_DRIVER, i2cadm_ctrl_list_ofmt_cb },
	{ "INSTANCE", 16, I2CADM_CTRL_LIST_INSTANCE, i2cadm_ctrl_list_ofmt_cb },
	{ "PROVIDER", 40, I2CADM_CTRL_LIST_PROVIDER, i2cadm_ctrl_list_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static int
i2cadm_controller_list(int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	uint_t flags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	bool *filts = NULL, print = false;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	i2c_ctrl_iter_t *iter;
	i2c_iter_t iret;
	const i2c_ctrl_disc_t *disc;

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
			i2cadm_controller_list_help("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_controller_list_help("unknown option: -%c",
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
		fields = i2cadm_ctrl_list_fields;
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

	oferr = ofmt_open(fields, i2cadm_ctrl_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);

	if (!i2c_ctrl_discover_init(i2cadm.i2c_hdl, &iter)) {
		i2cadm_fatal("failed to initialize controller walk");
	}

	while ((iret = i2c_ctrl_discover_step(iter, &disc)) == I2C_ITER_VALID) {
		i2cadm_ctrl_list_ofmt_t arg;
		i2c_ctrl_t *ctrl;

		(void) memset(&arg, 0, sizeof (arg));
		arg.icl_nexus = i2c_ctrl_disc_devi(disc);
		arg.icl_drv = di_parent_node(arg.icl_nexus);

		if (argc > 0) {
			const char *name = di_bus_addr(arg.icl_nexus);
			const char *drv = di_driver_name(arg.icl_drv);
			bool match = false;

			for (int i = 0; i < argc; i++) {
				if (strcmp(argv[i], name) == 0 ||
				    strcmp(argv[i], drv) == 0) {
					match = true;
					filts[i] = true;
				}
			}

			if (!match) {
				continue;
			}
		}

		if (!i2c_ctrl_init(i2cadm.i2c_hdl, arg.icl_nexus, &ctrl)) {
			i2cadm_warn("failed to initialize controller %s",
			    di_bus_addr(arg.icl_nexus));
			continue;
		}

		size_t len = sizeof (uint32_t);
		if (!i2c_prop_get(ctrl, I2C_PROP_BUS_SPEED, &arg.icl_speed,
		    &len)) {
			i2cadm_warn("failed to get controller %s speed",
			    di_bus_addr(arg.icl_nexus));
			i2c_ctrl_fini(ctrl);
			continue;
		}
		VERIFY3U(len, ==, sizeof (uint32_t));

		if (!i2c_prop_get(ctrl, I2C_PROP_TYPE, &arg.icl_type, &len)) {
			i2cadm_warn("failed to get controller %s type",
			    di_bus_addr(arg.icl_nexus));
			i2c_ctrl_fini(ctrl);
			continue;
		}
		VERIFY3U(len, ==, sizeof (uint32_t));

		if (!i2c_prop_get(ctrl, I2C_PROP_NPORTS, &arg.icl_nports,
		    &len)) {
			i2cadm_warn("failed to get controller %s ports",
			    di_bus_addr(arg.icl_nexus));
			i2c_ctrl_fini(ctrl);
			continue;
		}
		VERIFY3U(len, ==, sizeof (uint32_t));

		arg.icl_ctrl = ctrl;
		ofmt_print(ofmt, &arg);
		i2c_ctrl_fini(ctrl);
		print = true;
	}

	if (iret == I2C_ITER_ERROR) {
		i2cadm_warn("failed to iterate controllers");
		ret = EXIT_FAILURE;
	}

	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any controllers",
			    argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	if (!print && argc == 0) {
		warnx("no controllers found");
		ret = EXIT_FAILURE;
	}

	free(filts);
	ofmt_close(ofmt);
	i2c_ctrl_discover_fini(iter);
	return (ret);
}

static i2cadm_cmdtab_t i2cadm_ctrl_cmds[] = {
	{ "list", i2cadm_controller_list, i2cadm_controller_list_usage },
	{ "prop", i2cadm_controller_prop, i2cadm_controller_prop_usage }
};

int
i2cadm_controller(int argc, char *argv[])
{
	return (i2cadm_walk_tab(i2cadm_ctrl_cmds, ARRAY_SIZE(i2cadm_ctrl_cmds),
	    argc, argv));
}

void
i2cadm_controller_usage(FILE *f)
{
	i2cadm_walk_usage(i2cadm_ctrl_cmds, ARRAY_SIZE(i2cadm_ctrl_cmds), f);
}
