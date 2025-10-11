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
 * i2cadm scan -- scan a single port for devices. By default all devices are
 * scanned under the port, unless a specific set of devices is specified.
 */

#include <err.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <ofmt.h>

#include "i2cadm.h"

void
i2cadm_scan_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm scan [-d dev] [-o field,[...] [-H] [-p]] "
	    "<port>\n");
}

static void
i2cadm_scan_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm scan [-d dev] [-o field,[...] "
	    "[-H] [-p]] <port>\n");
	(void) fprintf(stderr, "\nScan for I2C devices\n\n"
	    "\t-d dev\t\tonly scan device address dev, can be specified "
	    "multiple\n\t\t\ttimes\n"
	    "\t-H\t\tomit the column header (requires -o)\n"
	    "\t-o field\toutput fields to print\n"
	    "\t-p\t\tparseable output (requires -o)\n");
	(void) fprintf(stderr, "\nThe following fields are supported when "
	    "using -o:\n"
	    "\taddr\t\tthe I2C address\n"
	    "\tresult\t\tthe address scan result\n"
	    "\terror\t\tthe error message if an error occurred\n");
}

typedef enum {
	I2CADM_BUS_SCAN_UNKNOWN = 0,
	I2CADM_BUS_SCAN_FOUND,
	I2CADM_BUS_SCAN_NO_DEV,
	I2CADM_BUS_SCAN_RESERVED,
	I2CADM_BUS_SCAN_TIMEOUT,
	I2CADM_BUS_SCAN_ERROR,
	I2CADM_BUS_SCAN_SKIPPED
} i2cadm_scan_result_t;

typedef struct {
	i2c_addr_t scan_addr;
	i2cadm_scan_result_t scan_res;
	char *scan_error;
} i2cadm_scan_t;

static void
i2cadm_scan_error(i2c_hdl_t *hdl, i2cadm_scan_t *scan)
{
	i2c_err_t err = i2c_err(hdl);
	if (err != I2C_ERR_CONTROLLER) {
		scan->scan_res = I2CADM_BUS_SCAN_ERROR;
		scan->scan_error = strdup(i2c_errmsg(hdl));
		if (scan->scan_error == NULL) {
			scan->scan_error = "libi2c error; but failed to "
			    "duplicate libi2c error message";
		}
		return;
	}

	switch (i2c_ctrl_err(hdl)) {
	case I2C_CTRL_E_ADDR_NACK:
	case I2C_CTRL_E_DATA_NACK:
	case I2C_CTRL_E_NACK:
		scan->scan_res = I2CADM_BUS_SCAN_NO_DEV;
		break;
	case I2C_CTRL_E_REQ_TO:
		scan->scan_res = I2CADM_BUS_SCAN_TIMEOUT;
		break;
	default:
		scan->scan_res = I2CADM_BUS_SCAN_ERROR;
		scan->scan_error = strdup(i2c_errmsg(hdl));
		if (scan->scan_error == NULL) {
			scan->scan_error = "i2c controller error; but "
			    "failed to duplicate libi2c error message";
		}
		break;
	}
}

/*
 * One does not simply scan an i2c device. In essence, we're trying to perform
 * some I/O such that it will ack an address, but without causing the device to
 * wreak havoc. Given the plethora of devices that are out there, this may not
 * be possible. Safety cannot be guaranteed by construction.
 *
 * We basically do a one byte read from the device. Most devices will respond to
 * this. The alternative that some other tools have done is to try to perform an
 * SMBus Quick action.
 */
static void
i2cadm_scan_one(i2c_hdl_t *hdl, i2c_port_t *port, i2cadm_scan_t *scan)
{
	i2c_io_req_t *req;
	uint8_t data = 0x77;

	if (!i2c_io_req_init(port, &req)) {
		i2cadm_fatal("failed to initialize I/O request");
	}

	if (!i2c_io_req_set_addr(req, &scan->scan_addr)) {
		i2cadm_fatal("failed to set scan address");
	}

	if (!i2c_io_req_set_receive_buf(req, &data, sizeof (data))) {
		i2cadm_fatal("failed to set receive buffer");
	}

	if (i2c_io_req_exec(req)) {
		scan->scan_res = I2CADM_BUS_SCAN_FOUND;
	} else {
		i2cadm_scan_error(hdl, scan);
	}

	i2c_io_req_fini(req);
}

typedef enum {
	I2CADM_SCAN_ADDR,
	I2CADM_SCAN_RESULT,
	I2CADM_SCAN_ERROR
} i2cadm_scan_otype_t;

static boolean_t
i2cadm_scan_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	const i2cadm_scan_t *scan = ofarg->ofmt_cbarg;
	const char *str;
	size_t len;

	switch (ofarg->ofmt_id) {
	case I2CADM_SCAN_ADDR:
		len = snprintf(buf, buflen, "0x%x", scan->scan_addr.ia_addr);
		break;
	case I2CADM_SCAN_RESULT:
		switch (scan->scan_res) {
		case I2CADM_BUS_SCAN_FOUND:
			str = "found";
			break;
		case I2CADM_BUS_SCAN_NO_DEV:
			str = "missing";
			break;
		case I2CADM_BUS_SCAN_RESERVED:
			str = "reserved";
			break;
		case I2CADM_BUS_SCAN_TIMEOUT:
			str = "timeout";
			break;
		case I2CADM_BUS_SCAN_ERROR:
			str = "error";
			break;
		case I2CADM_BUS_SCAN_SKIPPED:
			str = "skipped";
			break;
		default:
			str = "unknown";
			break;
		}
		len = strlcpy(buf, str, buflen);
		break;
	case I2CADM_SCAN_ERROR:
		if (scan->scan_error != NULL) {
			len = strlcpy(buf, scan->scan_error, buflen);
		} else {
			len = strlcpy(buf, "-", buflen);
		}
		break;
	default:
		return (B_FALSE);
	}

	return (len < buflen);
}

static const ofmt_field_t i2cadm_scan_ofmt[] = {
	{ "ADDR", 8, I2CADM_SCAN_ADDR, i2cadm_scan_ofmt_cb },
	{ "RESULT", 16, I2CADM_SCAN_RESULT, i2cadm_scan_ofmt_cb },
	{ "ERROR", 40, I2CADM_SCAN_ERROR, i2cadm_scan_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

/*
 * We can fit 16 devices on a line.
 */
#define	SCAN_DEVS_PER_LINE	0x10

static const char *key = ""
"\t- = No Device      @ = Device Found\n"
"\tR = Reserved       S = Skipped\n"
"\tX = Timed Out    Err = Error\n";

static bool
i2cadm_scan_table_cb(void *arg, uint16_t i)
{
	const i2cadm_scan_t *results = arg;
	const char *msgs[] = { "???", "@", "-", "R", "X", "Err", "S" };

	(void) printf("%3s", msgs[results[i].scan_res]);

	return (results[i].scan_res == I2CADM_BUS_SCAN_ERROR);
}

static void
i2cadm_scan_table_post(void *arg, uint16_t max_addr)
{
	const i2cadm_scan_t *results = arg;
	(void) printf("\nErrors\n");
	for (uint16_t i = 0; i < max_addr; i++) {
		if (results[i].scan_res != I2CADM_BUS_SCAN_ERROR)
			continue;

		if (max_addr > UINT8_MAX) {
			(void) printf("0x%03x: %s\n", i, results[i].scan_error);
		} else {
			(void) printf("0x%02x: %s\n", i, results[i].scan_error);
		}
	}
}

int
i2cadm_scan(int argc, char *argv[])
{
	int c;
	i2c_port_t *port;
	bool ten_bit = false;
	uint16_t max_addr = 1 << 7;
	i2cadm_scan_t *results;
	uint16_t *dev_addrs = NULL;
	size_t naddrs = 0, nalloc = 0;
	boolean_t parse = B_FALSE;
	uint_t flags = 0;
	const char *fields = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;

	/*
	 * In the future we should consider -T for 10-bit addressing.
	 */
	while ((c = getopt(argc, argv, ":d:Ho:p")) != -1) {
		switch (c) {
		case 'd': {
			if (naddrs == nalloc) {
				nalloc += 8;
				dev_addrs = recallocarray(dev_addrs, naddrs,
				    nalloc, sizeof (uint16_t));
				if (dev_addrs == NULL) {
					err(EXIT_FAILURE, "failed to allocate "
					    "memory for %zu I2C addresses",
					    nalloc);
				}
			}

			const char *err;
			long long l = strtonumx(optarg, 0, max_addr - 1, &err,
			    0);
			if (err != NULL) {
				errx(EXIT_FAILURE, "invalid device address %s: "
				    "address is %s", optarg, err);
			}
			dev_addrs[naddrs] = (uint16_t)l;
			naddrs++;
			break;
		}
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
			i2cadm_scan_help("option -%c requires an argument",
			    optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_scan_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argv += optind;
	argc -= optind;
	if (argc == 0) {
		errx(EXIT_USAGE, "missing required port to scan");
	} else if (argc > 1) {
		errx(EXIT_USAGE, "encountered extraneous arguments starting "
		    "with %s", argv[1]);
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

		oferr = ofmt_open(fields, i2cadm_scan_ofmt, flags, 0,
		    &ofmt);
		ofmt_check(oferr, parse, ofmt, i2cadm_ofmt_errx, warnx);
	}

	if (!i2c_port_init_by_path(i2cadm.i2c_hdl, argv[0], &port)) {
		i2cadm_fatal("failed to parse port path %s", argv[0]);
	}

	results = calloc(max_addr, sizeof (i2cadm_scan_t));
	if (results == NULL) {
		err(EXIT_FAILURE, "failed to allocate scan results tracking "
		    "structure");
	}

	/*
	 * If we have a specific device list, then mark everything skipped and
	 * come back and mark the specific instances we care about as things to
	 * check.
	 */
	if (dev_addrs != NULL) {
		for (uint16_t i = 0; i < max_addr; i++) {
			results[i].scan_res = I2CADM_BUS_SCAN_SKIPPED;
		}

		for (uint16_t i = 0; i < naddrs; i++) {
			results[dev_addrs[i]].scan_res =
			    I2CADM_BUS_SCAN_UNKNOWN;
		}
	}

	for (uint16_t i = 0; i < max_addr; i++) {
		i2cadm_scan_t *scan = &results[i];

		scan->scan_addr.ia_type = ten_bit ? I2C_ADDR_10BIT :
		    I2C_ADDR_7BIT;
		scan->scan_addr.ia_addr = i;

		if (scan->scan_res == I2CADM_BUS_SCAN_SKIPPED)
			continue;

		/*
		 * Determine if this is a reserved address or not.
		 */
		if (i2c_addr_reserved(&scan->scan_addr)) {
			scan->scan_res = I2CADM_BUS_SCAN_RESERVED;
			continue;
		}

		i2cadm_scan_one(i2cadm.i2c_hdl, port, scan);
	}

	if (fields == NULL) {
		i2cadm_table_t table = {
			.table_port = argv[0],
			.table_key = key,
			.table_msg = "Device scan on",
			.table_max = max_addr,
			.table_cb = i2cadm_scan_table_cb,
			.table_post = i2cadm_scan_table_post
		};
		i2cadm_print_table(&table, results);
	} else {
		for (uint16_t i = 0; i < max_addr; i++) {
			ofmt_print(ofmt, &results[i]);
		}
		ofmt_close(ofmt);
	}

	for (uint16_t i = 0; i < max_addr; i++) {
		free(results[i].scan_error);
	}
	free(results);
	i2c_port_fini(port);
	return (EXIT_SUCCESS);
}
